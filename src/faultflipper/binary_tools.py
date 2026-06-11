import os
import signal
import shutil
import struct
import subprocess
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime
from enum import Enum
from pathlib import Path
from random import sample
from tempfile import NamedTemporaryFile
from typing import Any

import capstone
import lief
import pandas as pd
from faultflipper.angr_backend import (
    run_angr_insn_trace,
)
from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_RISCV,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    Cs,
    CsInsn,
)
from elftools.elf.elffile import ELFFile


class OptimizationLevel(Enum):
    O0 = "0"
    O1 = "1"
    O2 = "2"
    O3 = "3"
    OZ = "z"


class Target(Enum):
    """Support Targets."""

    X86_32 = 0
    RISCV = 2
    ARM_64 = 3
    ARM_32 = 4
    RISCV_32 = 5
    X86_64 = 6


def compile_qemu_insn_plugin(
    source: Path,
    output: Path | None = None,
    cc: str = "gcc",
    qemu_prefix: Path = Path("~/.local").expanduser().absolute()
) -> Path:
    """
    Compile the QEMU instruction-trace plugin *without* using pkg-config.

    Assumes:
      - qemu-plugin.h is in <qemu_prefix>/include
      - GLib is installed in standard Ubuntu locations:
          /usr/include/glib-2.0
          /usr/lib/x86_64-linux-gnu/glib-2.0/include
          /usr/lib/x86_64-linux-gnu (libglib-2.0.so)
    """
    source = Path(source)

    if output is None:
        output = source.with_suffix(".so")

    output = Path(output)

    qemu_prefix = qemu_prefix.expanduser().absolute()

    # Where qemu-plugin.h lives
    qemu_inc = qemu_prefix / "include"
    if not qemu_inc.exists():
        raise RuntimeError(f"QEMU include dir not found: {qemu_inc} (looking for qemu-plugin.h)")

    # GLib standard locations on Ubuntu
    glib_inc1 = Path("/usr/include/glib-2.0")
    glib_inc2 = Path("/usr/lib/x86_64-linux-gnu/glib-2.0/include")
    glib_libdir = Path("/usr/lib/x86_64-linux-gnu")

    for p in (glib_inc1, glib_inc2, glib_libdir):
        if not p.exists():
            raise RuntimeError(
                f"Expected GLib path missing: {p}. "
                "Is libglib2.0-dev installed?"
            )

    cmd = [
        cc,
        "-fPIC",
        "-shared",
        f"-I{qemu_inc}",
        f"-I{glib_inc1}",
        f"-I{glib_inc2}",
        f"-L{glib_libdir}",
        "-lglib-2.0",
        "-o",
        str(output),
        str(source),
    ]

    print("Compiling QEMU plugin:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return output



def build_adjusted_hit_map_with_markers(
    disasm: Iterable[Any],
    raw_hit_map: dict[int, int],
    target,
    min_hits: int = 1,
    treat_markers_implicit: bool = True,
) -> dict[int, int]:
    """
    Take the original angr hit_map {addr -> count} and return an adjusted
    hit-map that:
      - keeps only instructions with hits >= min_hits
      - optionally treats certain ABI 'marker' instructions (endbr64, bti, etc.)
        as executed if at least one neighbor has hits >= min_hits.

    Args:
        disasm:
            Iterable of Capstone instruction objects.
        raw_hit_map:
            dict { address -> execution_count } from run_angr_trace.
        target:
            Your Target enum (Target.X86_64, Target.X86_32, Target.ARM_64, etc.).
        min_hits:
            Minimum execution count to consider an instruction executed.
        treat_markers_implicit:
            If True, special marker mnemonics can be treated as executed
            based on neighbor activity.

    Returns
    -------
        Dict[int, int]: adjusted hit_map {addr -> count} containing only
        instructions considered executed (including implicit markers).
    """
    insns = list(disasm)
    n = len(insns)

    # Direct hits from angr
    direct_hits = [raw_hit_map.get(insn.address, 0) for insn in insns]

    # Figure out which mnemonics are "marker" style for this target
    marker_mnemonics: set[str] = set()

    # x86-64 CET markers
    if target == Target.X86_64:
        marker_mnemonics.update({"endbr64"})

    # x86-32: do NOT assume CET; optionally auto-detect if endbr32 even exists
    elif target == Target.X86_32:
        if any(insn.mnemonic == "endbr32" for insn in insns):
            marker_mnemonics.add("endbr32")

    # AArch64 markers (BTI / hint-based)
    elif target == Target.ARM_64:
        marker_mnemonics.update({"bti", "hint"})

    # ARM32 / RISCV: leave marker_mnemonics empty by default

    # Decide effective hits per instruction
    effective_hits = [0] * n

    # 1) Start with the direct hits
    for i in range(n):
        if direct_hits[i] >= min_hits:
            effective_hits[i] = direct_hits[i]

    # 2) Optionally promote marker instructions based on neighbors
    if treat_markers_implicit and marker_mnemonics:
        for i, insn in enumerate(insns):
            # Skip if already considered executed
            if effective_hits[i] >= min_hits:
                continue

            # Skip if not a known marker
            if insn.mnemonic not in marker_mnemonics:
                continue

            # Check neighbors' direct hits
            left_hit = direct_hits[i - 1] if i > 0 else 0
            right_hit = direct_hits[i + 1] if i + 1 < n else 0

            if left_hit >= min_hits or right_hit >= min_hits:
                # Treat it as executed with at least min_hits.
                # You could also choose max(left_hit,right_hit,min_hits) if you
                # want a "stronger" inferred count.
                effective_hits[i] = max(min_hits, left_hit, right_hit)

    # Build the adjusted hit_map: only include instructions considered executed
    adjusted_hit_map: dict[int, int] = {}
    for insn, count in zip(insns, effective_hits, strict=False):
        if count >= min_hits:
            adjusted_hit_map[insn.address] = count

    return adjusted_hit_map


def compute_best_offset_with_distinct(
    qemu_trace: Sequence[tuple[int, bytes]],
    cap_insns,
) -> tuple[int, int, int]:
    """
    Infer the most likely OFFSET such that:
        pc_qemu ≈ cap_addr + OFFSET

    But score deltas by:
      - how many DISTINCT Capstone addresses support them
      - then total hits as a tie-breaker

    Returns
    -------
        best_offset, distinct_support, total_support
    """
    # Build bytes -> [cap_addr, ...] from Capstone
    caps_by_bytes: dict[bytes, list[int]] = defaultdict(list)
    for insn in cap_insns:
        caps_by_bytes[bytes(insn.bytes)].append(insn.address)

    deltas_total = Counter()
    delta_to_caps: dict[int, set[int]] = defaultdict(set)

    for pc_qemu, q_bytes in qemu_trace:
        addrs = caps_by_bytes.get(q_bytes)

        if not addrs:
            #print(f"pc of {pc_qemu} has: {q_bytes.hex()} or not in caps by bytes")
            continue

        for cap_addr in addrs:
            d = pc_qemu - cap_addr
            deltas_total[d] += 1
            delta_to_caps[d].add(cap_addr)

    print("Cap has bytes: {k.hex() for k in caps_by_bytes.keys()}")

    if not deltas_total:
        print("No delta total")
        return 0, 0, 0

    # Rank deltas: first by distinct cap addrs, then by total hits
    candidates: list[tuple[int, int, int]] = []
    for d, total in deltas_total.items():
        distinct = len(delta_to_caps[d])
        candidates.append((distinct, total, d))

    # max by (distinct, total)
    best_distinct, best_total, best_delta = max(candidates)
    print(
        f"[offset] best_offset={best_delta:#x}, "
        f"distinct_caps={best_distinct}, total_support={best_total}"
    )

    return best_delta, best_distinct, best_total

def build_executed_capstone_addrs_from_qemu(
    disasm,
    qemu_trace: Sequence[tuple[int, bytes]],
    min_distinct_caps: int = 3,
) -> tuple[dict[int,int], dict[int, int], int, int]:
    """
    Returns
    -------
      hit_map: {cap_addr -> exec_count}
      best_offset
      distinct_support
    """
    cap_insns = list(disasm)
    cap_addrs = [insn.address for insn in cap_insns]

    # Initialize hit map in Capstone space
    hit_map: dict[int, int] = dict.fromkeys(cap_addrs, 0)

    print("Computing best offset with distinct")

    best_offset, distinct_support, total_support = compute_best_offset_with_distinct(
        qemu_trace,
        cap_insns,
    )

    # If we only got 1 distinct Capstone addr, we probably locked onto
    # one repeated pattern (system noise) instead of real alignment.
    if distinct_support < min_distinct_caps:
        print(
            f"[warn] Only {distinct_support} distinct capstone addresses "
            f"support best offset; not trusting alignment."
        )
        return {}, hit_map, 0, distinct_support

    # Rebuild bytes map
    caps_by_bytes: dict[bytes, list[int]] = defaultdict(list)

    for insn in cap_insns:
        caps_by_bytes[bytes(insn.bytes)].append(insn.address)

    # Count executions: must match bytes AND chosen offset
    for pc_qemu, q_bytes in qemu_trace:
        addrs = caps_by_bytes.get(q_bytes)
        if not addrs:
            continue
        for cap_addr in addrs:
            if pc_qemu - cap_addr == best_offset:
                hit_map[cap_addr] += 1

    print(hit_map)
    adj_map = [x-best_offset for x,_ in qemu_trace]

    return adj_map, hit_map, best_offset, distinct_support




def load_qemu_trace_text(trace_path: Path) -> list[tuple[int, bytes]]:
    """
    Parse lines of the form:
      PC: 0x105e4, Size: 4, Bytes: aa bb cc dd

    Returns a list of (pc, raw_bytes).
    """
    pcs: list[tuple[int, bytes]] = []
    trace_path = Path(trace_path)

    with trace_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Very simple pattern-based parse
            # PC: 0x105e4, Size: 4, Bytes: aa bb cc dd
            try:
                # Split into 3 parts: "PC: ...", " Size: ...", " Bytes: ..."
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 3:
                    continue

                # PC
                pc_str = parts[0].split("PC:", 1)[1].strip()
                pc = int(pc_str, 16) if pc_str.startswith("0x") else int(pc_str)

                # Bytes
                bytes_part = parts[2]
                if "Bytes:" in bytes_part:
                    bytes_str = bytes_part.split("Bytes:", 1)[1].strip()
                else:
                    bytes_str = bytes_part.strip()

                if bytes_str:
                    byte_vals = bytes.fromhex(bytes_str)
                else:
                    byte_vals = b""

                pcs.append((pc, byte_vals))
            except Exception:
                # Ignore malformed lines
                continue

    #print(pcs)
    return pcs



def get_text_range(binary_path: Path) -> tuple[int, int]:
    """
    Return (text_start, text_end) virtual address range for the main .text section.
    """
    bin_ = lief.parse(str(binary_path))
    if not bin_:
        raise RuntimeError(f"Failed to parse ELF: {binary_path}")

    text = bin_.get_section(".text")
    if text is None:
        raise RuntimeError(".text section not found")

    start = text.virtual_address
    end = start + text.size
    return start, end


def file_compiled_as_pie(binary_path: Path) -> bool:
    """
    Determine whether an ELF binary was compiled as a position-independent executable.

    Parameters
    ----------
    binary_path : Path
        Path to the ELF binary being inspected.

    Returns
    -------
    bool
        ``True`` when the file type is ``ET_DYN`` (typical for PIE), otherwise ``False``.
    """
    bin_ = lief.parse(str(binary_path))
    if not bin_:
        raise RuntimeError(f"Failed to parse ELF: {binary_path}")
    return bin_.header.file_type == lief.ELF.E_TYPE.DYNAMIC


def compute_best_offset_pc_only(
    qemu_pcs: list[int],
    capstone_addrs: list[int],
    text_start: int,
    text_end: int,
    max_qemu_samples: int = 200_000,
    max_capstone_samples: int = 500_000,
) -> tuple[int, int]:
    """
    Improved PC-only offset inference for x86.

    1) Use sampled (pc, cap_addr) pairs to generate candidate deltas.
    2) For each candidate delta, use *all* PCs to compute:
         - how many distinct Capstone addrs in [.text] get hits,
         - how many total PCs map into [.text].
    3) Return the delta with best (distinct_caps_in_text, total_in_text).
    """
    if not qemu_pcs or not capstone_addrs:
        return 0, 0

    qemu_uniq = list(set(qemu_pcs))
    caps_uniq = list(set(capstone_addrs))

    if len(qemu_uniq) > max_qemu_samples:
        qemu_uniq = sample(qemu_uniq, max_qemu_samples)
    if len(caps_uniq) > max_capstone_samples:
        caps_uniq = sample(caps_uniq, max_capstone_samples)

    # Stage 1: generate candidate deltas from samples
    delta_hits: Counter = Counter()
    for qp in qemu_uniq:
        for ca in caps_uniq:
            d = qp - ca
            delta_hits[d] += 1

    if not delta_hits:
        return 0, 0

    # Only keep top-K deltas by raw hit count to keep stage 2 cheap
    TOP_K = 512
    candidate_deltas = [d for d, _ in delta_hits.most_common(TOP_K)]

    capstone_set = set(capstone_addrs)

    # Stage 2: full scoring using all PCs + .text range
    best_delta = 0
    best_distinct = -1
    best_in_text = -1

    for d in candidate_deltas:
        mapped_in_text = 0
        distinct_caps_in_text: set[int] = set()

        for pc in qemu_pcs:
            a = pc - d
            if text_start <= a < text_end:
                mapped_in_text += 1
                if a in capstone_set:
                    distinct_caps_in_text.add(a)

        distinct_count = len(distinct_caps_in_text)

        # Score by (distinct_capstone_in_text, mapped_in_text)
        if distinct_count > best_distinct or (
            distinct_count == best_distinct and mapped_in_text > best_in_text
        ):
            best_delta = d
            best_distinct = distinct_count
            best_in_text = mapped_in_text

    # Optional debug:
    # print(f"[pc-only] best_delta={best_delta:#x}, "
    #       f"distinct_caps_in_text={best_distinct}, mapped_in_text={best_in_text}")

    return best_delta, best_distinct

def build_x86_hit_map_from_pcs(
    binary_path: Path,
    disasm,          # list of Capstone insns
    qemu_pcs: list[int],
) -> tuple[dict[int, int], int]:
    """
    Build an execution hit map for x86 targets from raw QEMU program counters.

    Parameters
    ----------
    binary_path : Path
        Path to the binary whose instructions were traced.
    disasm : list[capstone.CsInsn]
        Disassembly of the binary's ``.text`` section.
    qemu_pcs : list[int]
        Raw PC values emitted by the QEMU tracing plugin.

    Returns
    -------
    tuple[dict[int, int], int]
        Mapping of Capstone instruction addresses to execution counts, and the
        offset applied to align QEMU PCs to static addresses.
    """
    capstone_addrs = [ins.address for ins in disasm]
    capstone_set = set(capstone_addrs)

    text_start, text_end = get_text_range(binary_path)

    if file_compiled_as_pie(binary_path):
        offset, support = compute_best_offset_pc_only(
            qemu_pcs,
            capstone_addrs,
            text_start,
            text_end,
        )
    else:
        offset, support = 0, len(capstone_set)

    hit_map: dict[int, int] = dict.fromkeys(capstone_set, 0)

    for pc in qemu_pcs:
        a = pc - offset
        if a in hit_map:
            hit_map[a] += 1

    # If you only care about executed:
    # hit_map = {addr: c for addr, c in hit_map.items() if c > 0}

    return hit_map, offset


def filter_executed_instructions(
    insns: list[CsInsn],
    hit_map: dict[int, int],
) -> list[CsInsn]:
    """
    Return only those disassembled instructions whose addresses
    appear in the QEMU hit_map with count >= 1.

    Parameters
    ----------
    insns : list[CsInsn]
        Instructions from disassemble_text_section(binary_path)
        Each `CsInsn` has a `.address` attribute.
    hit_map : dict[int, int]
        { pc : count } from run_qemu_trace()

    Returns
    -------
    list[CsInsn]
        Subset of insns that were executed at least once.
    """
    if not hit_map:
        #return []  # no instructions executed (or failed run)
        raise Exception("No instructions executed")

    #for ins in insns:
        #print(f"0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}")

    #print(f"In filter")
    max_cap = 0
    min_cap = float("inf")

    for insn in insns:
        max_cap = max(insn.address, max_cap)
        min_cap = min(insn.address, min_cap)

    executed = []
    for insn in insns:
        if hit_map.get(insn.address, 0) > 0:
            executed.append(insn)
        #else:
        #    print(f"Apparently {hex(insn.address)} has 0 {adj_map.get(hex(insn.address),None)}")


    return executed



def dyna_detect_insns(common, target:Target, disasm, drop_sys: bool = True)-> list[CsInsn]:
    """
    Execute the binary once to detect which instrcutions are executed
    """
    #plugin_so = compile_qemu_insn_plugin(Path(__file__).parent.parent.joinpath("trace_insn.c"))
    plugin_so = compile_qemu_insn_plugin(Path(__file__).parent.parent.joinpath("adv_trace_insn.c"))

    # Get the hit_map
    hit_map, series, rc, out, err, trace_path = run_qemu_trace(
        path=common.program_file,
        target=target,
        program_input=None,
        runtime_input=common.program_input,
        plugin_so=plugin_so,
        disasm=disasm,
        timeout=common.timeout*10,
        keep_trace=True,
        trace_backend=common.trace_backend,
    )


    #print("\n".join(sorted([hex(x.address) for x in disasm])))
    #sorted_insns = sorted(disasm, key=lambda ins: ins.address)

    #for ins in sorted_insns:
    #Jk:print(f"0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}")

    #filt_disasm, hit_map = filter_executed_insns(common.program_file, trace_path, disasm, min_hits=1)

    #return filt_disasm #filter_executed_instructions(disasm, hit_map, offset=0)
    return filter_executed_instructions(disasm, hit_map)

#TODO: DEP THIS 
def filter_executed_insns(binary_path: Path, trace_path: Path, disasm, min_hits: int = 1):
    """
    Filter Capstone instructions using a static hit map derived from a QEMU trace.

    Parameters
    ----------
    binary_path : Path
        Binary whose trace is being examined.
    trace_path : Path
        File produced by the QEMU tracing plugin.
    disasm : Iterable[capstone.CsInsn]
        Disassembled instructions to filter.
    min_hits : int, optional
        Minimum number of executions required to keep an instruction, by default ``1``.

    Returns
    -------
    tuple[list[capstone.CsInsn], dict[int, int]]
        (executed instructions, raw hit map indexed by instruction address).
    """
    hit_map = build_hit_map_static(binary_path, trace_path)
    executed = [insn for insn in disasm if hit_map.get(insn.address, 0) >= min_hits]

    return executed, hit_map


def map_asm_to_c(binary_path, source_path):
    """A simple mapper that uses pyelftools to map ASM lines to C.

    Notice: Sometime early addresses in the .text wont be mapped. This
    can be due to:
    1. They are "start up", plt jumps, or "veener" code.

    Those start up lines don't really map to a true line in the C code.
    """
    addresses = {}

    target = detect_target(binary_path)

    # Open the ELF binary
    with open(binary_path, "rb") as bf:
        elffile = ELFFile(bf)

        if not elffile.has_dwarf_info():
            raise RuntimeError(
                "No DWARF debug info found in the binary. Recompile with -g."
            )

        dwarfinfo = elffile.get_dwarf_info()
        text_section = elffile.get_section_by_name(".text")
        if text_section is None:
            raise RuntimeError("No .text section found in the ELF.")

        text_data = text_section.data()
        text_vaddr = text_section["sh_addr"]  # The load address of .text

        # Architecture and mode mappings for Capstone
        arch_mode_map = {
            Target.X86_64: (CS_ARCH_X86, CS_MODE_64),
            Target.X86_32: (CS_ARCH_X86, CS_MODE_32),

            Target.ARM_32: (CS_ARCH_ARM, CS_MODE_ARM),
            Target.ARM_64: (CS_ARCH_ARM64, CS_MODE_ARM),

            Target.RISCV: (CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC),
            Target.RISCV_32: (CS_ARCH_RISCV, capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC | capstone.CS_MODE_LITTLE_ENDIAN),
        }

        cs_arch, cs_mode = arch_mode_map[target]
        md = Cs(cs_arch, cs_mode)

        addr_to_line = {}  # maps instruction address -> line number
        for cu in dwarfinfo.iter_CUs():
            line_program = dwarfinfo.line_program_for_CU(cu)

            if not line_program:
                continue

            for entry in line_program.get_entries():
                state = entry.state
                if state is None or state.file == 0 or state.line == 0:
                    continue

                file_entry = line_program["file_entry"][state.file - 1]
                file_name = file_entry.name.decode("utf-8", errors="ignore")

                if os.path.basename(file_name) == os.path.basename(source_path):
                    addr_to_line[state.address] = state.line

    return addr_to_line


# TODO: THis is incomplete
def get_return_reg(target: Target) -> str | None:
    """Get the return register for the target."""
    # Get the register
    if target == Target.ARM_32:
        return "r0"
    elif target == Target.X86_64:
        return "rax"
    else:
        return None


from enum import Enum
from pathlib import Path


class Target(Enum):
    X86_32 = 0
    RISCV = 2
    ARM_64 = 3
    ARM_32 = 4
    RISCV_32 = 5
    X86_64 = 6


def generate_qemu_cmd_with_plugin(
    inp: Path,
    target: Target,
    plugin_so: Path,
    trace_log: Path,
    call_time_program_input: str | None = None,
    qemu_base: Path = Path("~/.local/bin/").expanduser().absolute()
) -> list[str]:
    """
    Build the QEMU user-mode command that runs `inp` for a given `Target`
    with the instruction-trace plugin attached.

    The plugin receives `trace_log` as its `input=` argument, so it writes PCs there.
    """
    inp = Path(inp).expanduser().absolute()
    plugin_so = Path(plugin_so).expanduser().absolute()
    trace_log = Path(trace_log).expanduser().absolute()

    # Base QEMU cmd: [qemu-bin, <opts...>, guest-binary]
    base = generate_run_cmd_custom_qemu(inp, target, qemu_base)
    if not base:
        raise RuntimeError("generate_run_cmd_custom_qemu returned an empty command")

    # Everything except the last element is QEMU + options, last is the guest binary
    emu_part = base[:-1]
    guest_bin = base[-1]

    # QEMU plugin arg: file=/path/to/trace.bin
    plugin_spec = f"{plugin_so},input={trace_log}"

    cmd: list[str] = emu_part + [
        "-plugin",
        plugin_spec,
        guest_bin,
    ]

    if call_time_program_input is not None:
        cmd.append(call_time_program_input)

    return cmd

from pathlib import Path


def load_qemu_trace(trace_path: Path) -> list[tuple[int, str]]:
    """
    Load the QEMU plugin trace written in *text* form:
        PC: 0x105e4, Instruction: mov

    Returns a list of (pc, mnemonic).
    """
    trace_path = Path(trace_path)
    pcs: list[tuple[int, str]] = []

    with trace_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Expected format: "PC: 0x..., Instruction: <mnemonic>"
            try:
                # Split at the first comma
                left, right = line.split(",", 1)
                # Left: "PC: 0x105e4"
                # Right: " Instruction: mov"

                # Parse PC
                _, pc_str = left.split("PC:", 1)
                pc_str = pc_str.strip()
                pc = int(pc_str, 16) if pc_str.startswith("0x") else int(pc_str)

                # Parse mnemonic
                if "Instruction:" in right:
                    _, mnem = right.split("Instruction:", 1)
                    mnemonic = mnem.strip()
                else:
                    mnemonic = right.strip()

                pcs.append((pc, mnemonic))
            except ValueError:
                # If a weird line sneaks in, just skip it
                continue

    print(pcs)
    return pcs


def load_pc_series_from_trace(trace_path: Path) -> list[int]:
    """
    Load the binary instruction trace produced by the QEMU plugin.

    The plugin writes a sequence of uint64_t (little-endian) PC values.
    """
    #print(f"The trace path is {trace_path}")

    pcs: list[int] = []

    count = 0
    with trace_path.open("rb") as f:
        while True:
            chunk = f.read(8 * 1024)  # multiple of 8 bytes
            count+=1

            if not chunk:
                break

            # Process in 8-byte steps
            for i in range(0, len(chunk), 8):
                if i + 8 > len(chunk):
                    break  # ignore partial trailing
                pc_bytes = chunk[i:i+8]
                pc = int.from_bytes(pc_bytes, byteorder="little", signed=False)
                pcs.append(pc)

    return pcs


def compute_best_offset_by_mnemonic(
    qemu_trace: Sequence[tuple[int, str]],
    disasm,
    align: int = 4,
    max_pairs_per_mnemonic: int = 20_000,
) -> tuple[int, int]:
    """
    Compute the best offset Δ such that:

        pc_qemu ≈ addr_capstone + Δ

    but only using pairs where the mnemonics match. This cuts down the
    D, D+4, D+8 ambiguity significantly.

    Returns (best_delta, support_count).
    """
    # Group QEMU PCs by mnemonic
    print("Qemu mnemonic")
    qemu_by_mnem: dict[str, list[int]] = defaultdict(list)
    for pc, mnem in qemu_trace:
        qemu_by_mnem[mnem].append(pc)
        print(mnem)

    # Group Capstone addresses by mnemonic
    print("Capstone mnemonic")
    cap_by_mnem: dict[str, list[int]] = defaultdict(list)
    for insn in disasm:
        cap_by_mnem[insn.mnemonic].append(insn.address)
        print(insn.mnemonic)

    deltas = Counter()

    for mnem in set(qemu_by_mnem.keys()) & set(cap_by_mnem.keys()):
        q_list = qemu_by_mnem[mnem]
        c_list = cap_by_mnem[mnem]

        # Some mnemonics (like 'mov') can be huge; bound work a bit
        if len(q_list) * len(c_list) > max_pairs_per_mnemonic:
            # crude throttling: subsample
            q_list = q_list[: max(1, max_pairs_per_mnemonic // max(len(c_list), 1))]
            c_list = c_list[: max(1, max_pairs_per_mnemonic // max(len(q_list), 1))]

        for qp in q_list:
            for ca in c_list:
                d = qp - ca
                if align and (d % align) != 0:
                    continue
                deltas[d] += 1

    if not deltas:
        # Nothing matched at all
        print("Nothing matched!!!")
        return 0, 0

    raw_top = deltas.most_common(8)
    print(f"Raw top deltas (mnemonic-filtered): {raw_top}")

    best_delta, support = raw_top[0]
    print(f"Chosen offset = {best_delta:#x}, support = {support}")
    return best_delta, support

def load_qemu_offsets(trace_path: Path) -> list[int]:
    """
    Load the raw offsets recorded by the QEMU trace plugin.

    Parameters
    ----------
    trace_path : Path
        Binary file generated by the plugin (sequence of little-endian ``uint64`` values).

    Returns
    -------
    list[int]
        Offsets measured relative to QEMU's start address for the code segment.
    """
    data = trace_path.read_bytes()

    if len(data) % 8 != 0:
        raise ValueError(f"Trace size {len(data)} not multiple of 8 bytes")

    return list(struct.unpack("<" + "Q" * (len(data) // 8), data))


def offsets_to_static_addrs(binary_path: Path, offsets: list[int]) -> list[int]:
    """
    Convert offsets emitted by the tracing plugin into static instruction addresses.

    Parameters
    ----------
    binary_path : Path
        ELF binary corresponding to the trace.
    offsets : list[int]
        Offsets returned by :func:`load_qemu_offsets`.

    Returns
    -------
    list[int]
        Absolute virtual addresses inside the binary's ``.text`` section.
    """
    binary = lief.parse(str(binary_path))
    if not binary:
        raise RuntimeError(f"Failed to parse {binary_path}")

    text = binary.get_section(".text")
    if text is None:
        raise RuntimeError(".text section not found")

    # Find the PT_LOAD segment that contains .text
    code_seg = None
    for seg in binary.segments:
        if seg.type != lief.ELF.Segment.TYPE.LOAD:
            continue
        start = seg.virtual_address
        end = start + seg.virtual_size
        if start <= text.virtual_address < end:
            code_seg = seg
            break

    if code_seg is None:
        raise RuntimeError("No LOAD segment found that covers .text")

    seg_base = code_seg.virtual_address  # this matches qemu_plugin_start_code()

    # Now reconstruct static addresses
    return [seg_base + off for off in offsets]
 
def build_hit_map_static(binary_path: Path, trace_path: Path) -> dict[int, int]:
    """
    Build a frequency map of executed addresses using only QEMU trace output.

    Parameters
    ----------
    binary_path : Path
        Binary whose instructions were executed.
    trace_path : Path
        Path to the raw trace file produced by QEMU.

    Returns
    -------
    dict[int, int]
        Counts keyed by static instruction address.
    """
    offsets = load_qemu_offsets(trace_path)
    print(f" Got {len(offsets)} offsets")

    static_addrs = offsets_to_static_addrs(binary_path, offsets)

    print(f" Got {len(static_addrs)} addrs")
    return Counter(static_addrs)

def align_qemu_pcs_to_text(
    qemu_pcs: list[int],
    offset: int,
    text_start: int,
    text_end: int,
):
    """
    Apply offset and keep only addresses that land in .text.
    """
    aligned = []
    for pc in qemu_pcs:
        addr = pc - offset
        if text_start <= addr < text_end:
            aligned.append(addr)
    return aligned

def get_text_range(binary_path: Path):
    """
    Return the start/end virtual addresses of the ``.text`` section.

    Parameters
    ----------
    binary_path : Path
        ELF binary to inspect.

    Returns
    -------
    tuple[int, int]
        Start (inclusive) and end (exclusive) virtual addresses.
    """
    binary = lief.parse(str(binary_path))
    text = binary.get_section(".text")
    start = text.virtual_address
    end = start + text.size
    return start, end

def file_compiled_as_pie(binary_path: Path) -> bool:
    """
    Return True if this ELF looks like a PIE (ET_DYN main executable),
    False for classic ET_EXEC binaries.

    Assumes 'binary_path' is an ELF binary that you're actually running
    under qemu-*-linux-user.
    """
    bin_obj = lief.parse(str(binary_path))
    if not isinstance(bin_obj, lief.ELF.Binary):
        raise ValueError(f"{binary_path} is not an ELF binary")

    ftype = bin_obj.header.file_type

    # ET_DYN => position-independent (shared object or PIE).
    # In your pipeline, anything ET_DYN that you're running as "the program"
    # is effectively a PIE.

    return ftype == lief.ELF.Header.FILE_TYPE.DYN

def build_aligned_trace(binary_path: Path, trace_path: Path, disasm, target:Target, stdin, trace_backend, assume_hits=True):
    """
    Align a QEMU or angr trace to static instruction addresses and build a hit map.

    Parameters
    ----------
    binary_path : Path
        Binary under analysis.
    trace_path : Path
        Trace file produced by the selected backend.
    disasm : list[capstone.CsInsn]
        Disassembly of the ``.text`` section.
    target : Target
        Architecture enum describing the binary.
    stdin : str | bytes | None
        Runtime input used for angr traces (ignored for QEMU).
    trace_backend : str
        Either ``\"angr\"`` or ``\"qemu\"`` to control offset recovery.
    assume_hits : bool, optional
        When ``True`` the resulting hit map is forced to contain every instruction
        once even if the trace skipped it; defaults to ``True``.
    """
    if file_compiled_as_pie(binary_path):

        print("FILE IS COMPILED AS PIE... MUST DETECT OFFSET")

        if trace_backend == "angr":

            map, offset = run_angr_insn_trace(binary_path, stdin)
            print(f"Capstone pre adj: {map}")
            map = {x-offset : k for x,k in map.items()}
            print(f"Capstone post adj: {map}")

            if assume_hits:
                map = build_adjusted_hit_map_with_markers(disasm, map, target=target)


        #elif target == Target.X86_32 or target == Target.X86_64:


        #    #qemu_pcs = load_qemu_trace(trace_path)
        #    qemu_pcs = [x[0] for x in out]
        #    #map, offset = build_x86_hit_map_from_pcs(binary_path, disasm, qemu_pcs)
        #    map, offset = build_x86_hit_map_from_pcs(binary_path, disasm, qemu_pcs)

        #    print(f"Running heuristic for x86")

            
        else:
            out = load_qemu_trace_text(trace_path)
            print("Building best offset with pcs and bytes")

            qemu_pcs, map, offset, _ = build_executed_capstone_addrs_from_qemu(disasm, out)

            print(f"Best offset = {offset:#x}")#, support = {support}")

    else:
        qemu_pcs = load_qemu_trace_text(trace_path)
        qemu_pcs = [x[0] for x in qemu_pcs]

        #text_start, text_end = get_text_range(binary_path)
        #aligned_pcs = align_qemu_pcs_to_text(qemu_pcs, offset, text_start, text_end)
        offset = 0

        #common = set(capstone_addrs) & set(aligned_pcs)
        #print(f"The new intestion size is: {len(common)} out of {len(capstone_addrs)} cap addrs")

        #print(f"The set size of qemu pcs is {len(set(qemu_pcs))}")
        map = Counter(qemu_pcs)

    print(map)

    # Now aligned_pcs live in the same address space as capstone_insns
    return map, offset


def _terminate_process_group(process: subprocess.Popen) -> None:
    """Forcefully terminate a subprocess and any children it spawned."""
    if process.poll() is not None:
        return

    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except Exception:
            try:
                process.kill()
            except Exception:
                return
    else:
        try:
            process.kill()
        except Exception:
            return

    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


def run_qemu_trace(
    path: Path,
    target: Target,
    program_input: str | None,
    plugin_so: Path,
    disasm,
    timeout: int = 60,
    keep_trace: bool = False,
    runtime_input: str | None = None,
    trace_backend: str = "best",
) -> tuple[dict[int, int], list[int], int | None, str, str, Path | None]:
    """
    Run `path` under QEMU with the instruction-trace plugin and
    return a hit-map and time series of executed PCs.

    Parameters
    ----------
    path : Path
        Path to the guest binary.
    target : Target
        Architecture / target enum.
    program_input : str | None
        Optional CLI argument passed to the guest program (like your current function).
    plugin_so : Path
        Path to compiled trace_insn.so.
    timeout : int
        Timeout in seconds for the whole run.
    keep_trace : bool
        If True, keep the trace file and return its path; otherwise use a temp file.

    Returns
    -------
    hit_map : dict[int, int]
        Map from PC -> execution count.
    pc_series : list[int]
        Time-ordered list of executed PCs.
    returncode : int | None
        Return code from QEMU process (None on timeout).
    stdout : str
        Captured stdout from QEMU.
    stderr : str
        Captured stderr from QEMU.
    trace_path : Path | None
        Path to the trace file if keep_trace=True, otherwise None.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Binary not found: {path}")

    plugin_so = Path(plugin_so).expanduser().absolute()

    # Create a temporary trace file or let the caller manage it
    if keep_trace:
        trace_path = path.with_suffix(path.suffix + ".insn_trace.bin")
        print(f"The trace path is {trace_path} being kept")
    else:
        tmp = NamedTemporaryFile(prefix="insn_trace_", suffix=".bin", delete=False)
        trace_path = Path(tmp.name)
        tmp.close()

    cmd = generate_qemu_cmd_with_plugin(
        inp=path,
        target=target,
        plugin_so=plugin_so,
        trace_log=trace_path,
        call_time_program_input=program_input,
    )

    full_cmd = cmd
    print(f"The golden run command is {full_cmd}")

    process = subprocess.Popen(
        full_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    try:
        if runtime_input is not None:
            if "\n" not in runtime_input:
                runtime_input = runtime_input + "\n"

            # Gather the outputs
            stdout_b, stderr_b = process.communicate(
                input=runtime_input.encode(), timeout=timeout
            )
        else:
            stdout_b, stderr_b = process.communicate(timeout=timeout)

        returncode = process.returncode
    except subprocess.TimeoutExpired:
        _terminate_process_group(process)
        stdout_b, stderr_b = b"TIMEOUT", b"timeout expired"
        returncode = None

    print(f"Godlen outputted: {stdout_b}")

    stdout = stdout_b.decode(errors="replace")
    stderr = stderr_b.decode(errors="replace")

    # Parse the trace
    pc_series: list[int] = []
    hit_map: dict[int, int] = {}

    if trace_path.is_file():
        #pc_series = load_pc_series_from_trace(trace_path)
        #pc_series = load_qemu_trace(trace_path)

        ##print(f"The pc series is {pc_series}")
        #hit_map = hit_map_from_pc_series(pc_series)

        hit_map, offset = build_aligned_trace(path, trace_path, disasm, target, program_input, trace_backend)

        #filt_disasm, offset = (path, trace_path, disasm)
        #print(f"THE DETECTED OFFSET IS {hex(offset)}")

        #hit_map = Counter(pc_series)

        if not keep_trace:
            # If you’d like to auto-clean, uncomment:
            trace_path.unlink(missing_ok=True)
            pass
    else:
        raise Exception("No trace path")

    return hit_map, pc_series, returncode, stdout, stderr, (trace_path if keep_trace else None)
    #return returncode, stdout, stderr, trace_path




def hit_map_from_pc_series(pcs: list[int]) -> dict[int, int]:
    """
    Convert a PC time series to a hit-map {address -> execution count}.
    """
    c = Counter(pcs)

    return dict(c)



def generate_compile_cmd(inp: Path, out: Path, target: Target, opts: str) -> list[str]:
    """
    Compile a program for a specific arch
    """
    if not out.parent.exists():
        out.parent.mkdir(parents=True)

    match target:
        case Target.X86_32:
            compiler = "gcc -m32 -g"
        case Target.X86_64:
            compiler = "gcc -g"
        case Target.RISCV:
            #compiler = "riscv64-linux-gnu-gcc -g"
            compiler = "riscv64-linux-gnu-gcc"
        case Target.RISCV_32:
            #compiler = "riscv32-unknown-linux-gnu-gcc -g"
            compiler = "riscv32-unknown-linux-gnu-gcc"
        case Target.ARM_64:
            #compiler = "aarch64-linux-gnu-gcc"
            compiler = "aarch64-linux-gnu-gcc -g"
        case Target.ARM_32:
            #compiler = "arm-linux-gnueabi-gcc -g"
            compiler = "arm-linux-gnueabi-gcc"
        case _:
            msg = f"Do not support Compilation for target {target}"
            raise Exception(msg)

    cmd = f"{compiler} {opts} {inp} -o {out}".split(" ")
    return cmd


class Nop(Enum):
    X86_64 = [0x90]
    X86_32 = [0x90]

    RISCV = [0x13, 0x00, 0x00, 0x00]
    RISCV_COMPACT = [0x01, 0x00]

    ARM_64 = [0xD5, 0x03, 0x20, 0x1F]

    ARM_32 = [0x00, 0x00, 0xA0, 0xE1]

    RISCV_32 = [0x13, 0x00, 0x00, 0x00]
    RISCV_32_COMPACT = [0x01, 0x00]


def disassemble_text_section(
    binary_path: Path,
    always_skip_data: bool = True,
    *,
    binary=None,
    target: Target | None = None,
):
#def disassemble_text_section(binary_path: Path, always_skip_data:bool = False):
    """Disassemble the .text section of the binary and output instructions.

    Use lief to get the bytes from the .text section, then use capstone
    to disassemble the bytes.
    """
    if not binary_path.exists():
        raise Exception("No bin")

    # Parse the binary if one is not provided
    if binary is None:
        binary = lief.parse(binary_path)

    # Find the .text section
    text_section = binary.get_section(".text")
    if not text_section:
        raise ValueError(".text section not found in the binary.")

    if target is None:
        target = detect_target(binary_path)

    match target:

        case Target.X86_64:
            md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        case Target.X86_32:
            md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

        case Target.RISCV:
            md = Cs(
                capstone.CS_ARCH_RISCV,
                capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC,
            )
        case Target.RISCV_32:
            md = Cs(
                capstone.CS_ARCH_RISCV,
                capstone.CS_MODE_RISCV32
                | capstone.CS_MODE_RISCVC
                | capstone.CS_MODE_LITTLE_ENDIAN,
            )
            #try:
            #    md.skipdata = True
            #except Exception:
            #    pass

        case Target.ARM_64:
            md = Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        case Target.ARM_32:
            md = Cs(
                capstone.CS_ARCH_ARM,
                capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN,
            )
        case _:
            msg = f"Target {target} is currently not support by the disassembler"
            raise Exception(msg)

    if always_skip_data:
        md.skipdata = True

    # The below code ensures that we are only mutating the instructions that
    # are _going to be run at startup_....
    #
    # Meaning, sometimes theres nops, trampolines, or code in the .text
    # that is not used. The trampolines specifically may have been causing
    # issues in the riscv decompilation. Therefore, we focus on starting
    # at the entrypoint offset if possible, otherwise just start at index 0 !
    # if not target == Target.RISCV_32:
    start_va = max(binary.entrypoint, text_section.virtual_address)
    start_off = start_va - text_section.virtual_address
    # else:
    #    start_va =  text_section.virtual_address
    #    start_off = start_va - text_section.virtual_address

    code = bytes(text_section.content)
    if 0 <= start_off < len(code):
        insns = list(md.disasm(code[start_off:], start_va))
    else:
        insns = list(md.disasm(code, text_section.virtual_address))

    return insns


def shift_exit_code(x: int) -> int:
    """Shift the exit that python returns to match a linux system.

    When python reads an exit code thats less than
    0, flip its sign and add 128
    """
    if x < 0:
        return 128 + (-1 * x)
    return x


def in_place_patch(in_file: Path, out_file: Path, patch_addr: int, patch_data: bytes):
    """
    Patches a running (virtual) address 'patch_addr' in 'in_file'
    with the bytes in 'patch_data', writing to 'out_file' in place.
    Does NOT remove any debug sections, because it avoids a full rebuild.
    """
    # print(f"   | File: {out_file} inplace at {patch_addr}")

    # Parse the original ELF with LIEF
    binary = lief.parse(in_file)
    if not binary:
        raise RuntimeError(f"Failed to parse {in_file} with LIEF")

    # We must find which segment covers 'patch_addr'
    # Typically .text is in one PT_LOAD segment, so let's search them all:
    segment_found = None
    for seg in binary.segments:
        va_start = seg.virtual_address
        va_end = va_start + seg.virtual_size

        if va_start <= patch_addr < va_end:
            segment_found = seg
            break

    if segment_found is None:
        raise ValueError(f"No segment covers address 0x{patch_addr:x} in {in_file}")

    # Compute the file offset
    # For that segment, the offset in the file that corresponds to 'patch_addr' is:
    #   file_offset_of_address = segment.file_offset + (patch_addr - segment.virtual_address)
    offset_in_file = segment_found.file_offset + (
        patch_addr - segment_found.virtual_address
    )

    # Read the entire file into memory
    with open(in_file, "rb") as f:
        data = bytearray(f.read())

    # Ensure we don't go out of range
    if offset_in_file < 0 or offset_in_file + len(patch_data) > len(data):
        raise ValueError(f"Computed file offset {offset_in_file} is out of range")

    # Overwrite the bytes in-place
    for i, b in enumerate(patch_data):
        data[offset_in_file + i] = b

    # Write out the new file
    with open(out_file, "wb") as f:
        f.write(data)



def get_capstone_arch_mode(filename):
    """
    Given a binary file, return (capstone_arch, capstone_mode) as a tuple
    that can be used to initialize a Capstone disassembler.

    For example:
        - (CS_ARCH_X86, CS_MODE_32) or (CS_ARCH_X86, CS_MODE_64)
        - (CS_ARCH_ARM, CS_MODE_ARM)
        - (CS_ARCH_ARM64, CS_MODE_ARM)
        - (CS_ARCH_MIPS, CS_MODE_32 + CS_MODE_LITTLE_ENDIAN), etc.
    """
    binary = lief.parse(filename)

    # Default return values (in case not recognized)
    cs_arch = None
    cs_mode = None

    # Detect format: ELF, PE, Mach-O, etc.
    binary_format = binary.format

    if binary_format == lief.Binary.FORMATS.ELF:
        # ELF-specific logic
        elf_header = binary.header
        machine_type = (
            elf_header.machine_type
        )  # e.g. lief.ELF.ARCH.x86, lief.ELF.ARCH.ARM, etc.

        # is_64 = (elf_header.identity_class == lief.ELF.ARCH.X86_64)
        # is_le = (elf_header.identity_data == lief.ELF.ELF_DATA.LSB)

        # Map the ELF machine_type to Capstone arch/mode
        if machine_type == lief.ELF.ARCH.X86_64:
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64

            # if is_64 else capstone.CS_MODE_32

        elif machine_type == lief.ELF.ARCH.ARM:
            # NOTE: Differentiating ARM vs. Thumb is not trivial solely from ELF headers
            # Typically defaulting to ARM mode:
            cs_arch = capstone.CS_ARCH_ARM
            # If 64-bit is possible, it might actually be AArch64, see below.
            # Usually 32-bit ARM is ARCH.ARM, but check your use case:
            cs_mode = capstone.CS_MODE_ARM

            if not is_le:
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN

        elif machine_type == lief.ELF.ARCH.AARCH64:
            cs_arch = capstone.CS_ARCH_ARM64
            cs_mode = capstone.CS_MODE_ARM
            if not is_le:
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN

        elif machine_type == lief.ELF.ARCH.MIPS:
            cs_arch = capstone.CS_ARCH_MIPS
            # MIPS can be 32 or 64
            cs_mode = capstone.CS_MODE_MIPS32 if not is_64 else capstone.CS_MODE_MIPS64
            # Add endianness
            if is_le:
                cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN
            else:
                cs_mode |= capstone.CS_MODE_BIG_ENDIAN

        # ... You can add more ELF.ARCH mappings as needed ...

    elif binary_format == lief.EXE_FORMATS.PE:
        # PE-specific logic (Windows binaries)
        # For example, use binary.header.machine (lief.PE.MACHINE)
        # to map to the correct arch.
        pe_header = binary.header
        machine_type = pe_header.machine

        # Example snippet:
        if machine_type in (lief.PE.MACHINE.I386, lief.PE.MACHINE.INTEL_386):
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_32
        elif machine_type == lief.PE.MACHINE.AMD64:
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64
        elif machine_type == lief.PE.MACHINE.ARM:
            cs_arch = capstone.CS_ARCH_ARM
            cs_mode = capstone.CS_MODE_ARM
        elif machine_type == lief.PE.MACHINE.ARM64:
            cs_arch = capstone.CS_ARCH_ARM64
            cs_mode = capstone.CS_MODE_ARM
        # ... etc. ...

    elif binary_format == lief.EXE_FORMATS.MACHO:
        # Mach-O-specific logic (macOS binaries)
        # For example: check binary.header.cputype or .cpusubtype
        macho_header = binary.header
        cputype = macho_header.cpu_type
        is_64 = macho_header.is_64

        # Example snippet:
        if cputype == lief.MachO.CPU_TYPES.X86:
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
        elif cputype == lief.MachO.CPU_TYPES.ARM:
            # Could be 32-bit ARM or 64-bit ARM (ARM64)
            if is_64:
                cs_arch = capstone.CS_ARCH_ARM64
                cs_mode = capstone.CS_MODE_ARM
            else:
                cs_arch = capstone.CS_ARCH_ARM
                cs_mode = capstone.CS_MODE_ARM
        # ... etc. ...

    return cs_arch, cs_mode


def get_lief_arch(filename):
    """
    Given a binary file, return a high-level LIEF architecture enum or identifier.
    For ELF files, this is typically `lief.ELF.ARCH.*`.
    For PE files, it's `lief.PE.MACHINE.*`.
    For Mach-O, it's `lief.MachO.CPU_TYPE.*`.
    """
    binary = lief.parse(filename)
    binary_format = binary.format

    if binary_format == lief.Binary.FORMATS.ELF:
        return (
            binary.header.machine_type
        )  # e.g. lief.ELF.ARCH.x86, lief.ELF.ARCH.ARM, etc.
    elif binary_format == lief.Binary.FORMATS.PE:
        return (
            binary.header.machine
        )  # e.g. lief.PE.MACHINE.I386, lief.PE.MACHINE.AMD64, etc.
    elif binary_format == lief.Binary.FORMATS.MACHO:
        return (
            binary.header.cpu_type
        )  # e.g. lief.MachO.CPU_TYPES.X86, lief.MachO.CPU_TYPES.ARM, etc.
    else:
        # If needed, handle other formats or return None
        return None


def gen_nop_patch(inst: CsInsn, target: Target) -> list[int]:
    """Generate a list of bytes that corresponds to the target's NOP instruction.

    If the target instruction requires 4 NOPs to completely overwrite, then
    the byte sequence for 4 NOPs will be returned.
    """
    match target:
        case Target.X86_64:
            nop = Nop.X86_64
        case Target.X86_32:
            nop = Nop.X86_32
        case Target.RISCV:
            nop = Nop.RISCV_COMPACT
        case Target.RISCV_32:
            nop = Nop.RISCV_32_COMPACT
        case Target.ARM_64:
            nop = Nop.ARM_64
        case Target.ARM_32:
            nop = Nop.ARM_32
        case _:
            raise Exception("No support for nops")

    if len(inst.bytes) % len(nop.value) != 0:
        msg = f"No way to generate nop patch for inst len {len(inst.bytes)} and nop size {len(nop.value)}"
        raise Exception(msg)

    nop_patch = nop.value * int(len(inst.bytes) / len(nop.value))
    return nop_patch


def get_target_nop(target):
    """
    Helper to return the nop for the target arch
    """
    match target:
        case Target.X86_64:
            return Nop.X86_64
        case Target.RISCV:
            return Nop.RISCV_COMPACT
        case Target.ARM_64:
            return Nop.ARM_64
        case Target.ARM_32:
            return Nop.ARM_32
        case _:
            raise ValueError("No support for nops")


def generate_x_bits_mutated_file(
    i, inst_bits, target, inst, common, num_bits
) -> None | Path:
    """
    Flip a contiguous block of bits in an instruction and materialize a mutated binary.

    Parameters
    ----------
    i : int
        Starting bit index to flip.
    inst_bits : list[str]
        Bit-string representation of the original instruction.
    target : Target
        Architecture of the binary (used to validate mutations).
    inst : Any
        Capstone instruction object providing the address/bytes to patch.
    common : CommandParameters
        Experiment settings containing paths and expectations.
    num_bits : int
        Number of consecutive bits to toggle starting at ``i``.

    Returns
    -------
    Path | None
        Path to the mutated binary when the instruction remains valid; ``None`` otherwise.
    """
    binary = lief.parse(common.program_file)

    original_bits = [x for x in inst_bits]

    for x in range(num_bits):
        if original_bits[i + x] == "0":
            original_bits[i + x] = 1
        else:
            original_bits[i + x] = 0

    bit_flipped_inst = "".join([str(x) for x in original_bits])

    # Turn the bits back to an instruction for the patch
    patch = bytes(
        int("".join(bit_flipped_inst[i : i + 8]), 2)
        for i in range(0, len(bit_flipped_inst), 8)
    )

    # If the instruction is not valid, go to the next instruction
    good_inst, new_inst = is_valid_instruction(patch, target)

    if not good_inst:
        return None

    # Re-adjust the patch so that it is a list of ints
    patch = [
        int("".join(bit_flipped_inst[i : i + 8]), 2)
        for i in range(0, len(bit_flipped_inst), 8)
    ]

    # If we get here the instruction is good

    binary.patch_address(inst.address, patch)

    out_file = common.out_dir.joinpath(
        common.program_file.name + f"_{hex(inst.address)}_{i}"
    )
    binary.write(str(out_file.resolve()))

    out_file.chmod(0o755)
    return out_file


def generate_bit_mutated_file(
    i,
    inst_bits,
    target,
    inst,
    common,
    *,
    binary=None,
    original_patch=None,
    out_dir: Path | None = None,
    base_bytes: bytes | None = None,
    patch_offset: int | None = None,
) -> tuple[None, Path]:
    """
    Flip a single bit within an instruction and write the patched binary to disk.

    Parameters
    ----------
    i : int
        Bit index to toggle.
    inst_bits : list[str]
        Bit-string representation of the instruction.
    target : Target
        Architecture of the binary (used for validation).
    inst : Any
        Capstone instruction describing the location being patched.
    common : CommandParameters
        Experiment settings with output directory and reference binary.
    out_dir : Path | None
        Override destination directory for mutated binaries.
    base_bytes : bytes | None
        Raw bytes for the reference binary, used to avoid reparsing with LIEF.
    patch_offset : int | None
        File offset for the instruction to patch when using base_bytes.

    Returns
    -------
    tuple[None, Path]
        ``None`` when the flipped bit produces an invalid instruction, otherwise the
        path to the mutated binary.
    """
    if out_dir is None:
        out_dir = common.out_dir

    original_bits = [x for x in inst_bits]
    if original_bits[i] == "0":
        original_bits[i] = 1
    else:
        original_bits[i] = 0

    bit_flipped_inst = "".join([str(x) for x in original_bits])

    # Turn the bits back to an instruction for the patch
    patch = bytes(
        int("".join(bit_flipped_inst[i : i + 8]), 2)
        for i in range(0, len(bit_flipped_inst), 8)
    )

    # If the instruction is not valid, go to the next instruction
    good_inst, new_inst = is_valid_instruction(patch, target)

    if not good_inst:
        return None

    # Re-adjust the patch so that it is a list of ints
    patch = [
        int("".join(bit_flipped_inst[i : i + 8]), 2)
        for i in range(0, len(bit_flipped_inst), 8)
    ]

    out_file = out_dir.joinpath(common.program_file.name + f"_{hex(inst.address)}_{i}")

    if base_bytes is not None and patch_offset is not None:
        patch_len = len(patch)
        if patch_offset < 0 or patch_offset + patch_len > len(base_bytes):
            return None
        mutated = bytearray(base_bytes)
        mutated[patch_offset : patch_offset + patch_len] = bytes(patch)
        out_file.write_bytes(mutated)
        out_file.chmod(0o755)
        return out_file

    if binary is None:
        binary = lief.parse(common.program_file)
    if original_patch is None:
        original_patch = list(inst.bytes)

    # If we get here the instruction is good
    binary.patch_address(inst.address, patch)
    try:
        binary.write(str(out_file.resolve()))
        out_file.chmod(0o755)
    finally:
        binary.patch_address(inst.address, original_patch)
    return out_file


def generate_data_bit_flip(
    binary_path: Path, data_idx: int, data_bit_idx: int, out_file: Path, target_section: str = ".data"
) -> Path:
    """
    Flip a specific bit inside a writeable section (default: ``.data``) and emit a new binary.

    Parameters
    ----------
    binary_path : Path
        Path to the source binary.
    data_idx : int
        Byte index within the target section to modify.
    data_bit_idx : int
        Bit position (0-7) inside the byte to toggle.
    out_file : Path
        Destination path for the mutated binary.
    target_section : str, optional
        Section name to mutate, default is ``\".data\"``.

    Returns
    -------
    Path
        Path to the mutated binary.
    """
    # Load the ELF binary
    binary = lief.parse(binary_path)

    # Find the .data section
    section = binary.get_section(target_section)

    if not section:
        raise ValueError("No section found in the binary.")

    # Get the content of the .data section (the raw bytes)
    data_bytes = bytearray(section.content)

    # Check if data_idx is within the bounds of the .data section
    if data_idx >= len(data_bytes):
        raise ValueError(
            f"Data index {data_idx} is out of bounds for the .data section."
        )

    # Get the byte at data_idx
    byte_to_modify = data_bytes[data_idx]

    # Flip the bit at the specified data_bit_idx (0-based bit index)
    if data_bit_idx < 0 or data_bit_idx >= 8:
        raise ValueError("data_bit_idx must be between 0 and 7.")

    # Flip the bit by toggling it using XOR
    modified_byte = byte_to_modify ^ (1 << data_bit_idx)

    data_bytes[data_idx] = modified_byte

    # Rewrite the .data section with the modified data
    section.content = list(data_bytes)

    binary.write(str(out_file.absolute()))

    out_file.chmod(0o755)
    return out_file


# def generate_data_mutated_bin(
#    binary: Path, target, data_idx, bit_idx, output: Path
# ) -> Path:
#    """Geneate a single mutated binary.
#
#    Replace all the instructions with the nop patch for this target
#    architecture.
#    """
#
#    shutil.copy(binary, output)
#
#    # Run many patches - patching in place so they all get applied
#    for inst in instructions:
#        nop_patch = gen_nop_patch(inst, target=target)
#        in_place_patch(output, output, inst.address, bytes(nop_patch))
#
#    output.chmod(0o755)
#
#    return output


def generate_nops_mutated_bin(
    binary: Path,
    target,
    instructions: list,
    output: Path,
    *,
    base_bytes: bytes | None = None,
    text_section_offset: int | None = None,
    text_section_vaddr: int | None = None,
) -> Path:
    """Generate a single mutated binary.

    Replace all the instructions with the nop patch for this target
    architecture.
    """
    if (
        base_bytes is not None
        and text_section_offset is not None
        and text_section_vaddr is not None
    ):
        # Run the new method that resuses the same bytes
        mutated = bytearray(base_bytes)
        for inst in instructions:
            nop_patch = gen_nop_patch(inst, target=target)
            patch_offset = text_section_offset + (inst.address - text_section_vaddr)
            patch_len = len(nop_patch)
            if patch_offset < 0 or patch_offset + patch_len > len(mutated):
                raise ValueError(
                    f"Computed file offset {patch_offset} is out of range for {binary}"
                )
            mutated[patch_offset : patch_offset + patch_len] = bytes(nop_patch)
        output.write_bytes(mutated)
        output.chmod(0o755)
        return output

    # Otherwise run the wold method 

    shutil.copy(binary, output)

    # Run many patches - patching in place so they all get applied
    for inst in instructions:
        nop_patch = gen_nop_patch(inst, target=target)
        in_place_patch(output, output, inst.address, bytes(nop_patch))

    output.chmod(0o755)

    return output


def detect_target_from_binary(binary) -> Target:
    """
    Detect the target of a parsed LIEF binary.
    """
    lief_arch = binary.header.machine_type

    match lief_arch:
        case lief.ELF.ARCH.X86_64:
            return Target.X86_64

        case lief.ELF.ARCH.I386:
            return Target.X86_32

        case lief.ELF.ARCH.RISCV:
            is_64 = binary.header.identity_class == lief.ELF.Header.CLASS.ELF64
            return Target.RISCV if is_64 else Target.RISCV_32

        case lief.ELF.ARCH.ARM:
            return Target.ARM_32

        case lief.ELF.ARCH.AARCH64:
            return Target.ARM_64

        case _:
            msg = f"The target architecture of {lief_arch} is unknown."
            raise ValueError(msg)


def detect_target(bin: Path) -> Target:
    """
    Detect the target of the binary
    """
    binary = lief.parse(bin)
    return detect_target_from_binary(binary)


def count_bit_differences(bytes_1, bytes_2):
    """
    Count the number of different bits in the two instructions.
    """
    if len(bytes_1) != len(bytes_2):
        return float("inf")  # Ensure same size; otherwise, reject

    diff_bits = 0
    for b1, b2 in zip(bytes_1, bytes_2, strict=False):
        diff_bits += bin(b1 ^ b2).count("1")  # Count bitwise differences

    return diff_bits


def timed_run_binary_w_input(
    path: Path, program_input: str, target: Target, timeout: int = 60
):
    """Run a binary with QEMU and record its runtime.

    Run a binary and capture its output
    """
    print(f"Running with target: {target}")

    if program_input[-1:] != "\n":
        program_input += "\n"

    cmd = generate_run_cmd(path, target)

    # Verify that the path exists and is a file
    if not path.is_file():
        print(f"Error: The path '{path}' does not exist or is not a file.")
        return "", "", "", ""

    start = datetime.now()

    # Run the compiled C program
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    try:
        # Gather the outputs
        stdout, stderr = process.communicate(
            input=program_input.encode(), timeout=timeout
        )
    except subprocess.TimeoutExpired:
        _terminate_process_group(process)
        stdout, stderr = b"", b"timeout expired"
    if process.returncode is None:
        process.returncode = LinuxExitCodes.EX_SIGSEGV

    runtime = datetime.now() - start

    return (
        process.returncode,
        stdout.decode(),
        stderr.decode(),
        runtime.total_seconds(),
    )


def run_binary_w_calltime_input(
    path: Path, program_input: str, target: Target, timeout: int = 60
) -> tuple[int | None, str, str] | None:
    """
    This function will provide the input at execution time.

    For example:
    ```
    ./my_binary arg1
    ```
    """
    cmd = generate_run_cmd(path, target)
    cmd.append(program_input)

    # Verify that the path exists and is a file
    if not path.is_file():
        print(f"Error: The path '{path}' does not exist or is not a file.")
        return None

    # Run the compiled C program
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    try:
        # Gather the outputs
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_group(process)
        stdout, stderr = b"TIMEOUT", b"timeout expired"
        return None, stdout.decode(), stderr.decode()

    # TODO: Allow for returncode of None
    # if process.returncode is None:
    #    process.returncode = LinuxExitCodes.EX_SIGSEGV - 255

    try: 
        out = stdout.decode()
    except UnicodeDecodeError:
        out = ""

    return process.returncode, out, ""  # stderr.decode()


def run_binary_w_input(
    path: Path, program_input: str, target: Target, timeout: int = 60
) -> tuple[int | None, str | None, str | None]:
    """
    Run a binary and capture its output
    """
    # TODO: Robust handle here?
    if program_input[-1:] != "\n":
        program_input += "\n"

    cmd = generate_run_cmd(path, target)

    # Verify that the path exists and is a file
    if not path.is_file():
        print(f"Error: The path '{path}' does not exist or is not a file.")
        return None, None, None

    # Run the compiled C program
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    try:
        # Gather the outputs
        stdout, stderr = process.communicate(
            input=program_input.encode(), timeout=timeout
        )
    except subprocess.TimeoutExpired:
        _terminate_process_group(process)
        stdout, stderr = b"TIMEOUT", b"timeout expired"
        return None, stdout.decode(), stderr.decode()
    return process.returncode, stdout.decode(), stderr.decode()


def is_valid_instruction(opcode_bytes, target):
    """
    Check if the provided byte sequence is a valid instruction
    """
    match target:
        case Target.X86_64:
            md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        case Target.X86_32:
            md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        case Target.RISCV:
            md = Cs(
                capstone.CS_ARCH_RISCV,
                capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC,
            )
        case Target.RISCV_32:
            md = Cs(
                capstone.CS_ARCH_RISCV,
                capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC,
            )
        case Target.ARM_64:
            md = Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        case Target.ARM_32:
            md = Cs(
                capstone.CS_ARCH_ARM,
                capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN,
            )
        case _:
            raise Exception

    md.skipdata = False
    md.detail = False

    try:
        # Attempt to disassemble the opcode
        instructions = list(
            md.disasm(opcode_bytes, 0x1000)
        )  # 0x1000 is a dummy address

        if not instructions:
            # No instructions decoded
            return False, None

        # Check if the entire byte sequence was consumed by the disassembler
        total_size = sum(insn.size for insn in instructions)
        return total_size == len(opcode_bytes), instructions

    except capstone.CsError:
        # An error occurred during disassembly
        return False, None
    except Exception as e:
        print(f"Could not validate correct instruction {e}")
        return False, None



class Target(Enum):
    X86_32 = 0
    RISCV = 2
    ARM_64 = 3
    ARM_32 = 4
    RISCV_32 = 5
    X86_64 = 6


def generate_run_cmd_custom_qemu(
    inp: Path,
    target: Target,
    qemu_base: Path | None = None,
) -> list[str]:
    """
    Produce the QEMU command that runs the given binary for the given target.
    If qemu_base is provided, QEMU binaries are searched there.
    Names used are the upstream-standard QEMU user-mode binaries:

        qemu-x86_64
        qemu-i386
        qemu-riscv64
        qemu-riscv32
        qemu-arm
        qemu-aarch64

    The sysroot -L directories stay the same, since they depend on the *guest*
    ABI, not how QEMU was built.
    """
    inp = inp.expanduser().absolute()

    def qemu_path(name: str) -> str:
        if qemu_base is not None:
            return str((qemu_base / name).expanduser().absolute())
        return name  # fallback to PATH-based discovery (e.g., /usr/bin)

    match target:
        case Target.X86_64:
            # Native execution on host
            return [str(inp), "-g"]

        case Target.X86_32:
            return [
                qemu_path("qemu-i386"),
                "-L", "/usr/i386-linux-gnu",
                str(inp),
                "-g",
            ]

        case Target.RISCV:
            return [
                qemu_path("qemu-riscv64"),
                "-L", "/usr/riscv64-linux-gnu",
                str(inp),
            ]

        case Target.RISCV_32:
            return [
                qemu_path("qemu-riscv32"),
                "-L", "/usr/riscv32-linux-gnu",
                str(inp),
            ]

        case Target.ARM_32:
            return [
                qemu_path("qemu-arm"),
                "-L", "/usr/arm-linux-gnueabi",
                str(inp),
            ]

        case Target.ARM_64:
            return [
                qemu_path("qemu-aarch64"),
                "-L", "/usr/aarch64-linux-gnu",
                str(inp),
            ]

        case _:
            raise Exception(f"Unsupported target {target}")
    return


def generate_run_cmd(
    inp: Path,
    target: Target,
    qemu_base: Path | None = None,
) -> list[str]:
    """Run the binary with the QEMU backend (where applicable).

    If qemu_base is provided, QEMU binaries are resolved as qemu_base / name.
    Otherwise, fall back to /usr/bin or bare names as appropriate.
    """
    inp = inp.expanduser().absolute()

    # Helper for building full path to a QEMU binary
    def qemu_path(name: str) -> str:
        if qemu_base is not None:
            return str((qemu_base / name).expanduser().absolute())
        # Default to /usr/bin/name to match your current layout
        return f"/usr/bin/{name}"

    match target:
        case Target.X86_64:
            # Native execution on host (no QEMU). If you later want QEMU here,
            # just change this branch.
            return [str(inp), "-g"]

        case Target.X86_32:
            return [
                qemu_path("qemu-i386-static"),  # or "qemu-i386" if that's what you build
                "-L",
                "/usr/i386-linux-gnu",
                str(inp),
                "-g",
            ]

        case Target.RISCV:
            return [
                qemu_path("qemu-riscv64-static"),  # or "qemu-riscv64"
                "-L",
                "/usr/riscv64-linux-gnu",
                str(inp),
            ]

        case Target.RISCV_32:
            return [
                qemu_path("qemu-riscv32-static"),  # or "qemu-riscv32"
                "-L",
                "/usr/riscv32-linux-gnu",
                str(inp),
            ]

        case Target.ARM_32:
            # For ARM you were using plain "qemu-arm-static" (no /usr/bin)
            # We can still run it through qemu_path for consistency:
            return [
                qemu_path("qemu-arm-static"),  # or "qemu-arm"
                "-L",
                "/usr/arm-linux-gnueabi",
                str(inp),
            ]

        case Target.ARM_64:
            return [
                qemu_path("qemu-aarch64-static"),  # or "qemu-aarch64"
                "-L",
                "/usr/aarch64-linux-gnu",
                str(inp),
            ]

        case _:
            raise Exception(f"Unsupported target {target}")
            
    return

def compile_program(
    inp: Path, out: Path, target: Target, optimization: OptimizationLevel, opts:str | None,
) -> Path:
    """Compile a program for a specific arch and specific target."""
    if not out.parent.exists():
        out.parent.mkdir(parents=True)

    match target:
        case Target.X86_64:
            compiler = "gcc -g"
        case Target.X86_32:
            compiler = "gcc -m32 -g"
        case Target.RISCV:
            compiler = "riscv64-linux-gnu-gcc -g"
        case Target.RISCV_32:
            compiler = "riscv32-unknown-linux-gnu-gcc -g"
        case Target.ARM_64:
            compiler = "aarch64-linux-gnu-gcc -g"
        case Target.ARM_32:
            compiler = "arm-linux-gnueabi-gcc -g"
        case _:
            raise Exception("No support for nops")

    if opts:
        cmd = f"{compiler} -O{optimization.value} {inp} -o {out} {opts}".split(" ")
    else:
        cmd = f"{compiler} -O{optimization.value} {inp} -o {out}".split(" ")

    try:
        subprocess.run(cmd, check=False)
        if not out.exists():
            msg = f"Failed to compile. Command was: {cmd}"
            raise Exception(msg)
        return out
    except Exception as e:
        # TODO
        print(f"[ERRORRRRRRRRRRRRRR] Error compiling with command: {cmd}")
        print(e)
        raise e


def disasm(
    binary: list[Path],
    start_addr: int,
    end_addr: int,
    text: bool = True,
    verbose: bool = False,
    pad: int = 2,
) -> str:
    """
    An over-engineered function to re-create objdump... but this allows
    me to easily inject its results into a PDF report! :D (and also make
    the output colorful)

    start_addr: int
        The decimal 10 start address
    end_addr: int
        The decimal 10 end address
    """
    pretty_insns = []
    for bin in binary:
        disassembly = disassemble_text_section(bin)

        filter_disasm = [
            x for x in disassembly if x.address >= start_addr and x.address <= end_addr
        ]
        if len(filter_disasm) == 0:
            raise Exception("Disasm length is zero")

        # Max len of just the bytes
        max_len = max(
            len(" ".join([f"{b:02x}" for b in x.bytes])) for x in filter_disasm
        )
        max_len += pad

        # Gruvbox color codes (24-bit ANSI)
        GRUVBOX_BLUE = "\033[38;2;131;165;152m"  # #83a598
        GRUVBOX_GRAY = "\033[38;2;146;131;116m"  # #928374
        GRUVBOX_ORANGE = "\033[38;2;254;128;25m"  # #fe8019
        GRUVBOX_YELLOW = "\033[38;2;250;189;47m"  # #fabd2f

        bin_pretty_insns = []
        # Iterate over the instructions in the range of the addrs
        for thing in filter_disasm:
            # Crate the bytes array
            byte_ar = thing.bytes
            byte_string = " ".join([f"{b:02x}" for b in byte_ar])

            if not text:
                #                   ADDR                               # BYTE                            # OPCODES + OPCODE
                res_str = f"{GRUVBOX_BLUE}0x{thing.address:x} {GRUVBOX_GRAY}{byte_string:<{max_len}} {GRUVBOX_ORANGE}{thing.mnemonic} {GRUVBOX_YELLOW}{thing.op_str}"
            else:
                #               ADDR               BYTES                   OPCODE             OPSTR
                res_str = f"0x{thing.address:x} {byte_string:<{max_len}} {thing.mnemonic} {thing.op_str}"

            white_res_str = f"0x{thing.address:x} {byte_string:<{max_len}} {thing.mnemonic} {thing.op_str}"
            bin_pretty_insns.append((white_res_str, res_str))

        pretty_insns.append(bin_pretty_insns)

    if len(pretty_insns) == 2:
        total = compare_disassembly(
            pretty_insns[0],
            pretty_insns[1],
            name1=binary[0].name,
            name2=binary[1].name,
            text=text,
            verbose=verbose,
        )
    elif len(pretty_insns) == 1:
        total = []
        for line in pretty_insns[0]:
            print(line)
    else:
        total = []
        print("")

    return total


def compare_disassembly(
    lines_a,
    lines_b,
    name1,
    name2,
    text: bool = False,
    verbose: bool = False,
) -> str:
    """
    Prints two lists of disassembly lines side by side, making it easy
    to compare them line by line.

    :param lines_a: list of strings (disassembly lines for binary A)
    :param lines_b: list of strings (disassembly lines for binary B)
    :param column_width: width allocated for each column
    """
    white_a = [x[0] for x in lines_a]
    white_b = [x[0] for x in lines_b]
    nice_a = [x[1] for x in lines_a]
    nice_b = [x[1] for x in lines_b]

    # Determine the max number of lines
    max_lines = max(len(white_a), len(white_b))

    max_left = max(len(x) for x in nice_a)
    max_right = max(len(x) for x in nice_b)

    short_max_left = max(len(x) for x in white_a)
    short_max_right = max(len(x) for x in white_b)

    i_pad = len(str(max_lines))

    if not text:
        GRUVBOX_YELLOW = "\033[38;2;250;189;47m"  # #fabd2f
    else:
        GRUVBOX_YELLOW = ""

    if not text or verbose:

        print(
            f"{GRUVBOX_YELLOW}{'-':<{i_pad}}|{GRUVBOX_YELLOW} {name1:<{short_max_left - 1}}|{GRUVBOX_YELLOW} {name2:<{short_max_right - 1}}{GRUVBOX_YELLOW}|"
        )
        print(
            f"{GRUVBOX_YELLOW}{'-':<{i_pad}}{GRUVBOX_YELLOW}|{'-' * (short_max_left)}|{'-' * short_max_right}|"
        )

    total = ""

    for i in range(max_lines):
        left_line = nice_a[i] if i < len(nice_a) else ""
        right_line = nice_b[i] if i < len(nice_b) else ""

        if left_line == "":
            out = (
                f"{GRUVBOX_YELLOW}{i:<{i_pad}}"
                + "|"
                + f"{' ' * short_max_left}"
                + "|"
                + f"{right_line:<{max_right}}"
                + "|"
            )
        elif right_line == "":
            out = (
                f"{GRUVBOX_YELLOW}{i:<{i_pad}}" + "|"
                f"{left_line:<{max_left}}" + "|" + f"{' ' * short_max_right}" + "|"
            )
        else:
            out = (
                f"{GRUVBOX_YELLOW}{i:<{i_pad}}" + "|"
                f"{left_line:<{max_left}}" + "|" + f"{right_line:<{max_right}}" + "|"
            )

        if not text or verbose:
            print(out)

        total += f"{out}\n"

    return total


def delete_mutated_binaries(*dfs: pd.DataFrame) -> int:
    """
    Delete binaries referenced by the provided dataframes.

    The helper returns the number of files removed so callers can emit
    a concise status message.
    """
    deleted = 0
    seen_paths: set[str] = set()

    for df in dfs:
        if df is None or getattr(df, "empty", True):
            continue

        if "binary_path" not in df.columns:
            continue

        for raw_path in df["binary_path"].dropna().unique():
            path = Path(str(raw_path))
            path_key = str(path)

            if path_key in seen_paths:
                continue

            seen_paths.add(path_key)

            try:
                if path.exists():
                    path.unlink()
                    deleted += 1
            except OSError as exc:
                print(f"Failed to delete {path}: {exc}")

    return deleted
