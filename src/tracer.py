#!/usr/bin/env python3

"""
CLI Usage:
  1) Explicitly provide critical instruction addresses:
     python critical_detector_elftools.py \
       --binary ./my_program \
       --stdin "my test input" \
       --critical-asm 0x4005c7 0x4005d2 0x400600 \
       --csv-out critical_hits.csv

  2) Provide a C source and a list of critical line numbers,
     letting pyelftools+Capstone figure out the addresses:
     python critical_detector_elftools.py \
       --binary ./my_program \
       --source ./my_program.c \
       --critical-source-lines 42 43 44 \
       --stdin "secret" \
       --csv-out critical_hits.csv

What it does:
  - If you pass --critical-asm, we directly parse those as hex addresses.
  - Otherwise, you must pass --source plus --critical-source-lines;
    we then use pyelftools (DWARF) to map those line numbers to instruction addresses.
  - Next, we run the binary under angr in a "concrete" mode with optional stdin.
  - We intercept each IRSB (basic block) to see if it matches any critical address,
    and count how many times each address was executed.
  - Finally, we present a Rich table of addresses + hit counts, and optionally export to CSV.

Requirements:
  - Python 3.7+ (for dataclasses)
  - pip install pyelftools capstone angr rich
  - Binary compiled with debug symbols (-g), so DWARF line info is present.
  - For multi-arch (x86_64, ARM64, RISC-V), ensure angr supports that arch,
    and Capstone is installed with the needed architectures.
"""

import argparse
import os
import sys
from cli import Target, get_capstone_arch_mode
from dataclasses import dataclass, field
from typing import List, Dict, Optional

import angr
import claripy

from cyclopts import App, Parameter
from typing import Annotated, Optional
from rich.table import Table
from rich.console import Console
from typing_extensions import Annotated
from enum import Enum
from pathlib import Path
from enums import LinuxExitCodes


# For reading DWARF debug info
from elftools.elf.elffile import ELFFile

# For disassembly
from capstone import (
    Cs,
    CS_ARCH_X86, CS_MODE_64,
    CS_ARCH_ARM64, CS_MODE_ARM,
    CS_ARCH_RISCV, CS_MODE_RISCV64
)

# For pretty output
from rich.table import Table
from rich.console import Console

console = Console()
app = App()


@dataclass
class CriticalHitResult:
    """
    Represents each "critical" instruction address and how many times it was executed.
    """
    address: int
    hit_count: int = field(default=0)

    def to_dict(self) -> Dict[str, str]:
        """
        Convert to dict for easy CSV or Pandas usage.
        """
        return {
            "address": f"0x{self.address:x}",
            "hit_count": str(self.hit_count),
        }


def parse_args():
    parser = argparse.ArgumentParser(description="Detect if critical instructions/lines are executed using angr, pyelftools, and Capstone.")
    parser.add_argument("--binary", required=True, help="Path to the ELF binary (must be compiled with -g for DWARF).")
    parser.add_argument("--stdin", default=None, help="Optional stdin content to feed the binary.")
    
    # Option A: Provide a list of ASM addresses directly
    parser.add_argument("--critical-asm", nargs="+", help="List of addresses (hex) considered critical, e.g.: 0x4005c7 0x4005d2.")
    
    # Option B: Provide a source file + lines, from which we find addresses via DWARF line info
    parser.add_argument("--source", help="Path to the C source file. Required if no --critical-asm is given.")
    parser.add_argument("--critical-source-lines", type=str, nargs="+",
                        help="One or more line numbers (or ranges) in the source that are critical, e.g.: 42 43 44 or 42-50.")
    
    parser.add_argument("--csv-out", help="Path to output CSV file with results (optional).")
    parser.add_argument("--arch", default="x86_64", choices=["x86_64","arm64","riscv"],
                        help="Architecture of the binary (used by Capstone). Default: x86_64")
    
    return parser.parse_args()


def parse_line_numbers(line_specs: List[str]) -> List[int]:
    """
    Parse a list of line specs which could be single integers (e.g., "42")
    or ranges (e.g., "40-45"). Return a flat list of all line numbers.

    Example: ["40", "42-44", "46"] -> [40, 42, 43, 44, 46]
    """
    lines = []
    for spec in line_specs:
        if "-" in spec:
            start_s, end_s = spec.split("-", 1)
            start, end = int(start_s), int(end_s)
            lines.extend(range(start, end+1))
        else:
            lines.append(int(spec))
    return sorted(set(lines))


#def find_addresses_with_pyelftools(binary_path: str, source_path: str, critical_lines: List[int]) -> List[int]:

def find_addresses_with_pyelftools(binary: Path, source_path: Path, critical_lines: List[int], base_addr:int, arch: Target) -> tuple[List[int], Dict]:
    """
    Use pyelftools to parse DWARF line info in the ELF and gather addresses
    corresponding to the given line numbers in source_path.
    
    We'll also do a minimal disassembly with Capstone so we can return
    *actual instruction addresses* for each line region. This helps ensure
    we gather all instructions relevant to that line (since one line
    can map to multiple instructions).
    
    Return a unique list of addresses (ints).
    """
    addresses = set()

    # Open ELF
    with open(binary, "rb") as bf:
        elffile = ELFFile(bf)
        if not elffile.has_dwarf_info():
            raise RuntimeError("No DWARF debug info found in the binary. Recompile with -g.")

        dwarfinfo = elffile.get_dwarf_info()
        text_section = elffile.get_section_by_name('.text')

        if text_section is None:
            raise RuntimeError("No .text section found in the ELF.")
        
        text_data = text_section.data()
        text_vaddr = text_section['sh_addr']  # The load address of .text

        # Setup Capstone for the requested architecture
        # (If you're dealing with 32-bit or different modes, adapt as needed)
        arch_mode_map = {
            "x86_64": (CS_ARCH_X86, CS_MODE_64),
            "arm64":  (CS_ARCH_ARM64, CS_MODE_ARM),
            "riscv":  (CS_ARCH_RISCV, CS_MODE_RISCV64),
        }

        cs_arch, cs_mode = get_capstone_arch_mode(binary)

        #if arch_mode_map.get(arch.name.lower()) is None:
        #    raise ValueError(f"Unsupported architecture: {arch}")

        #cs_arch, cs_mode = arch_mode_map[arch]
        md = Cs(cs_arch, cs_mode)

        # We'll gather all (address -> line) mappings from the DWARF line tables
        addr_to_line = {}  # maps instruction address -> line number
        #print(f" The length of cus is {len(list(dwarfinfo.iter_CUs()))}")
        for cu in dwarfinfo.iter_CUs():
            line_program = dwarfinfo.line_program_for_CU(cu)

            if not line_program:
                continue

            for entry in line_program.get_entries():

                state = entry.state

                if state is None:
                    continue

                if state.file == 0 or state.line == 0:
                    continue

                file_entry = line_program['file_entry'][state.file - 1]
                file_name = file_entry.name.decode("utf-8", errors="ignore")
                # Check if it matches our source filename (base name or exact path)
                if os.path.basename(file_name) == os.path.basename(source_path):
                    addr_to_line[state.address] = state.line
                else:
                    raise Exception("Basename does not match")

        if addr_to_line == {}:
            raise Exception("Error mapping addrs to lines")

        # Next, disassemble the .text section and see which instructions map
        # to line numbers of interest.
        for insn in md.disasm(text_data, text_vaddr):
        #for insn in md.disasm(text_data, base_addr):
            # Find the line number for this instruction by looking up the
            # "nearest" address in addr_to_line. Typically, line tables will
            # give the "start address" for a block of instructions. We'll do
            # a naive approach: find the largest address <= insn.address in
            # addr_to_line. This is a bit hacky but common in line table usage.
            candidate_lines = []
            # direct match?
            if insn.address in addr_to_line:
                candidate_lines.append(addr_to_line[insn.address])
            else:
                # find the largest address in addr_to_line that is <= insn.address
                # This is a linear search; if performance is an issue,
                # you can do a bisect on sorted keys.
                best_line = None
                best_addr = None
                for a, ln in addr_to_line.items():
                    if a <= insn.address:
                        if best_addr is None or a > best_addr:
                            best_addr = a
                            best_line = ln
                if best_line is not None:
                    candidate_lines.append(best_line)

            # If the line for this instruction is in our critical set, record the address
            if any(ln in critical_lines for ln in candidate_lines):
                addresses.add(insn.address)

    return sorted(addresses), addr_to_line


#def run_angr_concrete(binary_path: str, critical_addrs: List[int], stdin_data: Optional[str] = None) -> tuple[Dict[int, int], int]:
def run_angr_concrete(binary_path: str, stdin_data: Optional[str] = None) -> tuple[Dict[int, int], int]:
    """
    Load the binary into angr, feed it optional stdin (concretely),
    and track how many times each address in critical_addrs is executed.
    
    Return a dict { address -> hit_count }.
    """
    proj = angr.Project(binary_path, auto_load_libs=False)
    base_addr = proj.loader.main_object.min_addr 

    # Provide optional stdin
    if stdin_data is not None:
        sim_stdin = angr.SimFileStream(name='stdin', content=stdin_data + '\n')
        state = proj.factory.full_init_state(stdin=sim_stdin)
    else:
        state = proj.factory.full_init_state()

    #hit_map = {addr: 0 for addr in critical_addrs}
    hit_map = {}

    def block_callback(st):
        # Called before each IRSB (block). st.addr is the address of the block.
        if st.addr in hit_map:
            hit_map[st.addr] += 1
        else:
            hit_map[st.addr] = 1

    # Attach the callback
    state.inspect.b('irsb', when=angr.BP_BEFORE, action=block_callback)

    simgr = proj.factory.simulation_manager(state)
    simgr.run()

    for deadend_state in simgr.deadended:
        stdout = deadend_state.posix.dumps(1)
        print(f"The program had stdout: {stdout}")

    return hit_map, base_addr


def print_results_rich(results: List[CriticalHitResult]):
    """
    Pretty-print the results in a Rich table.
    """
    table = Table(title="Critical Instruction Hits (pyelftools + Capstone + angr)")
    table.add_column("Instruction Address", style="bold")
    table.add_column("Hit Count", justify="right")

    for r in results:
        table.add_row(f"0x{r.address:x}", str(r.hit_count))

    console = Console()
    console.print(table)


def save_results_csv(results: List[CriticalHitResult], csv_path: str):
    """
    Save the results to CSV format.
    """
    import csv
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["address", "hit_count"])
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_dict())

@app.command()
def trace(
    binary,
    stdin,
    critical_asm:Optional[list[str]] = None,
    source:Optional[Path] = None,
    critical_source_lines: Optional[list[str]] = None,
    csv_out: Optional[Path] = None,
    arch: Target = Target.X86_64,
):
    """
    Trace the program. 

    Two options:
    (1) Provide source code + critical lines 
    (2) Provide asm critcal lines
    """

    # 
    hit_map, base_addr = run_angr_concrete(binary,  stdin_data=stdin)

    # Determine the set of "critical" addresses to monitor
    if critical_asm is not None:
        # We have direct addresses
        critical_addresses = [int(x, 16) for x in critical_asm]
    else:
        # We must have a source file + lines
        if not source or not critical_source_lines:
            print("Error: If --critical-asm is not provided, you must specify --source and --critical-source-lines.")
            sys.exit(1)

        #critcial_source_lines = critical_source_lines.split('-')
        print( critical_source_lines)

        # Parse the line(s) or range(s)
        critical_lines = parse_line_numbers(critical_source_lines)

        # Use pyelftools & capstone to find the instruction addresses for those lines
        critical_addresses, addr_to_line = find_addresses_with_pyelftools(binary, source, critical_lines, base_addr, arch)

    if not critical_addresses:
        print("No critical addresses resolved. Exiting.")
        return

    new_map = {}
    for val in critical_addresses:
        if (x:=val+base_addr) in hit_map.keys():
            new_map[val] = hit_map[x]
        else:
            new_map[val] = 0

    # Build result objects
    results = []
    for addr in sorted(new_map.keys()):
        results.append(CriticalHitResult(address=addr, hit_count=new_map[addr]))

    # Print with Rich
    print_results_rich(results)

    # Optionally save to CSV
    if csv_out:
        save_results_csv(results, csv_out)
        print(f"[+] Results saved to {csv_out}")

if __name__ == "__main__":
    app()

