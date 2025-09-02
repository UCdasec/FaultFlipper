from datetime import datetime
import angr
import subprocess
from enum import Enum
import lief
from pathlib import Path
from capstone import CsInsn
import shutil
from angr.exploration_techniques import Timeout
import capstone
from capstone import Cs
import psutil, os, angr


class OptimizationLevel(Enum):
    O0 = "0"
    O1 = "1"
    O2 = "2"
    O3 = "3"
    OZ = "z"


class MemLimiter(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, max_gb: int, stash="out_of_memory"):
        super().__init__()
        self.proc = psutil.Process(os.getpid())
        self.limit = max_gb * (1 << 30)
        self.cap = max_gb
        self.triggered = False
        self.stash = stash

    def _over(self):
        return self.proc.memory_info().rss > self.limit

    def step(self, simgr, stash="active", **kwargs):
        if self._over():
            self.triggered = True
            # if self.proc.memory_info().rss > self.cap * (1<<30):
            simgr.move(from_stash=stash, to_stash=self.stash)
            return simgr
        return simgr.step(stash=stash, **kwargs)


class Target(Enum):
    X86_32 = 0
    RISCV = 2
    ARM_64 = 3
    ARM_32 = 4
    RISCV_32 = 5
    X86_64 = 6


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


def generate_compile_cmd(inp: Path, out: Path, target: Target) -> list[str]:
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
            compiler = "riscv64-linux-gnu-gcc"
        case Target.ARM_64:
            compiler = "aarch64-linux-gnu-gcc"
        case Target.ARM_32:
            compiler = "arm-linux-gnueabi-gcc"
        case _:
            msg = f"Do not support Compilation for target {target}"
            raise Exception(msg)

    cmd = f"{compiler} {inp} -o {out}".split(" ")
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


def disassemble_text_section(binary_path):
    """
    Disassemble the .text section of the binary and output instructions.
    """

    if not binary_path.exists():
        raise Exception("No bin")

    # Parse the binary
    binary = lief.parse(binary_path)

    # Find the .text section
    text_section = binary.get_section(".text")
    if not text_section:
        raise ValueError(".text section not found in the binary.")

    target = detect_target(binary_path)

    match target:
        case Target.X86_64:
            md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        case Target.X86_32:
            md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        case Target.RISCV:
            md = Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64)

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

    start_va = max(binary.entrypoint, text_section.virtual_address)
    start_off = start_va - text_section.virtual_address

    code = bytes(text_section.content)
    if 0 <= start_off < len(code):
        insns = list(md.disasm(code[start_off:], start_va))
    else:
        insns = list(md.disasm(code, text_section.virtual_address))
    return insns
    return list(md.disasm(bytes(text_section.content), text_section.virtual_address))


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

    return


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
    """Generate a list of bytes that corresponds to the targets NOP instruction.

    If the target instructio requies 4 NOPS to completely overwrite, then
    the byte sequence for 4 nops will be returned
    """

    match target:
        case Target.X86_64:
            nop = Nop.X86_64
        case Target.X86_32:
            nop = Nop.X86_32
        case Target.RISCV:
            nop = Nop.RISCV_COMPACT
        case Target.ARM_64:
            nop = Nop.ARM_64
        case Target.ARM_32:
            nop = Nop.ARM_32
        case _:
            raise Exception("No support for nops")

    if len(inst.bytes) % len(nop.value) != 0:
        msg = f"No way to generate nop patch for inst len {len(inst.bytes)} and nop size {len(nop.value)}"
        raise Exception(msg)

    nop_patch = nop.value * int((len(inst.bytes) / len(nop.value)))
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


def generate_double_bit_mutated_file(
    i, inst_bits, target, inst, common
) -> tuple[None, Path | None]:
    binary = lief.parse(common.program_file)

    original_bits = [x for x in inst_bits]
    if original_bits[i] == "0":
        original_bits[i] = 1
    else:
        original_bits[i] = 0

    if original_bits[i + 1] == "0":
        original_bits[i + 1] = 1
    else:
        original_bits[i + 1] = 0

    bit_flipped_inst = "".join([str(x) for x in original_bits])

    # Turn the bits back to an instruction for the patch
    patch = bytes(
        int("".join(bit_flipped_inst[i : i + 8]), 2)
        for i in range(0, len(bit_flipped_inst), 8)
    )

    # If the instruction is not valid, go to the next instruction
    good_inst, new_inst = is_valid_instruction(patch, target)

    if not good_inst:
        return None, None

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


def generate_bit_mutated_file(i, inst_bits, target, inst, common) -> tuple[None, Path]:
    binary = lief.parse(common.program_file)

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

    # If we get here the instruction is good

    binary.patch_address(inst.address, patch)
    out_file = common.out_dir.joinpath(
        common.program_file.name + f"_{hex(inst.address)}_{i}"
    )
    binary.write(str(out_file.resolve()))

    out_file.chmod(0o755)
    return out_file


def generate_nops_mutated_bin(
    binary: Path, target, instructions: list, output: Path
) -> Path:
    """Geneate a single mutated binary.

    Replace all the instructions with the nop patch for this target 
    architecture.
    """

    shutil.copy(binary, output)

    # Run many patches - patching in place so they all get applied
    for inst in instructions:
        nop_patch = gen_nop_patch(inst, target=target)
        in_place_patch(output, output, inst.address, bytes(nop_patch))

    output.chmod(0o755)

    return output


# def generate_double_nop_mutated_bin(common, target, inst1, inst2) -> Path:
def generate_double_nop_mutated_bin(
    program_file: Path, target, inst1, inst2, out_file: Path
) -> Path:
    """
    Geneate a single mutated binary
    """

    # out_file = common.out_dir.joinpath(
    #    common.program_file.name + f"_{hex(inst1.address)}"
    # )

    shutil.copy(program_file, out_file)
    nop_patch = gen_nop_patch(inst1, target=target)
    # in_place_patch(common.program_file, out_file, inst1.address, bytes(nop_patch))
    in_place_patch(program_file, out_file, inst1.address, bytes(nop_patch))

    nop_patch = gen_nop_patch(inst2, target=target)
    in_place_patch(out_file, out_file, inst2.address, bytes(nop_patch))

    out_file.chmod(0o755)

    return out_file


def generate_nop_mutated_bin(common, target, inst) -> Path:
    """
    Geneate a single mutated binary
    """

    out_file = common.out_dir.joinpath(
        common.program_file.name + f"_{hex(inst.address)}"
    )

    shutil.copy(common.program_file, out_file)
    nop_patch = gen_nop_patch(inst, target=target)

    in_place_patch(common.program_file, out_file, inst.address, bytes(nop_patch))
    out_file.chmod(0o755)

    return out_file


def _generate_nop_mutated_bin(source: Path, target, inst, out_dir: Path) -> Path:
    """
    Geneate a single mutated binary
    """

    out_file = out_dir.joinpath(source.name + f"_{hex(inst.address)}")

    shutil.copy(source, out_file)
    nop_patch = gen_nop_patch(inst, target=target)

    in_place_patch(source, out_file, inst.address, bytes(nop_patch))
    out_file.chmod(0o755)

    return out_file


def detect_target(bin: Path) -> Target:
    """
    Detect the target of the binary
    """
    # parsed = lief.parse(bin)
    lief_arch = get_lief_arch(bin)

    match lief_arch:
        case lief.ELF.ARCH.X86_64:
            return Target.X86_64

        case lief.ELF.ARCH.I386:
            return Target.X86_32

        case lief.ELF.ARCH.RISCV:
            return Target.RISCV

        # case lief.ELF.ARCH.RISC:
        #    return Target.RISCV_32

        case lief.ELF.ARCH.ARM:
            return Target.ARM_32

        case lief.ELF.ARCH.AARCH64:
            return Target.ARM_64
        case _:
            msg = f"The target architecture of {lief_arch} is unknown."
            raise ValueError(msg)
    return


def count_bit_differences(bytes_1, bytes_2):
    """
    Count the number of different bits in the two instructions.
    """
    if len(bytes_1) != len(bytes_2):
        return float("inf")  # Ensure same size; otherwise, reject

    diff_bits = 0
    for b1, b2 in zip(bytes_1, bytes_2):
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
    cmd = ["timeout", f"{timeout}s"] + cmd

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
    )

    try:
        # Gather the outputs
        stdout, stderr = process.communicate(
            input=program_input.encode(), timeout=timeout
        )
    except subprocess.TimeoutExpired:
        process.kill()
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
    This function will provide the input at execturion time.

    For example:
    ```
    ./my_binary arg1
    ```
    """

    cmd = generate_run_cmd(path, target)
    cmd = ["timeout", f"{timeout}s"] + cmd
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
    )

    try:
        # Gather the outputs
        stdout, stderr = process.communicate(timeout=timeout + 0.5)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = b"TIMEOUT", b"timeout expired"
        return None, stdout.decode(), stderr.decode()

    # TODO: Allow for returncode of None
    # if process.returncode is None:
    #    process.returncode = LinuxExitCodes.EX_SIGSEGV - 255

    return process.returncode, stdout.decode(), ""  # stderr.decode()


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
    cmd = ["timeout", f"{timeout}s"] + cmd

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
    )

    try:
        # Gather the outputs
        stdout, stderr = process.communicate(
            input=program_input.encode(), timeout=timeout
        )
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = b"TIMEOUT", b"timeout expired"
        return None, stdout.decode(), stderr.decode()
    return process.returncode, stdout.decode(), stderr.decode()


def is_valid_instruction(opcode_bytes, target):
    """
    Check if the provided byte sequence is a valid insturction
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


def generate_run_cmd(inp: Path, target: Target) -> list[str]:
    """Run the binary with the qemu backend.

    Run the binary using the corresponding QEMU emulator.
    """

    match target:
        case Target.X86_64:
            return [f"{inp.expanduser().absolute()}", "-g"]

        case Target.X86_32:
            return ["/usr/bin/qemu-i386-static",
                    "-L", 
                    "/usr/i386-linux-gnu", 
                    f"{inp.expanduser().absolute()}", 
                    "-g"]

        case Target.RISCV:
            return f"/usr/bin/qemu-riscv64-static -L /usr/riscv64-linux-gnu {inp.expanduser().absolute()}".split(
                " "
            )

        # TODO: Static bins don't need the linker
        case Target.ARM_32:
            return [
                "qemu-arm-static",
                "-L",
                "/usr/arm-linux-gnueabi",
                f"{inp.expanduser().absolute()}",
            ]
        case Target.ARM_64:
            return [
                "qemu-aarch64-static",
                "-L",
                "/usr/aarch64-linux-gnu",
                f"{inp.expanduser().absolute()}",
            ]
        case Target.RISCV_32:
            return [
                    "/usr/bin/qemu-riscv32-static",
                    "-L",
                    "/usr/riscv32-linux-gnu",
                    f"{inp.expanduser().absolute()}",
                ]

        case _:
            raise Exception(f"Unsupported target {target}")
    return


def old_sim_binary_w_input(bin: Path, inp: str):
    """
    Simulate the binary with ANGR
    """

    proj = angr.Project(bin, load_options={"auto_load_libs": False})
    pwd = inp.encode()
    cfg = proj.analyses.CFGFast()

    stdin_sf = angr.SimFile("stdin", content=pwd)

    state = proj.factory.full_init_state(stdin=stdin_sf)

    funcs = [v.name for _, v in cfg.functions.items()]

    addr_list = [x.addr for _, x in cfg.functions.items()]
    addr_list.sort()
    addr_set = list(set(addr_list))
    addr_set.sort()

    if len(addr_list) != len(addr_set):
        print(addr_list)
        print(addr_set)
        raise ValueError

    if addr_list != addr_set:
        print(f"Addr list: \n{addr_list}")
        print(f"Addr set: \n{addr_set}")
        raise ValueError

    captured = {}

    # def after_ret(s):
    #    if s.callstack.func_addr not in [x.addr for x in funcs]:
    #        return
    #
    #    cur_regs = {}
    #    for name in s.arch.registers.keys():
    #        bv = getattr(s.regs, name)
    #        cur_regs[name] = s.solver.eval(bv, cast_to=int)

    #    key =  addr_to_name[s.callstack.func_addr]

    #    if key not in captured.keys():
    #        captured[key] = []

    #    #captured[addr_to_name[s.callstack.func_addr]] = cur_regs
    #    captured[key].append(cur_regs)

    def ret_hook(fn_name):
        def _after_ret(s):
            cur_regs = {}
            for name in s.arch.registers.keys():
                bv = getattr(s.regs, name)
                cur_regs[name] = s.solver.eval(bv, cast_to=int)

            if fn_name not in captured.keys():
                captured[fn_name] = []
            captured[fn_name].append(cur_regs)

        return _after_ret

    # for func in funcs:
    #    if func.is_plt:
    #        continue
    #    # For every return site in the chosen function
    #    for r in func.ret_sites:
    #        state.inspect.b(
    #            'instruction',
    #            #when=angr.BP_BEFORE,
    #            when=angr.BP_AFTER,
    #            instruction=r.addr,
    #            action=ret_hook(func.name),
    #        )

    for func_name in funcs:
        cur_func = cfg.functions.function(name=func_name)
        if cur_func is None:
            captured[func_name] = []
            continue

            # For every return site in the chosen function
        state.inspect.b(
            #'instruction',
            "return",
            # when=angr.BP_AFTER,
            when=angr.BP_BEFORE,
            # instruction=pwd_clk.addr,
            function_address=cur_func.addr,
            action=ret_hook(func_name),
        )

    simgr = proj.factory.simulation_manager(state).run()

    dead = simgr.deadended[0]
    stdout = dead.posix.dumps(1).decode()
    ret = get_program_rc(dead)

    return ret, stdout, captured


def fast_sim_binary_w_input(bin: Path, inp: str, func_names: str):
    """
    Use a automatic prototype grabbing and execute the
    function directly with unicorn

    This requries knownledge aout the function arguments however
    """

    # proj = angr.Project(bin, load_options={'auto_load_libs': False}, add_options=angr.options.unicorn | {angr.options.LAZY_SOLVES})
    proj = angr.Project(bin, load_options={"auto_load_libs": False})
    extra_options = angr.options.unicorn | {angr.options.LAZY_SOLVES}

    cfg = proj.analyses.CFGFast()

    proj.analyses.CompleteCallingConventions(recover_variables=True)

    assert [x in [y.name for _, y in cfg.functions.items()] for x in func_names]

    # Setup the CFG parser

    # CFGFast only does static lifting...
    stdin_sf = angr.SimFile("stdin", content=inp.encode())

    print(f"Init state")
    # Initialiaitve the sim state
    state = proj.factory.full_init_state(stdin=stdin_sf, options=extra_options)

    captured = {}

    # Define a hook to capture register values based on
    # function name
    def ret_hook(fn_name):
        def _after_ret(s):
            cur_regs = {}

            # Solve for all register values
            for name in s.arch.registers.keys():
                bv = getattr(s.regs, name)
                cur_regs[name] = s.solver.eval(bv, cast_to=int)

            # Add all register information into captured dict
            if fn_name not in captured.keys():
                captured[fn_name] = []
            captured[fn_name].append(cur_regs)

        return _after_ret

    # Iterate over all functions
    # for _, func in cfg.functions.items():
    for func in func_names:
        # cur_func = cfg.functions.function(name=func.name)

        cur_func = cfg.functions.function(name=func)

        if cur_func is None:
            captured[func] = []
            continue
        captured[func] = []

        ret = proj.factory.callable(
            cur_func.addr, prototype=proto.c_prototype(), concrete_only=True
        )

        regs = {
            name: st.solver.eval(getattr(ret.regs, name), cast_to=int)
            for name in ret.arch.registers
        }

        captured[func] = [regs]

        # For every return site in the chosen function
        # state.inspect.b(
        #            'return',
        #            when=angr.BP_BEFORE,
        #            function_address=cur_func.addr,
        #            action=ret_hook(func)
        #        )

    # Run the simulation
    simgr = proj.factory.simulation_manager(state).run()

    # Dead is the deadend state of the program
    dead = simgr.deadended[0]
    stdout = dead.posix.dumps(1).decode()
    ret = get_program_rc(dead)

    return ret, stdout, captured


def sim_binary_w_calltime_input(
    bin: Path, inp: str, func_names: list[str], timeout, max_gb: int = 24
):
    """
    Simulate the binary with ANGR
    """

    proj = angr.Project(bin, load_options={"auto_load_libs": False})

    # TODO: This caused a segfault but should be possible soon
    extra_options = angr.options.unicorn | {angr.options.LAZY_SOLVES}
    cfg = proj.analyses.CFGFast()

    assert [x in [y.name for _, y in cfg.functions.items()] for x in func_names], (
        "Function names missing!"
    )

    # Setup the CFG parser

    # CFGFast only does static lifting...
    # stdin_sf = angr.SimFile("stdin", content=inp.encode())

    # Initialiaitve the sim state
    # state = proj.factory.full_init_state(stdin=stdin_sf, options=extra_options)
    state = proj.factory.full_init_state(args=["ignored", inp])

    captured = {}

    # Define a hook to capture register values based on
    # function name
    def ret_hook(fn_name):
        def _after_ret(s):
            cur_regs = {}

            # Solve for all register values
            for name in s.arch.registers.keys():
                bv = getattr(s.regs, name)
                cur_regs[name] = s.solver.eval(bv, cast_to=int)

            # Add all register information into captured dict
            if fn_name not in captured.keys():
                captured[fn_name] = []
            captured[fn_name].append(cur_regs)

        return _after_ret

    # Iterate over all functions
    for func in func_names:
        cur_func = cfg.functions.function(name=func)

        if cur_func is None:
            captured[func] = []
            continue

        # For every return site in the chosen function
        state.inspect.b(
            "return",
            when=angr.BP_BEFORE,
            function_address=cur_func.addr,
            action=ret_hook(func),
        )

    # Run the simulation
    simgr = proj.factory.simulation_manager(state)

    time_limiter = Timeout(timeout)
    simgr.use_technique(time_limiter)
    mem_limiter = MemLimiter(max_gb=max_gb)
    simgr.use_technique(mem_limiter)

    simgr.run()

    if len(simgr.deadended) != 0:
        # Dead is the deadend state of the program
        dead = simgr.deadended[0]
        stdout = dead.posix.dumps(1).decode()
        ret = get_program_rc(dead)
    else:
        stdout = ""
        ret = "error"

    if mem_limiter.triggered:
        ret = "mem_limit"
    elif simgr.stashes.get("timeout"):
        ret = "timeout"

    return ret, stdout, captured


def sim_binary_w_input(
    bin: Path, inp: str, func_names: list[str], timeout, max_gb: int = 24
):
    """
    Simulate the binary with ANGR
    """

    proj = angr.Project(bin, load_options={"auto_load_libs": False})

    # TODO: This caused a segfault but should be possible soon
    extra_options = angr.options.unicorn | {angr.options.LAZY_SOLVES}
    cfg = proj.analyses.CFGFast()

    assert [x in [y.name for _, y in cfg.functions.items()] for x in func_names], (
        "Function names missing!"
    )

    # Setup the CFG parser

    # CFGFast only does static lifting...
    stdin_sf = angr.SimFile("stdin", content=inp.encode())

    # Initialiaitve the sim state
    # state = proj.factory.full_init_state(stdin=stdin_sf, options=extra_options)
    state = proj.factory.full_init_state(stdin=stdin_sf)

    captured = {}

    # Define a hook to capture register values based on
    # function name
    def ret_hook(fn_name):
        def _after_ret(s):
            cur_regs = {}

            # Solve for all register values
            for name in s.arch.registers.keys():
                bv = getattr(s.regs, name)
                cur_regs[name] = s.solver.eval(bv, cast_to=int)

            # Add all register information into captured dict
            if fn_name not in captured.keys():
                captured[fn_name] = []
            captured[fn_name].append(cur_regs)

        return _after_ret

    # Iterate over all functions
    for func in func_names:
        cur_func = cfg.functions.function(name=func)

        if cur_func is None:
            captured[func] = []
            continue

        # For every return site in the chosen function
        state.inspect.b(
            "return",
            when=angr.BP_BEFORE,
            function_address=cur_func.addr,
            action=ret_hook(func),
        )

    # Run the simulation
    simgr = proj.factory.simulation_manager(state)

    time_limiter = Timeout(timeout)
    simgr.use_technique(time_limiter)
    mem_limiter = MemLimiter(max_gb=max_gb)
    simgr.use_technique(mem_limiter)

    simgr.run()

    if len(simgr.deadended) != 0:
        # Dead is the deadend state of the program
        dead = simgr.deadended[0]
        stdout = dead.posix.dumps(1).decode()
        ret = get_program_rc(dead)
    else:
        stdout = ""
        ret = "error"

    if mem_limiter.triggered:
        ret = "mem_limit"
    elif simgr.stashes.get("timeout"):
        ret = "timeout"

    return ret, stdout, captured


def get_program_rc(s):
    """
    Handle for the concrete exit status of a whole program
    """
    if hasattr(s, "exit_code"):  # modern angr
        return s.solver.eval(s.exit_code)

    if "exit_code" in s.globals:  # older angr
        return s.solver.eval(s.globals["exit_code"])

    # fallback: grab the arch's conventional return register
    ret_reg = s.arch.register_names.get(s.arch.ret_offset)
    return s.solver.eval(getattr(s.regs, ret_reg))


def compile_program(
    inp: Path, out: Path, target: Target, optimization: OptimizationLevel
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
        case Target.ARM_64:
            compiler = "aarch64-linux-gnu-gcc -g"
        case Target.ARM_32:
            compiler = "arm-linux-gnueabi-gcc -g"
        case _:
            raise Exception("No support for nops")

    cmd = f"{compiler} -O{optimization.value} {inp} -o {out}".split(" ")

    try:
        subprocess.run(cmd)
        if not out.exists():
            raise Exception(f"Failed to compile program")
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
        The decimsal 10 end address
    """

    pretty_insns = []
    for bin in binary:
        disassembly = disassemble_text_section(bin)

        filter_disasm = [
            x for x in disassembly if x.address >= start_addr and x.address <= end_addr
        ]
        if len(filter_disasm) == 0:
            raise Exception("Diasm length is zero")

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
        logger.debug("Using pretty lines")
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




