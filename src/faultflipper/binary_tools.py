from datetime import datetime
import subprocess
from enum import Enum
import lief
from pathlib import Path
from capstone import CsInsn
import shutil

import capstone

from capstone import Cs


class Target(Enum):
    X86_64 = 0
    RISCV = 2
    ARM_64 = 3
    ARM_32 = 4
    RISCV_32 = 5


class Nop(Enum):
    X86_64 = [0x90]
    RISCV = [0x13, 0x00, 0x00, 0x00]
    RISCV_COMPACT = [0x01, 0x00]

    # Below is good endianness for how we read it :) 
    ARM_64 = [0xd5, 0x03, 0x20, 0x1f] 

    #ARM_32 = [0xe1, 0xa0, 0x00, 0x00] # bad endianness
    ARM_32 = [0x00, 0x00, 0xA0, 0xE1]
    RISCV_32 = [0x13, 0x00, 0x00, 0x00]
    RISCV_32_COMPACT = [0x01, 0x00]



def shift_exit_code(x: int) -> int:
    """
    When python reads an exit code thats less than 
    0, flip its sign and add 128
    """
    if x < 0:
        return 128 + (-1 * x)
    return x


def in_place_patch(
    in_file: str,
    out_file: str,
    patch_addr: int,
    patch_data: bytes
):
    """
    Patches a running (virtual) address 'patch_addr' in 'in_file'
    with the bytes in 'patch_data', writing to 'out_file' in place.
    Does NOT remove any debug sections, because it avoids a full rebuild.

    This is a minimal example. It:
      1) Parses the ELF with LIEF to find which loadable segment covers 'patch_addr'.
      2) Computes the file offset corresponding to 'patch_addr'.
      3) Overwrites that region in the input file, saving the result to 'out_file'.

    Parameters:
      in_file   : Path to the original ELF binary (with debug info).
      out_file  : Where to write the patched ELF.
      patch_addr: The *virtual* address you want to patch (e.g. 0x4012cf).
      patch_data: The bytes you want to place there (e.g. b'\\x90\\x90').
    """

    # Parse the original ELF with LIEF
    binary = lief.parse(in_file)
    if not binary:
        raise RuntimeError(f"Failed to parse {in_file} with LIEF")

    # We must find which segment covers 'patch_addr'
    # Typically .text is in one PT_LOAD segment, so let's search them all:
    segment_found = None
    for seg in binary.segments:
        va_start = seg.virtual_address
        va_end   = va_start + seg.virtual_size
        if va_start <= patch_addr < va_end:
            segment_found = seg
            break

    if segment_found is None:
        raise ValueError(f"No segment covers address 0x{patch_addr:x} in {in_file}")

    # Compute the file offset
    # For that segment, the offset in the file that corresponds to 'patch_addr' is:
    #   file_offset_of_address = segment.file_offset + (patch_addr - segment.virtual_address)
    offset_in_file = segment_found.file_offset + (patch_addr - segment_found.virtual_address)

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

    #print(f"Patched 0x{patch_addr:x} in {in_file}, wrote result to {out_file}")

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
            cs_mode = (
                capstone.CS_MODE_MIPS32
                if not is_64
                else capstone.CS_MODE_MIPS64
            )
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
    """
    Rewrite the instruction with nop
    """

    match target:
        case Target.X86_64:
            nop = Nop.X86_64
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



def generate_double_bit_mutated_file(
    i, inst_bits, target, inst, common
) -> tuple[None, Path|None]:
    binary = lief.parse(common.program_file)

    original_bits = [x for x in inst_bits]
    if original_bits[i] == "0":
        original_bits[i] = 1
    else:
        original_bits[i] = 0

    if original_bits[i+1] == "0":
        original_bits[i+1] = 1
    else:
        original_bits[i+1] = 0


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



def generate_bit_mutated_file(
    i, inst_bits, target, inst, common
) -> tuple[None, Path]:
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





def generate_nops_mutated_bin(common, target, instructions:list) -> Path:
    """
    Geneate a single mutated binary
    """

    out_file = common.out_dir.joinpath(
        common.program_file.name + f"_{hex(instructions[0].address)}"
    )

    shutil.copy(common.program_file, out_file)

    # Run many patches - patching in place so they all get applied
    for inst in instructions:
        nop_patch = gen_nop_patch(inst, target=target)
        in_place_patch(common.program_file, out_file, inst.address, bytes(nop_patch))
    out_file.chmod(0o755)

    return out_file



def generate_double_nop_mutated_bin(common, target, inst1, inst2) -> Path:
    """
    Geneate a single mutated binary
    """

    out_file = common.out_dir.joinpath(
        common.program_file.name + f"_{hex(inst1.address)}"
    )

    shutil.copy(common.program_file, out_file)
    nop_patch = gen_nop_patch(inst1, target=target)
    in_place_patch(common.program_file, out_file, inst1.address, bytes(nop_patch))

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

def _generate_nop_mutated_bin(source:Path, target, inst, out_dir:Path) -> Path:
    """
    Geneate a single mutated binary
    """

    out_file = out_dir.joinpath(
        source.name + f"_{hex(inst.address)}"
    )

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

        case lief.ELF.ARCH.RISCV:
            return Target.RISCV

        #case lief.ELF.ARCH.RISC:
        #    return Target.RISCV_32

        case lief.ELF.ARCH.ARM:
            return Target.ARM_32

        case lief.ELF.ARCH.AARCH64:
            return Target.ARM_64
        case _:
            raise ValueError(
                "This script is intended for x86_64 ELF binaries only."
            )
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
    """
    Run a binary and capture its output
    """

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
)->tuple[int|None, str, str] | None:
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
        stdout, stderr = process.communicate(
            timeout=timeout+.5
        )
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = b"TIMEOUT", b"timeout expired"
        return None, stdout.decode(), stderr.decode()

    #TODO: Allow for returncode of None
    #if process.returncode is None:
    #    process.returncode = LinuxExitCodes.EX_SIGSEGV - 255

    return process.returncode, stdout.decode(), "" #stderr.decode()



def run_binary_w_input(
    path: Path, program_input: str, target: Target, timeout: int = 60
)->tuple[int|None, str|None, str|None]:
    """
    Run a binary and capture its output
    """

    #TODO: Robust handle here? 
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

    :param opcode_bytes: Byte sequence representing the opcode.
    :return: Boolean indicating the validity of the instruction.
    """

    match target:
        case Target.X86_64:
            md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        case Target.RISCV:
            md = Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC)
        case Target.ARM_64:
            md = Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        case Target.ARM_32:
            md = Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)
        case _:
            raise Exception

    # Initialize Capstone for x86_64
    # md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    md.skipdata = False  # Stop disassembly on invalid data
    md.detail = False  # We don't need detailed operand info

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
        print(e)
        return False, None


def generate_run_cmd(inp: Path, target: Target) -> list[str]:
    """
    Create the compile command
    """

    match target:
        case Target.X86_64:
            #TODO: Useing the -g for debug symbols
            return [f"{inp.expanduser().absolute()}", "-g" ]
        case Target.RISCV:
            return f"/usr/bin/qemu-riscv64-static -L /usr/riscv64-linux-gnu {inp.expanduser().absolute()}".split(
                " "
            )

        #TODO: Static bins don't need the linker
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
            cmd = f"/usr/bin/qemu-riscv32-static -L /usr/riscv32-linux-gnu {inp.expanduser().absolute()}".split(
                " "
            )
            logger.debug(f"Command is : {cmd}")
            return cmd

        case _:
            raise Exception(f"Unsupported target {target}")
    return


