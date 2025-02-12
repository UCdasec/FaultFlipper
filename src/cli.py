import lief
import shutil
import copy
import dynaconf
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import json
import warnings
from dataclasses import dataclass, fields
from bitstring import BitArray
from pathlib import Path
from capstone import (
    Cs,
    CS_ARCH_X86,
    CS_MODE_64,
    CS_ARCH_RISCV,
    CS_MODE_RISCV64,
    CS_MODE_RISCVC,
)

import capstone
from cyclopts import App, Parameter
from typing import Annotated, Optional
from rich.table import Table
from rich.console import Console
from typing_extensions import Annotated
from enum import Enum
import subprocess
import pandas as pd
from capstone import CsInsn
from enums import LinuxExitCodes

# All faults are a patch of some kind.


from dataclasses import dataclass
from typing import Union, Any
from alive_progress import alive_it

DEFAULT_LOGS = Path("faultsim_log")
if not DEFAULT_LOGS.exists():
    DEFAULT_LOGS.mkdir()


def shift_python_code(x: int) -> int:
    if x < 0:
        return 128 + (-1 * x)
    return x


class Mutation(Enum):
    NOP = 0
    BIT = 1


class Target(Enum):
    X86_64 = 0
    RISCV = 2
    ARM_64 = 3
    ARM_32 = 4


class Nop(Enum):
    X86_64 = [0x90]
    RISCV = [0x13, 0x00, 0x00, 0x00]
    RISCV_COMPACT = [0x01, 0x00]
    ARM_64 = [0xBF, 0x00]
    ARM_32 = [0xE1, 0xA0, 0x00, 0x00]


@Parameter(name="*")
@dataclass
class CommandParameters:
    program_file: Path
    out_dir: Path
    program_input: str
    expected_stdout: str
    expected_returncode: int
    list_expected: bool = False
    timeout: int = 5
    save_results: Union[Path, None] = None
    yes: bool = False

    def to_dict(self):

        if self.save_results is None:
            self.save_results = Path("")

        return {
                "program_file" : str(self.program_file.absolute()),
                "out_dir" : str(self.out_dir.absolute()),
                "program_input" : self.program_input,
                "expected_stdout" : self.expected_stdout,
                "expected_returncode" : self.expected_returncode,
                "list_expected" : self.list_expected,
                "timeout" : self.timeout,
                "save_results" : str(self.save_results.absolute()),
                "yes" : self.yes,
        }


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


@dataclass
class BinaryContext:
    # The capstone arch
    cap_arch: Any
    cap_mod: Any
    lief_arch: Any
    # arch: int
    # mode: Union[int, tuple[int,...]]

    # md = Cs(CS_ARCH_X86, CS_MODE_64)


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

    # The nop patch needs to take the same numer of bytes! 
    # So if the nop is 4 bytes and the instruction is 4 bytes, 
    # then we only patch with 1 nop
    #nop_patch = nop.value * len(inst.bytes)

    if len(inst.bytes) % len(nop.value) != 0:
        msg = f"No way to generate nop patch for inst len {len(inst.bytes)} and nop size {len(nop.value)}"
        raise Exception(msg)

    nop_patch = nop.value * int((len(inst.bytes)/len(nop.value)))
    return nop_patch


console = Console()
app = App()


def generate_run_cmd(inp: Path, target: Target) -> list[str]:
    """
    Create the compile command
    """

    match target:
        case Target.X86_64:
            return [f"{inp.expanduser().absolute()}"]
        case Target.RISCV:
            return f"/usr/bin/qemu-riscv64-static -L /usr/riscv64-linux-gnu {inp.expanduser().absolute()}".split(
                " "
            )
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
        case _:
            raise Exception(f"Unsupported target {target}")
    return


def para_run_binary_w_input(binary, common, inst, target: Target):
    """
    Run a binary and capture its output
    """

    nop_patch = gen_nop_patch(inst, target=target)

    # Patch the bytes at the given virtual address
    binary.patch_address(inst.address, nop_patch)
    out_file = common.out_dir.joinpath(
        common.program_file.name + f"_{hex(inst.address)}"
    )
    binary.write(str(out_file.resolve()))

    out_file.chmod(0o755)

    cmd = generate_run_cmd(out_file, target)
    cmd = ["timeout", f"{common.timeout}s"] + cmd

    # Verify that the path exists and is a file
    if not out_file.is_file():
        print(f"Error: The path '{out_file}' does not exist or is not a file.")
        return

    try:
        # Run the compiled C program
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Gather the outputs
        stdout, stderr = process.communicate(
            input=common.program_input.encode(), timeout=common.timeout
        )
        stdout, stderr = process.communicate()
        return (
            out_file,
            process.returncode,
            inst,
            common,
            target,
            stdout.decode(),
            stderr.decode(),
        )
    except Exception as e:
        print(e)
        return out_file, -100, inst, common, target, "", ""


def run_binary_w_input(
    path: Path, program_input: str, target: Target, timeout: int = 60
):
    """
    Run a binary and capture its output
    """

    if program_input[-2:] != "\n":
        program_input += "\n"

    cmd = generate_run_cmd(path, target)
    cmd = ["timeout", f"{timeout}s"] + cmd

    # Verify that the path exists and is a file
    if not path.is_file():
        print(f"Error: The path '{path}' does not exist or is not a file.")
        return

    # Run the compiled C program
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Gather the outputs
    stdout, stderr = process.communicate(
        input=program_input.encode(), timeout=timeout
    )
    # stdout, stderr = process.communicate()

    return process.returncode, stdout.decode(), stderr.decode()


def get_addrs(binary_path: Path):
    """
    get all the instuctions addrs in binary
    """

    binary = lief.parse(binary_path)

    if not binary:
        raise ValueError("Failed to parse the binary.")

    # Identify the code section (usually .text for ELF/Mach-O, or a code section in PE)
    # For simplicity, let's assume ELF/Mach-O and look for ".text"
    text_section = binary.get_section(".text")

    if not text_section:
        # For PE binaries, you might look for a section with execute permissions
        # E.g., something like:
        # text_section = next((s for s in binary.sections if s.characteristics & lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE), None)
        raise ValueError(
            "No .text section found. Adjust the code to find the code section in this binary."
        )

    # Extract the raw bytes and the virtual address of the .text section
    code_bytes = list(text_section.content)
    code_va = text_section.virtual_address

    # Convert the list of bytes into a bytes object for disassembly
    code_data = bytes(code_bytes)

    # Initialize Capstone for x86-64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False  # We only need instruction addresses, not details

    instruction_addresses = []

    # Disassemble the entire code section
    for insn in md.disasm(code_data, code_va):
        instruction_addresses.append(insn)

    return instruction_addresses


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
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
        case Target.ARM_64:
            md = Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        case Target.ARM_32:
            md = Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
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


class Mutation(Enum):
    NOP = 0
    BITFLIP = 1


# @dataclass
# class BitFlipExperimentResult:
#    binary_path: Path
#    return_code: int
#    flipped_addr: int
#    flipped_index: int
#    program_inp: str
#    target: Target
#    expected_return_code: int
#    other_returncodes: list[tuple[str, int]]
#
#    def to_dict(self):
#        """
#        Convert to a dictionary.. usually for a dataframe
#        """
#
#
#
#        return {
#            "experiment_type": "bit",
#            "expected_return_code": self.expected_return_code,
#            "flipped_addr": self.flipped_addr,
#            "flipped_index": self.flipped_index,
#            "return_code": self.return_code,
#            "program_inp": self.program_inp,
#            "target": self.target.name,
#            "other_returncodes": json.dumps(self.other_returncodes),
#            "binary_path": self.binary_path.expanduser().absolute(),
#        }


@dataclass
class MutationExperiment:
    original_program_file: Path
    binary_path: Path
    return_code: int
    program_input: str
    program_stdout: str
    target: Target
    expected_stdout: str
    expected_returncode: int
    custom_returncodes: list[tuple[str, int]]

    def to_dict(self):
        """
        Convert the dataclass to a dictionary
        """
        result = {}

        for field in fields(self):
            value = getattr(self, field.name)
            if isinstance(
                value, dict
            ):  # If the value is another dataclass, convert it
                result[field.name] = json.dumps(value)
            elif isinstance(
                value, Path
            ):  # Handle lists/dicts that might contain dataclasses
                result[field.name] = value.absolute()
            elif isinstance(
                value, Target
            ):  # Handle lists/dicts that might contain dataclasses
                result[field.name] = value.name
            elif value is None:
                result[field.name] = ""
            else:
                result[field.name] = value
        return result


@dataclass
class BitFlipExperimentResult(MutationExperiment):
    flipped_addr: int
    flipped_index: int
    mutation: str = "single_bit"
    source_code: Optional[Path] = None


@dataclass
class NopExperimentResult(MutationExperiment):
    nopped_addr: int
    mutation: str = "nop"
    source_code: Optional[Path] = None


@app.command
def bit(common: CommandParameters):
    """
    Patch all the addrs in the binar , and save bins that
    have a succesffuly exist code what running WITH NO FLAGS
    """

    common.out_dir.mkdir(exist_ok=True)
    disasm = disassemble_text_section(common.program_file)

    if not common.yes:
        cont = str(
            input(
                f"Will make {len(disasm)} mutated binaries, continue? (Yy/Nn)"
            )
        )
        if cont.lower() != "y":
            return

    target = detect_target(common.program_file)
    results: list[BitFlipExperimentResult] = []

    total_possible_inst = 0
    total_correct_inst = 0

    binary = lief.parse(common.program_file)

    other_returncodes = [
        ("password_accepted", 0),
        ("password_denied", 97),
        ("failed_to_run", 1),
    ]

    # For every instructions
    for inst in alive_it(disasm):
        # Need to pad the left with zeroes
        inst_bits = list(
            "".join([str(bin(byte)[2:]).zfill(8) for byte in inst.bytes])
        )

        # For every bit see if we get a valid opcode.
        for i in range(len(inst_bits)):
            original_bits = [x for x in inst_bits]

            if original_bits[i] == "0":
                original_bits[i] = 1
            else:
                original_bits[i] = 0

            total_possible_inst += 1

            bit_flipped_inst = "".join([str(x) for x in original_bits])

            # Turn the bits back to an instruction for the patch
            patch = bytes(
                int("".join(bit_flipped_inst[i : i + 8]), 2)
                for i in range(0, len(bit_flipped_inst), 8)
            )

            # If the instruction is not valid, go to the next instruction
            good_inst, new_inst = is_valid_instruction(patch, target)

            if not good_inst:
                continue

            inst_bits = list(
                "".join([str(bin(byte)[2:]).zfill(8) for byte in inst.bytes])
            )

            total_correct_inst += 1

            # Re-adjust the patch so that it is a list of ints
            patch = [
                int("".join(bit_flipped_inst[i : i + 8]), 2)
                for i in range(0, len(bit_flipped_inst), 8)
            ]

            # If we get here the instruction is good

            # Patch the bytes at the given virtual address
            binary.patch_address(inst.address, patch)
            out_file = common.out_dir.joinpath(
                common.program_file.name + f"_{hex(inst.address)}_{i}"
            )
            binary.write(str(out_file.resolve()))

            out_file.chmod(0o755)

            # Test the binary
            try:
                status, stdout, _ = run_binary_w_input(
                    out_file,
                    common.program_input,
                    target=target,
                    timeout=common.timeout,
                )
                status = shift_python_code(status)

            except Exception:
                # print(f"Failed to run and parse exit for {out_file}")
                # Set the exit code to 'generic error'
                status = 1
                stdout = ""

            result = BitFlipExperimentResult(
                original_program_file=common.program_file,
                binary_path=out_file,
                flipped_addr=inst.address,
                flipped_index=i,
                return_code=status,
                program_input=common.program_input,
                program_stdout=stdout,
                expected_stdout=common.expected_stdout,
                target=target,
                expected_returncode=common.expected_returncode,
                custom_returncodes=other_returncodes,
            )
            results.append(result)

    # Convert the results to a data frame and save
    df = dataclass_to_dataframe(results)
    save_df(df, common.save_results)

    # Dsiplay result info
    show_results(common, df, other_returncodes)

    return


@app.command
def disasm(binary: list[Path], start_addr: int, end_addr: int):
    pretty_insns = []
    for bin in binary:
        disassembly = disassemble_text_section(bin)

        max_len = max(
            len(" ".join([f"{b:02x}" for b in x.bytes])) for x in disassembly
        )

        # Gruvbox color codes (24-bit ANSI)
        GRUVBOX_BLUE = "\033[38;2;131;165;152m"  # #83a598
        GRUVBOX_GRAY = "\033[38;2;146;131;116m"  # #928374
        GRUVBOX_ORANGE = "\033[38;2;254;128;25m"  # #fe8019
        GRUVBOX_YELLOW = "\033[38;2;250;189;47m"  # #fabd2f
        RESET = "\033[0m"

        bin_pretty_insns = []
        for thing in [
            x
            for x in disassembly
            if x.address >= start_addr and x.address <= end_addr
        ]:
            byte_ar = thing.bytes
            byte_string = " ".join([f"{b:02x}" for b in byte_ar])
            res_str = f"{GRUVBOX_BLUE}0x{thing.address:x} {GRUVBOX_GRAY}{byte_string:<{max_len}} {GRUVBOX_ORANGE}{thing.mnemonic} {GRUVBOX_YELLOW}{thing.op_str}"
            white_res_str = f"0x{thing.address:x} {byte_string:<{max_len}} {thing.mnemonic} {thing.op_str}"
            bin_pretty_insns.append((white_res_str, res_str))

        pretty_insns.append(bin_pretty_insns)

    if len(pretty_insns) == 2:
        compare_disassembly(pretty_insns[0], pretty_insns[1], name1 = binary[0].name, name2=binary[1].name)
    else:
        for line in pretty_insns[0]:
            print(line)

    return


def dataclass_to_dataframe(
    result: list[NopExperimentResult] | list[BitFlipExperimentResult],
) -> pd.DataFrame:
    """
    Convert a dataclass to an experiment result
    """
    return pd.DataFrame([r.to_dict() for r in result])


def save_df(df: pd.DataFrame, out: Union[Path, None]) -> None:
    """
    Save the dataframe
    """
    if out is None:
        log_indices = [
            int(x.name.replace(".log", "").split("_")[-1])
            for x in list(DEFAULT_LOGS.glob("*"))
        ]
        if log_indices == []:
            last_log = -1
        else:
            last_log = max(log_indices)
        out = DEFAULT_LOGS.joinpath(f"faultlog_{last_log + 1}.log")
    else:
        out.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(out)
    return


@app.command
def nop_compile(
    common: CommandParameters, target: Target, bin_out: Path
) -> pd.DataFrame:
    """
    Patch all the addrs in the binar , and save bins that
    have a succesffuly exist code what running WITH NO FLAGS
    """

    source_code = common.program_file

    # Compile the binary for the target
    common.program_file = compile_program(
            common.program_file, bin_out, target
    )

    # Now run nop
    df = nop(common, source_code)
    return df

@app.command
def nop_exp(
    common: CommandParameters, target: Target,
) -> pd.DataFrame:
    """
    USE THIS WHEN YOU WHAT A SINGLE CLEAN EXPERIMENT !! :D 

    This will:
    1. Compile the binary for the target 
    2. Run the nop experiment on the compiled binary 
    3. Copy the source, the binary, the results, mutated binaries, command 
        parameters, to the out_dir
    """

    # Make the dir
    common.out_dir.mkdir(exist_ok=True, parents=True)
    base_out = common.out_dir

    # Copy the source cdoe to the experiement
    source_code = common.program_file
    shutil.copy(source_code, common.out_dir.joinpath(source_code.name))

    bin_out = common.out_dir.joinpath(common.program_file.name.replace('.c','.o'))

    common.save_results = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")

    # Compile the binary for the target
    common.program_file = compile_program(
            source_code, bin_out, target
    )

    # Now run nop
    df = nop(common, source_code)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params['target'] = target.value

    with open( base_out.joinpath('experiment_parametes.json'), 'w') as f:
        json.dump(params, f, indent=4)

    return df






#TODO: Removing this as a command in favor of nop_exp
#@app.command
def nop(
    common: CommandParameters, source_code: Optional[Path] = None
) -> pd.DataFrame:
    """
    Patch all the addrs in the binar , and save bins that
    have a succesffuly exist code what running WITH NO FLAGS

    """

    common.out_dir.mkdir(exist_ok=True)

    disasm = disassemble_text_section(common.program_file)
    if not common.yes:
        cont = str(input(f"Good for {len(disasm)} instructions? (Yy/Nn)"))

        if cont.lower() != "y":
            return

    # Parse the input binary
    binary = lief.parse(common.program_file)
    if not binary:
        raise ValueError(f"Failed to parse the binary: {common.program_file}")

    # Load the target type
    target = detect_target(common.program_file)

    other_returncodes = [
        ("password_accepted", 0),
        ("password_denied", 97),
        ("failed_to_run", 1),
    ]

    results: list[NopExperimentResult] = []

    # Iterate over single instructions
    for inst in alive_it(disasm):
        binary = lief.parse(common.program_file)

        nop_patch = gen_nop_patch(inst, target=target)

        # Patch the bytes at the given virtual address
        binary.patch_address(inst.address, nop_patch)
        out_file = common.out_dir.joinpath(
            common.program_file.name + f"_{hex(inst.address)}"
        )
        binary.write(str(out_file.resolve()))

        out_file.chmod(0o755)

        # Test the binary
        try:
            status, stdout, _ = run_binary_w_input(
                out_file,
                common.program_input,
                target=target,
                timeout=common.timeout,
            )
            status = shift_python_code(status)
        except Exception as e:
            # print(e)
            # print(f"Failed to run and parse exit for {out_file}")
            status = 1
            stdout = ""

        result = NopExperimentResult(
            original_program_file=common.program_file,
            binary_path=out_file,
            nopped_addr=inst.address,
            program_input=common.program_input,
            return_code=status,
            program_stdout=stdout,
            target=target,
            expected_returncode=common.expected_returncode,
            expected_stdout=common.expected_stdout,
            custom_returncodes=other_returncodes,
            source_code=source_code,
        )
        results.append(result)

    df = dataclass_to_dataframe(results)
    save_df(df, common.save_results)
    show_results(common, df, other_returncodes)

    return df


def show_results(
    common: CommandParameters,
    df: pd.DataFrame,
    other_returncodes: list[tuple[str, int]],
):
    console.print(
        df[
            [
                x
                for x in df.columns
                if x not in ["binary_path", "other_returncodes"]
            ]
        ]
    )
    if common.list_expected:
        info = df[df["return_code"] == common.expected_returncode]
        names = [Path(x).name for x in list(info["binary_path"])]
        print(f"The binaries with the expected output were:\n{names}")
        print(info[["return_code", "program_stdout", "binary_path"]])

    freqs = df["return_code"].value_counts().to_dict()

    new_freqs = {}
    weird_codes = {}

    # For return value and the number of returns that had that value
    for k, v in freqs.items():
        try:
            return_code_name = str(LinuxExitCodes(k).name) + f" ({k})"
        except:
            return_code_name = str(k)
            weird_codes[return_code_name] = list(
                df[df["return_code"] == k]["binary_path"]
            )

        # Replace with a fun name if otherwise specified
        for name, value in other_returncodes:
            if k == value:
                return_code_name = name + f" ({value})"
        new_freqs[return_code_name] = v

    print_histogram(new_freqs)

    # Make a histogam of program stdouts
    stdout_freqs = df["program_stdout"].value_counts().to_dict()

    # Get the outputs that contain the epected output
    correct_freq = {
        0: v for k, v in stdout_freqs.items() if common.expected_stdout in k
    }

    print(f"{correct_freq}")
    if correct_freq != {}:
        print(f"{correct_freq[0]} programs had the expected stdout")
    else:
        print("0 programs had the expected stdout")
    return


def print_histogram(results):
    """
    results: dict[str, int]
       A dictionary mapping 'Run Result' -> count
    """
    console = Console()
    table = Table(title="Results Histogram")

    table.add_column("Run Result", justify="left")
    table.add_column("Frequency", justify="right")
    table.add_column("Bar", justify="left")

    max_count = max(results.values()) if results else 0
    bar_width = 30  # Adjust to taste

    for result_type, count in results.items():
        # Scale the bar to max_count
        bar_length = int((count / max_count) * bar_width) if max_count else 0
        bar = "█" * bar_length

        table.add_row(result_type, str(count), bar)

    console.print(table)
    return


@app.command()
def disasm2(binary: Path, start_addr: str, end_addr: str):
    disassembly = disassemble_text_section(binary)

    start_addr = int(start_addr, 16)
    end_addr = int(end_addr, 16)

    max_len = max(
        len(" ".join([f"{b:02x}" for b in x.bytes])) for x in disassembly
    )

    # for instr in disassembly:
    for thing in [
        x
        for x in disassembly
        if x.address >= start_addr and x.address <= end_addr
    ]:
        byte_ar = thing.bytes
        byte_string = " ".join([f"{b:02x}" for b in byte_ar])
        res_str = f"0x{thing.address:x} {byte_string:<{max_len}} {thing.mnemonic} {thing.op_str}"
        print(res_str)

    return


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
        case lief.ELF.ARCH.ARM:
            # ARM32
            return Target.ARM_32
        case lief.ELF.ARCH.AARCH64:
            return Target.ARM_64
        case _:
            raise ValueError(
                "This script is intended for x86_64 ELF binaries only."
            )
    return


def disassemble_text_section(binary_path):
    """
    Disassemble the .text section of the binary and output instructions.
    """
    # Parse the binary
    binary = lief.parse(binary_path)

    # Find the .text section
    text_section = binary.get_section(".text")
    if not text_section:
        raise ValueError(".text section not found in the binary.")

    target = detect_target(binary_path)

    # start_addr = text_section.virtual_address

    match target:
        case Target.X86_64:
            md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            text_section = binary.get_section(".text")
        case Target.RISCV:
            # md = Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCVC)
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
            text_section = binary.get_section(".text")

        case Target.ARM_64:
            md = Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
            text_section = binary.get_section(".text")
        case Target.ARM_32:
            md = Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            text_section = binary.get_section(".text")
        case _:
            raise Exception("Unsupported file type")

    return list(md.disasm(text_section.content, text_section.virtual_address))


def compare_disassembly(lines_a, lines_b, name1, name2, column_width=100):
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

    GRUVBOX_ORANGE = "\033[38;2;254;128;25m"  # #fe8019
    GRUVBOX_BLUE = "\033[38;2;131;165;152m"  # #83a598
    GRUVBOX_GRAY = "\033[38;2;146;131;116m"  # #928374
    GRUVBOX_ORANGE = "\033[38;2;254;128;25m"  # #fe8019
    GRUVBOX_YELLOW = "\033[38;2;250;189;47m"  # #fabd2f

    print(f"{GRUVBOX_YELLOW}{'-':<{i_pad}}|{GRUVBOX_YELLOW} {name1:<{short_max_left-1}}|{GRUVBOX_YELLOW} {name2:<{short_max_right-1}}{GRUVBOX_YELLOW}|")
    print(f"{GRUVBOX_YELLOW}{'-':<{i_pad}}{GRUVBOX_YELLOW}|{"-"*(short_max_left)}|{"-"*short_max_right}|")

    for i in range(max_lines):
        left_line = nice_a[i] if i < len(nice_a) else ""
        right_line = nice_b[i] if i < len(nice_b) else ""

        if left_line == "":
            out = f"{GRUVBOX_YELLOW}{i:<{i_pad}}" + F"|" + f"{' '*short_max_left}" + "|" + f"{right_line:<{max_right}}"+ "|"
        elif right_line == "":
            out = f"{GRUVBOX_YELLOW}{i:<{i_pad}}" + "|" f"{left_line:<{max_left}}" + "|" + f"{" "*short_max_right}" + "|"
        else:
            out = f"{GRUVBOX_YELLOW}{i:<{i_pad}}" + "|" f"{left_line:<{max_left}}" + "|" + f"{right_line:<{max_right}}" + "|"

        print(out)
    return


@app.command
def read_results(inp: Path):
    """
    Read the results of an experiment
    """

    if inp.is_file():
        # Load the pandas dataframe
        df = pd.read_csv(inp)
    else:
        raise Exception

    # Get the number of accepted passwords, this is return code 1
    df = df[df["return_code"] == 1]

    # The result could be a nop experiment or a bit experiment
    if "nop" in list(df["experiment_type"]):
        info = df[["return_code", "nopped_addr"]]
    elif "bit" in list(df["experiment_type"]):
        info = df[["return_code", "flipped_addr", "flipped_index"]]

    # Want the number of exit codes that are 1

    print(df)
    return


@app.command
def many_bit(
    targets: Annotated[list[Target], Parameter(allow_leading_hyphen=True)],
    bin_dir: Path,
    common: CommandParameters,
):
    """
    Run the bit flip across multiple architectures
    """

    bin_dir.mkdir(exist_ok=True)

    orig_common = copy.deepcopy(common)

    # For each target, compile the program then test it
    for target in targets:
        common = orig_common

        # First compile the binary
        out_name = bin_dir.joinpath(f"{target.value}.o")
        common.program_file = compile_program(
            common.program_file, out_name, target
        )

        # Second run the bit expert
        common.out_dir = common.out_dir.joinpath(f"{target.value}")
        if common.save_results is not None:
            common.save_results = common.save_results.joinpath(
                f"{target.value}"
            )
        bit(common)
        # bin, mutated_out, comprogram_input, expected_output, list_expected, timeout, save_results)
    return


@app.command
def many_nop(
    targets: Annotated[list[Target], Parameter(allow_leading_hyphen=True)],
    bin_dir: Path,
    common: CommandParameters,
):
    """
    Run the bit flip across multiple architectures
    """

    bin_dir.mkdir(exist_ok=True)

    program_source_code = common.program_file
    result_save_to = common.out_dir.joinpath("total_results.csv")
    dfs = []

    # For each target, compile the program then test it
    for target in targets:
        common.program_file = program_source_code

        print(f"Compiling for target {target} : {common.program_file}")
        # First compile the binary
        out_name = bin_dir.joinpath(f"{target.name}.o")
        common.program_file = compile_program(
            common.program_file, out_name, target
        )

        # Second run the bit expert
        common.out_dir.mkdir(exist_ok=True)
        common.out_dir = common.out_dir.joinpath(f"{target.name}")
        if common.save_results is not None:
            common.save_results.mkdir(exist_ok=True)
            common.save_results = common.save_results.joinpath(f"{target.name}")

        print(f"Nopping for target {target} : {common.program_file}")
        df = nop(common, program_source_code)
        dfs.append(df)

    # Aggreagate dfs
    total_df = pd.concat(dfs, ignore_index=True)
    total_df.to_csv(result_save_to)

    return


@app.command()
def compile_many(inp: Path, out_dir: Path, targets: list[Target]):
    """
    Compile a program for a specific arch
    """

    out_dir.mkdir(exist_ok=True)

    for target in targets:
        match target:
            case Target.X86_64:
                compiler = "gcc"
            case Target.RISCV:
                compiler = "riscv64-linux-gnu-gcc"
            case Target.ARM_64:
                compiler = "aarch64-linux-gnu-gcc"
            case Target.ARM_32:
                compiler = "arm-linux-gnueabi-gcc"
            case _:
                raise Exception("No support for nops")

        new_name = inp.name.replace(".c", "")

        cmd = f"{compiler} {inp} -o {out_dir.joinpath(f'{new_name}_{compiler}.o')}".split(
            " "
        )
        try:
            subprocess.run(cmd)
        except:
            # TODO
            pass
    return


@app.command()
def compile_program(inp: Path, out: Path, target: Target) -> Path:
    """
    Compile a program for a specific arch
    """
    match target:
        case Target.X86_64:
            compiler = "gcc"
        case Target.RISCV:
            compiler = "riscv64-linux-gnu-gcc"
        case Target.ARM_64:
            compiler = "aarch64-linux-gnu-gcc"
        case Target.ARM_32:
            compiler = "arm-linux-gnueabi-gcc"
        case _:
            raise Exception("No support for nops")

    cmd = f"{compiler} {inp} -o {out}".split(" ")

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


def parallel_runs():
    """
    Run the binaries in parallel
    """

    return


# def run_command(cmd):
#    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#    stdout, stderr = process.communicate()
#    return (process.returncode, stdout.decode(), stderr.decode())


@app.command()
def para_nop(common: CommandParameters):
    num_cpus = os.cpu_count()  # or multiprocessing.cpu_count()
    max_workers = max(
        1, num_cpus // 2
    )  # avoid 0 in case cpu_count() returns None

    print(f"Using {max_workers} cpus")

    binary = lief.parse(common.program_file)
    disasm = disassemble_text_section(common.program_file)
    target = detect_target(common.program_file)

    other_returncodes = [
        ("password_accepted", 0),
        ("password_denied", 97),
        ("failed_to_run", 1),
    ]

    futures = []
    results: list[NopExperimentResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Run the threads
        for inst in disasm:
            future = executor.submit(
                para_run_binary_w_input, binary, common, inst, target
            )
            futures.append(future)

        total_tasks = len(futures)

        # for _, future in enumerate(futures):
        with alive_bar(total_tasks, title="Processing tasks") as bar:
            for future in as_completed(futures):
                # Check the status codes
                out_file, returncode, inst, common, target, stdout, stderr = (
                    future.result()
                )

                result = NopExperimentResult(
                    nopped_addr=inst.address,
                    program_input=common.program_input,
                    return_code=status,
                    program_stdout=output,
                    target=target,
                    expected_returncode=common.expected_returncode,
                    expected_stdout=common.expected_stdout,
                    custom_returncodes=other_returncodes,
                )
                results.append(result)
                bar()  # increment the progress bar by 1

            # returncode, output, arg1, arg2 = future.result()
            # alive_bar context manager
            # as_completed gives us futures as they finish
            # Get the result (this also re-raises any exception from the worker)
            # returncode, out, err = future.result()
            # Do something with returncode/out/err if needed

    df = dataclass_to_dataframe(results)
    save_df(df, common.save_results)

    console.print(
        df[
            [
                x
                for x in df.columns
                if x not in ["binary_path", "other_returncodes"]
            ]
        ]
    )

    if common.list_expected:
        info = df[df["return_code"] == common.expected_output]
        names = [Path(x).name for x in list(info["binary_path"])]
        print(f"The binaries with the expected output were:\n{names}")

    freqs = df["return_code"].value_counts().to_dict()

    new_freqs = {}
    for k, v in freqs.items():
        try:
            return_code_name = str(LinuxExitCodes(k).name)
        except:
            return_code_name = str(k)

        # Replace with a fun name if otherwise specified
        for name, value in other_returncodes:
            if k == value:
                return_code_name = name

        new_freqs[return_code_name] = v

    print_histogram(new_freqs)
    return


@app.command
def run(inps: list[Path] = [Path("experiment.toml")]):
    """
    This will run ALL the experiments in the provided experiment file
    """

    settings = dynaconf.Dynaconf(settings_files=["experiment.toml"])

    experiments = settings.get("experiment", {})
    commands = {
        "nop": nop,
        "bit": bit,
        "nop_exp": nop_exp,
        "many_nop": many_nop,
        "many_bit": many_bit,
    }

    # print(experiments)

    for exp_name, exp in experiments.items():
        # Get the function itself
        command_name = exp.pop("command", None)
        cmd_func = commands[command_name]

        # Some ditry hard coding to reformat the experiment settings
        # to a 'standard' type
        formated = {k.replace("-", "_"): v for k, v in exp.items()}
        formated["program_file"] = Path(formated["program_file"])
        formated["out_dir"] = Path(formated["out_dir"])

        if "save_results" in formated.keys():
            formated["save_results"] = Path(formated["save_results"])

        if "target" in formated.keys():
            formated["target"] = Target[formated["target"].upper()]


        if command_name in ["nop", "bit"]:
            params = CommandParameters(**formated)
            # Run the function
            cmd_func(params)
        elif command_name == "nop_exp":
            target = formated.pop("target")
            params = CommandParameters(**formated)

            # Get the other required params
            cmd_func(params, target=target)
            print(params)
            print(target)
            return

    return


if __name__ == "__main__":
    app()
