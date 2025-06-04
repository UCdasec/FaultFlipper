import lief
from typing import List, Tuple, Annotated, Optional
import matplotlib.pyplot as plt
from report_utils import list_tuple_table, generate_pdf_report
from sklearn.model_selection import train_test_split
import sklearn
from datetime import datetime
import shutil
import copy
import logging
import dynaconf
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import numpy as np
from dataclasses import dataclass, fields
from pathlib import Path
from capstone import (
    Cs,
    CS_ARCH_X86,
    CS_MODE_64,
    CS_ARCH_RISCV,
    CS_MODE_RISCV64,
    CS_MODE_RISCVC,
    CS_MODE_LITTLE_ENDIAN
)

import capstone
from cyclopts import App, Parameter
from rich.table import Table
from rich.console import Console
from enum import Enum
import subprocess
import pandas as pd
from enums import LinuxExitCodes

# All faults are a patch of some kind.


from dataclasses import dataclass
from typing import Union, Any
from alive_progress import alive_it


from logger_utils import setup_logger

from cli_utils import CommandParameters, show_results, calc_freqs



console = Console()
app = App()

DEFAULT_LOGS = Path("faultsim_log")
if not DEFAULT_LOGS.exists():
    DEFAULT_LOGS.mkdir()



other_returncodes = [
        #("critical_code_ran", 0),
        ("critical_code_did_not_run", 97),
        ("failed_to_run", -900),
    ]



from binary_tools import Target, Nop, shift_exit_code, in_place_patch, get_capstone_arch_mode, get_lief_arch, gen_nop_patch, generate_nop_mutated_bin, _generate_nop_mutated_bin



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
        case Target.ARM_32:
            return [
                "qemu-arm-static",
                #"-L",
                #"/usr/arm-linux-gnueabi",
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


def bit_para_run_helper(common, inst, target: Target):
    """
    Run a binary and capture its output - This version will return
    multiple results
    """

    if common.program_input[-1:] != "\n":
        input = common.program_input + "\n"
    else:
        input = common.program_input

    inst_bits = list(
        "".join([str(bin(byte)[2:]).zfill(8) for byte in inst.bytes])
    )

    results = []

    # For every bit see if we get a valid opcode.
    for i in range(len(inst_bits)):
        out_file = generate_bit_mutated_file(i, inst_bits, target, inst, common)

        if out_file is None:
            continue

        # Sanity check that a single bit has been changed and thats it
        mutated_text = lief.parse(out_file).get_section(".text")
        binary = lief.parse(common.program_file)
        vanilla_text = binary.get_section(".text")

        number_of_different_bits = count_bit_differences(
            mutated_text.content, vanilla_text.content
        )

        if number_of_different_bits != 1:
            raise Exception("Mutated wrong")

        try:
            returncode, stdout, stderr = run_binary_w_input(
                out_file, input, target, common.timeout
            )
            returncode = shift_exit_code(returncode)
            results.append(
                (out_file, returncode, inst, common, target, stdout, stderr, i)
            )
        except Exception as e:
            print(e)
            results.append((out_file, -900, inst, common, target, "", "", i))

    return results


def nop_para_run_helper(common, inst, target: Target):
    """
    Run a binary and capture its output
    """

    if common.program_input[-1:] != "\n":
        common.program_input += "\n"

    # Generate hte mutated binary
    try:
        out_file = generate_nop_mutated_bin(common, target, inst)

    except Exception as e:
        print(f"Issue making binary: {e}")
        return Path(""), -100, inst, common, target, "", ""

    try:
        returncode, stdout, stderr = run_binary_w_input(
            out_file, common.program_input, target, common.timeout
        )
        returncode = shift_exit_code(returncode)
        return out_file, returncode, inst, common, target, stdout, stderr
    except Exception as e:
        print(f"Failed to run bin with {e}")
        return out_file, -100, inst, common, target, "", ""


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
)->Tuple[int|None, str, str] | None:
    """
    Run a binary and capture its output
    """

    #if program_input[-1:] != "\n":
    #    program_input += "\n"

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
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = b"TIMEOUT", b"timeout expired"
        return None, stdout.decode(), stderr.decode()

    #TODO: Allow for returncode of None
    #if process.returncode is None:
    #    process.returncode = LinuxExitCodes.EX_SIGSEGV - 255

    return process.returncode, stdout.decode(), stderr.decode()




def run_binary_w_input(
    path: Path, program_input: str, target: Target, timeout: int = 60
)->Tuple[int|None, str, str] | None:
    """
    Run a binary and capture its output
    """

    if program_input[-1:] != "\n":
        program_input += "\n"

    cmd = generate_run_cmd(path, target)
    cmd = ["timeout", f"{timeout}s"] + cmd

    #print(f"Command is: {cmd}")

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
            input=program_input.encode(), timeout=timeout
        )
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = b"TIMEOUT", b"timeout expired"
        return None, stdout.decode(), stderr.decode()

    #TODO: Allow for returncode of None
    #if process.returncode is None:
    #    process.returncode = LinuxExitCodes.EX_SIGSEGV - 255

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
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
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


class Mutation(Enum):
    NOP = 0
    BITFLIP = 1


@dataclass
class MutationExperiment:
    source_file: Path | None
    unmutated_binary: Path | None
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
                result[field.name] = str(value.absolute())
            elif isinstance(
                value, Target
            ):  # Handle lists/dicts that might contain dataclasses
                result[field.name] = value.name
            elif value is None:
                result[field.name] = "None"
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


def preserve_debug_sections(orig_binary, patched_binary):
    debug_sections = []
    for sec in orig_binary.sections:
        if sec.name.startswith(".debug"):
            debug_sections.append(sec)

    # Re-create each debug section in the patched binary
    for sec in debug_sections:
        new_sec = lief.ELF.Section(sec.name)
        new_sec.content = sec.content
        new_sec.type = sec.type
        new_sec.flags = sec.flags
        new_sec.align = sec.align
        # Possibly set other fields to match original
        patched_binary.add(new_sec, loaded=False)  
        # 'loaded=False' so it doesn't try to place it in a PT_LOAD segment


def generate_bit_mutated_file(
    i, inst_bits, target, inst, common
) -> Union[None, Path]:
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


def count_bit_differences(bytes_1, bytes_2):
    if len(bytes_1) != len(bytes_2):
        return float("inf")  # Ensure same size; otherwise, reject

    diff_bits = 0
    for b1, b2 in zip(bytes_1, bytes_2):
        diff_bits += bin(b1 ^ b2).count("1")  # Count bitwise differences

        if diff_bits > 1:  # Stop early if more than one bit differs
            return diff_bits

    return diff_bits


# TODO: Removed in favor of bit_exp
# @app.command
def bit(
    common: CommandParameters, source_code: Optional[Path] = None, quiet: bool = True
) -> pd.DataFrame:
    """
    Patch all the addrs in the binar , and save bins that
    have a succesffuly exist code what running WITH NO FLAGS
    """

    common.out_dir.mkdir(exist_ok=True)
    disasm = disassemble_text_section(common.program_file)

    if not common.yes:
        cont = str(
            input(
                f"Will _attempt_ to make {len(lief.parse(common.program_file).get_section('.text').content)} mutated binaries, continue? (Yy/Nn)"
            )
        )
        if cont.lower() != "y":
            return

    target = detect_target(common.program_file)
    results: list[BitFlipExperimentResult] = []

    binary = lief.parse(common.program_file)

    # For every instructions
    for inst in alive_it(disasm):

        # Need to pad the left with zeroes
        inst_bits = list(
            "".join([str(bin(byte)[2:]).zfill(8) for byte in inst.bytes])
        )

        # For every bit see if we get a valid opcode.
        for i in range(len(inst_bits)):
            # Generate the mutated binary - If we did not generate a good one continue
            out_file = generate_bit_mutated_file(
                i, inst_bits, target, inst, common
            )

            if out_file is None:
                continue

            # Sanity check that a single bit has been changed and thats it
            mutated_text = lief.parse(out_file).get_section(".text")
            vanilla_text = binary.get_section(".text")

            number_of_different_bits = count_bit_differences(
                mutated_text.content, vanilla_text.content
            )

            if number_of_different_bits != 1:
                raise Exception("Great than 1 difference in bits")
            try:
                status, stdout, _ = run_binary_w_input(
                    out_file,
                    common.program_input,
                    target=target,
                    timeout=common.timeout,
                )
                status = shift_exit_code(status)
            except Exception:
                status = -999
                stdout = ""

            result = BitFlipExperimentResult(
                source_file=source_code,
                unmutated_binary=common.program_file,
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
    if not quiet:
        show_results(common, df, other_returncodes)

    return df


@app.command
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
            x
            for x in disassembly
            if x.address >= start_addr and x.address <= end_addr
        ]
        if len(filter_disasm) == 0:
            raise Exception

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
        RESET = "\033[0m"

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
    else:
        total = []
        for line in pretty_insns[0]:
            print(line)

    return total


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
    common.program_file = compile_program(common.program_file, bin_out, target)

    # Now run nop
    df = nop(common, source_code)
    return df


@app.command
def bit_exp(
    common: CommandParameters,
    target: Target,
) -> pd.DataFrame:
    """
    USE THIS WHEN YOU WHAT A SINGLE CLEAN EXPERIMENT !! :D

    This will:
    \n1. Compile the binary for the target
    \n2. Run the nop experiment on the compiled binary
    \n3. Copy: source code, binary, results, mutated bins, and params to out
    """

    # Make the dir
    common.out_dir.mkdir(exist_ok=True, parents=True)
    base_out = common.out_dir

    # Copy the source cdoe to the experiement
    source_code = common.program_file
    shutil.copy(source_code, common.out_dir.joinpath(source_code.name))

    bin_out = common.out_dir.joinpath(
        common.program_file.name.replace(".c", ".o")
    )

    common.save_results = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target)

    # Now run nop
    df = bit(common, source_code)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    return df

@app.command
def nop_exp_no_comp(
    common: CommandParameters,
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

    bin_out = common.out_dir.joinpath(
        common.program_file.name.replace(".c", ".o")
    )

    common.save_results = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")

    # Now run nop
    df = nop(common, source_code)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    return df



@app.command
def nop_exp(
    common: CommandParameters,
    target: Target,
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

    bin_out = common.out_dir.joinpath(
        common.program_file.name.replace(".c", ".o")
    )

    common.save_results = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target)

    # Now run nop
    df = nop(common, source_code)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    return df




# TODO: Removing this as a command in favor of nop_exp
@app.command
def bit_no_comp_inout(
    common: CommandParameters, 
    source_code: Optional[Path] = None, 
    ins: List[str] | None = None, 
    outs: List[str] | None = None,
    expected_correct: int | None = None,
) -> pd.DataFrame:
    """
    Patch all the addrs in the binar , and save bins that
    have a succesffuly exist code what running WITH NO FLAGS
    """
    other_returncodes = [
            ("failed_to_run", -999),
            ("correct_prediction", 0),
        ]

    if common.save_results.exists():
        # Gather the results
        df = pd.read_csv(common.save_results)
        print(f"Loading existing results")
    else:
        print(f"Old results: {common.save_results} does not exists")
        common.out_dir.mkdir(exist_ok=True)

        # Intermeidate results
        result_out = common.out_dir.joinpath("intermediate_results")
        result_out.mkdir(exist_ok=True)

        # Adjust the out dir 
        common.out_dir = common.out_dir.joinpath("mutated_bins")
        common.out_dir.mkdir(exist_ok=True)

        disasm = disassemble_text_section(common.program_file)
        if not common.yes:
            cont = str(input(f"Good for {len(disasm)} instructions? (Yy/Nn)"))

            if cont.lower() != "y":
                return

        # Load the target type
        target = detect_target(common.program_file)
        logger.debug(f"Detected Target: {target}")

        results: list[BitFlipExperimentResult] = []
        

        # Iterate over single instructions
        for inst in alive_it(disasm):

            # Need to pad the left with zeroes
            inst_bits = list(
                "".join([str(bin(byte)[2:]).zfill(8) for byte in inst.bytes])
            )

            # For every bit see if we get a valid opcode.
            for i in range(len(inst_bits)):
                # Generate the mutated binary - If we did not generate a good one continue
                out_file = generate_bit_mutated_file(
                    i, inst_bits, target, inst, common
                )

                if out_file is None:
                    continue

                # The out file is at out_dir/...
                #out_file = generate_nop_mutated_bin(common, target, inst)

                # Run all the possible inputs and outputs
                for cur_in, cur_out in zip(ins,outs):
                    cur_in = Path(cur_in)

                    # See if the intermediate result exists yet
                    intermediate_out = result_out.joinpath(out_file.name + f"_{cur_in.name.split('.')[0]}" + f"_{i}_" +".json")

                    if intermediate_out.exists():
                        print(f"Reading existing file {intermediate_out}")
                        # Load and skip test
                        with open(intermediate_out, 'r') as f: 
                            result = json.load(f)
                            result = BitFlipExperimentResult(**result)
                    else:
                        # Test the binary
                        status, stdout, _ = run_binary_w_calltime_input(
                            out_file,
                            cur_in,
                            target=target,
                            timeout=common.timeout,
                        )

                        # Status is None when there is a Timeout or 
                        # when there the input image does not exist

                        if status is not None:
                            status = shift_exit_code(status)
                        else:
                            status = -999
                            logger.debug("File failed")

                        result = BitFlipExperimentResult(
                            source_file=source_code,
                            unmutated_binary=common.program_file,
                            binary_path=out_file,
                            flipped_addr=inst.address,
                            flipped_index=i,
                            return_code=status,
                            program_input=cur_in,
                            program_stdout=stdout,
                            expected_stdout=cur_out,
                            target=target,
                            expected_returncode=common.expected_returncode,
                            custom_returncodes=other_returncodes,
                        )

                        dicted_result = result.to_dict()
                        with open(intermediate_out, 'w') as f:
                            json.dump(dicted_result, f)

                    results.append(result)


        df = dataclass_to_dataframe(results)
        save_df(df, common.save_results)

    print(f"Return code value counts...")
    print(df['return_code'].value_counts())

    # Number of (bin, inp) paris that had the expected output 
    correct_prediction_mask = df.apply(lambda row: str(row['expected_stdout']) in str(row['program_stdout']), axis=1)

    # Sum of ALL cases where a prediction was correct
    total_equal = correct_prediction_mask.sum()
    print(f"{total_equal} correct input binary pairs")


    # Per nopped addr, get the number of correct predictions 
    correct_per_mutated = df[correct_prediction_mask].groupby('nopped_addr').size().reset_index('count')

    counts = correct_per_mutated.value_counts()
    print(f"The value counts of correct predictions:")
    print(counts)

    #TODO: These are wrogn
    # Get the list of binaries that got the same expected
    #expected_correct_mutations =  correct_per_mutated["count"] == expected_correct
    num_correct_mutations =  (correct_per_mutated == expected_correct).sum()
    #num_correct_mutations = counts == expected_correct
    print(f"Number of files that got  correct predictions: {num_correct_mutations}")

    #expected_correct_mutations =  correct_per_mutated["count"] < expected_correct
    num_less_mutations =  (correct_per_mutated < expected_correct).sum()
    print(f"Number of files that got less than  correct predictions: {num_less_mutations}")


    # Number of failed binaries
    failed_result_mask = df[df['return_code'] == -999].groupby('nopped_addr').size().reset_index('count')
    print(f"{failed_result_mask.shape[0]} failed binaries input combinations")


    # Get the addrs that had both of the following (1) An occurance of correct
    # prediction (2) An occurance of -999 return code

    # Mask 1 is correct_prediction_mask 
    correct_and_failed = df[correct_prediction_mask & failed_result_mask]
    if correct_and_failed.shape[0] == 0:
        print(f"No occurance of a mutated binary getting a prediction correct for one sample and failing to run for another sample")


    show_results(common, df, other_returncodes)


    return df





# TODO: Removing this as a command in favor of nop_exp
@app.command
def nop_no_comp_inout(
    common: CommandParameters, 
    source_code: Optional[Path] = None, 
    ins: List[str] | None = None, 
    outs: List[str] | None = None,
    expected_correct: int | None = None,
) -> pd.DataFrame:
    """
    Patch all the addrs in the binar , and save bins that
    have a succesffuly exist code what running WITH NO FLAGS
    """
    other_returncodes = [
            #("critical_code_ran", 0),
            #("critical_code_did_not_run", 97),
            ("failed_to_run", -999),
            ("correct_prediction", 0),
        ]



    if common.save_results.exists():
        # Gather the results
        df = pd.read_csv(common.save_results)
        print(f"Loading existing results")
    else:
        print(f"Old results: {common.save_results} does not exists")
        common.out_dir.mkdir(exist_ok=True)

        # Intermeidate results
        result_out = common.out_dir.joinpath("intermediate_results")
        result_out.mkdir(exist_ok=True)

        # Adjust the out dir 
        common.out_dir = common.out_dir.joinpath("mutated_bins")
        common.out_dir.mkdir(exist_ok=True)

        disasm = disassemble_text_section(common.program_file)
        if not common.yes:
            cont = str(input(f"Good for {len(disasm)} instructions? (Yy/Nn)"))

            if cont.lower() != "y":
                return

        # Load the target type
        target = detect_target(common.program_file)
        logger.debug(f"Detected Target: {target}")

        results: list[NopExperimentResult] = []
        

        # Iterate over single instructions
        for inst in alive_it(disasm):

            # The out file is at out_dir/...
            out_file = generate_nop_mutated_bin(common, target, inst)

            # Run all the possible inputs and outputs
            for cur_in, cur_out in zip(ins,outs):
                cur_in = Path(cur_in)

                # See if the intermediate result exists yet
                intermediate_out = result_out.joinpath(out_file.name + f"_{cur_in.name.split('.')[0]}" + ".json")

                if intermediate_out.exists():
                    print(f"Reading existing file {intermediate_out}")
                    # Load and skip test
                    with open(intermediate_out, 'r') as f: 
                        result = json.load(f)
                        result = NopExperimentResult(**result)
                else:
                    # Test the binary
                    status, stdout, _ = run_binary_w_calltime_input(
                        out_file,
                        cur_in,
                        target=target,
                        timeout=common.timeout,
                    )

                    # Status is None when there is a Timeout or 
                    # when there the input image does not exist

                    if status is not None:
                        status = shift_exit_code(status)
                    else:
                        status = -999
                        logger.debug("File failed")

                    result = NopExperimentResult(
                        source_file=source_code,
                        unmutated_binary=common.program_file,
                        binary_path=out_file,
                        nopped_addr=inst.address,
                        program_input=cur_in,
                        return_code=status,
                        program_stdout=stdout,
                        target=target,
                        expected_returncode=common.expected_returncode,
                        expected_stdout=cur_out,
                        custom_returncodes=other_returncodes,
                        source_code=source_code,
                    )
                    dicted_result = result.to_dict()
                    with open(intermediate_out, 'w') as f:
                        json.dump(dicted_result, f)

                results.append(result)


        df = dataclass_to_dataframe(results)
        save_df(df, common.save_results)


    # Doing the analyiss.............................

    print(f"Return code value counts...")
    print(df['return_code'].value_counts())

    # Add a column to see if there was a match

    df['correct'] = df.apply(lambda row: str(row['expected_stdout']) in str(row['program_stdout']), axis=1)

    df['failed'] = df['return_code'] == -999

    # Use this to get the number of mutated bines that 
    # got 0 correct BUT still ran correctly
    addrs_with_failed = df.loc[df['return_code'] == -999, 'nopped_addr'].unique()
    df_no_fail = df[~df['nopped_addr'].isin(addrs_with_failed)]

    # nopped addrs that have one failed ANY

    # Grop by the addr and record the failed and correct
    agg_df = df.groupby('nopped_addr').agg(
        total_correct = ('correct', 'sum'),
        total_failed = ('failed', 'sum')
    ).reset_index()

    agg_df_no_fail = df_no_fail.groupby('nopped_addr').agg(
        total_correct = ('correct', 'sum'),
        total_failed = ('failed', 'sum')
    ).reset_index()

    print(f"We have {agg_df.shape} shaped agg df")
    print(f"We have {agg_df_no_fail.shape} shaped agg df no fail")
    #print(agg_df.head())

    # This is the count of number of corrects. Notice, that 
    # if the number of correct predictions is 0 it may 
    # or may not be a case where the model ran correctly 
    # and outputed zero.
    print(f"Counts of corrects:\n {agg_df['total_correct'].value_counts()}")
    print(f"Counts of failed:\n {agg_df['total_failed'].value_counts()}")

    print(f"NO FAIL Counts of corrects:\n {agg_df_no_fail['total_correct'].value_counts()}")

    print(f"How many failed on ALL inputs:\n {(agg_df['total_failed'] == 80).sum()}")

    # Overlapp of correct and failed
    mask = (agg_df['total_failed'] != 0 ) & (agg_df['total_correct'] != 0 )
    print(f"Number of nonzero failed and nonzero correct:\n {agg_df[mask].value_counts()}")


    # See how many counts of correct == expected cont 
    print(f"Therefore, of {agg_df.shape[0]} mutated bins, {(agg_df['total_correct'] == expected_correct).sum()} had the same number of correct predictions")
    print(f"Therefore, of {agg_df.shape[0]} mutated bins, {(agg_df['total_correct'] < expected_correct).sum()} had less than the correct predictions")
    print(f"Therefore, of {agg_df.shape[0]} mutated bins, {(agg_df['total_failed'] >= 1).sum()} had atleast one sample that caused a failed experiment")

    show_results(common, df, other_returncodes)


    return df




# TODO: Removing this as a command in favor of nop_exp
@app.command
def nop_no_comp(
    common: CommandParameters, source_code: Optional[Path] = None
) -> pd.DataFrame:
    """
    Patch all the addrs in the binar , and save bins that
    have a succesffuly exist code what running WITH NO FLAGS
    """

    if not isinstance(common.expected_stdout, list) and not isinstance(common.expected_stdout, str):
        with open(common.expected_stdout, 'r') as f:
            lines = f.readlines()
            common.expected_stdout = lines

    common.out_dir.mkdir(exist_ok=True)

    disasm = disassemble_text_section(common.program_file)
    if not common.yes:
        cont = str(input(f"Good for {len(disasm)} instructions? (Yy/Nn)"))

        if cont.lower() != "y":
            return

    # Parse the input binary
    #binary = lief.parse(common.program_file)
    #if not binary:
    #    raise ValueError(f"Failed to parse the binary: {common.program_file}")

    # Load the target type
    target = detect_target(common.program_file)
    logger.debug(f"Detected Target: {target}")

    other_returncodes = [
        ("critical_code_ran", 0),
        ("critical_code_did_not_run", 97),
        ("failed_to_run", -900),
        ("timeout", None)
    ]

    results: list[NopExperimentResult] = []

    # Iterate over single instructions
    for inst in alive_it(disasm):
        # Generate the mutated binary
        out_file = generate_nop_mutated_bin(common, target, inst)

        # Test the binary
        try:
            status, stdout, _ = run_binary_w_input(
                out_file,
                common.program_input,
                target=target,
                timeout=common.timeout,
            )
            #print(stdout)
            status = shift_exit_code(status)
        except Exception as e:
            status = -900
            stdout = ""

        result = NopExperimentResult(
            source_file=source_code,
            unmutated_binary=common.program_file,
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
            md = Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)
            text_section = binary.get_section(".text")
        case _:
            raise Exception("Unsupported file type")

    return list(md.disasm(text_section.content, text_section.virtual_address))


def compare_disassembly(
    lines_a,
    lines_b,
    name1,
    name2,
    column_width=100,
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
                f"{left_line:<{max_left}}"
                + "|"
                + f"{' ' * short_max_right}"
                + "|"
            )
        else:
            out = (
                f"{GRUVBOX_YELLOW}{i:<{i_pad}}" + "|"
                f"{left_line:<{max_left}}"
                + "|"
                + f"{right_line:<{max_right}}"
                + "|"
            )

        if not text or verbose:
            print(out)

        total += f"{out}\n"

    return total


@app.command
def find_faulted(results: Path, padding: int):
    """
    From the results file find the binaries that had the exptected STDOUT
    then print the dissassembly comparison between all those programs and the
    base program
    """

    if not results.exists():
        print(f"File {results} does not exist")
        return

    # Load the result and get those that have the epxeted STDOUT in them
    df = pd.read_csv(results)

    expected_stdout = str(list(df["expected_stdout"])[0])
    filtered_df = df[
        df["program_stdout"].str.contains(expected_stdout, na=False)
    ]

    # Get the mutated paths that have the expected stdouts
    mutated_binaries = [Path(x) for x in filtered_df["binary_path"]]

    # Get the vanilla binary
    vanilla_binary = Path(str(list(filtered_df["unmutated_binary"])[0]))
    assert vanilla_binary.exists()

    for mbin in mutated_binaries:
        # Get the mutated address
        addr = int(mbin.name.replace(vanilla_binary.name + "_", ""), 16)

        # Run the disassmebly
        disasm([vanilla_binary, mbin], addr - padding, addr + padding)

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
                compiler = "gcc -g"
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


def generate_compile_cmd(inp: Path, out: Path, target: Target) -> list[str]:
    """
    Compile a program for a specific arch
    """

    if not out.parent.exists():
        out.parent.mkdir(parents=True)

    match target:
        case Target.X86_64:
            compiler = "gcc -g"
        case Target.RISCV:
            compiler = "riscv64-linux-gnu-gcc"
        case Target.ARM_64:
            compiler = "aarch64-linux-gnu-gcc"
        case Target.ARM_32:
            compiler = "arm-linux-gnueabi-gcc"
        case _:
            raise Exception("No support for nops")

    cmd = f"{compiler} {inp} -o {out}".split(" ")
    return cmd


@app.command()
def compile_program(inp: Path, out: Path, target: Target) -> Path:
    """
    Compile a program for a specific arch
    """

    if not out.parent.exists():
        out.parent.mkdir(parents=True)

    match target:
        case Target.X86_64:
            compiler = "gcc -g"
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
def para_bit_no_comp(common: CommandParameters, num_cpus: int):
    """
    Parallelize the bit
    """


    if isinstance(common.expected_stdout, Path):
        with open(common.expected_stdout, 'r') as f:
            lines = f.readlines()
            common.expected_stdout = lines
     


    max_workers = max(
        1, num_cpus // 2
    )  # avoid 0 in case cpu_count() returns None

    # Make the dir
    common.out_dir.mkdir(exist_ok=True, parents=True)
    base_out = common.out_dir

    # Copy the source cdoe to the experiement
    source_code = common.program_file
    program_context = common.program_file.parent.joinpath(
        common.program_file.name.replace(".c", ".toml")
    )

    shutil.copy(source_code, common.out_dir.joinpath(source_code.name))
    if program_context.exists():
        shutil.copy(
            program_context, common.out_dir.joinpath(program_context.name)
        )

    #bin_out = common.out_dir.joinpath(
    #    common.program_file.name.replace(".c", ".o")
    #)
    #compile_cmd = generate_compile_cmd(common.program_file, bin_out, target)
    compile_cmd = ""

    common.save_results = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    #common.program_file = compile_program(source_code, bin_out, target)

    target = detect_target(common.program_file)

    if not common.yes:
        cont = str(
            input(
                f"Will _attempt_ to make {len(lief.parse(common.program_file).get_section('.text').content)} mutated binaries, continue? (Yy/Nn)"
            )
        )
        if cont.lower() != "y":
            return

    disasm = disassemble_text_section(common.program_file)

    futures = []
    results: list[BitFlipExperimentResult] = []

    start = datetime.now()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Run the threads
        for inst in disasm:
            future = executor.submit(bit_para_run_helper, common, inst, target)
            futures.append(future)

        total_tasks = len(futures)

        # for _, future in enumerate(futures):
        with alive_bar(total_tasks, title="Processing tasks") as bar:
            for future in as_completed(futures):
                # Check the status codes
                result = future.result()

                # Results = [out_file, returncode, inst, common, target, stdout, stderr, i]
                for (
                    out_file,
                    returncode,
                    inst,
                    common,
                    target,
                    stdout,
                    stderr,
                    i,
                ) in result:
                    cur_res = BitFlipExperimentResult(
                        source_file=source_code,
                        unmutated_binary=common.program_file,
                        binary_path=out_file,
                        flipped_addr=inst.address,
                        flipped_index=i,
                        program_input=common.program_input,
                        return_code=returncode,
                        program_stdout=stdout,
                        target=target,
                        expected_returncode=common.expected_returncode,
                        expected_stdout=common.expected_stdout,
                        custom_returncodes=other_returncodes,
                    )
                    results.append(cur_res)

                bar()  # increment the progress bar by 1

    runtime = datetime.now() - start

    num_instructions = len(disasm)

    num_bits = (
        len(lief.parse(common.program_file).get_section(".text").content) * 8
    )

    df = dataclass_to_dataframe(results)

    save_df(df, common.save_results)

    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    report_path = common.save_results.parent.joinpath("report.md")
    save_report(
        report_path,
        common,
        df,
        runtime,
        results,
        num_instructions,
        num_bits,
        compile_cmd,
        source_code,
        program_context,
        is_bit=True,
    )

    return




@app.command()
def para_bit(common: CommandParameters, target: Target, num_cpus: int):
    """
    Parallelize the bit
    """

    max_workers = max(
        1, num_cpus // 2
    )  # avoid 0 in case cpu_count() returns None

    # Make the dir
    common.out_dir.mkdir(exist_ok=True, parents=True)
    base_out = common.out_dir

    # Copy the source cdoe to the experiement
    source_code = common.program_file
    program_context = common.program_file.parent.joinpath(
        common.program_file.name.replace(".c", ".toml")
    )

    shutil.copy(source_code, common.out_dir.joinpath(source_code.name))
    if program_context.exists():
        shutil.copy(
            program_context, common.out_dir.joinpath(program_context.name)
        )

    bin_out = common.out_dir.joinpath(
        common.program_file.name.replace(".c", ".o")
    )
    compile_cmd = generate_compile_cmd(common.program_file, bin_out, target)

    common.save_results = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target)

    if not common.yes:
        cont = str(
            input(
                f"Will _attempt_ to make {len(lief.parse(common.program_file).get_section('.text').content)} mutated binaries, continue? (Yy/Nn)"
            )
        )
        if cont.lower() != "y":
            return

    disasm = disassemble_text_section(common.program_file)

    #other_returncodes = [
    #    ("critical_code_ran", 0),
    #    ("critical_code_did_not_run", 97),
    #    ("failed_to_run", -900),
    #]

    futures = []
    results: list[BitFlipExperimentResult] = []

    start = datetime.now()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Run the threads
        for inst in disasm:
            future = executor.submit(bit_para_run_helper, common, inst, target)
            futures.append(future)

        total_tasks = len(futures)

        # for _, future in enumerate(futures):
        with alive_bar(total_tasks, title="Processing tasks") as bar:
            for future in as_completed(futures):
                # Check the status codes
                result = future.result()

                # Results = [out_file, returncode, inst, common, target, stdout, stderr, i]
                for (
                    out_file,
                    returncode,
                    inst,
                    common,
                    target,
                    stdout,
                    stderr,
                    i,
                ) in result:
                    cur_res = BitFlipExperimentResult(
                        source_file=source_code,
                        unmutated_binary=common.program_file,
                        binary_path=out_file,
                        flipped_addr=inst.address,
                        flipped_index=i,
                        program_input=common.program_input,
                        return_code=returncode,
                        program_stdout=stdout,
                        target=target,
                        expected_returncode=common.expected_returncode,
                        expected_stdout=common.expected_stdout,
                        custom_returncodes=other_returncodes,
                    )
                    results.append(cur_res)

                bar()  # increment the progress bar by 1

    runtime = datetime.now() - start

    num_instructions = len(disasm)

    num_bits = (
        len(lief.parse(common.program_file).get_section(".text").content) * 8
    )

    df = dataclass_to_dataframe(results)

    save_df(df, common.save_results)

    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    report_path = common.save_results.parent.joinpath("report.md")
    save_report(
        report_path,
        common,
        df,
        runtime,
        results,
        num_instructions,
        num_bits,
        compile_cmd,
        source_code,
        program_context,
        is_bit=True,
    )

    return

@app.command()
def para_nop_no_comp(common: CommandParameters,  num_cpus: int):
    """
    Take c source code as input, compile it, mutate it, and test
    """


    if isinstance(common.expected_stdout, Path):
        with open(common.expected_stdout, 'r') as f:
            lines = f.readlines()
            common.expected_stdout = lines
        


    max_workers = max(1, num_cpus // 2)

    # Make the dir
    common.out_dir.mkdir(exist_ok=True, parents=True)
    program_context = common.program_file.parent.joinpath(
        common.program_file.name.replace(".c", ".toml")
    )
    base_out = common.out_dir

    # Copy the source cdoe to the experiement
    source_code = common.program_file
    shutil.copy(source_code, common.out_dir.joinpath(source_code.name))

    common.save_results = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    #common.program_file = compile_program(source_code, bin_out, target)

    #compile_cmd = generate_compile_cmd(common.program_file, bin_out, target)

    compile_cmd = ""

    original_bin = common.program_file

    disasm = disassemble_text_section(common.program_file)
    num_instructions = len(disasm)
    if not common.yes:
        cont = str(
            input(
                f"FaultSim will _attempt_ to generate {len(disasm)}. Continue? (Yy/Nn)"
            )
        )
        if cont.lower() != "y":
            return

    target = detect_target(common.program_file)

    #other_returncodes = [
    #    ("critical_code_ran", 0),
    #    ("critical_code_did_not_run", 97),
    #    ("failed_to_run", 1),
    #]

    futures = []
    results: list[NopExperimentResult] = []

    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Run the threads
        for inst in disasm:
            future = executor.submit(nop_para_run_helper, common, inst, target)
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
                    source_file=source_code,
                    unmutated_binary=original_bin,
                    binary_path=out_file,
                    nopped_addr=inst.address,
                    program_input=common.program_input,
                    return_code=returncode,
                    program_stdout=stdout,
                    target=target,
                    expected_returncode=common.expected_returncode,
                    expected_stdout=common.expected_stdout,
                    custom_returncodes=other_returncodes,
                )
                results.append(result)
                bar()  # increment the progress bar by 1

    runtime = datetime.now() - start_time

    df = dataclass_to_dataframe(results)
    save_df(df, common.save_results)
    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = (
        len(lief.parse(common.program_file).get_section(".text").content) * 8
    )

    report_path = common.save_results.parent.joinpath("report.md")
    save_report(
        report_path,
        common,
        df,
        runtime,
        results,
        num_instructions,
        num_bits,
        compile_cmd,
        source_code,
        program_context,
    )

    return




@app.command()
def para_nop(common: CommandParameters, target: Target, num_cpus: int):
    """
    Take c source code as input, compile it, mutate it, and test
    """

    max_workers = max(1, num_cpus // 2)

    # Make the dir
    common.out_dir.mkdir(exist_ok=True, parents=True)
    program_context = common.program_file.parent.joinpath(
        common.program_file.name.replace(".c", ".toml")
    )
    base_out = common.out_dir

    # Copy the source cdoe to the experiement
    source_code = common.program_file
    shutil.copy(source_code, common.out_dir.joinpath(source_code.name))

    bin_out = common.out_dir.joinpath(
        common.program_file.name.replace(".c", ".o")
    )

    common.save_results = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target)

    compile_cmd = generate_compile_cmd(common.program_file, bin_out, target)

    original_bin = common.program_file

    disasm = disassemble_text_section(common.program_file)
    num_instructions = len(disasm)
    if not common.yes:
        cont = str(
            input(
                f"FaultSim will _attempt_ to generate {len(disasm)}. Continue? (Yy/Nn)"
            )
        )
        if cont.lower() != "y":
            return

    target = detect_target(common.program_file)

    #other_returncodes = [
    #    ("critical_code_ran", 0),
    #    ("critical_code_did_not_run", 97),
    #    ("failed_to_run", 1),
    #]

    futures = []
    results: list[NopExperimentResult] = []

    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Run the threads
        for inst in disasm:
            future = executor.submit(nop_para_run_helper, common, inst, target)
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
                    source_file=source_code,
                    unmutated_binary=original_bin,
                    binary_path=out_file,
                    nopped_addr=inst.address,
                    program_input=common.program_input,
                    return_code=returncode,
                    program_stdout=stdout,
                    target=target,
                    expected_returncode=common.expected_returncode,
                    expected_stdout=common.expected_stdout,
                    custom_returncodes=other_returncodes,
                )
                results.append(result)
                bar()  # increment the progress bar by 1

    runtime = datetime.now() - start_time

    df = dataclass_to_dataframe(results)
    save_df(df, common.save_results)
    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = (
        len(lief.parse(common.program_file).get_section(".text").content) * 8
    )

    report_path = common.save_results.parent.joinpath("report.md")
    save_report(
        report_path,
        common,
        df,
        runtime,
        results,
        num_instructions,
        num_bits,
        compile_cmd,
        source_code,
        program_context,
    )

    return


def save_report(
    report_path: Path,
    common: CommandParameters,
    df: pd.DataFrame,
    runtime,
    results,
    num_instructions,
    num_bits,
    compile_cmd,
    source_code: Path,
    program_context: Path,
    is_bit=False,
) -> None:
    """
    Generate a report including:
    1. Experiment Settings
    2. Histrogram of exit codes
    3. List of files that ran critical code
    4. Disassmeblys of the files that ran critical codes
    5. Validation of correct mutations
    6. Whole dataframe
    """

    # . The title
    title = f"# Experiment {results[0].mutation.upper()} on {common.program_file.name} with target {results[0].target}\n"

    # 1. the settings
    settings = common.to_dict()

    settings_bullets = "## Settings \n"

    for k, v in settings.items():
        if k in ["program_input", "expected_stdout"]:
            settings_bullets = (
                settings_bullets + f"- **{k}**:" + f"`{list(v)}`" + "\n"
            )
            continue
        settings_bullets += f"- **{k}**: {v}\n"

    # 1.a - Program context
    if program_context.is_file():
        logger.debug(f"Opening context file: {program_context}")
        settings_bullets += "\n"
        settings_bullets += "```toml"
        with open(program_context, "r") as f:
            for line in f.readlines():
                settings_bullets += f"{line}\n"
        settings_bullets += "```"

    # 1.1 Binary information

    match results[0].target:
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

    binary_info = "#### Binary information + Running the binary information\n"
    binary_info += f"- Contains **{num_instructions}** instructions\n"
    binary_info += f"- Contains **{num_bits}** bits in the .text section\n"
    if is_bit:
        binary_info += f"- Therefore, FaultSim attempted to make **{num_bits}** mutations\n"
        binary_info += f"- Of the **{num_bits}** attempted mutations, **{len(df)}** valid mutated binaries were generated\n"
    else:
        binary_info += f"- Therefore, FaultSim attempted to make **{num_instructions}** mutations\n"
        binary_info += f"- Of the **{num_instructions}** attempted mutations, **{len(df)}** valid mutated binaries were generated\n"
    binary_info += f"- The target arch was {results[0].target}\n"
    binary_info += f"- The compile command was: `{' '.join(compile_cmd)}`\n"
    binary_info += "- The optimization level was: O0\n"
    run_cmd = generate_run_cmd(common.program_file, results[0].target)
    run_cmd = ["timeout", f"{common.timeout}s"] + run_cmd
    run_cmd = " ".join(run_cmd)
    binary_info += f"- An example run command: `{run_cmd}`\n"
    binary_info += (
        f"- The NOP for this target is: `{nop}` with values: {nop.value}\n"
    )
    binary_info += (
        f"- The runtime to generate and run all binaries was: {runtime}\n"
    )

    # 2. Exit code frequecies
    #other_returncodes = [
    #    ("critcal_code_ran", 0),
    #    ("critical_code_did_not_run", 97),
    #    ("failed_to_run", -900),
    #]

    freqs = calc_freqs(df, common, other_returncodes)
    table = "## Return Code Frequencies \n"
    table_str = list_tuple_table(["Exit code", "Frequency"], freqs)
    table += table_str

    # 3. list of programs that ran critical code
    list_of_progs = "## Programs that ran critical code \n"

    info = df[
        df["program_stdout"].str.contains(common.expected_stdout, na=False)
    ]
    names = [Path(x).name for x in list(info["binary_path"])]

    list_of_progs += f"**{len(names)}** programs ran the critical code out of **{len(df)}** mutated binaries. The binaires were:\n"

    names_str = ""
    for name in names:
        names_str += f"- {name}\n"

    list_of_progs += names_str

    # 4. Disassembly of the files that ran critical code
    # 10 bytes on either side will be included
    pad = 10
    bins = [Path(x) for x in list(info["binary_path"])]

    disassems = ""
    for i, bin in enumerate(bins):
        if is_bit:
            mut_addr = bin.name.replace(f"{common.program_file.name}_", "")
            mut_addr = mut_addr.split("_")[0]
            mut_addr = int(mut_addr, 16)
        else:
            mut_addr = int(
                bin.name.replace(f"{common.program_file.name}_", ""), 16
            )

        start_addr = mut_addr - pad
        end_addr = mut_addr + pad

        ret = disasm(
            [common.program_file.absolute(), bin],
            start_addr,
            end_addr,
            text=True,
            verbose=False,
        )

        disassems += f"#### Program {i} {bin.name} diassemebly vs vanilla\n\n"
        disassems += "```\n"
        disassems += ret
        disassems += "```\n"
        disassems += "\n\n"

    lines = "## Source Code Lines\n"
    lines += "```c\n"

    # Program file source code:
    with open(source_code, "r") as f:
        for v in f.readlines():
            lines = lines + v

    lines += "```\n"

    with open(report_path, "w") as f:
        f.write(title)
        f.write("\n\n")
        f.write(settings_bullets)
        f.write("\n\n")
        f.write(binary_info)
        f.write("\n\n")
        f.write(table)
        f.write("\n\n")
        f.write(list_of_progs)
        f.write("\n\n")
        f.write(disassems)
        f.write("\n\n")
        f.write(lines)

    # Generate the pdf version
    generate_pdf_report(
        report_path.absolute(),
        report_path.parent.joinpath(
            report_path.name.replace(".md", ".pdf")
        ).absolute(),
    )

    return


@app.command
def run(inps: list[Path] = [Path("experiment.toml")]):
    """
    This will run ALL the experiments in the provided experiment file
    """

    settings = dynaconf.Dynaconf(settings_files=inps)

    experiments = settings.get("experiment", {})

    commands = {
        # "nop": nop,
        # "bit": bit,
        # "nop_exp": nop_exp,
        "many_nop": many_nop,
        "many_bit": many_bit,
        "para_nop": para_nop,
        "para_bit": para_bit,
        "nop_no_comp_inout": nop_no_comp_inout,
        "bit_no_comp_inout": bit_no_comp_inout,
    }

    for exp_name, exp in experiments.items():
        print(f"Running {exp_name}")

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
        elif command_name in ["para_nop", "para_bit"]:
            target = formated.pop("target")
            num_cpus = formated.pop("num_cpus")
            params = CommandParameters(**formated)

            # Get the other required params
            cmd_func(params, target=target, num_cpus=num_cpus)
        elif command_name in ["nop_no_comp_inout", "bit_no_comp_inout"]:
            ins = formated.pop('ins')
            outs = formated.pop('outs')
            target = formated.pop('target')
            nocomp = formated.pop('no_compile')
            expected_correct = int(formated.pop('expected_correct'))
            params = CommandParameters(**formated)
            cmd_func(params, ins=ins, outs=outs, expected_correct=expected_correct) #, target=target, num_cpus=num_cpus)


    return


@app.command
def gather_reports(
    inp: Path, out: Path, force: bool = False, substrs: list[str] = []
):
    """
    Gather the reports in the directory
    """

    if out.exists():
        if not force:
            print(
                f"The destination already exists, if this is okay pass the force command"
            )
            return

        if out.is_file():
            print(
                f"The destination already exists is is a file. Please provide a new output"
            )
            return

        out.mkdir(parents=True, exist_ok=True)
    else:
        out.mkdir(parents=True)

    if not (inp.is_dir() and inp.exists()):
        print(f"The inp {inp} does not exist")
        return

    for p in inp.rglob("*"):
        if p.name == "report.pdf":
            # Filter for the substrs
            if (not any(x in str(p.parent) for x in substrs)) or (
                substrs != []
            ):
                continue

            shutil.copy(p, out.joinpath(p.parent.name + ".pdf"))
    return


@app.command
def get_overhead(
    output: Path,
    target: Target,
    runtime_inp: str,
    inps: list[Path],
    run_count: int = 10,
    timeout: int = 10,
) -> None:
    """
    Compare the overhead of files

    Common use case will be to compare a 'unsafe' program
    to programs that apply some mitigations

    The inputs should be r
    """

    results = []

    out = Path(".tmp")
    out.mkdir(exist_ok=True)

    for inp in inps:
        print(inp)

        # Count lines:
        with open(inp, "r") as f:
            source_len = len(f.readlines())

        # Compile
        comp_inp = compile_program(inp, out.joinpath(inp.name), target)

        print(comp_inp)

        # Assm len
        disasm = disassemble_text_section(comp_inp)
        num_inst = len(disasm)

        # Runtime
        # tot_runtime = timedelta()
        tot_runtime = 0

        for _ in range(run_count):
            _, _, _, runtime = timed_run_binary_w_input(
                comp_inp, runtime_inp, target, timeout
            )
            tot_runtime += runtime

        results.append((source_len, num_inst, tot_runtime / run_count))

    if output.exists():
        raise Exception

    with open(output, 'w') as f:
        for i, info in enumerate(results):
            print(f"INP {inps[i]} results: {info}")
            f.write(f"{inps[i]} | {' | '.join(str(x) for x in info)}\n")


    # out.unlink()
    shutil.rmtree(out)

    return


def dataset_split_random(data, val_size=0.25, test_size=0.25, random_state=3, column='split'):
    """
    Split DataFrame into 3 non-overlapping parts: train,val,test with specified proportions

    Returns a new DataFrame with the rows marked by the assigned split in @column
    """
    train_size = (1.0 - val_size - test_size)
    
    train_val_idx, test_idx = train_test_split(data.index, test_size=test_size, random_state=random_state)
    val_ratio = (val_size / (val_size+train_size))
    train_idx, val_idx = train_test_split(train_val_idx, test_size=val_ratio, random_state=random_state)

    train = data.loc[train_idx]
    val = data.loc[val_idx]
    test = data.loc[test_idx]

    return train, val, test


def evaluate_model(bin_path:Path, test, arm:bool):

    # Make predictions on dataset
    X_test = test[['x','y']]
    Y_test = test[['label']]

    y_pred_c = predict(str(bin_path), X_test, 5, arm)

    f1_score_c = sklearn.metrics.f1_score(Y_test, y_pred_c)
    return f1_score_c

def predict(bin_path, X, timeout:int, use_arm: bool = False):

    def predict_one(x):
        if use_arm:
            args = [ "qemu-arm-static", bin_path, str(x[0]), str(x[1]) ]
        else:
            args = [ bin_path, str(x[0]), str(x[1]) ]


        args = ["timeout", f"{timeout}s"] + args
        out = subprocess.check_output(args)
        cls = int(out)
        return cls

    y = [ predict_one(x) for x in np.array(X) ]
    return np.array(y)






@app.command()
def nn_test(inp:Path,out:Path, num_cpus: int):
#def nn_test(inp:Path, dataset: Path, out:Path):
    """
    A very hard coded version to run a NN using emlearn
    """

    out.mkdir(exist_ok=True)

    disasm = disassemble_text_section(inp)

    # Load the target type
    target = detect_target(inp)
    if target == Target.ARM_32:
        arm = True
    else:
        arm = False

    logger.debug(f"Detected Target: {target}")

    mutated_bins = []
    bin_futures = []
    #with ThreadPoolExecutor(max_workers=max_workers) as executor:
    #    for inst in alive_it(disasm, title='submitting mutations'):
    #        future = executor.submit( _generate_nop_mutated_bin, inp,target, inst, out)
    #        bin_futures.append(future)
    #    total_tasks = len(bin_futures)


    #    # for _, future in enumerate(futures):
    #    with alive_bar(total_tasks, title="Collecting mutations") as bar:
    #        for future in as_completed(bin_futures):
    #            # Check the status codes
    #            mutated_bins.append(future.result())
    #            bar()  # increment the progress bar by 1

    results = []
    for inst in alive_it(disasm, title='generating mutatations'):
        res = _generate_nop_mutated_bin(inp, target, inst, out)
        mutated_bins.append(res)
        results.append(nn_helper(res,arm))
        res.unlink()


    # For mutation in mutatations, get the f1 
    expected_acc = 0.9677

    good_res = {}
    bad_res = {}
    failed_bin = []


    futures = []


    #with ThreadPoolExecutor(max_workers=max_workers) as executor:
    #    # Run the threads
    #    for bin in mutated_bins:
    #        future = executor.submit(nn_helper, bin, arm)
    #        futures.append(future)
    #    total_tasks = len(futures)

    #    # for _, future in enumerate(futures):
    #    with alive_bar(total_tasks, title="Running nets") as bar:
    #        for future in as_completed(futures):
    #            # Check the status codes
    #            results.append(future.result())
    #            bar()  # increment the progress bar by 1

    for (bin, model_acc) in results:
        if abs(model_acc- expected_acc) < .03:
            good_res[bin.name] = model_acc
        elif model_acc == -99_9999:
            failed_bin.append(failed_bin)
        else:
            bad_res[bin.name] = model_acc



    #for bin in alive_it(mutated_bins):
    #    #compiled_model_path = Path(bin).absolute()

    #    try:
    #        acc = evaluate_model(bin, test, arm)

    #        if abs(acc - expected_acc) < .03:
    #            good_res[bin.name] = acc
    #            print(f"File {bin} had Acc: {acc}")
    #        else:
    #            bad_res[bin.name] = acc
    #    except Exception as e:
    #        failed_bin.append(bin.name)

    print(f"Had {len(good_res.keys())} good results")
    print(f"Had {len(bad_res.keys())} bad results")
    print(f"Had {len(failed_bin)} failed results")


    # Need to mutate the binay
    return

def nn_helper(model, arm):

    dataset = Path("test_packages/emlearn/examples/dataset.csv")
    df= pd.read_csv(dataset)
    _, _, test = dataset_split_random(df, test_size=0.10)
    try:
        acc = evaluate_model(model, test, arm)
        return (model, acc)
    except Exception as e:
        return (model, -99_999)

@app.command()
def new_nn_test(inp:Path, out:Path, test_size:int):
    """
    Temp function to run against the new neural net
    """

    out.mkdir(exist_ok=True)

    disasm = disassemble_text_section(inp)

    # Load the target type
    target = detect_target(inp)
    if target == Target.ARM_32:
        arm = True
    else:
        arm = False

    logger.debug(f"Detected Target: {target}")


    mutated_bins = [] 
    for inst in alive_it(disasm, title="generating mutations"):
        # 1. mutate 
        mutated_bins.append(_generate_nop_mutated_bin(inp, target, inst, out))

    # Now, for each bin I need to see if, for every input 
    # there is a potential difference. 
    # 
    # There are index 0-449, so, first obtain the correct 
    # predictions from the original model, anything with 
    # "CORRECT" in the stdout 

    baseline_correct_predictions = []
    for i in range(test_size):
        stdout = class_helper(inp, i, 5, arm)
        print(stdout)
        if "CORRECT" in stdout.decode():
            baseline_correct_predictions.append(i)

    # Now, try only those in the mutated model and see what 
    # we get 
    results = []

    atleast_one_mistake = 0

    for bin in alive_it(mutated_bins, title='testing mutations'):
        bin_results = {
            'correct' : [],
            'wrong' : [],
            'failed' : [],
        }

        for i in baseline_correct_predictions:
            try:
                stdout = class_helper(bin, i, 1, arm)
                if "CORRECT" in stdout.decode():
                    bin_results['correct'].append(bin)
                elif "WRONG" in stdout.decode():
                    bin_results['wrong'].append(bin)
                    print(f"Bin: {bin} wrong on {i}")
                else:
                    bin_results['failed'].append(bin)
            except:
                bin_results['failed'].append(bin)

        if len(bin_results['wrong']) > 0:
            atleast_one_mistake +=1
        if len(bin_results['failed']) > 0:
            atleast_one_mistake +=1

        results.append((bin,bin_results))

    console.print(f"Baseline correctly labeled {len(baseline_correct_predictions)} inputs")
    console.print(f"Of {len(mutated_bins)}, {atleast_one_mistake} mutated bins incorrect labeled an input that baseline correctly labeld")

    for (bin,res) in results:
        if len(res['wrong']) > 0:
                print(f"{bin.name} | mistakes: {res['wrong']}\n")

    with open("TEMPDELME.txt", 'w') as f:
        for (bin,res) in results:
            if len(res['wrong']) > 0:
                f.write(f"{bin.name} | mistakes: {res['wrong']}\n")



    return

def class_helper(bin_path: Path, input:int, timeout:int, use_arm:bool):
    """
    Helper for a simple nerual net 
    """

    if use_arm:
        args = [ "qemu-arm-static", bin_path, str(input) ]
    else:
        args = [ bin_path, str(input) ]

    args = ["timeout", f"{timeout}s"] + args
    out = subprocess.check_output(args,
            stderr=subprocess.DEVNULL  
                                      )

    return out



def plot_faults_and_failures(start_addr, end_addr, faulted_addresses, failed_addresses):
    """
    Plot vertical lines marking faulted and failed addresses over a given address range.

    Parameters
    ----------
    start_addr : int or float
        The lower bound of the x-axis (start address).
    end_addr : int or float
        The upper bound of the x-axis (end address).
    faulted_addresses : list of int/float
        Addresses where faults occurred (plotted in yellow).
    failed_addresses : list of int/float
        Addresses where failures occurred (plotted in red).
    """
    _, ax = plt.subplots(figsize=(10, 2))

    # Set the address range on the x-axis
    ax.set_xlim(start_addr, end_addr)
    ax.set_ylim(0, 1)

    # Plot faulted addresses
    for addr in faulted_addresses:
        ax.axvline(x=addr, color='yellow', linestyle='--', linewidth=2, label='Faulted')

    # Plot failed addresses
    for addr in failed_addresses:
        ax.axvline(x=addr, color='red', linestyle='-', linewidth=2, label='Failed')

    # Create a legend without duplicate entries
    handles, labels = ax.get_legend_handles_labels()
    unique = dict(zip(labels, handles))
    ax.legend(unique.values(), unique.keys(), loc='upper right')

    ax.set_xlabel('Address')
    ax.set_yticks([])               # hide y-tick marks
    ax.set_title('Memory Faults and Failures')

    return plt




@app.command()
def gen_fault_plot(inp:Path):
    """
    Generate a plot of addresses with a line at the addresses that 
    caused a successful fualt, and a line at the addresses that 
    caused the program to fail to run 

    Input
    -----
    csv with two 
    """
    return 


@app.command()
def generate_exp_file( exp_file_out: Path, out_dir:Path, target:Target, timeout:int,  expected_stdouts: str,  program_inputs:str, program_file:Path, expected_correct: int):
    """
    Save a toml that defines the experiment for the neural networks

    With this, a binary is ran on many input and expected output pairs
    """


    inputs_str = ",".join([f"'{x}'" for x in program_inputs])
    output_str = ",".join([f"'{x}'" for x in expected_stdouts])

    file = [f'[experiment.nop_no_comp_inout]',
        f"command = 'nop_no_comp_inout'",
        f"expected-stdout = ''",
        f"program-input= ''",
        f"program-file = '{str(program_file.absolute())}'",
        f"ins = [{inputs_str}]",
        f"expected-returncode = ''",
        f"outs = [{output_str}]",
        f"list-expected = false",
        f"timeout = {timeout}",
        f"out-dir = '{str(out_dir.absolute())}'",
        "yes= true ",
        f"target = '{target.name}' ",
        f"expected-correct= '{expected_correct}' ",
        f"no_compile= true "]

    # Make parent out 
    if not exp_file_out.parent.exists():
        exp_file_out.parent.mkdir(parents=True)

    with open(exp_file_out, 'w') as f:
        for line in file:
            f.write(line + '\n')

    return 


@app.command()
def nn_generate_exp_files( exp_file: Path, binary:Path, timeout:int, out_dir:Path,  input_dir:Path, expected_correct:int):
    """
    A temporary function to generate experiemnt files for classifier testing
    """

    target = detect_target(binary)

    outs = []
    ins = []

    # Iterate over the images 
    for file in input_dir.glob('*'):
        _, _, lbl = file.name.split('_')
        lbl = lbl.split('.')[0]
        ins.append(str(file.absolute()))
        outs.append(lbl)

    generate_exp_file(exp_file, out_dir, target=target, timeout=timeout, expected_stdouts=outs, program_inputs=ins, program_file=binary,expected_correct=expected_correct)

    return 


if __name__ == "__main__":
    setup_logger(console_level="DEBUG")

    logger = logging.getLogger(__name__)   # module-level logger

    app()
