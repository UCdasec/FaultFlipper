from pathlib import Path

import random
import lief
from angr_backend import sim_binary_w_input
from binary_tools import (
    Target,
    count_bit_differences,
    generate_data_bit_flip,
    generate_nops_mutated_bin,
    generate_x_bits_mutated_file,
    run_binary_w_input,
    shift_exit_code,
)


def x_bit_angr_helper(common, inst, target: Target, num_bits: int, func_names, timeout):
    """Generate all mutations and run each for the target binary with angr.

    Run a binary and capture its output - This version will return
    multiple results
    """
    if common.program_input[-1:] != "\n":
        common.program_input = common.program_input + "\n"
    else:
        common.program_input = common.program_input

    inst_bits = list("".join([str(bin(byte)[2:]).zfill(8) for byte in inst.bytes]))
    results = []

    # For every bit see if we get a valid opcode.
    for i in range(len(inst_bits) - num_bits + 1):
        out_file = generate_x_bits_mutated_file(
            i, inst_bits, target, inst, common, num_bits
        )

        if out_file is None:
            continue

        # Sanity check that a single bit has been changed and thats it
        mutated_text = lief.parse(out_file).get_section(".text")
        binary = lief.parse(common.program_file)
        vanilla_text = binary.get_section(".text")

        number_of_different_bits = count_bit_differences(
            mutated_text.content, vanilla_text.content
        )

        if number_of_different_bits != num_bits:
            raise Exception("Mutated wrong")

        out_file, returncode, inst, common, target, stdout, captured = run_simulation(
            common, inst, target, func_names, timeout, out_file
        )

        results.append(
            (out_file, returncode, inst, common, target, stdout, captured, i)
        )

    return results


def x_bit_para_run_helper(
    common, inst, target: Target, num_bits: int, instr_probs: dict[str, float] | None
):
    """
    Run a binary and capture its output - This version will return
    multiple results
    """
    if common.program_input[-1:] != "\n":
        input = common.program_input + "\n"
    else:
        input = common.program_input

    inst_bits = list("".join([str(bin(byte)[2:]).zfill(8) for byte in inst.bytes]))
    results = []

    inst_bits = list("".join([str(bin(byte)[2:]).zfill(8) for byte in inst.bytes]))
    results = []

    # For every bit see if we get a valid opcode.
    for i in range(len(inst_bits) - num_bits + 1):
        out_file = generate_x_bits_mutated_file(
            i, inst_bits, target, inst, common, num_bits
        )

        if out_file is None:
            continue

        # Sanity check that a single bit has been changed and thats it
        mutated_text = lief.parse(out_file).get_section(".text")
        binary = lief.parse(common.program_file)
        vanilla_text = binary.get_section(".text")

        number_of_different_bits = count_bit_differences(
            mutated_text.content, vanilla_text.content
        )

        if number_of_different_bits != num_bits:
            raise Exception("Mutated wrong")

        if instr_probs:
            # probabilistically choose to skip faulting that instruction
            instr_prob = instr_probs.get(inst.mnemonic, 1)
            # instr_prob is the probability that we SHOULD fault the instruction
            # if statement represents probability that we DO NOT fault the instruction
            if random.random() < (1 - instr_prob):
                continue

        try:
            returncode, stdout, stderr = run_binary_w_input(
                out_file, input, target, common.timeout
            )

            if returncode is not None:
                returncode = shift_exit_code(returncode)

            results.append(
                (out_file, returncode, inst, common, target, stdout, stderr, i)
            )
        except Exception:
            results.append((out_file, -900, inst, common, target, "", "", i))

    return results


def x_nop_para_run_helper(common, insts, target: Target):
    """
    Run a binary and capture its output
    """
    if common.program_input[-1:] != "\n":
        common.program_input += "\n"

    # Generate the mutated binary
    try:
        out_path = common.out_dir.joinpath(
            common.program_file.name + f"_{hex(insts[0].address)}"
        )
        out_file = generate_nops_mutated_bin(
            common.program_file, target, insts, out_path
        )

    except Exception as e:
        print(f"Issue making binary: {e}")
        return Path(""), -100, insts, common, target, "", ""

    try:
        returncode, stdout, stderr = run_binary_w_input(
            out_file, common.program_input, target, common.timeout
        )

        if returncode is not None:
            returncode = shift_exit_code(returncode)
        return out_file, returncode, insts, common, target, stdout, stderr
    except Exception as e:
        print(f"Failed to run bin with {e}")
        return out_file, -100, insts, common, target, "", ""


# TODO: Data struct for results


def x_data_para_run_helper(common, data_idx, target: Target, target_section):
    """
    Run a binary and capture its output
    """
    if common.program_input[-1:] != "\n":
        common.program_input += "\n"

    results = []

    # Generate hte mutated binary
    for i in range(8):
        try:
            out_path = common.out_dir.joinpath(
                common.program_file.name + f"_{data_idx}_{i}"
            )
            out_file = generate_data_bit_flip(
                common.program_file,
                data_idx,
                i,
                out_path,
                target_section=target_section,
            )

        except Exception as e:
            print(f"Issue making binary: {e}")
            results.append((Path(""), -100, data_idx, common, target, "", "", i))
            continue

        try:
            returncode, stdout, stderr = run_binary_w_input(
                out_file, common.program_input, target, common.timeout
            )

            if returncode is not None:
                returncode = shift_exit_code(returncode)

            results.append(
                (out_file, returncode, data_idx, common, target, stdout, stderr, i)
            )

        except Exception as e:
            print(f"Failed to run bin with {e}")
            results.append((out_file, -100, data_idx, common, target, "", "", i))

    return results


def x_nop_angr_helper(
    common, insts, target: Target, func_names: list[str], timeout: int
):
    """
    Run a binary and capture its output with angr
    """
    if common.program_input[-1:] != "\n":
        common.program_input += "\n"

    # Generate hte mutated binary
    try:
        out_path = common.out_dir.joinpath(
            common.program_file.name + f"_{hex(insts[0].address)}"
        )
        out_file = generate_nops_mutated_bin(
            common.program_file, target, insts, out_path
        )

    except Exception as e:
        print(f"Issue making binary: {e}")
        return Path(""), -100, insts, common, target, "", ""

    return run_simulation(common, insts, target, func_names, timeout, out_file)

    # try:
    #    returncode, stdout, captured = sim_binary_w_input(
    #        out_file, common.program_input, func_names, timeout
    #    )

    #    if returncode is not None:
    #        returncode = shift_exit_code(returncode)
    #    return out_file, returncode, insts, common, target, stdout, captured
    # except Exception as e:
    #    print(f"Failed to run bin with {e}")
    #    return out_file, -100, insts, common, target, None, None


def run_simulation(common, insts, target, func_names, timeout, out_file):

    try:
        returncode, stdout, captured = sim_binary_w_input(
            out_file, common.program_input, func_names, timeout
        )

        if returncode is not None and isinstance(returncode, int):
            returncode = shift_exit_code(returncode)
        return out_file, returncode, insts, common, target, stdout, captured
    except Exception as e:
        print(f"Failed to run bin with {e}")

        return out_file, -100, insts, common, target, None, None


def nop_para_run_helper(common, inst, target: Target):
    """
    Run a binary and capture its output
    """
    if common.program_input[-1:] != "\n":
        common.program_input += "\n"

    # Generate hte mutated binary
    try:

        insts = [inst]
        out_path = common.out_dir.joinpath(
            common.program_file.name + f"_{hex(insts[0].address)}"
        )
        out_file = generate_nops_mutated_bin(
            common.program_file, target, insts, out_path
        )

    except Exception as e:
        print(f"Issue making binary: {e}")
        return Path(""), -100, inst, common, target, "", ""

    try:
        returncode, stdout, stderr = run_binary_w_input(
            out_file, common.program_input, target, common.timeout
        )

        if returncode is None and stdout is None and stderr is None:
            print("Failed to run")
            return out_file, None, inst, common, target, None, None

        if returncode is not None:
            returncode = shift_exit_code(returncode)
        return out_file, returncode, inst, common, target, stdout, stderr
    except Exception as e:
        print(f"Failed to run bin with {e}")
        return out_file, -100, inst, common, target, "", ""
