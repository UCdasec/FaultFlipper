import lief
import json
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from report_utils import list_tuple_table, generate_pdf_report
from sklearn.model_selection import train_test_split
import sklearn
from datetime import datetime
import shutil
import logging
import dynaconf
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import numpy as np
from pathlib import Path
from cyclopts import App
from rich.console import Console
import subprocess
import pandas as pd
from alive_progress import alive_it
from logger_utils import setup_logger
from cli_utils import (
    CommandParameters,
    Backends,
    RegCommandParameters,
    show_results,
    calc_freqs,
    BitFlipExperimentResult,
    NopExperimentResult,
    smol_show_results,
    RegNopExperimentResult,
    RegBitFlipExperimentResult,
)

from binary_tools import (
    Target,
    get_return_reg,
    Nop,
    shift_exit_code,
    _generate_nop_mutated_bin,
    generate_nops_mutated_bin,
    generate_bit_mutated_file,
    generate_double_bit_mutated_file,
    detect_target,
    count_bit_differences,
    run_binary_w_input,
    is_valid_instruction,
    run_binary_w_calltime_input,
    timed_run_binary_w_input,
    generate_run_cmd,
    disassemble_text_section,
    sim_binary_w_input,
    fast_sim_binary_w_input,
    sim_binary_w_calltime_input,
)

from parallel_runner import (
    bit_para_run_helper,
    double_bit_para_run_helper,
    double_nop_para_run_helper,
    nop_para_run_helper,
    x_bit_para_run_helper,
    x_nop_para_run_helper,
    x_nop_angr_helper,
    x_bit_angr_helper,
)


console = Console()
app = App()

DEFAULT_LOGS = Path("faultsim_log")
if not DEFAULT_LOGS.exists():
    DEFAULT_LOGS.mkdir()


other_returncodes = [
    # ("critical_code_ran", 0),
    ("critical_code_did_not_run", 97),
    ("failed_to_run", -900),
]


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


def dataclass_to_dataframe(
    result: list[NopExperimentResult] | list[BitFlipExperimentResult],
) -> pd.DataFrame:
    """
    Convert a dataclass to an experiment result
    """
    return pd.DataFrame([r.to_dict() for r in result])


def save_df(df: pd.DataFrame, out: tuple[Path, None]) -> None:
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

def bit_inout_runner(inst, target, common, ins, outs, result_out, source_code):
    """A helper to run a bit mutantion on the file, and test on the inputs."""

    # Need to pad the left with zeroes
    inst_bits = list("".join([str(bin(byte)[2:]).zfill(8) for byte in inst.bytes]))
    results = []

    # For every bit see if we get a valid opcode.
    for i in range(len(inst_bits)):
        # Generate the mutated binary - If we did not generate a good one continue
        out_file = generate_bit_mutated_file(i, inst_bits, target, inst, common)

        if out_file is None:
            continue

        # Run all the possible inputs and outputs
        for cur_in, cur_out in zip(ins, outs):
            cur_in = Path(cur_in)

            # See if the intermediate result exists yet
            intermediate_out = result_out.joinpath(
                out_file.name + f"_{cur_in.name.split('.')[0]}" + f"_{i}_" + ".json"
            )

            if intermediate_out.exists():
                # Load and skip test
                with open(intermediate_out, "r") as f:
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
                with open(intermediate_out, "w") as f:
                    json.dump(dicted_result, f)
            results.append(result)
    print("ret")

    return results


@app.command
def bit_no_comp_inout(
    common: CommandParameters,
    source_code: Path | None = None,
    ins: list[str] | None = None,
    outs: list[str] | None = None,
    expected_correct: int | None = None,
    num_cpus: int = 24,
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
            cont = str(input(f"Normal for {len(disasm)} instructions? (Yy/Nn)"))

            if cont.lower() != "y":
                return

        # Load the target type
        target = detect_target(common.program_file)
        logger.debug(f"Detected Target: {target}")

        results: list[BitFlipExperimentResult] = []
        futures = []

        with ThreadPoolExecutor(max_workers=num_cpus) as executor:
            # Run the threads
            for inst in alive_it(disasm, title="Submitting tasks"):
                future = executor.submit(
                    bit_inout_runner,
                    inst,
                    target,
                    common,
                    ins,
                    outs,
                    result_out,
                    source_code,
                )
                futures.append(future)

            with alive_bar(len(futures), title="Processing tasks") as bar:
                for future in as_completed(futures):
                    # Check the status codes
                    result = future.result()
                    results.extend(result)
                    bar()

        df = dataclass_to_dataframe(results)
        save_df(df, common.save_results)

    print(f"Return code value counts... col names {df.columns}")
    print(df["return_code"].value_counts())
    print(f"DF shape: {df.shape}")

    # Number of (bin, inp) paris that had the expected output
    correct_prediction_mask = df.apply(
        lambda row: str(row["expected_stdout"]) in str(row["program_stdout"]), axis=1
    )

    print(
        f"Accoring to the correct predficton mask the total nmber of corrrect is {correct_prediction_mask.sum()}"
    )

    df["correct"] = [
        exp in prog
        for exp, prog in zip(
            df["expected_stdout"].astype(str), df["program_stdout"].astype(str)
        )
    ]

    print(f"The total number of correct predicionts: {df['correct'].sum()}")

    df["failed"] = df["return_code"] == -999

    ROWS_PER_COMBO = (
        df.groupby(["flipped_addr", "flipped_index"]).size().iloc[0]
    )  # → 10 in your data

    # ── 1. Group on the (addr, index) *pair* instead of the old nopped_addr column ──
    agg_df = (
        df.groupby(["flipped_addr", "flipped_index"])
        .agg(total_correct=("correct", "sum"), total_failed=("failed", "sum"))
        .reset_index()
    )

    # ── 2. Quick sanity-checks ─────────────────────────────────────────────────────
    print("Histogram of #correct rows per (addr, idx):")
    print(agg_df["total_correct"].value_counts().sort_index())

    print("Histogram of #failed rows per (addr, idx):")
    print(agg_df["total_failed"].value_counts().sort_index())

    # ── 3. Combos that bombed every single input ───────────────────────────────────
    all_failed = (agg_df["total_failed"] == ROWS_PER_COMBO).sum()
    print(f"{all_failed} mutation combos failed on ALL {ROWS_PER_COMBO} inputs")

    # Sum of ALL cases where a prediction was correct
    # total_equal = correct_prediction_mask.sum()
    total_equal = df["correct"].sum()
    print(f"{total_equal} correct input binary pairs")

    grouped_df = df.groupby(["flipped_addr", "flipped_index"])

    # Per nopped addr, get the number of correct predictions
    # correct_per_mutated = df[correct_prediction_mask].groupby(['flipped_addr', 'flipped_index']).size().reset_index(name='count')
    # Jkcorrect_per_mutated = df.groupby(['flipped_addr', 'flipped_index'])["correct"].sum()
    correct_per_mutated = grouped_df["correct"].sum()

    counts = correct_per_mutated.value_counts()
    print(f"The value counts of correct predictions:")
    print(counts)

    # TODO: These are wrogn
    # Get the list of binaries that got the same expected
    # expected_correct_mutations =  correct_per_mutated["count"] == expected_correct
    num_correct_mutations = (correct_per_mutated == expected_correct).sum()
    # num_correct_mutations = counts == expected_correct
    print(
        f"Number of files that got the expected number of correct predictions:\n {num_correct_mutations}"
    )

    # expected_correct_mutations =  correct_per_mutated["count"] < expected_correct
    num_less_mutations = (correct_per_mutated < expected_correct).sum()
    print(
        f"Number of files that got less than the expected number of correct predictions:\n {num_less_mutations}"
    )

    show_results(common, df, other_returncodes)
    return df


@app.command
def angr_nop_no_comp_inout(
    common: CommandParameters,
    func_names: str,
    timeout: int = 3,
    source_code: Path | None = None,
    ins: list[str] | None = None,
    outs: list[str] | None = None,
    expected_correct: int | None = None,
    debug_max_loop: int | None = None,
) -> pd.DataFrame:
    """
    This version of the experiments takes tuples of:
    [ (INPUT, EXPECTED_OUTPUT), ....]

    And runs each mutated program on _every tuple_.

    So if we have 4 tuples, and 10 mutated programs, we get
    40 results in total.
    """

    func_names = func_names.split(",")

    total_normal = 0
    total_upset = 0
    total_error = 0

    other_returncodes = [
        # ("critical_code_ran", 0),
        # ("critical_code_did_not_run", 97),
        ("failed_to_run", -999),
        ("correct_prediction", 0),
    ]

    gold_data = {}

    tot_good_res = []
    tot_bad_res = []
    tot_error_res = []

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
            cont = str(input(f"Normal for {len(disasm)} instructions? (Yy/Nn)"))

            if cont.lower() != "y":
                return

        # Load the target type
        target = detect_target(common.program_file)
        logger.debug(f"Detected Target: {target}")

        results: list[RegNopExperimentResult] = []

        # disasm = disasm[0:1]
        tmp = 0
        debug_max_loop = 2

        # Iterate over single instructions
        for inst in alive_it(disasm):
            tmp += 1

            if debug_max_loop and tmp >= debug_max_loop:
                break

            print(f"Tmp is current: {tmp}")

            # The out file is at out_dir/...
            # out_file = generate_nop_mutated_bin(common, target, inst)

            insts = [inst]
            out_path = common.out_dir.joinpath(
                common.program_file.name + f"_{hex(insts[0].address)}"
            )
            out_file = generate_nops_mutated_bin(
                common.program_file, target, insts, out_path
            )

            # out_file = generate_nops_mutated_bin(common, target, [inst])

            # Run all the possible inputs and outputs
            for cur_in, cur_out in zip(ins, outs):
                cur_in = Path(cur_in)

                # See if the intermediate result exists yet
                intermediate_out = result_out.joinpath(
                    out_file.name + f"_{cur_in.name.split('.')[0]}" + ".json"
                )

                if cur_in not in gold_data.keys():
                    gold_ret, gold_stdout, gold_reg_info = sim_binary_w_calltime_input(
                        out_file, str(cur_in.absolute()), func_names, timeout * 60
                    )
                    gold_data[cur_in] = (gold_ret, gold_stdout, gold_reg_info)

                if intermediate_out.exists():
                    print(f"Reading existing file {intermediate_out}")
                    # Load and skip test
                    with open(intermediate_out, "r") as f:
                        result = json.load(f)
                        result = RegNopExperimentResult(**result)
                else:
                    # Test the binary

                    ret, stdout, reg_info = sim_binary_w_calltime_input(
                        out_file, str(cur_in.absolute()), func_names, timeout * 60
                    )
                    result = RegNopExperimentResult(
                        source_file=source_code,
                        unmutated_binary=common.program_file,
                        binary_path=out_file,
                        nopped_addr=inst.address,
                        program_input=cur_in,
                        return_code=ret,
                        program_stdout=stdout,
                        target=target,
                        expected_returncode=common.expected_returncode,
                        expected_stdout=cur_out,
                        custom_returncodes=other_returncodes,
                        source_code=source_code,
                        reg_info=reg_info,
                    )
                    dicted_result = result.to_dict()
                    with open(intermediate_out, "w") as f:
                        json.dump(dicted_result, f)

                results.append(result)

            # print(f"THIRD ARG: {[x[2] for x in gold_data.values()]}")
            good_res, bad_res, error_case = analyze_reg_results(
                results, func_names, gold_data
            )

            tot_good_res.extend(good_res)
            tot_bad_res.extend(bad_res)
            tot_error_res.extend(error_case)
            print(
                f"BIN: at {tmp}  had {len(good_res)} norm {len(bad_res)} event_upset, and {len(error_case)} error"
            )

        print(
            f"BIN:  had {len(good_res)} norm {len(bad_res)} event_upset, and {len(error_case)} error"
        )

        total_normal += len(good_res)
        total_upset += len(bad_res)
        total_error += len(error_case)

        # df = dataclass_to_dataframe(results)
        # save_df(df, common.save_results)

    print(f"Total normal: {total_normal}")
    print(f"Total upset: {total_upset}")
    print(f"Total error: {total_error}")
    with open("RES.txt", "w") as f:
        f.write(f"Total normal: {total_normal}")
        f.write(f"Total upset: {total_upset}")
        f.write(f"Total error: {total_error}")
    return

    # Doing the analyiss.............................

    print(f"Return code value counts... cols: {df.columns}")
    print(df["return_code"].value_counts())

    # Add a column to see if there was a match

    df["correct"] = df.apply(
        lambda row: str(row["expected_stdout"]) in str(row["program_stdout"]), axis=1
    )

    df["failed"] = df["return_code"] == -999

    # Use this to get the number of mutated bines that
    # got 0 correct BUT still ran correctly
    addrs_with_failed = df.loc[df["return_code"] == -999, "nopped_addr"].unique()
    df_no_fail = df[~df["nopped_addr"].isin(addrs_with_failed)]

    # nopped addrs that have one failed ANY

    # Grop by the addr and record the failed and correct
    agg_df = (
        df.groupby("nopped_addr")
        .agg(total_correct=("correct", "sum"), total_failed=("failed", "sum"))
        .reset_index()
    )

    agg_df_no_fail = (
        df_no_fail.groupby("nopped_addr")
        .agg(total_correct=("correct", "sum"), total_failed=("failed", "sum"))
        .reset_index()
    )

    print(f"We have {agg_df.shape} shaped agg df")
    print(f"We have {agg_df_no_fail.shape} shaped agg df no fail")

    # This is the count of number of corrects. Notice, that
    # if the number of correct predictions is 0 it may
    # or may not be a case where the model ran correctly
    # and outputed zero.
    print(f"Counts of corrects:\n {agg_df['total_correct'].value_counts()}")
    print(f"Counts of failed:\n {agg_df['total_failed'].value_counts()}")

    print(
        f"NO FAIL Counts of corrects:\n {agg_df_no_fail['total_correct'].value_counts()}"
    )

    # Overlapp of correct and failed
    mask = (agg_df["total_failed"] != 0) & (agg_df["total_correct"] != 0)
    print(
        f"Number of nonzero failed and nonzero correct:\n {agg_df[mask].value_counts()}"
    )

    # See how many counts of correct == expected cont
    print(
        f"Therefore, of {agg_df.shape[0]} mutated bins, {(agg_df['total_correct'] == expected_correct).sum()} had the same number of correct predictions"
    )
    print(
        f"Therefore, of {agg_df.shape[0]} mutated bins, {(agg_df['total_correct'] < expected_correct).sum()} had less than the correct predictions"
    )
    print(
        f"Therefore, of {agg_df.shape[0]} mutated bins, {(agg_df['total_failed'] >= 1).sum()} had atleast one sample that caused a failed experiment"
    )

    show_results(common, df, other_returncodes)

    return df


def nn_inout_runner(common, inst, result_out, target, ins, outs, source_code):
    """Function to help with running parallel neural network in outs.

    That is. This function, given one instruction, will rewrite it with a
    nop, then test the mutant binary on all the in files.
    """

    insts = [inst]
    out_path = common.out_dir.joinpath(
        common.program_file.name + f"_{hex(insts[0].address)}"
    )

    # TODO - This is the old function
    out_file = generate_nops_mutated_bin(common.program_file, target, insts, out_path)

    # out_file = generate_nops_mutated_bin(common, target, [inst])

    results = []
    # Run all the possible inputs and outputs
    for cur_in, cur_out in zip(ins, outs):
        cur_in = Path(cur_in)

        # See if the intermediate result exists yet
        intermediate_out = result_out.joinpath(
            out_file.name + f"_{cur_in.name.split('.')[0]}" + ".json"
        )

        if intermediate_out.exists():
            print(f"Reading existing file {intermediate_out}")
            # Load and skip test
            with open(intermediate_out, "r") as f:
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
            )
            dicted_result = result.to_dict()
            with open(intermediate_out, "w") as f:
                json.dump(dicted_result, f)

        results.append(result)

    return results


@app.command
def nop_no_comp_inout(
    common: CommandParameters,
    source_code: Path | None = None,
    ins: list[str] | None = None,
    outs: list[str] | None = None,
    expected_correct: int | None = None,
    num_cpus: int = 24,
) -> pd.DataFrame:
    """
    This version of the experiments takes tuples of:
    [ (INPUT, EXPECTED_OUTPUT), ....]

    And runs each mutated program on _every tuple_.

    So if we have 4 tuples, and 10 mutated programs, we get
    40 results in total.
    """
    other_returncodes = [
        # ("critical_code_ran", 0),
        # ("critical_code_did_not_run", 97),
        ("failed_to_run", -999),
        ("correct_prediction", 0),
    ]

    if common.save_results.exists():
        # Gather the results
        df = pd.read_csv(common.save_results)
        print("Loading existing results")
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
            cont = str(input(f"Normal for {len(disasm)} instructions? (Yy/Nn)"))

            if cont.lower() != "y":
                return

        # Load the target type
        target = detect_target(common.program_file)
        logger.debug(f"Detected Target: {target}")

        results: list[NopExperimentResult] = []

        futures = []

        with ThreadPoolExecutor(max_workers=num_cpus) as executor:
            # Run the threads
            for inst in disasm:
                future = executor.submit(
                    nn_inout_runner,
                    common,
                    inst,
                    result_out,
                    target,
                    ins,
                    outs,
                    source_code,
                )
                futures.append(future)

            with alive_bar(len(futures), title="Processing tasks") as bar:
                for future in as_completed(futures):
                    # Check the status codes
                    result = future.result()
                    results.extend(result)
                    bar()

        df = dataclass_to_dataframe(results)
        save_df(df, common.save_results)

    # Doing the analyiss.............................
    print(f"Return code value counts...cols are {df.columns}")
    print(df["return_code"].value_counts())

    # Add a column to see if there was a match
    df["correct"] = df.apply(
        lambda row: str(row["expected_stdout"]) in str(row["program_stdout"]), axis=1
    )

    df["failed"] = df["return_code"] == -999

    # Use this to get the number of mutated bines that
    # got 0 correct BUT still ran correctly
    addrs_with_failed = df.loc[df["return_code"] == -999, "nopped_addr"].unique()
    df_no_fail = df[~df["nopped_addr"].isin(addrs_with_failed)]

    # nopped addrs that have one failed ANY

    # Grop by the addr and record the failed and correct
    agg_df = (
        df.groupby("nopped_addr")
        .agg(total_correct=("correct", "sum"), total_failed=("failed", "sum"))
        .reset_index()
    )

    agg_df_no_fail = (
        df_no_fail.groupby("nopped_addr")
        .agg(total_correct=("correct", "sum"), total_failed=("failed", "sum"))
        .reset_index()
    )

    print(f"We have {agg_df.shape} shaped agg df")
    print(f"We have {agg_df_no_fail.shape} shaped agg df no fail")

    # This is the count of number of corrects. Notice, that
    # if the number of correct predictions is 0 it may
    # or may not be a case where the model ran correctly
    # and outputed zero.
    print(f"Counts of corrects:\n {agg_df['total_correct'].value_counts()}")
    print(f"Counts of failed:\n {agg_df['total_failed'].value_counts()}")

    print(
        f"NO FAIL Counts of corrects:\n {agg_df_no_fail['total_correct'].value_counts()}"
    )

    # Overlapp of correct and failed
    mask = (agg_df["total_failed"] != 0) & (agg_df["total_correct"] != 0)
    print(
        f"Number of nonzero failed and nonzero correct:\n {agg_df[mask].value_counts()}"
    )

    # See how many counts of correct == expected cont
    print(
        f"Therefore, of {agg_df.shape[0]} mutated bins, {(agg_df['total_correct'] == expected_correct).sum()} had the same number of correct predictions"
    )
    print(
        f"Therefore, of {agg_df.shape[0]} mutated bins, {(agg_df['total_correct'] < expected_correct).sum()} had less than the correct predictions"
    )
    print(
        f"Therefore, of {agg_df.shape[0]} mutated bins, {(agg_df['total_failed'] >= 1).sum()} had atleast one sample that caused a failed experiment"
    )

    show_results(common, df, other_returncodes)

    return df


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


# @app.command
# def find_faulted(results: Path, padding: int):
#    """
#    From the results file find the binaries that had the exptected STDOUT
#    then print the dissassembly comparison between all those programs and the
#    base program
#    """
#
#    if not results.exists():
#        print(f"File {results} does not exist")
#        return
#
#    # Load the result and get those that have the epxeted STDOUT in them
#    df = pd.read_csv(results)
#
#    expected_stdout = str(list(df["expected_stdout"])[0])
#    filtered_df = df[df["program_stdout"].str.contains(expected_stdout, na=False)]
#
#    # Get the mutated paths that have the expected stdouts
#    mutated_binaries = [Path(x) for x in filtered_df["binary_path"]]
#
#    # Get the vanilla binary
#    vanilla_binary = Path(str(list(filtered_df["unmutated_binary"])[0]))
#    assert vanilla_binary.exists()
#
#    for mbin in mutated_binaries:
#        # Get the mutated address
#        addr = int(mbin.name.replace(vanilla_binary.name + "_", ""), 16)
#
#        # Run the disassmebly
#        disasm([vanilla_binary, mbin], addr - padding, addr + padding)
#
#    return


@app.command
def read_results(inp: Path):
    """Read the results.csv of and experiemnt"""

    if not inp.is_file():
        raise Exception("The input file does not exists")

    df = pd.read_csv(inp)

    expected_stdout = df["expected_stdout"].to_list()[0]
    custom_returncodes = df["custom_returncodes"].to_list()[0]

    ret_codes = ret_codes.split(")")
    ret_codes = [x.replace("(", "") for x in ret_codes if x != ""]

    codes = []
    for substr in ret_codes:
        # This should have two valles
        splits = [x.strip() for x in substr.split(",") if x.strip() != ""]
        # print(splits)
        codes.append((splits[0], int(splits[1])))

    smol_show_results(df, codes, expected_stdout)

    # Get the number of accepted passwords, this is return code 1
    # df = df[df["return_code"] == 0]

    ## The result could be a nop experiment or a bit experiment
    # if "nop" in list(df["experiment_type"]):
    #    info = df[["return_code", "nopped_addr"]]
    # elif "bit" in list(df["experiment_type"]):
    #    info = df[["return_code", "flipped_addr", "flipped_index"]]

    # Want the number of exit codes that are 1
    print(df)

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


def x_bit_reg_seq(
    common: CommandParameters,
    target: Target,
    names: str,
    num_bits: int = 1,
    verbose: bool = False,
):
    """Run a bit mutation experiment without parallel cores and with ANGR."""

    func_names: list[str] = names.split(",")

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
        shutil.copy(program_context, common.out_dir.joinpath(program_context.name))

    bin_out = common.out_dir.joinpath(common.program_file.name.replace(".c", ".o"))
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

    results: list[RegBitFlipExperimentResult] = []

    start = datetime.now()

    # Run the threads
    for inst in alive_it(disasm):
        result = x_bit_angr_helper(
            common, inst, target, num_bits, func_names, common.timeout * 60
        )

        for (
            out_file,
            returncode,
            inst,
            common,
            target,
            stdout,
            captured,
            i,
        ) in result:
            cur_res = RegBitFlipExperimentResult(
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
                reg_info=captured,
            )
            results.append(cur_res)

    runtime = datetime.now() - start

    num_instructions = len(disasm)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    df = dataclass_to_dataframe(results)

    save_df(df, common.save_results)

    # show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    report_path = common.save_results.parent.joinpath("report.md")
    # save_report(
    #    report_path,
    #    common,
    #    df,
    #    runtime,
    #    results,
    #    num_instructions,
    #    num_bits,
    #    compile_cmd,
    #    source_code,
    #    program_context,
    #    is_bit=True,
    # )

    print(f"Analyzing {len(results)} results")

    golden_ret, golden_stdout, golden_register_info = sim_binary_w_input(
        common.program_file, common.program_input, func_names, common.timeout * 60
    )

    good_res, bad_res, error_case = analyze_reg_results(
        results, func_names, golden_register_info
    )

    save_reg_report(
        report_path,
        common,
        df,
        runtime,
        results,
        num_instructions,
        num_bits,
        compile_cmd,
        bad_res,
        good_res,
        error_case,
        source_code,
        program_context,
    )

    if verbose:
        verbose_output(results, func_names, golden_register_info)

    print(f"Normal results: {len(good_res)} ")
    print(f"Event Upset results: {len(bad_res)} ")
    print(f"Error count: {len(error_case)}")

    return


def smol_analyze_reg_results(reg_infos, func_names, golden_register_info, bin: Path):
    """
    Anaylze the register results
    """
    event_upset_res = []
    error_case = []
    normal_case = []

    target = detect_target(bin)
    register = get_return_reg(target)

    for cur_bin, reg_info in reg_infos:
        # See if any of the func names are missing register information

        # If we are missing the reg_info this is an error case
        # or if the func name is missing from reg info
        if reg_info is None or not all(
            [name in reg_info.keys() for name in func_names]
        ):
            error_case.append(cur_bin)
            continue

        # See if the two match for all functions
        all_golden_rets = [
            collect_all_reg_calls(golden_register_info, register, name)
            for name in func_names
        ]
        all_mut_rets = [
            collect_all_reg_calls(reg_info, register, name) for name in func_names
        ]
        is_correct = all_golden_rets == all_mut_rets

        if is_correct:
            normal_case.append(cur_bin)
        # These are the error conditions
        elif not all(
            [
                len(all_golden_rets[i]) == len(all_mut_rets[i])
                for i in range(len(all_golden_rets))
            ]
        ):
            error_case.append(cur_bin)
        else:
            # Event upset is when the two programs disagree and the mutatnt one runs without error
            event_upset_res.append(cur_bin)

    assert len(normal_case) + len(event_upset_res) + len(error_case) == len(reg_infos)

    return normal_case, event_upset_res, error_case


def norm_v_upset_v_error(all_golden_rets, all_mut_rets):
    normal_case = False
    error_case = False
    event_upset_res = False

    is_correct = all_golden_rets == all_mut_rets

    if is_correct:
        normal_case = True
    # These are the error conditions
    elif not all(
        [
            len(all_golden_rets[i]) == len(all_mut_rets[i])
            for i in range(len(all_golden_rets))
        ]
    ):
        error_case = True
    else:
        # Event upset is when the two programs disagree and the mutatnt one runs without error
        event_upset_res = True

    return normal_case, event_upset_res, error_case


def analyze_reg_results(results, func_names, golden_register_info):
    """
    Anaylze the register results
    """
    event_upset_res = []
    error_case = []
    normal_case = []

    target = detect_target(results[0].binary_path)
    register = get_return_reg(target)

    for result in results:
        # See if any of the func names are missing register information

        # If we are missing the reg_info this is an error case
        # or if the func name is missing from reg info
        if (
            result.reg_info is None
            or not isinstance(result.reg_info, dict)
            or not all([name in result.reg_info.keys() for name in func_names])
        ):
            error_case.append(result)
            continue

        # See if the two match for all functions
        all_golden_rets = [
            collect_all_reg_calls(golden_register_info, register, name)
            for name in func_names
        ]
        all_mut_rets = [
            collect_all_reg_calls(result.reg_info, register, name)
            for name in func_names
        ]
        is_correct = all_golden_rets == all_mut_rets

        if is_correct:
            normal_case.append(result)
        # These are the error conditions
        elif not all(
            [
                len(all_golden_rets[i]) == len(all_mut_rets[i])
                for i in range(len(all_golden_rets))
            ]
        ):
            error_case.append(result)
        else:
            # Event upset is when the two programs disagree and the mutatnt one runs without error
            event_upset_res.append(result)

    assert len(normal_case) + len(event_upset_res) + len(error_case) == len(results)

    return normal_case, event_upset_res, error_case


# @app.command()
def x_bit_reg_parallel(
    common: RegCommandParameters,
    target: Target,
    num_cpus: int,
    func_names: str,
    num_bits: int = 1,
    verbose: bool = False,
):
    """
    Parallelize the bit
    """

    func_names: list[str] = func_names.split(",")

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
        shutil.copy(program_context, common.out_dir.joinpath(program_context.name))

    bin_out = common.out_dir.joinpath(common.program_file.name.replace(".c", ".o"))
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

    futures = []
    results: list[RegBitFlipExperimentResult] = []

    start = datetime.now()

    with ThreadPoolExecutor(max_workers=num_cpus) as executor:
        # Run the threads
        for inst in disasm:
            # future = executor.submit(bit_para_run_helper, common, inst, target)
            # future = executor.submit(double_bit_para_run_helper, common, inst, target)
            future = executor.submit(
                x_bit_angr_helper,
                common,
                inst,
                target,
                num_bits,
                func_names,
                common.timeout * 60,
            )
            futures.append(future)

        total_tasks = len(futures)

        # for _, future in enumerate(futures):
        with alive_bar(total_tasks, title="Processing tasks") as bar:
            for future in as_completed(futures):
                # Check the status codes
                result = future.result()

                # Results = [out_file, returncode, inst, common, target, stdout, stderr, captured]
                for (
                    out_file,
                    returncode,
                    inst,
                    common,
                    target,
                    stdout,
                    captured,
                    i,
                ) in result:
                    cur_res = RegBitFlipExperimentResult(
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
                        reg_info=captured,
                    )
                    results.append(cur_res)

                bar()  # increment the progress bar by 1

    runtime = datetime.now() - start

    num_instructions = len(disasm)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    df = dataclass_to_dataframe(results)

    save_df(df, common.save_results)

    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    report_path = common.save_results.parent.joinpath("report.md")
    # save_report(
    #    report_path,
    #    common,
    #    df,
    #    runtime,
    #    results,
    #    num_instructions,
    #    num_bits,
    #    compile_cmd,
    #    source_code,
    #    program_context,
    #    is_bit=True,
    # )

    print(f"Analyzing {len(results)} results")

    golden_ret, golden_stdout, golden_register_info = sim_binary_w_input(
        common.program_file, common.program_input, func_names, common.timeout * 60
    )

    good_res, bad_res, error_case = analyze_reg_results(
        results, func_names, golden_register_info
    )

    save_reg_report(
        report_path,
        common,
        df,
        runtime,
        results,
        num_instructions,
        num_bits,
        compile_cmd,
        bad_res,
        good_res,
        error_case,
        source_code,
        program_context,
    )

    if verbose:
        verbose_output(results, func_names, golden_register_info)

    print(f"Normal results: {len(good_res)} ")
    print(f"Event Upset results: {len(bad_res)} ")
    print(f"Error count: {len(error_case)}")

    return


# @app.command()
# def para_bit(common: CommandParameters, target: Target, num_cpus: int):
#    """
#    Parallelize the bit
#    """
#
#    max_workers = max(1, num_cpus // 2)  # avoid 0 in case cpu_count() returns None
#
#    # Make the dir
#    common.out_dir.mkdir(exist_ok=True, parents=True)
#    base_out = common.out_dir
#
#    # Copy the source cdoe to the experiement
#    source_code = common.program_file
#    program_context = common.program_file.parent.joinpath(
#        common.program_file.name.replace(".c", ".toml")
#    )
#
#    shutil.copy(source_code, common.out_dir.joinpath(source_code.name))
#    if program_context.exists():
#        shutil.copy(program_context, common.out_dir.joinpath(program_context.name))
#
#    bin_out = common.out_dir.joinpath(common.program_file.name.replace(".c", ".o"))
#    compile_cmd = generate_compile_cmd(common.program_file, bin_out, target)
#
#    common.save_results = common.out_dir.joinpath("results.csv")
#    common.out_dir = common.out_dir.joinpath("mutated_bins")
#    common.out_dir.mkdir(exist_ok=True)
#
#    # Compile the binary for the target
#    common.program_file = compile_program(source_code, bin_out, target)
#
#    if not common.yes:
#        cont = str(
#            input(
#                f"Will _attempt_ to make {len(lief.parse(common.program_file).get_section('.text').content)} mutated binaries, continue? (Yy/Nn)"
#            )
#        )
#        if cont.lower() != "y":
#            return
#
#    disasm = disassemble_text_section(common.program_file)
#
#    futures = []
#    results: list[BitFlipExperimentResult] = []
#
#    start = datetime.now()
#
#    with ThreadPoolExecutor(max_workers=max_workers) as executor:
#        # Run the threads
#        for inst in disasm:
#            # future = executor.submit(bit_para_run_helper, common, inst, target)
#            future = executor.submit(double_bit_para_run_helper, common, inst, target)
#            futures.append(future)
#
#        total_tasks = len(futures)
#
#        # for _, future in enumerate(futures):
#        with alive_bar(total_tasks, title="Processing tasks") as bar:
#            for future in as_completed(futures):
#                # Check the status codes
#                result = future.result()
#
#                # Results = [out_file, returncode, inst, common, target, stdout, stderr, i]
#                for (
#                    out_file,
#                    returncode,
#                    inst,
#                    common,
#                    target,
#                    stdout,
#                    stderr,
#                    i,
#                ) in result:
#                    cur_res = BitFlipExperimentResult(
#                        source_file=source_code,
#                        unmutated_binary=common.program_file,
#                        binary_path=out_file,
#                        flipped_addr=inst.address,
#                        flipped_index=i,
#                        program_input=common.program_input,
#                        return_code=returncode,
#                        program_stdout=stdout,
#                        target=target,
#                        expected_returncode=common.expected_returncode,
#                        expected_stdout=common.expected_stdout,
#                        custom_returncodes=other_returncodes,
#                    )
#                    results.append(cur_res)
#
#                bar()  # increment the progress bar by 1
#
#    runtime = datetime.now() - start
#
#    num_instructions = len(disasm)
#
#    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8
#
#    df = dataclass_to_dataframe(results)
#
#    save_df(df, common.save_results)
#
#    show_results(common, df, other_returncodes)
#
#    # Lastly save the experiment parameters
#    params = common.to_dict()
#    params["target"] = target.value
#
#    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
#        json.dump(params, f, indent=4)
#
#    report_path = common.save_results.parent.joinpath("report.md")
#    save_report(
#        report_path,
#        common,
#        df,
#        runtime,
#        results,
#        num_instructions,
#        num_bits,
#        compile_cmd,
#        source_code,
#        program_context,
#        is_bit=True,
#    )
#
#    return
#
#


# @app.command()
def x_bit_qemu_seq(common: CommandParameters, target: Target, num_bits: int):
    """
    Run the x bit mutation scheme with a qemu backend
    """

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
        shutil.copy(program_context, common.out_dir.joinpath(program_context.name))

    bin_out = common.out_dir.joinpath(common.program_file.name.replace(".c", ".o"))
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

    results: list[BitFlipExperimentResult] = []
    start = datetime.now()
    for inst in alive_it(disasm):
        bin_res = x_bit_para_run_helper(common, inst, target, num_bits)

        for (
            out_file,
            returncode,
            inst,
            common,
            target,
            stdout,
            stderr,
            i,
        ) in bin_res:
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

    runtime = datetime.now() - start
    num_instructions = len(disasm)
    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

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


# @app.command()
def x_bit_qemu_parallel(
    common: CommandParameters,
    target: Target,
    num_cpus: int,
    num_bits: int,
    log_matching: bool = True,
):
    """
    Run the x bit mutation scheme with a qemu backend
    """

    max_workers = max(1, num_cpus // 2)  # avoid 0 in case cpu_count() returns None

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
        shutil.copy(program_context, common.out_dir.joinpath(program_context.name))

    bin_out = common.out_dir.joinpath(common.program_file.name.replace(".c", ".o"))
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

    futures = []
    results: list[BitFlipExperimentResult] = []

    start = datetime.now()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Run the threads
        for inst in disasm:
            future = executor.submit(
                x_bit_para_run_helper, common, inst, target, num_bits
            )
            futures.append(future)

        with alive_bar(len(futures), title="Processing tasks") as bar:
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

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    df = dataclass_to_dataframe(results)

    save_df(df, common.save_results)

    show_results(common, df, other_returncodes, log_matching=log_matching)

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


def collect_all_reg_calls(capt_info, reg_name, func_name):
    return [x[reg_name] for x in capt_info[func_name]]


def x_nop_reg_seq(
    common: RegCommandParameters,
    target: Target,
    func_names: str,
    num_nops: int = 1,
    verbose: bool = False,
):
    """
    The register version of the nop x command.

    This will use ANGR to run the mutated binary
    """

    func_names: list[str] = func_names.split(",")

    print(f"The func names are: {func_names}")

    # Make the dir
    common.out_dir.mkdir(exist_ok=True, parents=True)
    program_context = common.program_file.parent.joinpath(
        common.program_file.name.replace(".c", ".toml")
    )
    base_out = common.out_dir

    # Copy the source cdoe to the experiement
    source_code = common.program_file
    shutil.copy(source_code, common.out_dir.joinpath(source_code.name))

    bin_out = common.out_dir.joinpath(common.program_file.name.replace(".c", ".o"))

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

    results: list[RegNopExperimentResult] = []

    start_time = datetime.now()

    # Run the binary to get the golden register values

    golden_ret, golden_stdout, golden_register_info = sim_binary_w_input(
        common.program_file, common.program_input, func_names, common.timeout * 60
    )

    for i in alive_it(range(len(disasm) - (num_nops) + 1)):
        # Keet x instructions to overwrite with nop
        insts = [disasm[i + x] for x in range(num_nops)]
        out_file, returncode, insts, common, target, stdout, captured = (
            x_nop_angr_helper(
                common,
                insts,
                target,
                func_names,
                common.timeout * 60,
            )
        )

        result = RegNopExperimentResult(
            source_file=source_code,
            unmutated_binary=original_bin,
            binary_path=out_file,
            nopped_addr=insts[0].address,
            program_input=common.program_input,
            return_code=returncode,
            program_stdout=stdout,
            target=target,
            expected_returncode=common.expected_returncode,
            expected_stdout=common.expected_stdout,
            custom_returncodes=other_returncodes,
            # TODO:
            reg_info=captured,
        )
        results.append(result)

    print(f"done")
    runtime = datetime.now() - start_time

    # TODO - Better implement the register version
    df = dataclass_to_dataframe(results)
    save_df(df, common.save_results)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    report_path = common.save_results.parent.joinpath("report.md")
    print(f"Analyzing {len(results)} results")

    good_res, bad_res, error_case = analyze_reg_results(
        results, func_names, golden_register_info
    )

    # bad_res = []
    # error_case = []
    # good_res = []

    # for result in results:
    #    all_names_good = True
    #    is_error_case = False

    #    for name in func_names:
    #        if result.reg_info is None:
    #            is_error_case = True
    #            # error_case.append(result)
    #            continue

    #        if name in result.reg_info.keys():
    #            # Get a liust of all the r0 values across all calls to func name
    #            gold_r0_ret = collect_all_reg_calls(golden_register_info, "r0", name)
    #            mut_r0_ret = collect_all_reg_calls(result.reg_info, "r0", name)
    #            # is_correct = gold_r0_ret[-1] == mut_r0_ret[-1]

    #            if len(mut_r0_ret) != len(gold_r0_ret):
    #                is_error_case = True
    #                continue

    #            is_correct = gold_r0_ret == mut_r0_ret

    #            if not is_correct:
    #                all_names_good = False
    #        else:
    #            is_error_case = True

    #    if is_error_case:
    #        error_case.append(result)
    #    elif not all_names_good:
    #        bad_res.append(result)
    #    else:
    #        good_res.append(result)

    save_reg_report(
        report_path,
        common,
        df,
        runtime,
        results,
        num_instructions,
        num_bits,
        compile_cmd,
        bad_res,
        good_res,
        error_case,
        source_code,
        program_context,
    )

    if verbose:
        verbose_output(results, func_names, golden_register_info)

    print(f"Normal results: {len(good_res)} ")
    print(f"Event Upset results: {len(bad_res)} ")
    print(f"Error count: {len(error_case)}")

    return


@app.command()
def x_bit(
    common: RegCommandParameters,  # TODO: Make everything use this version and rename
    target: Target,
    func_names: str,
    num_bits: int = 1,
    num_cpus: int = 1,
    verbose: bool = False,
    backend: Backends = Backends.ANGR,
    log_matching: bool = True,
):
    """
    Run the bit experiemnt with either the qemu backend
    or the angr backend
    """

    if backend == Backends.ANGR and num_cpus > 1:
        print("ANGR backend does not support parallel execution yet")
        return

    # Run the backend + the parallel versus sequentation version
    if backend == backend.ANGR:
        if num_cpus == 1:
            # Sequantial
            x_bit_reg_seq(common, target, func_names, num_bits, verbose)
        else:
            # Parallel
            x_bit_reg_parallel(common, target, num_cpus, func_names, num_bits, verbose)
    elif backend == backend.QEMU:
        # Now assert that we have stdout and expected return code
        if common.expected_stdout is None or common.expected_returncode is None:
            print(
                f"The backend {backend} requires expected_stdout and expected_returncode"
            )

        if num_cpus == 1:
            # Sequantial
            x_bit_qemu_seq(common, target, num_bits, log_matching)
        else:
            # Parallel
            x_bit_qemu_parallel(common, target, num_cpus, num_bits, log_matching)
    return


@app.command()
def x_nop(
    common: RegCommandParameters,  # TODO: Make everything use this version and rename
    target: Target,
    func_names: str,
    num_nops: int = 1,
    num_cpus: int = 1,
    verbose: bool = False,
    backend: Backends = Backends.ANGR,
    log_matching: bool = True,
):
    """
    Command to run
    """

    if backend == Backends.ANGR and num_cpus > 1:
        print("ANGR backend does not support parallel execution yet")
        return

    # Run the backend + the parallel versus sequentation version
    if backend == backend.ANGR:
        if num_cpus == 1:
            # Sequantial
            logger.info(f"Staring with backend {backend} sequential")
            x_nop_reg_seq(common, target, func_names, num_nops, verbose)
        else:
            # Parallel
            logger.info(f"Staring with backend {backend} parallel")
            x_nop_reg_parallel(common, target, num_cpus, func_names, num_nops, verbose)
    elif backend == backend.QEMU:
        # Now assert that we have stdout and expected return code
        if common.expected_stdout is None or common.expected_returncode is None:
            print(
                f"The backend {backend} requires expected_stdout and expected_returncode"
            )

        print(f"LOG MATHCING IS {log_matching} in x-nop")
        if num_cpus == 1:
            # Sequantial
            logger.info(f"Staring with backend {backend} sequential")
            x_nop_qemu_seq(common, target, num_nops, log_matching)
        else:
            # Parallel
            logger.info(f"Staring with backend {backend} parallel")
            x_nop_qemu_parallel(common, target, num_cpus, num_nops, log_matching)

    return


# @app.command()


def x_nop_reg_parallel(
    common: RegCommandParameters,
    target: Target,
    num_cpus: int,
    func_names: str,
    num_nops: int = 1,
    verbose: bool = False,
):
    """
    The register version of the nop x command.

    This will use ANGR to run the mutated binary
    """

    func_names: list[str] = func_names.split(",")

    print(f"The func names are: {func_names}")

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

    bin_out = common.out_dir.joinpath(common.program_file.name.replace(".c", ".o"))

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

    futures = []
    results: list[RegNopExperimentResult] = []

    start_time = datetime.now()

    # Run the binary to get the golden register values

    golden_ret, golden_stdout, golden_register_info = sim_binary_w_input(
        common.program_file, common.program_input, func_names, common.timeout * 60
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Run the threads
        # 1 nop : len(diasm)     = len(disasm) - 1nop + 1
        # 2 nop : len(diasm) - 1
        # ...
        for i in range(len(disasm) - (num_nops) + 1):
            # Keet x instructions to overwrite with nop
            insts = [disasm[i + x] for x in range(num_nops)]
            # future = executor.submit(x_nop_para_run_helper, common, insts, target)
            future = executor.submit(
                x_nop_angr_helper,
                common,
                insts,
                target,
                func_names,
                common.timeout * 60,
            )
            futures.append(future)

        total_tasks = len(futures)

        with alive_bar(total_tasks, title="Processing tasks") as bar:
            for future in as_completed(futures):
                # Check the status codes
                out_file, returncode, insts, common, target, stdout, captured = (
                    future.result()
                )

                result = RegNopExperimentResult(
                    source_file=source_code,
                    unmutated_binary=original_bin,
                    binary_path=out_file,
                    nopped_addr=insts[0].address,
                    program_input=common.program_input,
                    return_code=returncode,
                    program_stdout=stdout,
                    target=target,
                    expected_returncode=common.expected_returncode,
                    expected_stdout=common.expected_stdout,
                    custom_returncodes=other_returncodes,
                    # TODO:
                    reg_info=captured,
                )
                results.append(result)
                bar()

    print(f"done")
    runtime = datetime.now() - start_time

    # TODO - Better implement the register version
    df = dataclass_to_dataframe(results)
    save_df(df, common.save_results)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    report_path = common.save_results.parent.joinpath("report.md")
    print(f"Analyzing {len(results)} results")

    good_res, bad_res, error_case = analyze_reg_results(
        results, func_names, golden_register_info
    )

    save_reg_report(
        report_path,
        common,
        df,
        runtime,
        results,
        num_instructions,
        num_bits,
        compile_cmd,
        bad_res,
        good_res,
        error_case,
        source_code,
        program_context,
    )

    if verbose:
        verbose_output(results, func_names, golden_register_info)

    print(f"Normal results: {len(good_res)} ")
    print(f"Event Upset results: {len(bad_res)} ")
    print(f"Error count: {len(error_case)}")

    return


def verbose_output(results, func_names, golden_register_info):
    """
    Print to stdout a verbose output of the results
    """

    # Get the register value
    target = detect_target(results[0].binary_path)
    register = get_return_reg(target)

    reg_vals = []

    missing_func = []
    missing_reg_info = []

    for result in results:
        print(f"==== On res {result.binary_path} =====")

        if result.reg_info is None:
            print(f"No reg info")
            missing_reg_info.append(result)
            continue

        for name in func_names:
            if name in result.reg_info.keys():
                # Get a liust of all the r0 values across all calls to func name
                gold_register = collect_all_reg_calls(
                    golden_register_info, register, name
                )
                mut_r0_ret = collect_all_reg_calls(result.reg_info, register, name)
                is_correct = gold_register[-1] == mut_r0_ret[-1]
                reg_vals.append(mut_r0_ret[-1])

                print(
                    f"({name}:r0)  golden: {gold_register} | mut: {mut_r0_ret} same?: {is_correct}"
                )
                print(f"Program: {result.binary_path}")
                print(f"Stdout: {result.program_stdout}")
            else:
                missing_func.append(result.binary_path)
                print(f"Missing function: {name}")

        print(f"Reg vals set: {set(reg_vals)}")
        print(f"==== DONE res {result.binary_path} =====")

    print(f"Num missing func: {len(set(missing_func))}")
    print(f"Num missing reg info: {len(missing_reg_info)}")

    return


def x_nop_qemu_seq(
    common: RegCommandParameters,
    target: Target,
    num_nops: int = 1,
    verbose: bool = True,
    log_matching: bool = True,
):
    """
    Take c source code as input, compile it, mutate it, and test
    """

    assert common.expected_stdout is not None
    common.expected_stdout = str(common.expected_stdout)

    # Make the dir
    common.out_dir.mkdir(exist_ok=True, parents=True)
    program_context = common.program_file.parent.joinpath(
        common.program_file.name.replace(".c", ".toml")
    )
    base_out = common.out_dir

    # Copy the source cdoe to the experiement
    source_code = common.program_file
    shutil.copy(source_code, common.out_dir.joinpath(source_code.name))

    bin_out = common.out_dir.joinpath(common.program_file.name.replace(".c", ".o"))

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

    results: list[NopExperimentResult] = []

    start_time = datetime.now()

    for i in alive_it(range(len(disasm) - (num_nops) + 1)):
        insts = [disasm[i + x] for x in range(num_nops)]

        out_file, returncode, insts, common, target, stdout, stderr = (
            x_nop_para_run_helper(common, insts, target)
        )

        result = NopExperimentResult(
            source_file=source_code,
            unmutated_binary=original_bin,
            binary_path=out_file,
            nopped_addr=insts[0].address,
            program_input=common.program_input,
            return_code=returncode,
            program_stdout=stdout,
            target=target,
            expected_returncode=common.expected_returncode,
            expected_stdout=common.expected_stdout,
            custom_returncodes=other_returncodes,
        )
        results.append(result)

    for res in results:
        if res.expected_stdout not in res.program_stdout:
            print(f"Binary: {res.binary_path} printed: {res.program_stdout}")

    runtime = datetime.now() - start_time

    df = dataclass_to_dataframe(results)

    if verbose:
        print(f"The counts of stdout: {df['program_stdout'].value_counts()}")

    save_df(df, common.save_results)
    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

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
        log_matching=log_matching,
    )
    print(f"Report saved to {report_path}")

    return


def x_nop_qemu_parallel(
    common: RegCommandParameters,
    target: Target,
    num_cpus: int,
    num_nops: int = 1,
    log_matching: bool = True,
    comp: bool = True,
):
    """Run an experiment that gernerates mutant binaries with num_nops, and tests them with QEMU.

    Parameters
    ----------

    """

    print(f"LOG MATHCING IS {log_matching} in x-nop-qemu-para")
    max_workers = max(1, num_cpus // 2)

    # Make the dir
    common.out_dir.mkdir(exist_ok=True, parents=True)
    program_context = common.program_file.parent.joinpath(
        common.program_file.name.replace(".c", ".toml")
    )
    base_out = common.out_dir

    if comp:
        # Copy the source cdoe to the experiement
        source_code = common.program_file
        shutil.copy(source_code, common.out_dir.joinpath(source_code.name))

        bin_out = common.out_dir.joinpath(common.program_file.name.replace(".c", ".o"))

        # Compile the binary for the target
        common.program_file = compile_program(source_code, bin_out, target)
        compile_cmd = generate_compile_cmd(common.program_file, bin_out, target)
    else:
        source_code = ""
        bin_out = common.program_file
        compile_cmd = ""

    common.save_results = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

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

    futures = []
    results: list[NopExperimentResult] = []

    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for i in range(len(disasm) - (num_nops) + 1):
            insts = [disasm[i + x] for x in range(num_nops)]
            future = executor.submit(x_nop_para_run_helper, common, insts, target)
            futures.append(future)

        with alive_bar(len(futures), title="Processing tasks") as bar:
            for future in as_completed(futures):
                # Check the status codes
                out_file, returncode, insts, common, target, stdout, stderr = (
                    future.result()
                )

                result = NopExperimentResult(
                    source_file=source_code,
                    unmutated_binary=original_bin,
                    binary_path=out_file,
                    nopped_addr=insts[0].address,
                    program_input=common.program_input,
                    return_code=returncode,
                    program_stdout=stdout,
                    target=target,
                    expected_returncode=common.expected_returncode,
                    expected_stdout=common.expected_stdout,
                    custom_returncodes=other_returncodes,
                )
                results.append(result)
                bar()

    runtime = datetime.now() - start_time

    df = dataclass_to_dataframe(results)
    save_df(df, common.save_results)
    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

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
        log_matching=log_matching,
    )
    print(f"Report saved to {report_path}")

    return


def save_reg_report(
    report_path: Path,
    common: CommandParameters | RegCommandParameters,
    df: pd.DataFrame,
    runtime,
    results,
    num_instructions,
    num_bits,
    compile_cmd,
    bad_reg_info,
    normal_results,
    error_results,
    source_code: Path,
    program_context: Path,
    is_bit=False,
) -> None:
    """
    Generate a report including:
    1. Experiment Settings
    2. Histrogram of exit codes
    3. list of files that ran critical code
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
        if k in ["program_input", "expected_stdout"] and v is not None:
            settings_bullets = settings_bullets + f"- **{k}**:" + f"`{list(v)}`" + "\n"
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
        binary_info += (
            f"- Therefore, FaultSim attempted to make **{num_bits}** mutations\n"
        )
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
    binary_info += f"- The NOP for this target is: `{nop}` with values: {nop.value}\n"
    binary_info += f"- The runtime to generate and run all binaries was: {runtime}\n"

    if common.expected_stdout is not None:
        freqs = calc_freqs(df, common.expected_stdout, other_returncodes)
        table = "## Return Code Frequencies \n"
        table_str = list_tuple_table(["Exit code", "Frequency"], freqs)
        table += table_str
    else:
        table = ""

    # 3. list of programs that ran critical code
    if common.expected_stdout is not None:
        list_of_progs = "## Programs that ran critical code according to stdout\n"

        info = df[df["program_stdout"].str.contains(common.expected_stdout, na=False)]
        names = [Path(x).name for x in list(info["binary_path"])]

        list_of_progs += f"**{len(names)}** programs ran the critical code out of **{len(df)}** mutated binaries. The binaires were:\n"

        names_str = ""
        for name in names:
            names_str += f"- {name}\n"

        list_of_progs += names_str
        list_of_progs += "\n"
    else:
        list_of_progs = ""

    # 3.1 list of programs that ran cirtical code according to the reg info
    list_of_progs += f"### REG INFO {len(bad_reg_info)}** programs ran critical code according to reg info. These were:\n"
    for res in bad_reg_info:
        list_of_progs += f"- {res.binary_path}\n"

    list_of_progs += f"\n"
    list_of_progs += f"REG INFO NORMAL RESULTS: {len(normal_results)}"
    list_of_progs += f"\n"
    list_of_progs += f"REG INFO ERROR RESULTS: {len(error_results)}"

    # 4. Disassembly of the files that ran critical code
    # 10 bytes on either side will be included
    pad = 10
    # bins = [Path(x) for x in list(info["binary_path"])]
    bins = [Path(x.binary_path) for x in bad_reg_info]

    disassems = ""
    for i, bin in enumerate(bins):
        if is_bit:
            mut_addr = bin.name.replace(f"{common.program_file.name}_", "")
            mut_addr = mut_addr.split("_")[0]
            mut_addr = int(mut_addr, 16)
        else:
            mut_addr = int(bin.name.replace(f"{common.program_file.name}_", ""), 16)

        start_addr = mut_addr - pad
        end_addr = mut_addr + pad

        ret = disasm(
            [common.program_file.absolute(), bin],
            start_addr,
            end_addr,
            text=True,
            verbose=False,
        )

        disassems += f"#### Vanilla vs Mutant #{i}: {bin.name} diassemebly\n\n"
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
        report_path.parent.joinpath(report_path.name.replace(".md", ".pdf")).absolute(),
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
    log_matching: bool = True,
) -> None:
    """
    Generate a report including:
    1. Experiment Settings
    2. Histrogram of exit codes
    3. list of files that ran critical code
    4. Disassmeblys of the files that ran critical codes
    5. Validation of correct mutations
    6. Whole dataframe

    Parameters
    ----------

    log_matching: bool = True
        The default behavior is to save the disassembly for cases where the
    expected stdout matching the true stdout (log_matching=True). If set to
    false the disasseblies will include all the cases where the expected
    STDOUT was no observed.
    """

    # . The title
    title = f"# Experiment {results[0].mutation.upper()} on {common.program_file.name} with target {results[0].target}\n"

    # 1. the settings
    settings = common.to_dict()

    settings_bullets = "## Settings \n"

    for k, v in settings.items():
        if k in ["program_input", "expected_stdout"]:
            settings_bullets = settings_bullets + f"- **{k}**:" + f"`{list(v)}`" + "\n"
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
        binary_info += (
            f"- Therefore, FaultSim attempted to make **{num_bits}** mutations\n"
        )
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
    binary_info += f"- The NOP for this target is: `{nop}` with values: {nop.value}\n"
    binary_info += f"- The runtime to generate and run all binaries was: {runtime}\n"

    freqs = calc_freqs(df, common.expected_stdout, other_returncodes)
    table = "## Return Code Frequencies \n"
    table_str = list_tuple_table(["Exit code", "Frequency"], freqs)
    table += table_str

    # 3. List of programs that had the expected stdout
    list_of_progs = "## Programs that ran critical code \n"

    matching_info = df[
        df["program_stdout"].str.contains(common.expected_stdout, na=False)
    ]
    non_matching_info = df[
        ~df["program_stdout"].str.contains(common.expected_stdout, na=False)
    ]

    match_names = [Path(x).name for x in list(matching_info["binary_path"])]
    non_match_names = [Path(x).name for x in list(non_matching_info["binary_path"])]

    list_of_progs += f"**{len(match_names)}** programs had the expected STDOUT **{len(df)}** mutated binaries\n"
    list_of_progs += f"**{len(non_match_names)}** programs did not have the expected STDOUT **{len(df)}** mutated binaries"

    list_of_progs += "\n"
    if log_matching:
        list_of_progs += (
            "[LOGMATCHING=True] The binaries with the expected STDOUT were:\n"
        )
    else:
        list_of_progs += (
            "[LOGMATCHING=False] The binaries without the expected STDOUT were:\n"
        )

    names_str = ""
    for name in match_names if log_matching else non_match_names:
        names_str += f"- {name}\n"

    list_of_progs += names_str

    # 4. Disassembly of the files that ran critical code
    # 10 bytes on either side will be included
    pad = 10
    if log_matching:
        bins = [Path(x) for x in list(matching_info["binary_path"])]
    else:
        bins = [Path(x) for x in list(non_matching_info["binary_path"])]

    disassems = ""
    for i, bin in enumerate(bins):
        if is_bit:
            mut_addr = bin.name.replace(f"{common.program_file.name}_", "")
            mut_addr = mut_addr.split("_")[0]
            mut_addr = int(mut_addr, 16)
        else:
            mut_addr = int(bin.name.replace(f"{common.program_file.name}_", ""), 16)

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
        report_path.parent.joinpath(report_path.name.replace(".md", ".pdf")).absolute(),
    )

    return


@app.command
def run(inps: list[Path] = [Path("experiment.toml")]):
    """
    This will run ALL the experiments in the provided experiment file
    """

    for inp in inps:
        settings = dynaconf.Dynaconf(settings_files=inp)

        experiments = settings.get("experiment", {})

        commands = {
            "x_nop": x_nop,
            "nop_no_comp_inout": nop_no_comp_inout,
            "angr_nop_no_comp_inout": angr_nop_no_comp_inout,
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

            if command_name in [
                "nop",
                "para_bit",
                "para_double_nop",
                "para_double_bit",
            ]:
                # print("Launching exp")
                # Get the other required params
                target = formated.pop("target")
                num_cpus = formated.pop("num_cpus")
                params = CommandParameters(**formated)
                cmd_func(params, target=target, num_cpus=num_cpus)

            elif command_name in ["x_nop"]:
                target = formated.pop("target")
                num_cpus = formated.pop("num_cpus")
                num_nops = formated.get("num_nops", None)
                func_names = formated.get("func_names", None)

                if num_nops:
                    formated.pop("num_nops")
                    params = CommandParameters(**formated)
                    cmd_func(
                        params, target=target, num_cpus=num_cpus, num_nops=num_nops
                    )
                else:
                    params = CommandParameters(**formated)
                    cmd_func(params, target=target, num_cpus=num_cpus)

            elif command_name in ["x_nop_reg"]:
                target = formated.pop("target")
                num_cpus = formated.pop("num_cpus")
                num_nops = formated.get("num_nops", None)
                func_names = formated.get("func_names", None)

                if num_nops and func_names:
                    formated.pop("num_nops")
                    formated.pop("func_names")
                    formated.pop("expected_stdout")
                    formated.pop("expected_stdout")
                    params = RegCommandParameters(**formated)
                    cmd_func(
                        params,
                        target=target,
                        num_cpus=num_cpus,
                        num_nops=num_nops,
                        func_names=func_names,
                    )
                else:
                    params = CommandParameters(**formated)
                    cmd_func(params, target=target, num_cpus=num_cpus)

            elif command_name in ["nop_no_comp_inout", "bit_no_comp_inout"]:
                ins = formated.pop("ins")
                outs = formated.pop("outs")
                target = formated.pop("target")
                nocomp = formated.pop("no_compile")
                expected_correct = int(formated.pop("expected_correct"))
                params = CommandParameters(**formated)
                cmd_func(
                    params, ins=ins, outs=outs, expected_correct=expected_correct
                )  # , target=target, num_cpus=num_cpus)

            elif command_name in ["angr_nop_no_comp_inout"]:
                ins = formated.pop("ins")
                outs = formated.pop("outs")
                target = formated.pop("target")
                nocomp = formated.pop("no_compile")
                timeout = formated.pop("timeout")
                func_names = formated.pop("func_names")
                expected_correct = int(formated.pop("expected_correct"))
                params = CommandParameters(**formated)

                cmd_func(
                    params,
                    ins=ins,
                    outs=outs,
                    expected_correct=expected_correct,
                    timeout=timeout,
                    func_names=func_names,
                )  # , target=target, num_cpus=num_cpus)

    return


@app.command
def gather_reports(inp: Path, out: Path, force: bool = False, substrs: list[str] = []):
    """
    If there are many report.md files in a directory, this will
    1. Gather them
    2. Rename
    3. Save in the output directory
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
            if (not any(x in str(p.parent) for x in substrs)) or (substrs != []):
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

    with open(output, "w") as f:
        for i, info in enumerate(results):
            print(f"INP {inps[i]} results: {info}")
            f.write(f"{inps[i]} | {' | '.join(str(x) for x in info)}\n")

    # out.unlink()
    shutil.rmtree(out)

    return


def dataset_split_random(
    data, val_size=0.25, test_size=0.25, random_state=3, column="split"
):
    """
    Split DataFrame into 3 non-overlapping parts: train,val,test with specified proportions

    Returns a new DataFrame with the rows marked by the assigned split in @column
    """
    train_size = 1.0 - val_size - test_size

    train_val_idx, test_idx = train_test_split(
        data.index, test_size=test_size, random_state=random_state
    )
    val_ratio = val_size / (val_size + train_size)
    train_idx, val_idx = train_test_split(
        train_val_idx, test_size=val_ratio, random_state=random_state
    )

    train = data.loc[train_idx]
    val = data.loc[val_idx]
    test = data.loc[test_idx]

    return train, val, test


def evaluate_model(bin_path: Path, test, arm: bool):
    # Make predictions on dataset
    X_test = test[["x", "y"]]
    Y_test = test[["label"]]

    y_pred_c = predict(str(bin_path), X_test, 5, arm)

    f1_score_c = sklearn.metrics.f1_score(Y_test, y_pred_c)
    return f1_score_c


def predict(bin_path, X, timeout: int, use_arm: bool = False):
    def predict_one(x):
        if use_arm:
            args = ["qemu-arm-static", bin_path, str(x[0]), str(x[1])]
        else:
            args = [bin_path, str(x[0]), str(x[1])]

        args = ["timeout", f"{timeout}s"] + args
        out = subprocess.check_output(args)
        cls = int(out)
        return cls

    y = [predict_one(x) for x in np.array(X)]
    return np.array(y)


# @app.command()
# def angr_new_nn_test(inp: Path, out: Path, test_size: int):
#    """
#    Temp function to run against the new neural net
#    """
#
#    out.mkdir(exist_ok=True)
#
#    disasm = disassemble_text_section(inp)
#
#    # Load the target type
#    target = detect_target(inp)
#    if target == Target.ARM_32:
#        arm = True
#    else:
#        arm = False
#
#    logger.debug(f"Detected Target: {target}")
#
#    mutated_bins = []
#    for inst in alive_it(disasm, title="generating mutations"):
#        # 1. mutate
#        mutated_bins.append(_generate_nop_mutated_bin(inp, target, inst, out))
#
#    timeout = 4
#    #TODO
#    func_names = ['mlp_predict']
#
#    baseline_correct_predictions = []
#
#    captured_to_i_tups = {}
#
#    for i in range(test_size):
#
#        # Run the golen mutation
#        ret, stdout, register_info = sim_binary_w_calltime_input(
#            inp, i, func_names, timeout * 60
#        )
#
#        captured_to_i_tups[i] = [ret, stdout, register_info]
#
#        #stdout = class_helper(inp, i, 5, arm)
#
#        #print(stdout)
#        #if "CORRECT" in stdout.decode():
#        #    baseline_correct_predictions.append(i)
#
#    # Now, try only those in the mutated model and see what
#    # we get
#    results = []
#
#    atleast_one_mistake = 0
#
#    target = detect_target(inp)
#    reg = get_return_reg(target)
#
#    for bin in alive_it(mutated_bins, title="testing mutations"):
#        bin_results = {
#            "norm": [],
#            "upset": [],
#            "error": [],
#        }
#
#        for i in range(test_size):
#            # Run the mutant
#            ret, stdout, register_info = sim_binary_w_calltime_input(
#                bin, i, func_names, timeout * 60
#            )
#
#
#            # Compare
#            all_golden_rets = [
#                collect_all_reg_calls(captured_to_i_tups[i], reg, name)
#                for name in func_names
#            ]
#            all_mut_rets = [
#                collect_all_reg_calls(register_info, reg, name)
#                for name in func_names
#            ]
#            is_norm, is_upset, is_error = norm_v_upset_v_error(all_golden_rets, all_mut_rets)
#
#            if is_norm:
#                bin_results['norm'].append(bin)
#            elif is_upset:
#                bin_results['upset'].append(bin)
#            elif is_error:
#                bin_results['error'].append(bin)
#
#        if len(bin_results["upset"]) > 0:
#            atleast_one_mistake += 1
#        if len(bin_results["error"]) > 0:
#            atleast_one_mistake += 1
#
#        results.append((bin, bin_results))
#
#    console.print(
#        f"Baseline correctly labeled {len(baseline_correct_predictions)} inputs"
#    )
#    console.print(
#        f"Of {len(mutated_bins)}, {atleast_one_mistake} mutated bins incorrect labeled an input that baseline correctly labeld"
#    )
#
#    for bin, res in results:
#        if len(res["upset"]) > 0:
#            print(f"{bin.name} | mistakes: {res['wrong']}\n")
#
#    with open("TEMPDELME.txt", "w") as f:
#        for bin, res in results:
#            if len(res["upset"]) > 0:
#                f.write(f"{bin.name} | mistakes: {res['wrong']}\n")
#
#    return


@app.command()
def new_nn_test(inp: Path, out: Path, test_size: int):
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

    for bin in alive_it(mutated_bins, title="testing mutations"):
        bin_results = {
            "correct": [],
            "wrong": [],
            "failed": [],
        }

        for i in baseline_correct_predictions:
            try:
                stdout = class_helper(bin, i, 1, arm)
                if "CORRECT" in stdout.decode():
                    bin_results["correct"].append(bin)
                elif "WRONG" in stdout.decode():
                    bin_results["wrong"].append(bin)
                    print(f"Bin: {bin} wrong on {i}")
                else:
                    bin_results["failed"].append(bin)
            except:
                bin_results["failed"].append(bin)

        if len(bin_results["wrong"]) > 0:
            atleast_one_mistake += 1
        if len(bin_results["failed"]) > 0:
            atleast_one_mistake += 1

        results.append((bin, bin_results))

    console.print(
        f"Baseline correctly labeled {len(baseline_correct_predictions)} inputs"
    )
    console.print(
        f"Of {len(mutated_bins)}, {atleast_one_mistake} mutated bins incorrect labeled an input that baseline correctly labeld"
    )

    for bin, res in results:
        if len(res["wrong"]) > 0:
            print(f"{bin.name} | mistakes: {res['wrong']}\n")

    with open("TEMPDELME.txt", "w") as f:
        for bin, res in results:
            if len(res["wrong"]) > 0:
                f.write(f"{bin.name} | mistakes: {res['wrong']}\n")

    return


def class_helper(bin_path: Path, input: int, timeout: int, use_arm: bool):
    """
    Helper for a simple nerual net
    """

    if use_arm:
        args = ["qemu-arm-static", bin_path, str(input)]
    else:
        args = [bin_path, str(input)]

    args = ["timeout", f"{timeout}s"] + args
    out = subprocess.check_output(args, stderr=subprocess.DEVNULL)

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
        ax.axvline(x=addr, color="yellow", linestyle="--", linewidth=2, label="Faulted")

    # Plot failed addresses
    for addr in failed_addresses:
        ax.axvline(x=addr, color="red", linestyle="-", linewidth=2, label="Failed")

    # Create a legend without duplicate entries
    handles, labels = ax.get_legend_handles_labels()
    unique = dict(zip(labels, handles))
    ax.legend(unique.values(), unique.keys(), loc="upper right")

    ax.set_xlabel("Address")
    ax.set_yticks([])  # hide y-tick marks
    ax.set_title("Memory Faults and Failures")

    return plt


@app.command()
def generate_exp_file(
    exp_file_out: Path,
    out_dir: Path,
    target: Target,
    timeout: int,
    expected_stdouts: str,
    program_inputs: str,
    program_file: Path,
    expected_correct: int,
    result_file: Path,
):
    """
    Save a toml that defines the experiment for the neural networks

    With this, a binary is ran on many input and expected output pairs
    """

    inputs_str = ",".join([f"'{x}'" for x in program_inputs])
    output_str = ",".join([f"'{x}'" for x in expected_stdouts])

    file = [
        f"[experiment.nop_no_comp_inout]",
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
        f"no_compile= true ",
        f"save-results='{str(result_file.absolute())}'",
    ]

    # Make parent out
    if not exp_file_out.parent.exists():
        exp_file_out.parent.mkdir(parents=True)

    with open(exp_file_out, "w") as f:
        for line in file:
            f.write(line + "\n")

    print(f"Saved exp file to: {exp_file_out.absolute()}")
    return


@app.command()
def nn_generate_exp_files(
    exp_file: Path,
    binary: Path,
    timeout: int,
    out_dir: Path,
    input_dir: Path,
    expected_correct: int,
    result_file: Path,
):
    """
    A temporary function to generate experiemnt files for classifier testing
    """

    target = detect_target(binary)

    outs = []
    ins = []

    # Iterate over the images
    for file in input_dir.glob("*"):
        _, _, lbl = file.name.split("_")
        lbl = lbl.split(".")[0]
        ins.append(str(file.absolute()))
        outs.append(lbl)

    generate_exp_file(
        exp_file,
        out_dir,
        target=target,
        timeout=timeout,
        expected_stdouts=outs,
        program_inputs=ins,
        program_file=binary,
        expected_correct=expected_correct,
        result_file=result_file,
    )

    return


# TODO: Add this
def compare_plot(
    nop_list, bit_list, static_list, segfaults, num_instructions, out_path
):
    # Configuration
    dtypes = ["Bypass", "Loop", "Constant", "Branch", "NOP", "BIT"]
    colors = {
        "Both": "#7f2a19",  # blue
        "SIGSEGV": "#f6b26b",  # orange
        "Vulnerable": "#e66c2c",  # red
        "normal": "#e0e0e0",  # gray (default background)
    }

    nops = [ln for _, ln in nop_list]
    bits = [ln for _, ln in bit_list]
    constants = [ln for _, ln, dtype in static_list if dtype == DetectionType.Constant]
    branches = [ln for _, ln, dtype in static_list if dtype == DetectionType.BranchV2]
    loops = [ln for _, ln, dtype in static_list if dtype == DetectionType.Loop]
    bypasses = [ln for _, ln, dtype in static_list if dtype == DetectionType.Bypass]

    # Rows to in table consisting of sublists
    vulns = [bypasses, loops, constants, branches, nops, bits]

    # Plotting
    fig, ax = plt.subplots(figsize=(14, 8))
    y_pos = np.arange(len(dtypes))
    height = 0.8

    plt.rcParams.update(
        {
            "font.size": 14,  # Base font size
            "axes.titlesize": 30,  # Title
            "axes.labelsize": 20,  # X and Y labels
        }
    )

    for i, row in enumerate(vulns):
        for j in range(num_instructions):
            if j in row:
                if j in segfaults:
                    ax.barh(
                        i,
                        1,
                        left=j,
                        height=height,
                        color=colors["Both"],
                        edgecolor="none",
                    )
                else:
                    ax.barh(
                        i,
                        1,
                        left=j,
                        height=height,
                        color=colors["Vulnerable"],
                        edgecolor="none",
                    )
            elif j in segfaults:
                ax.barh(
                    i,
                    1,
                    left=j,
                    height=height,
                    color=colors["SIGSEGV"],
                    edgecolor="none",
                )
            else:
                ax.barh(
                    i,
                    1,
                    left=j,
                    height=height,
                    color=colors["normal"],
                    edgecolor="none",
                )

    # Formatting
    ax.set_yticks(y_pos)
    ax.set_yticklabels([f"{d}" for d in dtypes])
    ax.tick_params(axis="y", labelsize=20)
    ax.invert_yaxis()  # Like in the image

    tick_interval = 30
    xticks = list(range(0, num_instructions + 1, tick_interval))
    xtick_labels = [str(i + 1) for i in xticks]
    ax.set_xticks(xticks)
    ax.set_xticklabels(xtick_labels)

    ax.set_xlabel("Line Number", fontsize=20)
    ax.set_title("Vulnerable Instructions")

    legend_handles = [
        mpatches.Patch(color=colors["Both"], label="SIGSEGV and Vulnerable Output"),
        mpatches.Patch(color=colors["Vulnerable"], label="Vulnerable Output"),
        mpatches.Patch(color=colors["SIGSEGV"], label="SIGSEGV"),
    ]
    ax.legend(handles=legend_handles, loc="lower right")

    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    return plt


@app.command()
def compare_regs(
    inp: Path,
    mut: Path,
    stdin: str | None = None,
    func_names: list[str] = [],
    quiet: bool = True,
):
    """
    Temp function to get the registers of all functions
    """

    ret, stdout, capt = sim_binary_w_input(inp, stdin)
    mut_ret, mut_stdout, mut_capt = sim_binary_w_input(mut, stdin)

    # See the difference in registers

    # start with RAX if X86, R0 if arm
    print(capt)
    print(mut_capt)

    func_name = "password_check"

    tmp = capt[func_name]
    print("=====================================")
    print(tmp)
    norm_rax = capt[func_name][0]["r0"]
    mut_rax = mut_capt[func_name][0]["r0"]

    for name, info in capt.items():
        mut_info = mut_capt[name]

        for reg, val in info.items():
            if val != mut_info[reg]:
                print(f"DIFF in ({name}|{reg}): Vanilla: {val} Mut: {mut_info[reg]}")

    print(f"Retunr addrs of password_check: {norm_rax}")
    print(f"Mut Retunr addrs of password_check: {mut_rax}")

    func_name = "main"
    norm_rax = capt[func_name]["r0"]
    mut_rax = mut_capt[func_name]["r0"]
    print(f"Retunr addrs of password_check: {norm_rax}")
    print(f"Mut Retunr addrs of password_check: {mut_rax}")

    print(stdout)
    print(mut_stdout)

    return


if __name__ == "__main__":
    setup_logger(console_level="INFO")
    # setup_logger(console_level="DEBUG")
    logger = logging.getLogger(__name__)  # module-level logger

    for name in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(name).setLevel(logging.ERROR)
    import angr

    app()
