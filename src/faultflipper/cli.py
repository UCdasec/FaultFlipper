import lief
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from collections import Counter
from sklearn.model_selection import train_test_split
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
from cli_utils import (
    CommandParameters,
    Backends,
    RegCommandParameters,
    show_results,
    parse_results,
    BitFlipExperimentResult,
    NopExperimentResult,
    RegNopExperimentResult,
    RegBitFlipExperimentResult,
    save_report,
    save_reg_report,
)

from binary_tools import (
    disasm,
    generate_compile_cmd,
    Target,
    compile_program,
    get_return_reg,
    shift_exit_code,
    _generate_nop_mutated_bin,
    generate_nops_mutated_bin,
    generate_bit_mutated_file,
    detect_target,
    run_binary_w_calltime_input,
    timed_run_binary_w_input,
    disassemble_text_section,
    sim_binary_w_input,
    sim_binary_w_calltime_input,
    OptimizationLevel,
)

from parallel_runner import (
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
def get_disasm(
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

    total = disasm(binary, start_addr, end_addr, text, verbose, pad)
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
    """Run a bit experiment on a already compiled binary with (in,out) tups.

    Basically this runs x-bit with many different inputs.

    I.E) For ML, we pass in (input, output) pairs. That is mayeb 40 pairs of
    inputs and labels. Then, EACH mutated binary will be checked against ALL
    40 pairs.
    """

    other_returncodes = [
        ("failed_to_run", -999),
        ("correct_prediction", 0),
    ]

    res_file = common.out_dir.joinpath("results.csv")

    if not common.yes:
        num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8
        num_bytes = len(lief.parse(common.program_file).get_section(".text").content)
        num_insns = len(disassemble_text_section(common.program_file))
        cont = str(
            input(
                f"Run with {num_bits} bits, {num_bytes} bytes, {num_insns} insns? (Yy/Nn)"
            )
        )

        if cont.lower() != "y":
            return

    if res_file.exists():
        # Gather the results
        df = pd.read_csv(res_file)
        print(f"Loading existing results")
    else:
        print(f"Old results: {res_file} does not exists")
        common.out_dir.mkdir(exist_ok=True)

        # Intermeidate results
        result_out = common.out_dir.joinpath("intermediate_results")
        result_out.mkdir(exist_ok=True)

        # Adjust the out dir
        common.out_dir = common.out_dir.joinpath("mutated_bins")
        common.out_dir.mkdir(exist_ok=True)

        disasm = disassemble_text_section(common.program_file)
        # Load the target type
        target = detect_target(common.program_file)

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
        save_df(df, res_file)

    # Add a column for whetehr or not the output was correct and if the returncode indicates
    # a binary failed to run.
    df["correct"] = [
        exp in prog
        for exp, prog in zip(
            df["expected_stdout"].astype(str), df["program_stdout"].astype(str)
        )
    ]
    df["failed"] = df["return_code"] == -999

    # Build a MultiIndex of the bad (nopped_addr, index) pairs
    bad_idx = pd.MultiIndex.from_frame(
        df.loc[df["return_code"] == -999, ["flipped_addr", "flipped_index"]]
    )

    # Filter out rows whose tuple is in bad_idx
    df_no_fail = df[
        ~pd.MultiIndex.from_frame(df[["flipped_addr", "flipped_index"]]).isin(bad_idx)
    ]

    print(f"The shape of the dataframe that HAS fails is {df.shape}")
    print(f"The shape of the dataframe that dropped fails is {df_no_fail.shape}")

    ROWS_PER_COMBO = df.groupby(["flipped_addr", "flipped_index"]).size().iloc[0]

    # Make a agg group based on fliopped addr and index
    agg_df = (
        df.groupby(["flipped_addr", "flipped_index"])
        .agg(total_correct=("correct", "sum"), total_failed=("failed", "sum"))
        .reset_index()
    )

    # Make a agg group based on fliopped addr and index and not allowing any
    # groups that have atleast one failed index
    agg_df_no_fail = (
        df_no_fail.groupby(["flipped_addr", "flipped_index"])
        # .filter(lambda g: not (g["failed"] == -999).any())
        .agg(total_correct=("correct", "sum"), total_failed=("failed", "sum"))
        .reset_index()
    )

    agg_df["accuracy"] = agg_df.apply(
        lambda row: row["total_correct"] / len(outs), axis=1
    )

    agg_df_no_fail["accuracy"] = agg_df.apply(
        lambda row: row["total_correct"] / len(outs), axis=1
    )

    # agg_df_no_fail_upsests_only["accuracy"] = agg_df.apply(
    #    lambda row: row['total_correct'] / len(outs), axis=1
    # )

    # plot_df = agg_df_no_fail[(int(agg_df_no_fail["total_correct"]) != int(expected_correct)) & (agg_df_no_fail['total_correct'] != 0)]
    plot_df = agg_df_no_fail[
        int(agg_df_no_fail["total_correct"]) != int(expected_correct)
    ]

    # plot_df = agg_df_no_fail[(agg_df_no_fail["total_correct"] != (expected_correct / len(outs)))]

    plot_desc_accuracy(
        plot_df,
        expected_correct / len(outs),
        common.out_dir.joinpath("bar_plot.png"),
        is_bit=True,
    )
    plot_accuracy_ecdf(
        plot_df,
        expected_correct / len(outs),
        common.out_dir.joinpath("ecdf_plot.png"),
        is_bit=True,
    )
    plot_accuracy_rank(
        plot_df,
        expected_correct / len(outs),
        common.out_dir.joinpath("rank_plot.png"),
        is_bit=True,
    )

    print("Histogram of #correct rows per (addr, idx):")
    print(agg_df["total_correct"].value_counts().sort_index())

    print("Histogram of #failed rows per (addr, idx):")
    print(agg_df["total_failed"].value_counts().sort_index())

    # Per (flipped addr, flipped index), get the number of correct predictions
    grouped_df = df.groupby(["flipped_addr", "flipped_index"])
    correct_per_mutated = grouped_df["correct"].sum()

    # Per (flipped addr, flipped index), get the number of correct predictions
    grouped_df_no_fail = df_no_fail.groupby(["flipped_addr", "flipped_index"])
    correct_per_mutated_no_fail = grouped_df_no_fail["correct"].sum()

    counts = correct_per_mutated.value_counts()
    # print(f"GROUPPED WITH FAILS: ")
    # print(grouped_df)
    print(f"The value counts of correct predictions:")
    print(counts)

    # print(f"GROUPPED WITHOUT FAILS: ")
    # print(grouped_df_no_fail)
    # print(f"The value counts of correct predictions (of binaries that NEVER FAILED):")
    # counts_no_fail = correct_per_mutated_no_fail.count()
    # print(counts_no_fail)
    # print(agg_df['total_correct'].sum())

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

    res_file = common.out_dir.joinpath("results.csv")

    if res_file.exists():
        # Gather the results
        df = pd.read_csv(res_file)
        print(f"Loading existing results")
    else:
        print(f"Old results: {res_file} does not exists")
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


def plot_desc_accuracy(df, baseline, out: Path, step=1, width=0.8, is_bit=False):
    d = df.copy()
    d["accuracy"] = pd.to_numeric(d["accuracy"], errors="coerce").fillna(0)

    # pick x label column
    if is_bit:
        if "lbl" not in d.columns:
            d["lbl"] = (
                d["flipped_addr"].astype(str) + ":" + d["flipped_index"].astype(str)
            )
        xkey = "lbl"
    else:
        xkey = "nopped_addr"

    # sort by accuracy DESC
    d = d.sort_values("accuracy", ascending=False).reset_index(drop=True)
    nz = d[d["accuracy"] != 0].copy()
    z = d[d["accuracy"] == 0].copy()
    zcount = len(z)

    # final category order: non-zeros, then two condensed zeros
    x_labels = nz[xkey].astype(str).tolist()
    y_vals = nz["accuracy"].to_numpy()

    if not is_bit:
        x_labels = [hex(int(x)) for x in x_labels]

    x_labels += ["Others 1", f"Others {zcount}"]
    y_vals = np.concatenate([y_vals, [0, 0]])

    # categorical positions (for stable geometry), but we show your real labels
    x_pos = np.arange(len(x_labels))

    # ---- plot ----
    fig_w = min(24, max(8, len(x_labels) * 0.12))
    fig, ax = plt.subplots(figsize=(fig_w, 5), dpi=150)

    ax.bar(x_pos, y_vals, width=width, linewidth=0, antialiased=False, zorder=2)

    # y-limits: keep bottom at 0, give headroom for baseline/bars so plot isn't squished
    top_needed = max(y_vals.max(), float(baseline))
    ax.set_ylim(0, top_needed * 1.10 if top_needed > 0 else 1.0)

    # draw baseline
    ax.axhline(baseline, color="red", linestyle="--", linewidth=1, zorder=1)
    ymin, ymax = ax.get_ylim()
    ax.text(
        x_pos[-1],
        baseline + 0.01 * (ymax - ymin),
        "Original",
        color="red",
        ha="right",
        va="bottom",
        fontsize=16,
        fontweight="bold",
    )

    # x tick labels (your real values)
    ax.set_xticks(x_pos)
    # ax.set_xticklabels(x_labels, rotation=45, ha="right")

    # optional: thin crowded xticks
    if step > 1:
        for i, lab in enumerate(ax.get_xticklabels()):
            lab.set_visible((i % step) == 0)

    # put the bottom spine on y=0 (so slashes can cross the real axis)
    ax.spines["bottom"].set_position(("data", 0))
    ax.spines["bottom"].set_zorder(3)

    # break through the x-axis, centered between the two zero blocks
    # the two zero blocks are at positions len(nz) and len(nz)+1
    if zcount:
        x_break = len(nz) + 0.5  # midpoint between the two condensed zeros
        yr = ymax - 0
        dx = 0.12  # half-width of each slash (x units)
        dy = 0.045 * yr  # half-height so it clearly crosses the axis

        ax.plot(
            [x_break - dx, x_break],
            [-dy, +dy],
            color="k",
            lw=1.6,
            clip_on=False,
            zorder=4,
        )
        ax.plot(
            [x_break, x_break + dx],
            [-dy, +dy],
            color="k",
            lw=1.6,
            clip_on=False,
            zorder=4,
        )

        # ax.annotate(f"{zcount} zeros condensed",
        #            xy=(x_break, 0), xytext=(0, -10), textcoords="offset points",
        #            ha="center", va="top", fontsize=8)

    ax.set_xticklabels(x_labels, rotation=60, ha="right", fontsize=12)

    ax.set_ylabel("Accuracy", fontsize=16, fontweight="bold")
    ax.grid(axis="y", alpha=0.25, zorder=0)

    for lbl in ax.get_xticklabels() + ax.get_yticklabels():
        lbl.set_fontweight("bold")

    for spine in ax.spines.values():
        spine.set_linewidth(2.0)

    fig.tight_layout()
    fig.savefig(out, dpi=1_200)
    return


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

    res_file = common.out_dir.joinpath("results.csv")
    if res_file.exists():
        # Gather the results
        df = pd.read_csv(res_file)
        print("Loading existing results")
    else:
        print(f"Old results: {res_file} does not exists")
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
        save_df(df, res_file)

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

    agg_df["accuracy"] = agg_df.apply(
        lambda row: row["total_correct"] / len(outs), axis=1
    )

    plot_df = agg_df[agg_df["total_correct"] != expected_correct]
    # plot_desc_accuracy(plot_df, expected_correct / len(outs),common.out_dir.joinpath("bar_plot.png"))

    plot_desc_accuracy(
        plot_df, expected_correct / len(outs), common.out_dir.joinpath("bar_plot.png")
    )
    plot_accuracy_ecdf(
        plot_df, expected_correct / len(outs), common.out_dir.joinpath("ecdf_plot.png")
    )
    plot_accuracy_rank(
        plot_df, expected_correct / len(outs), common.out_dir.joinpath("rank_plot.png")
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
    filtered_df = df[df["program_stdout"].str.contains(expected_stdout, na=False)]

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
    """Read the results.csv of and experiemnt"""

    if not inp.is_file():
        raise Exception("The input file does not exists")

    df = pd.read_csv(inp, index_col=False)

    expected_stdout = [str(x) for x in df["expected_stdout"].to_list()]
    program_stdout = [str(x) for x in df["program_stdout"].to_list()]

    match = 0
    no_match = 0
    for expected, real in zip(expected_stdout, program_stdout):
        if expected in real:
            match += 1
        else:
            no_match += 1

    print(f"Matches: {match}")
    print(f"No Matche: {no_match}")

    print(df.columns)

    expected_stdout = str(list(df["expected_stdout"])[0])
    contains_df: pd.DataFrame = df[
        df["program_stdout"].str.contains(expected_stdout, na=False)
    ]
    not_contains_df = df.drop(contains_df.index)

    contains_hist = instruction_hist(contains_df)
    not_contains_hist = instruction_hist(not_contains_df)

    print(f"The histogram for the contains hist: {contains_hist}\n\n")
    print(f"The histogram for the not contains hist: {not_contains_hist}\n\n")
    return


def instruction_hist(df):
    """Get a histogram of the instructions in the df."""

    # Get the vanilla binary
    vanilla_binary = Path(str(list(df["unmutated_binary"])[0]))
    assert vanilla_binary.exists()
    contains_insts = []

    for _, row in df.iterrows():
        addr = int(row["nopped_addr"])

        disassembly = disassemble_text_section(vanilla_binary)

        inst = [f"{x.mnemonic} {x.op_str}" for x in disassembly if x.address == addr]
        if inst == []:
            raise Exception(f"Missing the matching instruction for addres {addr}")

        contains_insts.extend(inst)

    hist = Counter(contains_insts)

    return hist


def x_bit_reg_seq(
    common: CommandParameters,
    target: Target,
    names: str,
    num_bits: int = 1,
    verbose: bool = False,
    optimization: OptimizationLevel = OptimizationLevel.O0,
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

    res_file = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target, optimization)

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
    save_df(df, res_file)

    # show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    report_path = common.out_dir.parent.joinpath("report.md")

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


def x_bit_reg_parallel(
    common: RegCommandParameters,
    target: Target,
    num_cpus: int,
    func_names: str,
    num_bits: int = 1,
    verbose: bool = False,
    optimization: OptimizationLevel = OptimizationLevel.O0,
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

    res_file = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target, optimization)

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

    save_df(df, res_file)

    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    report_path = common.out_dir.parent.joinpath("report.md")

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


def x_bit_qemu_seq(
    common: CommandParameters,
    target: Target,
    num_bits: int,
    log_matching: bool,
    optimization: OptimizationLevel,
):
    """Run the x bit mutation scheme with a qemu backend.

    Run the X-BIT fault model, with qemu in a sequential fashion.
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

    res_file = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target, optimization)

    if not common.yes:
        cont = str(
            input(
                f"Will _attempt_ to make {len(lief.parse(common.program_file).get_section('.text').content) * 8} mutated binaries, continue? (Yy/Nn)"
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

    save_df(df, res_file)
    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    res_file = common.out_dir.joinpath("results.csv")
    report_path = common.our_dir.parent.joinpath("report.md")

    upset_on_match = False if "fib" in results[0].source_file.name else True
    normal_df, error_df, fault_df = parse_results(df, upset_on_match)

    save_report(
        report_path,
        common,
        df,
        normal_df,
        error_df,
        fault_df,
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


def x_bit_qemu_parallel(
    common: CommandParameters,
    target: Target,
    num_cpus: int,
    num_bits: int,
    log_matching: bool = True,
    optimization: OptimizationLevel = OptimizationLevel.O0,
):
    """Run the x bit mutation scheme with a parallel qemu backend.

    Run the X-BIT fault model with multiprocessed QEMU.
    """

    max_workers = max(1, num_cpus // 2)

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

    res_file = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target, optimization)

    if not common.yes:
        cont = str(
            input(
                f"Will _attempt_ to make {len(lief.parse(common.program_file).get_section('.text').content) * 8} mutated binaries, continue? (Yy/Nn)"
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

                bar()

    runtime = datetime.now() - start

    num_instructions = len(disasm)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    df = dataclass_to_dataframe(results)

    save_df(df, res_file)
    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    report_path = common.out_dir.parent.joinpath("report.md")
    upset_on_match = False if "fib" in results[0].source_file.name else True
    normal_df, error_df, fault_df = parse_results(df, upset_on_match)

    save_report(
        report_path,
        common,
        df,
        normal_df,
        error_df,
        fault_df,
        runtime,
        results,
        num_instructions,
        num_bits,
        compile_cmd,
        source_code,
        program_context,
        is_bit=True,
    )


    print(f"UPSET ON MATCH: {upset_on_match}")
    print(f"Had {normal_df.shape}) normal")
    print(f"Had {error_df.shape}) error")
    print(f"Had {fault_df.shape}) fault")

    return


def collect_all_reg_calls(capt_info, reg_name, func_name):
    return [x[reg_name] for x in capt_info[func_name]]


def x_nop_reg_seq(
    common: RegCommandParameters,
    target: Target,
    func_names: str,
    num_nops: int = 1,
    verbose: bool = False,
    optimization: OptimizationLevel = OptimizationLevel.O0,
):
    """
    The register version of the nop x command.

    This will use ANGR to run the mutated binary
    """

    func_names: list[str] = func_names.split(",")

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

    res_file = common.out_dir.joinpath("results.csv")

    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target, optimization)

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

    print("done")
    runtime = datetime.now() - start_time

    # TODO - Better implement the register version
    df = dataclass_to_dataframe(results)
    save_df(df, res_file)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    report_path = common.out_dir.parent.joinpath("report.md")
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


@app.command()
def x_bit(
    common: RegCommandParameters,  # TODO: Make everything use this version and rename
    target: Target,
    func_names: str,
    num_bits: int = 1,
    num_cpus: int = 1,
    verbose: bool = False,
    backend: Backends = Backends.QEMU,
    log_matching: bool = True,
    optimization: OptimizationLevel = OptimizationLevel.O0,
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
            x_bit_reg_seq(common, target, func_names, num_bits, verbose, optimization)
        else:
            # Parallel
            x_bit_reg_parallel(
                common, target, num_cpus, func_names, num_bits, verbose, optimization
            )
    elif backend == backend.QEMU:
        # Now assert that we have stdout and expected return code
        if common.expected_stdout is None or common.expected_returncode is None:
            print(
                f"The backend {backend} requires expected_stdout and expected_returncode"
            )

        if num_cpus == 1:
            # Sequantial
            x_bit_qemu_seq(common, target, num_bits, log_matching, optimization)
        else:
            # Parallel
            x_bit_qemu_parallel(
                common, target, num_cpus, num_bits, log_matching, optimization
            )
    return


@app.command()
def x_nop(
    common: RegCommandParameters,  # TODO: Make everything use this version and rename
    target: Target,
    func_names: str = "",
    num_nops: int = 1,
    num_cpus: int = 1,
    verbose: bool = False,
    backend: Backends = Backends.QEMU,
    log_matching: bool = True,
    optimization: OptimizationLevel = OptimizationLevel.O0,
):
    """
    Command to run NOP experiments!
    """

    if backend == Backends.ANGR and num_cpus > 1:
        print("ANGR backend does not support parallel execution yet")
        return

    # Run the backend + the parallel versus sequentation version
    if backend == backend.ANGR:
        if num_cpus == 1:
            # Sequantial
            logger.info(f"Staring with backend {backend} sequential")
            x_nop_reg_seq(common, target, func_names, num_nops, verbose, optimization)
        else:
            # Parallel
            logger.info(f"Staring with backend {backend} parallel")
            x_nop_reg_parallel(
                common, target, num_cpus, func_names, num_nops, verbose, optimization
            )
    elif backend == backend.QEMU:
        # Now assert that we have stdout and expected return code
        if common.expected_stdout is None or common.expected_returncode is None:
            print(
                f"The backend {backend} requires expected_stdout and expected_returncode"
            )

        if num_cpus == 1:
            # Sequantial
            logger.info(f"Staring with backend {backend} sequential")
            x_nop_qemu_seq(common, target, num_nops, log_matching, optimization)
        else:
            # Parallel
            logger.info(f"Staring with backend {backend} parallel")
            x_nop_qemu_parallel(
                common,
                target,
                num_cpus,
                num_nops,
                log_matching,
                optimization=optimization,
            )

    return


def x_nop_reg_parallel(
    common: RegCommandParameters,
    target: Target,
    num_cpus: int,
    func_names: str,
    num_nops: int = 1,
    verbose: bool = False,
    optimization: OptimizationLevel = OptimizationLevel.O0,
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

    res_file = common.out_dir.joinpath("results.csv")
    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target, optimization)

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
    save_df(df, res_file)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    report_path = common.out_dir.parent.joinpath("report.md")
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
    optimization: OptimizationLevel = OptimizationLevel.O0,
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

    res_file = common.out_dir.joinpath("results.csv")

    common.out_dir = common.out_dir.joinpath("mutated_bins")
    common.out_dir.mkdir(exist_ok=True)

    # Compile the binary for the target
    common.program_file = compile_program(source_code, bin_out, target, optimization)

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

    save_df(df, res_file)
    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    report_path = common.out_dir.parent.joinpath("report.md")


    upset_on_match = False if "fib" in results[0].source_file.name else True
    normal_df, error_df, fault_df = parse_results(df, upset_on_match)

    save_report(
        report_path,
        common,
        df,
        normal_df,
        error_df,
        fault_df,
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
    optimization: OptimizationLevel = OptimizationLevel.O0,
):
    """Run an experiment that gernerates mutant binaries with num_nops, and tests them with QEMU.

    Parameters
    ----------

    """

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
        common.program_file = compile_program(
            source_code, bin_out, target, optimization
        )
        compile_cmd = generate_compile_cmd(common.program_file, bin_out, target)
    else:
        source_code = ""
        bin_out = common.program_file
        compile_cmd = ""

    res_file = common.out_dir.joinpath("results.csv")

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
    save_df(df, res_file)
    show_results(common, df, other_returncodes)

    # Lastly save the experiment parameters
    params = common.to_dict()
    params["target"] = target.value

    with open(base_out.joinpath("experiment_parametes.json"), "w") as f:
        json.dump(params, f, indent=4)

    num_bits = len(lief.parse(common.program_file).get_section(".text").content) * 8

    report_path = common.out_dir.parent.joinpath("report.md")

    upset_on_match = False if "fib" in results[0].source_file.name else True
    normal_df, error_df, fault_df = parse_results(df, upset_on_match)

    save_report(
        report_path,
        common,
        df,
        normal_df,
        error_df,
        fault_df,
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


    print(f"UPSET ON MATCH: {upset_on_match}")
    print(f"Had {normal_df.shape}) normal")
    print(f"Had {error_df.shape}) error")
    print(f"Had {fault_df.shape}) fault")

    return


@app.command
def run(inps: list[Path] = [Path("experiment.toml")]):
    """
    This will run ALL the experiments in the provided experiment file
    """

    for inp in inps:
        if not inp.exists():
            print(f"The input {inp} does not exist!")
            continue
        settings = dynaconf.Dynaconf(settings_files=inp)

        experiments = settings.get("experiment", {})

        commands = {
            "x_nop": x_nop,
            "x_bit": x_bit,
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

            if command_name in ["x_nop"]:
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
                    cmd_func(
                        params, target=target, num_cpus=num_cpus, func_names=func_names
                    )

            elif command_name in ["x_bit"]:
                target = formated.pop("target")
                num_cpus = formated.pop("num_cpus")
                num_bits = formated.get("num_bits", None)
                func_names = formated.get("func_names", None)

                if num_bits:
                    formated.pop("num_bits")
                    params = CommandParameters(**formated)
                    cmd_func(
                        params,
                        target=target,
                        num_cpus=num_cpus,
                        num_bits=num_bits,
                        func_names=func_names,
                    )
                else:
                    params = CommandParameters(**formated)
                    cmd_func(
                        params, target=target, num_cpus=num_cpus, func_names=func_names
                    )

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
                num_cpus = formated.pop("num_cpus")
                _ = formated.pop("no_compile")
                expected_correct = int(formated.pop("expected_correct"))
                params = CommandParameters(**formated)
                cmd_func(
                    params, ins=ins, outs=outs, expected_correct=expected_correct, num_cpus=num_cpus
                )  # , target=target, num_cpus=num_cpus)

            elif command_name in ["angr_nop_no_comp_inout"]:
                ins = formated.pop("ins")
                outs = formated.pop("outs")
                target = formated.pop("target")
                _ = formated.pop("no_compile")
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


def _accuracy_series(
    df: pd.DataFrame, *, is_bit: bool, aggregate: str = "max"
) -> np.ndarray:
    """
    Return a 1D numpy array of accuracies suitable for plotting.
    - is_bit=True: one row per (flipped_addr, flipped_index) -> use all rows.
    - is_bit=False: collapse to one row per addr using aggregate {'max','mean','median'} if both 'addr' and 'index' exist.
    """
    d = df.copy()

    if is_bit:
        # Expect columns: flipped_addr, flipped_index, accuracy
        acc = pd.to_numeric(d["accuracy"], errors="coerce").dropna()
        return acc.to_numpy()

    acc = pd.to_numeric(d["accuracy"], errors="coerce").dropna()
    return acc.to_numpy()


def plot_accuracy_ecdf(
    df: pd.DataFrame,
    baseline: float,
    out: Path,
    *,
    is_bit: bool = False,
    aggregate: str = "max",
    dpi: int = 150,
):
    """
    ECDF of accuracies. X=accuracy, Y=fraction ≤ accuracy.
    Works for both is_bit paths.
    """
    y = _accuracy_series(df, is_bit=is_bit, aggregate=aggregate)
    y_sorted = np.sort(y)  # ascending for ECDF
    x_frac = np.arange(1, len(y_sorted) + 1) / len(y_sorted)

    fig, ax = plt.subplots(figsize=(8, 4), dpi=dpi)
    ax.step(y_sorted, x_frac, where="post", linewidth=1.2)
    ax.axvline(baseline, linestyle="--", linewidth=1)
    ax.text(baseline, 1.0, "baseline", ha="left", va="bottom")

    ax.set_xlabel("Accuracy")
    ax.set_ylabel("Fraction of (addr,index) ≤ accuracy")
    ax.set_title("ECDF of Accuracy")
    ax.grid(axis="both", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out)


def plot_accuracy_rank(
    df: pd.DataFrame,
    baseline: float,
    out: Path,
    *,
    is_bit: bool = False,
    aggregate: str = "max",
    top_k: int | None = None,
    dpi: int = 150,
):
    """
    Rank curve (sorted high→low). X=rank, Y=accuracy.
    Works for both is_bit paths. Optionally limit to top_k points.
    """
    y = _accuracy_series(df, is_bit=is_bit, aggregate=aggregate)
    y_sorted_desc = np.sort(y)[::-1]  # high → low

    if top_k is not None:
        y_sorted_desc = y_sorted_desc[:top_k]

    fig_w = min(24, max(8, len(y_sorted_desc) * 0.004))  # auto-scale width a bit
    fig, ax = plt.subplots(figsize=(fig_w, 4), dpi=dpi)
    ax.plot(np.arange(len(y_sorted_desc)), y_sorted_desc, linewidth=1.0)
    ax.axhline(baseline, linestyle="--", linewidth=1)
    ax.text(len(y_sorted_desc) - 1, baseline, "baseline", ha="right", va="bottom")

    ax.set_xlabel("Ranked (addr,index)")
    ax.set_ylabel("Accuracy")
    ax.set_title("Sorted Accuracy Curve (high → low)")
    ax.grid(axis="both", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out)


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


@app.command()
def spectral_plot(nop_exp_results: Path, bit_exp_results: Path, out: Path):
    """
    Make the spectrral plot.

    Spectral plot has the address as the x addr and plots
    which bytes cause a fault and which caused a program error.

    This is done for a single c source code file.
    """

    # Load the results and get all addrs that caused a successful attack

    # If this is a fib example, successful attack is returncode = 0
    # and STDOUT != expected

    # If this is a pass ewxample , seccessful attack is returncode= 0
    # and Correct in STDOUT

    nop_df = pd.read_csv(nop_exp_results)
    bit_df = pd.read_csv(bit_exp_results)

    all_addrs = set(nop_df["nopped_addr"].tolist())

    bit_all_addrs = set(bit_df["flipped_addr"].tolist())

    print(f"Len nop addrs: {len(all_addrs)}")
    print(f"Len bit addrs: {len(bit_all_addrs)}")
    assert bit_all_addrs == all_addrs

    nop_normal, nop_error, nop_fault = parse_results(nop_df)
    bit_normal, bit_error, bit_fault = parse_results(bit_df)

    nop_list = set(nop_fault["nopped_addr"].tolist())
    bit_list = set(bit_fault["flipped_addr"].tolist())

    # nop_list = [int(x,16) for x in nop_fault['nopped_addr'].tolist()]
    # nop_list = [int(x)-min_addr for x in nop_fault['nopped_addr'].tolist()]
    # bit_list = bit_fault['flipped_addr'].tolist()
    # bit_list = list(set([int(x,16) for x in bit_fault['flipped_addr'].tolist()]))
    # bit_list = list(set([int(x)-min_addr_bit for x in bit_fault['flipped_addr'].tolist()]))
    # print(f"The nop list is {nop_list}")
    # print(f"The bit list is {bit_list}")

    nop_e_list = set(nop_error["nopped_addr"].tolist())
    bit_e_list = set(bit_error["flipped_addr"].tolist())
    # nop_e_list = [int(x,16) for x in nop_error['nopped_addr'].tolist()]
    # nop_e_list = [int(x) for x in nop_error['nopped_addr'].tolist()]
    # bit_e_list = list(set([int(x,16) for x in bit_error['flipped_addr'].tolist()]))
    # bit_e_list = list(set([int(x) for x in bit_error['flipped_addr'].tolist()]))

    # Need to map the nopped_addr to the "line"
    # and flipped_addr to line

    #create_plot(
    #    nop_list, bit_list, nop_e_list, bit_e_list, nop_df.shape[0], out, all_addrs
    #)
    out.mkdir(exist_ok=True)

    create_single_plot(
        nop_list, nop_e_list, "NOP", nop_df.shape[0], out.joinpath("NOP.jpeg"), all_addrs
    )

    create_single_plot(
        bit_list,  bit_e_list, "BIT", nop_df.shape[0], out.joinpath("BIT.jpeg"), all_addrs
    )



    return


def create_single_plot(
    upsets: list,
    errors: list,
    x_axis: str,
    num_instructions,
    out: Path,
    all_addrs,
):
    """Create a spectrum plot.

    Make a spectrum gram plot of the data.
    """

    # Configuration
    colors = {
        "Both": "#7f2a19",  # blue
        "SIGSEGV": "#f6b26b",  # orange
        "Vulnerable": "#e66c2c",  # red
        "normal": "#e0e0e0",  # gray (default background)
    }

    # Plotting
    figa, ax = plt.subplots(figsize=(16, 4))

    # Iter over both lists
    for j, addr in enumerate(all_addrs):
        # We iterate over all instrcutoins because some of the insutrctions
        # wil have both some or none.

        # for j in range(num_instructions):
        is_upset = addr in upsets
        is_segfault = addr in errors

        if is_upset and is_segfault:
            color = colors["Both"]
        elif is_upset:
            color = colors["Vulnerable"]
        elif is_segfault:
            color = colors["SIGSEGV"]
        else:
            color = colors["normal"]

        ax.barh(
            0,
            1,
            left=j,
            color=color,
            edgecolor="none",
        )

    # Formatting
    ax.set_yticks([])
    #ax.set_ylabel(x_axis, fontsize=24, fontweight='bold')
    ax.tick_params(axis="y", labelsize=20)
    ax.invert_yaxis()

    tick_interval = 30
    xticks = list(range(0, num_instructions + 1, tick_interval))
    xtick_labels = [str(i + 1) for i in xticks]

    ax.set_xticks(xticks)
    ax.set_xticklabels(xtick_labels, fontsize=28)

    ax.set_xlabel("Line Number", fontsize=28, fontweight='bold')

    for lbl in ax.get_xticklabels() + ax.get_yticklabels():
        lbl.set_fontweight("bold")

    for spine in ax.spines.values():
        spine.set_linewidth(2.0)

    ax_legend_handles = [
        mpatches.Patch(color=colors["Both"], label="SIGSEGV + Vuln"),
        mpatches.Patch(color=colors["Vulnerable"], label="Vulnerable"),
        mpatches.Patch(color=colors["SIGSEGV"], label="SIGSEGV"),
    ]
    ax.legend(
        handles=ax_legend_handles,
        #loc="center left",
        #bbox_to_anchor=(1.01, 0.5),
        #borderaxespad=0,
        fontsize=18,
    )

    figa.savefig(out, dpi=800, bbox_inches="tight")

    return




def create_plot(
    nop_list,
    bit_list,
    nop_segfaults,
    bit_segfaults,
    num_instructions,
    out: Path,
    all_addrs,
):
    """Create a spectrum plot.

    Make a spectrum gram plot of the data.
    """

    # Configuration
    dynamic_dtypes = ["NOP     ", "BIT     "]
    colors = {
        "Both": "#7f2a19",  # blue
        "SIGSEGV": "#f6b26b",  # orange
        "Vulnerable": "#e66c2c",  # red
        "normal": "#e0e0e0",  # gray (default background)
    }

    # nops = [ln for _, ln in nop_list]
    # bits = [ln for _, ln in bit_list]

    # Rows to in table consisting of sublists
    dynamic_vulns = [nop_list, bit_list]

    # Plotting
    figa, ax = plt.subplots(figsize=(16, 4))

    for i, cur_list in enumerate(dynamic_vulns):
        # Iter over both lists
        for j, addr in enumerate(all_addrs):
            # We iterate over all instrcutoins because some of the insutrctions
            # wil have both some or none.

            # for j in range(num_instructions):
            is_vuln = addr in cur_list

            if i == 0:
                is_segfault = addr in nop_segfaults
            else:
                is_segfault = addr in bit_segfaults

            if is_vuln and is_segfault:
                color = colors["Both"]
            elif is_vuln:
                color = colors["Vulnerable"]
            elif is_segfault:
                color = colors["SIGSEGV"]
            else:
                color = colors["normal"]

            ax.barh(
                i,
                1,
                left=j,
                color=color,
                edgecolor="none",
            )

    # Formatting
    ax_y_pos = np.arange(len(dynamic_dtypes))
    ax.set_yticks(ax_y_pos)
    ax.set_yticklabels([f"{d}" for d in dynamic_dtypes], fontsize=24)
    ax.tick_params(axis="y", labelsize=16)
    ax.invert_yaxis()  # Like in the image

    tick_interval = 30
    xticks = list(range(0, num_instructions + 1, tick_interval))
    xtick_labels = [str(i + 1) for i in xticks]

    ax.set_xticks(xticks)
    ax.set_xticklabels(xtick_labels)

    ax.set_xlabel("Line Number", fontsize=24)

    for lbl in ax.get_xticklabels() + ax.get_yticklabels():
        lbl.set_fontweight("bold")

    for spine in ax.spines.values():
        spine.set_linewidth(2.0)

    ax_legend_handles = [
        mpatches.Patch(color=colors["Both"], label="SIGSEGV + Vuln"),
        mpatches.Patch(color=colors["Vulnerable"], label="Vulnerable"),
        mpatches.Patch(color=colors["SIGSEGV"], label="SIGSEGV"),
    ]
    ax.legend(
        handles=ax_legend_handles,
        loc="center left",
        bbox_to_anchor=(1.01, 0.5),
        borderaxespad=0,
    )

    figa.savefig(out, dpi=1200, bbox_inches="tight")

    return


if __name__ == "__main__":
    logger = logging.getLogger(__name__)  # module-level logger
    app()
