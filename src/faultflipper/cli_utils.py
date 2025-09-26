from dataclasses import dataclass
import json
from collections import defaultdict
from cyclopts import App, Parameter
from pathlib import Path
from typing import Union
import pandas as pd
from typing import Optional
from enum import Enum
from report_utils import list_tuple_table, generate_pdf_report

from dataclasses import dataclass, fields

from enums import LinuxExitCodes
from binary_tools import Target, generate_run_cmd, Nop, disasm

from rich.table import Table
from rich.console import Console
import logging

from rich.console import Console

logger = logging.getLogger(__name__)  # module-level logger


other_returncodes = [
    # ("critical_code_ran", 0),
    ("critical_code_did_not_run", 97),
    ("failed_to_run", -900),
]


console = Console()


class Backends(Enum):
    ANGR = "ANGR"
    QEMU = "qemu"


@Parameter(name="*")
@dataclass
class RegCommandParameters:
    program_file: Path
    out_dir: Path
    program_input: str
    list_expected: bool = False
    timeout: int = 5
    save_results: Union[Path, None] = None
    yes: bool = False
    expected_returncode: int | None = None
    expected_stdout: str | None = None

    def to_dict(self):
        if self.save_results is None:
            self.save_results = Path("")

        return {
            "program_file": str(self.program_file.absolute()),
            "out_dir": str(self.out_dir.absolute()),
            "program_input": self.program_input,
            "list_expected": self.list_expected,
            "expected_returncode": self.expected_returncode,
            "expected_stdout": self.expected_stdout,
            "timeout": self.timeout,
            "save_results": str(self.save_results.absolute()),
            "yes": self.yes,
        }


@Parameter(name="*")
@dataclass
class CommandParameters:
    program_file: Path
    out_dir: Path
    program_input: str
    expected_stdout: str | Path  # | list[str]
    expected_returncode: int
    list_expected: bool = False
    timeout: int = 5
    save_results: Union[Path, None] = None
    yes: bool = False

    def to_dict(self):
        if self.save_results is None:
            self.save_results = Path("")

        return {
            "program_file": str(self.program_file.absolute()),
            "out_dir": str(self.out_dir.absolute()),
            "program_input": self.program_input,
            "expected_stdout": ",".join(self.expected_stdout),
            "expected_returncode": self.expected_returncode,
            "list_expected": self.list_expected,
            "timeout": self.timeout,
            "save_results": str(self.save_results.absolute()),
            "yes": self.yes,
        }

def str_in_col(df: pd.DataFrame, inp: str, col: str)->pd.DataFrame:
    """
    Filter the df to get a sub-df where inp in string in col.
    """
    info = df[df[col].str.contains(inp, na=False)]
    return info


def show_results(
    common: CommandParameters,
    df: pd.DataFrame,
    other_returncodes: list[tuple[str, int]],
    print_df: bool = False,
):
    if print_df:
        console.print(
            df[[x for x in df.columns if x not in ["binary_path", "other_returncodes"]]]
        )

    if common.list_expected:
        good_names = set([])
        print(f"The expected stdout is: {common.expected_stdout}")
        if isinstance(common.expected_stdout, str):
            info = df[
                df["program_stdout"].str.contains(common.expected_stdout, na=False)
            ]
            good_names = set([Path(x).name for x in list(info["binary_path"])])
        else:
            print(f"Using the list of stdout")
            for line in common.expected_stdout:
                info = df[df["program_stdout"].str.contains(line, na=False)]
                out_names = set([Path(x).name for x in list(info["binary_path"])])
                print(f"Have {len(out_names)}")

                if len(good_names) == 0:
                    good_names = out_names
                else:
                    good_names = good_names.intersection(out_names)

        print(
            f"The binaries with the expected output were: {len(list(good_names))}:\n{good_names}"
        )
        print(info[["return_code", "program_stdout", "binary_path"]])

    new_freqs = calc_freqs(df, common.expected_stdout, other_returncodes)
    print_histogram(new_freqs)

    return

def parse_results(df: pd.DataFrame, upset_on_match: bool = True)->tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Returns the split of (Normal, Error, upset).

    Success only occurs when the returncode is 0. In some cases, if the 
    expected STDOUT is found, this is a successful attack, however in other cases 
    if it is found, this is a failed attack. 
    """

    expected = df['expected_stdout'][0]

    # If a program does not return 0, it must be an error case
    return_is_0 = df[df['return_code'] ==0]
    error = df[df['return_code'] != 0]

    # Get the expected and not expected 
    out_is_expected =     return_is_0[ return_is_0["program_stdout"].str.contains(expected, na=False)]
    out_is_not_expected = return_is_0[~return_is_0["program_stdout"].str.contains(expected, na=False)]

    upset = out_is_expected if upset_on_match else out_is_not_expected
    normal = out_is_expected if not upset_on_match else out_is_not_expected

    # - Temporary code for debugging 
    #print(f"[ IN PARSE ] Had {len(return_is_0['program_stdout'])} programs return 0, and {len(out_is_not_expected['return_code'])} programs return 0 and not have exepcte output, and {len(out_is_expected['return_code'])} return 0 and have expected")
    tmp = error[error["program_stdout"].str.contains(expected, na=False)]
    #print(f"[ IN PARSE ] Had {len(tmp['program_stdout'])} programs return non 0 and have expected output")

    # - Tempoary code done
    return normal, error, upset


def orig_parse_results(df: pd.DataFrame, upset_on_match: bool = True)->tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Returns the split of (Normal, Error, upset).

    Success only occurs when the returncode is 0. In some cases, if the 
    expected STDOUT is found, this is a successful attack, however in other cases 
    if it is found, this is a failed attack. 
    """

    expected = df['expected_stdout'][0]

    # Get the expected versus the not expected
    out_is_expected = df[df["program_stdout"].str.contains(expected, na=False)]
    out_is_not_expected = df[~df["program_stdout"].str.contains(expected, na=False)]

    # Define the upset df, and the remaining,
    # reamining will be split into nromal and error
    if upset_on_match:
        # If the upset is on a match then the definition is easy...
        upset = out_is_expected 
        #remaining = out_is_not_expected
        normal = out_is_not_expected[out_is_not_expected['return_code'] == 0]
        error =  out_is_not_expected[out_is_not_expected['return_code'] != 0]
    else:
        # If the upset is on a non-match, the definition is harder...
        # That is we need the program to returncode 0 AND have an 
        # stdout that is not match.
        upset = out_is_not_expected[out_is_not_expected['return_code'] == 0]
        error1 = out_is_not_expected[out_is_not_expected['return_code'] != 0]
        #upset = out_is_not_expected

        error2 = out_is_expected[out_is_expected['return_code'] != 0]
        normal = out_is_expected[out_is_expected['return_code'] == 0]

        error = pd.concat([error1, error2],axis=1)
    return normal, error, upset

    #out_is_expected = returncode_is_0[returncode_is_0["program_stdout"].str.contains(expected, na=False)]
    #out_is_not_expected = returncode_is_0[~returncode_is_0["program_stdout"].str.contains(expected, na=False)]

    #if upset_on_match:
        

        #TODO: This contradicts with the paper.
    #upset = out_is_expected if upset_on_match else out_is_not_expected
    #remaining= out_is_expected if not upset_on_match else out_is_not_expected

    #normal = remaining[remaining['return_code'] == 0]
    #error = remaining[remaining['return_code'] != 0]

    #return normal, error, upset

    #out_is_expected = returncode_is_0[returncode_is_0["program_stdout"].str.contains(expected, na=False)]
    #out_is_not_expected = returncode_is_0[~returncode_is_0["program_stdout"].str.contains(expected, na=False)]

    #if upset_on_match:
    #    return out_is_not_expected, returncode_means_error, out_is_expected

    #return  returncode_means_error, out_is_not_expected, out_is_expected


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

    vals = [x[1] for x in results]
    max_count = max(vals) if results else 0
    bar_width = 30  # Adjust to taste

    for result_type, count in results:
        # Scale the bar to max_count
        bar_length = int((count / max_count) * bar_width) if max_count else 0
        bar = "█" * bar_length

        table.add_row(result_type, str(count), bar)

    console.print(table)

    return


def calc_freqs(df, expected_stdout, other_returncodes) -> list[tuple[str, int]]:
    """Get the frequencies of returncdoes.

    Determine cases where the program exits with a normal exit code,
    and provides a bad output.
    """

    freqs = df["return_code"].value_counts().to_dict()

    if isinstance(expected_stdout, list):
        correct_stdouts = []
    else:
        ret_is_0 = df[df['return_code'] == 0]
        correct_stdouts = ret_is_0[
            ret_is_0["program_stdout"].str.contains(expected_stdout, na=False)
        ]

    print(f"[ IN CALC ] had {len(correct_stdouts)} correct stdout but {freqs[0]} programs return 0" )

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

        # Split the return code of 0 into two groups:
        # 1. Returncode 0 + Good stdout
        # 2. Returncode 0 + bad stdout
        if k == 0:
            new_freqs[return_code_name] = len(correct_stdouts)
            if v - len(correct_stdouts) > 0:
                new_freqs["Exit 0 : Bad STDOUT"] = v - len(correct_stdouts)
        else:
            new_freqs[return_code_name] = v

    # Make the output a list of tuples
    out = [(k, v) for k, v in new_freqs.items()]

    return out


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
            if isinstance(value, dict):  # If the value is another dataclass, convert it
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


@dataclass
class RegNopExperimentResult(MutationExperiment):
    nopped_addr: int
    mutation: str = "nop"
    source_code: Path | None = None
    reg_info: dict | None = None


@dataclass
class RegBitFlipExperimentResult(MutationExperiment):
    flipped_addr: int
    flipped_index: int
    mutation: str = "single_bit"
    source_code: Path | None = None
    reg_info: dict | None = None


def save_report(
    report_path: Path,
    common: CommandParameters,
    df: pd.DataFrame,
    normal_df: pd.DataFrame,
    error_df: pd.DataFrame,
    upset_df: pd.DataFrame,
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


    # 2.9 - TLDR of results 
    tldr = "## Results at a Glance\n"
    tldr += f"- **Normal:** {normal_df.shape[0]}\n"
    tldr += f"- **Error:** {error_df.shape[0]}\n"
    tldr += f"- **Upset:** {upset_df.shape[0]}\n"

    # 3. List of programs that had the expected stdout
    list_of_progs = "## List of Event Upset Mutations:\n"

    #matching_info = df[
    #    df["program_stdout"].str.contains(common.expected_stdout, na=False)
    #]
    #non_matching_info = df[
    #    ~df["program_stdout"].str.contains(common.expected_stdout, na=False)
    #]

    upset_names = [Path(x).name for x in list(upset_df["binary_path"])]
    #non_match_names = [Path(x).name for x in list(non_matching_info["binary_path"])]

    #list_of_progs += f"**{len(match_names)}** programs had the expected STDOUT **{len(df)}** mutated binaries\n\n"
    #list_of_progs += f"**{len(non_match_names)}** programs did not have the expected STDOUT **{len(df)}** mutated binaries\n"

    list_of_progs += "\n"
    if log_matching:
        list_of_progs += "The binaries **with** the expected STDOUT were:\n"
    else:
        list_of_progs += "The binaries **without** the expected STDOUT were:\n"

    names_str = ""
    for name in upset_names: #match_names if log_matching else non_match_names:
        names_str += f"- {name} \n"

    list_of_progs += names_str

    # 4. Disassembly of the files that ran critical code
    # 10 bytes on either side will be included
    pad = 10
    #if log_matching:

    bins = [Path(x) for x in list(upset_df["binary_path"])]

    #else:
    #    bins = [Path(x) for x in list(non_matching_info["binary_path"])]

    disassems = ""
    for i, bin in enumerate(bins):
        if is_bit:
            mut_addr = bin.name.replace(f"{common.program_file.name}_", "")
            mut_addr = mut_addr.split("_")[0]
            addresses = [mut_addr]
        else:
            addresses = bin.name.replace(f"{common.program_file.name}_", "").split("_")
                # mut_addr = int(bin.name.replace(f"{common.program_file.name}_", ""), 16)
        rets = []
        for address in addresses:
            mut_addr = int(address, 16)
            
            start_addr = mut_addr - pad
            end_addr = mut_addr + pad

            ret = disasm(
                [common.program_file.absolute(), bin],
                start_addr,
                end_addr,
                text=True,
                verbose=False,
            )
            rets.append(ret)
        disassems += f"#### Original Program vs Program {i} {bin.name} diassemebly\n\n"
        disassems += "```\n"
        disassems += "\n".join(str(x+ "\n") for x in rets)
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
        f.write(tldr)
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



