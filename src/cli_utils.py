from dataclasses import dataclass 
from cyclopts import App, Parameter
from pathlib import Path
from typing import Union
import pandas as pd 
from typing import Optional

from dataclasses import dataclass, fields

from enums import LinuxExitCodes
from binary_tools import Target

from rich.table import Table
from rich.console import Console
import logging

from rich.console import Console

logger = logging.getLogger(__name__)   # module-level logger

console = Console()

@Parameter(name="*")
@dataclass
class CommandParameters:
    program_file: Path
    out_dir: Path
    program_input: str
    expected_stdout:  str | Path #| list[str]
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


def smol_show_results(
    df: pd.DataFrame,
    other_returncodes: list[tuple[str, int]],
    expected_stdout: str,
    quiet: bool = True,
):
    #if print_df:
    #    console.print(
    #        df[
    #            [
    #                x
    #                for x in df.columns
    #                if x not in ["binary_path", "other_returncodes"]
    #            ]
    #        ]
    #    )
    #    print(f"The binaries with the expected output were: {len(list(good_names))}:\n{good_names}")
    #    print(info[["return_code", "program_stdout", "binary_path"]])

    new_freqs = calc_freqs(df, expected_stdout, other_returncodes)
    print_histogram(new_freqs)

    # Make a histogam of program stdouts
    stdout_freqs = df["program_stdout"].value_counts().to_dict()

    # Get the outputs that contain the epected output
    correct_freq = {
        0: v for k, v in stdout_freqs.items() if expected_stdout in k
    }

    if not quiet:
        if correct_freq != {}:
            print(
                f"{correct_freq[0]} programs out of {len(df)} total had the expected stdout"
            )
        else:
            print(f"0 programs out of {len(df)} had the expected stdout")
    return





def show_results(
    common: CommandParameters,
    df: pd.DataFrame,
    other_returncodes: list[tuple[str, int]],
    print_df: bool = False,
    quiet: bool = True,
):
    if print_df:
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
        good_names = set([])
        print(f"THe expected stdout is: {common.expected_stdout}")
        if isinstance(common.expected_stdout, str):
            info = df[
                df["program_stdout"].str.contains(common.expected_stdout, na=False)
            ]
            good_names =  set([Path(x).name for x in list(info["binary_path"])])
        else:
            print(f"Using the list of stdout")
            for line in common.expected_stdout:
                info = df[
                    df["program_stdout"].str.contains(line, na=False)
                ]
                out_names =  set([Path(x).name for x in list(info["binary_path"])])
                print(f"Have {len(out_names)}")

                if len(good_names) == 0:
                    good_names = out_names
                else:
                    good_names = good_names.intersection(out_names)

            #good_names.append(names)


        print(f"The binaries with the expected output were: {len(list(good_names))}:\n{good_names}")
        print(info[["return_code", "program_stdout", "binary_path"]])

    new_freqs = calc_freqs(df, common, other_returncodes)
    print_histogram(new_freqs)

    # Make a histogam of program stdouts
    stdout_freqs = df["program_stdout"].value_counts().to_dict()

    # Get the outputs that contain the epected output
    correct_freq = {
        0: v for k, v in stdout_freqs.items() if common.expected_stdout in k
    }

    if not quiet:
        if correct_freq != {}:
            print(
                f"{correct_freq[0]} programs out of {len(df)} total had the expected stdout"
            )
        else:
            print(f"0 programs out of {len(df)} had the expected stdout")
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
    """
    Get the frequencies of returncdoes
    """

    freqs = df["return_code"].value_counts().to_dict()
    if isinstance(expected_stdout, list):
        correct_stdouts = []
    else:
        correct_stdouts = df[
        df["program_stdout"].str.contains(expected_stdout, na=False)
    ]

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

        # Split the return code of 1 into two groups:
        # 1. Returncode 1 + Good stdout
        # 2. Returncode 1 + bad stdout
        if k == 0:
            new_freqs[return_code_name] = len(correct_stdouts)
            if v - len(correct_stdouts) > 0:
                new_freqs["Exit 0 : Bad STDOUT"] = v - len(correct_stdouts)
        else:
            new_freqs[return_code_name] = v

    # Make the output a list of tuples
    out = [(k, v) for k, v in new_freqs.items()]

    return out




#def calc_freqs(df, common, other_returncodes) -> list[tuple[str, int]]:
#    """
#    Get the frequencies of returncdoes
#    """
#
#    freqs = df["return_code"].value_counts().to_dict()
#    if isinstance(common.expected_stdout, list):
#        correct_stdouts = []
#    else:
#        correct_stdouts = df[
#        df["program_stdout"].str.contains(common.expected_stdout, na=False)
#    ]
#
#    new_freqs = {}
#    weird_codes = {}
#
#    # For return value and the number of returns that had that value
#    for k, v in freqs.items():
#        try:
#            return_code_name = str(LinuxExitCodes(k).name) + f" ({k})"
#        except:
#            return_code_name = str(k)
#            weird_codes[return_code_name] = list(
#                df[df["return_code"] == k]["binary_path"]
#            )
#
#        # Replace with a fun name if otherwise specified
#        for name, value in other_returncodes:
#            if k == value:
#                return_code_name = name + f" ({value})"
#
#        # Split the return code of 1 into two groups:
#        # 1. Returncode 1 + Good stdout
#        # 2. Returncode 1 + bad stdout
#        if k == 0:
#            new_freqs[return_code_name] = len(correct_stdouts)
#            if v - len(correct_stdouts) > 0:
#                new_freqs["Exit 0 : Bad STDOUT"] = v - len(correct_stdouts)
#        else:
#            new_freqs[return_code_name] = v
#
#    # Make the output a list of tuples
#    out = [(k, v) for k, v in new_freqs.items()]
#
#    return out


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



