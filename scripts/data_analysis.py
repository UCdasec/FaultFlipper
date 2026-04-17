#!/usr/bin/python

import itertools
import json
import os
import sys
from dataclasses import dataclass

import numpy as np
from scipy.stats import chi2_contingency, fisher_exact
from statsmodels.stats.power import GofChisquarePower
from tabulate import tabulate

# choose alpha value of 0.10 for experiments
ALPHA = 0.10

@dataclass
class Result:
    instruction: str
    rate1: float
    count1: int
    rate2: float
    count2: int
    p_value: float
    test: str
    significant: bool


@dataclass
class Datafile:
    image_name: str
    data: dict

    def __init__(self, file):
        self.image_name = os.path.basename(os.path.dirname(file))
        self.data = get_instruction_data(file)


def print_results(results: list[Result], image1: str, image2: str):
    results.sort(key=lambda x: x.p_value)

    table_data = []
    for r in results:
        table_data.append(
            [
                r.instruction,
                f"{r.rate1} ({r.count1})",
                f"{r.rate2} ({r.count2})",
                f"{r.p_value:.4e}",
                r.test,
                "Yes" if r.significant else "No",
            ]
        )

    headers = ["Instruction", f"{image1} Rate", f"{image2} Rate", "P-Value", "Test", "Sig?"]

    print(tabulate(table_data, headers=headers, tablefmt="pretty", stralign="right"))
    # print latex formatting
    # print(tabulate(table_data, headers=headers, tablefmt="latex", stralign="right"))


def calculate_dataset_independence(data1, data2):
    """
    Constructs a 2 x N contingency table to test if the distribution of
    instruction types is independent of the dataset. If the number of
    instructions is below 5, the column is dropped for that instruction type

    Row 1: Dataset 1 instruction counts
    Row 2: Dataset 2 instruction counts
    Columns: Instruction types
    """
    all_instructions = sorted(set(data1["total"].keys()) | set(data2["total"].keys()))
    row1 = []
    row2 = []
    for inst in all_instructions:
        d1count = data1["total"].get(inst, 0)
        d2count = data2["total"].get(inst, 0)
        # drop column if less than 5 for Chi-Squared tests
        if d1count < 5 or d2count < 5:
            if d1count > 30 or d2count > 30:
                raise ValueError("Instruction count disparity greater than 25")
            continue

        row1.append(d1count)
        row2.append(d2count)
    table = [row1, row2]
    try:
        chi2_stat, p_val, dof, expected = chi2_contingency(table)
        print(f"Chi:{chi2_stat}, P:{p_val}, DoF:{dof}")

        effect_size = 0.5  # Large effect
        power = 0.80  # Standard chosen value
        n_samples = GofChisquarePower().solve_power(
            effect_size=effect_size, alpha=ALPHA, power=power, n_bins=(dof + 1)
        )
        print(f"Required Samples: {n_samples}")
    except ValueError as e:
        print(f"Could not calculate Chi-Square: {e}")


def calculate_significances(data1, data2):
    """
    Analyze two datasets via constructing a contingency table and performing Fisher-Exact/Chi-Square
    tests for each instruction on each dataset.

    Contingency table constructed by creating columns for each dataset. Row-1 contains the total
    number of upsets for an instruction type, whereas Row-2 contains the "normal" and "error" cases.
    By constructing a contingency table, we can perform chi2_contingency
    (https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.chi2_contingency.html)
    analysis.
    """
    all_instructions = set(data1["total"].keys()) | set(data2["total"].keys())
    results = []

    # calculate Chi-Squared statistic between instruction types
    for inst in all_instructions:
        vul1 = data1["vulnerable"].get(inst, 0)
        total1 = data1["total"].get(inst, 0)

        vul2 = data2["vulnerable"].get(inst, 0)
        total2 = data2["total"].get(inst, 0)

        # total number of 'non' vulnerable instructions
        diff1 = total1 - vul1
        diff2 = total2 - vul2

        # skip if no data exists for this instruction in one of the models
        if total2 == 0 or total1 == 0:
            continue

        # build contingency table
        table = [[vul1, diff1], [vul2, diff2]]

        try:
            test_used = "Chi-Square"
            chi, p, dof, expected = chi2_contingency(table)

            # if our sample size is below 5, we rely on Fisher-Exact test for better results
            if np.any(expected < 5):
                fisher, p = fisher_exact(table)
                test_used = "Fisher-Exact"

            result = {
                "instruction": inst,
                "rate1": round((vul1 / total1), 3),
                "count1": vul1,
                "rate2": round((vul2 / total2), 3),
                "count2": vul2,
                "p_value": p,
                "test": test_used,
                "significant": p < ALPHA,
            }
            results.append(Result(**result))
        except ValueError:
            # this happens if a row/column is all zeros
            continue

    return results


def calculate_coverage(results: list[Result], total_upset_count: int):
    sig = sum([r.count1 + r.count2 for r in results if r.significant])
    return sig / total_upset_count


def get_instruction_data(filename: str):
    with open(filename) as f:
        loaded_data = json.load(f)

    # json keys used to categorize data
    return {
        "target": loaded_data.get("target", {}),
        "vulnerable": loaded_data.get("vulnerable", {}),
        "total": loaded_data.get("total", {}),
        "unique_vul": loaded_data.get("unique_vul", {}),
        "unique_total": loaded_data.get("unique_total", {}),
    }


if __name__ == "__main__":
    if len(sys.argv) > 2:
        file_paths = sys.argv[1:]
        datafiles = [Datafile(f) for f in file_paths]

        for datafile1, datafile2 in itertools.combinations(datafiles, 2):
            print(f"\n{'='*60}")
            print(f"Comparing: {datafile1.image_name} vs {datafile2.image_name}")
            print(f"{'='*60}")

            significances = calculate_significances(data1=datafile1.data, data2=datafile2.data)

            print("\n--- Dataset Independence ---")
            calculate_dataset_independence(data1=datafile1.data, data2=datafile2.data)

            total_upset_count = sum(datafile1.data["vulnerable"].values()) + sum(
                datafile2.data["vulnerable"].values()
            )
            coverage = calculate_coverage(significances, total_upset_count)
            coverage = coverage * 100  # percent
            print(f"Significance Coverage: {coverage:.3}%")

            print("\n--- Instruction Significances ---")
            print_results(significances, datafile1.image_name, datafile2.image_name)
    else:
        print("Error: No file provided. Usage: python data_analysis.py <filename>")
