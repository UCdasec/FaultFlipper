#!/usr/bin/python

from dataclasses import dataclass
import sys
import json
from collections import defaultdict

from scipy.stats import chi2_contingency, fisher_exact
import pandas as pd
import numpy as np


@dataclass
class Result:
    instruction: str
    rate1: str
    rate2: str
    p_value: float
    test: str
    significant: bool


def print_results(results: list[Result]):
    results.sort(key=lambda x: x.p_value)

    if not results:
        print("No results to display.")
        return

    # define column widths
    instr_w = 15
    rate_w = 12
    p_val_w = 12
    test_w = 15
    sig_w = 12

    header = (
        f"{'Instruction':<{instr_w}} "
        f"{'Rate 1':>{rate_w}} "
        f"{'Rate 2':>{rate_w}} "
        f"{'P-Value':>{p_val_w}} "
        f"{'Test Used':^{test_w}} "
        f"{'Significant':>{sig_w}}"
    )
    print(header)
    print("-" * len(header))

    for r in results:
        sig_text = "Significant★" if r.significant else "Insignificant"

        print(
            f"{r.instruction:<{instr_w}} "
            f"{r.rate1:>{rate_w}} "
            f"{r.rate2:>{rate_w}} "
            f"{r.p_value:>{p_val_w}.4e} "
            f"{r.test:^{test_w}} "
            f"{sig_text:>{sig_w}}"
        )


def analyze(data1, data2):
    all_instructions = set(data1["total"].keys()) | set(data2["total"].keys())
    results = []

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
                "rate1": f"{(vul1/total1):.3%}",
                "rate2": f"{(vul2/total2):.3%}",
                "p_value": p,
                "test": test_used,
                "significant": p < 0.05,
            }
            results.append(Result(**result))
        except ValueError:
            # this happens if a row/column is all zeros
            continue

    return results


def get_instruction_data(filename: str):
    with open(filename, "r") as f:
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
        file1: str = sys.argv[1]
        file2: str = sys.argv[2]
        data1 = get_instruction_data(file1)
        data2 = get_instruction_data(file2)
        results = analyze(data1=data1, data2=data2)
        print_results(results)
    else:
        print(
            "Error: No file provided. Usage: python instruction_visualizer.py <filename>"
        )
