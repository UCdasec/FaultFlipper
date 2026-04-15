#!/usr/bin/python

from dataclasses import dataclass
import sys
import json
import os
from collections import defaultdict

from tabulate import tabulate
from scipy.stats import chi2_contingency, fisher_exact
import pandas as pd
import numpy as np


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
        table_data.append([
            r.instruction,
            f"{r.rate1} ({r.count1})",
            f"{r.rate2} ({r.count2})",
            f"{r.p_value:.4e}",
            r.test,
            "Yes" if r.significant else "No"
        ])

    headers = ["Instruction", f"{image1} Rate", f"{image2} Rate", "P-Value", "Test", "Sig?"]
    
    print(tabulate(table_data, headers=headers, tablefmt="pretty", stralign="right"))
    # print latex formatting
    #print(tabulate(table_data, headers=headers, tablefmt="latex", stralign="right"))

    return
    # 1. Calculate dynamic width for the 'Instruction' column
    # Find the longest instruction name, but ensure it's at least 15
    max_instr = max([len(r.instruction) for r in results] + [len("Instruction")])
    instr_w = max_instr + 2 # Add some breathing room
    
    rate_w = 20
    p_val_w = 12
    test_w = 15
    sig_w = 12

    # 2. Build the Header
    header = (
        f"{'Instruction':<{instr_w}}"
        f"{f'{image1} (Rate)':>{rate_w}}"
        f"{f'{image2} (Rate)':>{rate_w}}"
        f"{'P-Value':>{p_val_w}}"
        f"{'Test Used':^{test_w}}"
        f"{'Significant':>{sig_w}}"
    )
    
    print("\n" + header)
    print("-" * len(header))

    # 3. Print Rows
    for r in results:
        sig_text = "yes" if r.significant else "no"
        
        # Combine rate and count into one string first to align them as a unit
        r1_str = f"{r.rate1:.3f} ({r.count1})"
        r2_str = f"{r.rate2:.3f} ({r.count2})"

        print(
            f"{r.instruction:<{instr_w}}"
            f"{r1_str:>{rate_w}}"
            f"{r2_str:>{rate_w}}"
            f"{r.p_value:>{p_val_w}.4e}"
            f"{r.test:^{test_w}}"
            f"{sig_text:>{sig_w}}"
        )


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
                "rate1": round((vul1/total1), 3),
                "count1": vul1,
                "rate2": round((vul2/total2), 3),
                "count2": vul2,
                "p_value": p,
                "test": test_used,
                "significant": p < 0.05,
            }
            results.append(Result(**result))
        except ValueError:
            # this happens if a row/column is all zeros
            continue

    return results


def calculate_coverage(results: list[Result], total_upset_count: int):
    sig = sum([r.count1 + r.count2 for r in results if r.significant])
    return sig/total_upset_count


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

        datafile1 = Datafile(file1) 
        datafile2 = Datafile(file2) 

        significances = calculate_significances(data1=datafile1.data, data2=datafile2.data)

        total_upset_count = sum(datafile1.data["vulnerable"].values()) + sum(datafile2.data["vulnerable"].values())
        coverage = calculate_coverage(significances, total_upset_count)
        coverage = coverage * 100 # percent
        print(f"Significance Coverage: {coverage:.3}%")

        print_results(significances, datafile1.image_name, datafile2.image_name)
    else:
        print("Error: No file provided. Usage: python data_analysis.py <filename>")
