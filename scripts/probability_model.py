#!/usr/bin/python

import sys
import json
import argparse
from enum import Enum

import pandas as pd

from data_analysis import analyze, get_instruction_data


class Metric(Enum):
    MMR = (1,)
    UIR = (2,)
    MultipleMutation = (3,)
    UniqueInstruction = (4,)


def analyze_MMR(data) -> dict:
    create_df = lambda dictionary: pd.DataFrame(
        list(dictionary.items()), columns=["Instruction", "Count"]
    )
    vul = create_df(data["vulnerable"])
    total = create_df(data["total"])
    merged = pd.merge(
        total.rename(columns={"Count": "Total_Count"}),
        vul.rename(columns={"Count": "Vul_Count"}),
        on="Instruction",
        how="left",
    )
    merged["Vul_Count"] = merged["Vul_Count"].fillna(0)
    merged["Vul_Rate"] = merged["Vul_Count"] / merged["Total_Count"]

    return dict(zip(merged["Instruction"], merged["Vul_Rate"]))


def construct_probability_model(data, metric: Metric):
    """
    Construct probability model with selected metric
    """
    if metric == Metric.MMR:
        prob_dict = analyze_MMR(data)

        model_json = {"target": data["target"], "instruction_probabilities": prob_dict}

        with open("probability_model.json", "w") as file:
            json.dump(model_json, file, indent=4)
    else:
        raise Exception("Only MMR currently supported")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create probability model from instruction_count.json files"
    )

    # 'nargs='+' gathers all remaining arguments into a list
    parser.add_argument(
        "files", metavar="F", type=str, nargs="+", help="an integer for the accumulator"
    )

    args = parser.parse_args()
    file_list = args.files

    for file in file_list:
        data = get_instruction_data(file)
        # TODO: verify targets are identical
        # TODO: check to add probabilities only if they are deemed SIGNIFICANT by chi-squared test
        # TODO: combine different instruction files to create single prob. model
        construct_probability_model(data, Metric.MMR)
