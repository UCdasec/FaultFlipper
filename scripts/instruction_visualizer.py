#!/bin/python3

import sys
import json
from collections import defaultdict

import pandas as pd
import matplotlib.pyplot as plt


def visualize(filename: str):
    with open(filename, "r") as f:
        loaded_data = json.load(f)

    df = pd.DataFrame(list(loaded_data.items()), columns=["Instruction", "Count"])
    df = df.sort_values(by="Count", ascending=False)

    plt.bar(df["Instruction"], df["Count"], color="skyblue", edgecolor="navy")
    plt.xlabel("Instruction")
    plt.ylabel("Count")
    plt.title("Instruction Frequency")
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save the resulting visualization
    plt.savefig("instruction_histogram.png")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        filename: str = sys.argv[1]
        visualize(filename)
    else:
        print(
            "Error: No file provided. Usage: python instruction_visualizer.py <filename>"
        )
