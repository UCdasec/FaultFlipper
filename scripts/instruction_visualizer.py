#!/bin/python3

import argparse
import json
import os
import sys

import matplotlib.pyplot as plt
import pandas as pd

plt.style.use("dark_background")


def plot_instruction_percentage(df):
    total_sum = df["Count"].sum()

    df_sorted = df.sort_values(by="Count", ascending=False).reset_index(drop=True)

    # only plot top 20 most common instructions
    top_20 = df_sorted.head(20).copy()
    others = df_sorted.iloc[20:]

    if not others.empty:
        others_row = pd.DataFrame(
            {
                "Instruction": [f"Others ({len(others)} items)"],
                "Count": [others["Count"].sum()],
            }
        )
        plot_df = pd.concat([top_20, others_row], ignore_index=True)
    else:
        plot_df = top_20

    plot_df = plot_df.iloc[::-1]

    plt.figure(figsize=(12, 8))
    bars = plt.barh(
        plot_df["Instruction"], plot_df["Count"], color="skyblue", edgecolor="navy"
    )

    # add percentage labels on top of each bar
    for bar in bars:
        width = bar.get_width()
        percentage = (width / total_sum) * 100
        plt.text(
            width + (plot_df["Count"].max() * 0.01),
            bar.get_y() + bar.get_height() / 2,
            f"{percentage:.1f}%",
            va="center",
            fontsize=9,
        )

    plt.xlabel("Count", fontsize=12)
    plt.ylabel("Instruction", fontsize=12)
    plt.title("Top 20 Instructions by Frequency", fontsize=16, pad=20)
    plt.grid(axis="x", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig("instruction_percentages.png")
    plt.close()


def plot_upset_prob(vulnerable, unique_vulnerable):
    vulnerable = vulnerable.sort_values(by="Count", ascending=False)
    unique_vulnerable = unique_vulnerable.sort_values(by="Count", ascending=False)

    # Get top 20
    vulnerable = vulnerable.head(20)
    unique_vulnerable = unique_vulnerable.head(20)

    # Create subplots (2 rows, 1 column)
    _, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 12))

    # --- Plot 1: Vulnerable Instructions ---
    vul_sum = vulnerable["Count"].sum()
    bars1 = ax1.bar(
        vulnerable["Instruction"],
        vulnerable["Count"],
        color="skyblue",
        edgecolor="navy",
    )

    # Add percentage labels
    for bar in bars1:
        height = bar.get_height()
        percentage = (height / vul_sum) * 100 if vul_sum > 0 else 0
        ax1.text(
            bar.get_x() + bar.get_width() / 2.0,
            height,
            f"{percentage:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    ax1.margins(y=0.05)
    ax1.set_xlabel("Instruction", fontsize=12)
    ax1.set_ylabel("Count", fontsize=12)
    ax1.set_title("Upset Probability (Multiple Mutation)", fontsize=16)
    ax1.tick_params(axis="x", rotation=45)

    # --- Plot 2: Unique Vulnerable Instructions ---
    uniq_sum = unique_vulnerable["Count"].sum()
    bars2 = ax2.bar(
        unique_vulnerable["Instruction"],
        unique_vulnerable["Count"],
        color="lightgreen",
        edgecolor="darkgreen",
    )

    # Add percentage labels
    for bar in bars2:
        height = bar.get_height()
        percentage = (height / uniq_sum) * 100 if uniq_sum > 0 else 0
        ax2.text(
            bar.get_x() + bar.get_width() / 2.0,
            height,
            f"{percentage:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    ax2.margins(y=0.05)
    ax2.set_xlabel("Instruction", fontsize=12)
    ax2.set_ylabel("Count", fontsize=12)
    ax2.set_title("Upset Probability (Unique Instruction)", fontsize=16)
    ax2.tick_params(axis="x", rotation=45)

    plt.tight_layout()
    plt.savefig("upset_probability.png")
    plt.close()


def plot_MMR(vul_df, total_df):
    merged_df = pd.merge(
        total_df.rename(columns={"Count": "Total_Count"}),
        vul_df.rename(columns={"Count": "Vul_Count"}),
        on="Instruction",
        how="left",
    )
    merged_df["Vul_Count"] = merged_df["Vul_Count"].fillna(0)
    merged_df["Vul_Rate"] = (merged_df["Vul_Count"] / merged_df["Total_Count"]) * 100
    merged_df = merged_df.sort_values(by="Vul_Rate", ascending=False).head(20)

    plt.figure(figsize=(10, 6))
    bars = plt.bar(
        merged_df["Instruction"],
        merged_df["Vul_Rate"],
        color="skyblue",
        edgecolor="navy",
    )

    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height,
            f"{height:.3g}%",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    plt.xlabel("Instruction", fontsize=12)
    plt.ylabel("Percentage", fontsize=12)
    plt.title("Multiple Mutation Ratio", fontsize=16)
    plt.grid(axis="y", linestyle="--", alpha=0.6)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("MMR.png")
    plt.close()


def plot_UIR(vul_df, unique_df):
    merged_df = pd.merge(
        unique_df.rename(columns={"Count": "Total_Count"}),
        vul_df.rename(columns={"Count": "Vul_Count"}),
        on="Instruction",
        how="left",
    )
    merged_df["Vul_Count"] = merged_df["Vul_Count"].fillna(0)
    merged_df["Vul_Rate"] = (merged_df["Vul_Count"] / merged_df["Total_Count"]) * 100
    merged_df = merged_df.sort_values(by="Vul_Rate", ascending=False).head(20)

    plt.figure(figsize=(10, 6))
    bars = plt.bar(
        merged_df["Instruction"],
        merged_df["Vul_Rate"],
        color="skyblue",
        edgecolor="navy",
    )

    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height,
            f"{height:.3g}%",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    plt.xlabel("Instruction", fontsize=12)
    plt.ylabel("Percentage", fontsize=12)
    plt.title("Unique Instruction Ratio", fontsize=16)
    plt.grid(axis="y", linestyle="--", alpha=0.6)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("UIR.png")
    plt.close()


def visualize(filename: str):
    with open(filename) as f:
        loaded_data = json.load(f)

    vul_dict = loaded_data.get("vulnerable", {})
    total_dict = loaded_data.get("total", {})
    unique_vul_dict = loaded_data.get("unique_vul", {})
    unique_total_dict = loaded_data.get("unique_total", {})

    create_df = lambda dictionary: pd.DataFrame(
        list(dictionary.items()), columns=["Instruction", "Count"]
    )

    vul_df = create_df(vul_dict)
    total_df = create_df(total_dict)
    unique_total_df = create_df(unique_total_dict)
    unique_vul_df = create_df(unique_vul_dict)

    plot_instruction_percentage(unique_total_df)
    plot_upset_prob(vul_df, unique_vul_df)
    plot_MMR(vul_df, total_df)
    plot_UIR(unique_vul_df, unique_total_df)


def plot_marked_instructions(csv_files, output_filename="marked_instructions_comparison.png"):
    """
    Parses multiple CSV files and creates a stacked event plot of marked instructions.
    
    Args:
        csv_files (list of str): List of file paths to the CSV files.
        output_filename (str): Name of the file to save the resulting plot.
    """
    all_marked_indices = []
    labels = []

    for file in csv_files:
        try:
            # Read the CSV. Assuming no header. If there is a header, add header=0
            # We use usecols=[4] to load only the 5th column to save memory and time
            df = pd.read_csv(file, header=None, usecols=[4])

            # The 5th column is at index 4. Find row indices where the value is 0
            marked_indices = df.index[df.iloc[:, 0] == 0].tolist()
            all_marked_indices.append(marked_indices)

            # Use the filename as the label for the y-axis
            labels.append(os.path.basename(file))

        except Exception as e:
            print(f"Error processing {file}: {e}")

    if not all_marked_indices:
        print("No data to plot.")
        return

    # Create the plot
    # A larger figure size helps when dealing with up to 120k instructions
    fig, ax = plt.subplots(figsize=(15, max(4, len(csv_files) * 0.8)))

    # Create the event plot
    # lineoffsets dictate the y-axis position of each program's row
    # linelengths dictate the height of the tick marks
    # linewidths are kept small (e.g., 0.5) to prevent overlapping in dense regions
    colors = plt.cm.tab10.colors # Use distinct colors for different programs
    ax.eventplot(
        all_marked_indices, 
        orientation="horizontal", 
        linelengths=0.7, 
        linewidths=0.5,
        colors=[colors[i % len(colors)] for i in range(len(csv_files))]
    )
    # Formatting the graph
    ax.set_title("Comparison of Marked Assembly Instructions")
    ax.set_xlabel("Instruction Index")
    ax.set_ylabel("Program")
    # Set y-ticks to match the files
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)
    # Optional: Set x-axis limit based on the maximum instruction index across all files
    max_index = max([max(indices) if indices else 0 for indices in all_marked_indices])
    ax.set_xlim(-1000, max_index + 1000)
    plt.tight_layout()
    # Save the figure instead of showing it directly
    plt.savefig(output_filename, dpi=300)
    print(f"Plot saved successfully to {output_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process either CSV results OR Upset results."
    )

    # Create a mutually exclusive group and make it required
    group = parser.add_mutually_exclusive_group(required=True)

    # Add the flags to the group instead of the main parser
    group.add_argument(
        "-u",
        "--upsets",
        help="List of one or more Upset files",
    )

    group.add_argument(
        "-c",
        "--csv",
        nargs="+",  # Requires 1 or more CSV files
        help="List of one or more CSV files",
    )

    try:
        args = parser.parse_args()
    except SystemExit:
        sys.exit(0)

    if args.csv:
        visualize(args.csv)
    elif args.upsets:
        plot_marked_instructions(args.upsets)

