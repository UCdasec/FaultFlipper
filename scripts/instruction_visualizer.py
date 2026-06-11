#!/bin/python3

import argparse
import json
import os
import sys

import matplotlib.pyplot as plt
import pandas as pd

#plt.style.use("dark_background")


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
    Supports both the original single-row-per-instruction format and the new 
    32-indexes-per-address format.
    """
    all_marked_indices = []
<<<<<<< HEAD
    labels = []
    max_instruction_index = 0
=======
    labels = ['image0_lbl7', 'image2_lbl11', 'image7_lbl11', 'image19_lbl6', 'image64_lbl6']
>>>>>>> 27d9bcd (change instr visualizer to BIT)

    for file in csv_files:
        try:
            header_df = pd.read_csv(file, nrows=0)
            
            if "flipped_addr" in header_df.columns:
                # --- NEW FORMAT ---
                df = pd.read_csv(file, usecols=["flipped_addr", "total_failed"])
                
                unique_addrs = df["flipped_addr"].drop_duplicates().tolist()
                addr_to_idx = {addr: idx for idx, addr in enumerate(unique_addrs)}
                
                marked_addrs = df[df["total_failed"] > 0]["flipped_addr"].unique()
                marked_indices = [addr_to_idx[addr] for addr in marked_addrs]
                all_marked_indices.append(marked_indices)
                
            else:
                # --- OLD FORMAT ---
                df = pd.read_csv(file, header=0, usecols=[4])
                marked_indices = df.index[df.iloc[:, 0] == 0].tolist()
                all_marked_indices.append(marked_indices)

<<<<<<< HEAD
            labels.append(os.path.splitext(os.path.basename(file))[0])
=======
            # Use the filename (without extension) as the label for the y-axis
            #labels.append(os.path.splitext(os.path.basename(file))[0])
>>>>>>> 27d9bcd (change instr visualizer to BIT)

            # Track the maximum index to properly bound the x-axis later
            if marked_indices:
                max_instruction_index = max(max_instruction_index, max(marked_indices))

        except Exception as e:
            print(f"Error processing {file}: {e}")

    if not all_marked_indices:
        print("No data to plot.")
        return

    # Create the plot
    fig, ax = plt.subplots(figsize=(15, max(4, len(csv_files) * 0.8)))

    # Explicitly define the y-positions for each row to prevent floating-point interpolation
    y_positions = list(range(len(csv_files)))
    colors = plt.cm.tab10.colors 

    ax.eventplot(
        all_marked_indices, 
        lineoffsets=y_positions, # Lock rows to integer y-coordinates
        orientation="horizontal", 
        linelengths=1.0, 
        linewidths=0.5,
        colors=[colors[i % len(colors)] for i in range(len(csv_files))]
    )
    
    # Formatting the graph
    ax.margins(0)
    ax.set_title("Instruction BIT Upset Comparison")
    ax.set_xlabel("Instruction Index")
    ax.set_ylabel("Image")
    
    # Set y-ticks to explicitly match our calculated integer positions
    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels)
    
    plt.tight_layout()
    
    # Removed pad_inches=0 so the labels aren't chopped off your screen
    plt.savefig(output_filename, bbox_inches="tight", dpi=300)
    plt.close(fig) 
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
        plot_marked_instructions(args.csv)
    elif args.upsets:
        visualize(args.upsets)

