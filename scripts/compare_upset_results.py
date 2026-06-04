import argparse
import csv


def compare_csv_upsets(baseline_csv_path, comparison_csv_path):
    baseline_upsets = set()

    # Step 1: Read the baseline CSV and find all addresses with an upset (0)
    with open(baseline_csv_path, encoding="utf-8") as f1:
        reader = csv.DictReader(f1)
        for row in reader:
            # We treat '0' as an upset based on your rules
            if row.get("total_correct") == "0":
                baseline_upsets.add(row.get("nopped_addr"))

    matching_upsets = 0
    differing_upsets = 0
    missing_in_csv2 = 0

    # Step 2: Read the comparison CSV and map its addresses to their results
    csv2_data = {}
    with open(comparison_csv_path, encoding="utf-8") as f2:
        reader = csv.DictReader(f2)
        for row in reader:
            csv2_data[row.get("nopped_addr")] = row.get("total_correct")

    # Step 3: Compare the baseline upsets against the comparison data
    for addr in baseline_upsets:
        if addr in csv2_data:
            if csv2_data[addr] == "0":
                matching_upsets += 1
            else:
                # The address was an upset in CSV1, but total_correct is '1' in CSV2
                differing_upsets += 1
        else:
            # Captures edge cases where an address from CSV1 doesn't exist in CSV2
            missing_in_csv2 += 1

    # Step 4: Output the results
    print("--- Upset Comparison Results ---")
    print(f"Total Upsets in Baseline (CSV 1): {len(baseline_upsets)}")
    print(f"Matching Upsets (0 in CSV 1 -> 0 in CSV 2): {matching_upsets}")
    print(f"Differing Upsets (0 in CSV 1 -> 1 in CSV 2): {differing_upsets}")

    if missing_in_csv2 > 0:
        print(f"Addresses missing in CSV 2 entirely: {missing_in_csv2}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process either CSV and compare upset results."
    )

    # Create a mutually exclusive group and make it required
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-c",
        "--csv",
        nargs=2,
        help="List of one or more CSV files",
    )

    args = parser.parse_args()
    compare_csv_upsets(args.csv[0], args.csv[1])

