import argparse
import csv


def compare_csv_upsets(baseline_csv_path, comparison_csv_path):
    # Map: nopped_addr -> total_failed
    baseline_upsets = {}
    
    # Step 1: Read the baseline CSV and find all addresses with an upset (0)
    with open(baseline_csv_path, encoding="utf-8") as f1:
        reader = csv.DictReader(f1)
        for row in reader:
            if row.get("total_correct") == "0":
                addr = row.get("nopped_addr")
                baseline_upsets[addr] = row.get("total_failed")
                
    matching_upsets = 0
    differing_upsets = 0
    missing_in_csv2 = 0
    
    # Trackers for total_failed differences
    failed_diff_in_differing = 0
    failed_diff_in_matching = 0
    
    # Step 2: Read the comparison CSV and map its addresses to their results
    csv2_data = {}
    with open(comparison_csv_path, encoding="utf-8") as f2:
        reader = csv.DictReader(f2)
        for row in reader:
            addr = row.get("nopped_addr")
            csv2_data[addr] = {
                "total_correct": row.get("total_correct"),
                "total_failed": row.get("total_failed")
            }
            
    # Step 3: Compare the baseline upsets against the comparison data
    for addr, csv1_failed in baseline_upsets.items():
        if addr in csv2_data:
            csv2_correct = csv2_data[addr]["total_correct"]
            csv2_failed = csv2_data[addr]["total_failed"]
            
            if csv2_correct == "0":
                matching_upsets += 1
                if csv1_failed != csv2_failed:
                    failed_diff_in_matching += 1
            else:
                # The address was an upset in CSV 1 (0), but total_correct is '1' in CSV 2
                differing_upsets += 1
                if csv1_failed != csv2_failed:
                    failed_diff_in_differing += 1
        else:
            missing_in_csv2 += 1
            
    # Step 4: Output the results
    print("--- Upset Comparison Results ---")
    print(f"Total Upsets in Baseline (CSV 1): {len(baseline_upsets)}")
    print(f"Matching Upsets (0 in CSV 1 -> 0 in CSV 2): {matching_upsets}")
    print(f"Differing Upsets (0 in CSV 1 -> 1 in CSV 2): {differing_upsets}")
    
    # Condition: If there is a discrepancy/difference in upset behavior
    if differing_upsets > 0:
        print("\n--- Total Failed Column Analysis ---")
        print(f"For the {differing_upsets} addresses where the upset status changed:")
        print(f"  - 'total_failed' column ALSO differed: {failed_diff_in_differing}")
        print(f"  - 'total_failed' column stayed the SAME: {differing_upsets - failed_diff_in_differing}")
        
        # Optional: Extra context if the user wants to see if total_failed changed for matching rows too
        if failed_diff_in_matching > 0:
            print(f"\nNote: Out of the {matching_upsets} matching upsets, 'total_failed' changed in {failed_diff_in_matching} rows.")
            
    if missing_in_csv2 > 0:
        print(f"\nAddresses missing in CSV 2 entirely: {missing_in_csv2}")


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

