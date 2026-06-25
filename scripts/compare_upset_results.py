import argparse
import csv
from collections import defaultdict


def compare_csv_upsets(baseline_csv_path, comparison_csv_path, addr_col):
    baseline_upsets = {}
    baseline_counts = defaultdict(int) # Fallback counter just in case
    
    # Step 1: Read the baseline CSV and find all addresses with a valid upset
    # (An upset is now defined as total_correct == "0" AND total_failed != "1")
    with open(baseline_csv_path, encoding="utf-8") as f1:
        reader = csv.DictReader(f1)
        for row in reader:
            addr = row.get(addr_col)
            if addr is None:
                continue  
                
            # Use flipped_index if it exists, otherwise fallback to sequential counting
            f_index = row.get("flipped_index")
            if f_index is not None:
                key = (addr, f_index)
            else:
                key = (addr, baseline_counts[addr])
                baseline_counts[addr] += 1
            
            correct = row.get("total_correct")
            failed = row.get("total_failed")
            
            # Filter out crashes/failures (failed == "1")
            if correct == "0" and failed != "1":
                baseline_upsets[key] = failed
                
    matching_upsets = 0
    differing_upsets = 0
    missing_in_csv2 = 0
    
    failed_diff_in_differing = 0
    failed_diff_in_matching = 0
    
    # Step 2: Read the comparison CSV and map its addresses to their results
    csv2_data = {}
    csv2_counts = defaultdict(int) # Fallback counter just in case
    
    with open(comparison_csv_path, encoding="utf-8") as f2:
        reader = csv.DictReader(f2)
        for row in reader:
            addr = row.get(addr_col)
            if addr is None:
                continue
                
            f_index = row.get("flipped_index")
            if f_index is not None:
                key = (addr, f_index)
            else:
                key = (addr, csv2_counts[addr])
                csv2_counts[addr] += 1
            
            csv2_data[key] = {
                "total_correct": row.get("total_correct"),
                "total_failed": row.get("total_failed")
            }
            
    # Step 3: Compare the baseline upsets against the comparison data
    for key, csv1_failed in baseline_upsets.items():
        if key in csv2_data:
            csv2_correct = csv2_data[key]["total_correct"]
            csv2_failed = csv2_data[key]["total_failed"]
            
            # It only remains a matching upset if it ALSO isn't failing in CSV 2
            if csv2_correct == "0" and csv2_failed != "1":
                matching_upsets += 1
                if csv1_failed != csv2_failed:
                    failed_diff_in_matching += 1
            else:
                differing_upsets += 1
                if csv1_failed != csv2_failed:
                    failed_diff_in_differing += 1
        else:
            missing_in_csv2 += 1
            
    # Step 4: Output the results
    print(f"--- Upset Comparison Results ({addr_col}) ---")
    print(f"Total True Upsets in Baseline (CSV 1): {len(baseline_upsets)}")
    print(f"Matching Upsets (Upset in CSV 1 -> Upset in CSV 2): {matching_upsets}")
    print(f"Differing Upsets (Upset in CSV 1 -> No Upset / Crash in CSV 2): {differing_upsets}")
    
    if differing_upsets > 0:
        print("\n--- Total Failed Column Analysis ---")
        print(f"For the {differing_upsets} addresses where the upset status changed:")
        print(f"  - 'total_failed' column ALSO differed: {failed_diff_in_differing}")
        print(f"  - 'total_failed' column stayed the SAME: {differing_upsets - failed_diff_in_differing}")
        
        if failed_diff_in_matching > 0:
            print(f"\nNote: Out of the {matching_upsets} matching upsets, 'total_failed' changed in {failed_diff_in_matching} rows.")
            
    if missing_in_csv2 > 0:
        print(f"\nAddresses missing in CSV 2 entirely: {missing_in_csv2}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process either CSV and compare upset results."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-c",
        "--csv",
        nargs=2,
        help="List of two CSV files: baseline and comparison",
    )

    parser.add_argument(
        "-a",
        "--addr-col",
        choices=["nopped_addr", "flipped_addr"],
        default="nopped_addr",
        help="Which address column to evaluate (default: nopped_addr)"
    )

    args = parser.parse_args()
    compare_csv_upsets(args.csv[0], args.csv[1], args.addr_col)
