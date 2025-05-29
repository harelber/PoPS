from __future__ import division
import os
import sys
import pandas as pd
import argparse
import re

def parse_args():
    # Parse command-line arguments for analysis mode, folder, and noise values
    parser = argparse.ArgumentParser(description="Analyze results of POPS.")
    parser.add_argument('--mode', choices=['mal', 'ben'], required=True,
                        help="Choose which type of analysis to run: 'mal' (malicious) or 'ben' (benign)")
    parser.add_argument('--folder', required=True,
                        help="Parent folder containing the result folders (e.g., 'results/')")
    parser.add_argument('--noise', type=int, required=True,
                        help="added noise value (e.g., 0 100 200 500)")
    return parser.parse_args()

def process_files(w_vals, d_vals, mode, folder_to_analyze, noise):
    # Process files in the specified folder based on the provided parameters
    if not os.path.exists(folder_to_analyze):
        print(f"Folder {folder_to_analyze} does not exist.")
        sys.exit(1)
    files = [x for x in os.listdir(folder_to_analyze) if x.endswith(".txt")]
    
    data = []
    for f in files:
        #check file is not blank
        if not f:
            continue
        d=0
        w=0   
        # Extract w_val and d from the filename using regex     
        match = re.search(r'_d(\d+)_w(\d+)', f)
        if match:
            d = int(match.group(1))
            w = int(match.group(2))
        # Initialize counters for each file
        noise_pacs = 0
        malicious_pacs = 0
        path = os.path.join(folder_to_analyze, f)
        with open(path, "r") as r:
            con = r.readlines()

        # Scan for non-statistically evaluated attacks in malicious mode
        if mode == "mal":
            # Only scan the first 100 lines for attack indicators (for efficiency)
            scan_lines = con[:100]
            # Fragmentation attack detection
            if any("first fragment - another optional attack vector" in line for line in scan_lines):
                print(f"Fragmentation attack detected in file: {f}")
                continue  # Skip further processing for this file
            # Out-of-Bailiwick attack detection
            if any("Out of bailiwich packet" in line for line in scan_lines):
                print(f"Out-of-Bailiwick attack detected in file: {f}")
                continue  # Skip further processing for this file
        # Count malicious and noise packets based on line content
        for line in con[2:]:
            if not "Too popular domain" in line:
                continue
            if ".example.com" in line:
                malicious_pacs += 1
            else:
                noise_pacs += 1

        # Append results to data list depending on mode
        if mode == "mal":
            data.append([w, d, 65535, noise, malicious_pacs, noise_pacs])
        elif mode == "ben":
            data.append([w, d, 65535, noise, noise_pacs, malicious_pacs])  # swap for benign
    
    # Aggregate results into a DataFrame and group by ADDED noise
    if data:
        df = pd.DataFrame(data, columns=['W', 'D', 'ORIGINAL', 'ADDED', 'Malicious_Found', 'Benign_Found'])
        df['FP'] = df['Benign_Found'] / df['ADDED']
        df['Success'] = 1 - (df['Malicious_Found'] / df['ORIGINAL'])
    # Merge all DataFrames into one
    return df

def main():
    # Entry point: parse arguments, run processing, and print results
    args = parse_args()
    w_vals = [100, 200, 500]
    d_vals = [2, 3, 4, 5]
    merged_df = process_files(w_vals, d_vals, args.mode, args.folder, args.noise)
    if merged_df.empty:
        print("No data found for the specified parameters.")
        return
    print(f"\nMerged DataFrame, mode is {args.mode}, {args.noise}:")
    print(merged_df)

if __name__ == "__main__":
    main()