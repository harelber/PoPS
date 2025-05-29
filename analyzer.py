from __future__ import division
import os
import sys
import pandas as pd
import argparse
import re

def parse_args():
    """Parse command-line arguments for analysis mode, folder, and noise value."""
    parser = argparse.ArgumentParser(description="Analyze results of POPS.")
    parser.add_argument('--mode', choices=['mal', 'ben'], required=True,
                        help="Choose which type of analysis to run: 'mal' (malicious) or 'ben' (benign)")
    parser.add_argument('--folder', required=True,
                        help="Parent folder containing the result folders (e.g., 'results/')")
    parser.add_argument('--noise', type=int, required=True,
                        help="added noise value (e.g., 0 100 200 500)")
    return parser.parse_args()

def parse_err_file(filepath):
    """Parse the last line of an _err.txt file to extract suspicious and total counts."""
    suspicious, total = 0, 65535
    with open(filepath, "r") as f:
        lines = f.readlines()
        if lines:
            last = lines[-1]
            m = re.search(r'Suspicious:\s*(\d+)\s*;Total:\s*(\d+)', last)
            if m:
                suspicious = int(m.group(1))
                total = int(m.group(2))
    return suspicious, total

def count_lines(filepath):
    """Count the number of lines in a file."""
    with open(filepath, "r") as f:
        return sum(1 for _ in f)

def extract_w_d(base):
    """Extract w and d values from the filename using regex."""
    match = re.search(r'_d(\d+)_w(\d+)', base)
    if match:
        return int(match.group(2)), int(match.group(1))  # w, d
    return None, None

def process_files(mode, folder_to_analyze, noise):
    """
    Process result files in the specified folder.
    For 'ben' mode: combine suspicious counts from _err.txt and line counts from main files.
    For 'mal' mode: count malicious and noise packets based on content.
    """
    if not os.path.exists(folder_to_analyze):
        print(f"Folder {folder_to_analyze} does not exist.")
        sys.exit(1)
    files = [x for x in os.listdir(folder_to_analyze) if x.endswith(".txt")]
    data = []

    if mode == "ben":
        # Map files by base name (without _err.txt or .txt)
        file_map = {}
        for f in files:
            base = f[:-8] if f.endswith("_err.txt") else f[:-4]
            file_map.setdefault(base, {})["err" if f.endswith("_err.txt") else "main"] = f

        # For each base, combine suspicious and line counts
        for base, pair in file_map.items():
            w, d = extract_w_d(base)
            if w is None or d is None:
                continue
            suspicious, total = 0, 65535
            x = 0
            if "err" in pair:
                suspicious, total = parse_err_file(os.path.join(folder_to_analyze, pair["err"]))
            if "main" in pair:
                x = count_lines(os.path.join(folder_to_analyze, pair["main"]))
            # Store results: [w, d, original, total, suspicious+lines, 0]
            data.append([w, d, 65535, total, suspicious + x, 0])
    else:
        # For malicious mode, scan each file for attack indicators and count packets
        for f in files:
            if not f:
                continue
            w, d = extract_w_d(f)
            if w is None or d is None:
                continue
            noise_pacs = 0
            malicious_pacs = 0
            path = os.path.join(folder_to_analyze, f)
            with open(path, "r") as r:
                con = r.readlines()
            scan_lines = con[:100]
            # Skip files with fragmentation or out-of-bailiwick attack indicators
            if any("first fragment - another optional attack vector" in line for line in scan_lines):
                print(f"Fragmentation attack detected in file: {f}")
                continue
            if any("Out of bailiwich packet" in line for line in scan_lines):
                print(f"Out-of-Bailiwick attack detected in file: {f}")
                continue
            # Count malicious and noise packets
            for line in con[2:]:
                if not "Too popular domain" in line:
                    continue
                if ".example.com" in line:
                    malicious_pacs += 1
                else:
                    noise_pacs += 1
            # Store results: [w, d, original, noise, malicious, benign]
            data.append([w, d, 65535, noise, malicious_pacs, noise_pacs])

    # Aggregate results into a DataFrame and compute metrics
    if data:
        df = pd.DataFrame(data, columns=['W', 'D', 'ORIGINAL', 'Total_Benign', 'Malicious_Found', 'Benign_Found'])
        df['FP'] = df['Benign_Found'] / df['Total_Benign']
        df['Success'] = 1 - (df['Malicious_Found'] / df['ORIGINAL'])
        return df
    return pd.DataFrame()

def main():
    args = parse_args()
    merged_df = process_files(args.mode, args.folder, args.noise)
    if merged_df.empty:
        print("No data found for the specified parameters.")
        return
    print(f"\nMerged DataFrame, mode is {args.mode}, {args.noise}:")
    print(merged_df)

if __name__ == "__main__":
    main()