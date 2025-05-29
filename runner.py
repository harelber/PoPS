w_vals = [100, 200, 500]  # w values to check with cms
d_vals = [2, 3, 4, 5]     # d values to check with cms

import os
import subprocess
import sys
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Generalized runner for POPS Experiments")
parser.add_argument('--base', required=True, help='Directory containing pcap files or subfolders')
parser.add_argument('--output', required=True, help='Directory to save output files')
parser.add_argument('--ip', required=True, help='IP address to use in the Go command')
args = parser.parse_args()

os.makedirs(args.output, exist_ok=True)  # Ensure output directory exists

for w_val in w_vals:
    for d in d_vals:
        # Walk through base_directory and process pcap files
        for subdir, _, files in os.walk(args.base):
            for file in files:
                if file.endswith('.pcap'):
                    pcap_path = os.path.join(subdir, file)
                    # Create a subdirectory for each pcap file (without extension)
                    pcap_dir_name = os.path.splitext(file)[0]
                    pcap_output_dir = os.path.join(args.output, pcap_dir_name)
                    os.makedirs(pcap_output_dir, exist_ok=True)

                    # Output filenames inside the pcap-specific directory
                    base_filename = f"{pcap_dir_name}_d{d}_w{w_val}"
                    output_filename = os.path.join(pcap_output_dir, f"{base_filename}.txt")
                    error_filename = os.path.join(pcap_output_dir, f"{base_filename}_err.txt")
                    command = f"go run . -r {pcap_path} -d {args.ip} -h {d} -c {w_val}"

                    # Run the Go command and save output/error
                    with open(output_filename, 'w') as output_file, open(error_filename, 'w') as error_file:
                        subprocess.run(command, shell=True, stdout=output_file, stderr=error_file)

                    print(f"Processed {pcap_path} and output saved to {output_filename}")