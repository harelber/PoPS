# Generators Folder README

This folder contains resources and scripts for generating PCAP files used in DNS security experiments.

- **domains.txt**:  
  Contains a list of domains from [Tranco](https://tranco-list.eu/).  
  Used to simulate benign DNS packets for experiments involving interleaved attack and benign traffic.

- **rl1_exp_gen.py**:  
  Script for generating PCAP files simulating the statistical guessing DNS cache poisoning attack.

- **rl2_exp_gen.py**:  
  Script for generating PCAP files for DNS fragmentation attacks.

- **rl3_exp_gen.py**:   
  Script for generating PCAP files for out-of-bailiwick attacks.

- **Other PCAP files**:  
  These files correspond to specific CVEs and are used for dedicated vulnerability testing.
