# Generators Folder README

This folder contains resources and scripts for generating PCAP files used in DNS security experiments.

---

## domains.txt

Contains a list of domains from [Tranco](https://tranco-list.eu/).  
Used to simulate benign DNS packets for experiments involving interleaved attack and benign traffic.

---

## rl1_exp_gen.py — Statistical Guessing Attack Generator

Generates PCAPs simulating a statistical guessing DNS cache poisoning attack, with interleaved noise.

**Arguments:**
- `--resolver-ip`: IP of the DNS resolver (default: 192.168.1.1)
- `--resolver-mac`: MAC of the resolver (random if not set)
- `--authoritative-ip`: IP of the authoritative DNS server (default: 192.168.1.3)
- `--authoritative-mac`: MAC of the authoritative server (random if not set)
- `--client-ip`: IP of the client (default: 192.168.1.2)
- `--client-mac`: MAC of the client (random if not set)
- `--target-domain`: Target domain for the attack (default: example.com)
- `--fake-ip`: Fake IP for spoofed responses (default: 6.6.6.6)
- `--num-queries`: Number of DNS queries to send (default: 1)
- `--s-per-query`: Number of spoofed responses per query (default: 65535)
- `--noise`: Number of noise packets per query (default: 1000)
- `--out`: Output directory for the pcap file (default: ../attack_pcaps)

---

## rl2_exp_gen.py — Fragmentation Attack Generator

Generates a fragmented DNS response to simulate fragmentation-based attacks.

**Arguments:**
- `--dst`: Destination IP (resolver IP, default: 192.168.1.1)
- `--pcap`: Output PCAP file path (default: ../attack_pcaps/frag.pcap)
- `--domain`: Domain name for the DNS response (default: example.com)
- `--rdata`: IP address for the DNS answer (A record, default: 93.184.216.34)

---

## rl3_exp_gen.py — Out-of-Bailiwick Attack Generator

Generates a PCAP simulating an out-of-bailiwick DNS attack.

**Arguments:**
- `--resolver-ip`: IP of the DNS resolver (default: 192.168.1.1)
- `--resolver-mac`: MAC of the resolver (random if not set)
- `--authoritative-ip`: IP of the authoritative DNS server (default: 192.168.1.2)
- `--authoritative-mac`: MAC of the authoritative server (random if not set)
- `--domain`: Domain name to query (default: example.com)
- `--output`: Output PCAP file name (default: ../attack_pcaps/out_of_bailiwick.pcap)
- `--oob`: Out-of-bailiwick domain (default: ns.abc.com)

---

## CVE-2008-1146_gen.py — CVE Attack Generators

Generate PCAPs for specific DNS cache poisoning CVE, which includes improper port randomization of using only 10 bits of randomaization.  
You can control all relevant parameters via command-line arguments.

**Arguments:**
- `--resolver-ip`: IP address of the DNS resolver (default: 192.168.1.1)
- `--resolver-mac`: MAC address of the resolver (random if not set)
- `--authoritative-ip`: IP address of the authoritative DNS server (default: 192.168.1.3)
- `--authoritative-mac`: MAC address of the authoritative server (random if not set)
- `--client-ip`: IP address of the client (default: 192.168.1.2)
- `--client-mac`: MAC address of the client (random if not set)
- `--target-domain`: Target domain for the attack (default: example.com)
- `--fake-ip`: Fake IP address to use in spoofed responses (default: 6.6.6.6)
- `--num-queries`: Number of DNS queries to send (default: 10)
- `--s-per-query`: Number of spoofed responses per query (default: 10)
- `--noise`: Number of noise packets to add per query (default: 1000)
- `--out`: Output directory for the pcap file (default: ../attack_pcaps)

**Example usage:**
```bash
python CVE-2008-1146_gen.py --num-queries 5 --noise 500 --target-domain victim.com --out ./attack_pcaps
```

---

**Note:**  
All scripts require [Scapy](https://scapy.net/) and, for some, `numpy`. Install dependencies with:

```bash
pip install -r requirements.txt
```