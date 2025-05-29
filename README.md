# PoPS
This repository is the implementation of "POPS: From History to Mitigation of DNS Cache Poisoning Attacks", to be presented in Usenix Security 25'.

This repository implements the mitigation of cache poisoning attacks, using TC Flag.

## 📁 File Structure

| File | Description |
|------|-------------|
| `main.go` | Core logic: reads packets, filters, batches, and enforces all rules |
| `cms_rule.go` | Implements Count-Min Sketch logic for statistical attacks and fragmentation attack detection |
| `bailiwick_rule.go` | Implements deteciton of out-of-bailiwick attacks |
| `runner.py` | Runs PoPS with a pcap file, to detect malicious activity |
| `analyzer.py` | Analyzes the results of `runner.py` |
| `generators` | Folder of sample scripts to generate pcaps |
| `attack_pcaps` | Folder of generated pcaps, from known attacks |

## 📦 Dataset Access
Due to GitHub’s file size limitations, the benign DNS traffic dataset used in this study is too large to host here.
You can download it directly from Mendeley Data:

➡ https://data.mendeley.com/datasets/c4n7fckkz3/3

Place the .pcap files as a folder in the project directory and reference them using the -base flag when running `runner.py`.

## ⚙️ Installation

```bash
git clone https://github.com/harelber/PoPS.git
cd PoPS
go mod tidy
go build

## 📚 Citation
If you use this tool or reference it in academic work, please cite the following paper:
'''
@article{afek2025pops,
  title     = {POPS: From History to Mitigation of DNS Cache Poisoning Attacks},
  author    = {Afek, Yehuda and Berger, Harel and Bremler-Barr, Anat},
  journal   = {arXiv preprint arXiv:2501.13540},
  year      = {2025},
  url       = {https://arxiv.org/abs/2501.13540}
}
'''
