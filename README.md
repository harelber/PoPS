# PoPS
This repository is the implementation of "POPS: From History to Mitigation of DNS Cache Poisoning Attacks", to be presented in Usenix Security 25'.

This repository implements the mitigation of cache poisoning attacks, using TC Flag.

## 📁 File Structure

| File | Description |
|------|-------------|
| `main.go` | Core logic: reads packets, filters, batches, and enforces all rules |
| `cms_rule.go` | Implements Count-Min Sketch logic for statistical attacks and fragmentation attack detection |
| `bailiwick_rule.go` | Implements deteciton of out-of-bailiwick attacks |

## ⚙️ Installation

```bash
git clone https://github.com/harelber/PoPS.git
cd PoPS
go mod tidy
go build

