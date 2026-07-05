# OSCAR Patch Mining — Replication Package

**From Fix Commits to Vulnerable Functions: Automated Patch Mining for Function-Level CVE Resolution**

Submitted to SCORED 2026 (ACM Workshop on Software Supply Chain Offensive Research and Ecosystem Defenses).

## Overview

This repository contains the replication package for our patch mining technique that extracts function-level vulnerability data from fix commits linked to GitHub Security Advisories (GHSA) and SAP Project KB.

## Contents

- `data/` — All extracted datasets (GHSA + Project KB) with schemas and statistics
- `evaluation/` — Precision validation samples, evaluation scripts, and summary reports
- `src/` — Extraction pipeline and helper scripts

## Quick Start

### Requirements

- Python 3.9+
- Dependencies: `pip install -r requirements.txt`
- A GitHub personal access token (for API rate limits): `export GITHUB_TOKEN=<your-token>`

### Reproducing the Evaluation

```bash
# 1. Verify data consistency
python evaluation/scored_evaluation.py

# 2. Reproduce precision validation sampling
python evaluation/generate_validation_samples.py

# 3. Verify precision verdicts against commit diffs
python evaluation/verify_verdicts.py
```

### Reproducing the Extraction

The extraction pipeline is part of the [OSCAR platform](https://github.com/fabiangonzalez/oscar-research-data). To run from scratch:

```bash
# Clone the OSCAR research data repo
git clone https://github.com/fabiangonzalez/oscar-research-data.git

# Run the patch mining pipeline on GHSA advisories
python oscar-research-data/scripts/mine_cve_patches.py --ecosystem npm pypi

# Run on Project KB entries
python evaluation/scored_evaluation.py --source project-kb
```

## Key Results

| Study | Corpus | Advisories | Extraction Rate | Functions |
|---|---|---|---|---|
| Study 1 (Precision) | GHSA (npm + PyPI) | 45 | 69% yield | 133 |
| Study 2 (Coverage) | Project KB (Java) | 1,248 | 86.0% | 8,069 |

Precision (n=50 JS/Python, n=20 Java cross-validation):
- Strict: 60.0% (JS/Python), 55.0% (Java)
- Relaxed: 78.0% (JS/Python), 75.0% (Java)

## Citation

If you use this dataset or technique, please cite:

```bibtex
@inproceedings{gonzalez2026patchmining,
  author    = {Fabian Gonzalez and Rakesh Podder},
  title     = {From Fix Commits to Vulnerable Functions: Automated Patch Mining for Function-Level {CVE} Resolution},
  booktitle = {Proc. SCORED '26},
  publisher = {ACM},
  year      = {2026},
}
```

## License

This replication package is provided for research purposes under the MIT License.
