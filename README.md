# Patch Mining — Replication Package

**From Fix Commits to Vulnerable Functions: Automated Patch Mining for Function-Level CVE Resolution**

Submitted to SCORED 2026 (ACM Workshop on Software Supply Chain Offensive Research and Ecosystem Defenses).

## Overview

This repository contains the replication package for our patch mining technique that extracts function-level vulnerability data from fix commits linked to GitHub Security Advisories (GHSA) and SAP Project KB.

The dataset spans three ecosystems (JavaScript/npm, Python/PyPI, Java) and contains **49,035 function-level CVE mappings** extracted from **13,668 advisories**.

## Contents

```
data/                          Extracted datasets (GHSA + Project KB)
  ghsa_full_npm_extraction.csv    6,780 npm advisories → 8,769 functions
  ghsa_full_pypi_extraction.csv   5,640 PyPI advisories → 32,197 functions
  project_kb_java_extraction.csv  1,248 Java statements → 8,069 functions
  ghsa_study1_precision_corpus.csv  92-advisory precision evaluation frame
  ghsa_js_python_extraction.csv   45-advisory reachability subset
  README.md                       Schema documentation

evaluation/                    Evaluation scripts & labeled data
  REPRODUCIBILITY.md              Full artifact-to-source map
  check_consistency.py            Consistency guard (asserts paper = data)
  noise_filter.py                 Deterministic F1–F5 noise filters
  apply_filters_corpus.py         Corpus-level filter application
  compute_recall.py               Recall estimation (original 20)
  compute_recall_extended.py      Recall estimation (extended 44)
  filter_held_out.py              Held-out Java filter validation
  treesitter_poc.py               Tree-sitter proof-of-concept
  merge_precision_samples.py      Merges raw labels → canonical n=104
  generate_validation_samples.py  Confidence-tier logic (assign_confidence)
  scored_evaluation.py            Project KB extraction & Study 2 summary
  verify_verdicts.py              Precision verdict verification
  ghsa_full_corpus.py             Full GHSA corpus extraction driver
  regenerate_temporal.py          Temporal analysis from real commit dates
  precision_validation_samples.csv      Raw labels (batch 1, n=50)
  precision_validation_samples_extra.csv  Raw labels (batch 2, n=55)
  precision_validation_samples_n104.csv   Canonical merged labels (n=104)
  java_precision_validation.csv   Java cross-validation labels (n=20)
  irr_coding_sheet.csv            Inter-rater reliability coding (15 samples)
  recall_study_samples.csv        Recall ground-truth (original 20)
  recall_study_samples_extended.csv  Recall ground-truth (extended 44)
  recall_study_results.json       Recall computation output
  filter_held_out_results.json    Held-out filter results
  treesitter_poc/results.json     Tree-sitter PoC results (18 cases)
  commit_dates_cache.csv          Cached commit dates for temporal analysis

src/                           Pipeline README and helpers
get_funcs.py                   Standalone function extraction utility
requirements.txt               Python dependencies
```

## Quick Start

### Requirements

- Python 3.9+
- Dependencies: `pip install -r requirements.txt`
- A GitHub personal access token (for API rate limits): `export GITHUB_TOKEN=<your-token>`

### Reproducing the Evaluation

See [`evaluation/REPRODUCIBILITY.md`](evaluation/REPRODUCIBILITY.md) for the full artifact-to-source map.

```bash
cd evaluation

# 1. Rebuild the canonical n=104 precision set
python3 merge_precision_samples.py

# 2. Apply noise filters to the corpus
python3 apply_filters_corpus.py

# 3. Compute recall estimates (extended, n=44)
python3 compute_recall_extended.py

# 4. Run the consistency guard (exit 0 = paper matches data)
python3 check_consistency.py
```

### Reproducing the Extraction

The extraction pipeline is part of a companion repository. To run from scratch:

```bash
# Clone the research data repo (anonymized URL for review)
git clone https://github.com/ANONYMIZED/ANONYMIZED.git

# Run the patch mining pipeline on GHSA advisories
python oscar-research-data/scripts/mine_cve_patches.py --ecosystem npm pypi

# Run on Project KB entries
python evaluation/scored_evaluation.py --source project-kb
```

## Key Results

| Study | Corpus | Advisories | Extraction Rate | Functions |
|---|---|---|---|---|
| Study 1 (Precision) | GHSA (npm + PyPI) | 92 | 69% yield | 3,648 |
| Study 2 (Coverage — Java) | Project KB | 1,248 | 86.0% | 8,069 |
| Study 2 (Coverage — npm) | GHSA | 6,780 | 49.9% | 8,769 |
| Study 2 (Coverage — PyPI) | GHSA | 5,640 | 83.0% | 32,197 |

**Precision** (n=104 JS/Python, n=20 Java cross-validation):
- Strict: 55.8% (JS/Python), 55.0% (Java)
- Relaxed: 75.0% (JS/Python), 75.0% (Java)
- **Post-filter**: 72.5% strict, 95.0% relaxed (zero Central false positives)

**Recall** (n=44 advisories):
- At-least-one: 56.8%
- Aggregate: 28.1%

## Citation

If you use this dataset or technique, please cite:

```bibtex
@inproceedings{anon2026patchmining,
  author    = {Anonymous},
  title     = {From Fix Commits to Vulnerable Functions: Automated Patch Mining for Function-Level {CVE} Resolution},
  booktitle = {Proc. SCORED '26},
  publisher = {ACM},
  year      = {2026},
}
```

## License

This replication package is provided for research purposes under the MIT License.
