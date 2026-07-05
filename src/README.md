# Source Code

The patch mining extraction pipeline is part of the OSCAR platform.

## Main Extraction Script

The primary extraction script is located at:
```
oscar-research-data/scripts/mine_cve_patches.py
```

This script:
1. Fetches advisory data from GitHub Security Advisories (GHSA) via the GitHub API
2. Retrieves fix-commit diffs for each advisory
3. Applies language-aware regex patterns to extract function names from unified diffs
4. Assigns confidence tiers (High/Medium/Low) based on function count

## Supported Languages

| Language | Regex Pattern | Extracts |
|---|---|---|
| JavaScript | `function\s+(\w+)`, `(\w+)\s*[=:]\s*(function\|async\s+function\|\([^)]*\)\s*=>)` | Named functions, arrow functions, method definitions |
| Python | `def\s+(\w+)` | Function and method definitions |
| Java | `(public\|private\|protected)\s+.*\s+(\w+)\s*\(` | Method definitions with access modifiers |

## Dependencies

- Python 3.9+
- `requests` library (for GitHub API calls)
- A GitHub personal access token (for rate limiting)

## Usage

```bash
# Set GitHub token
export GITHUB_TOKEN=<your-token>

# Run extraction on GHSA advisories (npm + PyPI)
python oscar-research-data/scripts/mine_cve_patches.py \
    --ecosystem npm pypi \
    --output data/ghsa_js_python_extraction.csv

# Run extraction on Project KB entries
python evaluation/scored_evaluation.py \
    --kb-path <path-to-project-kb-statements> \
    --output data/project_kb_java_extraction.csv
```

## Repository Structure

```
oscar-patch-mining/
├── README.md                    # Project overview
├── requirements.txt             # Python dependencies
├── data/                        # Extracted datasets
│   ├── README.md                # Data documentation
│   ├── ghsa_js_python_extraction.csv
│   ├── ghsa_study1_precision_corpus.csv
│   ├── project_kb_java_extraction.csv
│   └── project_kb_validation_summary.txt
├── evaluation/                  # Evaluation scripts and results
│   ├── scored_evaluation.py     # Project KB extraction + evaluation
│   ├── generate_validation_samples.py
│   ├── verify_verdicts.py
│   ├── precision_validation_samples.csv  # n=50 JS/Python verdicts
│   ├── java_precision_validation.csv     # n=20 Java verdicts
│   └── scored_evaluation_summary.txt
└── src/                         # Source documentation
    └── README.md                # This file
```
