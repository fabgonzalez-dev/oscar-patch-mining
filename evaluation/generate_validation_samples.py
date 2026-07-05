#!/usr/bin/env python3
"""
SCORED 2026 — Precision Validation Sample Generator
=====================================================
Generates a stratified random sample of function extractions for manual
precision validation. Outputs a CSV spreadsheet template with pre-populated
metadata for each sample.

Usage:
    python evaluation/generate_validation_samples.py [--n 30] [--seed 42]

Output:
    evaluation/precision_validation_samples.csv
"""

import csv
import random
import sys
from pathlib import Path
from collections import defaultdict

# ── Configuration ──
# Primary: local consolidated data directory
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
# Fallback: cross-repo path (legacy)
_LEGACY_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "oscar-research-data" / "data"
OUT_DIR = Path(__file__).resolve().parent
DEFAULT_N = 30
DEFAULT_SEED = 42

# Security-relevant naming patterns (from paper §3.3)
SECURITY_PATTERNS = {
    'parse', 'sanitize', 'validate', 'auth', 'encrypt', 'decrypt',
    'verify', 'sign', 'hash', 'token', 'session', 'permission',
    'access', 'check', 'filter', 'escape', 'encode', 'decode',
    'credential', 'password', 'certificate', 'ssl', 'tls',
}


def assign_confidence(num_functions, num_files, function_name):
    """Assign confidence tier per pipeline logic (paper §3.3).
    
    - High: Single function modified in a single source file
    - Medium: Multiple functions, but one matches security pattern
    - Low: Many functions across multiple files
    """
    name_lower = function_name.lower()
    has_security_match = any(pat in name_lower for pat in SECURITY_PATTERNS)
    
    if num_functions == 1:
        return 'High'
    elif num_functions <= 5 and has_security_match:
        return 'Medium'
    elif num_functions <= 3:
        return 'Medium'
    else:
        return 'Low'


def load_extractions():
    """Load JS/Python extractions for precision validation sampling."""
    # Primary: local Study 1 precision corpus (45 entries)
    csv_path = DATA_DIR / "ghsa_study1_precision_corpus.csv"
    if not csv_path.exists():
        # Fallback: legacy cross-repo path
        csv_path = _LEGACY_DATA_DIR / "cve_patch_analysis.csv"
    if not csv_path.exists():
        print(f"ERROR: No extraction data found")
        sys.exit(1)
    
    all_samples = []
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            functions_str = row.get('functions_mined', '')
            if not functions_str:
                continue
            
            functions = [fn.strip() for fn in functions_str.split(';') if fn.strip()]
            if not functions:
                continue
            
            vuln_id = row['vuln_id']
            package = row['affected_package']
            ecosystem = row['ecosystem']
            severity = row.get('severity', '')
            source_repo = row.get('source_repo', '')
            num_functions = len(functions)
            
            for func in functions:
                confidence = assign_confidence(num_functions, 1, func)
                all_samples.append({
                    'vuln_id': vuln_id,
                    'package': package,
                    'ecosystem': ecosystem,
                    'severity': severity,
                    'function_name': func,
                    'num_functions_in_advisory': num_functions,
                    'confidence': confidence,
                    'source_repo': source_repo,
                    'ghsa_url': f'https://github.com/advisories/{vuln_id}',
                })
    
    return all_samples


def stratified_sample(all_samples, n, seed):
    """Stratified random sampling by confidence tier.
    
    Target distribution: ~40% High, ~40% Medium, ~20% Low
    (adjusted if tiers have insufficient samples)
    """
    random.seed(seed)
    
    by_tier = defaultdict(list)
    for s in all_samples:
        by_tier[s['confidence']].append(s)
    
    # Target allocation
    targets = {'High': int(n * 0.4), 'Medium': int(n * 0.4), 'Low': n - int(n * 0.4) - int(n * 0.4)}
    
    selected = []
    remaining = n
    
    for tier in ['High', 'Medium', 'Low']:
        available = by_tier[tier]
        target = min(targets[tier], len(available))
        sampled = random.sample(available, target)
        selected.extend(sampled)
        remaining -= target
    
    # Fill remaining from any tier
    if remaining > 0:
        already = {(s['vuln_id'], s['function_name']) for s in selected}
        pool = [s for s in all_samples if (s['vuln_id'], s['function_name']) not in already]
        if pool:
            extra = random.sample(pool, min(remaining, len(pool)))
            selected.extend(extra)
    
    random.shuffle(selected)
    return selected


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate precision validation samples")
    parser.add_argument('--n', type=int, default=DEFAULT_N, help='Number of samples to generate')
    parser.add_argument('--seed', type=int, default=DEFAULT_SEED, help='Random seed')
    args = parser.parse_args()
    
    print("=" * 60)
    print("PRECISION VALIDATION SAMPLE GENERATOR")
    print("=" * 60)
    
    all_samples = load_extractions()
    print(f"\n  Total extractable function instances: {len(all_samples)}")
    
    # Count by tier
    by_tier = defaultdict(int)
    for s in all_samples:
        by_tier[s['confidence']] += 1
    
    print(f"  By confidence tier:")
    for tier in ['High', 'Medium', 'Low']:
        print(f"    {tier}: {by_tier[tier]}")
    
    # Sample
    selected = stratified_sample(all_samples, args.n, args.seed)
    print(f"\n  Selected {len(selected)} samples (seed={args.seed})")
    
    # Write CSV
    out_path = OUT_DIR / "precision_validation_samples.csv"
    fieldnames = [
        'sample_id', 'vuln_id', 'package', 'ecosystem', 'severity',
        'function_name', 'num_functions_in_advisory', 'confidence',
        'source_repo', 'ghsa_url',
        # Columns for manual validation (to be filled by human):
        'verdict', 'reasoning',
    ]
    
    with open(out_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i, s in enumerate(selected, 1):
            row = {**s, 'sample_id': i, 'verdict': '', 'reasoning': ''}
            writer.writerow(row)
    
    print(f"\n  Output: {out_path}")
    print(f"\n  Instructions:")
    print(f"    1. Open the CSV in a spreadsheet")
    print(f"    2. For each row, open the ghsa_url")
    print(f"    3. Inspect the fix commit diff")
    print(f"    4. Fill 'verdict' column with: Central | Tangential | Noise")
    print(f"    5. Add brief reasoning")
    print(f"\n  Verdict categories:")
    print(f"    Central    — function is directly modified to fix the vulnerability")
    print(f"    Tangential — function is related but not the primary fix target")
    print(f"    Noise      — false extraction (regex error, non-function match)")
    
    print(f"\n{'=' * 60}")
    print("DONE")
    print(f"{'=' * 60}")


if __name__ == '__main__':
    main()
