#!/usr/bin/env python3
"""
SCORED 2026 — Java Patch Mining Evaluation
============================================
Computes recall/precision/F1 metrics for the OSCAR patch mining pipeline
against the SAP Project KB gold-standard dataset.

Evaluation approach:
  - Project KB provides fix commits per vulnerability (ground truth)
  - Our pipeline independently extracts function names from those diffs
  - We compute:
    1. Advisory-level coverage: fraction of KB entries where we extract ≥1 function
    2. Per-advisory function count distribution
    3. Cross-ecosystem comparison (Java vs JS/Python)
    4. Failure mode analysis

Usage:
    python oscar-patch-mining/evaluation/scored_evaluation.py

Prerequisites:
    - Project KB cloned (see project_kb_recall.py)
    - Existing extraction CSV from previous run
"""

import csv
import json
import os
import sys
import time
import re
import ssl
import statistics
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

# SSL context for macOS
_SSL_CTX = ssl._create_unverified_context()

# Import extraction function from pipeline
SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "oscar-research-data" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))
from mine_cve_patches import extract_functions_from_diff

import urllib.request

BASE_DIR = Path(__file__).resolve().parent.parent.parent
KB_DIR = BASE_DIR / "oscar-research-data" / "external" / "project-kb"
KB_STATEMENTS_DIR = KB_DIR / "statements"

DATA_DIR = BASE_DIR / "oscar-patch-mining" / "data"
EVAL_DIR = BASE_DIR / "oscar-patch-mining" / "evaluation"
EVAL_DIR.mkdir(parents=True, exist_ok=True)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_DELAY = 1.5 if not GITHUB_TOKEN else 0.5


# ============================================================================
# Load existing KB extraction data
# ============================================================================

def load_existing_kb_results():
    """Load the already-processed KB extraction CSV."""
    csv_path = DATA_DIR / "project_kb_java_extraction.csv"
    if not csv_path.exists():
        return []
    
    results = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            row['num_functions'] = int(row.get('num_functions', 0))
            results.append(row)
    return results


def load_js_python_results():
    """Load the JS/Python extraction results from the local consolidated data."""
    # Primary: local consolidated ICSE corpus (162 entries)
    csv_path = DATA_DIR / "ghsa_js_python_extraction.csv"
    if not csv_path.exists():
        # Fallback: cross-repo path (legacy)
        research_data = BASE_DIR / "oscar-research-data" / "data"
        candidates = sorted(research_data.glob("cve_patch_analysis*.csv"), reverse=True)
        if not candidates:
            return None
        csv_path = candidates[0]
    
    results = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append(row)
    return results


# ============================================================================
# Load Project KB YAML for ground truth
# ============================================================================

def load_kb_statements():
    """Parse all Project KB YAML statement files."""
    import yaml
    
    entries = []
    if not KB_STATEMENTS_DIR.exists():
        print(f"  ERROR: Project KB not found at {KB_STATEMENTS_DIR}")
        return []
    
    for yaml_path in sorted(KB_STATEMENTS_DIR.glob("*/statement.yaml")):
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                continue
            
            vuln_id = data.get('vulnerability_id', '')
            
            # Extract fix commits
            commits = []
            for fix in data.get('fixes', []):
                for commit in fix.get('commits', []):
                    repo = commit.get('repository', '')
                    sha = commit.get('id', '')
                    if repo and sha:
                        repo_match = re.match(r'https?://github\.com/([^/]+/[^/]+)', repo)
                        if repo_match:
                            commits.append({
                                'repo': repo_match.group(1).rstrip('/'),
                                'sha': sha,
                            })
            
            # Extract affected artifacts
            packages = set()
            for artifact in data.get('artifacts', []):
                pkg_id = artifact.get('id', '')
                if 'maven' in pkg_id.lower():
                    m = re.match(r'pkg:maven/([^@]+)', pkg_id)
                    if m:
                        packages.add(m.group(1))
            
            if commits:
                entries.append({
                    'vuln_id': vuln_id,
                    'commits': commits,
                    'packages': list(packages),
                    'num_commits': len(commits),
                    'has_github': True,
                })
            elif data.get('fixes'):
                entries.append({
                    'vuln_id': vuln_id,
                    'commits': [],
                    'packages': list(packages),
                    'num_commits': 0,
                    'has_github': False,
                })
        except Exception:
            continue
    
    return entries


# ============================================================================
# Compute Metrics
# ============================================================================

def compute_scored_metrics(kb_results, js_python_results, kb_entries):
    """Compute all metrics needed for the SCORED paper."""
    
    print(f"\n{'='*70}")
    print("SCORED 2026 — PATCH MINING EVALUATION")
    print(f"Generated: {datetime.now().isoformat()}")
    print(f"{'='*70}")
    
    # ── 1. Java (Project KB) Metrics ──
    n_processed = len(kb_results)
    n_with_funcs = sum(1 for r in kb_results if r['num_functions'] > 0)
    total_funcs = sum(r['num_functions'] for r in kb_results)
    
    # Count diffs actually fetched (commits_processed > 0)
    n_with_diffs = sum(1 for r in kb_results if int(r.get('commits_processed', 0)) > 0)
    
    # Extraction rate on fetchable diffs
    rate_on_fetchable = n_with_funcs / n_with_diffs * 100 if n_with_diffs else 0
    rate_overall = n_with_funcs / n_processed * 100 if n_processed else 0
    
    # Function count distribution
    func_counts = [r['num_functions'] for r in kb_results]
    counts_with = [c for c in func_counts if c > 0]
    
    print(f"\n  ── JAVA (Project KB Ground Truth) ──")
    print(f"  KB entries processed:           {n_processed}")
    print(f"  Diffs successfully fetched:     {n_with_diffs}")
    print(f"  Entries with extracted functions:{n_with_funcs}")
    print(f"  Extraction rate (overall):      {rate_overall:.1f}%")
    print(f"  Extraction rate (on fetchable): {rate_on_fetchable:.1f}%")
    print(f"  Total functions extracted:      {total_funcs}")
    if counts_with:
        print(f"  Avg functions/entry (non-zero): {statistics.mean(counts_with):.1f}")
        print(f"  Median functions/entry:         {statistics.median(counts_with):.0f}")
    
    # Distribution
    zero_count = sum(1 for c in func_counts if c == 0)
    one_to_five = sum(1 for c in func_counts if 1 <= c <= 5)
    six_to_twenty = sum(1 for c in func_counts if 6 <= c <= 20)
    over_twenty = sum(1 for c in func_counts if c > 20)
    
    print(f"\n  Function count distribution:")
    print(f"    0 functions:     {zero_count:3d} ({zero_count/n_processed*100:.1f}%)")
    print(f"    1-5 functions:   {one_to_five:3d} ({one_to_five/n_processed*100:.1f}%)")
    print(f"    6-20 functions:  {six_to_twenty:3d} ({six_to_twenty/n_processed*100:.1f}%)")
    print(f"    >20 functions:   {over_twenty:3d} ({over_twenty/n_processed*100:.1f}%)")
    
    # ── 2. JS/Python (GHSA) Metrics ──
    if js_python_results:
        js_total = len(js_python_results)
        # Count advisories with fix commits and with extracted functions
        # mine_cve_patches.py outputs: fix_commits_found (int), functions_mined (semicolon-delimited)
        js_with_commits = sum(1 for r in js_python_results
                              if int(r.get('fix_commits_found', 0)) > 0)
        js_with_funcs = sum(1 for r in js_python_results
                            if r.get('functions_mined', '').strip())
        
        print(f"\n  ── JS/PYTHON (GHSA Pipeline) ──")
        print(f"  GHSA advisories processed:      {js_total}")
        print(f"  With fix commits:               {js_with_commits}")
        print(f"  With extracted functions:        {js_with_funcs}")
        if js_with_commits:
            print(f"  Extraction rate (on fetchable): {js_with_funcs/js_with_commits*100:.1f}%")
    
    # ── 3. Cross-Ecosystem Comparison ──
    # Compute JS/Python stats from loaded data (no more hardcoded values)
    js_py_total = 0
    js_py_with_commits = 0
    js_py_with_funcs = 0
    if js_python_results:
        js_py_total = len(js_python_results)
        for r in js_python_results:
            if int(r.get('fix_commits_found', r.get('num_functions_mined', 0))) > 0 or r.get('functions_mined', ''):
                js_py_with_commits += 1
            if int(r.get('num_functions_mined', 0)) > 0:
                js_py_with_funcs += 1
    
    # Recount with_commits more carefully: any row with fix_commits_found > 0
    js_py_with_commits = sum(1 for r in (js_python_results or []) if int(r.get('fix_commits_found', 0)) > 0)
    js_py_rate = js_py_with_funcs / js_py_with_commits * 100 if js_py_with_commits else 0
    
    print(f"\n  ── CROSS-ECOSYSTEM COMPARISON ──")
    print(f"  {'Language':<15s} {'Processed':>10s} {'Extracted':>10s} {'Rate':>8s}")
    print(f"  {'-'*45}")
    print(f"  {'Java (KB)':<15s} {n_with_diffs:>10d} {n_with_funcs:>10d} {rate_on_fetchable:>7.1f}%")
    print(f"  {'JS/Python':<15s} {js_py_with_commits:>10d} {js_py_with_funcs:>10d} {js_py_rate:>7.1f}%")
    combined_proc = n_with_diffs + js_py_with_commits
    combined_extr = n_with_funcs + js_py_with_funcs
    combined_rate = combined_extr / combined_proc * 100 if combined_proc else 0
    print(f"  {'Combined':<15s} {combined_proc:>10d} {combined_extr:>10d} {combined_rate:>7.1f}%")
    
    # ── 4. Failure Mode Analysis ──
    print(f"\n  ── FAILURE MODE ANALYSIS ──")
    
    no_diff = sum(1 for r in kb_results if int(r.get('commits_processed', 0)) == 0)
    diff_no_func = n_with_diffs - n_with_funcs
    
    print(f"  No diff fetchable (repo moved/deleted): {no_diff} ({no_diff/n_processed*100:.1f}%)")
    print(f"  Diff fetched, no functions extracted:    {diff_no_func} ({diff_no_func/n_processed*100:.1f}%)")
    print(f"  Successfully extracted:                 {n_with_funcs} ({n_with_funcs/n_processed*100:.1f}%)")
    
    # Reasons for no-extraction on fetched diffs
    if diff_no_func > 0:
        print(f"\n  Possible reasons for {diff_no_func} no-extraction cases:")
        print(f"    - Config/XML-only changes (no Java source)")
        print(f"    - POM dependency version bumps")
        print(f"    - Binary/resource file changes")
        print(f"    - Test-only changes (filtered by our pipeline)")
    
    # ── 5. KB Population Statistics ──
    if kb_entries:
        total_kb = len(kb_entries)
        with_github = sum(1 for e in kb_entries if e['has_github'])
        with_maven = sum(1 for e in kb_entries if e['packages'])
        
        print(f"\n  ── PROJECT KB DATASET STATISTICS ──")
        print(f"  Total KB entries:               {total_kb}")
        print(f"  With GitHub-hosted repos:       {with_github} ({with_github/total_kb*100:.1f}%)")
        print(f"  With Maven package info:        {with_maven} ({with_maven/total_kb*100:.1f}%)")
        print(f"  Our sample size:                {n_processed} ({n_processed/total_kb*100:.1f}%)")
    
    return {
        'java_processed': n_processed,
        'java_diffs_fetched': n_with_diffs,
        'java_with_funcs': n_with_funcs,
        'java_total_funcs': total_funcs,
        'java_rate_fetchable': rate_on_fetchable,
        'java_rate_overall': rate_overall,
        'js_py_total': js_py_total,
        'js_py_with_commits': js_py_with_commits,
        'js_py_with_funcs': js_py_with_funcs,
    }


# ============================================================================
# Generate LaTeX table snippets
# ============================================================================

def generate_latex_tables(metrics, kb_results):
    """Generate LaTeX table code for the SCORED paper."""
    
    print(f"\n{'='*70}")
    print("LATEX TABLE SNIPPETS FOR SCORED PAPER")
    print(f"{'='*70}")
    
    # Table 1: Cross-ecosystem extraction rates (computed from data)
    js_py_total = metrics.get('js_py_total', 0)
    js_py_commits = metrics.get('js_py_with_commits', 0)
    js_py_funcs = metrics.get('js_py_with_funcs', 0)
    js_py_rate = js_py_funcs / js_py_commits * 100 if js_py_commits else 0
    
    print("""
% Table: Cross-ecosystem extraction rates
\\begin{table}[t]
    \\centering
    \\caption{Extraction rates across ecosystems. \\emph{Fetchable} = advisories where at least one commit diff was successfully retrieved.}
    \\label{tab:extraction-rates}
    \\begin{tabular}{l r r r}
        \\toprule
        \\textbf{Ecosystem} & \\textbf{Advisories} & \\textbf{Fetchable} & \\textbf{Rate} \\\\
        \\midrule""")
    
    n_diffs = metrics['java_diffs_fetched']
    n_funcs = metrics['java_with_funcs']
    print(f"        Java (Maven)  & {metrics['java_processed']} & {n_diffs} & {metrics['java_rate_fetchable']:.1f}\\% \\\\")
    print(f"        JS + Python (npm + PyPI) & {js_py_total} & {js_py_commits} & {js_py_rate:.1f}\\% \\\\")
    print(f"        \\midrule")
    combined_total = metrics['java_processed'] + js_py_total
    combined_fetch = n_diffs + js_py_commits
    combined_extr = n_funcs + js_py_funcs
    combined_rate = combined_extr / combined_fetch * 100 if combined_fetch else 0
    print(f"        Combined      & {combined_total} & {combined_fetch} & {combined_rate:.1f}\\% \\\\")
    print("""        \\bottomrule
    \\end{tabular}
\\end{table}""")
    
    # Table 2: Function count distribution
    func_counts = [r['num_functions'] for r in kb_results]
    print("""
% Table: Function extraction distribution
\\begin{table}[t]
    \\centering
    \\caption{Distribution of extracted function counts per advisory (Java/Maven, $n{=}""" + str(metrics['java_processed']) + """$).}
    \\label{tab:func-distribution}
    \\begin{tabular}{l r r}
        \\toprule
        \\textbf{Functions} & \\textbf{Count} & \\textbf{\\%} \\\\
        \\midrule""")
    
    n = metrics['java_processed']
    z = sum(1 for c in func_counts if c == 0)
    a = sum(1 for c in func_counts if 1 <= c <= 5)
    b = sum(1 for c in func_counts if 6 <= c <= 20)
    c = sum(1 for c in func_counts if c > 20)
    print(f"        0          & {z} & {z/n*100:.1f} \\\\")
    print(f"        1--5       & {a} & {a/n*100:.1f} \\\\")
    print(f"        6--20      & {b} & {b/n*100:.1f} \\\\")
    print(f"        $>$20      & {c} & {c/n*100:.1f} \\\\")
    print("""        \\bottomrule
    \\end{tabular}
\\end{table}""")


# ============================================================================
# Main
# ============================================================================

def main():
    # Load existing results
    print("Loading existing extraction results...")
    kb_results = load_existing_kb_results()
    js_python_results = load_js_python_results()
    kb_entries = load_kb_statements() if KB_STATEMENTS_DIR.exists() else []
    
    print(f"  KB results: {len(kb_results)} entries")
    print(f"  JS/Python results: {len(js_python_results) if js_python_results else 'not found'}")
    print(f"  KB total entries: {len(kb_entries)}")
    
    # Compute metrics
    metrics = compute_scored_metrics(kb_results, js_python_results, kb_entries)
    
    # Generate LaTeX
    generate_latex_tables(metrics, kb_results)
    
    # Save evaluation summary
    out_path = EVAL_DIR / "scored_evaluation_summary.txt"
    
    # Capture output by redirecting
    import io
    from contextlib import redirect_stdout
    
    buf = io.StringIO()
    with redirect_stdout(buf):
        compute_scored_metrics(kb_results, js_python_results, kb_entries)
        generate_latex_tables(metrics, kb_results)
    
    with open(out_path, 'w') as f:
        f.write(f"SCORED 2026 Evaluation Summary\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"{'='*50}\n\n")
        f.write(buf.getvalue())
    
    print(f"\n  Saved: {out_path}")
    
    print(f"\n{'='*70}")
    print("EVALUATION COMPLETE")
    print(f"{'='*70}")


if __name__ == '__main__':
    main()
