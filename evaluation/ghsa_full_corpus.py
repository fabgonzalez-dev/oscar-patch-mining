#!/usr/bin/env python3
"""
SCORED 2026 — Full GHSA Corpus Extraction
==========================================
Queries the GitHub Advisory Database API for ALL reviewed npm and PyPI
advisories, then runs the patch mining extraction pipeline on each.

This produces the full-corpus extraction coverage numbers needed
to address the corpus size imbalance (1,248 Java vs 162 JS/Python).

Usage:
    # Set GitHub token for higher rate limits (5,000 req/hr vs 60/hr)
    export GITHUB_TOKEN="ghp_..."
    python oscar-patch-mining/evaluation/ghsa_full_corpus.py

Output:
    oscar-patch-mining/data/ghsa_full_npm_extraction.csv
    oscar-patch-mining/data/ghsa_full_pypi_extraction.csv
    oscar-patch-mining/data/ghsa_full_corpus_summary.txt
"""

import csv
import json
import os
import re
import ssl
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# SSL context for macOS
_SSL_CTX = ssl._create_unverified_context()

# Import extraction function from the pipeline
SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "oscar-research-data" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))
from mine_cve_patches import extract_functions_from_diff, get_commit_diff

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
# With token: 5,000 req/hr → ~0.72s delay. Without: 60 req/hr → 60s delay
GITHUB_DELAY = 0.8 if GITHUB_TOKEN else 2.0


# ============================================================================
# GitHub Advisory Database API
# ============================================================================

def fetch_ghsa_page(ecosystem, cursor=None):
    """Fetch one page of GHSA advisories for a given ecosystem.
    
    Uses the GitHub REST API: GET /advisories (cursor-based pagination)
    Docs: https://docs.github.com/en/rest/security-advisories/global-advisories
    """
    url = "https://api.github.com/advisories"
    params = [
        f"ecosystem={ecosystem}",
        "type=reviewed",        # only reviewed advisories
        "per_page=100",         # max page size
    ]
    if cursor:
        params.append(f"after={cursor}")
    
    full_url = f"{url}?{'&'.join(params)}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "PatchMining-Research/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    
    for attempt in range(3):
        try:
            req = urllib.request.Request(full_url, headers=headers)
            with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:
                data = json.loads(resp.read().decode())
                # Extract next cursor from Link header
                link_header = resp.getheader("Link", "")
                next_cursor = None
                if 'rel="next"' in link_header:
                    m = re.search(r'after=([^&>]+)', link_header)
                    if m:
                        next_cursor = urllib.parse.unquote(m.group(1))
                remaining = resp.getheader("X-RateLimit-Remaining", "?")
                return data, next_cursor, remaining
        except urllib.error.HTTPError as e:
            if e.code == 403:
                retry_after = int(e.headers.get("Retry-After", 60))
                print(f"  ⚠ Rate limited. Waiting {retry_after}s...")
                time.sleep(retry_after)
                continue
            if e.code == 422:
                print(f"  ⚠ Invalid cursor, stopping...")
                return [], None, "0"
            print(f"  ⚠ HTTP {e.code}: {e.read().decode()[:200]}")
            return [], None, "0"
        except Exception as e:
            if attempt < 2:
                time.sleep(2)
                continue
            print(f"  ⚠ Error: {e}")
            return [], None, "0"
    return [], None, "0"


def fetch_all_advisories(ecosystem):
    """Fetch ALL reviewed advisories for a given ecosystem using cursor pagination."""
    all_advisories = []
    cursor = None
    page = 0
    
    while True:
        page += 1
        print(f"  Fetching page {page}...")
        time.sleep(GITHUB_DELAY)
        
        advisories, next_cursor, remaining = fetch_ghsa_page(ecosystem, cursor)
        
        if not advisories:
            break
        
        all_advisories.extend(advisories)
        print(f"    → Got {len(advisories)} advisories (total: {len(all_advisories)}, rate limit: {remaining})")
        
        if not next_cursor:
            break
        cursor = next_cursor
    
    return all_advisories


def extract_fix_commits(advisory):
    """Extract fix commit URLs from a GHSA advisory object."""
    commits = []
    source_repo = None
    
    for ref in advisory.get("references", []):
        ref_url = ref if isinstance(ref, str) else ref.get("url", "")
        if "/commit/" in ref_url and "github.com" in ref_url:
            commits.append(ref_url)
        elif "/pull/" in ref_url and "github.com" in ref_url:
            commits.append(ref_url)
    
    # Extract source repo
    for ref in advisory.get("references", []):
        ref_url = ref if isinstance(ref, str) else ref.get("url", "")
        m = re.match(r"https://github\.com/([^/]+/[^/]+)", ref_url)
        if m and "advisories" not in ref_url and "nvd.nist" not in ref_url:
            source_repo = m.group(1)
            break
    
    return commits, source_repo


# ============================================================================
# Process Advisories
# ============================================================================

def process_ecosystem(ecosystem, ghsa_ecosystem_name):
    """Fetch advisories page-by-page and process each immediately (streaming)."""
    print(f"\n{'='*70}")
    print(f"PROCESSING: {ecosystem.upper()} ({ghsa_ecosystem_name})")
    print(f"{'='*70}\n", flush=True)
    
    eco_map = {"npm": "npm", "pip": "pypi"}
    pipeline_eco = eco_map.get(ghsa_ecosystem_name, ghsa_ecosystem_name)
    
    # Output CSV path — open for incremental writes
    csv_path = DATA_DIR / f"ghsa_full_{ecosystem}_extraction.csv"
    progress_path = DATA_DIR / f"ghsa_full_{ecosystem}_progress.txt"
    fieldnames = ["vuln_id", "affected_package", "ecosystem", "severity",
                  "fix_commits_found", "functions_mined", "num_functions_mined",
                  "functions_capped", "source_repo"]
    
    stats = {"total": 0, "with_commits": 0, "with_functions": 0,
             "total_functions": 0, "capped": 0}
    
    MAX_FUNCTIONS = 15
    cursor = None
    page = 0
    
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        while True:
            page += 1
            time.sleep(GITHUB_DELAY)
            advisories, next_cursor, remaining = fetch_ghsa_page(ghsa_ecosystem_name, cursor)
            
            if not advisories:
                break
            
            print(f"  Page {page}: {len(advisories)} advisories (rate limit: {remaining})", flush=True)
            
            # Process each advisory on this page immediately
            for adv in advisories:
                stats["total"] += 1
                ghsa_id = adv.get("ghsa_id", "")
                severity = adv.get("severity", "unknown")
                
                # Get package name
                pkg_name = ""
                for vuln in adv.get("vulnerabilities", []):
                    pkg = vuln.get("package", {})
                    if pkg.get("ecosystem", "").lower() == ghsa_ecosystem_name.lower():
                        pkg_name = pkg.get("name", "")
                        break
                if not pkg_name and adv.get("vulnerabilities"):
                    pkg_name = adv["vulnerabilities"][0].get("package", {}).get("name", "")
                
                # Extract fix commits from advisory references
                commits, source_repo = extract_fix_commits(adv)
                
                if not commits:
                    writer.writerow({
                        "vuln_id": ghsa_id, "affected_package": pkg_name,
                        "ecosystem": pipeline_eco, "severity": severity,
                        "fix_commits_found": 0, "functions_mined": "",
                        "num_functions_mined": 0, "functions_capped": False,
                        "source_repo": "",
                    })
                    continue
                
                stats["with_commits"] += 1
                
                # Fetch diffs and extract functions
                all_functions = set()
                for commit_url in commits[:3]:
                    time.sleep(GITHUB_DELAY)
                    diff = get_commit_diff(commit_url)
                    if diff:
                        funcs = extract_functions_from_diff(diff, pipeline_eco)
                        all_functions.update(funcs)
                
                functions_capped = len(all_functions) > MAX_FUNCTIONS
                if functions_capped:
                    stats["capped"] += 1
                if all_functions:
                    stats["with_functions"] += 1
                    stats["total_functions"] += len(all_functions)
                
                writer.writerow({
                    "vuln_id": ghsa_id, "affected_package": pkg_name,
                    "ecosystem": pipeline_eco, "severity": severity,
                    "fix_commits_found": len(commits),
                    "functions_mined": ";".join(sorted(all_functions)),
                    "num_functions_mined": len(all_functions),
                    "functions_capped": functions_capped,
                    "source_repo": source_repo or "",
                })
            
            # Flush CSV and write progress every page
            csvfile.flush()
            with open(progress_path, "w") as pf:
                pf.write(f"Ecosystem: {ecosystem}\n")
                pf.write(f"Updated: {datetime.now().isoformat()}\n")
                pf.write(f"Pages fetched: {page}\n")
                pf.write(f"Total advisories: {stats['total']}\n")
                pf.write(f"With fix commits: {stats['with_commits']}\n")
                pf.write(f"With functions: {stats['with_functions']}\n")
                pf.write(f"Total functions: {stats['total_functions']}\n")
                rate = stats['with_functions'] / stats['with_commits'] * 100 if stats['with_commits'] else 0
                pf.write(f"Extraction rate: {rate:.1f}%\n")
            
            if not next_cursor:
                break
            cursor = next_cursor
    
    # Print summary
    print(f"\n  ── {ecosystem.upper()} SUMMARY ──")
    print(f"  Total advisories:     {stats['total']}")
    print(f"  With fix commits:     {stats['with_commits']}")
    print(f"  With functions:       {stats['with_functions']}")
    print(f"  Total functions:      {stats['total_functions']}")
    print(f"  Capped (>{MAX_FUNCTIONS}):       {stats['capped']}")
    if stats["with_commits"]:
        rate = stats["with_functions"] / stats["with_commits"] * 100
        print(f"  Extraction rate:      {rate:.1f}%")
    
    return stats


# ============================================================================
# Main
# ============================================================================

def main():
    print("=" * 70)
    print("SCORED 2026 — FULL GHSA CORPUS EXTRACTION (streaming)")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"GitHub Token: {'configured' if GITHUB_TOKEN else 'NOT SET (will be slow!)'}")
    print("=" * 70, flush=True)
    
    if not GITHUB_TOKEN:
        print("\n⚠  WARNING: No GITHUB_TOKEN set. Rate limit is 60 req/hr.")
        print("   Set GITHUB_TOKEN for 5,000 req/hr:")
        print("   export GITHUB_TOKEN='ghp_...'")
        print("   Continuing with unauthenticated access...\n")
    
    # Process npm (CSV written incrementally)
    npm_stats = process_ecosystem("npm", "npm")
    
    # Process PyPI (CSV written incrementally)
    pypi_stats = process_ecosystem("pypi", "pip")
    
    # Combined summary
    print(f"\n{'='*70}")
    print("COMBINED SUMMARY")
    print(f"{'='*70}")
    
    total = npm_stats["total"] + pypi_stats["total"]
    with_commits = npm_stats["with_commits"] + pypi_stats["with_commits"]
    with_funcs = npm_stats["with_functions"] + pypi_stats["with_functions"]
    total_funcs = npm_stats["total_functions"] + pypi_stats["total_functions"]
    
    print(f"  Total advisories:     {total}")
    print(f"  With fix commits:     {with_commits}")
    print(f"  With functions:       {with_funcs}")
    print(f"  Total functions:      {total_funcs}")
    if with_commits:
        print(f"  Extraction rate:      {with_funcs/with_commits*100:.1f}%")
    
    # Save summary
    summary_path = DATA_DIR / "ghsa_full_corpus_summary.txt"
    with open(summary_path, "w") as f:
        f.write(f"SCORED 2026 — Full GHSA Corpus Summary\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"{'='*50}\n\n")
        
        for label, s in [("npm", npm_stats), ("PyPI", pypi_stats)]:
            f.write(f"{label}:\n")
            f.write(f"  Total advisories:     {s['total']}\n")
            f.write(f"  With fix commits:     {s['with_commits']}\n")
            f.write(f"  With functions:       {s['with_functions']}\n")
            f.write(f"  Total functions:      {s['total_functions']}\n")
            if s['with_commits']:
                f.write(f"  Extraction rate:      {s['with_functions']/s['with_commits']*100:.1f}%\n")
            f.write(f"\n")
        
        f.write(f"Combined:\n")
        f.write(f"  Total advisories:     {total}\n")
        f.write(f"  With fix commits:     {with_commits}\n")
        f.write(f"  With functions:       {with_funcs}\n")
        f.write(f"  Total functions:      {total_funcs}\n")
        if with_commits:
            f.write(f"  Extraction rate:      {with_funcs/with_commits*100:.1f}%\n")
    
    print(f"\n  → Saved: {summary_path}")
    print(f"  → npm CSV: {DATA_DIR / 'ghsa_full_npm_extraction.csv'}")
    print(f"  → PyPI CSV: {DATA_DIR / 'ghsa_full_pypi_extraction.csv'}")
    print(f"\n{'='*70}")
    print("FULL CORPUS EXTRACTION COMPLETE")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
