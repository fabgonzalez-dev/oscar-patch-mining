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

def fetch_ghsa_page(ecosystem, page=1):
    """Fetch one page of GHSA advisories for a given ecosystem.
    
    Uses the GitHub REST API: GET /advisories
    Docs: https://docs.github.com/en/rest/security-advisories/global-advisories
    """
    url = "https://api.github.com/advisories"
    params = [
        f"ecosystem={ecosystem}",
        "type=reviewed",        # only reviewed advisories
        "per_page=100",         # max page size
        f"page={page}",
    ]
    
    full_url = f"{url}?{'&'.join(params)}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "OSCAR-Research/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    
    for attempt in range(3):
        try:
            req = urllib.request.Request(full_url, headers=headers)
            with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:
                data = json.loads(resp.read().decode())
                # Check if there's a next page via Link header
                link_header = resp.getheader("Link", "")
                has_next = 'rel="next"' in link_header
                remaining = resp.getheader("X-RateLimit-Remaining", "?")
                return data, has_next, remaining
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # Rate limited
                retry_after = int(e.headers.get("Retry-After", 60))
                print(f"  ⚠ Rate limited. Waiting {retry_after}s...")
                time.sleep(retry_after)
                continue
            if e.code == 422:
                print(f"  ⚠ Invalid page, stopping...")
                return [], False, "0"
            print(f"  ⚠ HTTP {e.code}: {e.read().decode()[:200]}")
            return [], False, "0"
        except Exception as e:
            if attempt < 2:
                time.sleep(2)
                continue
            print(f"  ⚠ Error: {e}")
            return [], False, "0"
    return [], False, "0"


def fetch_all_advisories(ecosystem):
    """Fetch ALL reviewed advisories for a given ecosystem using pagination."""
    all_advisories = []
    page = 1
    
    while True:
        print(f"  Fetching page {page}...")
        time.sleep(GITHUB_DELAY)
        
        advisories, has_next, remaining = fetch_ghsa_page(ecosystem, page)
        
        if not advisories:
            break
        
        all_advisories.extend(advisories)
        print(f"    → Got {len(advisories)} advisories (total: {len(all_advisories)}, rate limit: {remaining})")
        
        if not has_next:
            break
        page += 1
    
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
    """Fetch all advisories for an ecosystem and run extraction."""
    print(f"\n{'='*70}")
    print(f"PROCESSING: {ecosystem.upper()} ({ghsa_ecosystem_name})")
    print(f"{'='*70}\n")
    
    # Map GHSA ecosystem names to our pipeline ecosystem names
    eco_map = {"npm": "npm", "pip": "pypi"}
    pipeline_eco = eco_map.get(ghsa_ecosystem_name, ghsa_ecosystem_name)
    
    # Step 1: Fetch all advisories
    print("Step 1: Fetching all reviewed advisories from GHSA...")
    advisories = fetch_all_advisories(ghsa_ecosystem_name)
    print(f"  → Total advisories: {len(advisories)}")
    
    if not advisories:
        print("  ⚠ No advisories found!")
        return []
    
    # Step 2: Process each advisory
    print(f"\nStep 2: Extracting functions from fix commits...")
    results = []
    stats = {
        "total": len(advisories),
        "with_commits": 0,
        "with_functions": 0,
        "total_functions": 0,
        "capped": 0,
    }
    
    for i, adv in enumerate(advisories, 1):
        ghsa_id = adv.get("ghsa_id", "")
        severity = adv.get("severity", "unknown")
        
        # Get affected package name
        pkg_name = ""
        for vuln in adv.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            if pkg.get("ecosystem", "").lower() == ghsa_ecosystem_name.lower():
                pkg_name = pkg.get("name", "")
                break
        
        if not pkg_name and adv.get("vulnerabilities"):
            pkg = adv["vulnerabilities"][0].get("package", {})
            pkg_name = pkg.get("name", "")
        
        if i % 50 == 0 or i <= 5:
            print(f"  [{i}/{len(advisories)}] {ghsa_id} ({pkg_name})")
        
        # Extract fix commits
        commits, source_repo = extract_fix_commits(adv)
        
        if not commits:
            results.append({
                "vuln_id": ghsa_id,
                "affected_package": pkg_name,
                "ecosystem": pipeline_eco,
                "severity": severity,
                "fix_commits_found": 0,
                "functions_mined": "",
                "num_functions_mined": 0,
                "functions_capped": False,
                "source_repo": "",
            })
            continue
        
        stats["with_commits"] += 1
        
        # Fetch diffs and extract functions
        all_functions = set()
        for commit_url in commits[:3]:  # cap at 3 commits per advisory
            time.sleep(GITHUB_DELAY)
            diff = get_commit_diff(commit_url)
            if diff:
                funcs = extract_functions_from_diff(diff, pipeline_eco)
                all_functions.update(funcs)
        
        # Function count cap
        MAX_FUNCTIONS = 15
        functions_capped = len(all_functions) > MAX_FUNCTIONS
        if functions_capped:
            stats["capped"] += 1
        
        if all_functions:
            stats["with_functions"] += 1
            stats["total_functions"] += len(all_functions)
        
        results.append({
            "vuln_id": ghsa_id,
            "affected_package": pkg_name,
            "ecosystem": pipeline_eco,
            "severity": severity,
            "fix_commits_found": len(commits),
            "functions_mined": ";".join(sorted(all_functions)),
            "num_functions_mined": len(all_functions),
            "functions_capped": functions_capped,
            "source_repo": source_repo or "",
        })
    
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
    
    return results


# ============================================================================
# Main
# ============================================================================

def main():
    print("=" * 70)
    print("SCORED 2026 — FULL GHSA CORPUS EXTRACTION")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"GitHub Token: {'configured' if GITHUB_TOKEN else 'NOT SET (will be slow!)'}")
    print("=" * 70)
    
    if not GITHUB_TOKEN:
        print("\n⚠  WARNING: No GITHUB_TOKEN set. Rate limit is 60 req/hr.")
        print("   Set GITHUB_TOKEN for 5,000 req/hr:")
        print("   export GITHUB_TOKEN='ghp_...'")
        print("   Continuing with unauthenticated access...\n")
    
    # Process npm
    npm_results = process_ecosystem("npm", "npm")
    
    # Save npm results
    if npm_results:
        npm_path = DATA_DIR / "ghsa_full_npm_extraction.csv"
        with open(npm_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=npm_results[0].keys())
            writer.writeheader()
            writer.writerows(npm_results)
        print(f"\n  → Saved: {npm_path} ({len(npm_results)} rows)")
    
    # Process PyPI
    pypi_results = process_ecosystem("pypi", "pip")
    
    # Save PyPI results
    if pypi_results:
        pypi_path = DATA_DIR / "ghsa_full_pypi_extraction.csv"
        with open(pypi_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=pypi_results[0].keys())
            writer.writeheader()
            writer.writerows(pypi_results)
        print(f"\n  → Saved: {pypi_path} ({len(pypi_results)} rows)")
    
    # Combined summary
    print(f"\n{'='*70}")
    print("COMBINED SUMMARY")
    print(f"{'='*70}")
    
    all_results = npm_results + pypi_results
    total = len(all_results)
    with_commits = sum(1 for r in all_results if r["fix_commits_found"] > 0)
    with_funcs = sum(1 for r in all_results if r["num_functions_mined"] > 0)
    total_funcs = sum(r["num_functions_mined"] for r in all_results)
    
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
        
        for label, results in [("npm", npm_results), ("PyPI", pypi_results)]:
            n = len(results)
            wc = sum(1 for r in results if r["fix_commits_found"] > 0)
            wf = sum(1 for r in results if r["num_functions_mined"] > 0)
            tf = sum(r["num_functions_mined"] for r in results)
            f.write(f"{label}:\n")
            f.write(f"  Total advisories:     {n}\n")
            f.write(f"  With fix commits:     {wc}\n")
            f.write(f"  With functions:       {wf}\n")
            f.write(f"  Total functions:      {tf}\n")
            if wc:
                f.write(f"  Extraction rate:      {wf/wc*100:.1f}%\n")
            f.write(f"\n")
        
        f.write(f"Combined:\n")
        f.write(f"  Total advisories:     {total}\n")
        f.write(f"  With fix commits:     {with_commits}\n")
        f.write(f"  With functions:       {with_funcs}\n")
        f.write(f"  Total functions:      {total_funcs}\n")
        if with_commits:
            f.write(f"  Extraction rate:      {with_funcs/with_commits*100:.1f}%\n")
    
    print(f"\n  → Saved: {summary_path}")
    print(f"\n{'='*70}")
    print("FULL CORPUS EXTRACTION COMPLETE")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
