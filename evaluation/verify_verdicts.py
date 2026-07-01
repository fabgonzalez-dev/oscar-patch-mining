#!/usr/bin/env python3
"""
Verify precision validation verdicts for consistency.

Two-phase verification:
  Phase 1: Internal consistency rules (offline, fast)
  Phase 2: Cross-reference against actual GitHub diffs (online, slower)

Usage:
  python verify_verdicts.py [--skip-github]
"""

import csv
import re
import ssl
import sys
import json
import urllib.request
import urllib.error
import time
from pathlib import Path

# macOS Python often lacks proper SSL certs; create unverified context for
# read-only GitHub API calls
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

CSV_PATH = Path(__file__).parent / "precision_validation_samples.csv"

# ── Phase 1: Internal consistency rules ──────────────────────────────

MINIFIED_PATTERN = re.compile(r'^[A-Z][a-z]?$|^[a-z]{1,2}$')  # Ye, Xc, Vo, etc.
GENERIC_NAMES = {'__init__', 'noop', 'setup', 'main', 'run', 'init', 'constructor'}


def check_internal_consistency(rows):
    """Apply heuristic rules to flag suspicious verdicts."""
    flags = []

    for r in rows:
        sid = int(r['sample_id'])
        func = r['function_name']
        conf = r['confidence']
        verdict = r['verdict']
        n_funcs = int(r['num_functions_in_advisory'])

        # Rule 1: High confidence + Noise is suspicious
        if conf == 'High' and verdict == 'Noise':
            flags.append((sid, 'WARN', f'High confidence but Noise: {func}'))

        # Rule 2: Low confidence + Central deserves scrutiny
        if conf == 'Low' and verdict == 'Central':
            flags.append((sid, 'INFO', f'Low confidence but Central: {func} (n_funcs={n_funcs})'))

        # Rule 3: Minified identifiers should be Noise
        if MINIFIED_PATTERN.match(func) and verdict != 'Noise':
            flags.append((sid, 'WARN', f'Looks minified ({func}) but verdict={verdict}'))

        # Rule 4: Generic names should rarely be Central
        if func in GENERIC_NAMES and verdict == 'Central':
            flags.append((sid, 'WARN', f'Generic name ({func}) marked Central'))

        # Rule 5: Very high function count + Central is unusual
        if n_funcs >= 15 and verdict == 'Central':
            flags.append((sid, 'INFO', f'{n_funcs} functions extracted but marked Central: {func}'))

        # Rule 6: Verdict must be one of the three valid values
        if verdict not in ('Central', 'Tangential', 'Noise'):
            flags.append((sid, 'ERROR', f'Invalid verdict: {verdict}'))

        # Rule 7: Reasoning must not be empty
        if not r['reasoning'].strip():
            flags.append((sid, 'ERROR', f'Missing reasoning'))

    # Rule 8: Cross-advisory consistency — same GHSA should have coherent verdicts
    ghsa_groups = {}
    for r in rows:
        ghsa = r['vuln_id']
        ghsa_groups.setdefault(ghsa, []).append(r)

    for ghsa, group in ghsa_groups.items():
        if len(group) > 1:
            verdicts_in_group = {r['verdict'] for r in group}
            confs_in_group = {r['confidence'] for r in group}
            # If the same advisory has both Central and Noise, flag for review
            if 'Central' in verdicts_in_group and 'Noise' in verdicts_in_group:
                sids = [r['sample_id'] for r in group]
                flags.append((
                    int(sids[0]), 'INFO',
                    f'{ghsa} has both Central and Noise verdicts across samples {sids} — check consistency'
                ))

    return flags


# ── Phase 2: GitHub diff cross-reference ─────────────────────────────

GITHUB_API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "OSCAR-Validation-Script/1.0"
}


def fetch_json(url, retries=2):
    """Fetch JSON from GitHub API with basic retry."""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403:  # Rate limited
                print(f"  ⚠ Rate limited, waiting 60s...")
                time.sleep(60)
            elif e.code == 404:
                return None
            else:
                if attempt == retries:
                    print(f"  ⚠ HTTP {e.code} for {url}")
                    return None
                time.sleep(2)
        except Exception as e:
            if attempt == retries:
                print(f"  ⚠ Error fetching {url}: {e}")
                return None
            time.sleep(2)
    return None


def fetch_diff(repo, commit_sha):
    """Fetch the diff for a specific commit."""
    url = f"{GITHUB_API}/repos/{repo}/commits/{commit_sha}"
    headers = {**HEADERS, "Accept": "application/vnd.github.diff"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as resp:
            return resp.read().decode(errors='replace')
    except Exception as e:
        print(f"  ⚠ Error fetching diff: {e}")
        return None


def get_fix_commits_for_advisory(ghsa_id):
    """Get fix commit SHAs from a GHSA advisory via the GitHub API."""
    url = f"{GITHUB_API}/advisories/{ghsa_id}"
    data = fetch_json(url)
    if not data:
        return []

    commits = []
    # The references field contains fix URLs (can be strings or dicts)
    for ref in data.get('references', []):
        if isinstance(ref, dict):
            ref_url = ref.get('url', '')
        else:
            ref_url = str(ref)
        # Match commit URLs like github.com/owner/repo/commit/sha
        m = re.search(r'github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})', ref_url)
        if m:
            commits.append((m.group(1), m.group(2)))
    return commits


def function_in_diff(func_name, diff_text):
    """Check if a function name appears in changed lines of a diff."""
    if not diff_text:
        return None  # Unknown

    in_changed_lines = False
    in_context = False

    for line in diff_text.split('\n'):
        if line.startswith('+') or line.startswith('-'):
            if func_name in line:
                in_changed_lines = True
        elif func_name in line:
            in_context = True

    if in_changed_lines:
        return 'changed'  # Function appears in added/removed lines
    elif in_context:
        return 'context'  # Function appears in context only
    else:
        return 'absent'   # Function not found in diff at all


def check_github_diffs(rows):
    """Cross-reference verdicts against actual GitHub diffs."""
    flags = []
    # Cache: ghsa_id -> diff_text
    diff_cache = {}

    unique_ghsas = list({r['vuln_id'] for r in rows})
    print(f"\n📡 Fetching diffs for {len(unique_ghsas)} unique advisories...")

    for i, ghsa_id in enumerate(unique_ghsas):
        print(f"  [{i+1}/{len(unique_ghsas)}] {ghsa_id}...", end=" ", flush=True)
        commits = get_fix_commits_for_advisory(ghsa_id)
        if not commits:
            print("no fix commits found")
            diff_cache[ghsa_id] = None
            continue

        # Concatenate all fix commit diffs
        all_diffs = []
        for repo, sha in commits[:3]:  # Limit to 3 commits
            diff = fetch_diff(repo, sha)
            if diff:
                all_diffs.append(diff)
            time.sleep(0.5)  # Rate limit courtesy

        diff_cache[ghsa_id] = '\n'.join(all_diffs) if all_diffs else None
        print(f"{len(commits)} commit(s), {len(all_diffs)} diff(s) fetched")

    # Now check each sample
    print(f"\n🔍 Cross-referencing {len(rows)} samples against diffs...\n")

    for r in rows:
        sid = int(r['sample_id'])
        func = r['function_name']
        verdict = r['verdict']
        ghsa_id = r['vuln_id']
        diff_text = diff_cache.get(ghsa_id)

        if diff_text is None:
            flags.append((sid, 'SKIP', f'No diff available for {ghsa_id}'))
            continue

        presence = function_in_diff(func, diff_text)

        # Cross-check verdict against diff presence
        if verdict == 'Central' and presence == 'absent':
            flags.append((sid, 'WARN',
                f'Verdict=Central but "{func}" NOT found in diff for {ghsa_id}'))
        elif verdict == 'Noise' and presence == 'changed':
            flags.append((sid, 'WARN',
                f'Verdict=Noise but "{func}" IS in changed lines for {ghsa_id}'))
        elif verdict == 'Central' and presence == 'changed':
            flags.append((sid, 'OK',
                f'✓ Confirmed: "{func}" found in changed lines'))
        elif verdict == 'Noise' and presence == 'absent':
            flags.append((sid, 'OK',
                f'✓ Confirmed: "{func}" not in diff (correctly Noise)'))
        elif verdict == 'Tangential' and presence == 'changed':
            flags.append((sid, 'INFO',
                f'Tangential but "{func}" in changed lines — could be Central?'))
        elif verdict == 'Tangential' and presence == 'context':
            flags.append((sid, 'OK',
                f'✓ Confirmed: "{func}" in context only (correctly Tangential)'))
        elif verdict == 'Tangential' and presence == 'absent':
            flags.append((sid, 'INFO',
                f'Tangential but "{func}" not found in diff at all — could be Noise?'))
        else:
            flags.append((sid, 'OK', f'"{func}" presence={presence}, verdict={verdict}'))

    return flags


# ── Main ─────────────────────────────────────────────────────────────

def main():
    skip_github = '--skip-github' in sys.argv

    # Read CSV
    with open(CSV_PATH, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"📄 Loaded {len(rows)} samples from {CSV_PATH.name}\n")

    # Phase 1
    print("=" * 60)
    print("PHASE 1: Internal Consistency Rules")
    print("=" * 60)
    phase1_flags = check_internal_consistency(rows)

    if not phase1_flags:
        print("  ✅ All internal consistency checks passed!\n")
    else:
        for sid, level, msg in sorted(phase1_flags):
            icon = {'ERROR': '🔴', 'WARN': '🟡', 'INFO': 'ℹ️ '}.get(level, '  ')
            print(f"  {icon} Sample {sid}: [{level}] {msg}")
        print()

    # Phase 2
    if skip_github:
        print("⏭  Skipping Phase 2 (GitHub diff check) — use without --skip-github to enable\n")
        phase2_flags = []
    else:
        print("=" * 60)
        print("PHASE 2: GitHub Diff Cross-Reference")
        print("=" * 60)
        phase2_flags = check_github_diffs(rows)

        if phase2_flags:
            # Show warnings first, then OKs
            warns = [(s, l, m) for s, l, m in phase2_flags if l in ('WARN', 'ERROR')]
            oks = [(s, l, m) for s, l, m in phase2_flags if l == 'OK']
            infos = [(s, l, m) for s, l, m in phase2_flags if l == 'INFO']
            skips = [(s, l, m) for s, l, m in phase2_flags if l == 'SKIP']

            if warns:
                print("\n⚠️  WARNINGS (verdict may be wrong):")
                for sid, level, msg in sorted(warns):
                    print(f"  🟡 Sample {sid}: {msg}")

            if infos:
                print("\n📋 INFO (worth reviewing):")
                for sid, level, msg in sorted(infos):
                    print(f"  ℹ️  Sample {sid}: {msg}")

            if skips:
                print(f"\n⏭  {len(skips)} samples skipped (no diff available)")

            print(f"\n✅ {len(oks)}/{len(rows)} verdicts confirmed by diff analysis")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    p1_errors = sum(1 for _, l, _ in phase1_flags if l == 'ERROR')
    p1_warns = sum(1 for _, l, _ in phase1_flags if l == 'WARN')
    p2_warns = sum(1 for _, l, _ in phase2_flags if l in ('WARN', 'ERROR'))
    p2_oks = sum(1 for _, l, _ in phase2_flags if l == 'OK')

    print(f"  Phase 1: {p1_errors} errors, {p1_warns} warnings")
    if not skip_github:
        print(f"  Phase 2: {p2_warns} warnings, {p2_oks} confirmed")

    total_issues = p1_errors + p1_warns + p2_warns
    if total_issues == 0:
        print("\n🎉 All verdicts are consistent!")
    else:
        print(f"\n⚡ {total_issues} issue(s) to review")


if __name__ == '__main__':
    main()
