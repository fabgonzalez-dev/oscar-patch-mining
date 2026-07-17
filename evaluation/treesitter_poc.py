#!/usr/bin/env python3
"""
treesitter_poc.py — Tree-sitter proof-of-concept for validating hunk-header
misattribution in CVE patch mining.

For each advisory:
1. Fetches the fix-commit diff from GitHub
2. Identifies hunk headers (@@) and their context function names
3. Identifies actually modified (+/-) lines and their line numbers
4. Fetches the pre-commit source file
5. Parses with tree-sitter to find the *real* enclosing function
6. Compares regex result vs tree-sitter result

Usage:
    export GITHUB_TOKEN=ghp_...
    python3 treesitter_poc.py
"""

import csv
import json
import os
import re
import sys
import time
import urllib.request
import ssl
from pathlib import Path
from collections import defaultdict

import tree_sitter as ts
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs

# ── Config ────────────────────────────────────────────────────────────

EVAL_DIR = Path(__file__).resolve().parent
SAMPLES_FILE = EVAL_DIR / "precision_validation_samples_n104.csv"
CACHE_DIR = EVAL_DIR / "treesitter_poc" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_DELAY = 1.0  # seconds between requests

_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX.load_verify_locations(certifi.where())
except (ImportError, Exception):
    # Fallback: disable verification for public GitHub API access only
    _SSL_CTX = ssl._create_unverified_context()

# Advisory → (repo, commit_url) mapping
# These are the fix commits for our 6 hunk-header noise cases
ADVISORY_COMMITS = {
    "GHSA-mcmc-2m55-j8jj": {
        "repo": "vllm-project/vllm",
        "language": "python",
    },
    "GHSA-jx7v-gmqc-6xrj": {
        "repo": "openstack/manila",
        "language": "python",
    },
    "GHSA-h75v-3vvj-5mfj": {
        "repo": "pallets/jinja",
        "language": "python",
    },
    "GHSA-hrf3-622q-8366": {
        "repo": "pypa/advisory-database",
        "language": "python",
    },
    "GHSA-mjqh-v5f2-g2mw": {
        "repo": "apache/airflow",
        "language": "python",
    },
    "GHSA-2r2c-g63r-vccr": {
        "repo": "digitalbazaar/forge",
        "language": "javascript",
    },
}

# Control cases - regex got it right
CONTROL_CASES = [
    {"vuln_id": "GHSA-vh95-rmgr-6w4m", "language": "javascript"},
    {"vuln_id": "GHSA-3xgq-45jj-v275", "language": "javascript"},
    {"vuln_id": "GHSA-phj8-2p6x-hq5r", "language": "javascript"},
    {"vuln_id": "GHSA-pxg6-pf52-xh8x", "language": "javascript"},
    {"vuln_id": "GHSA-4vmm-mhcq-4x9j", "language": "javascript"},
    {"vuln_id": "GHSA-46j5-6fg5-4gv3", "language": "javascript"},
    {"vuln_id": "GHSA-v6h2-p8h4-qcjw", "language": "javascript"},
    {"vuln_id": "GHSA-www2-v7xj-xrc6", "language": "python"},
    {"vuln_id": "GHSA-w2r7-9579-27hf", "language": "python"},
    {"vuln_id": "GHSA-pm87-24wq-r8w9", "language": "python"},
    {"vuln_id": "GHSA-2xpw-w6gg-jr37", "language": "python"},
    {"vuln_id": "GHSA-7p48-42j8-8846", "language": "python"},
    {"vuln_id": "GHSA-55m3-44xf-hg4h", "language": "python"},
    {"vuln_id": "GHSA-38jv-5279-wg99", "language": "python"},
]


# ── HTTP Helpers ──────────────────────────────────────────────────────

def _headers():
    h = {"User-Agent": "OSCAR-Research/1.0"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"token {GITHUB_TOKEN}"
    return h


def fetch_json(url, retries=2):
    headers = {**_headers(), "Accept": "application/vnd.github+json"}
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"  ⚠ Rate limited, waiting 60s...")
                time.sleep(60)
                continue
            if e.code == 404:
                return None
            print(f"  ⚠ HTTP {e.code} for {url}")
            return None
        except Exception as e:
            if attempt < retries:
                time.sleep(2)
                continue
            print(f"  ⚠ Error: {e}")
            return None
    return None


def fetch_text(url, retries=2):
    headers = _headers()
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:
                return resp.read().decode(errors='replace')
        except urllib.error.HTTPError as e:
            if e.code == 403:
                time.sleep(60)
                continue
            return None
        except Exception:
            if attempt < retries:
                time.sleep(2)
                continue
            return None
    return None


# ── GHSA Advisory Resolution ─────────────────────────────────────────

def get_ghsa_commit_urls(ghsa_id):
    """Get fix commit URLs from the GHSA API."""
    cache_file = CACHE_DIR / f"{ghsa_id}_advisory.json"
    if cache_file.exists():
        data = json.loads(cache_file.read_text())
    else:
        url = f"https://api.github.com/advisories/{ghsa_id}"
        data = fetch_json(url)
        if data:
            cache_file.write_text(json.dumps(data, indent=2))
        time.sleep(GITHUB_DELAY)

    if not data:
        return []

    # Extract references that are commit URLs
    commits = []
    for ref in data.get("references", []):
        ref_url = ref if isinstance(ref, str) else ref.get("url", "")
        m = re.match(r'https://github\.com/([^/]+/[^/]+)/commit/([a-f0-9]+)', ref_url)
        if m:
            commits.append({"repo": m.group(1), "sha": m.group(2), "url": ref_url})

    return commits


# ── Diff Fetching & Parsing ──────────────────────────────────────────

def get_commit_diff(repo, sha):
    """Fetch the unified diff for a commit."""
    cache_file = CACHE_DIR / f"{repo.replace('/', '_')}_{sha[:12]}.diff"
    if cache_file.exists():
        return cache_file.read_text()

    diff_url = f"https://github.com/{repo}/commit/{sha}.diff"
    diff_text = fetch_text(diff_url)
    if diff_text:
        cache_file.write_text(diff_text)
    time.sleep(GITHUB_DELAY)
    return diff_text


def parse_diff(diff_text, target_function=None, language="python"):
    """Parse a unified diff to identify hunk headers and modified lines.
    
    Returns a list of file entries, each with:
    - filename: the file path
    - hunks: list of hunks, each with:
        - header_function: function name from the @@ context
        - modified_lines: list of (line_number_in_pre, line_content, change_type)
    """
    if not diff_text:
        return []

    files = []
    current_file = None
    current_hunk = None
    pre_line = 0

    # Extension filter based on language
    source_exts = {
        "python": (".py",),
        "javascript": (".js", ".mjs", ".cjs", ".ts"),
    }
    valid_exts = source_exts.get(language, (".py", ".js"))

    for line in diff_text.split("\n"):
        # New file header
        if line.startswith("diff --git"):
            current_file = None
            current_hunk = None
            m = re.search(r'b/(.+)$', line)
            if m:
                filepath = m.group(1)
                # Only process source files
                if any(filepath.endswith(ext) for ext in valid_exts):
                    current_file = {"filename": filepath, "hunks": []}
                    files.append(current_file)
            continue

        if current_file is None:
            continue

        # Hunk header
        m = re.match(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$', line)
        if m:
            pre_line = int(m.group(1))
            header_context = m.group(3).strip()
            # Extract function name from context
            header_func = None
            for pattern in _get_patterns(language):
                fm = pattern.search(header_context)
                if fm:
                    header_func = fm.group(1)
                    break
            current_hunk = {
                "header_function": header_func,
                "header_context": header_context,
                "start_pre_line": pre_line,
                "modified_lines": [],
            }
            current_file["hunks"].append(current_hunk)
            continue

        if current_hunk is None:
            continue

        # Modified lines
        if line.startswith("+") and not line.startswith("+++"):
            current_hunk["modified_lines"].append({
                "pre_line": None,  # additions don't have a pre-commit line
                "content": line[1:],
                "type": "add",
            })
        elif line.startswith("-") and not line.startswith("---"):
            current_hunk["modified_lines"].append({
                "pre_line": pre_line,
                "content": line[1:],
                "type": "del",
            })
            pre_line += 1
        else:
            # Context line
            pre_line += 1

    return files


def _get_patterns(language):
    """Get regex patterns for function detection."""
    if language == "python":
        return [
            re.compile(r'def\s+(\w+)\s*\('),
            re.compile(r'async\s+def\s+(\w+)\s*\('),
            re.compile(r'class\s+(\w+)\s*[\(:]'),
        ]
    elif language == "javascript":
        return [
            re.compile(r'function\s+(\w+)\s*\('),
            re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:function|async\s+function)\s*\('),
            re.compile(r'(\w+)\s*\([^)]*\)\s*\{'),
            re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:\([^)]*\)|[^=])\s*=>'),
        ]
    return []


# ── Source File Fetching ──────────────────────────────────────────────

def fetch_source_file(repo, sha, filepath):
    """Fetch a source file at a specific commit."""
    safe_name = f"{repo.replace('/', '_')}_{sha[:12]}_{filepath.replace('/', '_')}"
    cache_file = CACHE_DIR / safe_name
    if cache_file.exists():
        return cache_file.read_text()

    # Fetch parent commit's version (pre-fix)
    url = f"https://raw.githubusercontent.com/{repo}/{sha}~1/{filepath}"
    content = fetch_text(url)
    if content:
        cache_file.write_text(content)
    time.sleep(GITHUB_DELAY)
    return content


# ── Tree-sitter Analysis ─────────────────────────────────────────────

PY_LANG = ts.Language(tspython.language())
JS_LANG = ts.Language(tsjs.language())


def get_parser(language):
    if language == "python":
        return ts.Parser(PY_LANG)
    elif language == "javascript":
        return ts.Parser(JS_LANG)
    raise ValueError(f"Unsupported language: {language}")


def get_function_ranges(source_code, language):
    """Parse source code and return all function definitions with their line ranges.
    
    Returns: list of (name, start_line_1indexed, end_line_1indexed)
    """
    parser = get_parser(language)
    tree = parser.parse(source_code.encode())
    functions = []

    def walk(node, class_name=None):
        if language == "python":
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    fn_name = name_node.text.decode()
                    if class_name:
                        fn_name = f"{class_name}.{fn_name}"
                    functions.append((
                        fn_name,
                        node.start_point[0] + 1,  # 1-indexed
                        node.end_point[0] + 1,
                    ))
            elif node.type == "class_definition":
                name_node = node.child_by_field_name("name")
                cls_name = name_node.text.decode() if name_node else None
                for child in node.children:
                    walk(child, class_name=cls_name)
                return  # don't recurse further for class
        elif language == "javascript":
            if node.type in ("function_declaration", "method_definition"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    functions.append((
                        name_node.text.decode(),
                        node.start_point[0] + 1,
                        node.end_point[0] + 1,
                    ))
            elif node.type == "variable_declarator":
                # const name = function() or const name = () =>
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node and value_node and value_node.type in (
                    "function_expression", "arrow_function"
                ):
                    functions.append((
                        name_node.text.decode(),
                        node.start_point[0] + 1,
                        node.end_point[0] + 1,
                    ))

        for child in node.children:
            walk(child, class_name)

    walk(tree.root_node)
    return functions


def find_enclosing_function(functions, line_number):
    """Find the innermost function that contains the given line number."""
    enclosing = None
    for name, start, end in functions:
        if start <= line_number <= end:
            if enclosing is None or (end - start) < (enclosing[2] - enclosing[1]):
                enclosing = (name, start, end)
    return enclosing


# ── Main ──────────────────────────────────────────────────────────────

def analyze_advisory(vuln_id, target_function, language):
    """Analyze one advisory: fetch diff, parse it, compare regex vs tree-sitter."""
    print(f"\n{'─' * 60}")
    print(f"  {vuln_id} | target: {target_function} | lang: {language}")
    print(f"{'─' * 60}")

    # Step 1: Get commit URLs
    commits = get_ghsa_commit_urls(vuln_id)
    if not commits:
        print(f"  ⚠ No commit URLs found for {vuln_id}")
        return None

    print(f"  Found {len(commits)} commit(s)")

    results = []

    for commit in commits[:2]:  # limit to first 2 commits
        repo = commit["repo"]
        sha = commit["sha"]
        print(f"  Commit: {repo}@{sha[:12]}")

        # Step 2: Fetch diff
        diff_text = get_commit_diff(repo, sha)
        if not diff_text:
            print(f"  ⚠ Could not fetch diff")
            continue

        # Step 3: Parse diff
        files = parse_diff(diff_text, target_function, language)
        if not files:
            print(f"  ⚠ No source files in diff")
            continue

        for fentry in files:
            filename = fentry["filename"]
            print(f"  File: {filename}")

            for hunk in fentry["hunks"]:
                header_func = hunk["header_function"]
                modified_lines = hunk["modified_lines"]
                del_lines = [ml for ml in modified_lines if ml["type"] == "del"]

                if not del_lines:
                    continue

                # Step 4: Fetch pre-commit source
                source = fetch_source_file(repo, sha, filename)
                if not source:
                    print(f"    ⚠ Could not fetch pre-commit source")
                    continue

                # Step 5: Parse with tree-sitter
                functions = get_function_ranges(source, language)

                # Step 6: For each deleted line, find enclosing function
                for ml in del_lines:
                    pre_line = ml["pre_line"]
                    if pre_line is None:
                        continue

                    enclosing = find_enclosing_function(functions, pre_line)
                    ast_func = enclosing[0] if enclosing else None

                    # Does this relate to our target function?
                    if header_func == target_function or (ast_func and target_function in (ast_func, ast_func.split(".")[-1])):
                        result = {
                            "vuln_id": vuln_id,
                            "file": filename,
                            "line": pre_line,
                            "hunk_header_func": header_func,
                            "ast_enclosing_func": ast_func,
                            "line_content": ml["content"][:80],
                            "match": header_func == (ast_func.split(".")[-1] if ast_func and "." in ast_func else ast_func),
                        }
                        results.append(result)
                        print(f"    L{pre_line}: hunk='{header_func}' → AST='{ast_func}' "
                              f"{'✓ match' if result['match'] else '✗ MISMATCH'}")

    return results


def main():
    # Load validation samples
    rows = list(csv.DictReader(open(SAMPLES_FILE, encoding="utf-8-sig")))

    print("=" * 60)
    print("TREE-SITTER PoC — Hunk-Header Misattribution Validation")
    print("=" * 60)

    # ── Phase A: Hunk-header noise cases ──────────────────────────────
    print("\n\n▶ PHASE A: Hunk-Header Noise Cases (6 targets)")
    print("  Expectation: tree-sitter should identify a DIFFERENT enclosing")
    print("  function than the hunk header, validating filter F5.\n")

    noise_results = []
    for vuln_id, info in ADVISORY_COMMITS.items():
        # Find the target function name from validation samples
        sample = next((r for r in rows if r["vuln_id"] == vuln_id
                       and r.get("reasoning", "").lower().find("hunk") >= 0), None)
        if not sample:
            sample = next((r for r in rows if r["vuln_id"] == vuln_id), None)
        if not sample:
            print(f"  ⚠ {vuln_id} not found in samples")
            continue

        target_fn = sample["function_name"].strip()
        lang = info["language"]
        result = analyze_advisory(vuln_id, target_fn, lang)
        if result:
            noise_results.extend(result)

    # ── Phase B: Control cases ────────────────────────────────────────
    print("\n\n▶ PHASE B: Control Cases (14 targets)")
    print("  Expectation: tree-sitter should AGREE with regex.\n")

    control_results = []
    for case in CONTROL_CASES:
        vuln_id = case["vuln_id"]
        lang = case["language"]
        sample = next((r for r in rows if r["vuln_id"] == vuln_id), None)
        if not sample:
            print(f"  ⚠ {vuln_id} not found in samples")
            continue

        target_fn = sample["function_name"].strip()
        result = analyze_advisory(vuln_id, target_fn, lang)
        if result:
            control_results.extend(result)

    # ── Summary ───────────────────────────────────────────────────────
    print("\n\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    print(f"\nNoise cases analyzed: {len(noise_results)}")
    mismatches = [r for r in noise_results if not r["match"]]
    print(f"  Hunk-header ≠ AST (mismatches): {len(mismatches)}")
    for r in mismatches:
        print(f"    {r['vuln_id']}: hunk='{r['hunk_header_func']}' → AST='{r['ast_enclosing_func']}'")

    print(f"\nControl cases analyzed: {len(control_results)}")
    agreements = [r for r in control_results if r["match"]]
    print(f"  Hunk-header = AST (agreements): {len(agreements)}")
    disagreements = [r for r in control_results if not r["match"]]
    if disagreements:
        print(f"  Disagreements: {len(disagreements)}")
        for r in disagreements:
            print(f"    {r['vuln_id']}: hunk='{r['hunk_header_func']}' → AST='{r['ast_enclosing_func']}'")

    # Save results
    output_file = EVAL_DIR / "treesitter_poc" / "results.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    all_results = {
        "noise_cases": noise_results,
        "control_cases": control_results,
        "summary": {
            "noise_analyzed": len(noise_results),
            "noise_mismatches": len(mismatches),
            "control_analyzed": len(control_results),
            "control_agreements": len(agreements),
            "control_disagreements": len(disagreements),
        }
    }
    output_file.write_text(json.dumps(all_results, indent=2))
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    main()
