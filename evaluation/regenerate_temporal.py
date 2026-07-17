#!/usr/bin/env python3
"""
Regenerate the Project KB temporal analysis (Table 6 + Figure 6) from REAL
fix-commit dates — the "route 2" fix for consistency-report finding B4.

Why: the drafted Table 6 / Figure 6 could not be reproduced from
`project_kb_java_extraction.csv` (it has no date column) and the era counts
did not match the data. This script recovers the commit year for each entry
from the fix-commit SHA recorded in the SAP Project KB statement YAMLs, bins
by commit era, and emits the LaTeX for Table 6, the Figure 6 coordinates,
and the prose numbers.

Coverage (measured): 1,227 / 1,248 entries (98.3%) have a parseable
(repo, sha); ~1,166 are on github.com (datable via the GitHub API). The
remaining legacy-host / unmapped entries fall back to CVE-assignment year
(flagged `date_source=cve_fallback`).

USAGE
  # dry run — no network, uses CVE year for every entry (validates the
  # table-generation pipeline and reproduces the CVE-year proxy):
  python3 regenerate_temporal.py --source cve

  # real run — fetch commit dates from GitHub (recommended: with a token
  # for 5000 req/hr instead of 60). Resumable via the on-disk cache.
  GITHUB_TOKEN=<your_token> python3 regenerate_temporal.py --source api

Outputs:
  - commit_dates_cache.csv     (vuln_id, repo, sha, commit_date, year, source)
  - temporal_regenerated.md    (copy-paste LaTeX for Table 6 + Fig 6 + prose)
"""
import argparse, csv, glob, os, re, ssl, sys, time, json
from collections import Counter, defaultdict
from pathlib import Path

# macOS / venv Pythons often lack a usable CA bundle -> SSL CERTIFICATE_VERIFY_FAILED.
# Prefer certifi's bundle; fall back to the system default context.
try:
    import certifi
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
    _CERTIFI = True
except Exception:
    SSL_CTX = ssl.create_default_context()
    _CERTIFI = False

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent                       # repo root
STMT_DIR = REPO_ROOT / "oscar-research-data/external/project-kb/statements"
KB_CSV = HERE.parent / "data/project_kb_java_extraction.csv"
CACHE = HERE / "commit_dates_cache.csv"
OUT = HERE / "temporal_regenerated.md"

ERAS = [("2005--2013", 2005, 2013), ("2014--2017", 2014, 2017), ("2018--2022", 2018, 2022)]


# ---------- statement YAML -> (repo, first commit sha) ----------
def load_statement_map():
    m = {}
    for p in glob.glob(str(STMT_DIR / "*" / "statement.yaml")):
        cve = os.path.basename(os.path.dirname(p))
        txt = open(p).read()
        sha = re.search(r"commits:\s*\n\s*-\s*id:\s*([0-9a-fA-F]{7,40})", txt)
        repo = re.search(r"repository:\s*(\S+)", txt)
        if sha and repo:
            m[cve] = (repo.group(1).strip().rstrip("/"), sha.group(1))
    return m


def cve_year(vuln_id):
    mo = re.search(r"CVE-(\d{4})", vuln_id or "")
    return int(mo.group(1)) if mo else None


def owner_repo(url):
    mo = re.search(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$", url or "")
    return (mo.group(1), mo.group(2)) if mo else None


# ---------- commit date via GitHub API ----------
def fetch_commit_year_api(url, sha, token):
    import urllib.request, urllib.error
    orp = owner_repo(url)
    if not orp:
        return None, None  # non-github host -> caller falls back
    api = f"https://api.github.com/repos/{orp[0]}/{orp[1]}/commits/{sha}"
    req = urllib.request.Request(api, headers={"User-Agent": "patchmining-temporal"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30, context=SSL_CTX) as r:
            data = json.load(r)
        date = data["commit"]["committer"]["date"]  # e.g. 2018-08-17T15:39:56Z
        return date, int(date[:4])
    except urllib.error.HTTPError as e:
        if e.code == 403:  # rate limit
            reset = e.headers.get("X-RateLimit-Reset")
            if reset:
                wait = max(0, int(reset) - int(time.time())) + 2
                print(f"  rate-limited; sleeping {wait}s...", file=sys.stderr)
                time.sleep(wait)
                return fetch_commit_year_api(url, sha, token)
        if not getattr(fetch_commit_year_api, "_warned", False):
            hint = "expired/invalid token or missing 'repo'/'contents' scope" if e.code == 401 else "see status"
            print(f"  !! GitHub API HTTP {e.code} (e.g. {url}@{sha[:7]}) -- {hint}. "
                  f"Further API errors suppressed.", file=sys.stderr)
            fetch_commit_year_api._warned = True
        return None, None
    except Exception as e:
        if not getattr(fetch_commit_year_api, "_warned2", False):
            extra = ""
            if "CERTIFICATE_VERIFY" in str(e):
                extra = " -> SSL cert issue: run `pip install certifi` in this venv, then retry."
            print(f"  !! network error ({type(e).__name__}: {e}).{extra} "
                  f"Further errors suppressed.", file=sys.stderr)
            fetch_commit_year_api._warned2 = True
        return None, None


def load_cache():
    if not CACHE.exists():
        return {}
    return {r["vuln_id"]: r for r in csv.DictReader(open(CACHE, newline=""))}


def save_cache(cache):
    with open(CACHE, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["vuln_id", "repo", "sha", "commit_date", "year", "source"])
        w.writeheader()
        for r in cache.values():
            w.writerow(r)


def build_years(rows, source, token):
    stmt = load_statement_map()
    cache = load_cache()
    years, srcs = {}, {}
    for i, r in enumerate(rows):
        vid = r["vuln_id"]
        # reuse ONLY real commit dates from cache; always retry fallbacks on --source api
        if vid in cache and cache[vid].get("source") == "commit" and cache[vid].get("year"):
            years[vid] = int(cache[vid]["year"]); srcs[vid] = cache[vid]["source"]; continue
        y = src = date = None
        if source == "api" and vid in stmt:
            repo, sha = stmt[vid]
            date, y = fetch_commit_year_api(repo, sha, token)
            if y:
                src = "commit"
            if i % 25 == 0:
                print(f"  [{i}/{len(rows)}] {vid} -> {y or 'fallback'}", file=sys.stderr)
        if y is None:                       # fallback
            y = cve_year(vid); src = "cve_fallback"
        years[vid] = y; srcs[vid] = src
        repo, sha = stmt.get(vid, ("", ""))
        cache[vid] = {"vuln_id": vid, "repo": repo, "sha": sha,
                      "commit_date": date or "", "year": y, "source": src}
    save_cache(cache)
    return years, srcs


# ---------- table + figure generation ----------
def fetched(r):  return str(r["commits_processed"]).strip() not in ("", "0", "nan")
def extr(r):     return str(r["num_functions"]).strip() not in ("", "0", "nan")


def selftest(token):
    for cve, (repo, sha) in load_statement_map().items():
        if "github.com" in repo:
            print(f"self-test: {cve}  {repo}@{sha[:10]}", file=sys.stderr)
            date, y = fetch_commit_year_api(repo, sha, token)
            if y:
                print(f"  SUCCESS: commit date {date} (year {y}). Token works -> "
                      f"delete commit_dates_cache.csv, then run --source api.", file=sys.stderr)
            else:
                print("  FAILED: no date returned (see the error above). "
                      "Fix the token/network, then retry.", file=sys.stderr)
            return
    print("  no github-hosted entry available for self-test.", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["cve", "api"], default="cve",
                    help="cve = CVE-year proxy, no network (dry run); api = real commit dates")
    ap.add_argument("--selftest", action="store_true",
                    help="fetch ONE commit date and report the raw result (token/network check)")
    args = ap.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    print(f"  GITHUB_TOKEN {'set (len=%d)' % len(token) if token else 'NOT SET'}", file=sys.stderr)
    print(f"  TLS CA bundle: {'certifi' if _CERTIFI else 'system default'}", file=sys.stderr)
    if args.selftest:
        selftest(token); return
    if args.source == "api" and not token:
        print("WARNING: no GITHUB_TOKEN set; GitHub API allows only ~60 req/hr.", file=sys.stderr)

    rows = list(csv.DictReader(open(KB_CSV, newline="")))
    years, srcs = build_years(rows, args.source, token)
    src_counts = Counter(srcs.values())

    lines = []
    lines.append(f"# Temporal analysis regenerated (source: {args.source})\n")
    lines.append(f"Date source mix: {dict(src_counts)}  (total {len(rows)})\n")

    # Era table
    lines.append("\n## Table 6 (LaTeX body)\n```")
    tot_e = tot_f = tot_x = 0
    for name, lo, hi in ERAS:
        grp = [r for r in rows if (y := years.get(r["vuln_id"])) and lo <= y <= hi]
        e = len(grp); fe = sum(fetched(r) for r in grp); xe = sum(extr(r) for r in grp)
        rate = xe / e * 100 if e else 0
        tot_e += e; tot_f += fe; tot_x += xe
        fp = fe/e*100 if e else 0; xp = xe/fe*100 if fe else 0  # With Extr. = % of fetchable
        lines.append(f"        {name} & {e} & {fe} ({fp:.0f}\\%) & {xe} ({xp:.0f}\\%) & {rate:.1f}\\% \\\\")
    ar = tot_x/tot_e*100 if tot_e else 0
    lines.append("        \\midrule")
    lines.append(f"        All & {tot_e:,} & {tot_f:,} ({tot_f/tot_e*100:.0f}\\%) & {tot_x} ({tot_x/tot_e*100:.0f}\\%) & {ar:.1f}\\% \\\\".replace(",", "{,}"))
    lines.append("```")

    # Per-year series for Figure 6
    by_year = defaultdict(lambda: [0, 0, 0])  # entries, fetchable, extracted
    for r in rows:
        y = years.get(r["vuln_id"])
        if not y: continue
        by_year[y][0] += 1; by_year[y][1] += fetched(r); by_year[y][2] += extr(r)
    lines.append("\n## Figure 6 coordinates\n```")
    fcoords = " ".join(f"({y},{v[1]/v[0]*100:.0f})" for y, v in sorted(by_year.items()) if v[0])
    xcoords = " ".join(f"({y},{v[2]/v[0]*100:.0f})" for y, v in sorted(by_year.items()) if v[0])
    lines.append("% fetchable %:\n" + fcoords)
    lines.append("% with-extraction %:\n" + xcoords)
    lines.append("```")

    # Prose numbers
    since14 = [r for r in rows if (y := years.get(r["vuln_id"])) and y >= 2014]
    x14 = sum(extr(r) for r in since14)
    post17 = [r for r in rows if (y := years.get(r["vuln_id"])) and y >= 2018]
    x17 = sum(extr(r) for r in post17)
    lines.append("\n## Prose numbers")
    lines.append(f"- since 2014: {len(since14)} entries, extraction rate {x14/len(since14)*100:.1f}%")
    lines.append(f"- 2018--2022: {len(post17)} entries, extraction rate {x17/len(post17)*100:.1f}%")

    OUT.write_text("\n".join(lines))
    print("\n".join(lines))
    print(f"\nWrote {OUT}  (cache: {CACHE})", file=sys.stderr)


if __name__ == "__main__":
    main()
