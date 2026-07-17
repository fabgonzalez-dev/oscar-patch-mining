# Reproducibility Manifest — SCORED 2026 Patch Mining

Maps every table, figure, and headline number in `main.tex` to the data file(s)
and script that produce it. An automated guard (`check_consistency.py`)
re-derives all of these and asserts they appear in `main.tex`.

Paths are relative to `oscar-patch-mining/`. Full-corpus extraction CSVs share the
schema in `data/README.md`; Project KB uses its own schema.

---

## How to reproduce / verify

```bash
cd oscar-patch-mining/evaluation

# 1. Rebuild the canonical n=104 precision set from the two raw label files
python3 merge_precision_samples.py            # -> precision_validation_samples_n104.csv

# 2. (optional) regenerate the Project KB temporal analysis from real commit dates
GITHUB_TOKEN=<token> python3 regenerate_temporal.py --source api   # -> commit_dates_cache.csv

# 3. Apply noise filters to the corpus
python3 apply_filters_corpus.py                # prints corpus-level filter stats

# 4. Compute recall estimates
python3 compute_recall_extended.py             # -> recall_study_results.json

# 5. Run held-out filter validation on Java
python3 filter_held_out.py                     # -> filter_held_out_results.json

# 6. Run the consistency guard (re-derives every headline number, checks main.tex)
python3 check_consistency.py                   # exit 0 = paper matches data

# (tree-sitter PoC requires tree-sitter installed; results cached in treesitter_poc/results.json)
# python3 treesitter_poc.py                    # -> treesitter_poc/results.json
```

`scored_evaluation.py` regenerates `data/project_kb_java_extraction.csv` and the
Study-2 summary; `generate_validation_samples.py` holds the confidence-tier logic
(`assign_confidence`, paper §3.3).

---

## Artifact → source map

### RQ1 — Precision (§4.2)

| Artifact | Value(s) | Data source | Producer |
|---|---|---|---|
| Table 2 | 58 / 20 / 26 → 55.8% / 75.0% | `evaluation/precision_validation_samples_n104.csv` | `merge_precision_samples.py` (from `precision_validation_samples.csv` + `..._extra.csv`) |
| Table 3 (tiers) | High 82.9%/92.7% (n=41); Med 47.6%/76.2% (n=42); Low 19.0%/38.1% (n=21) | same n=104 file (`confidence` column) | same |
| Statistical-note Wilson CIs | strict [46.6,65.3], relaxed [66.2,82.5], High [69.4,91.7] | same | inline Wilson (see `check_consistency.py`) |
| Cohen's κ = 0.583 | 15 samples, 4 disagreements | `evaluation/irr_coding_sheet.csv` ⋈ `precision_validation_samples.csv` (case-insensitive on `vuln_id`+`function_name`) | `check_consistency.py` |
| "13 of 133 (9.8%)" High filter | 13 High / 29 Med / 91 Low | `data/ghsa_study1_precision_corpus.csv` | `assign_confidence()` in `generate_validation_samples.py` |
| Java spot-check | 55.0% / 75.0% (n=20) | `evaluation/java_precision_validation.csv` | — |

### Dataset / Table 1 (§4.1)

| Artifact | Value(s) | Data source | Producer |
|---|---|---|---|
| Table 1 Study 1 | 92 adv / 90 fetched (98%) / 88 extr (96%) / 3,648 fns / median 2 | distinct advisories of `precision_validation_samples_n104.csv` ⋈ `data/ghsa_full_{npm,pypi}_extraction.csv` | `check_consistency.py` |
| Table 1 Study 2 | 1,248 / 1,109 (89%) / 954 (76%) / 8,069 / median 4 | `data/project_kb_java_extraction.csv` | `scored_evaluation.py` |
| Figure 2 (funnel) | Study 1 98/96; Study 2 89/76 | same as Table 1 | — |
| Severity 9/39/40/4; 39 npm/53 PyPI | per distinct advisory | `precision_validation_samples_n104.csv` | — |

### RQ2 — Coverage (§4.3)

| Artifact | Value(s) | Data source | Producer |
|---|---|---|---|
| Table 5 | Java 1,248/1,109/86.0%; npm 6,780/3,667/49.9%; PyPI 5,640/3,682/83.0%; Combined 13,668/8,458/69.0% | `data/ghsa_full_{npm,pypi}_extraction.csv`, `data/project_kb_java_extraction.csv` | `data/ghsa_full_corpus_summary.txt` |
| Function-count dist | 582 / 286 / 86 (over 954) | `data/project_kb_java_extraction.csv` | `scored_evaluation.py` |
| Table 6 + Figure 6 (temporal) | eras 92 / 409 / 747; 44.6% → 66.0% → 86.1% | `evaluation/commit_dates_cache.csv` ⋈ `data/project_kb_java_extraction.csv` | `regenerate_temporal.py --source api` |
| Struts CVE-2008-6505 = 10 fns | | `data/project_kb_java_extraction.csv` | — |

### RQ3 — Failures (§4.4)

| Artifact | Value(s) | Data source | Producer |
|---|---|---|---|
| Table 4 | 139 no-diff + 155 fetched-no-extract = 294 | `data/project_kb_java_extraction.csv` | `scored_evaluation.py` |
| "14.0% failed after fetch" | 155 / 1,109 | same | — |

### Noise Filters (§5.4)

| Artifact | Value(s) | Data source | Producer |
|---|---|---|---|
| Table 7 (filter-precision) | Strict 55.8% → 72.5%; Relaxed 75.0% → 95.0% | `evaluation/precision_validation_samples_n104.csv` | `evaluation/noise_filter.py` |
| Corpus-level reduction | npm 3,276/8,769 (37.4%); PyPI 22,153/32,197 (68.8%) | `data/ghsa_full_{npm,pypi}_extraction.csv` | `evaluation/apply_filters_corpus.py` |
| Held-out Java validation | 55.0% → 52.6% (n=19) | `evaluation/java_precision_validation.csv` | `evaluation/filter_held_out.py` → `filter_held_out_results.json` |
| Tree-sitter PoC | 4 noise corrected, 8/14 controls agreed, 6 improved | `evaluation/treesitter_poc/results.json` | `evaluation/treesitter_poc.py` (cache in `treesitter_poc/cache/`, gitignored) |

### Recall Estimation (§5.6)

| Artifact | Value(s) | Data source | Producer |
|---|---|---|---|
| At-least-one recall | 25/44 = 56.8% | `evaluation/recall_study_samples_extended.csv` | `evaluation/compute_recall_extended.py` → `recall_study_results.json` |
| Aggregate recall | 32/114 = 28.1% | same | same |
| 12 advisories with 100% recall | single-function fixes | same | same |

### Reachability (§5.5) + qs walkthrough (§3.6)

| Artifact | Value(s) | Data source | Producer |
|---|---|---|---|
| top-20 export; 9 with / 4 without call graphs | | `oscar-research-data/data/method_hotspots.csv` (20 rows/package) | — |
| 15 of 133 matched; 15/15 reachable (`fan_in ≥ 1`) | | `method_hotspots.csv` ⋈ `data/ghsa_study1_precision_corpus.csv` (`num_in_call_graph`) | — |
| qs `parseObject` `fan_in` = 1 | | `method_hotspots.csv` (package=`qs`) | — |

### Scale / Discussion (§2, §5)

| Artifact | Value(s) | Data source |
|---|---|---|
| 13,668-advisory corpus / 49,035 functions | 6,780 + 5,640 + 1,248 advisories; 8,069 + 8,769 + 32,197 functions | the three extraction CSVs |
| Link rates 54% npm / 65% PyPI | | `data/ghsa_full_{npm,pypi}_extraction.csv` |
| LLM cost \$137–410 | 13,668 × \$0.01–0.03/diff (footnoted assumption) | arithmetic |

---

## Not machine-reproducible (external / documented assumptions)

- **GHSA full-DB size** ("tens of thousands"): external GitHub Advisory API snapshot (May 2026), footnoted; only the processed 13,668 is in-repo.
- **LLM per-diff price** (\$0.01–0.03): footnoted estimate (commercial pricing ~\$3–5 / M tokens, ~3–6K tokens/diff), volatile.
- **Go**: patterns implemented, not evaluated (no artifact) — stated as future work.
- **"15/15 reachable" BFS verdict**: substantiated via `fan_in ≥ 1` in the hot-spot export; the platform's BFS verdicts are not exported as a column.
