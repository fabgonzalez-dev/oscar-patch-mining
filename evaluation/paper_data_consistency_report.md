# SCORED 2026 Patch Mining — `main.tex` vs. Raw Data Consistency Report

**Paper:** *From Fix Commits to Vulnerable Functions: Automated Patch Mining for Function-Level CVE Resolution*
**Sources cross-referenced:** `oscar-patch-mining/evaluation/*.csv`, `oscar-patch-mining/data/*.csv`, and the `*_summary.txt` files.
**Bottom line:** The large-scale coverage numbers (Study 2 / full GHSA corpus) are fully reproducible from the data. The **precision study (RQ1) is reported inconsistently at two sample sizes (n=50 and n=105) in the same paper**, and the **Project KB temporal analysis (Table 6 / Fig. 6) and the failure-mode table (Table 4) do not reconcile with the data**. Details below.

---

## Applied fixes (update)

The **n=104 dedup has been applied**. Canonical data: `precision_validation_samples_n104.csv` (58 / 20 / 26; the two source files retained as inputs; the n=105 intermediate removed). All precision references in `main.tex` were updated to n=104 — **55.8% strict / 75.0% relaxed**, High **82.9% / 92.7%**, Table 3 re-derived, statistical-note Wilson CIs updated, severity corrected to **9/39/40/4**, and the failure-mode paragraph re-tallied over all **26** noise samples (7 modes, led by hunk-header misattribution). This resolves **B1** (dual n=50/n=105 reporting) and **B2** (the "100% High-confidence" claim → 82.9%).

**P1.2 reconstruction (done):** running the pipeline's own `assign_confidence()` over the 133 Study-1 functions yields **13 High (9.8%)**, not the drafted "78 (58%)" — which was structurally impossible (High requires a single-function advisory, and only 13 of the 31 extracting advisories qualify). The paper now reads "13 of 133 (9.8%)", and the surrounding precision–coverage prose ("near-zero false positives") was softened accordingly.

**Also resolved:** **B4** (temporal Table 6 / Fig 6 regenerated from real commit dates via `regenerate_temporal.py` — eras 92/409/747, extraction 44.6%→66.0%→86.1%, all rows now reconcile), **B5** (failure Table 4 collapsed to the two verified buckets, 139 + 155 = 294, sub-reasons moved to prose), and **B6** (§RQ3 "21.0%" → **14.0%**).

**Also resolved:** **B3** (Table 1 Study 1 aligned to the 92-advisory precision frame — 90/88/3,648/median 2; the reachability sub-study's 133 functions relabeled as a separate 45-advisory subset).

**Also resolved (P1.5):** reachability sub-study verified against `method_hotspots.csv` — the top-20 export, the 9-with / 4-without call-graph split, the 15-of-133 match count, and 15/15 reachability (all matches have `fan_in ≥ 1`) are confirmed. The qs walkthrough was corrected (`parseObject` `fan_in` = 1, not 3; the unverifiable "47 functions" dropped).

**Also resolved (P1.7):** GHSA-scale reframed on the real 13,668-advisory corpus (removed the inconsistent "over 600 PyPI / 23,500+ / 29–39%"; cites measured 54%/65% link rates). Caught a missed n=104 fix — the approach-comparison table precision "60–78%" → **56–75%** (scale 23,500+ → 13,668), and LLM cost recomputed to $137–410. Go claim softened (no artifact exists).

**Also resolved (P3):** `REPRODUCIBILITY.md` (artifact→source map) and `check_consistency.py` (re-derives the headline numbers and checks `main.tex`; **28/28 pass**).

**Status: complete.** All identified inconsistencies (B1–B6) and follow-ups (P1.2, P1.5, P1.7, P3) are resolved and reflected in `main.tex`, verified by the guard. The only remaining figures are external/documented assumptions (GHSA full-DB size, LLM pricing, Go).

---

## A. Verdict summary

| Area | Status |
|---|---|
| Full GHSA corpus extraction (Table 5, abstract coverage) | ✅ Consistent |
| Study 2 coverage totals (Table 1 Study 2, §RQ2, function-count dist.) | ✅ Consistent |
| Combined precision headline n=105 (abstract, contributions, Table 2, conclusion) | ✅ Consistent |
| Study 1 advisory/severity/ecosystem descriptors (92; 39/53; 9/40/40/3) | ✅ Consistent |
| Java cross-ecosystem precision (n=20) | ✅ Consistent |
| Cohen's κ = 0.583, 4 disagreements, 15 samples | ✅ Consistent (case-insensitive) |
| Reachability match count (15/133) & Struts example (10 fn) | ✅ Consistent |
| **Precision reported at n=50 in parts of the paper (Table 3, §RQ1 bullets, Finding 1, statistical note, discussion)** | ❌ **Inconsistent with the n=105 headline** |
| **"High-confidence = 100% strict precision (n=20)"** | ❌ **Not supported by full data (35/42 = 83.3%)** |
| **Table 1 Study 1 "Total advisories 92" with 71%/69% rates** | ❌ **Internally inconsistent (rates use denominator 45)** |
| **Temporal Table 6 & Figure 6** | ❌ **Not reproducible from cited file; era counts contradict data** |
| **Failure Table 4 (Study 2 column)** | ❌ **Rows sum to 314, not stated 294; contradicts summary's 155 split** |
| **§RQ3 "failed only in 21.0% [after fetch]"** | ❌ **Data gives 14.0%** |
| Reachability "13 packages in the corpus" | ⚠️ Minor (data shows 19 distinct packages) |
| GHSA scale (23,500+ etc.), qs walkthrough internals, Go, LLM cost, cited-paper stats | ⓘ External / illustrative — not in data files |

---

## B. Critical inconsistencies (must fix before submission)

### B1. The precision study is reported at TWO sample sizes at once (n=50 vs n=105)

The two validation files combine as: `precision_validation_samples.csv` (50) + `precision_validation_samples_extra.csv` (55) = **105 samples across 92 distinct advisories**. Both computations below are individually correct for their sample; the paper mixes them.

| Quantity | n=50 subset (data) | n=105 full set (data) | Where the paper uses each |
|---|---|---|---|
| Central / Tangential / Noise | 30 / 9 / 11 | 59 / 20 / 26 | n=105 → Table 2, abstract, contributions, conclusion. n=50 → §RQ1 bullets, Table 3, statistical note |
| Strict precision | 30/50 = **60.0%** | 59/105 = **56.2%** | Both appear |
| Relaxed precision | 39/50 = **78.0%** | 79/105 = **75.2%** | Both appear |
| High tier | 20/20 = **100% / 100%** (n=20) | 35/42 = **83.3% / 92.9%** (n=42) | 100% in Finding 1 & discussion; 83.3% in conclusion |
| Medium tier | 7/20 = 35.0% / 70.0% | 20/42 = 47.6% / 76.2% | n=50 in Table 3 |
| Low tier | 3/10 = 30.0% / 50.0% | 4/21 = 19.0% / 38.1% | n=50 in Table 3 |

The clearest symptom: immediately **after** presenting Table 2 (which is the n=105 count 59/20/26), the text computes "Strict precision: 30/50 = 60.0%" and "Relaxed: 39/50 = 78.0%" — i.e., it switches to n=50 in the same subsection. Table 3, the statistical-note Wilson CIs, Finding 1, and the Discussion all remain on n=50; the abstract, contributions, Table 2, and conclusion are on n=105.

**Fix:** pick n=105 (the complete set) and update every derived figure. Corrected n=105 tier table and Wilson 95% CIs:

| Tier | # | Cen | Tang | Noise | Strict | Relaxed | Strict 95% CI |
|---|---|---|---|---|---|---|---|
| High | 42 | 35 | 4 | 3 | 83.3% | 92.9% | [69.4, 91.7] |
| Medium | 42 | 20 | 12 | 10 | 47.6% | 76.2% | [33.4, 62.3] |
| Low | 21 | 4 | 4 | 13 | 19.0% | 38.1% | [7.7, 40.0] |
| **Overall** | **105** | **59** | **20** | **26** | **56.2%** | **75.2%** | strict [46.6, 65.3]; relaxed [66.2, 82.5] |

### B2. "High-confidence extractions achieve 100% strict precision" is not supported by the full data

This claim appears in **Finding 1** ("100% strict precision (n=20)"), the **Discussion** ("100% strict precision (n=20)"), and §RQ1. It holds only for the original 50-sample subset (High = 20/20). In the complete 105-sample set, **High = 35/42 = 83.3% strict** (92.9% relaxed). The **conclusion already states 83.3%**, directly contradicting the Finding 1 box in the same paper. Because "100% high-confidence precision → suitable for automated filtering" is a headline selling point, this must be reconciled to 83.3% (or the paper must explicitly restrict the claim to the n=50 subset and justify why).

### B3. Table 1, Study 1 column — "Total advisories 92" is inconsistent with its own rates

- Data: the 92 figure is the count of **distinct advisories** across the 105 validation samples (confirmed: 92 distinct `vuln_id`; ecosystem 39 npm / 53 PyPI; severity 9 Critical / 40 High / 40 Moderate / 3 Low — all match the paper's Study 1 description exactly).
- But Table 1's "Fix diffs fetched 32 (71%)" and "With extractions 31 (69%)" use denominator **45**, not 92 (32/45 = 71%, 31/45 = 69%). These, plus "Functions extracted 133" and "Avg 4.3," come from `ghsa_study1_precision_corpus.csv` (a **45-advisory**, 133-function file; ecosystem 23 npm / 22 PyPI).
- So Table 1 blends a 92-advisory set (header, ecosystem, severity) with a 45-advisory set (fetched/extraction/function rows). With header = 92, the 71%/69% are wrong (should be 35%/34%); the percentages are only correct if the denominator is 45.
- Also note `data/README.md` states the 45-corpus has **41** fix-commit links, whereas Table 1 says **32** fetched — a second, smaller mismatch on that row.

**Fix:** state clearly that 105 function-level samples were drawn from 92 advisories for validation, and separate that from the 45-advisory/133-function extraction corpus. Recompute the "fetched"/"extraction" percentages against whichever denominator you actually mean.

### B4. Temporal analysis (Table 6 & Figure 6) is not reproducible from the cited file

- Figure 6's caption says values are "exact values from `project_kb_java_extraction.csv`," but **that file has no date/year/commit-date column** (schema: `vuln_id, repo, packages, num_commits_kb, commits_processed, functions_extracted, num_functions`).
- Using the only available date proxy (year parsed from the CVE ID), the era **entry counts do not match** the paper at all:

| Era | Paper (Table 6) entries / fetchable / w-extr | Data by CVE-year entries / fetchable / w-extr |
|---|---|---|
| 2005–2013 | 312 / 173 / 136 | 95 / 56 / 44 |
| 2014–2017 | 381 / 362 / 316 | 409 / 313 / 269 |
| 2018–2022 | 555 / 554 / 502 | 744 / 740 / 641 |
| All | 1248 / 1109 / 954 | 1248 / 1109 / 954 |

- The era totals reconcile only on the *All* row. The paper's fetchable sub-rows (173+362+554 = **1089**) do not even sum to 1109 (the with-extraction sub-rows 136+316+502 = 954 do sum correctly).
- Downstream claims that inherit this split are therefore unverifiable/inconsistent: "90.5% for 2018–2022," "83.1% for the 916 entries since 2014" (text says 916; Table 6 implies 936; CVE-year proxy gives 1153), "above 88% post-2017," and "139 (45%) of the 312 early entries returned 404."

**Fix:** either add the commit-date column to the released CSV and regenerate Table 6/Fig 6 from it, or drop the temporal breakdown. As written it cannot be reproduced from the replication package.

### B5. Failure-mode Table 4 (Study 2 column) does not add up

- Table 4 Study 2 rows: 139 + 80 + 40 + 35 + 20 = **314**, but the stated "Total no-extraction" is **294**.
- The correct total is 294 (= 1248 − 954). The summary file decomposes it as **139 no-diff-fetchable + 155 fetched-but-no-extraction**. Table 4's fetched-but-no-extraction categories sum to 80+40+35+20 = **175 ≠ 155**.
- Study 1 column (2+5+4+3+0 = 14) is internally consistent.

**Fix:** rescale the Study 2 sub-categories so they sum to 155 (fetched-no-extraction) + 139 (no-diff) = 294.

### B6. §RQ3 "the pipeline failed only in 21.0% of [fetched] cases"

Data: fetched-but-no-extraction = 1109 − 954 = 155 → **14.0%** of fetchable (or 12.4% of all 1248). **21.0% is not reproduced** by any denominator in the data.

---

## C. Fully consistent claims (verified against data)

- **Abstract / Table 5 coverage:** Java 1248→1109 fetchable, 86.0% on fetchable; npm 6780→3667, 49.9%; PyPI 5640→3682, 83.0%; Combined 13,668→8,458, 69.0%. All exact. (`ghsa_full_*_extraction.csv`, `ghsa_full_corpus_summary.txt`.)
- **Function totals:** Java 8,069; npm 8,769; PyPI 32,197. Exact.
- **Study 2 (Table 1 / §RQ2):** 1,248 total; 1,109 fetchable (88.9% ≈ 89%); 954 with extraction (76.4% overall, 86.0% on fetchable); avg 8.5; median 4. Function-count distribution 0=294, 1–5=582, 6–20=286, >20=86; the 61.0/30.0/9.0% figures are those counts over the 954 non-zero entries. All exact.
- **Precision headline (n=105):** 59/20/26 → 56.2% strict, 75.2% relaxed. 92 distinct advisories; 39 npm / 53 PyPI; severity 9/40/40/3. All exact.
- **Java precision (n=20):** 11 Central / 4 Tangential / 5 Noise → 55.0% strict, 75.0% relaxed; tiers 10 High / 5 Medium / 5 Low; 5 noise cases. Exact (`java_precision_validation.csv`).
- **Inter-rater:** `irr_coding_sheet.csv` has 15 rows; joining collaborator verdicts to the first-author verdicts (case-insensitive) gives 11/15 agreement, **Cohen's κ = 0.583, 4 disagreements**; "~14%" = 15/105. Exact. (Note: a case-sensitive comparison would wrongly count "Central" vs "central" as 2 extra disagreements → κ=0.438; the released sheet should normalize case.)
- **Reachability:** Σ`num_in_call_graph` over the 45-corpus = **15**, matching "15 of 133 matched." Struts **CVE-2008-6505 = 10 functions** in `project_kb_java_extraction.csv`. (The "15/15 reachable" verdict itself is not stored in the CSV — `reachability_verdicts` is empty — so the 100% figure is not independently checkable from the data provided.)
- **Derived internals:** "31% yield no functions" = 1 − 69% combined ✓; "~two-thirds" ✓; "27× larger" = 1248/45 ✓.

---

## D. External / illustrative claims — grounded disposition (after workspace scan)

These are the claims not directly in `data/` or `evaluation/`. A scan of the wider workspace shows several *can* in fact be made reproducible from artifacts that already exist elsewhere in the repo. Reclassified into three buckets by required action.

### D1. Reproducible now — supporting artifact already exists in-repo

- **"78 of 133 High-confidence functions (58%)." — RESOLVED → 13 of 133 (9.8%).** Ran `assign_confidence()` (`generate_validation_samples.py`) over all 133 Study-1 functions: **13 High / 29 Medium / 91 Low**. The drafted "78 (58%)" was structurally impossible — High requires a single-function advisory and only 13 of the 31 extracting advisories qualify. `main.tex` now reads "13 of 133 (9.8%)". Note the coverage cost of the High filter is far higher than the draft implied (~90% of functions dropped), which is why the neighbouring "near-zero false positives" prose was softened.
- **Reachability: "15 of 133 matched," "top-20 hot spots," "9 of 13 packages."** Call-graph / hot-spot exports exist: `oscar-research-data/data/method_hotspots.csv`, `oscar-research-data-icse/exports/method_hotspots_20260514_*.csv`, `research/data/method_hotspots_20260417_211624.csv`. The "15 matched" already reconciles with the corpus (Σ`num_in_call_graph` = 15); the top-20 scope and the package split are checkable against these hot-spot CSVs. **Action:** verify against the hot-spot export and reference it in the replication package. (The "15/15 reachable" *verdict* still is not stored anywhere machine-readable — see D3.)
- **"13 packages appearing in the Study 1 corpus."** Not external — the corpus has **19** distinct packages. **Action:** correct to 19, or rephrase to "13 packages with candidate call-graph matches."

### D2. Verify-then-attribute — a real source exists; pin it down

- **Walkthrough (CVE-2022-24999 / qs): "47 functions in call graph," "3 inbound edges."** `cve_patch_analysis.csv` (in `oscar-research-data/data/` and `oscar-research-data-icse/exports/`) is the origin of the extraction side, and the call-graph platform underlies the hot-spot exports. The pipeline half (parseObject/parseValues) is reproducible; the two graph-internal figures need the **full** qs@6.9.6 call graph (not the top-20 export). **Action:** reproduce against the call graph and cite the exact package version + source; if not reproducible, relabel as a representative example and lean on the NVD-confirmed qualitative claim. Soften ">30,000 npm packages" to an attributed/rounded figure.
- **GHSA scale ("23,500+"; 20k/2.9k/600; "29–39% have a fix-commit link").** Footnoted as GitHub API lower bounds; no query artifact in-repo. **Action:** commit the query script + retrieval date, or round to orders of magnitude. **Tension to resolve:** the *processed* corpus fetch rates are 54% (npm 3,667/6,780) and 65% (PyPI 3,682/5,640) — both well above the stated "29–39% have a fix-commit link," so clarify which population the 29–39% describes (all reviewed advisories vs. the diff-fetchable subset) or the two figures read as contradictory.

### D3. Weakest — add the artifact or soften

- **Go: "5 KB entries, 100%, 47 functions."** No Go extraction artifact exists anywhere in the repo (grep hits were the substring "go" in unrelated files). A precise "47 functions" from n=5 with no backing file is the easiest claim to challenge. **Action:** add the 5-row Go result CSV to the package, or drop the numbers ("Go patterns implemented; evaluation is future work").
- **"15/15 reachable (100%)."** `reachability_verdicts` is empty in `ghsa_study1_precision_corpus.csv`; the verdict is not stored. **Action:** export the per-function reachability verdicts to the package, or soften the 100% claim to reflect what is reproducible (the 15 matches).
- **Cited-literature figures (73% unreachable, 59% reachable, 9-day median).** Attributed to references. **Action:** spot-check each cited source actually states the figure. **LLM cost ($235–700)** is your own estimate with the arithmetic shown (23,500 × $0.01–0.03) — keep it framed as an estimate.

---

## E. Recommended edit checklist

1. Choose **n=105** as the precision sample throughout; update §RQ1 strict/relaxed bullets (→ 56.2% / 75.2%), Table 3 (→ the corrected tier table in B1), the statistical-note CIs (→ B1), Finding 1, and the Discussion.
2. Change every "High-confidence = 100% strict (n=20)" to **83.3% strict / 92.9% relaxed (n=42)**; reconcile with the conclusion (already 83.3%).
3. Fix Table 1 Study 1: separate the 92-advisory validation set from the 45-advisory/133-function extraction corpus; recompute the fetched/extraction percentages against the correct denominator; reconcile "32" vs README's "41."
4. Regenerate Table 6 / Figure 6 from an actual commit-date field (add it to the released CSV) or remove the temporal analysis; fix "916" vs "936"; re-derive the post-2014/post-2017 rates.
5. Rescale Table 4 Study 2 so the sub-rows sum to 294 (139 no-diff + 155 fetched-no-extraction).
6. Correct §RQ3 "21.0%" → **14.0%** (fetched-but-no-extraction over fetchable).
7. Minor: reconcile "13 packages" → 19 in the reachability sub-study; normalize verdict casing in `irr_coding_sheet.csv`.
8. Reconstruct "78 of 133 High-confidence (58%)" by running `assign_confidence()` over the 133-function corpus; cite the reproducible number.
9. Verify the reachability claims (15 matched, top-20, package split) and the qs walkthrough (47 functions, 3 edges) against `method_hotspots.csv` / the call graph; export the per-function reachability verdicts so "15/15 reachable" is checkable, or soften it.
10. External counts: commit a dated GHSA-API query script (or round the 23,500+/20k/2.9k/600 figures); reconcile "29–39% fix-link" against the processed-corpus fetch rates (54%/65%). Add the 5-row Go artifact or soften the Go claim. Spot-check cited-literature figures (73%, 59%, 9-day).
11. Add a **reproducibility manifest** (or Makefile) mapping every table, figure, and inline number to the script + data file that generates it — this forces each remaining number into "reproducible" or "attributed."
