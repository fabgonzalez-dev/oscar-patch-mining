# Implementation Plan — Fixing `main.tex` / Data Inconsistencies

Companion to `paper_data_consistency_report.md`. Ordered so that data/script work (which produces the authoritative numbers) happens **before** prose edits (which consume them). Effort is rough; "Prose" = edit `main.tex`, "Data" = script/CSV work.

---

## Status (update)

**Decision taken: n=104** (not 105) — the two validation samples were merged and the one genuine double-count (`GHSA-v6h2-p8h4-qcjw`/`expand`, OSV-confirmed Low) was dropped.

Completed:
- ✅ **P0.1 (revised)** — canonical sample fixed at **n=104**; `precision_validation_samples_n104.csv` is the single source (raw 50/55 inputs kept; n=105 intermediate deleted; `merge_precision_samples.py` regenerates it).
- ✅ **P1.1** — canonical stats: 58/20/26 → 55.8% strict / 75.0% relaxed; High 82.9%/92.7% (n=41), Medium 47.6%/76.2% (n=42), Low 19.0%/38.1% (n=21); Wilson CIs computed.
- ✅ **P1.2** — "78 of 133 (58%)" reconstructed as **13 of 133 (9.8%)** via `assign_confidence()`.
- ✅ **P2.1 / P2.2** — all RQ1 prose, both tables, Finding 1, statistical note, discussion, conclusion, and severity (9/39/40/4) updated in `main.tex`; failure-mode paragraph re-tallied over 26 noise; "100% / automated filtering / near-zero false positives" softened to 82.9% / prioritization.

- ✅ **P1.4 / P2.5 / P2.6** — failure Table 4 (Study 2) collapsed to the two verified buckets (139 no-diff + 155 fetched-no-extraction = 294; fabricated sub-counts removed, sub-reasons moved to prose); §RQ3 "21.0%" corrected to **14.0%** (155/1,109); Finding 3 and the "five/three failure modes" wording fixed.

- ✅ **P1.3 / P2.4 (route 2 — done)** — real commit dates fetched via `regenerate_temporal.py --source api` (1,163 commit / 85 CVE-fallback). Table 6, Figure 6, the era prose, Finding 2, the implication paragraph, the interpretation line, and the threats sentence were updated in `main.tex` with the real fix-commit-year distribution: eras **92 / 409 / 747**; extraction rate rises 44.6% → 66.0% → 86.1%; since-2013 commits = 79.0%. Numbers now reconcile (eras sum to 1,248 / 1,109 / 954). Note: the real distribution is far more recent-weighted than the draft's 312/381/555, so the "legacy tail" framing was softened accordingly.

- ✅ **P2.3 / B3 (done, Option B)** — Table 1 Study 1 aligned to the 92-advisory precision frame (90 fetched (98%) / 88 extracted (96%) / 3,648 functions / **median 2**, computed from the full-corpus CSVs); funnel (98/96), pattern-validation count (90), and threats rate (97.8%) updated. The reachability sub-study's 133 functions were relabeled as a separate 45-advisory subset with call-graph coverage (19 packages). Chose Option B over renaming "92→45" everywhere.

- ✅ **P1.5 (done)** — reachability sub-study verified against `method_hotspots.csv`: 20-per-package export, the 9 call-graph packages present / 4 excluded absent, 15-of-133 matches (= corpus count), and all 15 reachable (every match has `fan_in ≥ 1`, `is_orphan=False`) — the "100%" claim is now substantiated. qs walkthrough corrected: `parseObject` `fan_in` is **1** (not the stated 3), and the unverifiable "47 functions" figure was dropped.

- ✅ **P1.7 (done)** — GHSA-scale reframed on the real 13,668-advisory corpus (dropped the inconsistent "over 600 PyPI / 23,500+ / 29–39%"; now cites measured link rates 54% npm, 65% PyPI). Also caught a **missed n=104 fix**: the approach-comparison table's precision "60–78%" → **56–75%**, and its scale 23,500+ → 13,668. LLM-cost recomputed ($235–700 → **$137–410**). Go claim softened ("implemented but not yet systematically evaluated") since no Go artifact exists.

- ✅ **P3 (done)** — `REPRODUCIBILITY.md` maps every table/figure/number to its data + script; `check_consistency.py` re-derives the headline numbers and asserts them against `main.tex` (**28/28 pass, exit 0**). Run it as the pre-submission gate.

**All plan items complete.** The only remaining figures are inherently external/documented assumptions (GHSA full-DB size, LLM pricing, Go) — flagged in the manifest as not machine-reproducible.

---

## Phase 0 — One blocking decision (do first)

**P0.1 Fix the precision sample size at n=105.**
Everything in RQ1 branches from this. The combined validation set (`precision_validation_samples.csv` 50 + `precision_validation_samples_extra.csv` 55 = 105 over 92 advisories) is the larger, more defensible sample and already backs the abstract/Table 2/conclusion. Adopt it everywhere; retire the n=50 numbers.
*Owner: authors. Effort: decision only. Blocks: Phase 2 RQ1 edits.*

> Alternative if you prefer n=50: then the abstract, Table 2, and conclusion must revert to 60.0%/78.0% and 100% High — but you lose 55 validated samples and the "100% High" claim only survives on the smaller set. **Recommended: n=105.**

---

## Phase 1 — Data & script work (produces the authoritative numbers)

**P1.1 Emit a canonical precision-stats file.**
Script over the 105 combined rows → overall + per-tier Central/Tangential/Noise, strict/relaxed, and Wilson 95% CIs. Numbers are already computed (below) — commit the script so they are reproducible, output `evaluation/precision_stats.txt`.

| Tier | # | Cen | Tang | Noise | Strict | Relaxed | Strict 95% CI |
|---|---|---|---|---|---|---|---|
| High | 42 | 35 | 4 | 3 | 83.3% | 92.9% | [69.4, 91.7] |
| Medium | 42 | 20 | 12 | 10 | 47.6% | 76.2% | [33.4, 62.3] |
| Low | 21 | 4 | 4 | 13 | 19.0% | 38.1% | [7.7, 40.0] |
| **Overall** | **105** | **59** | **20** | **26** | **56.2%** | **75.2%** | strict [46.6, 65.3]; relaxed [66.2, 82.5] |

*Owner: Data. Effort: ~1h. Blocks: P2.1, P2.2.*

**P1.2 Reconstruct the "78 of 133" High-confidence count.**
Run `assign_confidence()` (already in `generate_validation_samples.py`) over all 133 functions in `ghsa_study1_precision_corpus.csv`; record the true High/Medium/Low split. Output the number that replaces "78 of 133 (58%)."
*Owner: Data. Effort: ~1h. Blocks: P2.2.*

**P1.3 Regenerate the temporal table from real commit dates.**
Do **not** use CVE-year (that is why the proxy disagreed). Commit dates are recoverable from the Project KB statement YAMLs at `oscar-research-data/external/project-kb/statements/CVE-*/statement.yaml`. Steps:
1. Parse each statement YAML for the fix-commit timestamp; join to `project_kb_java_extraction.csv` on `vuln_id`.
2. Add a `commit_year` column to the released CSV.
3. Regenerate Table 6 eras and Figure 6 per-year series from `commit_year`; recompute "since-2014" and "post-2017" rates and the "916 / 936" entry count.
4. Confirm the fetchable sub-rows now sum to 1,109 and with-extraction to 954.

If commit dates cannot be recovered cleanly, **cut** the temporal analysis (Table 6, Fig 6, and the era-rate sentences) rather than ship non-reproducible figures.
*Owner: Data. Effort: ~3–4h. Blocks: P2.4.*

**P1.4 Recompute the failure-mode categories (Table 4, Study 2).**
The only figures the data supports today are 139 no-diff + 155 fetched-no-extraction = 294. The sub-split (config/POM, diff-too-large, unsupported, test-only) is not in any CSV and currently sums to 175 ≠ 155. Either:
- (a) re-run `scored_evaluation.py` with per-failure-reason tagging so the four sub-categories sum to 155, or
- (b) collapse Table 4 to the two reproducible buckets (139 / 155) and describe the sub-reasons qualitatively.

*Owner: Data. Effort: ~2h (a) / ~15min (b). Blocks: P2.5.*

**P1.5 Verify reachability + qs walkthrough against the call graph.**
Check "15 matched," top-20 scope, and the 9-of-13 (→ correct to relevant N) package split against `oscar-research-data/data/method_hotspots.csv`. Reproduce the qs@6.9.6 figures (47 functions, 3 inbound edges) from the full call graph if available; export per-function reachability verdicts so "15/15 reachable" is checkable, else soften.
*Owner: Data. Effort: ~2h. Blocks: P2.6.*

**P1.6 Normalize IRR sheet casing.**
Lower/Title-case the `collaborator_verdict` values in `irr_coding_sheet.csv` so κ is unambiguous (case-insensitive already = 0.583, 4 disagreements; case-sensitive spuriously = 0.438). Re-emit κ from a script.
*Owner: Data. Effort: ~15min. Blocks: P2.7.*

**P1.7 GHSA scale + Go artifacts.**
- Commit a dated GitHub-Advisory-API query script that reproduces the 20k/2.9k/600 counts (record retrieval date), or round to orders of magnitude in prose.
- Reconcile "29–39% fix-link" vs processed-corpus fetch rates (npm 54%, PyPI 65%): state which population each measures.
- Add the 5-row Go extraction CSV to the package, or drop the "47 functions" figure.
*Owner: Data. Effort: ~2h. Blocks: P2.3, P2.8.*

---

## Phase 2 — Prose / table edits in `main.tex` (consume Phase 1 outputs)

**P2.1 RQ1 core (uses P1.1).** Replace the "30/50 = 60.0%" and "39/50 = 78.0%" bullets with 59/105 = 56.2% and 79/105 = 75.2%. Replace Table 3 with the P1.1 tier table. Update the statistical-note CIs to the P1.1 values. (Table 2 is already n=105 — leave it.)

**P2.2 High-confidence claim (uses P1.1, P1.2).** Change every "100% strict precision (n=20)" — Finding 1 box, Discussion, §RQ1 — to **83.3% strict / 92.9% relaxed (n=42)**. Replace "78 of 133 (58%)" with the P1.2 number. Verify the conclusion (already 83.3%) now matches.

**P2.3 Table 1, Study 1 column.** Disentangle the two sets: state that 105 function-level samples were validated across 92 advisories (39 npm / 53 PyPI; severity 9/40/40/3), and separately that the extraction corpus is 45 advisories / 133 functions. Recompute "fetched"/"extraction" percentages against the intended denominator; reconcile "32" with README's "41."

**P2.4 Temporal (uses P1.3).** Replace Table 6, Figure 6 data, and the era-rate sentences ("90.5%", "83.1%", "above 88%", "916 entries", "139 (45%) 404s") with commit-year-derived numbers — or remove the subsection if P1.3(cut) was chosen. Fix the Figure 6 caption's data-source attribution.

**P2.5 Failure table (uses P1.4).** Replace the Study 2 column so rows sum to 294; or collapse to two buckets.

**P2.6 Correct §RQ3 rate.** "failed only in 21.0% of [fetched] cases" → **14.0%** (155/1,109 fetchable).

**P2.7 Minor (uses P1.5, P1.6).** "13 packages" → correct N; note the IRR sheet is now case-normalized.

**P2.8 External counts (uses P1.7).** Add retrieval date / round GHSA figures; fix the 29–39% framing; adjust the Go sentence.

*Owner: Prose. Effort: ~4–5h total for P2.1–P2.8.*

---

## Phase 3 — Reproducibility manifest + final verification

**P3.1 Reproducibility manifest.** Add `evaluation/REPRODUCIBILITY.md` (or a Makefile) mapping every table, figure, and inline number to the script + data file that generates it. This is the durable fix — it prevents regressions and is what an artifact-evaluation committee looks for.

**P3.2 Automated consistency guard.** A small script that re-derives every headline number from the CSVs and asserts it against the values in `main.tex` (regex-extract the tex numbers, compare). Run it as the pre-submission gate.

**P3.3 Second-rater / κ note.** The paper already flags single-rater coding and κ=0.583 as "moderate." If time permits before the deadline, a fully independent second coding of a larger subset would strengthen internal validity; otherwise keep the existing honest caveat.

*Owner: Data + authors. Effort: ~3h (P3.1–P3.2).*

---

## Suggested sequencing / critical path

1. **P0.1** (decision) →
2. Phase 1 in parallel: **P1.1, P1.2, P1.5, P1.6** (fast, independent) and **P1.3, P1.4, P1.7** (heavier) →
3. Phase 2 edits once the corresponding P1 output is ready →
4. **P3.1–P3.2** last, then run the guard.

**Rough total:** ~1.5 days of data/script work + ~0.5 day of prose edits, with the temporal-table regeneration (P1.3) the largest single item and the main schedule risk.

## Priority if time is short (triage for the deadline)

- **Must-fix (correctness):** P0.1, P2.1, P2.2 (the n=50/n=105 split and the "100%" claim), P2.6, P1.4/P2.5 (failure table arithmetic).
- **Should-fix (reproducibility):** P1.3/P2.4 (temporal), P2.3 (Table 1), P1.2, P3.1.
- **Nice-to-have:** P1.5 export, P1.7 Go artifact, P3.2 guard, P3.3 second rater.
