# `main.tex` Patch List — dedup to n=104

Canonical data: `precision_validation_samples_n104.csv` (58 Central / 20 Tangential / 26 Noise; 92 advisories).
Apply the edits below. Line numbers are from the current `main.tex`; each is a verbatim OLD → NEW. Do **not** touch `L803 ymin=0, ymax=105` — that is a plot axis, not a sample size. Java figures ($n{=}20$, 55.0%/75.0%) stay unchanged.

## Number-change summary (105 → 104)

| Quantity | OLD | NEW |
|---|---|---|
| Sample size | 105 | 104 |
| Overall strict | 56.2% (59) | 55.8% (58) |
| Overall relaxed | 75.2% (79) | 75.0% (78) |
| High tier | 100% / 100% (n=20)* | 82.9% / 92.7% (n=41) |
| Medium tier | 35.0% / 70.0% (n=20)* | 47.6% / 76.2% (n=42) |
| Low tier | 30.0% / 50.0% (n=10)* | 19.0% / 38.1% (n=21) |
| Table 2 counts | 59 / 20 / 26 | 58 / 20 / 26 |
| Severity coverage | 9 / 40 / 40 / 3 | 9 / 39 / 40 / 4 |

\* the old tier rows were the stale n=50 subset; they are being unified to n=104 here.

---

## Mechanical edits (verbatim old → new)

**L62 (abstract)**
OLD: `...advisories (56.2\% strict precision and 75.2\% relaxed precision at $n{=}105$).`
NEW: `...advisories (55.8\% strict precision and 75.0\% relaxed precision at $n{=}104$).`

**L186 (contributions)**
OLD: `56.2\% strict precision (75.2\% relaxed precision) in identifying the`
NEW: `55.8\% strict precision (75.0\% relaxed precision) in identifying the`

**L503 (dataset — severity)**
OLD: `and severity coverage (9~Critical, 40~High, 40~Moderate, 3~Low),`
NEW: `and severity coverage (9~Critical, 39~High, 40~Moderate, 4~Low),`

**L562–564 (Finding 1 box)**
OLD: `(single function modified) achieve 100\% strict precision ($n{=}20$),\nmaking them suitable for automated triage, while the overall 78.0\%\nrelaxed precision ($n{=}50$) supports function-level alerting as a`
NEW: `(single function modified) achieve 82.9\% strict precision ($n{=}41$),\nmaking them suitable for triage prioritization, while the overall 75.0\%\nrelaxed precision ($n{=}104$) supports function-level alerting as a`

**L568**
OLD: `We drew a stratified random sample of 105 extractions from the Study~1`
NEW: `We drew a stratified random sample of 104 extractions from the Study~1`

**L583 (Table 2 caption)**
OLD: `\caption{Manual validation of 105 sampled extractions.}`
NEW: `\caption{Manual validation of 104 sampled extractions.}`

**L589–591 (Table 2 body)**
OLD:
```
        Central (directly CVE-relevant) & 59 & 56.2\% \\
        Tangential (modified but not primary fix) & 20 & 19.0\% \\
        Noise (extraction error) & 26 & 24.8\% \\
```
NEW:
```
        Central (directly CVE-relevant) & 58 & 55.8\% \\
        Tangential (modified but not primary fix) & 20 & 19.2\% \\
        Noise (extraction error) & 26 & 25.0\% \\
```

**L596–600 (prose after Table 2)**
OLD: `Among the 105 samples, 59 (56.2\%) directly identified the function\ncentral to the vulnerability fix, 20 (19.0\%) identified functions\ntangentially modified in the same commit but not the primary security\nremediation, and 26 (24.8\%) were noise`
NEW: `Among the 104 samples, 58 (55.8\%) directly identified the function\ncentral to the vulnerability fix, 20 (19.2\%) identified functions\ntangentially modified in the same commit but not the primary security\nremediation, and 26 (25.0\%) were noise`

**L606–607 (strict/relaxed bullets — n=50 remnant)**
OLD:
```
    \item \textbf{Strict precision}: 30/50 = 60.0\%
    \item \textbf{Relaxed precision}: 39/50 = 78.0\%
```
NEW:
```
    \item \textbf{Strict precision}: 58/104 = 55.8\%
    \item \textbf{Relaxed precision}: 78/104 = 75.0\%
```

**L611 (tier prose intro)**
OLD: `Table~\ref{tab:precision-tier} disaggregates the 50 samples`
NEW: `Table~\ref{tab:precision-tier} disaggregates the 104 samples`

**L613–622 (tier prose)**
OLD: `...file) achieve 100\% strict precision, confirming that single-function\nadvisories are reliably extracted.\nMedium-confidence extractions perform moderately (35.0\% strict, 70.0\%\nrelaxed), ... primary fix.\nLow-confidence extractions (many functions per advisory) have the\nlowest precision (30.0\% strict), reflecting the dilution effect of`
NEW: `...file) achieve 82.9\% strict precision, confirming that single-function\nadvisories are extracted with high precision (the three exceptions are\nanalysed under Failure modes below).\nMedium-confidence extractions perform moderately (47.6\% strict, 76.2\%\nrelaxed), ... primary fix.\nLow-confidence extractions (many functions per advisory) have the\nlowest precision (19.0\% strict), reflecting the dilution effect of`

**L626 (Table 3 caption)**
OLD: `\caption{Precision by confidence tier ($n{=}50$ validated samples).`
NEW: `\caption{Precision by confidence tier ($n{=}104$ validated samples).`

**L633–637 (Table 3 body)**
OLD:
```
        High   & 20 & 20 & 0 & 0 & 100\% / 100\% \\
        Medium & 20 &  7 & 7 & 6 & 35.0\% / 70.0\% \\
        Low    & 10 &  3 & 2 & 5 & 30.0\% / 50.0\% \\
        \midrule
        Overall & 50 & 30 & 9 & 11 & 60.0\% / 78.0\% \\
```
NEW:
```
        High   & 41 & 34 & 4 & 3 & 82.9\% / 92.7\% \\
        Medium & 42 & 20 & 12 & 10 & 47.6\% / 76.2\% \\
        Low    & 21 &  4 & 4 & 13 & 19.0\% / 38.1\% \\
        \midrule
        Overall & 104 & 58 & 20 & 26 & 55.8\% / 75.0\% \\
```

**L642–648 (high-confidence-filter implication)**
OLD: `The 100\% strict precision for High-confidence extractions has a direct\npractical implication. ... Applying this filter to Study~1 retains 78 of 133 functions (58\%) while\nachieving 100\% precision among the 20 High-confidence samples we\nmanually validated.`
NEW: `The 82.9\% strict precision for High-confidence extractions has a direct\npractical implication. ... Applying this filter to Study~1 retains <NN> of 133 functions (<NN>\%) while\nachieving 82.9\% precision among the 41 High-confidence samples we\nmanually validated.`
> `<NN>` = rerun `assign_confidence()` over the 133 (plan item P1.2); the old "78 (58%)" was never verifiable.

**L671–676 (statistical note — Wilson CIs)**
OLD:
```
With $n{=}50$ samples, the 95\% Wilson score confidence intervals are:
    \item Strict precision (60.0\%): [46.2\%, 72.4\%]
    \item Relaxed precision (78.0\%): [64.8\%, 87.2\%]
    \item High-confidence strict (100\%): [83.9\%, 100\%]
```
NEW:
```
With $n{=}104$ samples, the 95\% Wilson score confidence intervals are:
    \item Strict precision (55.8\%): [46.2\%, 64.9\%]
    \item Relaxed precision (75.0\%): [65.9\%, 82.3\%]
    \item High-confidence strict (82.9\%): [68.7\%, 91.5\%]
```

**L677–678**
OLD: `We note that the relaxed precision lower bound (64.8\%) is well above`
NEW: `We note that the relaxed precision lower bound (65.9\%) is well above`

**L680–683 (sample-size rationale — needs a small rewrite, not just a swap)**
OLD: `The sample size of $n{=}50$ was chosen to target a Wilson CI half-width\nof approximately $\pm$13\% at 95\% confidence for an expected precision\nnear 70\%, ...`
NEW (suggested): `The combined $n{=}104$ sample yields a Wilson CI half-width of roughly\n$\pm$9\% at 95\% confidence, ...`

**L699 (cross-ecosystem — change JS/Python only; keep Java $n{=}20$)**
OLD: `The consistency of precision across JS/Python ($n{=}50$) and`
NEW: `The consistency of precision across JS/Python ($n{=}104$) and`

**L964 (discussion)**
OLD: `of advisories. The 60.0\% strict precision (78.0\% relaxed) is sufficient`
NEW: `of advisories. The 55.8\% strict precision (75.0\% relaxed) is sufficient`

**L967–969 (discussion — substantive softening)**
OLD: `High-confidence extractions achieve 100\% strict\nprecision ($n{=}20$), making them suitable for automated filtering in\nproduction SCA pipelines.`
NEW: `High-confidence extractions achieve 82.9\% strict\nprecision ($n{=}41$), making them suitable for prioritization in\nproduction SCA pipelines.`

**L1365 (conclusion)**
OLD: `56.2\% strict precision ($n{=}105$, 75.2\% relaxed, with 83.3\% for High-confidence`
NEW: `55.8\% strict precision ($n{=}104$, 75.0\% relaxed, with 82.9\% for High-confidence`

---

## Failure-mode paragraph — full rewrite (L655–668, item 3)

The old paragraph tallied only the 11 noise samples of the n=50 subset (minified 4 / high-count 5 / test 2). Over all **26** noise samples in n=104 the taxonomy is richer and the dominant modes change. Replace the paragraph with the table + text below.

**New taxonomy (26 noise samples):**

| Failure mode | n | Addressable? |
|---|---|---|
| Hunk-header misattribution (function unmodified; only the git `@@` context label) | 6 | Yes — attribute by `+`/`-` lines, not the header |
| Name absent from diff (mass-deletion / bulk file replacement / huge refactor) | 7 | Partly — function-count threshold |
| High-function-count dilution (irrelevant utility co-modified in a large commit) | 5 | Partly — function-count threshold |
| Minified identifiers (`.min.js` artifacts, e.g. `Ye`, `Xc`, `Vo`) | 3 | Yes — `*.min.js` filter |
| Non-function / generic identifier (bare `__init__`, the variable `promise`) | 2 | Yes — identifier blocklist |
| Test-function capture | 1 | Yes — test-path filter |
| Other (wrong-language file `ensure_docker_access`; unrelated small-commit fn `has_jspi`) | 2 | Partly |
| **Total** | **26** | |

**Suggested prose:**
> The 26 noise samples cluster into seven failure modes. The two largest are new relative to the smaller pilot: **hunk-header misattribution** (6 cases), where the extracted name was never modified but was the nearest preceding `def`/`function` on the diff's `@@` context line, and **name-absent extraction** (7 cases), where the captured identifier does not appear in the diff at all — dominated by mass-deletion commits (e.g. the pytorch-lightning "remove the app" commit that deletes 1{,}307 functions) and bulk library replacements. **High-function-count dilution** (5) and **minified identifiers** (3) match the pilot's modes; **test capture** (1), **non-function tokens** (2, e.g. a bare `__init__` or the local variable `promise`), and **wrong-language files** (1) round out the tail. Notably, all three High-confidence noise cases (`manila/_security_service_get_query`, `node-forge/_getValueLength`, `n8n-mcp/promise` — each a single-function commit) are hunk-header or non-function misattributions; this is why High-confidence strict precision is 82.9% rather than the 100% observed on the smaller pilot. Five of the seven modes are fully addressable (line-level attribution, `*.min.js` and test-path filters, an identifier blocklist), and a function-count threshold prunes most of the remaining large-commit noise.

> **Key insight to carry into RQ3/Discussion:** hunk-header misattribution (6/26) is the single largest noise source and the only one that penetrates the High-confidence tier. It is a deterministic, fixable attribution bug (use the `+`/`-` changed lines rather than git's hunk-header label), so fixing it disproportionately improves the highest-value output.

---

## Not changed by the dedup (leave as-is)

- Java cross-ecosystem: $n{=}20$, 55.0% strict, 75.0% relaxed (L688–691, L700).
- Study 1 corpus: 133 extracted functions, 92 advisories, 39 npm / 53 PyPI (dedup does not change distinct advisories or the corpus).
- IRR: κ=0.583, 15 samples, "~14%" (15/104 = 14.4% ≈ 14%).
- Reachability: 15 of 133 matched.
- All Study 2 / full-corpus coverage numbers.

## Still outstanding (separate from dedup — see consistency report B3–B6)

Table 1 "92 vs 45" denominator; temporal Table 6 / Fig 6; failure Table 4 arithmetic; §RQ3 "21.0%"→14.0%; the "78 of 133" reconstruction (P1.2).
