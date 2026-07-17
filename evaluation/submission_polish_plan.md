# Submission-Polish Plan — "Cheap Trio" (+ optional PoC)

Goal: bank the reliable acceptance-odds gain before the **July 12** deadline without
touching any verified number. Estimated effect: ~55% → **~62%** for the trio;
~68% if the optional PoC lands cleanly. All trio items are prose/framing only —
`check_consistency.py` must still pass 28/28 afterward.

Sequence: **T1 → T3 → T2 → gate**. Total trio effort: **~3–4 hours**.

---

## T1 — Reposition as a dataset/benchmark contribution  (~1.5 h)

*Rationale:* converts the novelty-skeptic reviewer (C) from negative to neutral by
aligning with SCORED's "Datasets and benchmarking" track. Framing only.

Steps (all in `main.tex`):
1. **Abstract** — add one clause foregrounding the released artifact, e.g. "…and we
   release a reproducible, multi-language benchmark of function-level CVE mappings."
   Keep all existing numbers.
2. **Contributions list (§1)** — promote the "open replication package" bullet to
   first or second position and rephrase as a *community benchmark* (dataset +
   scripts + manifest + guard), not an afterthought.
3. **Keywords** — add `dataset`, `benchmark` (currently absent).
4. **§Dataset Release** — add one sentence tying it to the CFP track explicitly
   ("a resource for SCORED's Datasets and benchmarking area") and mention the
   reproducibility manifest + consistency guard as part of the release.
5. *(Optional, low-risk)* Title tweak toward the resource framing — only if your
   collaborator agrees; not required.

*Files:* `main.tex` (abstract, §1, keywords, §Dataset Release).
*Verify:* abstract/intro read as "resource-first"; `check_consistency.py` = 28/28.
*Odds:* +3–6 pts.

---

## T3 — Pre-empt Reviewer B in Threats to Validity  (~30 min)

*Rationale:* makes the known soft spots read as *acknowledged*, not *caught* — a
critical reviewer scores an owned limitation higher than a hidden one.

Steps (add to §Threats, 2–3 sentences):
1. **Coverage ≠ recall** — state plainly that RQ2 measures extraction coverage, not
   true recall, since no npm/PyPI/Java function-level oracle enumerates all affected
   functions (partly present — make it explicit and up front).
2. **Corpus-frame distinction** — acknowledge that the precision frame (92 advisories)
   and the extraction/reachability subsets (45-advisory corpus) differ, and why
   (broad stratified validation sample vs. a call-graph-covered pilot). This closes
   the one seam a careful reviewer could probe.
3. Confirm the existing single-annotator + κ=0.583 + planned-IRR sentence stays.

*Files:* `main.tex` (§Threats).
*Verify:* limitations read as deliberate; guard 28/28.
*Odds:* +2–4 pts.

---

## T2 — Page-limit check and trim  (~0.5–1 h)  [protective]

*Rationale:* SCORED is ACM sigconf, **≤11 pages**. Over-length risks desk-reject;
this is insurance, not lift. Do it **after** T1/T3 (they add a few lines).

Steps:
1. Build the PDF; read the page count.
2. If **≤11**: done (0 effort).
3. If **over**, trim in this priority order (lowest information-loss first):
   - **Related Work** (§7, ~33 refs across 6 subsections) — tighten to 1 sentence per
     work; biggest easy win.
   - **Discussion** — compress "Regex vs. LLM" and "Practical Deployment" subsections.
   - **Walkthrough (§3.5)** — trim the step-by-step prose; keep the extraction +
     reachability outcome.
   - **Threats** — remove any redundancy after T3.
   Avoid cutting tables/figures or any verified number.

*Files:* `main.tex`.
*Verify:* PDF ≤ 11 pages; guard 28/28; no orphaned `\ref`.
*Odds:* ~0 (avoids a −5–15 tail).

---

## Final gate  (~15 min)

```bash
cd oscar-patch-mining/evaluation && python3 check_consistency.py   # expect 28/28, exit 0
```
Then a full read-through of abstract → §1 → §Threats → §Dataset Release for flow,
and a PDF build to confirm ≤11 pages and no broken references.

---

## OPTIONAL — Tree-sitter AST PoC  (evidence, high variance)

*Rationale:* the only lever that raises the ceiling. Converts "AST would help"
(asserted) into "tree-sitter recovers the hunk-header noise" (shown), neutralizing
Reviewer C's strongest objection and substantiating the §RQ1 projection.

**Scope (strict):** a *minimal* PoC on ~20 diffs — specifically the 6 hunk-header
noise cases plus a few controls — showing tree-sitter attributes the correct
enclosing function where the regex/hunk-header heuristic did not. **Not** a pipeline
rewrite.

**Steps & effort:**
| Step | Work | Time |
|---|---|---|
| Env: `tree_sitter` + JS/Python/Java grammars | setup, version pinning | 1–2 h |
| Reconstruct pre/post full files per diff | fetch full file at commit (network, like `regenerate_temporal.py`); apply hunks | 3–5 h |
| Parse both, diff ASTs → changed enclosing functions | core logic, per-language node mapping | 4–6 h |
| Compare vs. regex on the ~20 cases; tabulate | analysis | 1–2 h |
| Write-up: 1 short paragraph + maybe a mini-table | prose | 1 h |
| **Total** | | **~1.5–2 focused days** |

**Cost / risk:**
- Needs GitHub fetches for full file contents (token, offline run) — same pattern as
  the temporal script.
- Pre/post reconstruction from hunks is fiddly; AST-diff → function mapping is real
  code with per-language edge cases.
- **Downside:** an underpowered/buggy PoC can *lower* scores (reviewers penalize
  half-finished experiments), and it risks reintroducing inconsistency into a paper
  we just fully reconciled.

**Go / no-go criteria (all must hold):**
1. T1–T3 done, PDF ≤ 11 pages, guard green.
2. ≥ **1 full day of buffer** remains before the deadline after the trio.
3. Scope frozen to the ~20 hunk-header cases (no creep toward re-running the corpus).
4. Hard time-box: if the AST-diff→function mapping isn't working within ~half a day,
   **abandon** and keep the analytical projection already in the paper.

**Expected impact:** +5–10 pts if clean; −0–5 if rushed. Recommend **only** if all
four criteria hold; otherwise the paper already states the projected improvement and
positions AST as future work, which is sufficient.

---

## Summary

| Item | Effort | Risk | Odds |
|---|---|---|---|
| T1 reposition | ~1.5 h | none | +3–6 |
| T3 threats pre-empt | ~0.5 h | none | +2–4 |
| T2 length | ~0.5–1 h | none | ~0 (protective) |
| **Trio total** | **~3–4 h** | **none** | **~+7 (→ ~62%)** |
| PoC (optional) | ~1.5–2 days | high variance | +5–10 / −0–5 (→ ~68% if clean) |

Do the trio for certain; treat the PoC as go/no-go against the four criteria above.
