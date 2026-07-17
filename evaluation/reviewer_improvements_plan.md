# Reviewer-Response Improvements Plan

Post-assessment polish to lift acceptance odds from ~68% toward ~74%. Deadline
**July 19**. Ordered by expected value / risk. Items T1–T3, T5 are safe;
T4 is the optional ceiling-raiser. After every edit, `check_consistency.py`
must stay green and the PDF must stay ≤ 11 pages (ACM sigconf).

Est. effect: T1+T2+T3+T5 → ~71–73%; adding T4 → ~74–77%. Hard ceiling ~high-70s.

---

## T1 — Held-out validation of the F1–F5 noise filters  (HIGHEST VALUE, ~0.5–1 day)

**Why:** the filters were *defined* from the 26 noise cases in the n=104 sample and
*evaluated* on that same sample (72.5%/95.0%). A rigorous reviewer discounts this as
train-on-test. A held-out number converts a puncturable claim into a defensible one.
This is the only item whose omission also *costs* odds (−2–3).

**Steps:**
1. Write `evaluation/filter_eval.py`: implement F1–F4 (computable from
   `function_name` + `num_functions`) and F5 (hunk-header-only; needs the diff, so
   mark it "diff-dependent" and skip where diffs aren't cached).
2. **Held-out set A (fast, defensible):** apply F1–F4 to `java_precision_validation.csv`
   (n=20, labelled independently and *not* used to design the filters). Report
   strict/relaxed precision before → after on this independent set.
3. **Held-out set B (stronger, optional):** draw a fresh ~40-sample npm/PyPI
   extraction set, label Central/Tangential/Noise, apply all F1–F5, report.
   (Overlaps T4; do only if enlarging samples anyway.)
4. Edit §Post-Extraction Noise Filtering: add a "held-out validation" paragraph +
   a column/row to `tab:filter-precision` with the independent-set result. Reframe
   the n=104 number as in-sample/illustrative and the held-out as the generalization
   evidence.
5. Extend `check_consistency.py` to check the held-out filter numbers.

**Risk:** the held-out may show weaker generalization (e.g. strict ~65% not 72.5%).
Report it honestly — a smaller *trusted* number still beats a discounted big one.
*Odds: +3–6 (and avoids −2–3).*

---

## T2 — Page-length check and trim  (protective, ~0.5–1 h)

**Why:** the draft grew to 1{,}698 lines with the filters/tree-sitter/recall
additions. Over 11 pages = easy desk-reject at some venues. Insurance, not lift.

**Steps:**
1. Build the PDF; read the page count. If ≤ 11, done.
2. If over, trim lowest-information-loss first: Related Work (tighten to ~1 sentence
   per work) → Discussion (compress "Regex vs. LLM", "Practical Deployment") →
   Walkthrough (§3.5) → any Threats redundancy. Never cut tables/figures or a
   verified number.
3. Re-check no orphaned `\ref`; guard still green.
*Odds: ~0 (avoids a −5–15 tail).*

---

## T3 — Harmonize pre/post-filter precision numbers  (framing, ~20 min)

**Why:** abstract leads with 55.8%/75.0% (raw), comparison table says "73–95%"
(post-filter), Discussion leads with 72.5%/95.0%. Flipping between them reads as
cherry-picking.

**Steps:**
1. Abstract: state both, e.g. "55.8% strict / 75.0% relaxed, rising to
   72.5% / 95.0% after deterministic noise filtering."
2. Ensure the first mention of the comparison-table "73–95%" is anchored to the
   post-filter result so it isn't a surprise.
3. Guard green.
*Odds: +1–2.*

---

## T5 — Update the Contributions list  (framing, ~15 min)

**Why:** the contributions bullets (§1) omit three of the now-strongest pieces.

**Steps:** add bullets for (a) the deterministic F1–F5 noise-filter taxonomy with
its measured precision gain, (b) the tree-sitter AST validation of the hunk-header
failure mode, and (c) the manual recall estimate. Keep the dataset bullet first.
*Odds: +0–1.*

---

## T4 — Deepen the empirical base  (OPTIONAL ceiling-raiser, ~2–4 days)

**Why:** n=104 precision, n=19 recall, n=18 PoC, single-annotator κ=0.583 are the
standing "small samples" objection that caps Reviewer B. Enlarging is the only
remaining lever (short of a full AST extractor) that pushes toward "likely accept."

**Steps (do as many as time allows):**
1. **Recall:** enlarge from 19 → ~40–50 advisories (label ground-truth modified
   functions per the same protocol); recompute at-least-one and aggregate recall.
2. **Held-out precision (set B from T1):** a fresh ~40-sample labelled npm/PyPI set;
   report filter generalization on it.
3. **Second-annotator IRR:** independent coding of a larger subset; recompute κ and
   report; replaces the "planned for extended version" caveat with an actual number.

**Risk:** real labeling time; larger samples may move numbers (report honestly).
*Odds: +3–5.*

---

## Sequencing & gate

1. **T3, T5** (30 min, safe framing) →
2. **T1** (the substantive one) →
3. **T2** (after all text edits, so the page count is final) →
4. **T4** only if time/appetite remain.

**Gate after each phase:** `python3 check_consistency.py` (green) + PDF build (≤ 11 pp,
no broken refs).

## Priority if time is short
Must-do: **T1** (defends the headline filter numbers) and **T2** (desk-reject
insurance). Grab **T3** and **T5** (45 min total). Treat **T4** as the
lean-accept → likely-accept investment.

## Reality check
These defend and modestly extend the odds; they cannot manufacture a strong accept.
The paper is a solid resource + modest-technique contribution with honestly-reported
56% raw precision / 23% aggregate recall. The only ceiling-breaker is a *full*
AST/tree-sitter extractor (beyond the PoC) showing materially higher precision *and*
recall — a next-paper effort, not a deadline task.
