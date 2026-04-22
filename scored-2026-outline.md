# SCORED 2026 Paper Outline

**Title:** From Fix Commits to Vulnerable Functions: Automated Patch Mining for Function-Level CVE Resolution

**Venue:** SCORED 2026 (Software Supply Chain Offensive Research and Ecosystem Defenses) @ ACM CCS  
**Format:** 6 pages, ACM conference format (acmart, sigconf)  
**Target Deadline:** ~July 2026  
**Review:** Single-anonymous (authors visible)

---

## Paper Structure

### §1 Introduction (0.75 pages)

**Opening hook:** Vulnerability databases report at the package level, but reachability tools need function-level data. This gap causes two problems:
1. False positives: SCA tools flag CVEs in functions your code never calls
2. Missing context: Security engineers can't prioritize without knowing *which* function is vulnerable

**The gap:** No automated, multi-language technique exists for extracting function-level vulnerability data from fix commits.

**Our contribution:** An automated patch mining technique that:
- Fetches fix commits linked to GHSA advisories via the GitHub API
- Parses commit diffs to extract modified function definitions
- Maps extracted functions to static call graphs for reachability verification
- Achieves 84% precision on a preliminary evaluation of 45 npm/PyPI advisories

**Framing as supply-chain security:** This work directly addresses the SCORED scope — it improves the precision of software supply chain vulnerability detection by bridging the gap between advisory databases and code-level analysis tools.

---

### §2 Background & Motivation (0.5 pages)

**2.1 The Function-Level Data Gap**
- Example: CVE-2022-24999 affects `qs` package → but which of its 30+ functions?
- NVD/OSV/GHSA all report at package-version granularity
- Project KB (Ponta et al.) manually curates ~800 Java entries — doesn't scale, single language
- Eclipse Steady needs this data as input, but has no automated way to produce it

**2.2 Fix Commits as a Data Source**
- GHSA advisories increasingly link to fix commits on GitHub
- The fix commit diff structurally contains information about what was changed
- Modified functions in a security fix are strong candidates for the vulnerable functions
- This is a form of "mining software repositories" applied to security

---

### §3 Technique (1.5 pages)

**3.1 Pipeline Overview (with figure)**

```
GHSA Advisory Database
    │
    ▼
[1] Fetch advisory metadata (package, ecosystem, severity, CWE)
    │
    ▼
[2] Resolve fix commit URL(s) via GitHub API
    │
    ▼
[3] Download commit diff
    │
    ▼
[4] Filter to source code files (exclude docs, tests, configs)
    │
    ▼
[5] Extract modified function definitions via language-aware patterns
    │
    ▼
[6] Output: (advisory_id, package, function_name, file_path, confidence)
```

**3.2 Language-Aware Function Extraction**

For each diff hunk, apply regex patterns that match function declarations:

| Language | Patterns | Example |
|----------|----------|---------|
| JavaScript | `function name(`, `const name = (`, `name(args) {`, `=>` | `function parseObject(str) {` |
| Python | `def name(`, `async def name(` | `def parse(self, data):` |

Key design decisions:
- Match declarations in **modified lines** (lines starting with `+` or `-` in the diff)
- Use surrounding context (±3 lines) to resolve ambiguous matches
- Handle arrow functions by detecting `const/let/var name = (...) =>`
- Deduplicate across files (same function name in test + source → keep source)

**3.3 Confidence Scoring**

Each extraction receives a confidence label based on heuristics:
- **High:** Single function modified in a single file (most likely the vulnerable function)
- **Medium:** Multiple functions modified, but one matches security-related naming (parse, sanitize, validate)
- **Low:** Many functions modified across multiple files (harder to isolate)

**3.4 Reachability Verification**

After extraction, function names are matched against static call graphs (produced by the OSCAR Method Observatory) to determine whether the mined functions are reachable from the package's public API. This serves as an independent validation signal: if a mined function is unreachable from any public entry point, it may be dead code or a false extraction.

---

### §4 Evaluation (1.5 pages)

**4.1 Dataset**

| Property | Value |
|----------|-------|
| Source | GitHub Advisory Database (GHSA) |
| Ecosystems | npm (JavaScript), PyPI (Python) |
| Total advisories processed | 45 |
| Advisories with fix commits | 45 (selection criterion) |
| Advisories yielding functions | 31 (69% yield) |
| Unique functions extracted | 133 |
| Packages covered | 12 |

**4.2 Precision Evaluation**

Manual validation of 20 randomly sampled extractions:

| Category | Count | Percentage |
|----------|-------|------------|
| Central (directly CVE-relevant) | 16 | 84% |
| Tangential (test helpers, refactoring) | 3 | 16% |
| Noise (extraction error) | 0 | 0% |
| Excluded (documentation-only) | 1 | — |

**Precision = 84%** (16/19 valid extractions)

**4.3 Reachability Confirmation**

Of the 15 mined functions found in our call graphs, **all 15 (100%)** are reachable from the package's public API. This confirms that the mined vulnerabilities reside in actively used code paths, not dead code.

**4.4 Failure Analysis (Preliminary)**

Of the 14 advisories (31%) that yielded no functions:

| Failure Mode | Count | Example |
|--------------|-------|---------|
| No source code changes (config/lockfile only) | 5 | Dependency version bump |
| Diff too large to parse reliably | 4 | Auto-formatter + fix |
| Fix in non-supported syntax | 3 | Class decorators, dynamic requires |
| Commit not accessible | 2 | Private repository |

---

### §5 Discussion (0.5 pages)

**5.1 Implications for Supply Chain Security**
- Automated patch mining can upgrade every SCA tool from package-level to function-level alerting
- The 69% yield means ~1/3 of advisories cannot be automatically resolved — these represent opportunities for improving advisory reporting practices
- 84% precision is sufficient for triage assistance but not for fully automated decision-making

**5.2 Limitations**
- Small sample size (n=45) — results are preliminary
- Only JavaScript and Python supported
- Regex-based extraction misses complex patterns (decorators, metaprogramming)
- No recall measurement (would require manually curated ground truth)
- Confidence scoring is heuristic, not learned

**5.3 Integration with OSCAR**
- Brief description of how the mined data feeds into OSCAR's cross-level risk pipeline
- When combined with call graphs and ecosystem fan-in, patch mining enables reachability-aware CVE triage

---

### §6 Related Work (0.5 pages)

- **Project KB** (Ponta et al., 2019): Manual curation of Java vulnerable constructs
- **VulnCode-DB** (Google): Links CVEs to commits but not to specific functions
- **VUDDY** (Kim et al., 2017): Clone detection for vulnerable functions (different approach)
- **Eclipse Steady** (Plate et al., 2015): Consumer of function-level data, not producer
- **SZZ Algorithm**: Traces bug-introducing commits (complementary direction)
- **OSV Schema** (Google, 2021): Standardized advisory format — our work extends it downward

---

### §7 Conclusion & Future Work (0.25 pages)

- Summarize: automated technique for extracting function-level CVE data from fix commits
- 84% precision on preliminary evaluation of 45 advisories
- Future: scale to 500+ advisories, add Go/Rust/Java, measure recall against Project KB, release as open dataset with DOI

---

## Figures and Tables

| Element | Location | Purpose |
|---------|----------|---------|
| Figure 1: Pipeline diagram | §3.1 | Visual overview of the mining pipeline |
| Table 1: Dataset statistics | §4.1 | Corpus summary |
| Table 2: Precision results | §4.2 | Main evaluation result |
| Table 3: Failure taxonomy | §4.4 | Characterize extraction failures |
| Table 4: Related work comparison | §6 | Position against prior work |

---

## Key Differences from ICSME Papers

| Aspect | ICSME Visions | ICSME Tool Demo | SCORED Paper |
|--------|--------------|-----------------|--------------|
| Focus | Cross-level formula | OSCAR platform | Patch mining technique |
| Core contribution | CLR equation + hidden amplifiers | Three-service architecture | Function-level CVE extraction |
| Evaluation | P@K on package ranking | Usage scenario + screenshots | Precision on function extraction |
| Overlap | Mentions patch mining in §4.4 (~3 sentences) | Mentions in §3 (~2 sentences) | Full 6-page treatment |

The SCORED paper expands what was a **sub-subsection** (3 sentences) in the ICSME papers into a **full paper** with its own pipeline, evaluation, and failure analysis. There is minimal text overlap.

---

## Writing Timeline

| Week | Task |
|------|------|
| Week 1 (Jun 1) | Draft §3 (Technique) — the core of the paper |
| Week 2 (Jun 8) | Draft §4 (Evaluation) — tables and analysis |
| Week 3 (Jun 15) | Draft §1-2 (Intro, Background) + §5-6 (Discussion, Related Work) |
| Week 4 (Jun 22) | Full draft revision, co-author review |
| Week 5 (Jun 29) | Final polish, format check |
| Buffer (Jul 1-15) | Ready for submission when SCORED CFP opens |
