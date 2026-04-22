# Patch Mining Research Plan

**Title:** From Fix Commits to Vulnerable Functions: Automated Patch Mining for Function-Level CVE Resolution

**Authors:** R. Fabian Gonzalez-Arellano, Rakesh Podder

**Target Venue:** MSR 2027 (Mining Software Repositories)  
**Target Track:** Data Showcase (4 pages) or Technical Papers (12 pages)  
**Expected Deadline:** ~November 2026

---

## 1. Problem Statement

Vulnerability databases (NVD, OSV, GHSA) report security advisories at the **package-version** level: _"Package X, version Y, is affected by CVE-Z."_ However, modern supply-chain security tools increasingly require **function-level** vulnerability data to perform reachability analysis, triage effectively, and reduce false-positive alerts.

Today, this function-level mapping is almost entirely absent from automated systems:

| Source | Granularity | Scale | Automated? |
|--------|-------------|-------|------------|
| NVD / CVE | Package + version | 200K+ CVEs | ✅ |
| OSV / GHSA | Package + version range | 50K+ advisories | ✅ |
| Project KB (Ponta et al.) | Java methods | ~800 vulnerabilities | ❌ Manual curation |
| **This work** | Multi-language functions | Target: 1,000+ | ✅ Automated |

### Gap

No automated, multi-language technique exists for extracting function-level vulnerability data from fix commits at scale. This gap blocks an entire class of tools (reachability-based SCA) from operating effectively.

### Thesis

Fix commits linked to security advisories contain sufficient structural information to automatically recover affected function names with high precision, enabling automated construction of function-level vulnerability databases across multiple programming language ecosystems.

---

## 2. Research Questions

| ID | Research Question | Measurement |
|----|-------------------|-------------|
| **RQ1** | What proportion of GHSA advisories yield function-level data through automated fix-commit mining? | Yield rate = advisories with ≥1 extracted function / total advisories |
| **RQ2** | What is the precision of automated function extraction from fix commit diffs? | P = correctly identified CVE-relevant functions / total extracted functions |
| **RQ3** | How does yield and precision vary across programming languages and advisory types? | Stratified analysis by language (JS, Python, Go, Rust, Java) and CWE category |
| **RQ4** | What are the failure modes, and what proportion of failures are addressable? | Taxonomy of extraction failures with frequency counts |
| **RQ5** | How does the automated technique compare to manually curated datasets (Project KB) on overlapping vulnerabilities? | Precision, recall, and F1 on the intersection set |

---

## 3. Current State (Proof of Concept)

The existing implementation within the OSCAR Method Observatory provides baseline results:

### Current Pipeline

```
GHSA Advisory
    → GitHub API: fetch fix commit URL(s)
        → Download commit diff
            → Language-aware regex: extract modified function definitions
                → Match: function/def/arrow-function declarations with context
                    → Output: (CVE-ID, package, function_name, file_path, confidence)
```

### Current Results (from ICSME submissions)

| Metric | Value | Notes |
|--------|-------|-------|
| Advisories processed | 45 | npm + PyPI corpus |
| Yield rate | 69% (31/45) | Advisories producing ≥1 function name |
| Unique functions extracted | 133 | Across 12 packages |
| Manual validation sample | 20 | Random stratified sample |
| Precision | 84% (16/19 valid) | 1 excluded as documentation-only |
| Reachability confirmation | 100% (15/15) | All mined functions reachable from public API |

### Current Limitations

- Small sample size (n=45 advisories, n=20 validation)
- Only JavaScript and Python supported
- Regex-based extraction (no AST parsing of diffs)
- No recall measurement
- No systematic failure characterization

---

## 4. Methodology

### 4.1 Data Collection

#### Step 1: Advisory Corpus Construction

Source all advisories from the GitHub Advisory Database (GHSA) that meet the following criteria:

```
Inclusion Criteria:
  - Has at least one linked fix commit URL
  - Affects a package in npm, PyPI, Go modules, crates.io, or Maven Central
  - Advisory published between 2019-01-01 and 2026-06-30
  - Fix commit is publicly accessible on GitHub

Exclusion Criteria:
  - Advisory withdrawn or disputed
  - Fix commit is in a private repository
  - Advisory affects only binary/compiled artifacts (no source diff)
```

**Target corpus size:** 1,000–2,000 advisories

**Data sources:**
- GitHub Advisory Database API (primary)
- OSV.dev API (supplementary, for cross-referencing)
- NVD API (for CWE classification)

#### Step 2: Fix Commit Retrieval

For each advisory:
1. Query GHSA API for linked fix commit SHAs
2. Download the full commit diff via GitHub API
3. Parse diff into per-file hunks
4. Filter to source code files (exclude docs, configs, tests, CI files)

#### Step 3: Function Extraction

Apply language-specific extractors to each diff hunk:

| Language | Declaration Patterns | Parser Strategy |
|----------|---------------------|-----------------|
| JavaScript | `function name(`, `const name =`, `name(` (method), arrow functions | Regex + AST fallback (Esprima/Acorn) |
| Python | `def name(`, `async def name(`, class methods | Regex + AST fallback (ast module) |
| Go | `func name(`, `func (receiver) name(` | Regex + AST fallback (go/parser) |
| Rust | `fn name(`, `pub fn name(`, `impl ... { fn name(` | Regex |
| Java | Method declarations with modifiers | Regex + AST fallback (JavaParser) |

**Two-tier extraction strategy:**
1. **Tier 1 (Regex):** Fast, pattern-based extraction. Handles ~80% of cases.
2. **Tier 2 (AST):** For cases where regex is ambiguous, parse the pre-fix and post-fix file versions and compute the AST diff to identify exactly which functions changed.

#### Step 4: Confidence Scoring

Each extraction receives a confidence score based on:

| Factor | Weight | Rationale |
|--------|--------|-----------|
| Single function modified | +0.3 | High probability of being the vulnerable function |
| Function in test file | -0.2 | Likely a test helper, not the vulnerability |
| Function name contains security keyword (parse, sanitize, validate, auth) | +0.1 | Higher a priori probability |
| Multiple functions in same file modified | -0.1 | Harder to isolate the vulnerable one |
| Diff adds bounds checking, input validation, or error handling | +0.2 | Typical vulnerability fix pattern |

### 4.2 Validation

#### Manual Validation Protocol

1. **Sample size:** 200 randomly selected extractions, stratified by language (40 per language)
2. **Labels:** Each extraction labeled by two independent annotators as:
   - **Central:** Function directly contains or triggers the vulnerability
   - **Related:** Function modified as part of the fix but not the vulnerability itself (e.g., renamed, refactored)
   - **Tangential:** Test helper, documentation update, or unrelated cleanup
   - **Noise:** Extraction error (wrong function name, parsing artifact)
3. **Inter-annotator agreement:** Measured via Cohen's κ
4. **Disagreements:** Resolved by third annotator or discussion

#### Recall Estimation via Project KB

For Java advisories that overlap with Project KB's curated dataset:
1. Retrieve Project KB's manually identified vulnerable methods
2. Run our automated extraction on the same advisories
3. Compute recall = |our functions ∩ KB functions| / |KB functions|
4. Analyze false negatives: what did we miss and why?

**Expected overlap:** ~100–200 advisories (Project KB covers ~800 Java vulnerabilities)

### 4.3 Failure Analysis

Categorize all advisories that yield zero functions:

| Failure Category | Description | Example |
|------------------|-------------|---------|
| **No source diff** | Fix commit modifies only binary, config, or lockfile | Dependency version bump fix |
| **Documentation only** | Diff touches only docs, comments, or changelogs | README security notice |
| **Multi-commit fix** | Vulnerability fixed across multiple commits, only one linked | Complex refactoring fix |
| **Build/CI change** | Fix is a build configuration or CI pipeline change | GitHub Actions workflow update |
| **Language unsupported** | Function syntax not matched by current patterns | C macros, Haskell, Perl |
| **Obfuscated diff** | Large reformatting commit obscures the actual fix | Auto-formatter run alongside fix |
| **Private commit** | Linked commit is in a private or deleted repository | Removed repository |

For each category, assess whether the failure is:
- **Addressable:** Could be fixed with better extraction techniques
- **Inherent:** Fundamental limitation of the approach (no function to extract)

---

## 5. Expected Contributions

### Contribution 1: Automated Multi-Language Patch Mining Technique

A fully automated pipeline that extracts function-level vulnerability data from fix commits across 5 programming languages, with documented precision per language.

### Contribution 2: Function-Level Vulnerability Dataset

A curated, validated dataset mapping CVE/GHSA IDs to affected functions:

```json
{
  "advisory_id": "GHSA-xxxx-yyyy-zzzz",
  "cve_id": "CVE-2024-12345",
  "package": "express",
  "ecosystem": "npm",
  "language": "javascript",
  "affected_functions": [
    {
      "name": "parseUrl",
      "file": "lib/utils.js",
      "confidence": 0.92,
      "validation": "central"
    }
  ],
  "fix_commits": ["abc123"],
  "cwe": "CWE-79"
}
```

**Release format:** JSON + CSV, hosted on GitHub with DOI via Zenodo.

### Contribution 3: Failure Taxonomy

A systematic characterization of when and why automated function extraction fails, with actionable recommendations for improving vulnerability database reporting practices.

### Contribution 4: Recall Benchmark Against Project KB

The first automated recall measurement for function-level vulnerability extraction, using Project KB as ground truth for the Java ecosystem.

---

## 6. Paper Outline

### Option A: MSR Data Showcase (4 pages)

```
§1  Introduction + Motivation                          (0.5 page)
    - The function-level CVE gap
    - Why this blocks reachability analysis

§2  Mining Technique                                   (1.0 page)
    - Pipeline overview (figure)
    - Two-tier extraction (regex + AST)
    - Confidence scoring

§3  Dataset Description                                (1.0 page)
    - Corpus statistics (table: advisories by language, CWE)
    - Schema and access
    - Comparison with Project KB

§4  Validation + Failure Analysis                      (1.0 page)
    - Precision per language (table)
    - Recall vs. Project KB
    - Failure taxonomy (table)

§5  Availability + Use Cases                           (0.5 page)
    - Zenodo DOI
    - Integration with OSCAR, Steady, etc.
    - Community call for contributions

References                                             (~15-20 refs)
```

### Option B: MSR Technical Paper (12 pages)

Extends Option A with:
- Detailed related work (Project KB, VulnCode-DB, VUDDY, etc.)
- Per-language precision/recall breakdown with statistical tests
- Longitudinal analysis: how has advisory quality changed over time?
- User study: do developers make better triage decisions with function-level data?
- Replication package with full pipeline code

---

## 7. Related Work

### Vulnerability Databases and Curation

| Work | What They Do | How We Differ |
|------|-------------|---------------|
| **Project KB** (Ponta et al., 2019) | Manually curate Java vulnerable methods | We automate extraction across 5 languages |
| **VulnCode-DB** (Google) | Link CVEs to code commits | We extract function-level granularity, not just commits |
| **VUDDY** (Kim et al., 2017) | Detect cloned vulnerable code via function hashing | We identify the original vulnerable function, not clones |
| **VCCFinder** (Perl et al., 2015) | Identify vulnerability-contributing commits | We extract from fix commits, not contributing commits |
| **OSV Schema** (Google, 2021) | Standardized advisory format with affected ranges | We extend the schema downward to function granularity |

### Patch Analysis

| Work | What They Do | How We Differ |
|------|-------------|---------------|
| **SZZ Algorithm** (Śliwerski et al., 2005) | Trace bug-introducing commits | We extract affected functions, not introducing commits |
| **Commit Guru** (Rosen et al., 2015) | Classify commits as bug-fixing | We parse the diff content, not just commit metadata |
| **PyDriller** (Spadini et al., 2018) | Mine Git repositories | We build on similar infrastructure but focus on function extraction |

### Reachability Analysis (Consumers of Our Data)

| Work | What They Do | How They'd Use Our Data |
|------|-------------|------------------------|
| **Eclipse Steady** (Plate et al., 2015) | Dynamic reachability for Java | Automated identification of vulnerable constructs |
| **OSCAR** (this project) | Static cross-level risk analysis | Function-level CVE-to-call-graph mapping |
| **Snyk Code** (commercial) | SAST + SCA integration | Automated function-level alert enrichment |

---

## 8. Implementation Plan

### Phase 1: Infrastructure (June 2026)

- [ ] Extract patch mining module from OSCAR Method Observatory into standalone package
- [ ] Create `oscar-patch-mining` GitHub repository with CI/CD
- [ ] Set up GHSA API integration for bulk advisory retrieval
- [ ] Implement rate-limiting and caching for GitHub API calls
- [ ] Define output schema (JSON + CSV)

### Phase 2: Multi-Language Support (July 2026)

- [ ] Refine JavaScript extractor (add class method support, destructuring)
- [ ] Refine Python extractor (add decorator support, nested functions)
- [ ] Implement Go extractor (receiver methods, init functions)
- [ ] Implement Rust extractor (impl blocks, trait methods, macros)
- [ ] Implement Java extractor (annotations, generic methods, lambdas)
- [ ] Add Tier 2 AST-based extraction for each language
- [ ] Unit test suite with known-good fix commits per language

### Phase 3: Corpus Construction (August 2026)

- [ ] Query GHSA for all advisories meeting inclusion criteria
- [ ] Run extraction pipeline on full corpus
- [ ] Generate corpus statistics and distribution analysis
- [ ] Identify Project KB overlap set for recall measurement

### Phase 4: Validation (September 2026)

- [ ] Design annotation guidelines document
- [ ] Sample 200 extractions (40 per language, stratified)
- [ ] Two-annotator labeling + Cohen's κ calculation
- [ ] Compute precision per language and overall
- [ ] Compute recall against Project KB
- [ ] Failure taxonomy coding and frequency analysis

### Phase 5: Paper Writing (October 2026)

- [ ] Draft MSR Data Showcase paper (4 pages)
- [ ] Assess whether results warrant full Technical Paper (12 pages)
- [ ] Prepare replication package (code, data, scripts)
- [ ] Request Zenodo DOI for dataset
- [ ] Internal review with collaborator

### Phase 6: Submission (November 2026)

- [ ] Final revision based on internal review
- [ ] Submit to MSR 2027
- [ ] Prepare supplementary materials (video, poster if required)

---

## 9. Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Low yield on new languages (Go, Rust, Java) | Medium | Medium | Regex + AST two-tier approach; fail gracefully |
| GitHub API rate limiting blocks corpus construction | Medium | High | Token rotation, aggressive caching, incremental processing |
| Project KB overlap too small for recall measurement | Low | Medium | Supplement with manual curation of 50 Java advisories |
| Low inter-annotator agreement on validation | Low | High | Pre-study calibration round; detailed annotation guidelines |
| MSR 2027 deadline earlier than expected | Low | Medium | SCORED 2026 or SANER 2027 as backup venues |
| Precision drops significantly at scale | Medium | High | Confidence threshold tuning; Tier 2 AST extraction |

---

## 10. Resource Requirements

| Resource | Need | Status |
|----------|------|--------|
| GitHub API token(s) | 2-3 tokens for rate limit rotation | Available |
| Compute for batch processing | Local machine sufficient for 2K advisories | Available |
| Annotation labor | 2 annotators × ~20 hours each | Fabian + Rakesh |
| Project KB dataset | Publicly available | Download needed |
| Zenodo account | For DOI assignment | Create when ready |

---

## 11. Success Criteria

The paper is ready for submission when:

- [ ] Corpus ≥ 500 advisories processed across ≥ 3 languages
- [ ] Precision validated on ≥ 100 samples with inter-annotator agreement κ ≥ 0.7
- [ ] Recall measured against Project KB on ≥ 50 overlapping advisories
- [ ] Failure taxonomy with ≥ 5 categories and frequency counts
- [ ] Dataset published on GitHub with DOI
- [ ] Paper reviewed internally by at least one co-author

---

## 12. Timeline Summary

```
Jun 2026  ████████  Infrastructure + standalone extraction
Jul 2026  ████████  Multi-language support (Go, Rust, Java)
Aug 2026  ████████  Corpus construction (1000+ advisories)
Sep 2026  ████████  Validation + failure analysis
Oct 2026  ████████  Paper writing + dataset packaging
Nov 2026  ████████  Submission to MSR 2027
```

---

## 13. Connection to OSCAR and EB-2 NIW

This paper strengthens the OSCAR research portfolio by:

1. **Demonstrating independent value** of a component originally developed for OSCAR
2. **Producing a citable community resource** (function-level CVE dataset)
3. **Targeting a top venue** (MSR) that complements ICSME submissions
4. **Building publication count** for the EB-2 NIW petition with a distinct contribution

The narrative arc across publications becomes:
- **ICSME Visions 2026:** The cross-level risk propagation concept
- **ICSME Tool Demo 2026:** The OSCAR platform implementation
- **MSR 2027:** The patch mining technique and dataset (standalone contribution)
- **Future:** Full empirical study with large-scale evaluation
