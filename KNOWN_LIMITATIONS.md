---
# Sentinel Known Limitations Registry
Version: 1.0
Updated: 2026-03-22
Maintained by: Sentinel Engineering

This registry documents all known limitations of the
Sentinel forensic engine. It is updated with every
new phase and every newly discovered boundary.

Documenting limitations is not a weakness.
It is the foundation of forensic credibility.

---

## OPEN LIMITATIONS

### KL-001: Code Obfuscation Bypass
Status: OPEN
Severity: MEDIUM
Affects: AI Detection (Phase 2), Signal Extraction
Description:
  Sentinel can be bypassed by renaming AI-related
  functions to non-standard names.
  Example: generate() renamed to fetchData() will
  not be caught by keyword-based pattern matching.
Mitigation:
  Semantic layering (Phase 2) reduces this risk by
  detecting parameter signatures (temperature,
  max_tokens) and response structures
  (.choices[0].message.content).
  However, a determined developer can still evade
  detection by renaming both functions and parameters.
Impact:
  A finding may be classified ABSENT when the control
  exists under a non-standard name.
  Trust Score may be understated for obfuscated repos.
Workaround for users:
  Manual review is recommended for repositories with
  non-standard naming conventions.
  Declaring all AI execution points in
  sentinel.manifest.json mitigates this limitation.
Discovered: 2026-03-22
Target resolution: Phase 11 (LLM Semantic Layer)

---

### KL-002: External API Blindness
Status: OPEN
Severity: HIGH
Affects: AI Detection, Risk Classification
Description:
  Sentinel is 100% blind to AI systems that operate
  via remote APIs using generic HTTP or gRPC calls
  without standard SDK library imports.
  Example: A system calling a biometric AI API via
  a generic fetch() call with no openai/langchain
  import will be reported as "No AI Execution Detected."
Mitigation:
  None currently available in static analysis mode.
  Requires runtime analysis (Phase 12) for full coverage.
Impact:
  Trust Score may be significantly inflated for systems
  using external AI APIs without library imports.
  Risk classification may be understated (LOW when
  actual risk is HIGH).
Workaround for users:
  All external AI API dependencies MUST be declared
  in sentinel.manifest.json under "external_ai_apis".
  Undeclared external APIs are outside scan boundary.
Discovered: 2026-03-22
Target resolution: Phase 12 (Runtime Agent)

---

### KL-003: Dynamic Import Blindness
Status: OPEN
Severity: MEDIUM
Affects: Cross-File Dependency Mapping (Phase 9)
Description:
  Dynamic imports using require(variable) or
  import() with a computed path are not tracked
  in the dependency graph built by autodiscovery.js.
  A compliance control imported dynamically will
  appear as ABSENT in cross-file analysis.
  Example: require(config.controlModule) where
  config.controlModule = './governance.js' will
  not be resolved by the static import extractor.
Mitigation:
  extractImports() handles static CommonJS (require)
  and ESM (import) statements correctly.
  Dynamic patterns are outside current scope.
Impact:
  False positive on VOID/ABSENT classification for
  repositories using webpack aliases, barrel exports,
  or dynamic module loading patterns.
  An AI execution file may appear ungoverned when it
  is actually connected to a control via dynamic import.
Workaround for users:
  Use static imports for all compliance control modules.
  Replace require(variable) with explicit
  require('./governance.js') for sentinel-tracked files.
Discovered: 2026-03-22
Target resolution: Phase 9b (AST full resolution)

---

### KL-004: Windows Buffer Limit
Status: MITIGATED
Severity: LOW
Affects: Reproducibility Test Suite
Description:
  On Windows, spawned child processes hit default Node.js
  maxBuffer limit (200KB) when scanning large repositories,
  causing scan to crash mid-execution.
Mitigation:
  maxBuffer set to 10 * 1024 * 1024 (10MB) in
  run_reproducibility_test.js
Impact:
  Very large repos (>10MB stdout) may still hit limit.
Workaround:
  Resolved by Phase 11 fix in reproducibility suite.
Discovered: 2026-03-22
Target resolution: RESOLVED (Mitigated).

---

### KL-005: Python Relative Imports
Status: OPEN
Severity: MEDIUM
Affects: Phase 9 Cross-File Dependency Mapping
Description:
  Python relative imports using `from .module import X` or
  `from ..module import Y` syntax are not resolved by the
  dependency graph builder.
Impact:
  Affected files appear disconnected even when they are
  connected, causing false Scenario A penalties
  (-20 trust score points).
Workaround:
  None. Manual inspection required for Python packages
  using relative imports.
Discovered: 2026-03-22
Target resolution: Phase 9b (AST full resolution).

---

### KL-006: Semantic Evaluation Requires External LLM
Status: OPEN
Severity: LOW
Affects: Phase 11 Semantic Layer
Description:
  Semantic document quality evaluation requires
  an external LLM API (OpenAI or Anthropic).
  If no API key is configured, semantic_quality
  field is populated with evaluated: false.
  All other scan functionality is unaffected.
Impact:
  Without LLM configuration, Sentinel cannot
  evaluate document quality — only document
  existence. "Deaf Spot" limitation remains
  active without API key.
Workaround:
  Set environment variables:
  SENTINEL_LLM_PROVIDER=openai|anthropic
  SENTINEL_LLM_API_KEY=[your key]
Discovered: 2026-03-22
Target resolution: By design — requires user
                   API key configuration.

---

### KL-007: Single Article Mapping Per Document
Status: OPEN
Severity: LOW
Affects: Phase 11 Semantic Layer
Description:
  Each document finding is mapped to a single EU AI Act
  article. Documents that are relevant to multiple
  articles (e.g., a technical file covering both Art.11
  and Art.17) are only credited for one.
Impact:
  This may undercount compliance evidence and deflate
  trust score for well-documented systems.
Workaround:
  None. Multi-article mapping planned for future phase.
Discovered: 2026-03-23
Target resolution: Planned enhancement.

---

## RESOLVED LIMITATIONS

### KL-000: Non-reproducible scan outputs
Status: RESOLVED
Resolved in: v2.1
Resolution:
  SHA-256 hashing implemented in generateEvidencePack().
  Evidence package seal verified in runVerify().
  PEM-based digital signatures applied to all reports.
  Reproducibility confirmed across 3 consecutive runs.
Originally discovered: 2026-03-01

---

## HOW TO ADD A NEW LIMITATION

When a new limitation is discovered:
1. Add entry under OPEN LIMITATIONS
2. Assign next KL number (KL-004, KL-005, etc.)
3. Fill all fields: Status, Severity, Affects,
   Description, Mitigation, Impact, Workaround,
   Discovered, Target resolution
4. Link from the relevant phase walkthrough
5. Update "Version" and "Updated" fields at top

When a limitation is resolved:
1. Move entry to RESOLVED LIMITATIONS section
2. Change Status to RESOLVED
3. Add "Resolved in: [version]" field
4. Add "Resolution: [what was done]" field
5. Keep original "Originally discovered" date

---
*This file is referenced in every Sentinel audit report footer.*
*Last entry: KL-007*
---
