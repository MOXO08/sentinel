# Sentinel Scan

![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Technical%20Evidence-blue)

Sentinel is a static analysis CLI tool that extracts and verifies technical evidence for EU AI Act compliance. It scans local repository file-sets to identify code signatures, configuration patterns, and documentation markers for regulatory alignment.

---

## 📘 Overview

Sentinel evaluates the alignment of a repository implementation with defined regulatory requirements through pattern-based detection. It correlates technical signals with documentation declarations to provide a verifiable technical evidence base.

## 🚀 Core Capabilities

- **Signal Extraction**: Recursive scanning for technical implementation markers (libraries, API calls, structural patterns).
- **Integrity Guard (SIG)**: Zero-trust verification that strips comments and strings to ensure compliance signals exist in executable logic.
- **Correlation Logic**: Multi-signal verification that cross-references documentation claims with technical reality.
- **Audit Evolution**: Tracking of compliance progression or regression between repository states.

## 🛠️ Installation

```bash
npm install -g @radu_api/sentinel-scan
```

## 📋 Quick Start

```bash
# 1. Initialize repository manifest
sentinel-scan init

# 2. Extract technical signals
sentinel-scan discover

# 3. Generate baseline technical documentation
sentinel-scan fix --apply

# 4. Perform technical audit
sentinel-scan check --threshold 80
```

## 📥 Input Requirements
- **Repository Scope**: Local filesystem directory with source code and CI/CD configs.
- **Manifest**: `sentinel.manifest.json` declaring system identity and article coverage.
- **Source Code**: Python and JavaScript/TypeScript files.

## 📤 Output Artifacts
- **Terminal Summary**: Audit verdict, score, and prioritized findings.
- **Audit Ledger (JSON)**: Machine-readable report with forensic hashes and signal IDs.
- **Audit Signature**: RSA-PSS (SHA-256) cryptographic digest ensuring report integrity.
- **Annex IV Dossier (if generated)**: Structured technical documentation for regulatory submission.

## ⚖️ Audit Verdict Model
Sentinel calculates a final verdict based on a dual-track evaluation of technical maturity and documentation completeness:
- **APPROVED**: Robust technical implementation and complete documentation.
- **HOLD**: Technical implementation is robust but documentation requires completion.
- **REJECTED**: Critical technical or documentation gaps detected in the repository implementation.

---

## 🛡️ Regulatory Mapping (Technical Levels)

| Article | Requirement | Target Signal |
| :--- | :--- | :--- |
| **Art. 9** | Risk Management | Risk assessment artifacts and bias mitigation libraries (e.g., Fairlearn). |
| **Art. 13** | Transparency | User disclosures, AI indicators, and transparency cards. |
| **Art. 14** | Human Oversight | Hard-coded kill-switches and manual override logic. |
| **Art. 20** | Traceability | Industrial logging frameworks and trace-ID propagation patterns. |

---

## ⚠️ Limitations & Boundary Conditions
- **Static Analysis Only**: Sentinel does not observe repository implementations during execution.
- **No External Verification**: Cloud infrastructure and external APIs are outside the scan scope.
- **Supporting Evidence**: Sentinel establishes a technical floor of evidence; it does not issue legal opinions, certifications, or regulatory approvals.

## 💡 Valid Use Case
Engineering and compliance teams use Sentinel to verify that technical controls are physically implemented in the codebase. It is executed in CI/CD pipelines for technical verification to ensure repository implementations maintain a verifiable evidence base for Annex IV documentation.

---

## Documentation
- [User Manual](USER_MANUAL.md)
- [Known Limitations](KNOWN_LIMITATIONS.md)
- [NPM Registry](https://www.npmjs.com/package/@radu_api/sentinel-scan)

---
*Last Updated: 2026-03-25. Aligned with Sentinel v2.1-SEC core logic.*