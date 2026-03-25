# Sentinel User Manual 🛡️

This guide provides the functional steps for identifying technical compliance markers and generating verifiable evidence for Annex IV documentation.

---

## 🏗️ 1. Preparation

Before running Sentinel, ensure your environment meets the following requirements:
1.  **Node.js**: Install Node.js (LTS version recommended).
2.  **Verification**: Confirm installation by running `node -v` in your terminal.

---

## 💻 2. Basic Technical Audit Flow

The standard execution sequence for a repository implementation:

### Step 1: Initialization (`init`)
```bash
sentinel-scan init
```
- **Action**: Creates the `sentinel.manifest.json` configuration file.
- **Note**: This file declares the target AI implementation details and technical coverage areas.

### Step 2: Autodiscovery (`discover`)
```bash
sentinel-scan discover
```
- **Action**: Extracts technical signals from source code and CI/CD configurations.
- **Note**: It identifies library imports and functional hooks that correspond to EU AI Act technical requirements.

### Step 3: Technical Scan (`check`)
```bash
sentinel-scan check --threshold 80
```
- **Action**: Performs a structured audit against the manifest and discovered signals.
- **Output**: Returns a score and technical findings based on documentation completeness and technical maturity.

### Step 4: Documentation Patching (`fix`)
```bash
sentinel-scan fix --apply
```
- **Action**: Generates placeholder technical documentation structures aligned with detected signals.

---

## 💡 3. Technical Integrity & SIG

Sentinel implements the **Sentinel Integrity Guard (SIG)** to ensure all technical claims are substantiated by executable code:

- **Article 13 (Transparency)**: Requires detectable transparency indicators in the repository scope.
- **Article 14 (Human Oversight)**: Requires detectable control hooks (e.g., `manualOverride`, `killSwitch`).
- **Article 20 (Traceability)**: Requires detectable industrial logging frameworks.

> [!IMPORTANT]
> **Static Integrity Rule**: Sentinel strips commentary and non-executable strings before performing signal matching to prevent "document-only" compliance claims for features that do not exist in code.

---

## 🔄 4. Understanding Verdicts

The dual-track model produces one of three verdicts for any repository implementation:

- **APPROVED**: Technical controls are physically detected and documentation is complete.
- **HOLD**: Technical controls are detected but mandatory documentation markers are missing.
- **REJECTED**: Critical technical gaps or significant documentation deficiencies detected.

---

## ⚠️ 5. Ethical & Legal Disclaimer

**Sentinel is a Technical Evidence Engine, not a Legal Certification.**
- It establishes a technical baseline of evidence within the repository scope.
- It does not observe runtime behavior or Verify external system outputs.
- A "V-Score" of 100/100 does not constitute legal approval under the EU AI Act.

---
*Last Updated: 2026-03-25. Reference: CURRENT_STATE.md.*
