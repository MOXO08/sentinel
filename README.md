# 🛡 sentinel-scan (v1.2.3)

**Deterministic AI compliance infrastructure for the EU AI Act. 100% offline. Zero-Egress. Driven by a high-performance Rust engine.**

Sentinel automates regulatory technical verification directly in your development workflow. It bridges the gap between official AI Act requirements (EU 2024/1689) and your repository reality.

[![npm version](https://img.shields.io/npm/v/sentinel-scan.svg)](https://npmjs.com/package/sentinel-scan)
[![license](https://img.shields.io/npm/l/sentinel-scan.svg)](LICENSE)
[![eu-ai-act](https://img.shields.io/badge/EU%20AI%20Act-2024%2FReady-blue)](https://artificialintelligenceact.eu/)
[![Documentation](https://img.shields.io/badge/docs-canonical-green)](https://github.com/MOXO08/sentinel)

---

## ⚡ 2-Minute Quickstart

Run a local diagnostic scan without an account or API key:

```bash
npx sentinel-scan ./manifest.json
```

**Zero Data Exfiltration.** The compliance engine runs locally via WebAssembly. Your source code and AI manifests never leave your machine.

---

## ⚡ Quick Start

Run Sentinel locally:

```bash
npx sentinel-scan ./manifest.json
```

**No tokens. No API keys. No network calls.**

The entire EU AI Act ruleset runs locally inside a WebAssembly binary.

---

## GitHub Action

Sentinel can run automatically in CI using the official GitHub Action. This is the recommended way to enforce compliance for every Pull Request.

[https://github.com/MOXO08/sentinel-scan-action](https://github.com/MOXO08/sentinel-scan-action)

### Example Workflow

```yaml
name: Sentinel Compliance

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  sentinel:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Sentinel Scan
        run: npx sentinel-scan ./manifest.json
```

---

## Sentinel Verified Registry

Explore public AI projects scanned with Sentinel:

[https://moxo08.github.io/sentinel-verified/](https://moxo08.github.io/sentinel-verified/)

Repositories using Sentinel can appear in the public registry of repositories scanned for EU AI Act readiness.

---

## 🛡 Namespaced Rule IDs
Sentinel uses a deterministic identification system for compliance issues:
- `EUAI-GOV-*` — Governance & Data Policy
- `EUAI-DOC-*` — Missing Evidence/Documentation
- `EUAI-TECH-*` — Technical Transparency
- `EUAI-DATA-*` — Data Governance & Bias
- `EUAI-BLOCK-*` — Prohibited Practices (Blocked)

---

## Why developers use Sentinel

• **Deterministic compliance checks** based on official regulation.
• **Runs 100% offline** for maximum data privacy.
• **CI/CD friendly** with SARIF and JSON output.
• **WebAssembly execution** (<5ms latency).
• **GitHub Security integration** via native alerts.

---

## Data Contract (Example Manifest)

Create a `manifest.json` file describing your AI application:

```json
{
  "app_name": "hr-cv-screener",
  "version": "2.1.0",
  "risk_category": "High",
  "app_description": "Automated CV screening assistant for enterprise hiring.",
  "declared_flags": [
    "human_oversight_enabled",
    "bias_assessment_performed",
    "data_governance_policy_documented",
    "user_notification_ai_interaction"
  ],
  "fallback_ai_verification": false
}
```

### Risk Category Reference

| Value | When to use |
|---|---|
| `Minimal` | Chatbots, spam filters, recommendation engines |
| `Limited` | Emotion-aware UX, deepfake detection tools |
| `High` | HR screening, medical diagnosis, credit scoring |
| `Unacceptable` | Social scoring, subliminal manipulation (blocked) |

---

## CI/CD Integration & SARIF

Sentinel exports findings in SARIF format for native integration with GitHub Security.

### Generate SARIF for Code Scanning

### Generate SARIF for GitHub Security
```bash
npx sentinel-scan ./manifest.json --sarif > sentinel.sarif
```
*Upload the resulting SARIF file to the GitHub Security tab to see compliance findings as native code scanning alerts.*

---

## Advanced Features

### Policy Packs & Registry
Sentinel supports reusable compliance rulesets:
- `policy-pack list`: List all built-in rulesets.
- `policy-pack show <name>`: Inspect specific rule requirements.

### Compliance Evidence Pack
Generate a full regulatory technical file (JSON, SARIF, Markdown):
```bash
npx sentinel-scan ./manifest.json --evidence
```
This creates a `sentinel-evidence/` folder containing all required audit artifacts.

### Audit Ledger Sync
Canonically synchronize your local evidence pack to the SaaS dashboard:
```bash
npx sentinel-scan evidence push ./sentinel-evidence --api-key YOUR_KEY
```

### Baseline Support
Adopt Sentinel incrementally by ignoring existing compliance debt:
```bash
npx sentinel-scan manifest.json --baseline .sentinel-baseline.json
```

---

## Verdict Reference

| Verdict | Meaning | Action |
|---|---|---|
| `COMPLIANT` | Passed all applicable rules | ✅ Safe to Ship |
| `NON_COMPLIANT` | Violation detected | ❌ Block deploy |
| `HIGH_RISK` | High-risk system requirements | ⚠️ Audit required |
| `BLOCKED` | Art. 5 prohibited practice | 🚫 Hard block |

---

## Remote Audit Mode

For official **Automated Compliance Reports** (Audit-grade PDF), use the remote flag:

```bash
npx sentinel-scan ./manifest.json --remote --api-key YOUR_KEY
```

**[→ Visit Dashboard](https://sentinel-api.sentinel-moxo.workers.dev/dashboard)**

---

## Troubleshooting

### WASM Execution Errors
If you encounter an error related to `sentinel_engine.wasm`, ensure you are using a Node.js version >= 18.0.0 and that the `.wasm` file is present in the `pkg-node/` directory.

---

## License

UNLICENSED — Commercial use requires a Sentinel subscription.
