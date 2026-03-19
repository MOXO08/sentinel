# Sentinel Scan

![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Sentinel%20Verified-blue)

Deterministic AI compliance scanner for the EU AI Act.

Run local audits on AI systems, manifests, and documentation.
Works offline. No external API calls. No telemetry by default.

- **Risk-aware scoring**: Tiered requirements (Minimal / Limited / High / Unacceptable).
- **Article verification**: Formal mapping to EU AI Act articles (Art. 9, 13, 14, 20).
- **CI-ready**: Non-zero exit codes on compliance failure (suitable for CI pipelines)
- **Fail-safe**: Automatic fallback to internal default policy.

## Install

```bash
npm install -g @radu_api/sentinel-scan
```

Or run directly via npx (Zero Ambiguity Contract):

```bash
npx @radu_api/sentinel-scan@latest check --manifest sentinel.manifest.json
```

## Quick Start

Create a `sentinel.manifest.json` using the top-level schema:

```json
{
  "app_name": "hr-cv-screening-ai",
  "risk_category": "high",
  "declared_flags": [
    "transparency_disclosure_provided",
    "user_notification_ai_interaction"
  ],
  "human_oversight": {
    "description": "Human reviewer monitors decisions and can override outputs."
  },
  "oversight_evidence_path": "docs/compliance/human_oversight.md",
  "logging_capabilities": {
    "enabled": true,
    "events_logged": ["input", "output", "decision"]
  },
  "logging_evidence_path": "docs/compliance/data_governance.md"
}
```

Run the scan (Implicitly looks for sentinel.manifest.json):

```bash
npx @radu_api/sentinel-scan
```

Or target a specific file using the explicit contract:

```bash
npx @radu_api/sentinel-scan check --manifest sentinel.manifest.json
```

## Required Supporting Documents

For high-risk systems, the scanner expects evidence files at specific paths if declared in the manifest:

- `docs/compliance/risk_assessment.md` (Art. 9)
- `docs/compliance/human_oversight.md` (Art. 14)
- `docs/compliance/data_governance.md` (Art. 20)

## Example Execution Flow

```text
╔══════════════════════════════════════════════════╗
║  🛡  SENTINEL — LOCAL DIAGNOSTIC TOOL (OFFLINE)  ║
╚══════════════════════════════════════════════════╝

Scanning: sentinel.manifest.json
Mode: ⚡ Local Diagnostic

✅ Sentinel compliance check passed
Compliance Status: COMPLIANT
Base Score: 100/100
Deductions: -0
Final Score: 100/100
Confidence Level: HIGH
Risk Category: high
Required Controls: Art. 9, Art. 13, Art. 14, Art. 20
Verified Controls: Art. 9, Art. 13, Art. 14, Art. 20
Verified Articles: Art. 9, Art. 13, Art. 14, Art. 20

Sentinel policy: default.policy.json
```

"Verified Articles indicate which regulatory requirements are substantiated.  
They do not imply full legal compliance."

## Risk Model

Sentinel implements a risk-aware requirement matrix:

- **Minimal**: Requires basic transparency signal (Art. 13). 100/100 score if flag is present.
- **Limited**: Requires Art. 13 + explicit evidence (JSON/Markdown file). Flag alone is insufficient and results in a failing score (0/100).
- **High-Risk**: Requires substantiation for Art. 9 (Risk), Art. 13 (Transparency), Art. 14 (Oversight), and Art. 20 (Logging).
- **Unacceptable**: Immediate HARD FAIL for prohibited practices (e.g., social scoring). Final score is forced to 0.

## Policy System

Sentinel uses a tiered policy resolution system:

1. **Local Policy**: Looks for `sentinel.policy.json` in the working directory.
2. **Fallback**: Automatically uses the internal [default.policy.json](cci:7://file:///d:/AI%20Act%20Compliance%20API/sentinel-cli/configs/default.policy.json:0:0-0:0) if no local file is found.

The CLI is designed to run in empty or clean environments (like Docker or CI) without requiring manual configuration of a policy file for basic audits.

## CI Integration

Add Sentinel to your GitHub Actions workflow:

```yaml
- name: Run Sentinel Compliance Scan
  run: npx @radu_api/sentinel-scan check --manifest sentinel.manifest.json
```

The CLI returns exit code `0` on success and non-zero on compliance failure or hard fails.

## Philosophy

- **Deterministic**: Outcomes are based on code-level signals and evidence files, not probabilistic models.
- **Explainable**: All scores are broken down by Base Score (required controls) and Deductions (findings).
- **Transparent**: Article verification is earned through substantiation, never assumed.
- **Standard-First**: Mapping follows the official EU AI Act (EU 2024/1689).

## Links

- **Verified Registry**: [https://moxo08.github.io/sentinel-verified/](https://moxo08.github.io/sentinel-verified/)
- **Repository**: [https://github.com/MOXO08/sentinel](https://github.com/MOXO08/sentinel)