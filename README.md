# Sentinel Scan

![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Sentinel%20Verified-blue)

Deterministic AI compliance scanner for the EU AI Act.

Run local audits on AI systems, manifests, and documentation.  
Works offline. No external API calls. No telemetry by default.

---

## 📕 Official User Manual
For a comprehensive guide covering both **Executive Reports (Sovereign)** and **Technical CLI Usage**, please refer to our unified manual:

👉 [**USER_MANUAL.md**](USER_MANUAL.md)

---

## Install

```bash
npm install -g @radu_api/sentinel-scan
```

Or run instantly:

```bash
npx @radu_api/sentinel-scan@latest check --manifest sentinel.manifest.json
```

> Sentinel enforces a **zero-ambiguity CLI contract**.  
> Positional arguments are NOT supported.

---

## 🚀 Quick Start (Recommended Flow)

```bash
# 1. Initialize manifest
npx @radu_api/sentinel-scan@latest init

# 2. (Optional) Discover signals in your project
npx @radu_api/sentinel-scan@latest discover

# 3. Scaffold missing compliance structure
npx @radu_api/sentinel-scan@latest fix --apply

# 4. Run compliance check
npx @radu_api/sentinel-scan@latest check --threshold 90 --manifest sentinel.manifest.json
```

---

## CLI Usage

### Default behavior

Runs a scan on `sentinel.manifest.json` in the current directory:

```bash
npx @radu_api/sentinel-scan@latest
```

### Explicit behavior (recommended)

```bash
npx @radu_api/sentinel-scan@latest check --threshold 90 --manifest sentinel.manifest.json
```

---

## Manifest Example

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

---

## Required Supporting Documents

For high-risk systems:

- `docs/compliance/risk_assessment.md` (Art. 9)
- `docs/compliance/human_oversight.md` (Art. 14)
- `docs/compliance/data_governance.md` (Art. 20)

---

## Example Output

```text
Sentinel Check: PASS
Score: 100/100
Risk Category: high

Verified Articles:
Art. 9, Art. 13, Art. 14, Art. 20
```

> Verified Articles indicate substantiated requirements.  
> They do NOT imply full legal compliance.

---

## Risk Model

- **Minimal** → Basic transparency (Art. 13)
- **Limited** → Transparency + evidence required
- **High-Risk** → Full coverage (Art. 9, 13, 14, 20)
- **Unacceptable** → Immediate HARD FAIL

---

## Policy System

Sentinel uses deterministic policy resolution:

1. Local: `sentinel.policy.json`
2. Fallback: internal default policy

Used ONLY when no local policy exists to ensure consistent CI behavior.

---

## CI Integration

```yaml
- name: Sentinel Compliance Scan
  run: npx @radu_api/sentinel-scan@latest check --manifest sentinel.manifest.json
```

Returns:

- `0` → pass  
- non-zero → failure  

---

## Philosophy

- Deterministic  
- Explainable  
- Offline-first  
- Standard-aligned (EU AI Act 2024/1689)

---

## Links

- Verified Registry: https://moxo08.github.io/sentinel-verified/
- Repository: https://github.com/MOXO08/sentinel