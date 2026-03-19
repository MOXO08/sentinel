# Sentinel Scan

Deterministic AI compliance scanner for the EU AI Act.

Works offline. No external API calls. No telemetry by default.

---

## Install

npm install -g @radu_api/sentinel-scan

Or run:

npx @radu_api/sentinel-scan@latest check --threshold 90 --manifest sentinel.manifest.json

---

## Quick Start

npx @radu_api/sentinel-scan@latest init
npx @radu_api/sentinel-scan@latest fix --apply
npx @radu_api/sentinel-scan@latest check --threshold 90 --manifest sentinel.manifest.json

---

## CLI Contract

No positional arguments are supported.
Always use explicit flags.

---

## Example Output

Sentinel Check: PASS
Score: 100/100

---

## CI

npx @radu_api/sentinel-scan@latest check --manifest sentinel.manifest.json

---

## Philosophy

Deterministic  
Offline-first  
Explainable  