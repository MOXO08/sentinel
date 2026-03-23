# Official User Manual: Sentinel & Sovereign Framework 🛡️

This guide is designed to take you from **Zero to 100% Compliance** in the shortest time possible. Follow the steps below based on your role.

---

## 🏗️ 1. Preparation (One-Time)
Before running Sentinel, ensure you have the execution "engine" installed:
1.  **Download Node.js**: Visit [nodejs.org](https://nodejs.org/) and install the **LTS** version (recommended).
2.  **Verify**: Open a terminal (Command Prompt or PowerShell) and type `node -v`. If you see a version number (e.g., `v20.x.x`), you are ready!

---

## 🤝 2. Guide for Clients & Managers (No-Code)
If your task is to verify the score and generate reports for management, follow these steps:

### Step A: Consulting the Global Dashboard
1.  Navigate to the project folder through Windows Explorer.
2.  Open the folder: `[Project-Folder]\sovereign-reports\`
3.  Double-click on: `sovereign-portfolio-report.html`
    - **What do you see?** An overview of all projects, with color-coded scores (Green = Good, Red = Danger).

### Step B: Generating the PDF Boardroom Report
1.  While you have the HTML report open in your browser (Chrome/Edge):
2.  Press the keys: `Ctrl + P` (Print).
3.  Under "Destination," choose: **Save as PDF**.
4.  This document is now ready to be sent via email to investors or legal counsel.

---

## 💻 3. Guide for Developers (First Audit)
Run these commands in the terminal, in the root folder of your project:

### Step 1: Initialization (`init`)
```bash
npx @radu_api/sentinel-scan init
```
- **Goal**: Creates the AI "ID card" (`sentinel.manifest.json`).
- **Tip**: If the file already exists, the program will refuse to overwrite it for data protection.

### Step 2: Autodiscovery (`discover`)
```bash
npx @radu_api/sentinel-scan discover
```
- **Goal**: Automatically scans the project to find hidden or forgotten AI models.

### Step 3: Global Portfolio Audit (`portfolio`)
```bash
npx @radu_api/sentinel-scan portfolio --threshold 90
```
- **Goal**: Automatically discovers all compliance manifests in the current directory and subdirectories.
- **Result**: Performs a fleet-wide audit and generates a consolidated **Sovereign Portfolio Dashboard** in HTML/MD.
- **Resilience**: Individually failing repositories are skipped without stopping the global process.

### Step 4: The Actual Audit (`check`)

### Step 4: Automatic Correction (`fix`)
```bash
npx @radu_api/sentinel-scan fix --apply
```
- **Goal**: Automatically generates the technical documentation structure required to pass the audit.

---

## 🛠️ 4. Troubleshooting - Common Issues

| Issue | Possible Cause | Solution |
| :--- | :--- | :--- |
| `npx: command not found` | Node.js is not installed or not in PATH. | Reinstall Node.js and ensure "Add to PATH" is checked. |
| `Sentinel Check: FAIL` | The score is below the set `--threshold`. | Run `npx sentinel-scan fix --apply` to correct errors. |
| `Permissions Error (PS)` | The `.ps1` script is blocked by Windows. | Run in terminal: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. |
| `Manifest already exists` | Trying to run `init` over an existing file. | Manually delete `sentinel.manifest.json` if you want to start over. |

---

## 🔄 5. Portfolio Automation
If you have multiple projects and want to audit them all in one action:
1.  Open PowerShell in the main folder.
2.  Run: `./_antigravity-audit.ps1`
3.  **Result**: The system will "fly" through all folders, perform the audit, and automatically populate the `sovereign-reports/` folder.

---

## 💡 6. Technical Integrity & Hardening
Sentinel uses **Sovereign Hardening Probes** to ensure that compliance claims are backed by physical code, not just words:
- **Artificial Intelligence Disclosure (Art. 13)**: Requires detectable UI labels or strings (e.g., `powered-by-ai`) in the public application path.
- **Human Oversight (Art. 14)**: Requires detectable control hooks (e.g., `manualOverride`, `killSwitch`).
- **Data Governance (Art. 20)**: Requires detectable industrial logging (e.g., `winston`, `pino`).

> [!IMPORTANT]
> **Documentation is NOT proof.** Sentinel explicitly ignores files in `docs/compliance/` when searching for technical probes. This prevents "self-validation" and ensures that if a feature is claimed, it truly exists in your implementation.

---

## 🔄 7. Meaning of Verdicts
- **COMPLIANT (Green)**: ✅ Passed. The system meets legal requirements.
- **PARTIAL (Yellow)**: ⚠️ Documentation is incomplete or the score is borderline.
- **NON_COMPLIANT (Red)**: ❌ Legal danger. The AI does not meet minimum standards.

---
*This manual is your property and is updated along with the Sovereign system.*
