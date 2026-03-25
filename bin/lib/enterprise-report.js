const fs = require('fs');
const path = require('path');

/**
 * Enterprise Audit Report Generator
 * Transforms Sentinel JSON scan results into a boardroom-ready Markdown document.
 * 
 * @param {object} scanResult - The full JSON output from Sentinel scan.
 * @returns {string} - Path to the generated markdown file.
 */
function generateEnterpriseReport(scanResult) {
    if (!scanResult) throw new Error("No scan result provided.");

    const manifest = scanResult.manifest || {};
    const context = scanResult.audit_context || {};
    const summaries = scanResult.article_summaries || {};
    const articles = summaries.articles || {};
    const findings = (scanResult._internal && scanResult._internal.all_findings) ? scanResult._internal.all_findings : (scanResult.findings || []);
    const coverage = scanResult.coverage || {};
    const attestation = scanResult.auditor_attestation || {};
    const nextStep = summaries.next_step || {};
    const limits = summaries.audit_limitations || {};
    const boundary = summaries.audit_boundary || {};
    const confidence = summaries.audit_confidence || {};

    const projectName = manifest.app_name || (scanResult.audit_scope && scanResult.audit_scope.within_scope ? scanResult.audit_scope.within_scope.repository : "Unknown AI System");
    const timestamp = context.timestamp || new Date().toISOString();
    const centralVerdict = scanResult.central_verdict || scanResult.verdict || "NOT_DETERMINED";
    
    // 1. Business-Readable Risk Mapping for Top Findings
    const topFindings = (scanResult.top_findings || findings.slice(0, 3)).map(f => {
        // Higher-order lookup if field is missing in top_findings summary
        let severity = f.severity;
        if (!severity) {
            const matchingFull = findings.find(full => full.rule_id === f.rule_id || full.description === f.description);
            severity = matchingFull ? (matchingFull.severity || (matchingFull.reasoning ? matchingFull.reasoning.severity : "INFO")) : "INFO";
        }
        
        const severityPrefix = severity.toUpperCase();
        const articleRef = f.article ? ` (${f.article})` : "";
        return `- **${severityPrefix} RISK**: ${f.description}${articleRef} — Potential deficiency in regulatory technical controls.`;
    }).join('\n');

    // 2. Methodology Derivation
    const methodologyBase = (summaries.audit_scope && summaries.audit_scope.method) ? summaries.audit_scope.method : "pattern-based detection";
    const methodologyLevel = confidence.verification_level || "PATTERN_BASED";
    
    // 3. Findings Segmentation
    const criticalGaps = findings.filter(f => (f.severity || (f.reasoning && f.reasoning.severity) || "").toLowerCase() === "critical").slice(0, 5);
    const highRisks = findings.filter(f => (f.severity || (f.reasoning && f.reasoning.severity) || "").toLowerCase() === "high").slice(0, 5);
    const informational = findings.filter(f => {
        const sev = (f.severity || (f.reasoning && f.reasoning.severity) || "").toLowerCase();
        return sev === "medium" || sev === "low" || sev === "info";
    }).slice(0, 5);

    const formatFinding = (f) => {
        const origin = f.evidence_origin || (f.source === "intelligence" ? "manifest_claim" : "code_pattern");
        const ref = f.source_reference || (f.evidence && f.evidence.checked_files ? f.evidence.checked_files[0] : (f.article ? `EU AI Act ${f.article}` : "N/A"));
        const type = f.evidence_type || "DETECTION";
        const note = (f.evidence && f.evidence.note) ? f.evidence.note : (f.reasoning && f.reasoning.reason ? f.reasoning.reason : "No specific technical evidence attached.");
        const severity = (f.severity || (f.reasoning && f.reasoning.severity) || "INFO").toUpperCase();
        
        return `
#### [${severity}] ${f.rule_id || "GNR-VAL-001"}
- **Finding ID**: \`${f.finding_id || "N/A"}\`
- **Requirement**: ${f.article || "General Compliance"}
- **Description**: ${f.description}
- **Reasoning**: ${f.reasoning && f.reasoning.reasoning ? f.reasoning.reasoning.join(' ') : "Automated rule violation identified in scanned scope."}
- **Traceability**:
    - **Origin**: ${origin}
    - **Reference**: \`${ref}\`
    - **Evidence Status**: ${type}
- **Technical Note**: ${note}
`;
    };

    // 4. Construct Markdown
    let md = `# ENTERPRISE AUDIT REPORT: ${projectName.toUpperCase()}
**Status**: INTERNAL AUDIT DOCUMENT — CONFIDENTIAL
**Date**: ${timestamp}
**Audit Framework**: EU AI ACT (Local Repository Coverage)

---

## 1. EXECUTIVE SUMMARY

### 1.1 Final Verdict
The analyzed AI system is currently assessed as **${centralVerdict.toUpperCase()}**.

### 1.2 Audit Readiness Summary
- **Current Readiness Status**: **${summaries.audit_readiness || "PENDING"}**
- **Sovereign Attestation Status**: **${attestation.status || "UNSUPPORTED"}**

### 1.3 Key Risk Identifiers (Business Summary)
${topFindings}

---

## 2. SYSTEM OVERVIEW & METHODOLOGY

### 2.1 Scope of Analysis
The audit was performed as a **${methodologyBase}** at the **${methodologyLevel}** level. The analysis targets technical signals representing regulatory requirements of the EU AI Act.

### 2.2 Audit Implementation
- **Detection Method**: Static pattern analysis / Proportional weighted scoring.
- **Verification Origin**: Physical repository artifacts (Code, Config, Manifest).

---

## 3. AUDIT CONFIDENCE

- **Signal Coverage**: **${confidence.signal_coverage || "LOW"}**
- **Verification Basis**: ${confidence.verification_level || "UNSPECIFIED"}
- **System Determinism**: ${confidence.determinism || "DETERMINISTIC (static analysis)"}
- **Determinism Note**: ${confidence.determinism_note || "Static analysis yields deterministic results across identical scopes."}
- **Status Note**: Technical confidence is derived from the density of detected implementation patterns relative to manifest declarations.

---

## 4. KEY FINDINGS (PRIORITIZED)

### 4.1 CRITICAL GAPS
${criticalGaps.length === 0 ? "_No critical gaps detected within the analyzed scope._" : criticalGaps.map(formatFinding).join('\n')}

### 4.2 HIGH RISKS
${highRisks.length === 0 ? "_No high-risk findings detected._" : highRisks.map(formatFinding).join('\n')}

### 4.3 INFORMATIONAL & REMEDIATION NOTES
${informational.length === 0 ? "_No informational items recorded._" : informational.map(formatFinding).join('\n')}

---

## 5. ARTICLE-BY-ARTICLE ANALYSIS

| Article | Status | Findings | Residual Risk |
| :--- | :--- | :--- | :--- |
${Object.keys(articles).map(key => {
    const art = articles[key];
    return `| ${key} | ${art.status} | ${art.finding_count} | ${art.residual_risk} |`;
}).join('\n')}

---

## 6. TECHNICAL EVIDENCE SUMMARY

- **Analyzed Scope**: ${scanResult.audit_scope && scanResult.audit_scope.within_scope ? scanResult.audit_scope.within_scope.files_analyzed : "N/A"} files analyzed.
- **Signal Density Index**: ${coverage.signal_density_index || 0} (signals per file)
- **Status**: ${coverage.status || "PENDING"}

---

## 7. AUDITOR ATTESTATION (SOVEREIGN LAYER)

- **Status**: **${attestation.status || "UNSUPPORTED"}**
- **Primary Basis**: ${attestation.basis ? attestation.basis.join('; ') : "Insufficient data for formal basis."}
- **Auditor Note**: *"${attestation.auditor_note || "No additional notes provided."}"*

---

## 8. SCOPE LIMITATIONS & BOUNDARY CONDITIONS

### 8.1 Boundary Exclusions
The following areas are explicitly **OUT OF SCOPE**:
${boundary.exclusions ? boundary.exclusions.map(e => `- ${e}`).join('\n') : "- Not specified"}

### 8.2 Safe Mode Limitations
- **Epistemic Status**: ${limits.epistemic_status || "NON_EXHAUSTIVE"}
- **Mandatory Caveat**: ${limits.statement || "Absence of evidence is not proof of absence."}
- **Structural Risk**: ${limits.risk || "Controls may exist outside the scanned repository scope."}
- **Audit Caveats**:
${limits.audit_caveats ? limits.audit_caveats.map(c => `    - ${c}`).join('\n') : "    - Runtime behavior not verified."}

---

## 9. REQUIRED NEXT STEPS

- **Action Required**: **${nextStep.required ? "MANDATORY MANUAL AUDIT" : "SUPPORTED AUTOMATED REVIEW"}**
- **Procedure Type**: ${nextStep.type || "REVIEW"}
- **Reason**: ${nextStep.reason || "Verification of automated findings required for regulatory sign-off."}

---

## 10. FINAL VERDICT & DEFENSIBILITY

**Final Statement**: 
The conclusions provided in this report are technically supportive for further auditor review but are **not sufficient alone for final legal sign-off** under the EU AI Act. This document establishes a technical floor of evidence within the analyzed repository scope.

---
**END OF REPORT**
`;

    const outputPath = path.join(process.cwd(), 'enterprise_audit_report.md');
    fs.writeFileSync(outputPath, md);
    return outputPath;
}

module.exports = { generateEnterpriseReport };
