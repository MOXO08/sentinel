#!/usr/bin/env node

/**
 * Sentinel Enterprise Core (SEC)
 * Orchestrator and Supervisory Wrapper for the Sentinel Ecosystem.
 * 
 * Flow: sentinel-scan -> JSON -> SIG -> Final Exit Code
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { runSig } = require('./lib/sentinel-bridge.js');
const { generateHtml } = require('./lib/report-generator.js');

const AUDIT_THRESHOLD = 0.8;
const EXIT_CODE_AUDIT_FAIL = 100;
const EXIT_CODE_SYSTEM_ERROR = 2;

/**
 * Deterministic JSON Canonicalization (RFC8785-Lite)
 * Sorts keys recursively and removes whitespace.
 */
function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalize(item)).join(',') + ']';
  }

  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(key => {
    return JSON.stringify(key) + ':' + canonicalize(obj[key]);
  });
  
  return '{' + pairs.join(',') + '}';
}

/**
 * Generates a SHA-256 digest of the critical audit data.
 */
function generateAuditSignature(report) {
  const surface = getAuditSurface(report);
  const canonicalString = canonicalize(surface);
  const digest = crypto.createHash('sha256').update(canonicalString).digest('hex');

  return {
    algorithm: 'sha256',
    canonicalization: 'RFC8785-Lite',
    signed_at: new Date().toISOString(),
    digest: digest
  };
}

/**
 * Extracts the deterministic fields for hashing.
 */
function getAuditSurface(report) {
  return {
    app_name: report.app_name || (report.manifest ? report.manifest.app_name : 'unknown'),
    version: report.version || (report.manifest ? report.manifest.version : '1.0.0'),
    risk_category: report.risk_category,
    score: report.score,
    status: report.status,
    verdict: report.verdict,
    top_findings: (report.top_findings || [])
      .map(f => ({
        rule_id: f.rule_id,
        description: f.description,
        evidence_location: f.evidence_location
      }))
      .sort((a, b) => {
        const keyA = `${a.rule_id || ''}-${a.evidence_location?.file || ''}-${a.evidence_location?.line || 0}`;
        const keyB = `${b.rule_id || ''}-${b.evidence_location?.file || ''}-${b.evidence_location?.line || 0}`;
        return keyA.localeCompare(keyB);
      }),
    all_findings: (report._internal?.all_findings || [])
      .map(f => ({
        rule_id: f.rule_id,
        article: f.article,
        description: f.description,
        severity: f.severity,
        evidence_location: f.evidence_location
      }))
      .sort((a, b) => {
        const keyA = `${a.article || ''}-${a.rule_id || ''}-${a.evidence_location?.file || ''}-${a.evidence_location?.line || 0}`;
        const keyB = `${b.article || ''}-${b.rule_id || ''}-${b.evidence_location?.file || ''}-${b.evidence_location?.line || 0}`;
        return keyA.localeCompare(keyB);
      }),
    integrity_issues: (report.integrity_issues || [])
      .map(i => ({
        id: i.id,
        severity: i.severity,
        message: i.message,
        evidence_location: i.evidence_location
      }))
      .sort((a, b) => {
        const keyA = `${a.id || ''}-${a.evidence_location?.file || ''}-${a.evidence_location?.line || 0}`;
        const keyB = `${b.id || ''}-${b.evidence_location?.file || ''}-${b.evidence_location?.line || 0}`;
        return keyA.localeCompare(keyB);
      })
  };
}

/**
 * Verifies if a report is authentic.
 */
function verifyAuditSignature(report) {
  const sig = report._audit_signature;
  if (!sig || !sig.digest) return false;
  const surface = getAuditSurface(report);
  const calculatedDigest = crypto.createHash('sha256').update(canonicalize(surface)).digest('hex');
  return calculatedDigest === sig.digest;
}

/**
 * P3: Audit Diffing Logic
 */
async function performDiff(basePath, currentPath) {
  try {
    const base = JSON.parse(fs.readFileSync(basePath, 'utf8'));
    const current = JSON.parse(fs.readFileSync(currentPath, 'utf8'));

    // 1. Integrity Verification (P2 Requirement)
    if (!verifyAuditSignature(base)) throw new Error(`Base report integrity failed: ${basePath}`);
    if (!verifyAuditSignature(current)) throw new Error(`Current report integrity failed: ${currentPath}`);

    const normalizedSeverity = (s) => (s || 'INFO').toUpperCase();

    const getFingerprint = (f) => {
      const lid = f.rule_id || f.description || 'unknown';
      const file = f.evidence_location?.file || 'unknown';
      const line = f.evidence_location?.line || 0;
      return `${lid}|${file}|${line}`;
    };

    const baseMap = new Map(baseFindings.map(f => [getFingerprint(f), f]));
    const currentMap = new Map(currentFindings.map(f => [getFingerprint(f), f]));

    const newF = [];
    const resolvedF = [];
    const persistentF = [];

    currentFindings.forEach(f => {
      const fp = getFingerprint(f);
      if (!baseMap.has(fp)) {
        newF.push(f);
      } else {
        persistentF.push(f);
      }
    });

    baseFindings.forEach(f => {
      if (!currentMap.has(getFingerprint(f))) resolvedF.push(f);
    });

    // 2. Risk Summary (Standardized Severity)
    const riskSummary = {
      new_critical: newF.filter(f => normalizedSeverity(f.severity) === 'CRITICAL').length,
      new_high: newF.filter(f => normalizedSeverity(f.severity) === 'HIGH').length,
      resolved_high: resolvedF.filter(f => normalizedSeverity(f.severity) === 'HIGH').length
    };

    // 3. Verdict Logic (STRICT PRECEDENCE: New Risk > Improvements)
    let verdict = 'STABLE';
    if (riskSummary.new_critical > 0) {
      verdict = 'CRITICAL_REGRESSION';
    } else if (riskSummary.new_high > 0) {
      verdict = 'REGRESSION';
    } else if (newF.length > 0) {
      verdict = 'REGRESSION'; // Any new finding is a regression unless proven stable/improved
    } else if (resolvedF.length > 0) {
      verdict = 'IMPROVED';
    }

    // 4. Integrity Drift
    const integrityDrift = current.integrity_issues.length > base.integrity_issues.length ? 'DEGRADED' : 'STABLE';
    if (integrityDrift === 'DEGRADED' && verdict === 'STABLE') verdict = 'REGRESSION';

    const diffReport = {
      verdict,
      risk_summary: riskSummary,
      score_delta: `${current.score - base.score > 0 ? '+' : ''}${current.score - base.score}`,
      findings: {
        new: newF.map(f => ({ rule_id: f.rule_id, severity: f.severity, evidence_location: f.evidence_location })),
        resolved: resolvedF.map(f => ({ rule_id: f.rule_id, severity: f.severity, evidence_location: f.evidence_location })),
        persistent: persistentF.map(f => ({ rule_id: f.rule_id, severity: f.severity, evidence_location: f.evidence_location }))
      },
      integrity_drift: integrityDrift
    };

    console.log(JSON.stringify({ diff_report: diffReport }, null, 2));

  } catch (e) {
    console.error(`[SEC] Diff Error: ${e.message}`);
    process.exit(EXIT_CODE_SYSTEM_ERROR);
  }
}

/**
 * P4: Audit-Ready Export Logic
 */
async function performExport(reportPath, diffPath = null) {
  try {
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    let diff = null;

    // 1. Verify Primary Report Integrity
    if (!verifyAuditSignature(report)) {
      throw new Error(`Report integrity failed: ${reportPath}`);
    }

    // 2. V2.1 Dual-Track Evaluator
    const allFindings = report._internal?.all_findings || [];
    
    // Track A: Regulatory Governance (ALIGNED / GAP)
    // Procedural rules usually start with EUAI-MIN or EUAI-TRANS
    const proceduralFindings = allFindings.filter(f => f.rule_id?.startsWith('EUAI-MIN') || f.rule_id?.startsWith('EUAI-TRANS'));
    const governanceStatus = proceduralFindings.length > 0 ? 'GAP' : 'ALIGNED';

    // Track B: Technical Maturity (ROBUST / WEAK)
    const validTechnicalSignals = report._internal?.signals?.length || 0;
    // Considered WEAK if no valid signals are found, otherwise ROBUST
    const technicalStatus = validTechnicalSignals > 0 ? 'ROBUST' : 'WEAK';

    // Central Verdict Decision Matrix
    let centralVerdict = 'REJECTED';
    if (technicalStatus === 'ROBUST' && governanceStatus === 'ALIGNED') centralVerdict = 'APPROVED';
    else if (technicalStatus === 'ROBUST' && governanceStatus === 'GAP') centralVerdict = 'HOLD';
    else if (technicalStatus === 'WEAK' && governanceStatus === 'ALIGNED') centralVerdict = 'REJECTED';
    else if (technicalStatus === 'WEAK' && governanceStatus === 'GAP') centralVerdict = 'REJECTED';

    // Forensic Noise Reduction (SIG Poisoning)
    const forensicExclusionsCount = (report.integrity_issues || []).filter(i => i.id === 'SIG-CODE-001').length;
    report.integrity_issues = (report.integrity_issues || []).filter(i => i.id !== 'SIG-CODE-001');

    const dualTrack = {
        centralVerdict,
        technicalStatus,
        governanceStatus,
        forensicExclusionsCount
    };

    // 3. Load Diff if requested
    if (diffPath) {
      const base = JSON.parse(fs.readFileSync(diffPath, 'utf8'));
      if (!verifyAuditSignature(base)) {
        throw new Error(`Base report integrity failed: ${diffPath}`);
      }
      
      const baseFindings = base._internal?.all_findings || [];
      const currentFindings = report._internal?.all_findings || [];
      const getFingerprint = (f) => `${f.rule_id || f.description}|${f.evidence_location?.file}|${f.evidence_location?.line}`;
      const baseMap = new Map(baseFindings.map(f => [getFingerprint(f), f]));
      const currentMap = new Map(currentFindings.map(f => [getFingerprint(f), f]));
      
      const newF = [];
      const resolvedF = [];
      currentFindings.forEach(f => { if (!baseMap.has(getFingerprint(f))) newF.push(f); });
      baseFindings.forEach(f => { if (!currentMap.has(getFingerprint(f))) resolvedF.push(f); });

      const normalizedSeverity = (s) => (s || 'INFO').toUpperCase();
      const riskSummary = {
        new_critical: newF.filter(f => normalizedSeverity(f.severity) === 'CRITICAL').length,
        new_high: newF.filter(f => normalizedSeverity(f.severity) === 'HIGH').length,
        resolved_high: resolvedF.filter(f => normalizedSeverity(f.severity) === 'HIGH').length
      };

      let verdict = 'STABLE';
      if (riskSummary.new_critical > 0) verdict = 'CRITICAL_REGRESSION';
      else if (riskSummary.new_high > 0) verdict = 'REGRESSION';
      else if (newF.length > 0) verdict = 'REGRESSION';
      else if (resolvedF.length > 0) verdict = 'IMPROVED';

      diff = {
        diff_report: {
          verdict,
          score_delta: `${report.score - base.score > 0 ? '+' : ''}${report.score - base.score}`,
          findings: { new: newF, resolved: resolvedF }
        }
      };
    }

    // 2.5 Audit Trail Archiving
    const auditMeta = AuditMetadata.createMetadataBlock();
    AuditVault.archiveAudit(process.cwd(), auditMeta, report, dualTrack);
    dualTrack.auditMeta = auditMeta;

    // 4. Generate HTML
    const html = generateHtml(report, diff, dualTrack);
    const outputPath = 'sentinel-audit.html';
    fs.writeFileSync(outputPath, html);
    
    console.error(`[SEC] Professional Audit Statement generated: ${outputPath}`);

  } catch (e) {
    console.error(`[SEC] Export Error: ${e.message}`);
    process.exit(EXIT_CODE_SYSTEM_ERROR);
  }
}

async function main() {
  const args = process.argv.slice(2);

  // P3: Diff Command Routing
  if (args[0] === 'diff') {
     const baseIdx = args.indexOf('--base');
     const currIdx = args.indexOf('--current');
     if (baseIdx === -1 || currIdx === -1) {
        console.error("Usage: sentinel-enterprise diff --base <path> --current <path>");
        process.exit(EXIT_CODE_SYSTEM_ERROR);
     }
     await performDiff(args[baseIdx + 1], args[currIdx + 1]);
     return;
  }

  // P4: Export Command Routing
  if (args[0] === 'export') {
    const reportIdx = args.indexOf('--report');
    const diffIdx = args.indexOf('--diff');
    if (reportIdx === -1) {
      console.error("Usage: sentinel-enterprise export --report <path> [--diff <base-path>]");
      process.exit(EXIT_CODE_SYSTEM_ERROR);
    }
    await performExport(args[reportIdx + 1], diffIdx !== -1 ? args[diffIdx + 1] : null);
    return;
  }
  
  // Ensure JSON and Autodiscover are core for Enterprise runs
  const cliArgs = [...args];
  
  // SEC Default: if no command is provided, default to 'check'
  const knownCommands = ['check', 'discover', 'init', 'fix', 'diff', 'export'];
  if (cliArgs.length === 0 || !knownCommands.includes(cliArgs[0])) {
    cliArgs.unshift('check');
  }

  if (!cliArgs.includes('--json')) cliArgs.push('--json');
  if (!cliArgs.includes('--autodiscover')) cliArgs.push('--autodiscover');
  if (!cliArgs.includes('--threshold')) cliArgs.push('--threshold', '80');

  const cliPath = path.join(__dirname, 'sentinel-scan.js');
  const probingRulesPath = path.join(__dirname, 'lib', 'probing-rules.json');

  console.error(`[SEC] Starting Enterprise Audit Pipeline...`);

  // 1. Spawn the CLI Scanner
  const cli = spawn('node', [cliPath, ...cliArgs]);

  let stdoutBuffer = '';

  cli.stdout.on('data', (data) => {
    stdoutBuffer += data;
  });

  cli.stderr.on('data', (data) => {
    // Direct pass-through for visibility
    process.stderr.write(data);
  });

  cli.on('error', (err) => {
    console.error(`\n[SEC] Critical System Error (Spawn): ${err.message}`);
    process.exit(EXIT_CODE_SYSTEM_ERROR);
  });

  cli.on('close', async (code) => {
    // 2. Technical Check (CLI Threshold)
    if (code !== 0) {
      console.error(`\n[SEC] Technical Compliance Failed (CLI Code: ${code}).`);
      process.exit(code);
    }

    // 3. SIG Integration (Integrity Check)
    try {
      if (!stdoutBuffer.trim()) {
        console.error(`[SEC] System Error: No output from scanner.`);
        process.exit(EXIT_CODE_SYSTEM_ERROR);
      }

      const cliResults = JSON.parse(stdoutBuffer);
      const rootDir = process.cwd();
      
      const sigReport = await runSig(cliResults, probingRulesPath, rootDir);

      const finalReport = {
        ...cliResults,
        enterprise_confidence: sigReport.enterprise_confidence,
        defensibility: sigReport.defensibility,
        integrity_issues: sigReport.integrity_issues,
        _sig_internal: sigReport._internal
      };

      // 4. Generate Audit Signature (Surgical P2)
      const auditSignature = generateAuditSignature(finalReport);
      finalReport._audit_signature = auditSignature;

      // 5. Generate Artifacts (Double-Seal Model)
      const reportFilename = 'sentinel-report.json';
      const sidecarFilename = `${reportFilename}.sha256`;
      
      try {
        fs.writeFileSync(path.join(rootDir, reportFilename), JSON.stringify(finalReport, null, 2));
        fs.writeFileSync(path.join(rootDir, sidecarFilename), `${auditSignature.digest}  ${reportFilename}\n`);
        console.error(`[SEC] Audit artifacts generated: ${reportFilename}, ${sidecarFilename}`);
      } catch (e) {
        console.error(`[SEC] Warning: Failed to write audit artifacts: ${e.message}`);
      }

      // 6. Print Final Augmented JSON
      process.stdout.write(JSON.stringify(finalReport, null, 2) + '\n');

      // 7. Audit Decision (Dual-Threshold Enforcement)
      const hasCriticalIssues = sigReport.integrity_issues.some(i => i.severity === 'CRITICAL');
      const isConfidenceLow = sigReport.enterprise_confidence < AUDIT_THRESHOLD;

      if (hasCriticalIssues || isConfidenceLow) {
        console.error(`\n[SEC] ❌ AUDIT FAILURE (Code ${EXIT_CODE_AUDIT_FAIL})`);
        console.error(`[SEC] Reason: ${hasCriticalIssues ? "CRITICAL Integrity Violations Detected" : "Low Enterprise Confidence"}`);
        process.exit(EXIT_CODE_AUDIT_FAIL);
      }

      console.error(`\n[SEC] ✅ AUDIT SUCCESS (Technical & Integrity Verified).`);
      process.exit(0);

    } catch (err) {
      console.error(`[SEC] System Error during SIG processing: ${err.message}`);
      process.exit(EXIT_CODE_SYSTEM_ERROR);
    }
  });
}

main();
