#!/usr/bin/env node
// sentinel-scan — EU AI Act Compliance CLI
// Usage: npx @radu_api/sentinel-scan check --threshold 90 --manifest sentinel.manifest.json [--policy <path>] [--baseline <path>] [--json] [--api-key <key>] [--endpoint <url>]

'use strict';

const fs = require('fs');
const path = require('path');
const cliProgress = require('cli-progress');

const autodiscovery = require('./lib/autodiscovery');
const discoveryRules = require('./lib/discovery-rules.json');
const ruleRegistry = require('./lib/registry.json');

// ── ANSI Colors (no external deps) ──
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m',
  white: '\x1b[97m',
};

function colorVerdict(verdict) {
  switch (verdict) {
    case 'COMPLIANT': return `${C.bold}${C.green}✅ COMPLIANT${C.reset}`;
    case 'COMPLIANT_VIA_AI_REVIEW': return `${C.bold}${C.green}✅ COMPLIANT (via AI Review)${C.reset}`;
    case 'NON_COMPLIANT': return `${C.bold}${C.red}❌ NON_COMPLIANT${C.reset}`;
    case 'HUMAN_INTERVENTION_REQUIRED': return `${C.bold}${C.yellow}⚠️  HUMAN_INTERVENTION_REQUIRED${C.reset}`;
    case 'INSUFFICIENT_DATA': return `${C.bold}${C.magenta}❓ INSUFFICIENT_DATA${C.reset}`;
  }
}

function pauseAndExit(code = 0) {
  if (process.stdout.isTTY && process.env.SENTINEL_INTERACTIVE !== 'false' && process.platform === 'win32' && !process.argv.includes('--json')) {
    process.stdout.write(`\n${C.gray}Scan finished. Press ENTER to close this window...${C.reset}`);
    process.stdin.resume();
    process.stdin.on('data', () => process.exit(code));
  } else {
    process.exit(code);
  }
}

function printBanner() {
  console.log(`\n${C.cyan}${C.bold}╔══════════════════════════════════════════════════╗`);
  console.log(`║  🛡  SENTINEL — LOCAL DIAGNOSTIC TOOL (OFFLINE)  ║`);
  console.log(`╚══════════════════════════════════════════════════╝${C.reset}\n`);
}

function printHelp() {
  console.log(`${C.bold}Usage:${C.reset}`);
  console.log(`  npx @radu_api/sentinel-scan check --threshold 90 --manifest sentinel.manifest.json`);
  console.log(`  npx @radu_api/sentinel-scan discover`);
  console.log(`  npx @radu_api/sentinel-scan init`);
  console.log(`  npx @radu_api/sentinel-scan fix --apply --manifest sentinel.manifest.json`);

  console.log(`\n${C.bold}Options:${C.reset}`);
  console.log(`  --manifest <path>      Path to manifest file (default: sentinel.manifest.json)`);
  console.log(`  --threshold <score>    Required score for 'check' command`);
  console.log(`  --api-key <key>        API Key (Developer or Pro)`);
  console.log(`  --policy <path>        Path to the sentinel.policy.json file (default: sentinel.policy.json)`);
  console.log(`  --policy-pack <name>   Use built-in Sentinel policy pack`);
  console.log(`  --baseline <path>      Path to a Sentinel baseline file`);
  console.log(`  --json                 Output raw JSON for CI/CD pipelines`);
  console.log(`  --sarif                Output results in SARIF v2.1.0 format`);
  console.log(`  --evidence             Generate a full compliance evidence pack (sentinel-evidence/)`);
  console.log(`  --autodiscover         Enable the Autodiscovery engine to verify manifest against code`);
  console.log(`  --endpoint <url>       Custom Edge API endpoint`);
  console.log(`  --help                 Show this help`);

  console.log(`\n${C.bold}Policy Pack Commands:${C.reset}`);
  console.log(`  policy-pack list                List built-in Sentinel policy packs`);
  console.log(`  policy-pack show <name>         Show policy pack details`);

  console.log(`\n${C.bold}Remediation Commands:${C.reset}`);
  console.log(`  npx @radu_api/sentinel-scan fix --manifest <path>`);
  console.log(`  npx @radu_api/sentinel-scan fix --apply --manifest <path>`);
  console.log(`  npx @radu_api/sentinel-scan fix --yes                 Skip confirmation during apply`);
}

// ── Top 10 Reguli AI Act — Embedded offline ──
const OFFLINE_RULES = {
  rules: [
    { id: "ART5-001", description: "Subliminal manipulation", risk_category: "Unacceptable", required_flags: [], forbidden_flags: ["subliminal_techniques"], fix_snippet: "Remove features exploiting subliminal techniques (Article 5.1a Prohibited)." },
    { id: "ART5-003", description: "Social scoring", risk_category: "Unacceptable", required_flags: [], forbidden_flags: ["social_scoring"], fix_snippet: "Remove social scoring functionality or restrict to non-prohibited domains (Article 5.1c)." },
    { id: "ART10-001", description: "Data governance & Bias assessment", risk_category: "High", required_flags: ["bias_assessment_performed", "data_governance_policy_documented"], fix_snippet: "Add 'bias_assessment_performed' and 'data_governance_policy_documented' to 'declared_flags' array." },
    { id: "ART13-001", description: "User notification of AI interaction", risk_category: "High", required_flags: ["user_notification_ai_interaction"], fix_snippet: "Add 'user_notification_ai_interaction' to 'declared_flags' array and implement UI notification." },
    { id: "ART14-001", description: "Human oversight", risk_category: "High", required_flags: ["human_oversight_enabled"], fix_snippet: "Add 'human_oversight_enabled' to 'declared_flags' array and implement a kill-switch." },
    { id: "ART22-001", description: "Conformity assessment", risk_category: "High", required_flags: ["conformity_assessment_completed"], fix_snippet: "Add 'conformity_assessment_completed' to 'declared_flags' array after legal review." }
  ]
};

async function runOffline(manifest) {
  const { run_audit } = require('../pkg-node/sentinel_core.js');
  const verdictText = run_audit(JSON.stringify(manifest), JSON.stringify(OFFLINE_RULES));
  return JSON.parse(verdictText);
}


/**
 * Logic to resolve the target manifest path from CLI arguments and environment.
 */
function resolveTargetManifest(args) {
  let manifestPath = null;

  // 1. Explicit --manifest flag
  const manifestArgIdx = args.indexOf('--manifest');
  if (manifestArgIdx !== -1 && args[manifestArgIdx + 1]) {
    manifestPath = args[manifestArgIdx + 1];
  }

  // 2. Default lookup (prefer sentinel.manifest.json)
  if (!manifestPath) {
    const hasSentinelManifest = fs.existsSync('sentinel.manifest.json');
    const hasManifestJson = fs.existsSync('manifest.json');

    manifestPath = hasSentinelManifest
      ? 'sentinel.manifest.json'
      : (hasManifestJson ? 'manifest.json' : null);
  }

  return manifestPath;
}

// ── Evidence-Based Validation Engine ──
// Validates actual evidence files, content, and controls — not just manifest shape.

function validateEvidence(manifest, manifestDir) {
  const findings = [];
  const modules = Array.isArray(manifest.modules) ? manifest.modules : [];
  const declaredFlags = Array.isArray(manifest.declared_flags) ? manifest.declared_flags : [];

  const riskCat = (manifest.risk_category || "").toLowerCase();
  const isHighRisk = riskCat === 'high';
  const isLimited = riskCat === 'limited';
  const isUnacceptable = riskCat === 'unacceptable';

  const hasHighRiskModules = modules.some(m =>
    m.risk_level === 'High' || m.risk_level === 'Unacceptable' || m.risk_category === 'High'
  );
  const strictEnforcement = isHighRisk || hasHighRiskModules;

  // ── 0. Unacceptable Risk: Immediate Hard Fail ──
  if (isUnacceptable) {
    findings.push({
      article: 'General', rule_id: 'EUAI-UNACCEPTABLE-001',
      description: "[Unacceptable risk category]",
      deduction: 100, severity: 'critical', hard_fail: true, source: 'evidence'
      ,
      fix_snippet: "Change 'risk_category' to a permitted value."
    });
    return findings; // No scoring for unacceptable
  }

  // ── 1. risk_category: NEVER silently default to Minimal ──
  if (!manifest.risk_category) {
    findings.push({
      article: 'Art. 9', rule_id: 'EUAI-RISK-002',
      description: "[Missing risk category]",
      deduction: 25, severity: 'critical', hard_fail: true, source: 'evidence'
      ,
      fix_snippet: "Add 'risk_category' to manifest.json."
    });
  }

  // ── 1.1 Minimum Compliance Signal check ──
  const hasTransparencyFlag = declaredFlags.includes('transparency_disclosure_provided');
  const hasTransparencyFile = !!manifest.evidence_path;
  const hasOversight = !!manifest.human_oversight || !!manifest.oversight_evidence_path;
  const hasLogging = !!manifest.logging_capabilities || !!manifest.logging_evidence_path;

  if (!hasTransparencyFlag && !hasTransparencyFile && !hasOversight && !hasLogging) {
    findings.push({
      article: 'General', rule_id: 'EUAI-MIN-001',
      description: "[Missing baseline structure]",
      deduction: 30, severity: 'critical', hard_fail: true, source: 'evidence'
      ,
      fix_snippet: "Add required top-level flags and evidence fields."
    });
  }

  // ── 1.2 Limited Risk Stricter Transparency check ──
  if (isLimited && hasTransparencyFlag && !hasTransparencyFile) {
    findings.push({
      article: 'Art. 13', rule_id: 'EUAI-TRANS-002',
      description: "[Missing transparency evidence]",
      deduction: 20, severity: 'high', hard_fail: false, source: 'evidence',
      fix_snippet: "Add 'evidence_path' for technical documentation."
    },
    );
  }

  // ── 2. evidence_path: Art. 13 Transparency && disclosure-config semantics ──
  if (manifest.evidence_path) {
    const evidencePath = path.resolve(manifestDir, manifest.evidence_path);
    if (!fs.existsSync(evidencePath)) {
      findings.push({
        article: 'Art. 13', rule_id: 'EUAI-EVID-001',
        description: `Declared evidence_path does not exist: ${manifest.evidence_path}`,
        deduction: 25, severity: 'critical', hard_fail: true, source: 'evidence',
        fix_snippet: "Create the missing evidence file at the path specified in your manifest."
      });
    } else {
      try {
        const stat = fs.statSync(evidencePath);
        if (stat.size < 10) {
          findings.push({
            article: 'Art. 13', rule_id: 'EUAI-EVID-002',
            description: `Evidence file is trivially empty (${stat.size} bytes): ${manifest.evidence_path}`,
            deduction: 15, severity: 'high', hard_fail: true, source: 'evidence',
            fix_snippet: "Add meaningful compliance documentation to the empty evidence file."
          });
        } else if (manifest.evidence_path.endsWith('.json')) {
          try {
            const content = fs.readFileSync(evidencePath, 'utf8');
            const parsed = JSON.parse(content);
            if (!parsed || (typeof parsed === 'object' && Object.keys(parsed).length === 0)) {
              findings.push({
                article: 'Art. 13', rule_id: 'EUAI-EVID-003',
                description: `Evidence file is valid JSON but contains no meaningful content: ${manifest.evidence_path}`,
                deduction: 15, severity: 'high', hard_fail: true, source: 'evidence',
                fix_snippet: "Populate the JSON evidence file with required compliance data fields."
              });
            }
            // REQUIREMENT 4: disclosure-config semantic check
            if (manifest.evidence_path.includes('disclosure')) {
              const requiredKeys = ['component', 'trigger', 'text', 'active'];
              const missingKeys = requiredKeys.filter(k => parsed[k] === undefined);
              if (missingKeys.length > 0) {
                findings.push({
                  article: 'Art. 13', rule_id: 'EUAI-EVID-006',
                  description: `disclosure-config.json missing required semantic keys: ${missingKeys.join(', ')}`,
                  deduction: 20, severity: 'critical', hard_fail: true, source: 'evidence',
                  fix_snippet: "Add missing keys (component, trigger, text, active) to disclosure-config.json."
                });
              }
            }
          } catch (parseErr) {
            findings.push({
              article: 'Art. 13', rule_id: 'EUAI-EVID-004',
              description: `Evidence file is not valid JSON (parse error): ${manifest.evidence_path}`,
              deduction: 15, severity: 'critical', hard_fail: true, source: 'evidence',
              fix_snippet: "Fix JSON syntax errors in the evidence file."
            });
          }
        }
      } catch (readErr) {
        findings.push({
          article: 'Art. 13', rule_id: 'EUAI-EVID-005',
          description: `[Unreadable evidence file]`,
          deduction: 25, severity: 'critical', hard_fail: true, source: 'evidence',
          fix_snippet: "Ensure evidence file has correct read permissions."
        });
      }
    }
  }

  // ── 3. Transparency flags: Art. 13 ──
  if (!declaredFlags.includes('transparency_disclosure_provided')) {
    findings.push({
      article: 'Art. 13', rule_id: 'EUAI-TRANS-001',
      description: "[Missing transparency flag]",
      deduction: 15, severity: 'high', hard_fail: false, source: 'evidence',
      fix_snippet: "Add 'transparency_disclosure_provided' to 'declared_flags' array."
    });
  }

  // ── 4. Module-level evidence validation: Art. 9 && risk management semantics ──
  for (const mod of modules) {
    if (mod.risk_level === 'High' || mod.risk_level === 'Unacceptable') {
      if (!mod.evidence) {
        findings.push({
          article: 'Art. 9', rule_id: 'EUAI-MOD-001',
          description: `High-risk module "${mod.id || 'unnamed'}" has no evidence field`,
          fix_snippet: "Add 'evidence' field to the high-risk module in manifest.json.",
          deduction: 10, severity: 'high', hard_fail: false, source: 'evidence'
        });
      } else {
        const modEvidencePath = path.resolve(manifestDir, mod.evidence);
        if (!fs.existsSync(modEvidencePath)) {
          findings.push({
            article: 'Art. 9', rule_id: 'EUAI-MOD-002',
            description: `High-risk module "${mod.id || 'unnamed'}" declares evidence but file missing: ${mod.evidence}`,
            fix_snippet: "Create the missing module evidence file specified in the manifest.",
            deduction: 10, severity: 'high', hard_fail: false, source: 'evidence'
          });
        } else {
          try {
            const stat = fs.statSync(modEvidencePath);
            if (stat.size < 20) {
              findings.push({
                article: 'Art. 9', rule_id: 'EUAI-MOD-003',
                description: `High-risk module "${mod.id}" evidence file is trivially empty or too small: ${mod.evidence}`,
                fix_snippet: "Add meaningful content to the empty module evidence file.",
                deduction: 15, severity: 'high', hard_fail: true, source: 'evidence'
              });
            } else {
              const content = fs.readFileSync(modEvidencePath, 'utf8');
              if (modEvidencePath.endsWith('.json')) {
                try {
                  const parsed = JSON.parse(content);
                  if (!parsed || Object.keys(parsed).length === 0) {
                    findings.push({
                      article: 'Art. 9', rule_id: 'EUAI-MOD-004', description: `Module JSON evidence is empty: ${mod.evidence}`,
                      fix_snippet: "Populate the module JSON evidence with required compliance data.", deduction: 15, severity: 'high', hard_fail: true, source: 'evidence'
                    });
                  }
                } catch (e) {
                  findings.push({
                    article: 'Art. 9', rule_id: 'EUAI-MOD-005', description: `Module evidence is not valid JSON: ${mod.evidence}`,
                    fix_snippet: "Fix JSON syntax errors in the module evidence file.", deduction: 15, severity: 'high', hard_fail: true, source: 'evidence'
                  });
                }
              } else {
                // REQUIREMENT 5: risk management semantic check
                if (modEvidencePath.includes('risk') || content.toLowerCase().includes('risk management')) {
                  const lowerContent = content.toLowerCase();
                  const requiredTerms = ['risk category', 'mitigation', 'oversight', 'transparency'];
                  const missingTerms = requiredTerms.filter(t => !lowerContent.includes(t));
                  if (missingTerms.length > 0) {
                    findings.push({
                      article: 'Art. 9', rule_id: 'EUAI-MOD-006',
                      description: `Risk management evidence lacks required semantic sections: ${missingTerms.join(', ')}`,
                      fix_snippet: "Add missing sections (risk category, mitigation, oversight, transparency) to the risk management file.",
                      deduction: 20, severity: 'critical', hard_fail: true, source: 'evidence'
                    });
                  }
                }
              }
            }
          } catch (e) {
            findings.push({
              article: 'Art. 9', rule_id: 'EUAI-MOD-007', description: `Module evidence unreadable: ${mod.evidence}`,
              fix_snippet: "Ensure the module evidence file has correct read permissions.", deduction: 15, severity: 'high', hard_fail: true, source: 'evidence'
            });
          }
        }
      }
    }
  }

  // ── 5. Human oversight: Art. 14 (Must not pass from flag alone) ──
  if (strictEnforcement) {
    const hasOversightObj = manifest.human_oversight && typeof manifest.human_oversight === 'object' && Object.keys(manifest.human_oversight).length > 0;
    let hasValidOversightFile = false;
    if (manifest.oversight_evidence_path) {
      const p = path.resolve(manifestDir, manifest.oversight_evidence_path);
      if (fs.existsSync(p) && fs.statSync(p).size > 10) hasValidOversightFile = true;
    }

    if (!hasOversightObj && !hasValidOversightFile) {
      findings.push({
        article: 'Art. 14', rule_id: 'EUAI-OVER-002',
        description: "[Missing human oversight details]",
        deduction: 20, severity: 'critical', hard_fail: true, source: 'evidence',
        fix_snippet: "Provide 'human_oversight' object or 'oversight_evidence_path'."
      });
    }
  }

  // ── 6. Logging / Traceability: Art. 20 (Must not pass from flag alone) ──
  if (strictEnforcement) {
    const hasLoggingObj = manifest.logging_capabilities && typeof manifest.logging_capabilities === 'object' && Object.keys(manifest.logging_capabilities).length > 0;
    let hasValidLoggingFile = false;
    if (manifest.logging_evidence_path) {
      const p = path.resolve(manifestDir, manifest.logging_evidence_path);
      if (fs.existsSync(p) && fs.statSync(p).size > 10) hasValidLoggingFile = true;
    }

    if (!hasLoggingObj && !hasValidLoggingFile) {
      findings.push({
        article: 'Art. 20', rule_id: 'EUAI-LOG-003',
        description: "[Missing logging details]",
        deduction: 20, severity: 'critical', hard_fail: true, source: 'evidence',
        fix_snippet: "Provide 'logging_capabilities' object or 'logging_evidence_path'."
      });
    }
  }

  return findings;
}

function determineVerifiedArticles(findings, manifest) {
  const verified = [];
  const failedArticles = new Set(findings.filter(f => f.article).map(f => f.article));

  const modules = Array.isArray(manifest.modules) ? manifest.modules : [];
  const declaredFlags = Array.isArray(manifest.declared_flags) ? manifest.declared_flags : [];

  const hasTransparency = !!manifest.evidence_path || declaredFlags.includes('transparency_disclosure_provided');
  const hasOversight = (manifest.human_oversight && Object.keys(manifest.human_oversight).length > 0) || !!manifest.oversight_evidence_path;
  const hasLogging = (manifest.logging_capabilities && Object.keys(manifest.logging_capabilities).length > 0) || !!manifest.logging_evidence_path;
  const hasRiskManagement = modules.length > 0 && modules.some(m => m.evidence);

  if (hasTransparency && !failedArticles.has('Art. 13')) verified.push('Art. 13');
  if (hasOversight && !failedArticles.has('Art. 14')) verified.push('Art. 14');
  if (hasLogging && !failedArticles.has('Art. 20')) verified.push('Art. 20');
  if (hasRiskManagement && !failedArticles.has('Art. 9')) verified.push('Art. 9');

  return verified;
}

function computeEvidenceScore(findings, manifest) {
  const riskCat = (manifest.risk_category || "minimal").toLowerCase();
  let required = ['Art. 13'];
  if (riskCat === 'high') {
    required = ['Art. 9', 'Art. 13', 'Art. 14', 'Art. 20'];
  } else if (riskCat === 'limited') {
    required = ['Art. 13'];
  } else if (riskCat === 'unacceptable') {
    return { baseScore: 0, deductions: 0, finalScore: 0 };
  }

  const verified = determineVerifiedArticles(findings, manifest);
  const verifiedRequired = required.filter(a => verified.includes(a));

  if (required.length === 0) return { baseScore: 0, deductions: 0, finalScore: 0 };

  // Base Score = % of required controls satisfied
  const baseScore = Math.round((verifiedRequired.length / required.length) * 100);

  let totalDeductions = 0;
  // Subtract deductions for required articles if they have findings
  for (const f of findings) {
    if (required.includes(f.article)) {
      totalDeductions += (f.deduction || 0) / required.length;
    }
  }

  const finalScore = Math.max(0, Math.min(100, Math.round(baseScore - totalDeductions)));
  return {
    baseScore,
    deductions: Math.round(totalDeductions),
    finalScore
  };
}

function hasHardFail(findings) {
  return findings.some(f => f.hard_fail === true);
}

function computeVerdict(score, findings, manifest) {
  if (hasHardFail(findings)) return 'NON_COMPLIANT';

  const riskCat = (manifest.risk_category || "minimal").toLowerCase();
  let required = ['Art. 13'];
  if (riskCat === 'high') {
    required = ['Art. 9', 'Art. 13', 'Art. 14', 'Art. 20'];
  }

  const verified = determineVerifiedArticles(findings, manifest);
  const allRequiredVerified = required.every(a => verified.includes(a));

  if (allRequiredVerified && score >= 85) return 'COMPLIANT';
  if (score >= 60) return 'PARTIAL';
  return 'NON_COMPLIANT';
}

async function reportError(err) {
  if (process.env.SENTINEL_NO_TELEMETRY === 'true') return;
  try {
    const https = require('https');
    const pkg = require('../package.json');
    const body = JSON.stringify({
      event: 'cli_crash',
      version: pkg.version,
      os: process.platform,
      arch: process.arch,
      error: err.message,
      stack: err.stack ? err.stack.split('\n').slice(0, 3).join('\n') : 'no-stack'
    });
    const req = https.request({
      hostname: 'sentinel-api.sentinel-moxo.workers.dev',
      path: '/api/telemetry/error',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    });
    req.on('error', () => { }); req.write(body); req.end();
  } catch (e) { }
}

function printOnboarding() {
  console.log(`\n${C.yellow}${C.bold}⚠  No sentinel.manifest.json found in the current directory.${C.reset}`);
  console.log(`${C.gray}Compliance cannot be evaluated until a manifest exists.${C.reset}\n`);
  console.log(`${C.cyan}${C.bold}How to initialize:${C.reset}`);
  console.log(`Run: ${C.white}npx @radu_api/sentinel-scan init${C.reset}`);
  console.log(`\n${C.gray}This will create a template manifest you can use to document your AI compliance.${C.reset}\n`);
}

async function runRemote(manifest, apiKey, endpoint, telemetry = {}) {
  const url = new URL(endpoint);

  // Correctly target the audit endpoint
  if (url.pathname === '/v1' || url.pathname === '/v1/') {
    url.pathname = '/v1/audit';
  } else if (!url.pathname.endsWith('/audit')) {
    // If it's just the root or something else, and doesn't have audit, maybe append it
    // But for api.gettingsentinel.com/v1 we want /v1/audit
  }

  // Normalize manifest fields for the API (must match Rust AIAppManifest struct exactly)
  let appName = manifest.app_name || manifest.project_name || manifest.name || "Unknown-AI-App";
  const appVersion = manifest.version || manifest.schema_version || "1.0.0";

  // CRITICAL: Sanitize appName (remove spaces) as Rust miniserde fails on certain characters
  appName = appName.replace(/[^a-zA-Z0-9_\-]/g, '');

  // LEAN FLAT PAYLOAD: Do NOT send telemetry at top level as it breaks miniserde deserialization in WASM
  const body = JSON.stringify({
    app_name: appName,
    version: appVersion,
    risk_category: manifest.risk_category || "Minimal",
    app_description: manifest.app_description || null,
    declared_flags: manifest.declared_flags || [],
    fallback_ai_verification: manifest.fallback_ai_verification || false
  });

  if (process.env.SENTINEL_DEBUG === 'true' || !process.argv.includes('--json')) {
    console.log(`${C.gray}REMOTE REQUEST: POST ${url.href}${C.reset}`);
    if (process.env.SENTINEL_DEBUG === 'true') {
      console.log(`${C.gray}PAYLOAD: ${body}${C.reset}`);
    }
  }

  const pkg = require('../package.json');

  try {
    const response = await fetch(url.href, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'X-Sentinel-CLI-Version': pkg.version,
        'X-Sentinel-Protocol': 'v1.0.2',
        // Pass telemetry in headers to avoid breaking WASM JSON contract
        'X-Sentinel-Client-Id': telemetry.clientId || '',
        'X-Sentinel-Scan-Id': telemetry.scanId || '',
        'X-Sentinel-Project-Hash': telemetry.projectHash || '',
        'X-Sentinel-Context': telemetry.executionContext || '',
      },
      body: body
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API Error (${response.status}): ${errorText}`);
    }

    const results = await response.json();

    if (process.env.SENTINEL_DEBUG === 'true') {
      console.log(`${C.gray}REMOTE RESPONSE: ${JSON.stringify(results, null, 2)}${C.reset}`);
    }

    // Validation: Ensure we didn't just hit the health endpoint
    if (results.status === "online" && !results.verdict && !results.violations) {
      throw new Error("Remote audit failed: Received health status instead of audit results. Check endpoint configuration.");
    }

    if (typeof results === 'object' && !Array.isArray(results)) {
      results._headers = Object.fromEntries(response.headers.entries());
    }
    return results;
  } catch (err) {
    if (err.code === 'ENOTFOUND') {
      throw new Error(`Connection failed: Could not resolve ${url.hostname}. Check your internet connection or DNS settings.`);
    }
    throw err;
  }
}

function getOrCreateClientId() {
  const os = require('os');
  const configDir = path.join(os.homedir(), '.sentinel');
  const configPath = path.join(configDir, 'config.json');

  if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });

  let config = {};
  if (fs.existsSync(configPath)) {
    try {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (e) { }
  }

  if (!config.anonymous_client_id) {
    const crypto = require('crypto');
    config.anonymous_client_id = crypto.randomBytes(16).toString('hex');
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  }

  return config.anonymous_client_id;
}

function computeProjectHash() {
  const crypto = require('crypto');
  const cwd = process.cwd();
  let signals = [cwd];

  try {
    const { execSync } = require('child_process');
    const remote = execSync('git remote get-url origin', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    if (remote) signals.push(remote);
  } catch (e) { }

  return crypto.createHash('sha256').update(signals.join('|')).digest('hex');
}

function detectExecutionContext() {
  if (process.env.GITHUB_ACTIONS === 'true') return 'github_actions';
  if (process.env.GITLAB_CI === 'true') return 'gitlab_ci';

  try {
    const fs = require('fs');
    if (fs.existsSync('/.dockerenv')) return 'docker';
    if (fs.readFileSync('/proc/self/cgroup', 'utf8').includes('docker')) return 'docker';
  } catch (e) { }

  return 'local';
}

function getGitMetadata() {
  const { execSync } = require('child_process');
  let project = {
    repo: null,
    origin: 'local',
    name: path.basename(process.cwd())
  };
  let commit = null;
  let branch = null;

  try {
    commit = execSync('git rev-parse HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    branch = execSync('git rev-parse --abbrev-ref HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();

    try {
      const remote = execSync('git remote get-url origin', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
      if (remote.includes('github.com')) {
        project.origin = 'github';
        project.repo = remote.split('github.com/')[1].replace('.git', '');
        project.name = project.repo.split('/')[1] || project.name;
      } else if (remote.includes('gitlab.com')) {
        project.origin = 'gitlab';
        project.repo = remote.split('gitlab.com/')[1].replace('.git', '');
        project.name = project.repo.split('/').pop() || project.name;
      }
    } catch (re) {
      // Remote not set
    }
  } catch (e) {
    // Git not available or not in a repo
  }

  return { project, commit, branch };
}

function calculateEvidenceHash(outDir) {
  const { createHash } = require('crypto');
  const hash = createHash('sha256');
  const files = ['scan-metadata.json', 'scan-report.json', 'scan-report.sarif', 'audit-evidence.json', 'compliance-summary.md'];

  for (const f of files) {
    const fPath = path.join(outDir, f);
    if (fs.existsSync(fPath)) {
      hash.update(fs.readFileSync(fPath));
    }
  }
  return hash.digest('hex');
}

function generateEvidencePack(params) {
  const { report, metadata, sarif, policyPath } = params;
  const outDir = path.resolve(process.cwd(), "sentinel-evidence");

  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  // 1. scan-metadata.json
  fs.writeFileSync(path.join(outDir, "scan-metadata.json"), JSON.stringify(metadata, null, 2));

  // 2. scan-report.json
  fs.writeFileSync(path.join(outDir, "scan-report.json"), JSON.stringify(report, null, 2));

  // 3. scan-report.sarif
  fs.writeFileSync(path.join(outDir, "scan-report.sarif"), JSON.stringify(sarif, null, 2));

  // 4. audit-evidence.json
  const auditEvidence = {
    documents: (metadata.required_documents || []).map(doc => ({
      path: doc,
      rule_id: "EUAI-DOC-001",
      status: fs.existsSync(path.resolve(process.cwd(), doc)) ? "present" : "missing",
      source: "filesystem"
    })),
    violations: report.violations.map(v => ({
      rule_id: v.rule_id,
      severity: v.severity,
      status: "open",
      source: v.source || (v.rule_id?.startsWith('EUAI-DOC-') ? 'filesystem' : 'engine')
    }))
  };
  fs.writeFileSync(path.join(outDir, "audit-evidence.json"), JSON.stringify(auditEvidence, null, 2));

  // 5. compliance-summary.md
  const highRisk = report.violations.filter(v => v.severity?.toLowerCase() === 'high' || v.severity?.toLowerCase() === 'critical');
  const missingDocs = auditEvidence.documents.filter(d => d.status === 'missing');

  const md = `# Sentinel Compliance Summary

## Overall Status
**${report.verdict}**

## Findings Summary
- Total violations: ${report.violations.length}
- High/Critical severity: ${highRisk.length}
- Missing required documentation: ${missingDocs.length}

## Top Violations
${report.violations.slice(0, 5).map(v => `- **${v.rule_id}** — ${v.description}`).join('\n')}

## Missing Documentation
${missingDocs.length > 0 ? missingDocs.map(d => `- ${d.path}`).join('\n') : "- None"}

## Recommended Next Actions
1. ${missingDocs.length > 0 ? "Add required compliance documentation" : "Address identified engine violations"}
2. Re-run Sentinel scan with evidence export
3. Review full report in \`scan-report.json\`

---
Generated by Sentinel CLI (Evidence Pack v1)
`;
  fs.writeFileSync(path.join(outDir, "compliance-summary.md"), md);

  // 6. Update scan-metadata.json with integrity hash
  const evidenceHash = calculateEvidenceHash(outDir);
  const updatedMetadata = { ...metadata, evidence_hash: evidenceHash };
  fs.writeFileSync(path.join(outDir, "scan-metadata.json"), JSON.stringify(updatedMetadata, null, 2));

  return { outDir, evidenceHash };
}

async function pushEvidence(dirPath, apiKey, endpoint) {
  const absolutePath = path.resolve(process.cwd(), dirPath);
  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Evidence directory not found: ${dirPath}`);
  }

  const metadataPath = path.join(absolutePath, 'scan-metadata.json');
  const reportPath = path.join(absolutePath, 'scan-report.json');

  if (!fs.existsSync(metadataPath) || !fs.existsSync(reportPath)) {
    throw new Error('Invalid evidence pack: Missing scan-metadata.json or scan-report.json');
  }

  const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));

  // Calculate hash to verify integrity before push
  const currentHash = calculateEvidenceHash(absolutePath);
  if (metadata.evidence_hash && metadata.evidence_hash !== currentHash) {
    console.warn(`${C.yellow}⚠️  Warning: Evidence pack integrity hash mismatch. Files may have been tampered with.${C.reset}`);
  }

  const payload = {
    mode: "evidence_push",
    schema: metadata.schema || "sentinel.audit.v1",
    schema_version: metadata.schema_version || "2026-03",
    ...metadata,
    project: metadata.project, // Ensure project object is included
    compliance_status: report.compliance_status,
    summary: report.summary,
    violations: report.violations,
    evidence_hash: currentHash
  };

  const body = JSON.stringify(payload);
  const url = new URL(endpoint);
  if (url.pathname === '/' || url.pathname === '/audit') url.pathname = '/v1/evidence';
  else if (url.pathname === '/v1') url.pathname = '/v1/evidence';

  if (process.env.SENTINEL_DEBUG === 'true' || !process.argv.includes('--json')) {
    console.log(`${C.gray}REMOTE REQUEST: ${url.href}${C.reset}`);
  }

  try {
    const response = await fetch(url.href, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Sentinel-API-Key': apiKey,
        'X-Sentinel-Remote': '1',
        'X-Sentinel-Protocol': 'v1.0.2',
        'X-Sentinel-CLI-Version': require('../package.json').version,
      },
      body: body
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Sync Failed (${response.status}): ${errorText}`);
    }

    return await response.json();
  } catch (err) {
    if (err.code === 'ENOTFOUND') {
      throw new Error(`Connection failed: Could not resolve ${url.hostname}. Check your internet connection.`);
    }
    throw err;
  }
}

function printSuccess(policyPath, auditMetadata = {}) {
  console.log("");
  console.log(`${C.bold}${C.green}✅ Sentinel compliance check passed${C.reset}`);

  if (auditMetadata.score !== undefined) {
    const scoreColor = auditMetadata.score > 80 ? C.green : (auditMetadata.score > 50 ? C.yellow : C.red);
    console.log(`${C.bold}Compliance Score: ${scoreColor}${auditMetadata.score}/100${C.reset}`);
  }

  if (auditMetadata.mapped_articles && auditMetadata.mapped_articles.length > 0) {
    console.log(`${C.bold}Verified Articles: ${C.cyan}${auditMetadata.mapped_articles.join(", ")}${C.reset}`);
  }

  console.log("");
  // Only display earned verification items
  if (auditMetadata.evidence_findings && auditMetadata.evidence_findings.length === 0) {
    console.log("All evidence validations passed.");
  } else if (auditMetadata.evidence_findings) {
    console.log(`${C.yellow}Minor findings (non-blocking):${C.reset}`);
    for (const f of auditMetadata.evidence_findings) {
      console.log(`${C.yellow}  ⚠ [${f.rule_id}] ${f.description}${C.reset}`);
    }
  }

  if (policyPath) {
    console.log("");
    console.log(`${C.gray}Sentinel policy: ${policyPath}${C.reset}`);
  }

  console.log("");
  console.log(`View verified AI projects:`);
  console.log("https://moxo08.github.io/sentinel-verified/");
  console.log("");
  console.log(`⭐ ${C.bold}Star the project:${C.reset}`);
  console.log("https://github.com/MOXO08/sentinel");
  console.log("");
}

function printFailure(missingFiles, policyPath) {
  console.log("");
  console.log("Repository is not EU AI Act ready.");
  console.log("");

  if (missingFiles.length > 0) {
    console.log(`${C.bold}Missing required artifacts:${C.reset}`);
    for (const file of missingFiles) {
      console.log(`- ${file}`);
    }
    console.log("");
  }

  console.log(`${C.bold}How to fix:${C.reset}`);
  console.log("1. Add the missing files");
  console.log("2. Commit the changes");
  console.log("3. Re-run the workflow");

  if (policyPath) {
    console.log("");
    console.log(`${C.gray}Sentinel policy: ${policyPath}${C.reset}`);
  }

  console.log("");
  console.log(`View verified AI projects:`);
  console.log("https://moxo08.github.io/sentinel-verified/");
  console.log("");
  console.log(`⭐ ${C.bold}Star the project:${C.reset}`);
  console.log("https://github.com/MOXO08/sentinel");
  console.log("");
}

function loadDefaultPolicy() {
  const defaultPath = path.resolve(__dirname, '../configs/default.policy.json');
  if (!fs.existsSync(defaultPath)) return null;
  try {
    const raw = fs.readFileSync(defaultPath, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

function loadPolicy(policyPath = "sentinel.policy.json") {
  const resolvedPath = path.resolve(process.cwd(), policyPath);

  if (!fs.existsSync(resolvedPath)) {
    if (policyPath === "sentinel.policy.json") {
      return {
        path: 'default.policy.json',
        config: loadDefaultPolicy(),
        warning: `Using default Sentinel policy (no local policy file found)`
      };
    }

    return {
      path: policyPath,
      config: null,
      error: `Policy file not found: ${policyPath}`
    };
  }

  try {
    const raw = fs.readFileSync(resolvedPath, "utf8");
    const config = JSON.parse(raw);

    return {
      path: policyPath,
      config,
      error: null
    };
  } catch (error) {
    return {
      path: policyPath,
      config: null,
      error: `Invalid policy file: ${policyPath} (${error.message})`
    };
  }
}

function resolvePolicyPack(policyPackName) {
  if (!policyPackName) return null;

  const packPath = path.resolve(
    __dirname,
    "../policy-packs",
    `${policyPackName}.json`
  );

  if (!fs.existsSync(packPath)) {
    return {
      error: `Policy pack not found: ${policyPackName}`
    };
  }

  try {
    const raw = fs.readFileSync(packPath, "utf8");
    const config = JSON.parse(raw);

    return {
      path: packPath,
      config
    };
  } catch (err) {
    return {
      error: `Invalid policy pack: ${policyPackName}`
    };
  }
}

function loadPolicyPackRegistry() {
  const registryPath = path.resolve(__dirname, "../policy-packs/index.json");

  if (!fs.existsSync(registryPath)) {
    return {
      path: registryPath,
      config: null,
      error: "Policy pack registry not found"
    };
  }

  try {
    const raw = fs.readFileSync(registryPath, "utf8");
    const config = JSON.parse(raw);

    return {
      path: registryPath,
      config,
      error: null
    };
  } catch (error) {
    return {
      path: registryPath,
      config: null,
      error: `Invalid policy pack registry (${error.message})`
    };
  }
}

function printPolicyPackList() {
  const registry = loadPolicyPackRegistry();

  if (registry.error) {
    console.error("");
    console.error(`Sentinel policy pack registry error: ${registry.error}`);
    console.error("");
    process.exit(1);
  }

  const packs = Array.isArray(registry.config?.packs) ? registry.config.packs : [];

  console.log("");
  console.log("Available Sentinel policy packs:");
  console.log("");

  for (const pack of packs) {
    console.log(`- ${pack.name}`);
    console.log(`  ${pack.description}`);
    if (pack.category) {
      console.log(`  category: ${pack.category}`);
    }
    console.log("");
  }
}

function printPolicyPackDetails(policyPackName) {
  const registry = loadPolicyPackRegistry();

  if (registry.error) {
    console.error("");
    console.error(`Sentinel policy pack registry error: ${registry.error}`);
    console.error("");
    process.exit(1);
  }

  const packs = Array.isArray(registry.config?.packs) ? registry.config.packs : [];
  const packMeta = packs.find(pack => pack.name === policyPackName);

  if (!packMeta) {
    console.error("");
    console.error(`Sentinel policy pack error: Pack not found: ${policyPackName}`);
    console.error("");
    process.exit(1);
  }

  const pack = resolvePolicyPack(policyPackName);

  if (!pack || pack.error) {
    console.error("");
    console.error(`Sentinel policy pack error: ${pack?.error || "Unable to load pack"}`);
    console.error("");
    process.exit(1);
  }

  const requiredDocuments =
    pack.config &&
      pack.config.rules &&
      Array.isArray(pack.config.rules.required_documents)
      ? pack.config.rules.required_documents
      : [];

  console.log("");
  console.log(`Policy Pack: ${packMeta.name}`);
  console.log("");
  console.log(`Description: ${packMeta.description}`);
  if (packMeta.category) {
    console.log(`Category: ${packMeta.category}`);
  }
  console.log(`File: ${packMeta.file}`);
  console.log("");

  console.log("Required documents:");
  if (requiredDocuments.length === 0) {
    console.log("- none");
  } else {
    for (const doc of requiredDocuments) {
      console.log(`- ${doc}`);
    }
  }

  console.log("");
}

function checkRequiredDocuments(policyConfig) {
  const requiredDocuments =
    policyConfig &&
      policyConfig.rules &&
      Array.isArray(policyConfig.rules.required_documents)
      ? policyConfig.rules.required_documents
      : [];

  const missingFiles = [];

  for (const filePath of requiredDocuments) {
    const resolvedPath = path.resolve(process.cwd(), filePath);
    if (!fs.existsSync(resolvedPath)) {
      missingFiles.push(filePath);
    }
  }

  return missingFiles;
}

function loadBaseline(baselinePath) {
  if (!baselinePath) {
    return {
      path: null,
      config: null,
      error: null
    };
  }

  const resolvedPath = path.resolve(process.cwd(), baselinePath);

  if (!fs.existsSync(resolvedPath)) {
    return {
      path: baselinePath,
      config: null,
      error: `Baseline file not found: ${baselinePath}`
    };
  }

  try {
    const raw = fs.readFileSync(resolvedPath, "utf8");
    const config = JSON.parse(raw);

    return {
      path: baselinePath,
      config,
      error: null
    };
  } catch (error) {
    return {
      path: baselinePath,
      config: null,
      error: `Invalid baseline file: ${baselinePath} (${error.message})`
    };
  }
}

function filterMissingFilesAgainstBaseline(missingFiles, baselineConfig) {
  if (
    !baselineConfig ||
    !Array.isArray(baselineConfig.violations)
  ) {
    return missingFiles;
  }

  const baselinePaths = new Set(
    baselineConfig.violations
      .filter(v => v && v.rule_id === "required_document" && v.path)
      .map(v => v.path)
  );

  return missingFiles.filter(filePath => !baselinePaths.has(filePath));
}

function generateSarif(report, manifestPath) {
  const violations = (report && Array.isArray(report.violations)) ? report.violations : [];

  const rulesMap = {
    'ART5-001': { id: 'EU-AI-ACT-ART5', name: 'Prohibited AI Practice: Subliminal manipulation' },
    'ART5-003': { id: 'EU-AI-ACT-ART5', name: 'Prohibited AI Practice: Social scoring' },
    'required_document': { id: 'EU-AI-ACT-DOCS', name: 'Missing Required Compliance Documentation' }
  };

  const results = violations.map(v => {
    let ruleId = v.rule_id;

    // Backward compatibility & Registry lookup
    if (!ruleId && v.description) {
      const desc = v.description.toLowerCase();
      const registryMatch = ruleRegistry.rules.find(r =>
        desc.includes(r.name.toLowerCase()) || desc.includes(r.description.toLowerCase())
      );
      if (registryMatch) ruleId = registryMatch.id;

      // Fallback heuristics for legacy rules
      if (!ruleId) {
        if (desc.includes('subliminal')) ruleId = 'EUAI-BLOCK-001';
        else if (desc.includes('social scoring')) ruleId = 'EUAI-BLOCK-002';
        else if (desc.includes('transparent about being an ai') || desc.includes('transparency')) ruleId = 'EUAI-TECH-001';
        else if (desc.includes('human oversight')) ruleId = 'EUAI-GOV-002';
        else if (desc.includes('bias') || desc.includes('representativeness')) ruleId = 'EUAI-DATA-001';
        else if (desc.includes('biometric')) ruleId = 'EUAI-TECH-020';
        else if (desc.includes('missing required document') || desc.includes('required document')) ruleId = 'EUAI-DOC-001';
        else if (desc.includes('gpai')) ruleId = 'EUAI-TECH-010';
      }
    }

    const regEntry = ruleRegistry.rules.find(r => r.id === ruleId);
    const ruleRef = {
      id: ruleId || 'EUAI-GENERIC',
      name: regEntry ? regEntry.name : (v.description || 'Compliance Violation')
    };

    return {
      ruleId: ruleRef.id,
      level: 'error',
      message: {
        text: v.description || 'Compliance violation detected'
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: manifestPath.replace(/\\/g, '/')
            }
          }
        }
      ]
    };
  });

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Sentinel",
            informationUri: "https://sentinel-moxo.workers.dev",
            rules: Object.values(rulesMap).map(r => ({ id: r.id, name: r.name }))
          }
        },
        results: results
      }
    ]
  };

  return sarif;
}

function generateEvidence(policyConfig) {
  const baseDir = path.resolve(process.cwd(), "docs/compliance");
  const templatesDir = path.resolve(__dirname, "../templates");

  if (!fs.existsSync(baseDir)) {
    fs.mkdirSync(baseDir, { recursive: true });
  }

  const requiredDocuments =
    policyConfig &&
      policyConfig.rules &&
      Array.isArray(policyConfig.rules.required_documents)
      ? policyConfig.rules.required_documents
      : [];

  const createdDocs = [];

  for (const docPath of requiredDocuments) {
    const fileName = path.basename(docPath);
    const targetPath = path.resolve(process.cwd(), docPath);

    if (fs.existsSync(targetPath)) continue;

    const templatePath = path.resolve(templatesDir, fileName);

    if (!fs.existsSync(templatePath)) continue;

    let content = fs.readFileSync(templatePath, "utf8");
    content = content.replace("{{DATE}}", new Date().toISOString());

    const dir = path.dirname(targetPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(targetPath, content);
    createdDocs.push(docPath);
  }

  const index = {
    generated_at: new Date().toISOString(),
    documents: requiredDocuments.map(doc => ({
      path: doc,
      rule_id: "EUAI-DOC-001", // Standardized DOC namespace
      status: fs.existsSync(path.resolve(process.cwd(), doc)) ? "closed" : "open"
    }))
  };

  fs.writeFileSync(
    path.resolve(baseDir, "evidence.index.json"),
    JSON.stringify(index, null, 2)
  );

  console.log("");
  console.log(`${C.bold}${C.green}✅ Sentinel evidence templates generated.${C.reset}`);
  if (createdDocs.length > 0) {
    console.log(`Created ${createdDocs.length} new templates in docs/compliance/`);
  } else {
    console.log("No new documents needed or all already exist.");
  }
  console.log("");
}

function printResult(verdict, isJson, isSarif, policyPath = "sentinel.policy.json") {
  if (isJson) {
    console.log(JSON.stringify(verdict, null, 2));
    return;
  }

  const singleVerdict = Array.isArray(verdict) ? verdict[0] : verdict;
  const violations = singleVerdict?.violations || [];
  const isFail = Array.isArray(verdict)
    ? verdict.some(v => v.verdict === "NON_COMPLIANT" || v.verdict === "NON_COMPLIANT_VIA_AI_REVIEW")
    : (singleVerdict?.verdict === "NON_COMPLIANT" || singleVerdict?.verdict === "NON_COMPLIANT_VIA_AI_REVIEW");

  let missingFiles = [];

  if (violations.length > 0) {
    missingFiles = violations
      .map(v => {
        if (!v || !v.description) return null;
        const desc = String(v.description).trim();

        if (desc.toLowerCase().includes("missing")) {
          const parts = desc.split(":");
          return parts.length > 1 ? parts[parts.length - 1].trim() : desc;
        }

        return null;
      })
      .filter(Boolean);
  }

  const auditMetadata = {
    score: singleVerdict?.score?.finalScore !== undefined ? singleVerdict.score.finalScore : singleVerdict?.score,
    baseScore: singleVerdict?.score?.baseScore,
    deductions: singleVerdict?.score?.deductions,
    mapped_articles: singleVerdict?.mapped_articles,
    risk_category: singleVerdict?.risk_category,
    required_articles: singleVerdict?.required_articles,
    verdict: singleVerdict?.verdict
  };

  const confidence = (auditMetadata.score >= 90 && auditMetadata.mapped_articles?.length >= 3) ? "HIGH" :
    (auditMetadata.score >= 70) ? "MEDIUM" : "LOW";

  if (isFail) {
    if (!isJson && !isSarif) {
      console.log(`${C.bold}${C.red}❌ Sentinel compliance check failed${C.reset}`);

      console.log(`${C.bold}Compliance Status: ${C.red}NON_COMPLIANT${C.reset}`);

      if (auditMetadata.risk_category === 'unacceptable') {
        console.log(`${C.bold}Risk Category: ${C.white}unacceptable${C.reset}`);
        console.log(`${C.bold}Verified Controls: ${C.gray}None${C.reset}`);
        console.log(`${C.bold}Verified Articles: ${C.gray}None${C.reset}`);
        console.log(`${C.bold}Reason: ${C.red}Prohibited system / hard fail${C.reset}`);
      } else {
        if (auditMetadata.baseScore !== undefined) {
          console.log(`${C.bold}Base Score: ${C.white}${auditMetadata.baseScore}/100${C.reset}`);
          console.log(`${C.bold}Deductions: ${C.red}-${auditMetadata.deductions}${C.reset}`);
          console.log(`${C.bold}Final Score: ${C.red}${auditMetadata.score}/100${C.reset}`);
        } else if (auditMetadata.score !== undefined) {
          console.log(`${C.bold}Compliance Score: ${C.red}${auditMetadata.score}/100${C.reset}`);
        }

        console.log(`${C.bold}Confidence Level: ${C.yellow}${confidence}${C.reset}`);
        console.log(`${C.bold}Risk Category: ${C.white}${auditMetadata.risk_category || 'minimal'}${C.reset}`);
        console.log(`${C.bold}Required Controls: ${C.gray}${auditMetadata.required_articles?.join(', ') || 'Art. 13'}${C.reset}`);
        console.log(`${C.bold}Verified Controls: ${C.gray}${auditMetadata.mapped_articles?.join(', ') || 'None'}${C.reset}`);
        console.log(`${C.bold}Verified Articles: ${C.gray}${auditMetadata.mapped_articles?.join(', ') || 'None'}${C.reset}`);
      }

      console.log("");

      const getRuleId = (v) => {
        let ruleId = v.rule_id;
        if (!ruleId && v.description) {
          const desc = v.description.toLowerCase();
          if (desc.includes('transparent about being an ai')) ruleId = 'EUAI-TECH-001';
          else if (desc.includes('human oversight')) ruleId = 'EUAI-GOV-002';
          else if (desc.includes('bias')) ruleId = 'EUAI-DATA-001';
          else if (desc.includes('missing required document')) ruleId = 'EUAI-DOC-001';
        }
        return ruleId;
      };

      const hardFails = violations.filter(v => v.hard_fail);
      const evidenceFindings = violations.filter(v => v.source === "evidence" && !v.hard_fail);
      const policyViolations = violations.filter(v => v.source !== "evidence" && !v.hard_fail);

      if (policyViolations.length > 0) {
        console.log(`${C.bold}${C.yellow}Policy Violations:${C.reset}`);
        policyViolations.forEach(v => {
          const ruleId = getRuleId(v);
          const idStr = ruleId ? `[${C.bold}${ruleId}${C.reset}] ` : "";
          console.log(`  ${C.yellow}✖ ${idStr}${v.description}${C.reset}`);
        });
        console.log("");
      }

      if (evidenceFindings.length > 0) {
        console.log(`${C.bold}${C.yellow}Evidence Validation Findings:${C.reset}`);
        evidenceFindings.forEach(v => {
          const ruleId = getRuleId(v);
          const idStr = ruleId ? `[${C.bold}${ruleId}${C.reset}] ` : "";
          console.log(`  ${C.yellow}⚠ ${idStr}${v.description}${C.reset}`);
        });
        console.log("");
      }

      if (hardFails.length > 0) {
        console.log(`${C.bold}${C.red}Hard Fails:${C.reset}`);
        hardFails.forEach(v => {
          const ruleId = getRuleId(v);
          const idStr = ruleId ? `[${C.bold}${ruleId}${C.reset}] ` : "";
          console.log(`  ${C.red}✖ HARD FAIL ${idStr}${v.description}${C.reset}`);
        });
        console.log("");
      }

      const summaryParts = [];
      if (hardFails.length > 0) summaryParts.push(`${hardFails.length} hard fail${hardFails.length > 1 ? 's' : ''}`);
      if (policyViolations.length > 0) summaryParts.push(`${policyViolations.length} policy violation${policyViolations.length > 1 ? 's' : ''}`);
      if (evidenceFindings.length > 0) summaryParts.push(`${evidenceFindings.length} evidence finding${evidenceFindings.length > 1 ? 's' : ''}`);

      if (summaryParts.length > 0) {
        console.log(`  ${C.gray}Failure caused by ${summaryParts.join(" and ")}${C.reset}`);
        console.log("");
      }
    }
    printFailure(missingFiles, policyPath);
  } else {
    if (!isJson && !isSarif) {
      const statusColor = auditMetadata.verdict === 'COMPLIANT' ? C.green : (auditMetadata.verdict === 'PARTIAL' ? C.yellow : C.red);
      console.log(`${C.bold}${statusColor}✅ Sentinel compliance check passed${C.reset}`);
      console.log(`${C.bold}Compliance Status: ${statusColor}${auditMetadata.verdict}${C.reset}`);

      if (auditMetadata.baseScore !== undefined) {
        console.log(`${C.bold}Base Score: ${C.white}${auditMetadata.baseScore}/100${C.reset}`);
        console.log(`${C.bold}Deductions: ${C.green}-${auditMetadata.deductions}${C.reset}`);
        console.log(`${C.bold}Final Score: ${C.green}${auditMetadata.score}/100${C.reset}`);
      } else {
        console.log(`${C.bold}Compliance Score: ${C.green}${auditMetadata.score}/100${C.reset}`);
      }

      console.log(`${C.bold}Confidence Level: ${C.green}${confidence}${C.reset}`);
      console.log(`${C.bold}Risk Category: ${C.white}${auditMetadata.risk_category || 'minimal'}${C.reset}`);
      console.log(`${C.bold}Required Controls: ${C.gray}${auditMetadata.required_articles?.join(', ') || 'Art. 13'}${C.reset}`);
      console.log(`${C.bold}Verified Controls: ${C.gray}${auditMetadata.mapped_articles?.join(', ') || 'None'}${C.reset}`);
      console.log(`${C.bold}Verified Articles: ${C.gray}${auditMetadata.mapped_articles?.join(', ') || 'None'}${C.reset}`);

      if (policyPath) {
        console.log("");
        console.log(`${C.gray}Sentinel policy: ${policyPath}${C.reset}`);
      }
      console.log("");
    }
  }
}

function printVersion() {
  const pkg = require('../package.json');
  console.log(`Sentinel CLI v${pkg.version}`);
}


/**
 * CI/CD Guardrail: check compliance score against threshold.
 */
async function runCheck(args) {
  const isJson = args.includes('--json');

  // 1. Resolve Threshold
  const thresholdArgIdx = args.indexOf('--threshold');
  let threshold = null;
  if (thresholdArgIdx !== -1 && args[thresholdArgIdx + 1]) {
    threshold = parseInt(args[thresholdArgIdx + 1]);
  }

  if (threshold === null || isNaN(threshold)) {
    console.error(`\n${C.red}${C.bold}Error: --threshold is required for sentinel check${C.reset}`);
    console.log(`\n${C.bold}Suggested thresholds:${C.reset}`);
    console.log(`  - 70 → development baseline`);
    console.log(`  - 80 → production minimum`);
    console.log(`  - 90 → high-risk systems (recommended)`);
    process.exit(2);
  }

  // 2. Resolve Manifest
  const manifestPath = resolveTargetManifest(args);
  if (!manifestPath || !fs.existsSync(manifestPath)) {
    console.error(`${C.red}Error: No manifest found. Use --manifest <path>${C.reset}`);
    process.exit(2);
  }

  const manifestDir = path.dirname(path.resolve(manifestPath));
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (e) {
    console.error(`${C.red}Error reading manifest: ${e.message}${C.reset}`);
    process.exit(2);
  }

  // Normalize risk category for reporting
  const riskCatOrig = manifest.risk_category || "Minimal";
  const riskCat = riskCatOrig.toUpperCase();

  // 3. Perform Audit
  const offlineResult = await runOffline(manifest);
  const engineViolations = offlineResult.violations || [];
  const evidenceFindings = validateEvidence(manifest, manifestDir);
  const allFindings = [...evidenceFindings, ...engineViolations];

  // Post-process findings to ensure 100% DX compliance (labels and snippets)
  allFindings.forEach(f => {
    if (f.fix_snippet && f.fix_snippet.includes('declared_flags') && !f.fix_snippet.includes('array')) {
      f.fix_snippet = f.fix_snippet.replace('declared_flags', "'declared_flags' array");
    }
    if (f.description && f.description.toLowerCase().includes('transparent about being an ai')) {
      f.description = "[Missing user notification]";
      f.fix_snippet = "Add 'user_notification_ai_interaction' to 'declared_flags' array.";
      if (!f.article) f.article = "Art. 13";
    }
  });

  const scoreObj = computeEvidenceScore(evidenceFindings, manifest);
  const score = scoreObj.finalScore !== undefined ? scoreObj.finalScore : scoreObj;
  const verdict = computeVerdict(score, allFindings, manifest);

  // 4. Output
  if (isJson) {
    const report = {
      command: "check",
      status: score >= threshold ? "PASS" : "FAIL",
      score,
      threshold,
      verdict,
      exit_code: score >= threshold ? 0 : 1,
      remaining_findings: allFindings.length,
      top_findings: allFindings.slice(0, 5).map(f => ({
        rule_id: f.rule_id,
        description: f.description,
        fix_snippet: f.fix_snippet
      }))
    };
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.exit_code);
  }

  if (score >= threshold) {
    console.log(`\n${C.green}${C.bold}Sentinel Check: PASS${C.reset}`);
  } else {
    console.log(`\n${C.red}${C.bold}Sentinel Check: FAIL${C.reset}`);
  }

  console.log(`${C.gray}Manifest: ${C.white}${manifestPath}${C.reset}`);
  console.log(`${C.gray}Score: ${C.white}${score}/100${C.reset}`);
  console.log(`${C.gray}Threshold: ${C.white}${threshold}${C.reset}`);


  if (riskCat === 'HIGH') {
    console.log(`\n${C.yellow}${C.bold}⚠ High-risk system detected${C.reset}`);
    console.log(`${C.cyan}Recommended minimum threshold: 90${C.reset}`);
  }

  if (score < threshold) {

    allFindings.slice(0, 5).forEach(f => {
      const legalRef = f.article ? ` (${f.article})` : '';
      console.log(`\n[${C.yellow}${f.description}${C.reset}]${legalRef}`);
      if (f.fix_snippet) console.log(`${C.green}→ ${f.fix_snippet}${C.reset}`);
    });


    const contextualFix = manifestPath ? ` --manifest ${manifestPath}` : '';
    console.log(`\n${C.cyan}Next step: run ${C.bold}npx @radu_api/sentinel-scan fix --apply${contextualFix}${C.reset} to scaffold structure.`);
    console.log(`${C.gray}Note: scaffolds missing structure only. Manual content still required.${C.reset}\n`);

    process.exit(1);
  }

  process.exit(0);
}

async function main() {
  const args = process.argv.slice(2);
  const command = (args[0] || '').toLowerCase();

  // 1. Global Flags (Priority)
  if (args.includes('--version') || args.includes('-v')) {
    printBanner();
    printVersion();
    process.exit(0);
  }
  if (args.includes('--help') || args.includes('-h')) {
    printBanner();
    printHelp();
    process.exit(0);
  }

  // 2. Subcommand Routing (MUST EXIT AFTER)
  if (command === 'fix') {
    await runFix(args.slice(1));
    process.exit(0);
  }

  if (command === 'check') {
    await runCheck(args.slice(1));
    process.exit(0);
  }

  if (command === 'init') {
    runInit();
    process.exit(0);
  }

  if (command === 'discover') {
    printBanner();
    console.log(`${C.cyan}${C.bold}🔍 Sentinel Magic Onboarding: Scanning repository...${C.reset}`);
    const repoFiles = autodiscovery.crawlRepository(process.cwd());
    const signals = autodiscovery.extractSignals(repoFiles, discoveryRules);
    const suggestedManifest = autodiscovery.generateManifestFromSignals(signals);
    console.log(`${C.gray}Analyzed ${repoFiles.length} files. Detected ${signals.length} signals.${C.reset}\n`);
    console.log(`${C.bold}Generated suggested manifest for ${C.cyan}${suggestedManifest.app_name}${C.reset}:`);
    console.log(JSON.stringify(suggestedManifest, null, 2));
    console.log("");
    const manifestPath = path.join(process.cwd(), "sentinel.manifest.json");
    if (fs.existsSync(manifestPath)) {
      console.log(`${C.yellow}⚠️  A manifest already exists. Skipping auto-save.${C.reset}`);
    } else {
      fs.writeFileSync(manifestPath, JSON.stringify(suggestedManifest, null, 2));
      console.log(`${C.green}${C.bold}✅ Suggested manifest saved to sentinel.manifest.json${C.reset}`);
    }
    process.exit(0);
  }

  if (command === "policy-pack") {
    if (args[1] === "list") { printPolicyPackList(); process.exit(0); }
    if (args[1] === "show" && args[2]) { printPolicyPackDetails(args[2]); process.exit(0); }
  }

  if (command === "evidence") {
    if (args[1] === "generate") {
      let policyPath = "sentinel.policy.json";
      let policyPack = null;
      for (let i = 0; i < args.length; i++) {
        if (args[i] === "--policy" && args[i + 1]) { policyPath = args[i + 1]; i++; }
        if (args[i] === "--policy-pack" && args[i + 1]) { policyPack = args[i + 1]; i++; }
      }
      let policy = policyPack ? { path: resolvePolicyPack(policyPack).path, config: resolvePolicyPack(policyPack).config } : loadPolicy(policyPath);
      if (policy.error) { console.error(`\nError: ${policy.error}\n`); process.exit(1); }
      generateEvidence(policy.config);
      process.exit(0);
    }
    if (args[1] === "push") {
      const dir = args[2] || "sentinel-evidence";
      const apiKeyIdx = args.indexOf('--api-key');
      const apiKey = apiKeyIdx !== -1 ? args[apiKeyIdx + 1] : process.env.SENTINEL_API_KEY || '';
      if (!apiKey) { console.error(`${C.red}Error: --api-key required.${C.reset}`); process.exit(1); }
      console.log(`${C.cyan}🚀 Porting Evidence...${C.reset}`);
      pushEvidence(dir, apiKey, 'https://api.gettingsentinel.com/v1').then(() => process.exit(0));
      return;
    }
  }

  // 3. Default Scan Logic (Locked Contract)
  let manifestPath = null;
  const validSubcommands = ['fix', 'check', 'init', 'discover', 'policy-pack', 'evidence'];

  if (args.length === 0) {
    if (fs.existsSync('sentinel.manifest.json')) {
      manifestPath = 'sentinel.manifest.json';
    } else if (fs.existsSync('manifest.json')) {
      manifestPath = 'manifest.json';
    } else {
      printOnboarding();
      process.exit(0);
      return;
    }
  } else if (!validSubcommands.includes(command) && !args[0].startsWith('-')) {
    // If it's a positional argument but not a subcommand -> DISALLOWED
    console.error(`\n${C.red}❌ Error: Ambiguous usage. Positional manifest aliases are no longer supported.${C.reset}`);
    console.log(`\n${C.cyan}${C.bold}Correct usage:${C.reset}`);
    console.log(`  npx @radu_api/sentinel-scan check --threshold 90 --manifest <path>`);
    console.log(`  npx @radu_api/sentinel-scan`);
    process.exit(1);
    return;
  } else if (!validSubcommands.includes(command)) {
    // Other ambiguous usage (e.g. flags without check subcommand)
    console.error(`\n${C.red}❌ Error: Invalid command or flag usage: "${args[0]}"${C.reset}`);
    console.log(`\n${C.cyan}${C.bold}Correct usage:${C.reset}`);
    console.log(`  npx @radu_api/sentinel-scan check --threshold 90 --manifest <path>`);
    process.exit(1);
    return;
  }

  // Initialize scan variables
  const isRemote = args.includes('--remote');
  const isJson = args.includes('--json');
  const isSarif = args.includes('--sarif');
  const isEvidence = args.includes('--evidence');
  const isAutodiscover = args.includes('--autodiscover');

  let policyPath = "sentinel.policy.json";
  let baselinePath = null;
  let policyPack = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--policy" && args[i + 1]) { policyPath = args[i + 1]; i++; }
    if (args[i] === "--baseline" && args[i + 1]) { baselinePath = args[i + 1]; i++; }
    if (args[i] === "--policy-pack" && args[i + 1]) { policyPack = args[i + 1]; i++; }
  }

  const apiKeyIdx = args.indexOf('--api-key');
  const apiKey = apiKeyIdx !== -1 ? args[apiKeyIdx + 1] : process.env.SENTINEL_API_KEY || '';
  const endpointIdx = args.indexOf('--endpoint');
  const endpoint = endpointIdx !== -1 ? args[endpointIdx + 1] : 'https://api.gettingsentinel.com/v1';

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (!manifest || (typeof manifest !== 'object')) {
      throw new Error("Manifest must be a JSON object or array.");
    }
  } catch (e) {
    console.error(`\n${C.red}❌ Error: Invalid manifest format: ${e.message}${C.reset}`);
    pauseAndExit(2);
    return; // Atomic exit
  }

  // Hard-Gate Validation Guard
  if (!manifest) {
    return; // Exit main flow immediately
  }

  if (!isJson && !isSarif) {
    printBanner();
    console.log(`${C.gray}Scanning: ${path.resolve(manifestPath)}${C.reset}`);
    console.log(`${C.gray}Mode: ${isRemote ? '🌐 Remote Audit' : '⚡ Local Diagnostic'}${C.reset}\n`);
  }

  let alignmentIssues = [];
  if (isAutodiscover && !Array.isArray(manifest)) {
    if (!isJson && !isSarif) console.log(`${C.cyan}${C.bold}🔍 Running Sentinel Autodiscovery...${C.reset}`);
    const repoFiles = autodiscovery.crawlRepository(process.cwd());
    const signals = autodiscovery.extractSignals(repoFiles, discoveryRules);
    alignmentIssues = autodiscovery.verifyAlignment(manifest, signals);
    if (!isJson && !isSarif) {
      console.log(`${C.gray}Analyzed ${repoFiles.length} files. Detected ${signals.length} signals.${C.reset}`);
      if (alignmentIssues.length > 0) {
        console.log(`\n${C.yellow}${C.bold}⚠️  INTEGRITY ISSUES DETECTED:${C.reset}`);
        alignmentIssues.forEach(issue => console.log(`${C.yellow}- [${issue.type}] ${issue.recommendation}${C.reset}`));
        console.log("");
      } else {
        console.log(`${C.green}✅ No integrity discrepancies found between code and manifest.${C.reset}\n`);
      }
    }
  }

  try {
    let results;
    const telemetry = {
      clientId: getOrCreateClientId(),
      scanId: require('crypto').randomBytes(8).toString('hex'),
      projectHash: computeProjectHash(),
      executionContext: detectExecutionContext()
    };

    if (Array.isArray(manifest)) {
      const bar = new cliProgress.SingleBar({
        format: `${C.cyan}Scanning |${C.reset}{bar}${C.cyan}| {percentage}% || {value}/{total} Items`,
        barCompleteChar: '\u2588', barIncompleteChar: '\u2591', hideCursor: true
      });
      if (!isJson && !isSarif) bar.start(manifest.length, 0);
      results = [];
      for (const item of manifest) {
        results.push(isRemote ? await runRemote(item, apiKey, endpoint, telemetry) : await runOffline(item));
        if (!isJson && !isSarif) bar.increment();
      }
      if (!isJson && !isSarif) bar.stop();
    } else {
      results = isRemote ? await runRemote(manifest, apiKey, endpoint, telemetry) : await runOffline(manifest);
    }

    let policy;
    if (policyPack) {
      const pack = resolvePolicyPack(policyPack);
      if (pack.error) { console.error(`\n${pack.error}\n`); process.exit(1); }
      policy = { path: pack.path, config: pack.config };
    } else {
      policy = loadPolicy(policyPath);
      if (policy.warning && !isJson && !isSarif) console.log(`${C.yellow}⚠  ${policy.warning}${C.reset}`);
      if (policy.error) { console.error(`\nSentinel policy error: ${policy.error}\n`); process.exit(1); }
    }

    const baseline = loadBaseline(baselinePath);
    if (baseline.error) { console.error(`\nSentinel baseline error: ${baseline.error}\n`); process.exit(1); }

    const missingPolicyFiles = checkRequiredDocuments(policy.config);
    const newMissingPolicyFiles = filterMissingFilesAgainstBaseline(missingPolicyFiles, baseline.config);

    const combinedViolations = [];
    const engineVerdicts = Array.isArray(results) ? results : [results];
    for (const v of engineVerdicts) {
      if (v && Array.isArray(v.violations)) combinedViolations.push(...v.violations);
    }

    if (newMissingPolicyFiles.length > 0) {
      combinedViolations.push(...newMissingPolicyFiles.map(file => ({
        rule_id: "EUAI-DOC-001",
        description: `Missing required document: ${file}`,
        source: "filesystem"
      })));
    }

    const manifestDir = path.dirname(path.resolve(manifestPath));
    const singleManifest = Array.isArray(manifest) ? manifest[0] : manifest;
    const evidenceFindings = validateEvidence(singleManifest, manifestDir);

    for (const finding of evidenceFindings) {
      combinedViolations.push({
        rule_id: finding.rule_id,
        description: finding.description,
        severity: finding.severity,
        source: finding.source,
        article: finding.article,
        hard_fail: finding.hard_fail
      });
    }

    const riskCat = (singleManifest.risk_category || "minimal").toLowerCase();
    let required = riskCat === 'high' ? ['Art. 9', 'Art. 13', 'Art. 14', 'Art. 20'] : ['Art. 13'];
    const evidenceScore = computeEvidenceScore(evidenceFindings, singleManifest);
    const verifiedArticles = determineVerifiedArticles(evidenceFindings, singleManifest);
    const evidenceVerdict = computeVerdict(evidenceScore.finalScore !== undefined ? evidenceScore.finalScore : evidenceScore, evidenceFindings, singleManifest);

    const summary = {
      violations_total: combinedViolations.length,
      high: combinedViolations.filter(v => ['high', 'critical'].includes(v.severity?.toLowerCase())).length,
      medium: combinedViolations.filter(v => v.severity?.toLowerCase() === 'medium').length,
      low: combinedViolations.filter(v => v.severity?.toLowerCase() === 'low').length,
      informational: combinedViolations.filter(v => v.severity?.toLowerCase() === 'informational').length
    };

    let complianceStatus = evidenceVerdict;
    if (combinedViolations.some(v => v.rule_id?.startsWith('EUAI-BLOCK-'))) complianceStatus = "BLOCKED";

    const finalReport = {
      schema: "sentinel.audit.v1",
      schema_version: "2026-03",
      verdict: evidenceVerdict,
      score: evidenceScore,
      mapped_articles: verifiedArticles,
      risk_category: riskCat,
      required_articles: required,
      compliance_status: complianceStatus,
      summary,
      evidence_findings: evidenceFindings,
      violations: combinedViolations.map(v => {
        let ruleId = v.rule_id;
        if (!ruleId && v.description) {
          const desc = v.description.toLowerCase();
          if (desc.includes('transparent about being an ai')) ruleId = 'EUAI-TECH-001';
          else if (desc.includes('human oversight')) ruleId = 'EUAI-GOV-002';
          else if (desc.includes('bias')) ruleId = 'EUAI-DATA-001';
          else if (desc.includes('missing required document')) ruleId = 'EUAI-DOC-001';
        }
        return {
          ...v,
          rule_id: ruleId || "EUAI-GENERIC",
          source: v.source || (ruleId?.startsWith('EUAI-DOC-') ? 'filesystem' : 'engine')
        };
      })
    };

    const remoteResult = Array.isArray(results) ? results[0] : results;
    if (isRemote && remoteResult) {
      let remoteScore = remoteResult.score !== undefined ? remoteResult.score : (remoteResult.risk_score !== undefined ? 100 - remoteResult.risk_score : undefined);
      if (remoteScore !== undefined) finalReport.score = Math.min(evidenceScore.finalScore || evidenceScore, remoteScore);
      if (remoteResult.verdict && !["COMPLIANT", "COMPLIANT_VIA_AI_REVIEW"].includes(remoteResult.verdict)) {
        finalReport.verdict = "NON_COMPLIANT";
        if (remoteResult.justification) {
          combinedViolations.push({
            rule_id: remoteResult.verdict === "INVALID_PAYLOAD" ? "SENTINEL-API-001" : "EUAI-REMOTE-001",
            description: `Remote Audit Feedback: ${remoteResult.justification.join(", ")}`,
            source: "remote"
          });
        }
      }
    }

    if (isEvidence) {
      const git = getGitMetadata();
      const pkg = require('../package.json');
      const packMetadata = {
        schema: "sentinel.audit.v1",
        schema_version: "2026-03",
        scan_id: require('crypto').randomUUID ? require('crypto').randomUUID() : Math.random().toString(36).substring(7),
        timestamp: new Date().toISOString(),
        repo_path: process.cwd(),
        project: git.project,
        commit: git.commit,
        branch: git.branch,
        sentinel_version: pkg.version,
        engine_version: "2.0.0",
        ruleset: "eu-ai-act",
        evidence_version: 1,
        required_documents: policy.config?.rules?.required_documents || []
      };
      const sarifData = generateSarif(finalReport, manifestPath);
      const { outDir, evidenceHash } = generateEvidencePack({ report: finalReport, metadata: packMetadata, sarif: sarifData, policyPath: policy.path });
      console.log(`\n${C.green}${C.bold}✔ Evidence pack generated at ${outDir}${C.reset}`);
      console.log(`${C.gray}Integrity Hash: ${evidenceHash}${C.reset}\n`);
    }

    if (isSarif) {
      console.log(JSON.stringify(generateSarif(finalReport, manifestPath), null, 2));
      process.exit(finalReport.verdict === "NON_COMPLIANT" ? 1 : 0);
    }

    if (isJson) {
      console.log(JSON.stringify(finalReport, null, 2));
      process.exit(finalReport.verdict === "NON_COMPLIANT" ? 1 : 0);
    }

    printResult(finalReport, isJson, isSarif, policy.path);
    if (finalReport.verdict === "NON_COMPLIANT") {
      pauseAndExit(1);
      return;
    }
    pauseAndExit(0);
    return;
  } catch (err) {
    console.error(`${C.red}Scan failed: ${err.message}${C.reset}`);
    await reportError(err);
    pauseAndExit(2);
    return;
  }
}

/**
 * Guided remediation for compliance gaps.
 */
async function runFix(args) {
  const isApply = args.includes('--apply');

  // 1. Resolve manifest
  const manifestPath = resolveTargetManifest(args);

  if (!manifestPath || !fs.existsSync(manifestPath)) {
    console.error(`${C.red}Error: No sentinel.manifest.json or manifest.json found in current directory.${C.reset}`);
    process.exit(1);
  }

  const manifestDir = path.dirname(path.resolve(manifestPath));
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (e) {
    console.error(`${C.red}Error reading manifest: ${e.message}${C.reset}`);
    process.exit(1);
  }

  // 2. Initial Audit
  const findings = validateEvidence(manifest, manifestDir);
  const actionableRuleIds = ['EUAI-MIN-001', 'EUAI-TRANS-001', 'EUAI-OVER-002', 'EUAI-LOG-003'];
  const actionableFindings = findings.filter(f => actionableRuleIds.includes(f.rule_id));

  if (actionableFindings.length === 0) {
    console.log(`\n${C.green}No safe structural fixes available.${C.reset}`);
    return;
  }

  // 3. Generate Plan
  const plan = [];
  const docsToCreate = [];

  if (findings.some(f => f.rule_id === 'EUAI-MIN-001' || f.rule_id === 'EUAI-TRANS-001')) {
    plan.push({ type: 'update', file: manifestPath, desc: 'Add missing flags and root compliance structure' });
  }

  if (findings.some(f => f.rule_id === 'EUAI-OVER-002')) {
    plan.push({ type: 'update', file: manifestPath, desc: 'Add human_oversight configuration' });
    docsToCreate.push('docs/compliance/human_oversight.md');
  }

  if (findings.some(f => f.rule_id === 'EUAI-LOG-003')) {
    plan.push({ type: 'update', file: manifestPath, desc: 'Add logging_capabilities configuration' });
    docsToCreate.push('docs/compliance/data_governance.md');
  }

  if (manifest.risk_category === 'high') {
    docsToCreate.push('docs/compliance/risk_assessment.md');
  }

  const uniqueDocs = [...new Set(docsToCreate)];
  for (const doc of uniqueDocs) {
    const docPath = path.join(manifestDir, doc);
    if (fs.existsSync(docPath)) {
      plan.push({ type: 'skip', file: doc, desc: 'File already exists' });
    } else {
      plan.push({ type: 'create', file: doc, desc: 'Generate compliance starter template' });
    }
  }

  console.log(`\n${C.cyan}${C.bold}🛠  Sentinel Remediation Plan${C.reset}`);
  console.log(`${C.gray}Target manifest: ${C.white}${manifestPath}${C.reset}\n`);

  plan.forEach(step => {
    const icon = step.type === 'create' ? `${C.green} + ` : (step.type === 'update' ? `${C.yellow} ~ ` : `${C.gray} . `);
    const label = step.type === 'create' ? 'CREATE' : (step.type === 'update' ? 'UPDATE' : 'SKIP  ');
    console.log(`${icon}${C.bold}${label}${C.reset} ${C.white}${step.file}${C.reset} ${C.gray} (${step.desc})${C.reset}`);
  });

  if (!isApply) {
    console.log(`\n${C.yellow}Dry-run mode. No changes made.${C.reset}`);
    console.log(`Run with ${C.white}--apply${C.reset} to execute this plan.`);
    return;
  }

  // 5. Apply Plan
  console.log(`\n${C.cyan}${C.bold}🚀 Applying fixes...${C.reset}`);

  const patchedManifest = JSON.parse(JSON.stringify(manifest));
  const declaredFlags = patchedManifest.declared_flags || [];

  const requiredFlags = ['transparency_disclosure_provided', 'user_notification_ai_interaction'];
  requiredFlags.forEach(f => {
    if (!declaredFlags.includes(f)) declaredFlags.push(f);
  });
  patchedManifest.declared_flags = declaredFlags;

  if (findings.some(f => f.rule_id === 'EUAI-OVER-002')) {
    if (!patchedManifest.human_oversight) patchedManifest.human_oversight = { description: "Human reviewer monitors decisions and can override outputs." };
    if (!patchedManifest.oversight_evidence_path) patchedManifest.oversight_evidence_path = "docs/compliance/human_oversight.md";
  }

  if (findings.some(f => f.rule_id === 'EUAI-LOG-003')) {
    if (!patchedManifest.logging_capabilities) {
      patchedManifest.logging_capabilities = {
        enabled: true,
        events_logged: ["input", "output", "decision"]
      };
    }
    if (!patchedManifest.logging_evidence_path) patchedManifest.logging_evidence_path = "docs/compliance/data_governance.md";
  }

  fs.writeFileSync(manifestPath, JSON.stringify(patchedManifest, null, 2));
  console.log(`${C.green}✔ Updated ${manifestPath}${C.reset}`);

  uniqueDocs.forEach(doc => {
    const docPath = path.join(manifestDir, doc);
    if (fs.existsSync(docPath)) {
      console.log(`${C.gray}. Skipped ${doc} (exists)${C.reset}`);
    } else {
      const docDir = path.dirname(docPath);
      if (!fs.existsSync(docDir)) fs.mkdirSync(docDir, { recursive: true });

      let content = "";
      if (doc.includes('human_oversight')) {
        content = `# Human Oversight Protocol (Art. 14)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and legal review. This document does not imply final legal compliance.\n\n## Oversight Mechanism\nImplementation details pending...\n\n## Roles and Responsibilities\n- Reviewer: [Role Name]\n- Intervention Threshold: [Threshold Details]\n`;
      } else if (doc.includes('data_governance')) {
        content = `# Data Governance and Logging (Art. 20)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and legal review. This document does not imply final legal compliance.\n\n## Logging Capabilities\nImplementation details pending...\n\n## Retention Policy\nStored for [Duration] in [Location].\n`;
      } else if (doc.includes('risk_assessment')) {
        content = `# Risk Management System (Art. 9)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and legal review. This document does not imply final legal compliance.\n\n## Risk Identification\nImplementation details pending...\n\n## Mitigation Strategy\nDetails about bias assessment and testing protocols.\n`;
      }

      fs.writeFileSync(docPath, content);
      console.log(`${C.green}✔ Created ${doc}${C.reset}`);
    }
  });

  // 6. Audit Comparison
  console.log(`\n${C.cyan}${C.bold}📊 Verification Audit${C.reset}`);

  // Pre-fix Audit (Full)
  const oldOfflineResult = await runOffline(manifest);
  const oldEngineViolations = oldOfflineResult.violations || [];
  const oldEvidenceFindings = validateEvidence(manifest, manifestDir);
  const oldAllFindings = [...oldEvidenceFindings, ...oldEngineViolations];

  const oldScoreObj = computeEvidenceScore(oldEvidenceFindings, manifest);
  const oldScore = oldScoreObj.finalScore !== undefined ? oldScoreObj.finalScore : oldScoreObj;
  const oldVerdict = computeVerdict(oldScore, oldAllFindings, manifest);

  // Post-fix Audit (Full)
  const newOfflineResult = await runOffline(patchedManifest);
  const newEngineViolations = newOfflineResult.violations || [];
  const newEvidenceFindings = validateEvidence(patchedManifest, manifestDir);
  const newAllFindings = [...newEvidenceFindings, ...newEngineViolations];

  const newScoreObj = computeEvidenceScore(newEvidenceFindings, patchedManifest);
  const newScore = newScoreObj.finalScore !== undefined ? newScoreObj.finalScore : newScoreObj;
  const newVerdict = computeVerdict(newScore, newAllFindings, patchedManifest);

  console.log(`${C.gray}Previous Status: ${C.reset}${oldVerdict} (${oldScore}/100)`);
  const statusColor = newVerdict === 'COMPLIANT' ? C.green : (newVerdict === 'PARTIAL' ? C.yellow : C.red);
  console.log(`${C.gray}New Status:      ${C.reset}${C.bold}${statusColor}${newVerdict}${C.reset} (${C.bold}${newScore}/100${C.reset})`);
  console.log(`\n${C.green}${C.bold}✔ Structural compliance issues resolved.${C.reset}`);

  if (newEngineViolations.length > 0) {
    console.log(`\n${C.yellow}${C.bold}Remaining findings require human review:${C.reset}`);
    console.log(`${C.yellow}- governance${C.reset}`);
    console.log(`${C.yellow}- data quality${C.reset}`);
    console.log(`${C.yellow}- risk assessment${C.reset}`);
  }

  console.log(`\n${C.gray}Sentinel prepares your system for audit.${C.reset}`);
  console.log(`${C.gray}It does not replace legal validation.${C.reset}\n`);
}

/**
 * Initialize a new Sentinel project scaffolding.
 */
function runInit() {
  const hasManifestJson = fs.existsSync('manifest.json');
  const hasSentinelManifest = fs.existsSync('sentinel.manifest.json');

  if (hasManifestJson || hasSentinelManifest) {
    console.error(`\n${C.red}${C.bold}Error: Manifest already exists. Aborting to avoid overwrite.${C.reset}\n`);
    process.exit(1);
  }

  // 1. Create sentinel.manifest.json
  const minimalManifest = {
    app_name: "unnamed-ai-service",
    version: "1.0.0",
    risk_category: "high",
    declared_flags: []
  };

  fs.writeFileSync('sentinel.manifest.json', JSON.stringify(minimalManifest, null, 2));
  console.log(`${C.green}✔ Created sentinel.manifest.json${C.reset}`);

  // 2. Create docs/compliance directory
  const complianceDir = path.join(process.cwd(), 'docs/compliance');
  if (!fs.existsSync(complianceDir)) {
    fs.mkdirSync(complianceDir, { recursive: true });
    console.log(`${C.green}✔ Created docs/compliance/${C.reset}`);
  }

  // 3. Create starter templates
  const templates = [
    {
      file: 'human_oversight.md',
      content: `# Human Oversight Protocol (Art. 14)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and legal review. This document does not imply final legal compliance.\n\n## Oversight Mechanism\nImplementation details pending...\n\n## Roles and Responsibilities\n- Reviewer: [Role Name]\n- Intervention Threshold: [Threshold Details]\n`
    },
    {
      file: 'data_governance.md',
      content: `# Data Governance and Logging (Art. 20)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and legal review. This document does not imply final legal compliance.\n\n## Logging Capabilities\nImplementation details pending...\n\n## Retention Policy\nStored for [Duration] in [Location].\n`
    },
    {
      file: 'risk_assessment.md',
      content: `# Risk Management System (Art. 9)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and legal review. This document does not imply final legal compliance.\n\n## Risk Identification\nImplementation details pending...\n\n## Mitigation Strategy\nDetails about bias assessment and testing protocols.\n`
    }
  ];

  let createdCount = 0;
  let skippedCount = 0;
  const createdList = [];

  templates.forEach(t => {
    const targetPath = path.join(complianceDir, t.file);
    if (fs.existsSync(targetPath)) {
      skippedCount++;
    } else {
      fs.writeFileSync(targetPath, t.content);
      createdCount++;
      createdList.push(`docs/compliance/${t.file}`);
    }
  });

  if (createdCount > 0) {
    console.log(`${C.green}✔ Created ${createdCount} files:${C.reset}`);
    createdList.forEach(f => console.log(`  - ${f}`));
  }
  if (skippedCount > 0) {
    console.log(`${C.gray}. Skipped ${skippedCount} files (already exist)${C.reset}`);
  }

  console.log(`\n${C.bold}Next steps:${C.reset}`);
  console.log(`1. Run: ${C.cyan}npx @radu_api/sentinel-scan check --threshold 90 --manifest sentinel.manifest.json${C.reset}`);
  console.log(`2. Review findings`);
  console.log(`3. Run: ${C.cyan}npx @radu_api/sentinel-scan fix --apply --manifest sentinel.manifest.json${C.reset}\n`);
}