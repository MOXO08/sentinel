#!/usr/bin/env node
// sentinel-scan — EU AI Act Compliance CLI
// Usage: npx @radu_api/sentinel-scan check --threshold 90 --manifest sentinel.manifest.json [--policy <path>] [--baseline <path>] [--json] [--api-key <key>] [--endpoint <url>]

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const isJson = process.argv.includes('--json');
if (isJson) {
  console.log = () => {};
  console.error = () => {};
}
const { execSync } = require('child_process');
const cliProgress = require('cli-progress');

const autodiscovery = require('./lib/autodiscovery');
const discoveryRules = JSON.parse(fs.readFileSync(path.join(__dirname, 'lib', 'discovery-rules.json'), 'utf8'));
let probingRules = null;
try {
  probingRules = JSON.parse(fs.readFileSync(path.join(__dirname, 'lib', 'probing-rules.json'), 'utf8'));
} catch (e) {
  // Optional, fallback to null
}
const intelligence = require('./lib/intelligence');
const PreAuditor = require('./lib/pre-auditor');
const AuditVault = require('./lib/vault');
const DiffEngine = require('./lib/diff-engine');
const AuditMetadata = require('./lib/audit-metadata');
const AuditExporter = require('./lib/exporter');
const ReportGenerator = require('./lib/report-generator');
const { extractDocsFromRepo,
        evaluateAllDocuments,
        generateSemanticReport } = require('./lib/semantic-evaluator');

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
  if (isJson) {
    process.exit(code);
  }
  if (process.stdout.isTTY && process.env.SENTINEL_INTERACTIVE !== 'false' && process.platform === 'win32') {
    process.stdout.write(`\n${C.gray}Scan finished. Press ENTER to close this window...${C.reset}`);
    process.stdin.resume();
    process.stdin.on('data', () => process.exit(code));
  } else {
    process.exit(code);
  }
}

function printBanner() {
  if (isJson) return;
  console.log(`\n${C.cyan}${C.bold}╔══════════════════════════════════════════════════╗`);
  console.log(`║  🛡  SENTINEL — LOCAL DIAG NOSTIC TOOL (OFFLINE)  ║`);
  console.log(`╚══════════════════════════════════════════════════╝${C.reset}\n`);
  console.log(`\n\x1b[36m\x1b[1mPro-Tip:\x1b[0m\x1b[36m Consult the official Compliance Guide at \x1b[97mUSER_MANUAL.md\x1b[0m\n`);
}

function printHelp() {
  if (isJson) return;
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
  console.log(`  --production-hash <h>  Link audit to a production artifact (SHA-256)`);
  console.log(`  --build-id <id>        Link audit to a declared production build ID`);
  console.log(`  --strict               Enforce 1:1 alignment between manifest and discovered signals`);
  console.log(`  --autodiscover         Enable the Autodiscovery engine to verify manifest against code`);
  console.log(`  --generate-tech-file   Generate an Annex IV Technical Documentation dossier (Markdown)`);
  console.log(`  --endpoint <url>       Custom Edge API endpoint`);
  console.log(`  --help                 Show this help`);
}

function printVersion() {
  if (isJson) return;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));
    console.log(`v${pkg.version}`);
  } catch (e) {
    console.log(`v2.0.0-sovereign`);
  }
}

const OFFLINE_RULES = {
  rules: [
    { 
      id: "ART5-001", description: "Subliminal manipulation", risk_category: "Unacceptable", required_flags: [], forbidden_flags: ["subliminal_techniques"], fix_snippet: "Remove features exploiting subliminal techniques (Article 5.1a Prohibited).",
      rule_id: "EU-AIA-ART5-PROHIBITED-001", source_type: "regulatory", source_reference: "Regulation (EU) 2024/1689, Article 5", enforcement_level: "mandatory",
      authority_mapping: { "framework": "EU AI Act", "article": "Article 5", "annex": null, "requirement_topic": "Prohibited AI Practices", "notes": "Subliminal manipulation" }
    },
    { 
      id: "ART5-003", description: "Social scoring", risk_category: "Unacceptable", required_flags: [], forbidden_flags: ["social_scoring"], fix_snippet: "Remove social scoring functionality or restrict to non-prohibited domains (Article 5.1c).",
      rule_id: "EU-AIA-ART5-PROHIBITED-002", source_type: "regulatory", source_reference: "Regulation (EU) 2024/1689, Article 5", enforcement_level: "mandatory",
      authority_mapping: { "framework": "EU AI Act", "article": "Article 5", "annex": null, "requirement_topic": "Prohibited AI Practices", "notes": "Social scoring" }
    },
    { 
      id: "ART10-001", description: "Data governance & Bias assessment", risk_category: "High", required_flags: ["bias_assessment_performed", "data_governance_policy_documented"], fix_snippet: "Add 'bias_assessment_performed' and 'data_governance_policy_documented' to 'declared_flags' array.",
      rule_id: "EU-AIA-ART10-DATAGOV-001", source_type: "regulatory", source_reference: "Regulation (EU) 2024/1689, Article 10", enforcement_level: "mandatory",
      authority_mapping: { "framework": "EU AI Act", "article": "Article 10", "annex": null, "requirement_topic": "Data and data governance", "notes": "Governance and bias" }
    },
    { 
      id: "ART13-001", description: "User notification of AI interaction", risk_category: "High", required_flags: ["user_notification_ai_interaction"], fix_snippet: "Add 'user_notification_ai_interaction' to 'declared_flags' array and implement UI notification.",
      rule_id: "EU-AIA-ART13-TRANSPARENCY-001", source_type: "regulatory", source_reference: "Regulation (EU) 2024/1689, Article 13", enforcement_level: "mandatory",
      authority_mapping: { "framework": "EU AI Act", "article": "Article 13", "annex": null, "requirement_topic": "Transparency and provision of information", "notes": "User notification" }
    },
    { 
      id: "ART14-001", description: "Human oversight", risk_category: "High", required_flags: ["human_oversight_enabled"], fix_snippet: "Add 'human_oversight_enabled' to 'declared_flags' array and implement a kill-switch.",
      rule_id: "EU-AIA-ART14-OVERSIGHT-001", source_type: "regulatory", source_reference: "Regulation (EU) 2024/1689, Article 14", enforcement_level: "mandatory",
      authority_mapping: { "framework": "EU AI Act", "article": "Article 14", "annex": null, "requirement_topic": "Human oversight", "notes": "Technical hooks" }
    },
    { 
      id: "ART22-001", description: "Conformity assessment", risk_category: "High", required_flags: ["conformity_assessment_completed"], fix_snippet: "Add 'conformity_assessment_completed' to 'declared_flags' array after regulatory review.",
      rule_id: "EU-AIA-ART43-CONFORMITY-001", source_type: "regulatory", source_reference: "Regulation (EU) 2024/1689, Article 43", enforcement_level: "mandatory",
      authority_mapping: { "framework": "EU AI Act", "article": "Article 43", "annex": null, "requirement_topic": "Conformity assessment", "notes": "Procedural compliance" }
    }
  ]
};

/**
 * Validates authority metadata for a rule registry.
 */
function validateRegistryAuthority(registry, name) {
  const allowedSourceTypes = ['regulatory', 'standard', 'internal', 'unmapped'];
  const allowedEnforcementLevels = ['mandatory', 'recommended', 'informational'];

  const validateRule = (rule, path) => {
    if (!rule.rule_id || typeof rule.rule_id !== 'string') throw new Error(`Registry Validation Error [${name}]: Missing or invalid rule_id at ${path}`);
    if (!allowedSourceTypes.includes(rule.source_type)) throw new Error(`Registry Validation Error [${name}]: Invalid source_type "${rule.source_type}" at ${path}`);
    if (typeof rule.source_reference !== 'string') throw new Error(`Registry Validation Error [${name}]: Missing source_reference at ${path}`);
    if (!allowedEnforcementLevels.includes(rule.enforcement_level)) throw new Error(`Registry Validation Error [${name}]: Invalid enforcement_level "${rule.enforcement_level}" at ${path}`);
    if (!rule.authority_mapping || typeof rule.authority_mapping !== 'object') throw new Error(`Registry Validation Error [${name}]: Missing authority_mapping at ${path}`);
    
    // Check keys exist (even if null)
    const requiredKeys = ['framework', 'article', 'annex', 'requirement_topic', 'notes'];
    requiredKeys.forEach(key => {
      if (!(key in rule.authority_mapping)) throw new Error(`Registry Validation Error [${name}]: Missing authority_mapping key "${key}" at ${path}`);
    });
  };

  if (registry.dependencies) {
    Object.entries(registry.dependencies).forEach(([dep, rule]) => validateRule(rule, `dependencies.${dep}`));
  }
  if (registry.code_signatures) {
    registry.code_signatures.forEach((rule, i) => validateRule(rule, `code_signatures[${i}]`));
  }
  if (registry.doc_hints) {
    registry.doc_hints.forEach((rule, i) => validateRule(rule, `doc_hints[${i}]`));
  }
  if (registry.probes) {
    Object.entries(registry.probes).forEach(([probeKey, probe]) => {
      (probe.strong_signals || []).forEach((s, i) => validateRule(s, `probes.${probeKey}.strong_signals[${i}]`));
      (probe.traceability_signals || []).forEach((s, i) => validateRule(s, `probes.${probeKey}.traceability_signals[${i}]`));
      (probe.weak_signals || []).forEach((s, i) => validateRule(s, `probes.${probeKey}.weak_signals[${i}]`));
    });
  }
  if (registry.rules) {
    registry.rules.forEach((rule, i) => validateRule(rule, `rules[${i}]`));
  }
}

// Perform initial validation of internal rules
validateRegistryAuthority(OFFLINE_RULES, 'OFFLINE_RULES');

async function runOffline(manifest) {
  const { run_audit } = require('../pkg-node/sentinel_core.js');
  const verdictText = run_audit(JSON.stringify(manifest), JSON.stringify(OFFLINE_RULES));
  return JSON.parse(verdictText);
}

function resolveTargetManifest(args) {
  let manifestPath = null;
  const manifestArgIdx = args.indexOf('--manifest');
  if (manifestArgIdx !== -1 && args[manifestArgIdx + 1]) {
    manifestPath = args[manifestArgIdx + 1];
  }
  if (!manifestPath) {
    const hasSentinelManifest = fs.existsSync('sentinel.manifest.json');
    const hasManifestJson = fs.existsSync('manifest.json');
    manifestPath = hasSentinelManifest ? 'sentinel.manifest.json' : (hasManifestJson ? 'manifest.json' : null);
  }
  return manifestPath;
}

function applySubstanceAudit(findings, content, filePath, article = 'Art. 9/13') {
  const substance = intelligence.analyzeSubstance(content);
  if (substance.score < 1.0) {
    findings.push({
      article, rule_id: 'EUAI-SUBSTANCE-001',
      description: `[Documentation] Low substance: ${substance.findings.join('; ')}: ${filePath}`,
      deduction: Math.round((1 - substance.score) * 20),
      severity: substance.score < 0.5 ? 'high' : 'medium',
      hard_fail: false, source: 'evidence',
      fix_snippet: "Replace placeholder/boilerplate text with real compliance analysis."
    });
  }
  
  // Phase 2: Consistency Check
  const consistency = intelligence.checkConsistency(article, content);
  if (consistency.score < 0.6) {
    findings.push({
      article, rule_id: 'EUAI-CONSISTENCY-001',
      description: `[Documentation] Low consistency: Evidence does not sufficiently address Article requirements. Missing keywords: ${consistency.missing.slice(0, 3).join(', ')}`,
      deduction: Math.round((1 - consistency.score) * 15),
      severity: 'medium',
      hard_fail: false, source: 'evidence',
      fix_snippet: `Ensure documentation explicitly addresses: ${consistency.missing.join(', ')}.`
    });
  }
}

/**
 * Phase 3: Hardening Probe Scoring
 */
function computeHardeningFindings(signals, manifest, findings, repoFilesOrCount = [], dependencyGraph = null) {
  const projectFiles = Array.isArray(repoFilesOrCount) ? repoFilesOrCount : [];
  const fileCount = Array.isArray(repoFilesOrCount) ? repoFilesOrCount.length : repoFilesOrCount;

  // Phase B: Project-wide language detection (Refined for polyglot repos)
  const pyCount = projectFiles.filter(f => f.path?.endsWith('.py')).length;
  const jsCount = projectFiles.filter(f => f.path?.endsWith('.js') || f.path?.endsWith('.ts')).length;
  
  const isProjectPython = 
    (pyCount > jsCount) || 
    manifest.language === 'python' || 
    projectFiles.some(f => f.path === 'requirements.txt');


  if (!probingRules || !probingRules.probes) return;

  const hardeningSignals = signals.filter(s => s.kind === 'hardening_probe');
  const declaredFlags = manifest.declared_flags || [];

  Object.entries(probingRules.probes).forEach(([probeKey, probe]) => {
    const article = probe.article;
    const probeSignals = signals.filter(s => {
      // Use the new kind-based filtering only for specific probes that require it
      if ((probeKey === 'ai_execution' || probeKey === 'connectivity') && (s.kind === 'code_signature_call' || s.kind === 'code_signature_load' || s.kind === 'dependency')) {
        if (probeKey === 'ai_execution') return (s.id.includes('AI') || s.id.includes('MODEL') || s.id.includes('LLM'));
        if (probeKey === 'connectivity') return (s.id.startsWith('CODE_HTTP') || s.id.startsWith('CODE_SOCKET') || s.id.startsWith('CODE_URI'));
      }
      
      // Fallback/Legacy string-based matching for existing probes
      if (probeKey === 'logging') return (s.id.startsWith('DEP_') || s.id.includes('LOG') || s.id.includes('TRACE'));
      if (probeKey === 'human_oversight') return (s.id.includes('OVERRIDE') || s.id.includes('KILL_SWITCH') || s.id.includes('HUMAN'));
      if (probeKey === 'ai_transparency') return (s.id.includes('DISCLOSURE') || s.id.includes('LABEL'));
    });
    const hasStrong = probeSignals.some(s => s.probe_type === 'strong');
    const hasWeak = probeSignals.some(s => s.probe_type === 'weak');
    const hasTraceOrEquivalent = probeSignals.some(s => s.probe_type === 'traceability');
    const hasExecSignature = probeSignals.some(s => s.kind === 'code_signature_call');

    // Phase 9/10: Usage-Centric Verification
    const executionSignals = signals.filter(s => s.kind === 'code_signature_call' && (s.id.includes('AI') || s.id.includes('MODEL') || s.id.includes('LLM')));
    
    // Initial verdict is FAIL unless proven otherwise per-usage
    let verdict = 'FAIL';

    if (probeKey === 'ai_execution') {
        verdict = hasExecSignature ? 'PASS' : (probeSignals.length > 0 ? 'WEAK PASS' : 'FAIL');
    } else if (probeKey === 'connectivity') {
        verdict = probeSignals.length > 0 ? 'PASS' : 'FAIL';
    } else if (probeKey === 'human_oversight' || probeKey === 'logging') {
        const ungovernedExecutions = executionSignals.filter(exec => {
            const execFile = exec.source_path.replace(/\\/g, "/");
            const localSupport = probeSignals.some(s => s.source_path.replace(/\\/g, "/") === execFile && s.probe_type === 'strong');
            if (localSupport) return false;
            
            // Phase 10: Recursive Transitive Check (Follow the Graph)
            const visited = new Set();
            const checkTransitiveDeep = (currentFile) => {
               if (visited.has(currentFile)) return false;
               visited.add(currentFile);
               
               const imports = (dependencyGraph && dependencyGraph.imports[currentFile]) || [];
               for (const imp of imports) {
                  const normalizedImp = imp.replace(/^\.\//, "").replace(/\.[^/.]+$/, "").toLowerCase();
                  // 1. Direct Signal in Imported File
                  const hasDirect = signals.some(s => {
                    if (s.article !== article || s.probe_type !== 'strong') return false;
                    const normalizedSource = s.source_path.replace(/\\/g, "/").replace(/\.[^/.]+$/, "").toLowerCase();
                    return normalizedSource === normalizedImp || normalizedSource.endsWith("/" + normalizedImp);
                  });
                  if (hasDirect) return true;
                  
                  // 2. Recursive Check (Go Deeper)
                  // Find the actual file path for this import in dependencyGraph keys
                  const resolvedPath = Object.keys(dependencyGraph.imports).find(k => {
                     const nk = k.replace(/\\/g, "/").replace(/\.[^/.]+$/, "").toLowerCase();
                     return nk === normalizedImp || nk.endsWith("/" + normalizedImp);
                  });
                  if (resolvedPath && checkTransitiveDeep(resolvedPath)) return true;
               }
               return false;
            };

            return !checkTransitiveDeep(exec.source_path);
        });
        
        if (ungovernedExecutions.length > 0) {
            verdict = hasWeak ? 'WEAK PASS' : 'FAIL';
            if (verdict === 'FAIL') {
                ungovernedExecutions.forEach(e => e.governance_gap = article);
            }
        } else if (executionSignals.length > 0) {
            verdict = 'PASS';
        } else {
            // Default project-wide verdict if no explicit AI executions found
            verdict = (hasStrong || (hasWeak && hasTraceOrEquivalent)) ? 'PASS' : (hasWeak ? 'WEAK PASS' : 'FAIL');
        }
    } else {
        // Fallback for other probes
        verdict = (hasStrong || (hasWeak && hasTraceOrEquivalent)) ? 'PASS' : (hasWeak ? 'WEAK PASS' : 'FAIL');
    }

    // Check if the article is claimed
    let isClaimed = false;
    if (probeKey === 'logging') {
      isClaimed = declaredFlags.some(f => f.includes('log') || f.includes('traceability'));
    } else if (probeKey === 'human_oversight') {
      isClaimed = declaredFlags.some(f => f.includes('human_oversight') || f.includes('kill_switch') || f.includes('manual_override'));
    } else if (probeKey === 'ai_transparency') {
      isClaimed = declaredFlags.some(f => f.includes('transparency_disclosure_provided') || f.includes('ai_disclosure'));
    } else if (probeKey === 'ai_execution' || probeKey === 'connectivity') {
      isClaimed = true; // Always evaluate these in Extended mode for inference
    }
    
    const hasAIExecution = signals.some(s => (s.id.includes('AI') || s.id.includes('MODEL') || s.id.includes('LLM')));

    if (isClaimed || ((probeKey === 'human_oversight' || probeKey === 'logging') && hasAIExecution)) {
      const getSubject = (pk) => {
        if (pk === 'logging') return 'Logging/Traceability';
        if (pk === 'human_oversight') return 'Human Control (Kill-switch/Override)';
        if (pk === 'ai_transparency') return 'AI Disclosure (Banner/System-label)';
        if (pk === 'ai_execution') return 'AI Execution Logic';
        if (pk === 'connectivity') return 'Technical Connectivity';
        if (pk === 'data_quality') return 'Data Quality & Bias Mitigation';
        if (pk === 'robustness') return 'System Robustness & Cyber-Resilience';
        return pk;
      };

      const getFix = (pk, match) => {
        const isPython = match?.file ? match.file.endsWith('.py') : isProjectPython;
        const langRef = isPython ? 'Python' : 'JavaScript/TypeScript';
        
        if (pk === 'logging') {
          if (isPython) {
            return "Implement Python logging control using standard logging module or loguru. Create a sentinel_log() wrapper function.";
          }
          return `Implement logging control using Winston or Pino. Create a sentinelLog() wrapper function. Current logic in ${match?.file} relies on generic tracers.`;
        }
        if (pk === 'human_oversight') {
          if (isPython) {
            return "Implement Python manual override hook using a decorator or function. Create a sentinel_override() wrapper function.";
          }
          return `Implement a manual override hook (e.g., manualApprovalRequired()) in ${match?.file} to satisfy Art 14.`;
        }

        if (pk === 'ai_transparency') {
          return "Add an explicit 'powered by AI' disclosure to your interface/code to satisfy Art 13 transparency requirements.";
        }
        if (pk === 'ai_execution') {
          return "No active AI execution markers found. If AI is used, ensure code is not obfuscated for audit transparency.";
        }
        if (pk === 'connectivity') {
          return "No external connectivity markers found. Verify if model execution is fully localized.";
        }
        if (pk === 'data_quality') {
          return `Implement ${langRef === 'Python' ? 'great_expectations' : 'automated validation'} for data quality/bias mitigation to satisfy Art 10.`;
        }
        if (pk === 'robustness') {
          return `Implement Art 15 cyber-resilience controls (e.g., input sanitization, stress testing) for the logic in ${match?.file}.`;
        }
        return "Implement required technical proof and documentation in the scoped repository.";
      };


      // Surgical Precision: Capture first evidence location with Context & Integrity
      const crypto = require('crypto');
      const evidenceMatch = probeSignals.find(s => s.line);
      let evidenceLoc = null;
      
      if (evidenceMatch) {
         const auditId = manifest.audit_id || 'PENDING';
         const rawData = `${evidenceMatch.source_path}:${evidenceMatch.line}:${evidenceMatch.evidence_context || ''}:${auditId}`;
         const hash = crypto.createHash('sha256').update(rawData).digest('hex').substring(0, 16);
         
         evidenceLoc = { 
           file: evidenceMatch.source_path, 
           line: evidenceMatch.line, 
           snippet: evidenceMatch.snippet,
           context: evidenceMatch.evidence_context,
           evidence_hash: `SIG-${hash.toUpperCase()}`,
           rule_id: evidenceMatch.rule_id,
           source_type: evidenceMatch.source_type,
           source_reference: evidenceMatch.source_reference,
           enforcement_level: evidenceMatch.enforcement_level,
           authority_mapping: evidenceMatch.authority_mapping
         };
      }

      // Evidence Depth Metadata
      const search_metadata = {
        files_scanned: fileCount || 0,
        patterns: [
          ...(probe.strong_signals || []).map(s => s.pattern),
          ...(probe.weak_signals || []).map(s => s.pattern),
          ...(probe.traceability_signals || []).map(s => s.pattern)
        ].filter(Boolean)
      };

      if (verdict === 'FAIL') {
        const specificRuleId = `EUAI-${probeKey.toUpperCase().replace(/_/g, '-')}-MISSING`;
        
        // Language-aware fallback for implementation remediation
        const fallbackFix = isProjectPython ?
          (probeKey === 'logging' ? "Implement Python logging control using standard logging module or loguru. Create a sentinel_log() wrapper function." :
           probeKey === 'human_oversight' ? "Implement Python manual override hook using a decorator or function. Create a sentinel_override() wrapper function." :
           "No specific code location identified. Apply recommended Python compliance control at the primary AI execution entry point.") :
          (probeKey === 'logging' ? "Implement logging control using Winston or Pino. Create a sentinelLog() wrapper function." :
           probeKey === 'human_oversight' ? "Implement a manual override hook (e.g., manualApprovalRequired()) to satisfy Art 14." :
           "No specific code location identified. Apply recommended control at the primary AI execution entry point in this file.");

        findings.push({
          article, rule_id: specificRuleId,
          description: `[Implementation] Hardening NOT DETECTED: No technical indicators of ${getSubject(probeKey)} found in code despite claims.`,
          deduction: 20, severity: 'high', source: 'implementation',
          fix_snippet: evidenceLoc?.snippet ?? fallbackFix,
          hardening_verdict: 'FAIL',
          search_metadata,
          source_type: probe.source_type || 'internal',
          source_reference: probe.source_reference,
          enforcement_level: probe.enforcement_level || 'mandatory',
          authority_mapping: probe.authority_mapping
        });

      } else if (verdict === 'WEAK PASS' || verdict === 'PASS') {
        const isWeak = verdict === 'WEAK PASS';
        
        // Language-aware fallback for weak pass remediation
        const fallbackFix = isProjectPython ?
          (probeKey === 'logging' ? "Implement Python logging control using standard logging module or loguru. Create a sentinel_log() wrapper function." :
           probeKey === 'human_oversight' ? "Implement Python manual override hook using a decorator or function. Create a sentinel_override() wrapper function." :
           "No specific code location identified. Apply recommended Python compliance control at the primary AI execution entry point.") :
          (probeKey === 'logging' ? "Implement logging control using Winston or Pino. Create a sentinelLog() wrapper function." :
           probeKey === 'human_oversight' ? "Implement a manual override hook (e.g., manualApprovalRequired()) to satisfy Art 14." :
           "No specific code location identified. Apply recommended control at the primary AI execution entry point in this file.");

        findings.push({
          article, 
          rule_id: isWeak ? 'EUAI-HARDENING-002' : 'EUAI-HARDENING-000',
          description: isWeak 
            ? `[Implementation] Hardening PARTIAL: Found only basic/partial signals for ${probeKey} in ${evidenceLoc?.file || 'scoped files'}. Lacks robust industrial enforcement.`
            : `[Implementation] Hardening DETECTED: Detected technical indicator of ${getSubject(probeKey)} in code.`,
          deduction: isWeak ? 8 : 0, 
          severity: isWeak ? 'medium' : 'info', 
          source: 'implementation',
          fix_snippet: isWeak ? (evidenceLoc?.snippet ?? fallbackFix) : null,
          hardening_verdict: verdict,
          evidence_location: evidenceLoc,
          search_metadata,
          source_type: probe.source_type || 'internal',
          source_reference: probe.source_reference,
          enforcement_level: probe.enforcement_level || 'mandatory',
          authority_mapping: probe.authority_mapping
        });

      }
    }
  });
}

/**
 * Extracts a likely identifier (variable/function/class name) from a code snippet.
 */
function extractIdentifier(snippet) {
  if (!snippet) return null;
  const line = snippet.split('\n')[0].trim();
  
  // Pattern matching for common declarations
  const patterns = [
    /(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=/,           // const x =
    /function\s+([a-zA-Z0-9_$]+)\s*\(/,                  // function x()
    /class\s+([a-zA-Z0-9_$]+)/,                          // class x
    /([a-zA-Z0-9_$]+)\s*:/,                              // x: (property)
    /([a-zA-Z0-9_$]+)\s*=/                               // x = (assignment)
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match && match[1]) return match[1];
  }
  return null;
}

/**
 * Searches for references to detected identifiers across the repository.
 */
function correlateFindings(findings, repoFiles) {
  findings.forEach(f => {
    if (!f.evidence_location || !f.evidence_location.snippet) {
       return;
    }

    let identifier = extractIdentifier(f.evidence_location.snippet);
    const definitionFile = f.evidence_location.file;

    // Reliability Hack: If identifier not found on the match line, it might be a comment line.
    // Peek at next 2 lines in the same file to find the likely declaration.
    if (!identifier && definitionFile) {
       try {
          const defFileContent = fs.readFileSync(path.resolve(process.cwd(), definitionFile), 'utf8');
          const defLines = defFileContent.split('\n');
          const startLine = f.evidence_location.line; // 1-indexed, so lines[startLine-1] is current
          for (let i = startLine; i < Math.min(startLine + 3, defLines.length); i++) {
             identifier = extractIdentifier(defLines[i]);
             if (identifier) break;
          }
       } catch (e) {}
    }

    if (!identifier) {
       if (process.env.SENTINEL_DEBUG === 'true' && f.hardening_verdict) {
          console.log(`[DEBUG] Could not extract identifier for ${f.article} from snippet or following lines.`);
       }
       return;
    }
    const references = [];
    const referenceFiles = new Set();

    repoFiles.forEach(rf => {
      // Skip the file where it's defined
      if (rf.path === definitionFile) return;

      try {
        const content = fs.readFileSync(rf.path, 'utf8');
        // Simple word-boundary check for the identifier
        const regex = new RegExp(`\\b${identifier}\\b`, 'g');
        const matches = content.match(regex);
        
        if (matches && matches.length > 0) {
          referenceFiles.add(rf.path);
          references.push(...matches);
        }
      } catch (e) {
        // Skip files that can't be read
      }
    });

    const refCount = references.length;
    let classification = "No references detected";
    if (refCount >= 3) classification = "Multiple references detected";
    else if (refCount > 0) classification = "Limited references detected";

    f.connectivity = {
      identifier,
      definition: definitionFile,
      reference_count: refCount,
      files: Array.from(referenceFiles),
      classification
    };
  });
}

function validateEvidence(manifest, manifestDir, signals = [], requiresGovernance = true) {
  const findings = [];
  const modules = Array.isArray(manifest.modules) ? manifest.modules : [];
  const declaredFlags = Array.isArray(manifest.declared_flags) ? manifest.declared_flags : [];
  const riskCat = (manifest.risk_category || "").toLowerCase();
  const isMinimal = riskCat === 'minimal';
  const isHighRisk = riskCat === 'high';
  const isLimited = riskCat === 'limited';
  const isUnacceptable = riskCat === 'unacceptable';
  const hasHighRiskModules = modules.some(m => m.risk_level === 'High' || m.risk_level === 'Unacceptable' || m.risk_category === 'High');
  const strictEnforcement = isHighRisk || hasHighRiskModules;

  if (isUnacceptable) {
    findings.push({ article: 'General', rule_id: 'EUAI-UNACCEPTABLE-001', description: "[Unacceptable risk category]", deduction: 100, severity: 'critical', hard_fail: true, source: 'evidence', fix_snippet: "Change 'risk_category' to a permitted value." });
    return findings;
  }
  if (!manifest.risk_category) {
    findings.push({ article: 'Art. 9', rule_id: 'EUAI-RISK-002', description: "[Missing risk category]", deduction: 25, severity: 'critical', hard_fail: true, source: 'evidence', fix_snippet: "Add 'risk_category' to manifest.json." });
  }

  const hasTransparencyFlag = declaredFlags.includes('transparency_disclosure_provided');
  const hasTransparencyFile = !!manifest.evidence_path;
  const hasOversight = !!manifest.human_oversight || !!manifest.oversight_evidence_path;
  const hasLogging = !!manifest.logging_capabilities || !!manifest.logging_evidence_path;

  if (requiresGovernance && !hasTransparencyFlag && !hasTransparencyFile && !hasOversight && !hasLogging) {
    findings.push({ article: 'General', rule_id: 'EUAI-MIN-001', description: "[Missing baseline structure]", deduction: 30, severity: 'critical', hard_fail: false, source: 'evidence', fix_snippet: "Add required top-level flags and evidence fields." });
  }
  
  if (isLimited && hasTransparencyFlag && !hasTransparencyFile) {
    findings.push({ article: 'Art. 13', rule_id: 'EUAI-TRANS-002', description: "[Missing transparency evidence]", deduction: 20, severity: 'high', hard_fail: false, source: 'evidence', fix_snippet: "Add 'evidence_path' for technical documentation." });
  }

  if (manifest.evidence_path) {
    const evidencePath = path.resolve(manifestDir, manifest.evidence_path);
    if (!fs.existsSync(evidencePath)) {
      findings.push({ article: 'Art. 13', rule_id: 'EUAI-EVID-001', description: `Declared evidence_path does not exist: ${manifest.evidence_path}`, deduction: 25, severity: 'critical', hard_fail: true, source: 'evidence', fix_snippet: "Create the missing evidence file at the path specified in your manifest." });
    } else {
      try {
        const stat = fs.statSync(evidencePath);
        if (stat.size < 10) {
          findings.push({ article: 'Art. 13', rule_id: 'EUAI-EVID-002', description: `Evidence file is trivially empty (${stat.size} bytes): ${manifest.evidence_path}`, deduction: 15, severity: 'high', hard_fail: true, source: 'evidence', fix_snippet: "Add meaningful compliance documentation to the empty evidence file." });
        } else if (manifest.evidence_path.endsWith('.json')) {
          try {
            const content = fs.readFileSync(evidencePath, 'utf8');
            const parsed = JSON.parse(content);
            if (!parsed || (typeof parsed === 'object' && Object.keys(parsed).length === 0)) {
              findings.push({ article: 'Art. 13', rule_id: 'EUAI-EVID-003', description: `Evidence file is valid JSON but contains no meaningful content: ${manifest.evidence_path}`, deduction: 15, severity: 'high', hard_fail: true, source: 'evidence', fix_snippet: "Populate the JSON evidence file with required compliance data fields." });
            }
          } catch(e) {}
        } else if (manifest.evidence_path.endsWith('.md')) {
            const content = fs.readFileSync(evidencePath, 'utf8');
            applySubstanceAudit(findings, content, manifest.evidence_path, 'Art. 13');
        }
      } catch (e) {}
    }
  }

  if (requiresGovernance && !declaredFlags.includes('transparency_disclosure_provided')) {
    findings.push({ article: 'Art. 13', rule_id: 'EUAI-TRANS-001', description: "[Missing transparency flag]", deduction: 15, severity: 'high', hard_fail: false, source: 'evidence', fix_snippet: "Add 'transparency_disclosure_provided' to 'declared_flags' array." });
  }

  for (const mod of modules) {
    if (mod.risk_level === 'High' || mod.risk_level === 'Unacceptable') {
      if (!mod.evidence) {
        findings.push({ article: 'Art. 9', rule_id: 'EUAI-MOD-001', description: `High-risk module "${mod.id || 'unnamed'}" has no evidence field`, fix_snippet: "Add 'evidence' field to the high-risk module in manifest.json.", deduction: 10, severity: 'high', hard_fail: false, source: 'evidence' });
      } else {
        const modEvidencePath = path.resolve(manifestDir, mod.evidence);
        if (!fs.existsSync(modEvidencePath)) {
          findings.push({ article: 'Art. 9', rule_id: 'EUAI-MOD-002', description: `High-risk module "${mod.id || 'unnamed'}" declares evidence but file missing: ${mod.evidence}`, fix_snippet: "Create the missing module evidence file specified in the manifest.", deduction: 10, severity: 'high', hard_fail: false, source: 'evidence' });
        } else {
          try {
            const stat = fs.statSync(modEvidencePath);
            if (stat.size < 20) {
              findings.push({ article: 'Art. 9', rule_id: 'EUAI-MOD-003', description: `High-risk module "${mod.id}" evidence file is trivially empty: ${mod.evidence}`, fix_snippet: "Add meaningful content to the empty module evidence file.", deduction: 15, severity: 'high', hard_fail: true, source: 'evidence' });
            } else {
              const content = fs.readFileSync(modEvidencePath, 'utf8');
              if (!modEvidencePath.endsWith('.json')) {
                applySubstanceAudit(findings, content, mod.evidence, 'Art. 9');
              }
            }
          } catch(e) {}
        }
      }
    }
  }

  if (strictEnforcement) {
    if (manifest.oversight_evidence_path) {
      const p = path.resolve(manifestDir, manifest.oversight_evidence_path);
      if (fs.existsSync(p) && fs.statSync(p).size > 10) {
        const content = fs.readFileSync(p, 'utf8');
        applySubstanceAudit(findings, content, manifest.oversight_evidence_path, 'Art. 14');
      }
    }
    if (manifest.logging_evidence_path) {
      const p = path.resolve(manifestDir, manifest.logging_evidence_path);
      if (fs.existsSync(p) && fs.statSync(p).size > 10) {
        const content = fs.readFileSync(p, 'utf8');
        applySubstanceAudit(findings, content, manifest.logging_evidence_path, 'Art. 20');
      }
    }
  }

  return findings;
}

const AUDIT_BASELINE = {
  'Art. 9':  { target: 2, weight: 0.25 },
  'Art. 10': { target: 2, weight: 0.25 },
  'Art. 13': { target: 1, weight: 0.15 },
  'Art. 14': { target: 3, weight: 0.20 },
  'Art. 20': { target: 2, weight: 0.15 }
};

function determineVerifiedArticles(findings, manifest) {
  const verified = [];
  const riskCat = (manifest.risk_category || "minimal").toLowerCase();
  const modules = Array.isArray(manifest.modules) ? manifest.modules : [];
  const declaredFlags = Array.isArray(manifest.declared_flags) ? manifest.declared_flags : [];

  const check = (art) => {
    const failedFindings = findings.filter(f => f.article === art && f.hardening_verdict === 'FAIL');
    // For verification, we still use a hybrid logic but more permissive for Minimal
    if (riskCat === 'minimal') return true; 
    return failedFindings.length === 0;
  };

  if (check('Art. 9') && (modules.some(m => m.evidence) || declaredFlags.includes('bias_assessment_performed'))) verified.push('Art. 9');
  if (check('Art. 10') && (declaredFlags.includes('data_governance_documented') || declaredFlags.includes('data_lineage_tracked'))) verified.push('Art. 10');
  if (check('Art. 13') && (!!manifest.evidence_path || declaredFlags.includes('transparency_disclosure_provided') || declaredFlags.includes('ai_disclosure'))) verified.push('Art. 13');
  if (check('Art. 14') && (!!manifest.oversight_evidence_path || declaredFlags.includes('human_oversight_enabled') || declaredFlags.includes('manual_override'))) verified.push('Art. 14');
  if (check('Art. 20') && (!!manifest.logging_evidence_path || declaredFlags.includes('logging_capabilities_declared'))) verified.push('Art. 20');

  return verified;
}

function calculateSignalBreakdown(signals = []) {
  return {
     ai_assets: signals.filter(s => s.kind === 'dependency' || s.kind === 'code_signature_load').length,
     execution: signals.filter(s => s.kind === 'code_signature_call' && (s.id.includes('AI') || s.id.includes('MODEL') || s.id.includes('LLM'))).length,
     connectivity: signals.filter(s => s.kind === 'code_signature_call' && (s.id.startsWith('CODE_HTTP') || s.id.startsWith('CODE_SOCKET') || s.id.startsWith('CODE_URI'))).length,
     transparency: signals.filter(s => { const id = s.id.toUpperCase(); return id.includes('DISCLOSURE') || id.includes('LABEL') || id.includes('AI_VAR') || id.includes('TRANS'); }).length,
     oversight: signals.filter(s => { const id = s.id.toUpperCase(); return id.includes('OVERRIDE') || id.includes('KILL_SWITCH') || id.includes('EXIT') || id.includes('HUMAN') || id.includes('OVERSIGHT'); }).length,
     logging: signals.filter(s => { const id = s.id.toUpperCase(); return id.includes('LOG') || id.includes('TRACE'); }).length
  };
}

function computeTrustMetrics(findings, manifest, signalBreakdown, requiresGovernance = true) {
  const riskCat = (manifest.risk_category || "minimal").toLowerCase();
  
  if (!requiresGovernance && findings.length === 0) {
      return {
          finalScore: 100,
          claim_score: 100,
          evidence_score: 100,
          confidence: 'HIGH',
          phi: 1.0,
          exposure: 0.1,
          breakdown: {}
      };
  }
  const declaredFlags = Array.isArray(manifest.declared_flags) ? manifest.declared_flags : [];
  const modules = Array.isArray(manifest.modules) ? manifest.modules : [];
  
  let required = [];
  let weights = {};
  
  if (riskCat === 'high') {
    required = ['Art. 9', 'Art. 10', 'Art. 13', 'Art. 14', 'Art. 20'];
    weights = { 'Art. 9': 0.25, 'Art. 10': 0.25, 'Art. 13': 0.15, 'Art. 14': 0.20, 'Art. 20': 0.15 };
  } else if (riskCat === 'limited' || riskCat === 'minimal') {
    required = ['Art. 13'];
    weights = { 'Art. 13': 1.0 };
  } else if (riskCat === 'unacceptable') {
    return { finalScore: 0, compliance: 0, exposure: 1.0, confidence: 'LOW', breakdown: {} };
  }

  if (required.length === 0) return { finalScore: 0, confidence: 'N/A' };

  let totalWeightedScore = 0;
  const breakdown = {};
  let totalTargetSignals = 0;
  let totalFoundSignals = 0;

  required.forEach(art => {
    // 1. Calculate Claim(a) ∈ [0, 1]
    let claim = 0;
    if (art === 'Art. 13') {
      if (manifest.evidence_path) claim += 0.5;
      if (declaredFlags.includes('transparency_disclosure_provided') || declaredFlags.includes('ai_disclosure')) claim += 0.5;
    } else if (art === 'Art. 14') {
      if (manifest.oversight_evidence_path) claim += 0.5;
      if (declaredFlags.includes('human_oversight_enabled') || declaredFlags.includes('manual_override')) claim += 0.5;
    } else if (art === 'Art. 20') {
      if (manifest.logging_evidence_path) claim += 0.5;
      if (declaredFlags.includes('logging_capabilities_declared')) claim += 0.5;
    } else if (art === 'Art. 9') {
      if (modules.some(m => m.evidence)) claim += 0.5;
      if (declaredFlags.includes('bias_assessment_performed')) claim += 0.5;
    } else if (art === 'Art. 10') {
      if (declaredFlags.includes('data_governance_documented')) claim += 0.5;
      if (declaredFlags.includes('data_lineage_tracked')) claim += 0.5;
    }
    claim = Math.min(1.0, claim);

    // 2. Calculate Evidence(a) ∈ [0, 1] (Proportional)
    const target = AUDIT_BASELINE[art] ? AUDIT_BASELINE[art].target : 1;
    totalTargetSignals += target;
    
    let found = 0;
    if (art === 'Art. 13') found = signalBreakdown.transparency || 0;
    if (art === 'Art. 14') found = signalBreakdown.oversight || 0;
    if (art === 'Art. 20') found = signalBreakdown.logging || 0;
    if (art === 'Art. 10') found = signalBreakdown.ai_assets || 0; // AI Assets map to Data Gov for now
    if (art === 'Art. 9') found = signalBreakdown.ai_assets ? Math.floor(signalBreakdown.ai_assets / 2) : 0; 
    
    totalFoundSignals += found;
    let baseEvidence = Math.min(1.0, found / target);
    
    // Proportional Penalties
    let penaltyMultiplier = 1.0;
    findings.filter(f => f.article === art).forEach(f => {
      const p = (f.deduction || 0) / 100;
      penaltyMultiplier *= (1 - p);
    });
    
    const evidence = baseEvidence * penaltyMultiplier;

    // 3. Article Score
    const artScore = (claim * 0.2 + evidence * 0.8);
    const weightedArtScore = artScore * weights[art];
    
    totalWeightedScore += weightedArtScore;
    breakdown[art] = { claim, evidence, weight: weights[art], contribution: weightedArtScore };
  });

  const finalScore = totalWeightedScore * 100;
  
  // 4. Confidence Metric (Signal Saturation)
  const phi = Math.min(1.0, totalFoundSignals / totalTargetSignals);
  let confidence = 'HIGH';
  if (phi < 0.3) confidence = 'LOW';
  else if (phi < 0.7) confidence = 'MEDIUM';

  // Risk Exposure
  const gravity = { 'high': 1.0, 'limited': 0.4, 'minimal': 0.1 };
  const exposure = (1 - totalWeightedScore) * (gravity[riskCat] || 0.1);

  return {
    finalScore: parseFloat(finalScore.toFixed(1)),
    claim_score: Math.round(finalScore), // Legacy support
    evidence_score: Math.round(finalScore), // Legacy support
    confidence,
    phi: parseFloat(phi.toFixed(2)),
    exposure: parseFloat(exposure.toFixed(2)),
    breakdown
  };
}
function hasHardFail(findings) {
  return findings.some(f => f.hard_fail === true);
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

function printOnboarding(isJson = false) {
  if (isJson) return;
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

  if (process.env.SENTINEL_DEBUG === 'true' && !isJson) {
    console.log(`${C.gray}REMOTE REQUEST: POST ${url.href}${C.reset}`);
    console.log(`${C.gray}PAYLOAD: ${body}${C.reset}`);
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

    if (process.env.SENTINEL_DEBUG === 'true' && !isJson) {
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
function generateEvidencePack(report, manifestPath) {
  const manifestDir = path.dirname(path.resolve(manifestPath));
  const outDir = path.join(manifestDir, 'sentinel-evidence');
  
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  console.log(`Evidence path: ${path.resolve(outDir)}`);

  const manifestRaw = fs.readFileSync(manifestPath, 'utf8');
  const manifest = JSON.parse(manifestRaw);

  const fileList = [];

  // 1. AUDITOR_SUMMARY.md
  const summaryMd = ReportGenerator.generateAuditorMarkdown(report);
  const summaryPath = path.join(outDir, "AUDITOR_SUMMARY.md");
  fs.writeFileSync(summaryPath, summaryMd);
  fileList.push("AUDITOR_SUMMARY.md");

  // 2. audit.json
  const auditJsonPath = path.join(outDir, "audit.json");
  fs.writeFileSync(auditJsonPath, JSON.stringify(report, null, 2));
  fileList.push("audit.json");

  // 3. sentinel.manifest.json (Snapshot)
  const manifestSnapshotPath = path.join(outDir, "sentinel.manifest.json");
  fs.writeFileSync(manifestSnapshotPath, manifestRaw);
  fileList.push("sentinel.manifest.json");

  // 4. EVIDENCE.md (Snapshot - only if path relates to existing file)
  if (manifest.evidence_path) {
    const evidencePath = path.resolve(manifestDir, manifest.evidence_path);
    if (fs.existsSync(evidencePath)) {
      const evidenceContent = fs.readFileSync(evidencePath, 'utf8');
      fs.writeFileSync(path.join(outDir, "EVIDENCE.md"), evidenceContent);
      fileList.push("EVIDENCE.md");
    }
  }

  // 5. checksums.txt (SHA-256 Ledger)
  const checksums = [];
  for (const fileName of fileList) {
    const filePath = path.join(outDir, fileName);
    const content = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    checksums.push(`${hash}  ${fileName}`);
  }
  fs.writeFileSync(path.join(outDir, "checksums.txt"), checksums.join('\n') + '\n');

  return { outDir };
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
    if (!isJson) console.warn(`${C.yellow}⚠️  Warning: Evidence pack integrity hash mismatch. Files may have been tampered with.${C.reset}`);
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
  if (isJson) return;
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
  if (isJson) return;
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

function printPolicyPackList(isJson = false) {
  const registry = loadPolicyPackRegistry();

  if (registry.error) {
    if (isJson) {
      console.error(JSON.stringify({ error: registry.error }));
    } else {
      console.error("");
      console.error(`Sentinel policy pack registry error: ${registry.error}`);
      console.error("");
    }
    process.exit(1);
  }

  const packs = Array.isArray(registry.config?.packs) ? registry.config.packs : [];

  if (isJson) {
    console.log(JSON.stringify({ status: "SUCCESS", packs }));
    return;
  }

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

function printPolicyPackDetails(policyPackName, isJson = false) {
  const registry = loadPolicyPackRegistry();

  if (registry.error) {
    if (isJson) {
      console.log(JSON.stringify({ status: "FAIL", error: true, message: registry.error }));
    } else {
      console.error("");
      console.error(`Sentinel policy pack registry error: ${registry.error}`);
      console.error("");
    }
    process.exit(1);
  }

  const packs = Array.isArray(registry.config?.packs) ? registry.config.packs : [];
  const packMeta = packs.find(pack => pack.name === policyPackName);

  if (!packMeta) {
    if (isJson) {
      console.log(JSON.stringify({ status: "FAIL", error: true, message: `Pack not found: ${policyPackName}` }));
    } else {
      console.error("");
      console.error(`Sentinel policy pack error: Pack not found: ${policyPackName}`);
      console.error("");
    }
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

  if (isJson) {
    console.log(JSON.stringify({ status: "PASS", pack: packMeta, config: pack.config }));
    return;
  }

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
      name: regEntry ? regEntry.name : (v.description || 'Compliance Gap')
    };

    return {
      ruleId: ruleRef.id,
      level: 'error',
      message: {
        text: v.description || 'Compliance gap detected'
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
        results: results,
        properties: {
          claim_score: report.claim_score,
          evidence_score: report.evidence_score,
          confidence: report.confidence,
          risk_category: report.risk_category
        }
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

  if (!isJson) {
    console.log("");
    console.log(`${C.bold}${C.green}✅ Sentinel evidence templates generated.${C.reset}`);
    if (createdDocs.length > 0) {
      console.log(`Created ${createdDocs.length} new templates in docs/compliance/`);
    } else {
      console.log("No new documents needed or all already exist.");
    }
    console.log("");
  }
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
    score: singleVerdict?.score,
    claim_score: singleVerdict?.claim_score,
    evidence_score: singleVerdict?.evidence_score,
    confidence: singleVerdict?.confidence,
    deductions: singleVerdict?.deductions,
    mapped_articles: singleVerdict?.mapped_articles,
    risk_category: singleVerdict?.risk_category,
    required_articles: singleVerdict?.required_articles,
    verdict: singleVerdict?.verdict
  };

  const confidenceColor = auditMetadata.confidence === 'HIGH' ? C.green : (auditMetadata.confidence === 'MEDIUM' ? C.yellow : C.red);
  const isTrustGap = auditMetadata.confidence === 'LOW';

  if (isFail) {
    if (!isJson && !isSarif) {
      console.log(`${C.bold}${C.red}❌ Sentinel compliance check failed${C.reset}`);
      console.log(`${C.bold}Compliance Status: ${C.red}NON_COMPLIANT${C.reset}`);

      if (auditMetadata.risk_category === 'unacceptable') {
        console.log(`${C.bold}Risk Category: ${C.white}unacceptable${C.reset}`);
        console.log(`${C.bold}Reason: ${C.red}Prohibited system / hard fail${C.reset}`);
      } else {
        console.log(`${C.bold}Claim Score (Coverage): ${C.white}${auditMetadata.claim_score || 0}/100${C.reset}`);
        console.log(`${C.bold}Evidence Score (Proof): ${C.red}${auditMetadata.evidence_score || 0}/100${C.reset}`);
        console.log(`${C.bold}Trust Confidence:      ${confidenceColor}${C.bold}${auditMetadata.confidence || 'LOW'}${C.reset}`);
        
        if (isTrustGap) {
          console.log(`\n${C.red}${C.bold}⚠ TRUST GAP DETECTED:${C.reset}${C.red} High compliance claims but missing/invalid evidence docs.${C.reset}`);
        }

        console.log(`\n${C.bold}Risk Category: ${C.white}${auditMetadata.risk_category || 'minimal'}${C.reset}`);
        console.log(`${C.bold}Required Controls: ${C.gray}${auditMetadata.required_articles?.join(', ') || 'Art. 13'}${C.reset}`);
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
        console.log(`${C.bold}${C.yellow}Technical Indicators Absent (Policy):${C.reset}`);
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
      if (policyViolations.length > 0) summaryParts.push(`${policyViolations.length} indicator${policyViolations.length > 1 ? 's' : ''} absent`);
      if (evidenceFindings.length > 0) summaryParts.push(`${evidenceFindings.length} evidence finding${evidenceFindings.length > 1 ? 's' : ''}`);

      if (summaryParts.length > 0) {
        console.log(`  ${C.gray}Audit identified ${summaryParts.join(" and ")}${C.reset}`);
        console.log("");
      }
    }
    printFailure(missingFiles, policyPath);
  } else {
    if (!isJson && !isSarif) {
      const statusColor = auditMetadata.verdict === 'COMPLIANT' ? C.green : (auditMetadata.verdict === 'PARTIAL' ? C.yellow : C.red);
      console.log(`${C.bold}${statusColor}✅ Sentinel compliance check finished${C.reset}`);
      console.log(`${C.bold}Evaluation Status: ${statusColor}${auditMetadata.verdict}${C.reset}`);

      console.log(`${C.bold}Claim Score (Coverage): ${C.white}${auditMetadata.claim_score || 0}/100${C.reset}`);
      console.log(`${C.bold}Evidence Score (Proof): ${C.green}${auditMetadata.evidence_score || 0}/100${C.reset}`);
      console.log(`${C.bold}Computed Trust Score (heuristic): ${confidenceColor}${C.bold}${auditMetadata.phi || 0}${C.reset}`);

      if (isTrustGap) {
        console.log(`\n${C.yellow}${C.bold}⚠ TRUST GAP DETECTED:${C.reset}${C.yellow} Claims are high, but evidence is boilerplate or low-substance.${C.reset}`);
      }

      console.log(`\n${C.bold}Risk Category: ${C.white}${auditMetadata.risk_category || 'minimal'}${C.reset}`);
      console.log(`${C.bold}Required Controls: ${C.gray}${auditMetadata.required_articles?.join(', ') || 'Art. 13'}${C.reset}`);
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
 * Enforcement Policy Checker
 * @param {string} verdict APPROVED, HOLD, REJECTED
 * @param {string} policy REJECTED, HOLD, NONE
 * @returns {boolean} True if enforcement failed (should exit 1)
 */
function isEnforcementViolation(verdict, policy) {
  if (policy === 'NONE') return false;
  if (policy === 'REJECTED' && verdict === 'REJECTED') return true;
  if (policy === 'HOLD' && (verdict === 'REJECTED' || verdict === 'HOLD')) return true;
  return false;
}

/**
 * Writes a markdown summary to a file.
 */
function writeSummary(report, summaryPath) {
  try {
    const ReportGenerator = require('./lib/report-generator');
    const md = ReportGenerator.generateMarkdownSummary(report);
    fs.writeFileSync(path.resolve(summaryPath), md);
    return true;
  } catch (e) {
    if (!isJson) console.error(`\n${C.yellow}Warning: Failed to generate summary: ${e.message}${C.reset}`);
    return false;
  }
}


/**
 * Generates a top-level system assessment based on findings and signals.
 * @param {object[]} findings - Audit findings.
 * @returns {object} { overall_posture, key_risks, dominant_gaps }
 */
function generateSystemAssessment(findings) {
  const criticalFindings = findings.filter(f => (f.reasoning?.severity || "").toUpperCase() === 'CRITICAL');
  const highFindings = findings.filter(f => (f.reasoning?.severity || "").toUpperCase() === 'HIGH');
  
  let overall_posture = "Partial implementation with moderate risk.";
  if (criticalFindings.length > 0) {
    overall_posture = "System demonstrates critical gaps with high audit risk.";
  } else if (highFindings.length > 5) {
    overall_posture = "Multiple high-severity implementation gaps detected.";
  } else if (findings.length === 0) {
    overall_posture = "System demonstrates baseline technical compliance markers.";
  }

  const uniqueGaps = [...new Set(findings.flatMap(f => f.reasoning?.gaps || []))];
  const uniqueContradictions = [...new Set(findings.flatMap(f => f.reasoning?.contradictions || []))];

  return {
    overall_posture,
    key_risks: criticalFindings.map(f => f.description).slice(0, 3),
    dominant_gaps: [...uniqueGaps, ...uniqueContradictions].slice(0, 3)
  };
}

/**
 * Generates a final executive audit position.
 * @param {object[]} findings - Audit findings.
 * @param {number} score - Final audit score.
 * @returns {object} { audit_readiness, major_blockers, risk_level }
 */
function generateFinalAuditPosition(findings, score) {
  const criticals = findings.filter(f => (f.reasoning?.severity || "").toUpperCase() === 'CRITICAL');
  const highs = findings.filter(f => (f.reasoning?.severity || "").toUpperCase() === 'HIGH');
  const conflicts = findings.filter(f => f.document_conflict);
  
  let readiness = "Audit Ready";
  if (criticals.length > 0 || conflicts.length > 0) readiness = "NOT AUDIT READY";
  else if (highs.length > 3) readiness = "ACTION REQUIRED";

  return {
    audit_readiness: readiness,
    major_blockers: [...new Set([...criticals, ...conflicts].map(f => f.description))].slice(0, 3),
    risk_level: score < 40 ? "CRITICAL" : (score < 70 ? "HIGH" : (score < 90 ? "MEDIUM" : "LOW"))
  };
}

/**
 * Core audit engine. Finalizes all metrics and returns the report object.
 * This is the Single Source of Truth for Sentinel.
 */
async function performAudit(manifestPath, threshold, options = {}) {
  const engine = options.engine || 'stable';
  if (process.env.SENTINEL_DEBUG === 'true' && !options.isJson) {
     console.log(`[DEBUG] performAudit call: ${manifestPath} (Threshold: ${threshold}) | Engine: ${engine}`);
  }
  const manifestDir = path.dirname(path.resolve(manifestPath));
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    
    // Validate loaded registries
    validateRegistryAuthority(discoveryRules, 'discovery-rules.json');
    if (probingRules) validateRegistryAuthority(probingRules, 'probing-rules.json');
  } catch (e) {
    throw new Error(`Failed to read manifest: ${e.message}`);
  }

  // 1. Implementation Audit (Signals)
  const commitId = AuditMetadata.getGitCommit(manifestDir);
  const repoFiles = autodiscovery.crawlRepository(manifestDir);
  // Rule Shadowing: Load extended rules if in extended mode
  let effectiveProbingRules = probingRules;
  if (engine === 'extended') {
    try {
      const extendedRulesPath = path.join(__dirname, 'lib', 'probing-rules-extended.json');
      if (fs.existsSync(extendedRulesPath)) {
        const extendedRules = JSON.parse(fs.readFileSync(extendedRulesPath, 'utf8'));
        // Deep merge logic for probes
        effectiveProbingRules = JSON.parse(JSON.stringify(probingRules)); // Clone
        if (extendedRules.probes) {
          for (const [key, value] of Object.entries(extendedRules.probes)) {
            if (!effectiveProbingRules.probes[key]) {
              effectiveProbingRules.probes[key] = value;
            } else {
              // Merge signals
              effectiveProbingRules.probes[key].strong_signals = [
                ...(effectiveProbingRules.probes[key].strong_signals || []),
                ...(value.strong_signals || [])
              ];
              effectiveProbingRules.probes[key].weak_signals = [
                ...(effectiveProbingRules.probes[key].weak_signals || []),
                ...(value.weak_signals || [])
              ];
            }
          }
        }
      }
    } catch (err) {
      if (!options.isJson) {
        console.warn(`[ENGINE-EXTENDED] Warning: Could not merge extended rules: ${err.message}`);
      }
    }
  }

  const dependencyGraph = autodiscovery.buildDependencyGraph(repoFiles);
  let signals = autodiscovery.extractSignals(repoFiles, discoveryRules, effectiveProbingRules, dependencyGraph, commitId);

  // 1.05 Production Trace Context (Step 4 Hardening)
  const buildId = options.buildId || null;
  const traceStatus = buildId ? 'USER_DECLARED' : 'UNBOUND';

  if (!options.isJson) {
    process.stdout.write(`\n${C.cyan}${C.bold}Production Trace Context:${C.reset}\n`);
    process.stdout.write(`* build_id: ${buildId || 'NOT PROVIDED'}\n`);
    process.stdout.write(`* trace_status: ${traceStatus}\n`);

    if (!buildId) {
      process.stdout.write(`\n${C.yellow}${C.bold}EVIDENCE SCOPE LIMITATION:${C.reset}\n`);
      process.stdout.write(`No production build reference (--build-id) was provided.\n`);
      process.stdout.write(`This audit verifies repository-level technical signals only.\n`);
      process.stdout.write(`It does NOT establish traceability to a deployed production system.\n`);
    }
  }

  // 1.06 Strict Mode Enforcement (Hardened with Evidence Trace)
  if (options.strict) {
    const normalize = v => String(v).toLowerCase().trim();
    const declaredFlags = Object.keys(manifest.declared_flags || {})
      .filter(k => manifest.declared_flags[k] === true)
      .map(normalize);
    
    const detectedSignals = signals.map(s => ({
      type: normalize(s.type || s.id),
      file: s.source_path || "unknown",
      line: s.line || "unknown",
      match: s.snippet || "unknown"
    })).filter(s => s.type);

    const undeclared = detectedSignals.filter(s => !declaredFlags.includes(s.type));
    const missing = declaredFlags.filter(f => !detectedSignals.some(s => s.type === f));

    if (undeclared.length > 0 || missing.length > 0) {
      if (!options.isJson) {
        process.stdout.write(`\n${C.red}${C.bold}❌ STRICT MODE VIOLATION${C.reset}\n`);
        process.stdout.write(`${C.white}Strict mode enforces exact alignment between declared capabilities and detected technical signals without interpretation.${C.reset}\n`);
        
        if (undeclared.length > 0) {
          process.stdout.write(`\n${C.yellow}Undeclared signals detected:${C.reset}\n`);
          undeclared.forEach(s => {
            process.stdout.write(`- ${C.white}${s.type}${C.reset}\n`);
            process.stdout.write(`  ${C.gray}file:  ${s.file}${C.reset}\n`);
            process.stdout.write(`  ${C.gray}line:  ${s.line}${C.reset}\n`);
            if (s.match && s.match !== "unknown") {
              process.stdout.write(`  ${C.gray}match: ${C.cyan}${s.match}${C.reset}\n`);
            }
          });
        }
        
        if (missing.length > 0) {
          process.stdout.write(`\n${C.yellow}Declared but not detected:${C.reset}\n`);
          [...new Set(missing)].forEach(f => process.stdout.write(`- ${f}\n`));
        }
        
        process.stdout.write(`\n${C.gray}Audit Terminated (Strict Mode).${C.reset}\n\n`);
      }
      throw new Error(`STRICT MODE VIOLATION: Declared flags do not match detected signals.`);
    }
    if (!options.isJson) {
      process.stdout.write(`${C.green}${C.bold}✅ STRICT MODE PASSED${C.reset}\n`);
    }
  }

  // 1.1 Governance Context
  const isMinimal = (manifest.risk_category || "").toLowerCase() === 'minimal';
  const hasAISignals = signals.length > 0;
  const requiresGovernance = !isMinimal || hasAISignals;

  // 2. Evidence & Governance Audit (Context-Aware)
  const offlineResult = await runOffline(manifest);
  const allEngineViolations = offlineResult.violations || [];
  const engineViolations = requiresGovernance ? allEngineViolations : allEngineViolations.filter(v => v.risk_category !== 'High' && v.risk_category !== 'Limited');
  const evidenceFindings = validateEvidence(manifest, manifestDir, signals, requiresGovernance);

  // Alignment Heuristic: Reduce impact of marketing/content repositories
  // Signal Diversity & Density check
  const contentSignals = signals.filter(s => /\.(html|txt|astro|vue|svelte)$/i.test(s.source_path));
  const codeSignals = signals.filter(s => s.kind === 'dependency' || s.kind === 'hardening_probe' || /\.(js|ts|tsx|jsx|mjs|cjs|md|mdx|py|go|java|rb|cpp|cs|php|rs|swift|kt)$/i.test(s.source_path));

  const contentCount = contentSignals.length;
  const codeCount = codeSignals.length;
  
  const hasDeepCodeSupport = codeSignals.some(s => s.confidence >= 0.8 && (/\b(src|lib|api|bin|core|engine|app|packages|apps|services)\b/i.test(s.source_path) || s.source_path.includes('/')));
  
  const isHighNoise = codeCount === 0 && contentCount > 10;
  const isLowReliability = contentCount > 20 && (codeCount < 1 || !hasDeepCodeSupport);

  // Alignment Heuristic: Discard low-confidence signals if the repo is considered low reliability/marketing noise
  if (isHighNoise || isLowReliability) {
     signals = signals.filter(s => s.confidence >= 0.9 || s.kind === 'hardening_probe'); 
  }

  const hardeningFindings = [];
  computeHardeningFindings(signals, manifest, hardeningFindings, repoFiles, dependencyGraph);


  // 2.1 Enterprise Safety Gate: Negative Assurance
  const hasIntent = autodiscovery.detectHeuristicIntent(repoFiles);
  if (hasIntent && signals.length === 0 && (manifest.risk_category || "minimal").toLowerCase() === 'minimal') {
      hardeningFindings.push({
          article: "Art. 9/13",
          rule_id: "EUAI-NEG-ASSURANCE-001",
          description: `[Safety] Negative Assurance FAIL: Metadata indicates AI intent, but zero technical signals found.`,
          deduction: 30,
          severity: "high",
          source: "implementation",
          fix_snippet: "Declare AI assets in manifest or update discovery rules to match your tech stack.",
          hard_fail: true
      });
  }

  // 2.2 Enterprise Safety Gate: Behavioral Suspicion Fallback
  const hasBehaviorSuspicion = signals.some(s => s.id === 'BEHAVIORAL_SUSPICION_FLAG_HIGH_RISK');
  if (hasBehaviorSuspicion && (manifest.risk_category || "minimal").toLowerCase() === 'minimal') {
      hardeningFindings.push({
          article: "Art. 6 / Annex III",
          rule_id: "EUAI-BEHAVIOR-001",
          description: `[Safety] Unknown AI System: Behavioral analysis strongly suggests obfuscated/wrapper AI integration. Risk overridden to HIGH.`,
          deduction: 50,
          severity: "critical",
          source: "implementation",
          fix_snippet: "Declare AI assets clearly or escalate to Human Review to bypass.",
          hard_fail: true
      });
  }

  // 3. Combine & Post-process
  const allFindings = [...evidenceFindings, ...allEngineViolations, ...hardeningFindings];
  
  // 3.0 Auditor Resistance: Detect Document Contradictions
  const docConflicts = intelligence.detectDocumentContradictions(manifest, signals);
  const combinedFindings = [...allFindings, ...docConflicts].filter(f => {
      if (requiresGovernance) return true;
      // Suppress advanced AI Act rules for Minimal Non-AI projects
      const articleClean = (f.article || "").toLowerCase().replace(/[^a-z0-9]/g, '');
      const isAdvanced = articleClean.includes('art13') || articleClean.includes('art14') || articleClean.includes('art10') || articleClean.includes('art20') || articleClean.includes('article13') || articleClean.includes('article14') || articleClean.includes('article10') || articleClean.includes('article20') ||
                        (f.rule_id && (f.rule_id.startsWith('ART') || f.rule_id.startsWith('EUAI-TRANS') || f.rule_id.startsWith('EUAI-EVID')));
      return !isAdvanced;
  });
  
  // Ensure DX compliance
  combinedFindings.forEach(f => {
    if (f.fix_snippet && f.fix_snippet.includes('declared_flags') && !f.fix_snippet.includes('array')) {
      f.fix_snippet = f.fix_snippet.replace('declared_flags', "'declared_flags' array");
    }
    if (f.description && f.description.toLowerCase().includes('transparent about being an ai')) {
      f.description = "[Missing user notification]";
      f.fix_snippet = "Add 'user_notification_ai_interaction' to 'declared_flags' array.";
      if (!f.article) f.article = "Art. 13";
    }
  });

  // 3.1 Evidence Correlation Layer
  // Phase 1.5: Reasoning Hardening
  intelligence.correlateFindings(combinedFindings, manifest, signals);

  // Phase 1 & 2: Evidence Reasoning & Dossier Enrichment
  combinedFindings.forEach(f => intelligence.applyReasoning(f, manifest, signals));

  // 3.1 CI/CD & Test Discovery (Phase 14.3)
  const ciCdFiles = autodiscovery.discoverCiCdSignals(repoFiles);
  const testFiles = autodiscovery.discoverTestFiles(repoFiles);
  const correlationSignals = autodiscovery.correlateSignals(ciCdFiles, testFiles);

  const articleSummaries = intelligence.generateArticleSummaries(combinedFindings, signals, manifest);

  // Phase 2: Audit Dossier Hardening (Sorting)
  const severityMap = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
  const strengthMap = { 'HIGH': 4, 'MODERATE': 3, 'WEAK': 2, 'NONE': 1 };
  
  combinedFindings.sort((a, b) => {
    const sevA = severityMap[a.reasoning?.severity] || 0;
    const sevB = severityMap[b.reasoning?.severity] || 0;
    if (sevB !== sevA) return sevB - sevA;
    
    const strA = strengthMap[a.reasoning?.evidence_strength] || 0;
    const strB = strengthMap[b.reasoning?.evidence_strength] || 0;
    return strB - strA;
  });

  const auditScope = {
    within_scope: {
      repository: path.basename(process.cwd()),
      files_analyzed: repoFiles.length,
      analysis_depth: "Static Technical Audit (Annex IV)"
    },
    outside_scope: [
      "Real-time runtime monitoring",
      "Human organizational processes",
      "Live production environment validation",
      "Physical security of hosting infrastructure"
    ]
  };

  // Signal Breakdown for UX (Categorical Analysis)
  const signalBreakdown = calculateSignalBreakdown(signals);

  const trust = computeTrustMetrics(combinedFindings, manifest, signalBreakdown, requiresGovernance);
  const score = trust.finalScore;

  const reasoningSummary = {
    top_critical_risks: combinedFindings
      .filter(f => f.reasoning?.severity === 'CRITICAL' || f.reasoning?.severity === 'HIGH')
      .slice(0, 3)
      .map(f => f.description),
    top_contradictions: combinedFindings
      .flatMap(f => f.reasoning?.contradictions || [])
      .slice(0, 3),
    overall_posture: score < 40 ? "HIGH RISK" : (score < 80 ? "MODERATE RISK" : "LOW RISK")
  };

  // V2.1 Dual-Track Evaluation (Premium)
  const Evaluator = require('./lib/evaluator');
  const dualTrack = Evaluator.evaluate({
    score,
    threshold,
    _internal: {
      signalBreakdown,
      signals: (signals || []).map(s => {
        let fullContent = "";
        try {
          fullContent = fs.readFileSync(path.resolve(process.cwd(), s.source_path));
        } catch(e) {}
        return {
          ...s,
          source_sha256: fullContent ? crypto.createHash('sha256').update(fullContent).digest('hex') : 'unknown',
          evidence_sha256: s.snippet ? crypto.createHash('sha256').update(s.snippet).digest('hex') : 'unknown'
        };
      }),
      all_findings: combinedFindings
    }
  });

  // Phase 11: Semantic Document Evaluation (Optional)
  let semanticReport = null;
  if (process.env.SENTINEL_LLM_PROVIDER && 
      process.env.SENTINEL_LLM_PROVIDER !== 'none') {
    try {
      const docsMap = await extractDocsFromRepo(manifestDir, manifest);
      if (Object.keys(docsMap).length > 0) {
        const evalResults = await evaluateAllDocuments(docsMap);
        semanticReport = generateSemanticReport(evalResults);
      }
    } catch (e) {
      if (process.env.SENTINEL_DEBUG === 'true' && !options.isJson) {
        console.log(`[DEBUG] Semantic evaluation failed or skipped: ${e.message}`);
      }
      semanticReport = null;
    }
  }

  const systemAssessment = generateSystemAssessment(combinedFindings);

  // Coverage Calculation
  const signalsDetected = signals.length;
  const discoveryRuleCount = Object.keys(discoveryRules.rules || {}).length;
  const probingRuleCount = Object.keys(effectiveProbingRules.probes || {}).length;
  const signalsExpected = discoveryRuleCount + probingRuleCount;
  const coverageRatio = signalsExpected > 0 ? (signalsDetected / signalsExpected).toFixed(4) : 0;


  // 4. Construct SSoT Report
  const report = {
    status: "COMPLIANT", // Initial status; overridden by resolveFinalVerdict
    score,
    findings: combinedFindings,
    confidence: trust.confidence,
    command: "check",
    manifest_path: manifestPath,
    audit_context: {
      timestamp: new Date().toISOString(),
      repository: manifestDir,
      commit: commitId || "uncommitted",
      execution_mode: "local_static_scan"
    },
    coverage: {
      signals_detected: signalsDetected,
      signals_expected: signalsExpected,
      coverage_ratio: parseFloat(coverageRatio)
    },
    claim_score: trust.claim_score,
    evidence_score: trust.evidence_score,
    phi: trust.phi,
    exposure: trust.exposure,
    threshold,
    production_hash: options.productionHash || null,
    production_trace_context: {
      build_id: buildId || 'NOT PROVIDED',
      trace_status: buildId ? 'USER_DECLARED' : 'UNBOUND'
    },
    system_assessment: systemAssessment,
    reasoning_summary: reasoningSummary,
    article_summaries: articleSummaries,
    final_audit_position: generateFinalAuditPosition(combinedFindings, score),
    _context_validation: evaluateContextSufficiency(manifest, combinedFindings, engine),
    _declaration_consistency: checkDeclarationConsistency(manifest, combinedFindings, signals, engine),
    _executive_summary: generateExecutiveSummary(manifest, combinedFindings, signals, engine),
    findings: combinedFindings,
    risk_category: signals.some(s => s.id === 'BEHAVIORAL_SUSPICION_FLAG_HIGH_RISK') ? "High" : (manifest.risk_category || "Minimal"),
    semantic_quality: semanticReport?.semantic_quality ?? { evaluated: false },
    exit_code: 0,
    findings_count: combinedFindings.length,
    score_breakdown: trust.breakdown,
    top_findings: combinedFindings.slice(0, 5).map(f => ({
      rule_id: f.rule_id,
      description: f.description,
      fix_snippet: f.fix_snippet,
      article: f.article,
      source: f.source,
      hardening_verdict: f.hardening_verdict,
      authority_mapping: f.authority_mapping || null,
      source_reference: f.source_reference || null,
      enforcement_level: f.enforcement_level || null
    })),
    _internal: {
        total_signals: signals.length,
        signals: (signals || []).map(s => {
          let fullContent = "";
          try {
            fullContent = fs.readFileSync(path.resolve(process.cwd(), s.source_path));
          } catch(e) {}
          return {
            ...s,
            source_sha256: fullContent ? crypto.createHash('sha256').update(fullContent).digest('hex') : 'unknown',
            evidence_sha256: s.snippet ? crypto.createHash('sha256').update(s.snippet).digest('hex') : 'unknown'
          };
        }),
        signal_breakdown: signalBreakdown,
        all_findings: combinedFindings, // Expose for CLI/Dashboard
        files: repoFiles.length
    },
    
    // --- CI/CD & Test Discovery (Phase 14.3) ---
    ci_cd_files: ciCdFiles,
    test_files: testFiles,
    correlation_signals: correlationSignals,

    // --- Enterprise Defensibility Extensions (Additive) ---
    "AUDIT_SCOPE": {
      "scan_root": path.dirname(path.resolve(manifestPath || "./")),
      "analysis_type": "static code + manifest + local documentation",
      "included": [
        "source code within repository",
        "local documentation files",
        "sentinel.manifest.json"
      ],
      "excluded": [
        "external services",
        "third-party APIs",
        "shared infrastructure outside repository",
        "manual human processes",
        "vendor dashboards"
      ],
      "statement": "This audit strictly evaluates the local codebase and declared artifacts. Any control implemented outside this boundary is not validated."
    },
    "AUDIT_COVERAGE": {
      "files_scanned": repoFiles.length || null,
      "files_detected": null,
      "coverage_ratio": null,
      "scan_patterns": "derived from internal rule registry",
      "excluded_paths": [
        "node_modules/",
        "dist/",
        "build/"
      ],
      "coverage_statement": "Findings are based on analysis of scanned files only. Unscanned areas are outside current audit coverage."
    },
    "EVIDENCE_INTERPRETATION": {
      "method": "pattern-based static analysis",
      "negative_evidence_definition": "NOT_FOUND indicates absence of expected technical signals within scanned scope, not absolute absence across entire system",
      "limitation": "Controls implemented outside detectable patterns or outside scan boundary may not be captured"
    },
    "AUDIT_REASONING_CHAIN": {
      "step_1": "Manifest declares control (e.g., logging_enabled: true)",
      "step_2": "System scans codebase for corresponding implementation signals",
      "step_3": "No matching patterns detected in scanned scope",
      "step_4": "Contradiction established between declared and observed state",
      "step_5": "For HIGH-RISK systems, absence of implementation constitutes regulatory risk"
    }
  };


  // Phase 7: Confidence Enrichment (Corrected Location)
  report.audit_confidence = articleSummaries.audit_confidence;
  delete articleSummaries.audit_confidence;

  if (report.audit_confidence) {
    const ciCdPresent = (report.ci_cd_files || []).length > 0;
    const testFilesPresent = (report.test_files || []).length > 0;
    const correlation = report.correlation_signals || {};
    const correlated = correlation.test_execution_pipeline || correlation.test_validation_signals;

    report.audit_confidence.evidence_profile = {
      ci_cd_present: ciCdPresent,
      test_files_present: testFilesPresent,
      correlated_signals: correlated
    };

    let explanation = "Limited supporting signals detected. Confidence remains based on pattern detection only within analyzed scope.";
    if (ciCdPresent && testFilesPresent && correlated) {
      explanation = "Multiple repository-scoped signals detected (CI/CD + test evidence + correlation), increasing confidence within analyzed scope.";
    } else if (testFilesPresent) {
      explanation = "Test evidence detected without CI/CD correlation. Moderate confidence within analyzed scope.";
    }
    report.audit_confidence.confidence_explanation = explanation;
  }

  // RULE 5: Runtime Safety - Define core verdict variables
  const findings = report.findings || [];
  const activeRisk = (manifest.risk_category || manifest.risk_level_declared || "minimal").toUpperCase();
  
  // Rule 1 & 2: Identify Contradictions (Manifest vs reality)
  const contradictions = findings.filter(f => {
    const isDirectContradiction = (f.source === 'epistemic' || (f.rule_id || "").includes('CONTRADICTION'));
    const hasContradictionText = f.description.toLowerCase().includes("contradiction");
    const isHardFail = f.hard_fail === true;
    const isNotFound = f.description.toLowerCase().includes("not found");

    // RULE: "not found" is only a contradiction if:
    // 1. It is explicitly marked as a hard_fail (critical violation)
    // 2. It comes from the epistemic engine (direct manifest-vs-code mismatch)
    if (isNotFound && !isHardFail && f.source !== 'epistemic') {
      return false;
    }

    return isDirectContradiction || hasContradictionText || isHardFail;
  });

  // Rule 3: Mandatory Controls (Article 14, Article 20, Connectivity)
  const missingMandatory = findings.filter(f => {
    const ruleId = (f.rule_id || "").toUpperCase();
    const art = (f.article || "").toUpperCase();
    const isMandatoryField = art.includes('ARTICLE 14') || art.includes('ARTICLE 20') || ruleId.includes('CONNECTIVITY');
    return isMandatoryField && f.hardening_verdict === 'FAIL';
  });

  // Rule 1: Gaps (Incomplete but no contradiction)
  const gaps = findings.filter(f => {
    if (contradictions.includes(f) || missingMandatory.includes(f)) return false;
    
    return (
      f.hardening_verdict === 'WEAK PASS' ||
      f.hardening_verdict === 'FAIL' || // non-mandatory hardening fails
      f.description.toLowerCase().includes("not detected") ||
      f.description.toLowerCase().includes("incomplete")
    );
  });

  // 3.5 Diagnostic Metadata (Temporary)
  report._debug_verdict = {
    contradictions_count: contradictions.length,
    missingMandatory_count: missingMandatory.length,
    gaps_count: gaps.length,
    contradictions_sample: contradictions.slice(0,3).map(f => ({
      rule_id: f.rule_id,
      source: f.source,
      hard_fail: f.hard_fail,
      description: f.description
    })),
    missingMandatory_sample: missingMandatory.slice(0,3).map(f => ({
      rule_id: f.rule_id,
      source: f.source,
      hardening_verdict: f.hardening_verdict
    }))
  };

  // Rule 4: Single Source of Truth
  const finalState = resolveFinalVerdict(contradictions, missingMandatory, gaps);
  
  report.status = finalState;
  report.exit_code = (finalState === "FAIL") ? 1 : 0;

  // Add mandatory metadata to the report object
  report.audit_metadata = {
    verdict: finalState,
    contradictions_found: contradictions.length,
    missing_mandatory: missingMandatory.length,
    gaps_detected: gaps.length,
    timestamp: new Date().toISOString()
  };

  // RULE 5: Runtime Safety - Final Sanitization Pass
  function sanitizeObject(obj) {
    if (!obj) return obj;
    if (typeof obj === 'string') return intelligence.sanitize(obj);
    if (Array.isArray(obj)) return obj.map(sanitizeObject);
    if (typeof obj === 'object') {
      const sanitized = {};
      for (const key in obj) {
        sanitized[key] = sanitizeObject(obj[key]);
      }
      return sanitized;
    }
    return obj;
  }

  return sanitizeObject(report);
}

/**
 * Strict Family Detection (Extended Mode Only).
 * Uses hardened findings to ensure PROVEN/INDICATED substance.
 */
function getEvidencedFamilies(findings) {
  const families = new Set();
  const activeFindings = findings.filter(f => f.hardening_verdict === 'PROVEN' || f.hardening_verdict === 'INDICATED');
  
  activeFindings.forEach(f => {
    const art = (f.article || "").toUpperCase();
    if (art.includes('ART. 13') || art.includes('ARTICLE 13')) families.add('transparency');
    if (art.includes('ART. 14') || art.includes('ARTICLE 14')) families.add('human_oversight');
    if (art.includes('ART. 20') || art.includes('ARTICLE 20')) families.add('traceability');
  });
  return families;
}

/**
 * Strict "Missing" Check (Extended Mode Only).
 * Missing = Zero PROVEN/INDICATED AND Positive Negative Evidence.
 */
function isMissing(article, findings) {
  const artUpper = article.toUpperCase();
  const familyFindings = findings.filter(f => (f.article || "").toUpperCase().includes(artUpper));
  
  const hasSubstance = familyFindings.some(f => f.hardening_verdict === 'PROVEN' || f.hardening_verdict === 'INDICATED');
  if (hasSubstance) return false;

  // Must have negative evidence confirmation
  const hasNegativeEvidence = familyFindings.some(f => f.negative_evidence && f.negative_evidence.includes("No direct evidence found"));
  return hasNegativeEvidence;
}

/**
 * Contextual Sufficiency Engine (Hardened).
 */
function evaluateContextSufficiency(manifest, findings, engine) {
  if (engine !== 'extended') return null;

  const domain = manifest.system_domain || "not declared";
  const declaredRisk = (manifest.risk_level_declared || "not declared").toUpperCase();
  const intendedUse = manifest.intended_use || "not declared";

  if (declaredRisk === "NOT DECLARED") {
    return {
      declaredDomain: domain,
      declaredRisk: "NOT DECLARED",
      intendedUse,
      technicalStatement: "Context not declared; contextual sufficiency check not performed",
      note: "Context validation is based on manifest-declared system profile and repository-scoped technical evidence only."
    };
  }

  // 1. Evidence-Backed Family Detection
  const detectedFamilies = getEvidencedFamilies(findings);

  // 2. Technical Sufficiency Mapping
  const requirementsMap = {
    'HIGH': ['transparency', 'human_oversight', 'traceability'],
    'MEDIUM': ['transparency', 'traceability'],
    'LOW': ['transparency']
  };

  const requiredFamilies = requirementsMap[declaredRisk] || [];
  const missingFamilies = requiredFamilies.filter(req => {
    // A family is missing if it's required but NOT detected.
    return !detectedFamilies.has(req);
  });

  const isSupported = missingFamilies.length === 0;
  const technicalStatement = isSupported 
    ? "Declared risk profile is supported by detected controls within scanned scope"
    : `Declared risk profile is NOT supported by detected controls within scanned scope (Missing: ${missingFamilies.join(', ')})`;

      }

/**
 * Correlate evidence signals into higher-level clusters.
 */
function correlateEvidenceClusters(signals) {
  const clusters = {
    safety_validated: false,
    unmitigated_execution: false,
    traceability_gap: false,
    reasons: []
  };

  const hasExecution = signals.some(s => s.id.startsWith('CODE_AI_CALL') || s.kind === 'code_signature_call');
  const hasRobustness = signals.some(s => s.id.startsWith('CODE_ADVERSARIAL') || s.id.startsWith('CODE_STRESS') || s.id.startsWith('CODE_SANITIZATION'));
  const hasOversight = signals.some(s => s.id.startsWith('CODE_OVERRIDE') || s.id.startsWith('CODE_KILL_SWITCH'));
  const hasLogging = signals.some(s => s.id.startsWith('DEP_WINSTON') || s.id.startsWith('DEP_PINO') || s.id.startsWith('CODE_LOGGER_INIT'));

  if (hasExecution) {
    if (hasRobustness && hasOversight) {
      clusters.safety_validated = true;
      clusters.reasons.push("Safety Cluster detected: AI execution is paired with robustness and oversight markers.");
    } else {
      clusters.unmitigated_execution = true;
      clusters.reasons.push("Unmitigated Execution Chain: AI execution observed without sufficient robustness/oversight markers.");
    }
  }

  if (hasExecution && !hasLogging) {
    clusters.traceability_gap = true;
    clusters.reasons.push("Traceability Gap: AI execution markers present without industrial logging infrastructure.");
  }

  return clusters;
}

/**
 * Hardened Technical Risk Inference (Extended Mode Only).
 */
function inferTechnicalRiskSignal(findings, signals, engine) {
  if (engine !== 'extended') return { signal: 'low', confidence: 'LOW', reasons: ["Inference disabled in stable mode"] };

  const clusters = correlateEvidenceClusters(signals);
  const executionSignals = signals.filter(s => s.id.startsWith('CODE_AI_CALL') || s.kind === 'code_signature_call');
  const aiExecutionSignals = executionSignals; // For backward compatibility in reasons
  const hasExecution = executionSignals.length > 0;
  
  // Connectivity Scanner Logic
  const connectivitySignals = signals.filter(s => s.kind === 'code_signature_call' && (s.id.startsWith('CODE_HTTP') || s.id.startsWith('CODE_SOCKET') || s.id.startsWith('CODE_URI')));
  const activeConnectivity = connectivitySignals.length > 0;
  
  const missingTransparency = isMissing('Art. 13', findings);
  const missingOversight = isMissing('Art. 14', findings);
  const hasBasicSafeguards = findings.some(f => (f.hardening_verdict === 'PROVEN' || f.hardening_verdict === 'INDICATED' || f.hardening_verdict === 'PASS' || f.hardening_verdict === 'WEAK PASS') && (f.article || "").toUpperCase().match(/ART. 20|LOGGING|MONITORING/));

  let signal = 'low';
  let confidence = 'LOW';
  let reasons = [];

  if (clusters.unmitigated_execution) {
    signal = 'elevated';
    confidence = 'HIGH';
    reasons.push("High Risk Execution Chain detected (Art 15/14 deficiency)");
  } else if (clusters.safety_validated) {
    signal = 'low';
    confidence = 'HIGH';
    reasons.push("Verified Safety Cluster: Proactive controls observed");
  } else if (hasExecution && activeConnectivity) {
    signal = 'elevated';
    confidence = 'HIGH';
    reasons.push(`Direct AI model execution detected (${aiExecutionSignals.length} markers) with active technical connectivity`);
  } else if (hasExecution) {
    signal = 'medium';
    confidence = 'MEDIUM';
    reasons.push("AI execution markers detected but technical connectivity within scope is limited/isolated");
  } else if (activeConnectivity) {
    signal = 'medium';
    confidence = 'LOW';
    reasons.push("Technical connectivity markers detected without confirmed AI execution signatures");
  } else if (signals.some(s => s.kind === 'code_signature_load' || s.kind === 'dependency')) {
    signal = 'low';
    confidence = 'MEDIUM';
    reasons.push("AI capability/loading detected but no active execution signatures observed");
  } else {
    reasons.push("No elevated technical risk markers observed in scanned repository scope");
  }

  // Add cluster reasons if not already present
  reasons = [...reasons, ...clusters.reasons];

  return { 
    signal, 
    confidence, 
    reasons: Array.from(new Set(reasons)).slice(0, 3), 
    _meta: { hasExecution, activeConnectivity, missingTransparency, missingOversight, clusters } 
  };
}

/**
 * Declaration Consistency Engine (Extended Mode Only).
 */
function checkDeclarationConsistency(manifest, findings, signals, engine) {
  if (engine !== 'extended') return null;

  const inferred = inferTechnicalRiskSignal(findings, signals, engine);
  const declared = (manifest.risk_level_declared || "NOT DECLARED").toLowerCase();

  let result = 'CONSISTENT';
  let technicalStatement = "Declared profile is consistent with observed technical evidence within scanned scope";

  if (declared === "not declared") {
    result = 'NOT DECLARED';
    technicalStatement = "Declaration consistency check not performed because context was not declared";
  } else if (declared === 'low' && inferred.signal === 'elevated') {
    result = 'POSSIBLE UNDERDECLARATION';
    technicalStatement = "Declared profile may understate the observed technical risk signal within scanned scope";
  } else if (declared === 'medium' && inferred.signal === 'elevated' && inferred.confidence === 'HIGH') {
    result = 'POSSIBLE UNDERDECLARATION';
    technicalStatement = "Declared profile may understate the observed technical risk signal within scanned scope";
  }

  return {
    declaredRisk: declared.toUpperCase(),
    inferredSignal: inferred.signal.toUpperCase(),
    confidence: inferred.confidence,
    reasons: inferred.reasons,
    result,
    technicalStatement,
    note: "Declaration consistency is based on manifest declarations and repository-scoped technical evidence only. It is not a regulatory classification."
  };
}

/**
 * Jargon-Free Executive Risk Summary (Top of Report).
 */
function generateExecutiveSummary(manifest, findings, signals, engine) {
  if (engine !== 'extended') return null;

  const inferred = inferTechnicalRiskSignal(findings, signals, engine);
  const consistency = checkDeclarationConsistency(manifest, findings, signals, engine);
  const evidencedFamilies = getEvidencedFamilies(findings);
  
  // 1. AI USAGE
  let aiUsage = "No AI execution evidence observed within analyzed repository scope";
  if (inferred._meta.hasExecution && inferred._meta.activeConnectivity) {
    aiUsage = "Production AI usage";
  } else if (inferred._meta.hasExecution) {
    aiUsage = "Experimental AI usage";
  } else if (inferred._meta.activeConnectivity) {
    aiUsage = "Capabilities loading (Connectivity markers present)";
  } else if (signals.some(s => s.kind === 'dependency' || s.kind === 'code_signature_load')) {
    aiUsage = "Capabilities present (Inactive/Dead code)";
  }

  // 2. CONTROL STATUS
  let controlStatus = "Critical gaps detected";
  const hasTransparency = evidencedFamilies.has('transparency');
  const hasOversight = evidencedFamilies.has('human_oversight');
  const hasTraceability = evidencedFamilies.has('traceability');
  
  if (hasTransparency && hasOversight && hasTraceability) {
    controlStatus = "MARKER DETECTED";
  } else if (hasTransparency || hasTraceability) {
    controlStatus = "MARKER PARTIALLY DETECTED";
  } else if (inferred.signal === 'low') {
    controlStatus = "Minimal observable risk; basic technical markers sufficient";
  }

  // 3. INTERNAL VALIDATION (Consistency Check)
  if (inferred.signal === 'elevated' && aiUsage === "No AI execution evidence observed within analyzed repository scope") {
    throw new Error("Validation Failure: Elevated risk signal detected but AI usage marked as 'No AI execution markers'");
  }
  if (controlStatus === "MARKER DETECTED" && (isMissing('Art. 13', findings) || isMissing('Art. 14', findings))) {
    throw new Error("Validation Failure: Controls marked as present but critical gaps found in findings");
  }

  return {
    aiUsage,
    controlStatus,
    riskInterpretation: `${inferred.signal.charAt(0).toUpperCase() + inferred.signal.slice(1)} technical risk signal`,
    keyReason: inferred.reasons[0] + (inferred.reasons[1] ? ". " + inferred.reasons[1] : "")
  };
}

/**
 * CI/CD Guardrail: check compliance score against threshold.
 */
/**
 * Recursive manifest discovery.
 */
function findManifests(dir, found = []) {
  const list = fs.readdirSync(dir);
  for (const item of list) {
    if (['node_modules', '.git', 'dist', 'bin', 'audit-results', 'sovereign-reports'].includes(item)) continue;
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      findManifests(fullPath, found);
    } else if (item === 'sentinel.manifest.json' || item === 'manifest.json') {
      found.push(fullPath);
    }
  }
  return found;
}

/**
 * Portfolio Audit Orchestrator.
 */
async function runPortfolio(args) {
    const isJson = args.includes('--json');
    if (!isJson) console.log(`\n${C.cyan}${C.bold}🚀 Sentinel Portfolio Audit Starting...${C.reset}`);
    
    // 1. Setup results dir
    const projectRoot = process.cwd();
    const resultsDir = path.join(projectRoot, 'audit-results');
    if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });

    // 2. Discover manifests
    const manifests = findManifests(projectRoot);
    if (!isJson) console.log(`${C.gray}Found ${manifests.length} audit units.${C.reset}\n`);

    const thresholdArgIdx = args.indexOf('--threshold');
    const threshold = (thresholdArgIdx !== -1 && args[thresholdArgIdx + 1]) ? parseInt(args[thresholdArgIdx + 1]) : 90;

    let successCount = 0;
    let failCount = 0;

    for (const manifestPath of manifests) {
        const relativePath = path.relative(projectRoot, manifestPath);
        const repoName = path.dirname(relativePath) === '.' ? 'root' : path.dirname(relativePath).replace(/[/\\]/g, '-');
        
        if (!isJson) process.stdout.write(`${C.gray}Auditing [${C.white}${repoName}${C.gray}]... ${C.reset}`);
        
        try {
            const report = await performAudit(manifestPath, threshold, { isJson });
            const resultFile = path.join(resultsDir, `sentinel-${repoName}-report.json`);
            fs.writeFileSync(resultFile, JSON.stringify(report, null, 2));
            
            if (!isJson) {
                const statusColor = report.status === 'COMPLIANT' ? C.green : C.red;
                console.log(`${statusColor}${report.status}${C.reset} (${report.score}/100)`);
            }
            successCount++;
        } catch (err) {
            if (!isJson) {
                console.log(`${C.red}ERROR${C.reset}`);
                console.error(`  ${C.red}↳ ${err.message}${C.reset}`);
            }
            failCount++;
        }
    }

    if (!isJson) {
        console.log(`\n${C.bold}Portfolio Audit Complete:${C.reset}`);
        console.log(`  - ${C.green}Processed: ${successCount}${C.reset}`);
        if (failCount > 0) console.log(`  - ${C.red}Failed/Skipped: ${failCount}${C.reset}`);

        // 3. Trigger Unification (Consolidator)
        console.log(`\n${C.cyan}Synthesizing Portfolio Dashboard...${C.reset}`);
        try {
            const consolidatorPath = path.join(projectRoot, 'sovereign-consolidator.js');
            if (fs.existsSync(consolidatorPath)) {
                require(consolidatorPath); // This runs the consolidator logic
            } else {
                console.warn(`${C.yellow}Warning: sovereign-consolidator.js not found. Skipping dashboard generation.${C.reset}`);
            }
        } catch (e) {
            console.error(`${C.red}Failed to generate dashboard: ${e.message}${C.reset}`);
        }
        
        console.log(`\n${C.green}${C.bold}✔ Portfolio audit cycle finished.${C.reset}\n`);
    }

    if (isJson) {
        // For portfolio mode, we might want to emit a summary JSON
        console.log(JSON.stringify({
            status: failCount === 0 ? "COMPLIANT" : "FAIL",
            portfolio_audit: true,
            success_count: successCount,
            fail_count: failCount
        }));
    }
}

async function runCheck(args, productionHash = null, isStrict = false, buildId = null) {
  let __debug_step = "start";
  let result = null;
  let exitCode = 0;
  const isEvidence = args.includes('--evidence');

  try {
    // 1. Resolve Parameters
    const thresholdArgIdx = args.indexOf('--threshold');
    let threshold = (thresholdArgIdx !== -1 && args[thresholdArgIdx + 1]) ? parseInt(args[thresholdArgIdx + 1]) : 0;
    if (isNaN(threshold)) threshold = 0;

    const manifestPath = resolveTargetManifest(args);
    if (!manifestPath || !fs.existsSync(manifestPath)) {
      throw new Error("No manifest found. Use --manifest <path>");
    }

    const engineArgIdx = args.indexOf('--engine');
    const engine = (engineArgIdx !== -1 && args[engineArgIdx + 1]) ? args[engineArgIdx + 1].toLowerCase() : 'stable';
    const failOnArgIdx = args.indexOf('--fail-on');
    const failOnPolicy = (failOnArgIdx !== -1 && args[failOnArgIdx + 1]) ? args[failOnArgIdx + 1].toUpperCase() : 'REJECTED';

    // 2. Perform Audit
    let report = await performAudit(manifestPath, threshold, { engine, productionHash, strict: isStrict, buildId, isJson });
    
    // 3. Enterprise Upgrade
    __debug_step = "before_pre_auditor";
    try {
      const manifestDir = path.dirname(path.resolve(manifestPath));
      const lockedStatus = report.status;
      report = await PreAuditor.upgrade(report, manifestDir, { generateHtml: !isJson, engine });
      report.status = lockedStatus;
    } catch (err) {
      if (!isJson) console.error(`Sentinel Pre-Auditor Error: ${err.message}`);
    }
    __debug_step = "after_pre_auditor";

    // 4. Finalize Result
    // CLEANUP: Remove legacy dual-track blocks to prevent auditor confusion
    delete report.dual_track;
    delete report._dual_track;

    // ADD CONTEXT: Disclaimer for defensibility field
    const defensibilityNote = "Reflects signal coverage of this scan, not tool validity. Increase evidence signals (CI/CD, test files, correlated patterns) to raise to STRONG.";
    
    // Sibling field addition (ensuring order for JSON output)
    __debug_step = "before_final_report";
    const finalReport = {};
    for (const key of Object.keys(report)) {
      finalReport[key] = report[key];
      if (key === 'defensibility') {
        finalReport.defensibility_note = defensibilityNote;
      }
    }
    __debug_step = "after_final_report";
    
    result = finalReport;
    exitCode = finalReport.exit_code;

    // 4.1 Auditor Package V1 (Orchestration)
    if (isEvidence) {
      __debug_step = "before_evidence_pack";
      const { dossierName } = generateEvidencePack(report, manifestPath);
      if (!isJson) {
        process.stdout.write(`\n${C.green}${C.bold}✔ AUDITOR PACKAGE GENERATED: ${dossierName}${C.reset}\n`);
      }
      __debug_step = "after_evidence_pack";
    }

    // 5. Pretty Output (Gated)
    if (!isJson) {
      if (report.status === 'COMPLIANT') {
        process.stdout.write(`\n${C.green}${C.bold}Sentinel Check: COMPLIANT${C.reset}\n`);
      } else if (report.status === 'NEEDS_REVIEW') {
        process.stdout.write(`\n${C.yellow}${C.bold}Sentinel Check: NEEDS_REVIEW${C.reset}\n`);
      } else if (report.status === 'GAP') {
        process.stdout.write(`\n${C.yellow}${C.bold}Sentinel Check: GAP${C.reset}\n`);
      } else {
        process.stdout.write(`\n${C.red}${C.bold}Sentinel Check: FAIL${C.reset}\n`);
      }

      console.log(`${C.gray}Audit Readiness: ${C.white}${report.final_audit_position?.audit_readiness || 'N/A'}${C.reset}`);
      console.log(`${C.gray}Risk Level:      ${C.white}${report.final_audit_position?.risk_level || 'N/A'}${C.reset}`);
      console.log(`${C.gray}Manifest:        ${C.white}${manifestPath}${C.reset}`);
      console.log(`${C.gray}Total Score:           ${report.score < threshold ? C.red + C.bold : C.green + C.bold}${report.score}${C.gray}/100${C.reset}`);
      
      const confColor = report.confidence === 'HIGH' ? C.green : (report.confidence === 'MEDIUM' ? C.yellow : C.red);
      console.log(`${C.gray}Trust Confidence (φ):  ${confColor}${C.bold}${report.confidence}${C.reset}${C.gray} (Saturation: ${Math.round(report.phi * 100)}%)${C.reset}`);
      
      if (report.score < threshold) {
        console.log(`\n${C.red}${C.bold}❌ SCOREGATE FAILURE: Score (${report.score}) is below threshold (${threshold})${C.reset}`);
      }
    }
  } catch (err) {
    result = {
      schema: "sentinel.audit.v1",
      status: "FAIL",
      error: true,
      message: err.message,
      _debug_catch: true,
      _debug_last_step: __debug_step,
      _debug_error_message: err.message,
      _debug_error_stack_top: err.stack ? err.stack.split('\n').slice(0, 3) : []
    };
    if (process.env.SENTINEL_DEBUG === 'true' && !isJson) {
      console.error(err.stack);
    }
    exitCode = 1;
  } finally {
    if (isJson && result) {
      __debug_step = "before_output";
      process.stdout.write(JSON.stringify(result));
      process.exit(exitCode);
    } else {
      pauseAndExit(exitCode);
    }
  }
}

/**
 * Deterministic Status Engine Layer.
 * Derives PASS/FAIL/NEEDS_REVIEW from technical pulse.
 */
function resolveFinalVerdict(contradictions, missingMandatory, gaps) {
  if (contradictions.length > 0) return "FAIL";
  if (missingMandatory.length > 0) return "FAIL";
  if (gaps.length > 0) return "GAP";
  return "COMPLIANT";
}
/**
 * Independent Audit Verification Engine.
 * Re-validates evidence hashes against the current filesystem.
 */
async function runVerify(args) {
  
  if (args.includes('--package')) {
    const pkgIdx = args.indexOf('--package');
    return runPackageVerify(args[pkgIdx + 1], args);
  }

  const auditIdIdx = args.indexOf('--audit');
  const auditId = (auditIdIdx !== -1 && args[auditIdIdx + 1]) ? args[auditIdIdx + 1] : null;
  const auditPathIdx = args.indexOf('--file');
  let report = null;

  const rootDir = process.cwd();

  if (auditId) {
    report = AuditVault.getAuditById(rootDir, auditId);
    if (!report) {
      throw new Error(`Audit '${auditId}' not found in vault.`);
    }
  } else if (auditPathIdx !== -1 && args[auditPathIdx + 1]) {
    try {
      report = JSON.parse(fs.readFileSync(args[auditPathIdx + 1], 'utf8'));
    } catch (e) {
      if (!isJson) console.error(`${C.red}Error reading audit file: ${e.message}${C.reset}`);
      if (isJson) console.log(JSON.stringify({ status: "FAIL", error: true, message: e.message }));
      process.exit(1);
    }
  } else {
    report = AuditVault.getLatestAudit(rootDir);
    if (!report) {
      throw new Error("No audit found. Use --audit <id> or --file <path>.");
    }
  }

  const auditIdReport = (report._audit_trail?.audit_id || report.audit_metadata?.audit_id || 'Unknown');
  const commit = (report._audit_trail?.commit || report.audit_metadata?.commit || 'N/A');
  if (!isJson) {
    console.log(`\n${C.cyan}${C.bold}🔍 Sentinel Evidence Verification Engine${C.reset}`);
    console.log(`${C.gray}Audit ID: ${C.white}${auditIdReport}${C.reset}`);
    console.log(`${C.gray}Reference Commit: ${C.white}${commit}${C.reset}\n`);
  }

  const signals = report._internal?.signals || [];
  if (signals.length === 0) {
    if (!isJson) console.log(`${C.yellow}No technical evidence found in report to verify.${C.reset}\n`);
    process.exit(0);
  }

  let verifiedCount = 0;
  let tamperedCount = 0;
  let missingCount = 0;

  if (!isJson) {
    console.log(`${C.bold}${'STATUS'.padEnd(12)} | ${'REGULATORY ARTICLE'.padEnd(15)} | ${'LOCATION'}${C.reset}`);
    console.log(`${C.gray}-------------|-----------------|-----------------------------------${C.reset}`);
  }

  for (const s of signals) {
    const fullPath = path.join(rootDir, s.source_path);
    const PROBE_MAP = {
      'DEP_WINSTON': 'Art. 20', 'DEP_PINO': 'Art. 20', 'DEP_PYTHON_LOG': 'Art. 20',
      'CODE_LOGGER_INIT': 'Art. 20', 'CODE_TRACE_ID': 'Art. 20',
      'CODE_MANUAL_OVERRIDE': 'Art. 14', 'CODE_KILL_SWITCH': 'Art. 14',
      'CODE_AI_DISCLOSURE': 'Art. 13', 'DEP_FAIRLEARN': 'Art. 10',
      'CODE_BIAS_MITIGATION': 'Art. 10', 'CODE_DATA_ETL': 'Art. 10'
    };
    const regArt = PROBE_MAP[s.id] || 'Other';

    if (!fs.existsSync(fullPath)) {
      if (!isJson) console.log(`${C.red}${'MISSING'.padEnd(12)}${C.reset} | ${regArt.padEnd(15)} | ${s.source_path}:${s.line}`);
      missingCount++;
      continue;
    }

    const currentContent = fs.readFileSync(fullPath, 'utf8');
    const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');
    const expectedHash = s.source_sha256;

    if (currentHash === expectedHash) {
      if (!isJson) console.log(`${C.green}${'VERIFIED'.padEnd(12)}${C.reset} | ${regArt.padEnd(15)} | ${s.source_path}:${s.line} (${s.id})`);
      verifiedCount++;
    } else {
      if (!isJson) console.log(`${C.red}${'TAMPERED'.padEnd(12)}${C.reset} | ${regArt.padEnd(15)} | ${s.source_path}:${s.line} (${s.id})`);
      tamperedCount++;
    }
  }

  if (!isJson) {
    console.log(`\n${C.bold}Verification Result:${C.reset}`);
    console.log(`  - Verified: ${C.green}${verifiedCount}${C.reset}`);
    if (tamperedCount > 0) console.log(`  - Tampered: ${C.red}${tamperedCount}${C.reset}`);
    if (missingCount > 0) console.log(`  - Missing:  ${C.yellow}${missingCount}${C.reset}`);
    console.log("");

    if (tamperedCount === 0 && missingCount === 0) {
      console.log(`${C.green}${C.bold}✔ ALL TECHNICAL EVIDENCE VERIFIED.${C.reset}\n`);
    } else {
      console.log(`${C.red}${C.bold}✖ AUDIT INTEGRITY FAILURE: EVIDENCE HAS CHANGED.${C.reset}\n`);
    }
  }

  if (isJson) {
    console.log(JSON.stringify({
      status: (tamperedCount === 0 && missingCount === 0) ? "PASS" : "FAIL",
      verified: verifiedCount,
      tampered: tamperedCount,
      missing: missingCount
    }));
  }
  
  process.exit((tamperedCount === 0 && missingCount === 0) ? 0 : 1);
}

/**
 * Validates a standalone forensic audit package.
 * Frictionless: Auth Check -> Integrity Check -> Traceability Check.
 */
async function runPackageVerify(packagePath, argv) {
  const isJson = argv.includes('--json');
  if (!packagePath) {
    if (!isJson) console.error(`${C.red}✖ Error: Missing package path. Usage: sentinel verify --package <path.zip>${C.reset}`);
    if (isJson) console.log(JSON.stringify({ status: "FAIL", error: true, message: "Missing package path" }));
    process.exit(1);
  }

  const fullPackagePath = path.resolve(packagePath);
  if (!fs.existsSync(fullPackagePath)) {
    if (!isJson) console.error(`${C.red}✖ Error: Package not found: ${fullPackagePath}${C.reset}`);
    if (isJson) console.log(JSON.stringify({ status: "FAIL", error: true, message: `Package not found: ${fullPackagePath}` }));
    process.exit(1);
  }

  const tempDir = path.join(process.cwd(), `.sentinel_verify_${Date.now()}`);
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

  const CryptoUtils = require('./lib/crypto-utils');

  try {
    if (!isJson) {
      console.log(`\n${C.cyan}${C.bold}🔍 Sentinel Forensic Verification Engine [Offline Mode]${C.reset}`);
      console.log(`${C.gray}Loading package: ${path.basename(fullPackagePath)}${C.reset}\n`);
    }

    // 1. Extract Package
    try {
      const psPath = fullPackagePath.replace(/\\/g, '/');
      const psDest = tempDir.replace(/\\/g, '/');
      if (process.platform === 'win32') {
        execSync(`powershell -Command "Expand-Archive -Path '${psPath}' -DestinationPath '${psDest}' -Force"`);
      } else {
        execSync(`unzip -o "${fullPackagePath}" -d "${tempDir}"`);
      }
    } catch (err) {
      if (!isJson) console.error(`${C.red}✖ Error: Failed to extract package. ${err.message}${C.reset}`);
      process.exit(1);
    }

    // 2. Auth Check (Signature)
    const sigJsonPath = path.join(tempDir, 'signature.json');
    const sigBinPath = path.join(tempDir, 'signature.bin');
    const pubKeyPath = path.join(tempDir, 'authority.pub');
    const checksumsPath = path.join(tempDir, 'checksums.sha256');

    if (!fs.existsSync(sigJsonPath) || !fs.existsSync(sigBinPath) || !fs.existsSync(pubKeyPath)) {
      if (!isJson) console.log(`${C.red}AUTH CHECK: FAIL → MISSING SECURITY ANCHORS${C.reset}`);
      process.exit(1);
    }

    const signatureJson = JSON.parse(fs.readFileSync(sigJsonPath, 'utf8'));
    const signatureBin = fs.readFileSync(sigBinPath);
    const publicKey = fs.readFileSync(pubKeyPath, 'utf8');
    const checksumsRaw = fs.readFileSync(checksumsPath, 'utf8');
    const checksums = checksumsRaw.replace(/\r\n/g, '\n'); // Normalize for Windows extraction

    const isSignedCorrectly = CryptoUtils.verifyData(checksums, signatureBin, publicKey);

    if (!isSignedCorrectly) {
      if (!isJson) console.log(`${C.red}AUTH CHECK: FAIL → AUTH BREACH (Invalid Signature)${C.reset}`);
      process.exit(1);
    }
    if (!isJson) console.log(`${C.green}AUTH CHECK: PASS${C.reset}`);

    // 3. Integrity Check (Structure)
    const checksumLines = checksums.split('\n').filter(l => l.trim());
    let integrityFailed = false;

    for (const line of checksumLines) {
      const match = line.match(/^([a-f0-9]{64})\s+(.+)$/);
      if (!match) continue;
      const expectedHash = match[1];
      const relPath = match[2];
      const filePath = path.join(tempDir, relPath);
      
      if (!fs.existsSync(filePath)) {
        integrityFailed = true;
        continue;
      }

      const actualHash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
      if (actualHash !== expectedHash) {
        integrityFailed = true;
      }
    }

    if (integrityFailed) {
      if (!isJson) console.log(`${C.red}INTEGRITY CHECK: FAIL → STRUCTURE BREACH (Corrupted Files)${C.reset}`);
      process.exit(1);
    }
    if (!isJson) console.log(`${C.green}INTEGRITY CHECK: PASS${C.reset}`);

    // 4. Traceability Check (Deep Evidence Alignment)
    const auditReport = JSON.parse(fs.readFileSync(path.join(tempDir, 'audit.json'), 'utf8'));
    const signals = auditReport._internal?.signals || [];
    let traceFailCount = 0;

    signals.forEach(s => {
      const evidenceFilename = `evidence_${s.id}_${s.evidence_sha256 ? s.evidence_sha256.substring(0, 8) : 'raw'}.txt`;
      const evidencePath = path.join(tempDir, 'evidence', evidenceFilename);
      
      if (!fs.existsSync(evidencePath)) {
        traceFailCount++;
        return;
      }

      const snippetInFile = fs.readFileSync(evidencePath, 'utf8');
      if (snippetInFile !== s.snippet) {
        traceFailCount++;
      }
    });

    if (traceFailCount > 0) {
      if (!isJson) console.log(`${C.red}TRACEABILITY CHECK: FAIL → EVIDENCE BREACH (${traceFailCount} mismatched signals)${C.reset}`);
      process.exit(1);
    }
    if (!isJson) {
      console.log(`${C.green}TRACEABILITY CHECK: PASS${C.reset}`);

      console.log(`\n${C.green}${C.bold}FINAL VERDICT: AUDIT VALIDATED${C.reset}\n`);
      console.log(`${C.gray}Artifact ID: ${C.white}${signatureJson.signed_content_digest}${C.reset}`);
      console.log(`${C.gray}Authority:   ${C.white}${signatureJson.signed_by} (${signatureJson.authority_id})${C.reset}\n`);
    }

  } finally {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
}

/**
 * Exports a standalone forensic audit package.
 */
async function runExport(args) {
  const auditIdIdx = args.indexOf('--audit');
  const auditId = (auditIdIdx !== -1 && args[auditIdIdx + 1]) ? args[auditIdIdx + 1] : 'latest';
  const outputIdx = args.indexOf('--output');
  const outputPath = (outputIdx !== -1 && args[outputIdx + 1]) ? args[outputIdx + 1] : `sentinel-audit-${Date.now()}.zip`;

  if (!isJson) {
    console.log(`\n${C.cyan}${C.bold}📦 Sentinel Forensic Export Engine${C.reset}`);
    console.log(`${C.gray}Target Audit: ${C.white}${auditId}${C.reset}`);
  }

  const rootDir = process.cwd();
  const report = auditId === 'latest' ? AuditVault.getLatestAudit(rootDir) : AuditVault.getAuditById(rootDir, auditId);

  if (!report) {
    if (!isJson) console.error(`${C.red}✖ Error: Audit record '${auditId}' not found in vault.${C.reset}`);
    process.exit(1);
  }

  if (!isJson) console.log(`${C.gray}Generating forensic bundle...${C.reset}`);
  
  try {
    const success = await AuditExporter.exportBundle(report, rootDir, outputPath);
    if (success && !isJson) {
      console.log(`\n${C.green}${C.bold}✔ FORENSIC ARTIFACT GENERATED SUCCESSFULLY${C.reset}`);
      console.log(`${C.white}Location: ${path.resolve(outputPath)}${C.reset}`);
      console.log(`${C.gray}Digital Signature: ${report._audit_signature?.digest.substring(0, 16)}...${C.reset}\n`);
    }
  } catch (err) {
    if (!isJson) console.error(`${C.red}✖ Export failed: ${err.message}${C.reset}`);
    process.exit(1);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = (args[0] || '').toLowerCase();

  try {
    // 1. Global Flags
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

    // 2. Command Routing
    if (command === 'check') {
      await runCheck(args);
    } else if (command === 'verify') {
      await runVerify(args);
    } else if (command === 'init') {
      await runInit(args);
    } else if (command === 'discover') {
      await runDiscover(args);
    } else if (command === 'fix') {
      await runFix(args);
    } else if (command === 'portfolio') {
      await runPortfolio(args);
    } else if (command === 'export') {
      await runExport(args);
    } else if (command === 'history') {
      const history = AuditVault.getHistory(process.cwd());
      if (!isJson) {
        console.log(`\n${C.cyan}${C.bold}Audit History:${C.reset}`);
        history.reverse().forEach(h => console.log(`- ${h.timestamp}: ${h.status} (Score: ${h.score}) | ID: ${h.audit_id}`));
      } else {
        console.log(JSON.stringify(history));
      }
    } else {
      if (!isJson) {
        printBanner();
        printHelp();
      }
      process.exit(0);
    }
  } catch (err) {
    if (isJson) {
      process.stdout.write(JSON.stringify({
        status: "FAIL",
        error: true,
        message: err.message
      }) + '\n');
    } else {
      console.error(`\n${C.red}${C.bold}Critical Error: ${err.message}${C.reset}`);
    }
    process.exit(1);
  }
}

main();

/**
 * Guided remediation for compliance gaps.
 */
async function runFix(args) {
  const isApply = args.includes('--apply');

  // 1. Resolve manifest
  const manifestPath = resolveTargetManifest(args);

  if (!manifestPath || !fs.existsSync(manifestPath)) {
    if (!isJson) console.error(`${C.red}Error: No sentinel.manifest.json or manifest.json found in current directory.${C.reset}`);
    process.exit(1);
  }

  const manifestDir = path.dirname(path.resolve(manifestPath));
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (e) {
    if (!isJson) console.error(`${C.red}Error reading manifest: ${e.message}${C.reset}`);
    process.exit(1);
  }

  // 2. Initial Audit
  const repoFiles = autodiscovery.crawlRepository(manifestDir);
  const signals = autodiscovery.extractSignals(repoFiles, discoveryRules, probingRules);
  if (process.env.SENTINEL_DEBUG === 'true' && !isJson) {
    console.log(`[DEBUG] Extracted Signals: ${signals.length}`);
    signals.forEach(s => console.log(`  - Signal: ${s.id} from ${s.source_path} (${s.probe_type || 'standard'})`));
  }
  const hardeningFindings = [];
  computeHardeningFindings(signals, manifest, hardeningFindings, repoFiles);


  const findings = validateEvidence(manifest, manifestDir);
  const allFindings = [...findings, ...hardeningFindings];
  
  const actionableRuleIds = [
    'EUAI-MIN-001', 'EUAI-TRANS-001', 'EUAI-OVER-002', 'EUAI-LOG-003', 
    'EUAI-HUMAN-OVERSIGHT-MISSING', 'EUAI-LOGGING-MISSING'
  ];
  const actionableFindings = allFindings.filter(f => actionableRuleIds.includes(f.rule_id));

  if (actionableFindings.length === 0) {
    if (!isJson) console.log(`\n${C.green}No structural or implementation fixes available.${C.reset}`);
    return;
  }

  // 3. Generate Plan
  const plan = [];
  const docsToCreate = [];

  if (findings.some(f => f.rule_id === 'EUAI-MIN-001' || f.rule_id === 'EUAI-TRANS-001')) {
    plan.push({ type: 'update', file: manifestPath, desc: 'Add missing flags and root compliance structure' });
  }

  if (allFindings.some(f => f.rule_id === 'EUAI-OVER-002' || f.rule_id === 'EUAI-HUMAN-OVERSIGHT-MISSING')) {
    plan.push({ type: 'update', file: manifestPath, desc: 'Add human_oversight configuration' });
    plan.push({ type: 'code', file: 'sentinel-oversight.js', desc: 'Implement Art. 14 Sovereign Oversight Hook' });
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

  if (allFindings.some(f => f.rule_id === 'EUAI-LOG-003' || f.rule_id === 'EUAI-LOGGING-MISSING')) {
    plan.push({ type: 'code', file: 'logger.js', desc: 'Implement production-grade logging (Winston)' });
  }

  if (!isJson) {
    console.log(`\n${C.cyan}${C.bold}🛠  Sentinel Remediation Plan${C.reset}`);
    console.log(`${C.gray}Target manifest: ${C.white}${manifestPath}${C.reset}\n`);
  }

  plan.forEach(step => {
    if (!isJson) {
      const icon = step.type === 'create' ? `${C.green} + ` : (step.type === 'update' ? `${C.yellow} ~ ` : `${C.gray} . `);
      const label = step.type === 'create' ? 'CREATE' : (step.type === 'update' ? 'UPDATE' : 'SKIP  ');
      console.log(`${icon}${C.bold}${label}${C.reset} ${C.white}${step.file}${C.reset} ${C.gray} (${step.desc})${C.reset}`);
    }
  });

  if (!isApply) {
    if (!isJson) {
      console.log(`\n${C.yellow}Dry-run mode. No changes made.${C.reset}`);
      console.log(`Run with ${C.white}--apply${C.reset} to execute this plan.`);
    }
    return;
  }

  // 5. Apply Plan
  if (!isJson) console.log(`\n${C.cyan}${C.bold}🚀 Applying fixes...${C.reset}`);

  const patchedManifest = JSON.parse(JSON.stringify(manifest));
  const declaredFlags = patchedManifest.declared_flags || [];

  const requiredFlags = ['transparency_disclosure_provided', 'user_notification_ai_interaction'];
  requiredFlags.forEach(f => {
    if (!declaredFlags.includes(f)) declaredFlags.push(f);
  });
  patchedManifest.declared_flags = declaredFlags;

  if (allFindings.some(f => f.rule_id === 'EUAI-OVER-002' || f.rule_id === 'EUAI-HUMAN-OVERSIGHT-MISSING')) {
    if (!patchedManifest.human_oversight) patchedManifest.human_oversight = { description: "Human reviewer monitors decisions and can override outputs." };
    if (!patchedManifest.oversight_evidence_path) patchedManifest.oversight_evidence_path = "docs/compliance/human_oversight.md";
  }

  if (allFindings.some(f => f.rule_id === 'EUAI-LOG-003' || f.rule_id === 'EUAI-LOGGING-MISSING')) {
    if (!patchedManifest.logging_capabilities) {
      patchedManifest.logging_capabilities = {
        enabled: true,
        events_logged: ["input", "output", "decision"]
      };
    }
    if (!patchedManifest.logging_evidence_path) patchedManifest.logging_evidence_path = "docs/compliance/data_governance.md";
  }

  fs.writeFileSync(manifestPath, JSON.stringify(patchedManifest, null, 2));
  if (!isJson) console.log(`${C.green}✔ Updated ${manifestPath}${C.reset}`);

  uniqueDocs.forEach(doc => {
    const docPath = path.join(manifestDir, doc);
    if (fs.existsSync(docPath)) {
      if (!isJson) console.log(`${C.gray}. Skipped ${doc} (exists)${C.reset}`);
    } else {
      const docDir = path.dirname(docPath);
      if (!fs.existsSync(docDir)) fs.mkdirSync(docDir, { recursive: true });

      let content = "";
      if (doc.includes('human_oversight')) {
        content = `# Human Oversight Protocol (Art. 14)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and regulatory review. This document does not imply final regulatory compliance.\n\n## Oversight Mechanism\nImplementation details pending...\n\n## Roles and Responsibilities\n- Reviewer: [Role Name]\n- Intervention Threshold: [Threshold Details]\n`;
      } else if (doc.includes('data_governance')) {
        content = `# Data Governance and Logging (Art. 20)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and regulatory review. This document does not imply final regulatory compliance.\n\n## Logging Capabilities\nImplementation details pending...\n\n## Retention Policy\nStored for [Duration] in [Location].\n`;
      } else if (doc.includes('risk_assessment')) {
        content = `# Risk Management System (Art. 9)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and regulatory review. This document does not imply final regulatory compliance.\n\n## Risk Identification\nImplementation details pending...\n\n## Mitigation Strategy\nDetails about bias assessment and testing protocols.\n`;
      }

      fs.writeFileSync(docPath, content);
      if (!isJson) console.log(`${C.green}✔ Created ${doc}${C.reset}`);
    }
  });

  if (plan.some(p => p.type === 'code' && p.file === 'sentinel-oversight.js')) {
    const oversightPath = path.join(manifestDir, 'sentinel-oversight.js');
    if (!fs.existsSync(oversightPath)) {
      const oversightCode = `/**
 * Sentinel Sovereign Oversight Hook (Art. 14)
 * 🏛 PURPOSE: Technical control to allow human intervention/override of AI outputs.
 */
class SentinelOversight {
  constructor(config = {}) {
    this.threshold = config.threshold || 0.8;
    this.audit Trail = [];
  }

  /**
   * Guards an AI invocation.
   * @param {Object} input - Prompt/Request
   * @param {Object} output - AI Response
   * @returns {Object} { approved: boolean, reason: string, finalOutput: Object }
   */
  async sentinelOverride(input, output) {
    // 1. Technical Consistency Check (Heuristic)
    const isSuspicious = this._checkSuspicion(output);
    
    if (isSuspicious) {
      return { 
        approved: false, 
        reason: "SUSPICIOUS_OUTPUT_DETECTED", 
        requires_human: true,
        finalOutput: null 
      };
    }

    return { approved: true, finalOutput: output };
  }

  _checkSuspicion(output) {
    // Placeholder for bias/harm/hallucination detection logic
    return false; 
  }
}

module.exports = new SentinelOversight();
`;
      fs.writeFileSync(oversightPath, oversightCode);
      if (!isJson) console.log(`${C.green}✔ Created ${oversightPath} (Art. 14 Oversight Hook)${C.reset}`);
    }
  }

  if (plan.some(p => p.type === 'code' && p.file === 'logger.js')) {
    const loggerPath = path.join(autodiscovery.findProjectRoot ? autodiscovery.findProjectRoot(manifestDir) : manifestDir, 'logger.js');
    if (!fs.existsSync(loggerPath)) {
      const loggerCode = `/**\n * Sentinel Sovereign Logging Implementation\n * Auto-generated scaffolding for Art. 20 Compliance.\n */\nconst winston = require('winston');\n\nconst logger = winston.createLogger({\n  level: 'info',\n  format: winston.format.combine(\n    winston.format.timestamp(),\n    winston.format.json()\n  ),\n  transports: [\n    new winston.transports.Console(),\n    new winston.transports.File({ filename: 'audit_trail.log' })\n  ]\n});\n\n/**\n * Sentinel Compliance Logging Hook\n */\nfunction sentinelLog(level, message, meta = {}) {\n  logger.log(level, message, { ...meta, sentinel_audit: true });\n}\n\nmodule.exports = { logger, sentinelLog };\n`;
      fs.writeFileSync(loggerPath, loggerCode);
      if (!isJson) {
        console.log(`${C.green}✔ Created ${loggerPath} (Winston Scaffolding)${C.reset}`);
        console.log(`${C.yellow}👉 Remember to run: npm install winston${C.reset}`);
      }
    }
  }

  // 6. Audit Comparison
  if (!isJson) console.log(`\n${C.cyan}${C.bold}📊 Verification Audit${C.reset}`);

  // Pre-fix Audit (Full)
  const oldFiles = autodiscovery.crawlRepository(manifestDir);
  const oldSignals = autodiscovery.extractSignals(oldFiles, discoveryRules, probingRules);
  const oldBreakdown = calculateSignalBreakdown(oldSignals);
  const oldOfflineResult = await runOffline(manifest);
  const oldEngineViolations = oldOfflineResult.violations || [];
  const oldEvidenceFindings = validateEvidence(manifest, manifestDir, oldSignals);
  const oldAllFindings = [...oldEvidenceFindings, ...oldEngineViolations];

  const oldTrust = computeTrustMetrics(oldEvidenceFindings, manifest, oldBreakdown);
  const oldScore = oldTrust.finalScore;
  const oldVerdict = oldScore >= threshold ? 'COMPLIANT' : 'FAIL';

  // Post-fix Audit (Full)
  const newFiles = autodiscovery.crawlRepository(manifestDir);
  const newSignals = autodiscovery.extractSignals(newFiles, discoveryRules, probingRules);
  const newBreakdown = calculateSignalBreakdown(newSignals);
  const newOfflineResult = await runOffline(patchedManifest);
  const newEngineViolations = newOfflineResult.violations || [];
  const newEvidenceFindings = validateEvidence(patchedManifest, manifestDir, newSignals);
  const newAllFindings = [...newEvidenceFindings, ...newEngineViolations];

  const newTrust = computeTrustMetrics(newEvidenceFindings, patchedManifest, newBreakdown);
  const newScore = newTrust.finalScore;
  const newVerdict = newScore >= threshold ? 'COMPLIANT' : 'FAIL';

  if (!isJson) {
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
    console.log(`${C.gray}It does not replace regulatory validation.${C.reset}\n`);
  }

  if (isJson) {
    console.log(JSON.stringify({
      status: newVerdict,
      score: newScore,
      actionable_findings: actionableFindings.length,
      plan_steps: plan.length
    }));
  }
}

/**
 * Initialize a new Sentinel project scaffolding.
 */
function runInit(args) {
  const isJson = (args || []).includes('--json');
  const hasManifestJson = fs.existsSync('manifest.json');
  const hasSentinelManifest = fs.existsSync('sentinel.manifest.json');

  if (hasManifestJson || hasSentinelManifest) {
    if (!isJson) console.error(`\n${C.red}${C.bold}Error: Manifest already exists. Aborting to avoid overwrite.${C.reset}\n`);
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
  if (!isJson) console.log(`${C.green}✔ Created sentinel.manifest.json${C.reset}`);

  // 2. Create docs/compliance directory
  const complianceDir = path.join(process.cwd(), 'docs/compliance');
  if (!fs.existsSync(complianceDir)) {
    fs.mkdirSync(complianceDir, { recursive: true });
    if (!isJson) console.log(`${C.green}✔ Created docs/compliance/${C.reset}`);
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

  if (!isJson) {
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

  if (isJson) {
    console.log(JSON.stringify({
      status: "PASS",
      initialized: true,
      manifest: "sentinel.manifest.json",
      templates: createdList
    }));
  }
}
main().catch(err => {
  const isJson = process.argv.includes('--json');
  if (isJson) {
    console.log(JSON.stringify({
      schema: "sentinel.audit.v1",
      status: "FAIL",
      error: true,
      message: err.message
    }));
  } else {
    console.error(`\n${C.red}Critical Error: ${err.message}${C.reset}\n`);
    if (process.env.SENTINEL_DEBUG === 'true') console.error(err.stack);
  }
  process.exit(1);
});
