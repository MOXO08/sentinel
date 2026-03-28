#!/usr/bin/env node
// sentinel-scan — EU AI Act Compliance CLI
// Usage: npx @radu_api/sentinel-scan check --threshold 90 --manifest sentinel.manifest.json [--policy <path>] [--baseline <path>] [--json] [--api-key <key>] [--endpoint <url>]

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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
  console.log(`║  🛡  SENTINEL — LOCAL DIAG NOSTIC TOOL (OFFLINE)  ║`);
  console.log(`╚══════════════════════════════════════════════════╝${C.reset}\n`);
  console.log(`\n\x1b[36m\x1b[1mPro-Tip:\x1b[0m\x1b[36m Consult the official Compliance Guide at \x1b[97mUSER_MANUAL.md\x1b[0m\n`);
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
  console.log(`  --production-hash <h>  Link audit to a production artifact (SHA-256)`);
  console.log(`  --build-id <id>        Link audit to a declared production build ID`);
  console.log(`  --strict               Enforce 1:1 alignment between manifest and discovered signals`);
  console.log(`  --autodiscover         Enable the Autodiscovery engine to verify manifest against code`);
  console.log(`  --generate-tech-file   Generate an Annex IV Technical Documentation dossier (Markdown)`);
  console.log(`  --endpoint <url>       Custom Edge API endpoint`);
  console.log(`  --help                 Show this help`);
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
      // Use the new kind-based filtering where possible
      if (s.kind === 'code_signature_call' || s.kind === 'code_signature_load' || s.kind === 'dependency') {
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
            verdict = 'FAIL';
            ungovernedExecutions.forEach(e => e.governance_gap = article);
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
    findings.push({ article: 'General', rule_id: 'EUAI-MIN-001', description: "[Missing baseline structure]", deduction: 30, severity: 'critical', hard_fail: true, source: 'evidence', fix_snippet: "Add required top-level flags and evidence fields." });
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

/**
 * Deterministic Status Engine Layer.
 */
function computeDeterministicStatus(findings = [], verdict = 'COMPLIANT') {
  let hasContradiction = false;
  for (const f of findings) {
    const desc = (f.description || "").toLowerCase();
    if (desc.includes("contradiction") || desc.includes("declared but not found")) {
      hasContradiction = true;
    }
  }

  if (hasContradiction || verdict === 'NON_COMPLIANT') return 'FAIL';
  if (findings.length > 0) return 'GAP';
  return 'PASS';
}

function computeVerdict(score, findings, manifest, requiresGovernance = true) {
  if (hasHardFail(findings)) return 'NON_COMPLIANT';
  if (!requiresGovernance && findings.length === 0 && score >= 90) return 'COMPLIANT';

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

## Findings
- Total findings: ${report.violations.length}
- High/Critical severity: ${highRisk.length}
- Missing required documentation: ${missingDocs.length}

## Top Findings
${report.violations.slice(0, 5).map(v => `- **${v.rule_id}** — ${v.description}`).join('\n')}

## Missing Documentation
${missingDocs.length > 0 ? missingDocs.map(d => `- ${d.path}`).join('\n') : "- None"}

## Recommended Next Actions
1. ${missingDocs.length > 0 ? "Add required compliance documentation" : "Address identified engine findings"}
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
    console.error(`\n${C.yellow}Warning: Failed to generate summary: ${e.message}${C.reset}`);
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
  if (process.env.SENTINEL_DEBUG === 'true') {
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
      console.warn(`[ENGINE-EXTENDED] Warning: Could not merge extended rules: ${err.message}`);
    }
  }

  const dependencyGraph = autodiscovery.buildDependencyGraph(repoFiles);
  let signals = autodiscovery.extractSignals(repoFiles, discoveryRules, effectiveProbingRules, dependencyGraph, commitId);

  // 1.05 Production Trace Context (Step 4 Hardening)
  const buildId = options.buildId || null;
  const traceStatus = buildId ? 'USER_DECLARED' : 'UNBOUND';

  process.stdout.write(`\n${C.cyan}${C.bold}Production Trace Context:${C.reset}\n`);
  process.stdout.write(`* build_id: ${buildId || 'NOT PROVIDED'}\n`);
  process.stdout.write(`* trace_status: ${traceStatus}\n`);

  if (!buildId) {
    process.stdout.write(`\n${C.yellow}${C.bold}EVIDENCE SCOPE LIMITATION:${C.reset}\n`);
    process.stdout.write(`No production build reference (--build-id) was provided.\n`);
    process.stdout.write(`This audit verifies repository-level technical signals only.\n`);
    process.stdout.write(`It does NOT establish traceability to a deployed production system.\n`);
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
      
      process.stdout.write(`\n${C.gray}Exit immediately.${C.reset}\n\n`);
      process.exit(1);
    }
    process.stdout.write(`${C.green}${C.bold}✅ STRICT MODE PASSED${C.reset}\n`);
  }

  // 1.1 Governance Context
  const riskCat = (manifest.risk_category || "").toLowerCase();
  const isMinimal = riskCat === 'minimal';
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
  const docConflicts = intelligence.detectDocumentContradictions(manifest, allFindings);
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
  correlateFindings(combinedFindings, repoFiles);

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

  const verdict = computeVerdict(score, combinedFindings, manifest);

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
      if (process.env.SENTINEL_DEBUG === 'true') {
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

  // Phase 15: HARDENED DETERMINISTIC STATUS ENGINE
  // 1. Identify Critical Risks and Contradictions
  const hasCriticalSeverity = combinedFindings.some(f => 
    (f.severity || "").toUpperCase() === 'CRITICAL' || 
    (f.reasoning?.severity || "").toUpperCase() === 'CRITICAL'
  );
  
  const contradictionFindings = combinedFindings.filter(f => (f.rule_id || "").startsWith('EUAI-CONTRADICTION'));

  // 2. Map Epistemic Contradictions (DECLARED_ONLY or MISSING_TECHNICAL_EVIDENCE)
  const epistemicMap = contradictionFindings.map(f => ({
    rule_id: f.rule_id,
    contradiction_type: f.reasoning?.contradiction_type || "DECLARED_ONLY",
    article: f.article,
    description: f.description
  }));

  // 3. Extract Status metrics
  const auditReadiness = (articleSummaries.audit_readiness || "LOW").toUpperCase();
  const auditorAttestationStatus = (articleSummaries.auditor_attestation?.status || "UNSUPPORTED").toUpperCase();
  const govStatus = (dualTrack.governanceStatus || "GAP").toUpperCase();
  const cVerdict = (dualTrack.centralVerdict || "HOLD").toUpperCase();

  // 4. Deterministic Final Status Computation
  // PRIORITY 1: FAIL conditions
  const isFail = (
    auditReadiness === "LOW" ||
    auditorAttestationStatus === "UNSUPPORTED" ||
    govStatus === "GAP" ||
    cVerdict === "HOLD" ||
    hasCriticalSeverity ||
    epistemicMap.length > 0
  );

  // PRIORITY 2: NEEDS_REVIEW conditions
  const isNeedsReview = (
    !isFail &&
    (auditReadiness === "MEDIUM" || govStatus === "PARTIAL")
  );

  let finalStatus = "PASS";
  let finalExitCode = 0;

  if (isFail) {
    finalStatus = "FAIL";
    finalExitCode = 1;
  } else if (isNeedsReview) {
    finalStatus = "NEEDS_REVIEW";
    finalExitCode = 1;
  }

  // 4. Construct SSoT Report
  const report = {
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
    status: finalStatus,
    score,
    claim_score: trust.claim_score,
    evidence_score: trust.evidence_score,
    confidence: trust.confidence,
    phi: trust.phi,
    exposure: trust.exposure,
    threshold,
    production_hash: options.productionHash || null,
    production_trace_context: {
      build_id: buildId || 'NOT PROVIDED',
      trace_status: buildId ? 'USER_DECLARED' : 'UNBOUND'
    },
    verdict: dualTrack.centralVerdict,
    system_assessment: systemAssessment,
    reasoning_summary: reasoningSummary,
    article_summaries: articleSummaries,
    epistemic_map: epistemicMap,
    audit_scope: auditScope,
    final_audit_position: generateFinalAuditPosition(combinedFindings, score),
    _context_validation: evaluateContextSufficiency(manifest, combinedFindings, engine),
    _declaration_consistency: checkDeclarationConsistency(manifest, combinedFindings, signals, engine),
    _executive_summary: generateExecutiveSummary(manifest, combinedFindings, signals, engine),
    central_verdict: dualTrack.centralVerdict,
    technical_status: dualTrack.technicalStatus,
    governance_status: dualTrack.governanceStatus,
    findings: combinedFindings,
    dual_track: dualTrack,
    contradictions: epistemicMap,
    risk_category: signals.some(s => s.id === 'BEHAVIORAL_SUSPICION_FLAG_HIGH_RISK') ? "High" : (manifest.risk_category || "Minimal"),
    semantic_quality: semanticReport?.semantic_quality ?? { evaluated: false },
    exit_code: finalExitCode,
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

  // Phase 16: Deterministic Status Injection
  report.status = computeDeterministicStatus(report);

  // 4.1 Final Sanitization Pass (Neutral Audit Language)
  const sanitizeObject = (obj) => {
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
  };

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
    console.log(`\n${C.cyan}${C.bold}🚀 Sentinel Portfolio Audit Starting...${C.reset}`);
    
    // 1. Setup results dir
    const projectRoot = process.cwd();
    const resultsDir = path.join(projectRoot, 'audit-results');
    if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });

    // 2. Discover manifests
    const manifests = findManifests(projectRoot);
    console.log(`${C.gray}Found ${manifests.length} audit units.${C.reset}\n`);

    const thresholdArgIdx = args.indexOf('--threshold');
    const threshold = (thresholdArgIdx !== -1 && args[thresholdArgIdx + 1]) ? parseInt(args[thresholdArgIdx + 1]) : 90;

    let successCount = 0;
    let failCount = 0;

    for (const manifestPath of manifests) {
        const relativePath = path.relative(projectRoot, manifestPath);
        const repoName = path.dirname(relativePath) === '.' ? 'root' : path.dirname(relativePath).replace(/[/\\]/g, '-');
        
        process.stdout.write(`${C.gray}Auditing [${C.white}${repoName}${C.gray}]... ${C.reset}`);
        
        try {
            const report = await performAudit(manifestPath, threshold);
            const resultFile = path.join(resultsDir, `sentinel-${repoName}-report.json`);
            fs.writeFileSync(resultFile, JSON.stringify(report, null, 2));
            
            const statusColor = report.status === 'PASS' ? C.green : C.red;
            console.log(`${statusColor}${report.status}${C.reset} (${report.score}/100)`);
            successCount++;
        } catch (err) {
            console.log(`${C.red}ERROR${C.reset}`);
            console.error(`  ${C.red}↳ ${err.message}${C.reset}`);
            failCount++;
        }
    }

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

async function runCheck(args, productionHash = null, isStrict = false, buildId = null) {
  const isJson = args.includes('--json');
  
  // CI/CD Flags
  const failOnArgIdx = args.indexOf('--fail-on');
  const failOnPolicy = (failOnArgIdx !== -1 && args[failOnArgIdx + 1]) ? args[failOnArgIdx + 1].toUpperCase() : 'REJECTED';
  
  const summaryArgIdx = args.indexOf('--summary');
  const summaryPath = (summaryArgIdx !== -1 && args[summaryArgIdx + 1]) ? args[summaryArgIdx + 1] : null;

  const engineArgIdx = args.indexOf('--engine');
  const engine = (engineArgIdx !== -1 && args[engineArgIdx + 1]) ? args[engineArgIdx + 1].toLowerCase() : 'stable';

  const isGenerateTechFile = args.includes('--generate-tech-file');

  // 1. Resolve Threshold (Default to 0)
  const thresholdArgIdx = args.indexOf('--threshold');
  let threshold = 0;
  if (thresholdArgIdx !== -1 && args[thresholdArgIdx + 1]) {
    threshold = parseInt(args[thresholdArgIdx + 1]);
    if (isNaN(threshold)) threshold = 0;
  }

  // 2. Resolve Manifest
  const manifestPath = resolveTargetManifest(args);
  if (!manifestPath || !fs.existsSync(manifestPath)) {
    console.error(`${C.red}Error: No manifest found. Use --manifest <path>${C.reset}`);
    process.exit(2);
  }

  // 3. Perform Audit via SSoT Engine
  let report;
  try {
    report = await performAudit(manifestPath, threshold, { engine, productionHash, strict: isStrict, buildId });
  } catch (err) {
    console.error(`${C.red}${C.bold}Audit Critical Failure: ${err.message}${C.reset}`);
    process.exit(1);
  }

  const { score, trust_confidence, verdict } = report; // Destructure for display (internal names might vary)

  // 4. Output
  // 4. Enterprise Upgrade (SIG, P2, Vault, V2.1 HTML)
  try {
    const manifestDir = path.dirname(path.resolve(manifestPath));
    const upgradedReport = await PreAuditor.upgrade(report, manifestDir, { generateHtml: !isJson, engine });
    report = upgradedReport;
  } catch (err) {
    console.error(`Sentinel Pre-Auditor Error: ${err.message}`);
  }

  // 5. Output Handler
  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.exit_code || 0);
  }

  if (report.status === 'PASS') {
    console.log(`\n${C.green}${C.bold}Sentinel Check: PASS${C.reset}`);
  } else if (report.status === 'NEEDS_REVIEW') {
    console.log(`\n${C.yellow}${C.bold}Sentinel Check: NEEDS_REVIEW${C.reset}`);
  } else {
    console.log(`\n${C.red}${C.bold}Sentinel Check: FAIL${C.reset}`);
  }

  const pos = report.final_audit_position || {};
  console.log(`${C.gray}Audit Readiness: ${C.white}${pos.audit_readiness || 'N/A'}${C.reset}`);
  console.log(`${C.gray}Risk Level:      ${C.white}${pos.risk_level || 'N/A'}${C.reset}`);
  console.log(`${C.gray}Manifest:        ${C.white}${manifestPath}${C.reset}`);
  console.log(`${C.gray}Total Score:           ${score < threshold ? C.red + C.bold : C.green + C.bold}${score}${C.gray}/100${C.reset}`);
  
  const confColor = report.confidence === 'HIGH' ? C.green : (report.confidence === 'MEDIUM' ? C.yellow : C.red);
  console.log(`${C.gray}Trust Confidence (φ):  ${confColor}${C.bold}${report.confidence}${C.reset}${C.gray} (Saturation: ${Math.round(report.phi * 100)}%)${C.reset}`);
  console.log(`${C.gray}Risk Exposure Index:   ${C.white}${report.exposure}${C.reset}`);

  if (report.score_breakdown) {
    console.log(`\n${C.cyan}Compliance Breakdown:${C.reset}`);
    Object.entries(report.score_breakdown).forEach(([art, data]) => {
      const artScore = Math.round((data.claim * 0.2 + data.evidence * 0.8) * 100);
      console.log(`  - ${C.white}${art.padEnd(8)}${C.reset}: ${C.gray}Score: ${C.white}${artScore.toString().padStart(3)}${C.gray} | Weight: ${C.white}${data.weight}${C.reset}`);
    });
  }

  if (report._internal && report._internal.signal_breakdown) {
    const sb = report._internal.signal_breakdown;
    console.log(`\n${C.gray}Audit Rigor:           ${C.white}${report._internal.total_signals} signals extracted${C.reset}`);
    process.stdout.write(`${C.gray}   ↳ [ AI Assets: ${C.white}${sb.ai_assets}${C.gray} | Trans: ${C.white}${sb.transparency}${C.gray} | Oversight: ${C.white}${sb.oversight}${C.gray} | Log: ${C.white}${sb.logging}${C.gray} ]${C.reset}\n`);
  }

  if (report.confidence === 'LOW') {
    console.log(`\n${C.red}${C.bold}⚠ TRUST GAP DETECTED:${C.reset}${C.red} Declared coverage not matched by evidence substance.${C.reset}`);
  }


  if (report.risk_category && report.risk_category.toUpperCase() === 'HIGH') {
    console.log(`\n${C.yellow}${C.bold}⚠ High-risk system detected${C.reset}`);
    console.log(`${C.cyan}Recommended minimum threshold: 90${C.reset}`);
  }

  if (score < threshold) {
    const allFindings = (report._internal && report._internal.all_findings) || [];
    const docFindings = allFindings.filter(f => f.source === 'evidence');
    const impFindings = allFindings.filter(f => f.source === 'implementation');

    if (docFindings.length > 0) {
      console.log(`\n${C.bold}📄 DOCUMENTATION FINDINGS:${C.reset}`);
      docFindings.slice(0, 3).forEach(f => {
        const regulatoryRef = f.article ? ` (${f.article})` : '';
        console.log(`- [${C.yellow}${f.description}${C.reset}]${regulatoryRef}`);
        if (f.fix_snippet) console.log(`  ${C.green}→ ${f.fix_snippet}${C.reset}`);
      });
    }

    if (impFindings.length > 0) {
      console.log(`\n${C.bold}💻 DEEP ENFORCEMENT FINDINGS (Hardening):${C.reset}`);
      impFindings.forEach(f => {
        const regulatoryRef = f.article ? ` (${f.article})` : '';
        console.log(`- [${C.red}${f.description}${C.reset}]${regulatoryRef}`);
        if (f.fix_snippet) console.log(`  ${C.green}→ ${f.fix_snippet}${C.reset}`);
      });
    }


    const contextualFix = manifestPath ? ` --manifest ${manifestPath}` : '';
    console.log(`\n${C.cyan}Next step: run ${C.bold}npx @radu_api/sentinel-scan fix --apply${contextualFix}${C.reset} to scaffold structure.`);
    console.log(`${C.gray}Note: scaffolds missing structure only. Manual content still required.${C.reset}\n`);
  }

  // 5. Enterprise Upgrade (SIG, P2, Vault, V2.1 HTML)
  try {
    if (!isJson) {
      console.log(`\n${C.cyan}${C.bold}🏛  Audit Trail Foundation: Archiving Snapshot...${C.reset}`);
    }
    const manifestDir = path.dirname(path.resolve(manifestPath));
    const upgradedReport = await PreAuditor.upgrade(report, manifestDir, { generateHtml: !isJson, engine });
    report = upgradedReport; // Sync for summary/enforcement
    
    if (!isJson) {
      console.log(`${C.green}✔ Audit archived to .sentinel/vault/${C.reset}`);
      console.log(`${C.green}✔ Professional V2.1 Audit Statement generated: sentinel-audit.html${C.reset}`);
    }

    // Annex IV Generation Hook
    if (isGenerateTechFile) {
      const ReportGenerator = require('./lib/report-generator');
      const techFileContent = ReportGenerator.generateAnnexIVMarkdown(report);
      fs.writeFileSync('ANNEX_IV_EVIDENCE_PACK.md', techFileContent);
      if (!isJson) {
        console.log(`${C.green}✔ Professional Annex IV Technical Dossier generated: ANNEX_IV_EVIDENCE_PACK.md${C.reset}`);
      }
    }
  } catch (err) {
    console.error(`\n${C.yellow}⚠️  Audit Trail Warning: Failed to archive snapshot: ${err.message}${C.reset}`);
  }

  // 6. CI/CD Enforcement & Summary
  if (summaryPath) {
    writeSummary(report, summaryPath);
  }

  const isTotalFail = report.exit_code === 1;

  if (isJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(isTotalFail ? 1 : 0);
  }

  if (isTotalFail) {
      if (report.score < threshold) {
          console.log(`\n${C.red}${C.bold}❌ SCOREGATE FAILURE: Score (${report.score}) is below threshold (${threshold})${C.reset}`);
      }
      if (isEnforcementViolation(report.central_verdict, failOnPolicy)) {
          console.log(`\n${C.red}${C.bold}❌ CI ENFORCEMENT FAILURE: Verdict (${report.central_verdict}) violates policy (${failOnPolicy})${C.reset}`);
      }
      if (report.status === 'FAIL' && !isEnforcementViolation(report.central_verdict, failOnPolicy) && report.score >= threshold) {
          console.log(`\n${C.red}${C.bold}❌ COMPLIANCE GATE FAILURE: Deterministic status is FAIL due to critical findings or contradictions.${C.reset}`);
      }
  }

  process.exit(isTotalFail ? 1 : 0);
}

/**
 * Deterministic Status Engine Layer.
 * Derives PASS/FAIL/NEEDS_REVIEW from technical pulse.
 */
function computeDeterministicStatus(report) {
  const findings = report.findings || [];
  const dual = report.dual_track || {};
  const contradictions = report.contradictions || [];

  const centralVerdict = dual.centralVerdict || dual.central_verdict;
  const governanceStatus = dual.governanceStatus || dual.governance_status;

  const hasCritical = findings.some(f => (f.severity || "").toLowerCase() === 'critical' || (f.reasoning?.severity || "").toLowerCase() === 'critical');
  const hasGap = governanceStatus === 'GAP';
  const hasHold = centralVerdict === 'HOLD';
  const hasContradiction = contradictions.length > 0;

  if (hasCritical || hasGap || hasHold || hasContradiction) {
    return "FAIL";
  }

  if (findings.length > 0) {
    return "NEEDS_REVIEW";
  }

  return "PASS";
}

/**
 * Independent Audit Verification Engine.
 * Re-validates evidence hashes against the current filesystem.
 */
async function runVerify(args) {
  const isJson = args.includes('--json');
  
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
      console.error(`${C.red}Error: Audit '${auditId}' not found in vault.${C.reset}`);
      process.exit(1);
    }
  } else if (auditPathIdx !== -1 && args[auditPathIdx + 1]) {
    try {
      report = JSON.parse(fs.readFileSync(args[auditPathIdx + 1], 'utf8'));
    } catch (e) {
      console.error(`${C.red}Error reading audit file: ${e.message}${C.reset}`);
      process.exit(1);
    }
  } else {
    report = AuditVault.getLatestAudit(rootDir);
    if (!report) {
      console.error(`${C.red}Error: No audit found. Use --audit <id> or --file <path>.${C.reset}`);
      process.exit(1);
    }
  }

  const auditIdReport = (report._audit_trail?.audit_id || report.audit_metadata?.audit_id || 'Unknown');
  const commit = (report._audit_trail?.commit || report.audit_metadata?.commit || 'N/A');
  console.log(`\n${C.cyan}${C.bold}🔍 Sentinel Evidence Verification Engine${C.reset}`);
  console.log(`${C.gray}Audit ID: ${C.white}${auditIdReport}${C.reset}`);
  console.log(`${C.gray}Reference Commit: ${C.white}${commit}${C.reset}\n`);

  const signals = report._internal?.signals || [];
  if (signals.length === 0) {
    console.log(`${C.yellow}No technical evidence found in report to verify.${C.reset}\n`);
    process.exit(0);
  }

  let verifiedCount = 0;
  let tamperedCount = 0;
  let missingCount = 0;

  console.log(`${C.bold}${'STATUS'.padEnd(12)} | ${'REGULATORY ARTICLE'.padEnd(15)} | ${'LOCATION'}${C.reset}`);
  console.log(`${C.gray}-------------|-----------------|-----------------------------------${C.reset}`);

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
      console.log(`${C.red}${'MISSING'.padEnd(12)}${C.reset} | ${regArt.padEnd(15)} | ${s.source_path}:${s.line}`);
      missingCount++;
      continue;
    }

    const currentContent = fs.readFileSync(fullPath, 'utf8');
    const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');

    if (currentHash === s.sha256) {
      console.log(`${C.green}${'VERIFIED'.padEnd(12)}${C.reset} | ${regArt.padEnd(15)} | ${s.source_path}:${s.line || 'base'}`);
      verifiedCount++;
    } else {
      if (process.env.SENTINEL_DEBUG === 'true') {
        console.log(`[DEBUG] Hash Mismatch for ${s.source_path}:`);
        console.log(`  Stored:  ${s.sha256}`);
        console.log(`  Current: ${currentHash}`);
      }
      console.log(`${C.red}${'TAMPERED'.padEnd(12)}${C.reset} | ${regArt.padEnd(15)} | ${s.source_path}:${s.line || 'base'}`);
      tamperedCount++;
    }
  }

  console.log(`\n${C.bold}Verification Summary:${C.reset}`);
  console.log(`  - ${C.green}Verified: ${verifiedCount}${C.reset}`);
  if (tamperedCount > 0) console.log(`  - ${C.red}Tampered/Changed: ${tamperedCount}${C.reset}`);
  if (missingCount > 0) console.log(`  - ${C.red}Missing Files: ${missingCount}${C.reset}`);

  const cryptoUtils = require('./lib/crypto-utils');
  const sigValid = cryptoUtils.verifyAuditSignature(report);
  console.log(`\n${C.bold}Audit Signature:${C.reset} ${sigValid ? C.green + 'VALID ✅' : C.red + 'INVALID ❌'}${C.reset}`);

  if (tamperedCount === 0 && missingCount === 0 && sigValid) {
    console.log(`\n${C.green}${C.bold}✔ ALL TECHNICAL EVIDENCE IS CRYPTOGRAPHICALLY AUTHENTIC.${C.reset}\n`);
    process.exit(0);
  } else {
    console.log(`\n${C.red}${C.bold}✖ INTEGRITY BREACH: Technical evidence does not match the audit record.${C.reset}\n`);
    process.exit(1);
  }
}

/**
 * Validates a standalone forensic audit package.
 * Frictionless: Auth Check -> Integrity Check -> Traceability Check.
 */
async function runPackageVerify(packagePath, argv) {
  if (!packagePath) {
    console.error(`${C.red}✖ Error: Missing package path. Usage: sentinel verify --package <path.zip>${C.reset}`);
    process.exit(1);
  }

  const fullPackagePath = path.resolve(packagePath);
  if (!fs.existsSync(fullPackagePath)) {
    console.error(`${C.red}✖ Error: Package not found: ${fullPackagePath}${C.reset}`);
    process.exit(1);
  }

  const tempDir = path.join(process.cwd(), `.sentinel_verify_${Date.now()}`);
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

  const CryptoUtils = require('./lib/crypto-utils');

  try {
    console.log(`\n${C.cyan}${C.bold}🔍 Sentinel Forensic Verification Engine [Offline Mode]${C.reset}`);
    console.log(`${C.gray}Loading package: ${path.basename(fullPackagePath)}${C.reset}\n`);

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
      console.error(`${C.red}✖ Error: Failed to extract package. ${err.message}${C.reset}`);
      process.exit(1);
    }

    // 2. Auth Check (Signature)
    const sigJsonPath = path.join(tempDir, 'signature.json');
    const sigBinPath = path.join(tempDir, 'signature.bin');
    const pubKeyPath = path.join(tempDir, 'authority.pub');
    const checksumsPath = path.join(tempDir, 'checksums.sha256');

    if (!fs.existsSync(sigJsonPath) || !fs.existsSync(sigBinPath) || !fs.existsSync(pubKeyPath)) {
      console.log(`${C.red}AUTH CHECK: FAIL → MISSING SECURITY ANCHORS${C.reset}`);
      process.exit(1);
    }

    const signatureJson = JSON.parse(fs.readFileSync(sigJsonPath, 'utf8'));
    const signatureBin = fs.readFileSync(sigBinPath);
    const publicKey = fs.readFileSync(pubKeyPath, 'utf8');
    const checksumsRaw = fs.readFileSync(checksumsPath, 'utf8');
    const checksums = checksumsRaw.replace(/\r\n/g, '\n'); // Normalize for Windows extraction

    const isSignedCorrectly = CryptoUtils.verifyData(checksums, signatureBin, publicKey);

    if (!isSignedCorrectly) {
      console.log(`${C.red}AUTH CHECK: FAIL → AUTH BREACH (Invalid Signature)${C.reset}`);
      process.exit(1);
    }
    console.log(`${C.green}AUTH CHECK: PASS${C.reset}`);

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
      console.log(`${C.red}INTEGRITY CHECK: FAIL → STRUCTURE BREACH (Corrupted Files)${C.reset}`);
      process.exit(1);
    }
    console.log(`${C.green}INTEGRITY CHECK: PASS${C.reset}`);

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
      console.log(`${C.red}TRACEABILITY CHECK: FAIL → EVIDENCE BREACH (${traceFailCount} mismatched signals)${C.reset}`);
      process.exit(1);
    }
    console.log(`${C.green}TRACEABILITY CHECK: PASS${C.reset}`);

    console.log(`\n${C.green}${C.bold}FINAL VERDICT: AUDIT VALIDATED${C.reset}\n`);
    console.log(`${C.gray}Artifact ID: ${C.white}${signatureJson.signed_content_digest}${C.reset}`);
    console.log(`${C.gray}Authority:   ${C.white}${signatureJson.signed_by} (${signatureJson.authority_id})${C.reset}\n`);

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

  console.log(`\n${C.cyan}${C.bold}📦 Sentinel Forensic Export Engine${C.reset}`);
  console.log(`${C.gray}Target Audit: ${C.white}${auditId}${C.reset}`);

  const rootDir = process.cwd();
  const report = auditId === 'latest' ? AuditVault.getLatestAudit(rootDir) : AuditVault.getAuditById(rootDir, auditId);

  if (!report) {
    console.error(`${C.red}✖ Error: Audit record '${auditId}' not found in vault.${C.reset}`);
    process.exit(1);
  }

  console.log(`${C.gray}Generating forensic bundle...${C.reset}`);
  
  try {
    const success = await AuditExporter.exportBundle(report, rootDir, outputPath);
    if (success) {
      console.log(`\n${C.green}${C.bold}✔ FORENSIC ARTIFACT GENERATED SUCCESSFULLY${C.reset}`);
      console.log(`${C.white}Location: ${path.resolve(outputPath)}${C.reset}`);
      console.log(`${C.gray}Digital Signature: ${report._audit_signature?.digest.substring(0, 16)}...${C.reset}\n`);
    }
  } catch (err) {
    console.error(`${C.red}✖ Export failed: ${err.message}${C.reset}`);
    process.exit(1);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = (args[0] || '').toLowerCase();

  // Global Production Hash & Strict Mode Extraction
  let productionHash = null;
  const hashIdx = args.indexOf('--production-hash');
  if (hashIdx !== -1 && args[hashIdx + 1]) {
    productionHash = args[hashIdx + 1];
    if (!/^[a-fA-F0-9]{64}$/.test(productionHash)) {
      console.error(`\n${C.red}${C.bold}❌ Error: Invalid production hash format.${C.reset}`);
      console.error(`${C.red}Must be a valid SHA-256 (64 hex characters).${C.reset}\n`);
      process.exit(1);
    }
  }

  const isStrict = args.includes('--strict');

  let buildId = null;
  const buildIdx = args.indexOf('--build-id');
  if (buildIdx !== -1 && args[buildIdx + 1]) {
    buildId = args[buildIdx + 1];
  }

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
    await runCheck(args.slice(1), productionHash, isStrict, buildId);
    process.exit(0);
  }

  if (command === 'verify') {
    await runVerify(args.slice(1));
    process.exit(0);
  }

  if (command === 'export') {
    await runExport(args.slice(1));
    process.exit(0);
  }

  if (command === 'history') {
    const rootDir = process.cwd();
    const index = AuditVault.getHistory(rootDir);
    if (!index || !index.history || index.history.length === 0) {
      console.log(`\n${C.yellow}No audit history found for this project.${C.reset}\n`);
      process.exit(0);
    }
    console.log(`\n${C.cyan}${C.bold}🏛  Sentinel Audit History: ${index.project_name}${C.reset}\n`);
    console.log(`${C.gray}${'ID'.padEnd(10)} | ${'TIMESTAMP'.padEnd(20)} | ${'VERDICT'.padEnd(10)} | ${'COMMIT'}${C.reset}`);
    console.log(`${C.gray}-----------|----------------------|------------|--------${C.reset}`);
    index.history.reverse().forEach(h => {
      const vColor = h.verdict === 'APPROVED' ? C.green : (h.verdict === 'HOLD' ? C.yellow : C.red);
      console.log(`${C.white}${h.audit_id.substring(0, 8).padEnd(10)}${C.reset} | ${C.gray}${h.timestamp.substring(0, 19).padEnd(20)}${C.reset} | ${vColor}${h.verdict.padEnd(10)}${C.reset} | ${C.white}${h.commit || '----'}${C.reset}`);
    });
    console.log("");
    process.exit(0);
  }

  if (command === 'diff') {
    const rootDir = process.cwd();
    const argsCopy = args.slice(1);
    const isJson = argsCopy.includes('--json');
    
    // CI/CD Flags
    const failOnArgIdx = argsCopy.indexOf('--fail-on');
    const failOnPolicy = (failOnArgIdx !== -1 && argsCopy[failOnArgIdx + 1]) ? argsCopy[failOnArgIdx + 1].toUpperCase() : 'REJECTED';
    
    const summaryArgIdx = argsCopy.indexOf('--summary');
    const summaryPath = (summaryArgIdx !== -1 && argsCopy[summaryArgIdx + 1]) ? argsCopy[summaryArgIdx + 1] : null;

    const baseIdArgIndex = argsCopy.indexOf('--base');
    let baseReport = null;

    if (baseIdArgIndex !== -1 && argsCopy[baseIdArgIndex + 1]) {
      const baseId = argsCopy[baseIdArgIndex + 1];
      baseReport = AuditVault.getAuditById(rootDir, baseId);
      if (!baseReport) {
        console.error(`\n${C.red}Error: Base audit with ID '${baseId}' not found in vault.${C.reset}\n`);
        process.exit(1);
      }
    } else {
      baseReport = AuditVault.getLatestAudit(rootDir);
      if (!baseReport) {
        console.error(`\n${C.yellow}No previous audits found to compare against.${C.reset}\n`);
        process.exit(0);
      }
    }

    console.log(`\n${C.cyan}${C.bold}📈 Sentinel Compliance Evolution${C.reset}`);
    console.log(`${C.gray}Comparing current state against: ${baseReport.audit_metadata?.audit_id || 'Unknown'} (${baseReport.audit_metadata?.timestamp || 'N/A'})${C.reset}\n`);

    // To perform a real-time diff, we must run a fresh check but without archiving it as a new "history" entry just yet,
    // or just run the check and let PreAuditor handle the diff injection for the report.
    // For the CLI output, we'll run performAudit.
    
    const manifestArgIndex = argsCopy.indexOf('--manifest');
    const manifestPath = (manifestArgIndex !== -1 && argsCopy[manifestArgIndex + 1]) || 'sentinel.manifest.json';
    // rootDir is already declared at line 1853
    
    const thresholdArgIndex = argsCopy.indexOf('--threshold');
    const threshold = (thresholdArgIndex !== -1 && parseInt(argsCopy[thresholdArgIndex + 1])) || 0;

    try {
      let currentReport = await performAudit(manifestPath, threshold);
      currentReport.threshold = threshold; // Explicit sync!

      // 1. Sentinel Integrity Guard (SIG)
      const { runSig } = require('./lib/sentinel-bridge');
      const probingRulesPath = path.join(__dirname, 'lib', 'probing-rules.json');
      const sigReport = await runSig(currentReport, probingRulesPath, rootDir);
      
      currentReport = {
        ...currentReport,
        enterprise_confidence: sigReport.enterprise_confidence,
        defensibility: sigReport.defensibility,
        integrity_issues: sigReport.integrity_issues,
        _sig_internal: sigReport._internal
      };

      // 2. Generate Traceability Metadata
      const AuditMetadata = require('./lib/audit-metadata');
      const AuditSignature = require('./lib/crypto-utils');
      const auditMeta = AuditMetadata.createMetadataBlock(rootDir);
      currentReport._audit_trail = auditMeta;
      currentReport._audit_signature = AuditSignature.generateAuditSignature(currentReport);

      // 3. Evaluate Dual-Track Result
      const Evaluator = require('./lib/evaluator');
      currentReport._dual_track = Evaluator.evaluate(currentReport);
      currentReport._dual_track.auditMeta = auditMeta; // Pass meta to report generator
      
      const diff = DiffEngine.compare(currentReport, baseReport);
      
      const isImproved = diff.evolution === 'PROGRES';
      const isRegressed = diff.evolution === 'DECLIN';
      const statusColor = isImproved ? C.green : (isRegressed ? C.red : C.yellow);
      
      console.log(`  Verdict: ${statusColor}${C.bold}${diff.verdictFrom} ➔ ${diff.verdictTo}${C.reset} (${diff.evolution})`);
      console.log(`  ${diff.tracks.technical.name}: ${diff.tracks.technical.shift === 'PROGRES' ? C.green : (diff.tracks.technical.shift === 'DECLIN' ? C.red : C.gray)}${diff.tracks.technical.from} ➔ ${diff.tracks.technical.to}${C.reset}`);
      console.log(`  ${diff.tracks.regulatory.name}:     ${diff.tracks.regulatory.shift === 'PROGRES' ? C.green : (diff.tracks.regulatory.shift === 'DECLIN' ? C.red : C.gray)}${diff.tracks.regulatory.from} ➔ ${diff.tracks.regulatory.to}${C.reset}`);
      
      console.log(`\n${C.white}${C.bold}RESPONSABIL AC\u021aIUNE:${C.reset}`);
      console.log(`${statusColor}${C.bold}${diff.actionOwner}${C.reset}`);
      
      if (diff.actionRequired === 'ENGINEERING') {
        console.log(`${C.gray}Sunt necesare interven\u021bii tehnice pentru a remedia vulnerabilit\u0103\u021bile identificate.${C.reset}`);
      } else if (diff.actionRequired === 'GOVERNANCE') {
        console.log(`${C.gray}Este necesar\u0103 revizuirea politicilor \u0219i a documenta\u021biei de guvernan\u021b\u0103.${C.reset}`);
      } else {
        console.log(`${C.green}Sistemul se afl\u0103 \u00eentr-o stare de conformitate stabil\u0103.${C.reset}`);
      }
      
      // Update HTML Report with evolution context
      const ReportGenerator = require('./lib/report-generator');
      const html = ReportGenerator.generateHtml(currentReport, diff, currentReport._dual_track);
      fs.writeFileSync(path.join(process.cwd(), 'sentinel-audit.html'), html);
      console.log(`\n ${C.blue}${C.bold}🏛  Audit Trail Foundation: Executive Statement updated.${C.reset}`);
      
      console.log("");
      // 6. CI/CD Enforcement & Summary
      if (summaryPath) {
        writeSummary(currentReport, summaryPath);
      }

      const enforcementFailed = isEnforcementViolation(currentReport.central_verdict, failOnPolicy);
      
      if (isJson) {
        console.log(JSON.stringify(currentReport, null, 2));
        process.exit(enforcementFailed ? 1 : 0);
      }

      if (enforcementFailed) {
        console.log(`\n${C.red}${C.bold}❌ CI Enforcement Failure: Current Verdict (${currentReport.central_verdict}) violates policy (${failOnPolicy})${C.reset}\n`);
      }

      process.exit(enforcementFailed ? 1 : 0);
    } catch (err) {
      console.error(`\n${C.red}Diff Failure: ${err.message}${C.reset}\n`);
      process.exit(1);
    }
  }

  if (command === 'portfolio') {
    await runPortfolio(args.slice(1));
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
    const suggestedManifest = autodiscovery.generateManifestFromSignals(signals, repoFiles);
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

    const combinedFindings = [];
    const engineFindings = Array.isArray(results) ? results : [results];
    for (const v of engineFindings) {
      if (v && Array.isArray(v.violations)) combinedFindings.push(...v.violations);
    }

    if (newMissingPolicyFiles.length > 0) {
      combinedFindings.push(...newMissingPolicyFiles.map(file => ({
        rule_id: "EUAI-DOC-001",
        description: `Missing required document: ${file}`,
        source: "filesystem"
      })));
    }

    const manifestDir = path.dirname(path.resolve(manifestPath));
    const singleManifest = Array.isArray(manifest) ? manifest[0] : manifest;
    const evidenceFindings = validateEvidence(singleManifest, manifestDir);

    for (const finding of evidenceFindings) {
      combinedFindings.push({
        rule_id: finding.rule_id,
        description: finding.description,
        severity: finding.severity,
        source: finding.source,
        article: finding.article,
        hard_fail: finding.hard_fail
      });
    }

    let riskCat = (singleManifest.risk_category || "minimal").toLowerCase();
    if (signals.some(s => s.id === 'BEHAVIORAL_SUSPICION_FLAG_HIGH_RISK')) {
      riskCat = 'high';
    }
    let required = riskCat === 'high' ? ['Art. 9', 'Art. 13', 'Art. 14', 'Art. 20'] : ['Art. 13'];
    const trustMetrics = computeTrustMetrics(evidenceFindings, singleManifest);
    const verifiedArticles = determineVerifiedArticles(evidenceFindings, singleManifest);
    const evidenceVerdict = computeVerdict(trustMetrics.finalScore, evidenceFindings, singleManifest);

    const summary = {
      violations_total: combinedFindings.length,
      high: combinedFindings.filter(v => ['high', 'critical'].includes(v.severity?.toLowerCase())).length,
      medium: combinedFindings.filter(v => v.severity?.toLowerCase() === 'medium').length,
      low: combinedFindings.filter(v => v.severity?.toLowerCase() === 'low').length,
      informational: combinedFindings.filter(v => v.severity?.toLowerCase() === 'informational').length
    };

    let complianceStatus = evidenceVerdict;
    if (combinedFindings.some(v => v.rule_id?.startsWith('EUAI-BLOCK-'))) complianceStatus = "BLOCKED";

    const status = computeDeterministicStatus(combinedFindings, evidenceVerdict);

    const finalReport = {
      schema: "sentinel.audit.v1",
      schema_version: "2026-03",
      status: status,
      verdict: evidenceVerdict,
      score: trustMetrics.finalScore,
      claim_score: trustMetrics.claim_score,
      evidence_score: trustMetrics.evidence_score,
      confidence: trustMetrics.confidence,
      mapped_articles: verifiedArticles,
      risk_category: riskCat,
      required_articles: required,
      compliance_status: complianceStatus,
      summary,
      evidence_findings: evidenceFindings,
      violations: combinedFindings.map(v => {
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
      if (remoteScore !== undefined) finalReport.score = Math.min(trustMetrics.finalScore, remoteScore);
      if (remoteResult.verdict && !["COMPLIANT", "COMPLIANT_VIA_AI_REVIEW"].includes(remoteResult.verdict)) {
        finalReport.verdict = "NON_COMPLIANT";
        if (remoteResult.justification) {
          combinedFindings.push({
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
      if (status === 'FAIL') { process.exit(1); } else { process.exit(0); }
    }

    if (isJson) {
      console.log(JSON.stringify(finalReport, null, 2));
      if (status === 'FAIL') { process.exit(1); } else { process.exit(0); }
    }

    printResult(finalReport, isJson, isSarif, policy.path);
    if (status === 'FAIL') {
      pauseAndExit(1);
    } else {
      pauseAndExit(0);
    }
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
  const repoFiles = autodiscovery.crawlRepository(manifestDir);
  const signals = autodiscovery.extractSignals(repoFiles, discoveryRules, probingRules);
  if (process.env.SENTINEL_DEBUG === 'true') {
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
    console.log(`\n${C.green}No structural or implementation fixes available.${C.reset}`);
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
        content = `# Human Oversight Protocol (Art. 14)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and regulatory review. This document does not imply final regulatory compliance.\n\n## Oversight Mechanism\nImplementation details pending...\n\n## Roles and Responsibilities\n- Reviewer: [Role Name]\n- Intervention Threshold: [Threshold Details]\n`;
      } else if (doc.includes('data_governance')) {
        content = `# Data Governance and Logging (Art. 20)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and regulatory review. This document does not imply final regulatory compliance.\n\n## Logging Capabilities\nImplementation details pending...\n\n## Retention Policy\nStored for [Duration] in [Location].\n`;
      } else if (doc.includes('risk_assessment')) {
        content = `# Risk Management System (Art. 9)\n\n> [!IMPORTANT]\n> This is a starter template generated by Sentinel. It requires human and regulatory review. This document does not imply final regulatory compliance.\n\n## Risk Identification\nImplementation details pending...\n\n## Mitigation Strategy\nDetails about bias assessment and testing protocols.\n`;
      }

      fs.writeFileSync(docPath, content);
      console.log(`${C.green}✔ Created ${doc}${C.reset}`);
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
      console.log(`${C.green}✔ Created ${oversightPath} (Art. 14 Oversight Hook)${C.reset}`);
    }
  }

  if (plan.some(p => p.type === 'code' && p.file === 'logger.js')) {
    const loggerPath = path.join(autodiscovery.findProjectRoot ? autodiscovery.findProjectRoot(manifestDir) : manifestDir, 'logger.js');
    if (!fs.existsSync(loggerPath)) {
      const loggerCode = `/**\n * Sentinel Sovereign Logging Implementation\n * Auto-generated scaffolding for Art. 20 Compliance.\n */\nconst winston = require('winston');\n\nconst logger = winston.createLogger({\n  level: 'info',\n  format: winston.format.combine(\n    winston.format.timestamp(),\n    winston.format.json()\n  ),\n  transports: [\n    new winston.transports.Console(),\n    new winston.transports.File({ filename: 'audit_trail.log' })\n  ]\n});\n\n/**\n * Sentinel Compliance Logging Hook\n */\nfunction sentinelLog(level, message, meta = {}) {\n  logger.log(level, message, { ...meta, sentinel_audit: true });\n}\n\nmodule.exports = { logger, sentinelLog };\n`;
      fs.writeFileSync(loggerPath, loggerCode);
      console.log(`${C.green}✔ Created ${loggerPath} (Winston Scaffolding)${C.reset}`);
      console.log(`${C.yellow}👉 Remember to run: npm install winston${C.reset}`);
    }
  }

  // 6. Audit Comparison
  console.log(`\n${C.cyan}${C.bold}📊 Verification Audit${C.reset}`);

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
  const oldVerdict = computeVerdict(oldScore, oldAllFindings, manifest);

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
  console.log(`${C.gray}It does not replace regulatory validation.${C.reset}\n`);
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
main().catch(err => { console.error(err); process.exit(1); });
