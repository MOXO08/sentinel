#!/usr/bin/env node
// sentinel-scan — EU AI Act Compliance CLI
// Usage: npx sentinel-scan ./manifest.json [--policy <path>] [--baseline <path>] [--json] [--api-key <key>] [--endpoint <url>]

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
  console.log(`  npx sentinel-scan <manifest.json>           Run offline diagnostic scan`);
  console.log(`  npx sentinel-scan <manifest.json> --remote  Real-time audit via Sentinel Edge API`);
  console.log(`  npx sentinel-scan discover                  Magic Onboarding: Auto-generate manifest from code`);
  console.log(`\n${C.bold}Options:${C.reset}`);
  console.log(`  --api-key <key>     API Key (Developer or Pro)`);
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
  
  console.log(`\n${C.bold}Evidence Commands:${C.reset}`);
  console.log(`  evidence push <dir>             Sync evidence pack to Sentinel SaaS Audit Ledger`);
}

// ── Top 10 Reguli AI Act — Embedded offline ──
const OFFLINE_RULES = {
  rules: [
    { id: "ART5-001", description: "Subliminal manipulation", risk_category: "Unacceptable", required_flags: [], forbidden_flags: ["subliminal_techniques"] },
    { id: "ART5-003", description: "Social scoring", risk_category: "Unacceptable", required_flags: [], forbidden_flags: ["social_scoring"] },
    { id: "ART10-001", description: "Data governance & Bias assessment", risk_category: "High", required_flags: ["bias_assessment_performed", "data_governance_policy_documented"] },
    { id: "ART13-001", description: "User notification of AI interaction", risk_category: "High", required_flags: ["user_notification_ai_interaction"] },
    { id: "ART14-001", description: "Human oversight", risk_category: "High", required_flags: ["human_oversight_enabled"] },
    { id: "ART22-001", description: "Conformity assessment", risk_category: "High", required_flags: ["conformity_assessment_completed"] },
  ]
};

async function runOffline(manifest) {
  const { run_audit } = require('../pkg-node/sentinel_core.js');
  const verdictText = run_audit(JSON.stringify(manifest), JSON.stringify(OFFLINE_RULES));
  return JSON.parse(verdictText);
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
    req.on('error', () => {}); req.write(body); req.end();
  } catch (e) {}
}

async function runRemote(manifest, apiKey, endpoint, telemetry = {}) {
  const https = require('https');
  const body = JSON.stringify({
    ...manifest,
    anonymous_client_id: telemetry.clientId,
    scan_id: telemetry.scanId,
    project_hash: telemetry.projectHash,
    execution_context: telemetry.executionContext,
  });
  const url = new URL(endpoint);

  const pkg = require('../package.json');
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: url.hostname,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'X-Sentinel-CLI-Version': pkg.version,
        'Content-Length': Buffer.byteLength(body),
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`API Error (${res.statusCode}): ${data}`));
        const results = JSON.parse(data);
        if (typeof results === 'object' && !Array.isArray(results)) {
          results._headers = res.headers;
        }
        resolve(results);
      });
    });
    req.on('error', reject); req.write(body); req.end();
  });
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
    } catch (e) {}
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
  } catch (e) {}
  
  return crypto.createHash('sha256').update(signals.join('|')).digest('hex');
}

function detectExecutionContext() {
  if (process.env.GITHUB_ACTIONS === 'true') return 'github_actions';
  if (process.env.GITLAB_CI === 'true') return 'gitlab_ci';
  
  try {
    const fs = require('fs');
    if (fs.existsSync('/.dockerenv')) return 'docker';
    if (fs.readFileSync('/proc/self/cgroup', 'utf8').includes('docker')) return 'docker';
  } catch (e) {}
  
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

  const https = require('https');
  const body = JSON.stringify(payload);
  const url = new URL(endpoint);
  if (url.pathname === '/' || url.pathname === '/audit') url.pathname = '/evidence'; // Target dedicated endpoint

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: url.hostname,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Sentinel-API-Key': apiKey,
        'X-Sentinel-Remote': '1',
        'X-Sentinel-CLI-Version': require('../package.json').version,
        'Content-Length': Buffer.byteLength(body),
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`Sync Failed (${res.statusCode}): ${data}`));
        resolve(JSON.parse(data));
      });
    });
    req.on('error', reject); req.write(body); req.end();
  });
}

function printSuccess(policyPath) {
  console.log("");
  console.log(`${C.bold}${C.green}✅ Sentinel compliance check passed${C.reset}`);
  console.log("");
  console.log("Repository satisfies the configured Sentinel policy.");
  console.log("");
  console.log("Verified:");
  console.log("- required compliance artifacts present");
  console.log("- policy checks passed");
  console.log("- repository ready for audit evidence generation");

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

function loadPolicy(policyPath = "sentinel.policy.json") {
  const resolvedPath = path.resolve(process.cwd(), policyPath);

  if (!fs.existsSync(resolvedPath)) {
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
    ? verdict.some(v => v.verdict === "NON_COMPLIANT")
    : singleVerdict?.verdict === "NON_COMPLIANT";

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

  if (isFail) {
    if (!isJson && !isSarif) {
      console.log(`${C.bold}${C.red}❌ Sentinel compliance check failed${C.reset}`);
      console.log("");
      violations.forEach(v => {
        let ruleId = v.rule_id;
        if (!ruleId && v.description) {
           const desc = v.description.toLowerCase();
           if (desc.includes('transparent about being an ai')) ruleId = 'EUAI-TECH-001';
           else if (desc.includes('human oversight')) ruleId = 'EUAI-GOV-002';
           else if (desc.includes('bias')) ruleId = 'EUAI-DATA-001';
           else if (desc.includes('missing required document')) ruleId = 'EUAI-DOC-001';
        }
        const idStr = ruleId ? `${C.bold}${ruleId}${C.reset} ` : "";
        console.log(`${C.red}✖ ${idStr}${v.description}${C.reset}`);
      });
      console.log("");
    }
    printFailure(missingFiles, policyPath);
  } else {
    printSuccess(policyPath);
  }
}

function printVersion() {
  const pkg = require('../package.json');
  console.log(`Sentinel CLI v${pkg.version}`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args[0] === "discover") {
    printBanner();
    console.log(`${C.cyan}${C.bold}🔍 Sentinel Magic Onboarding: Scanning repository...${C.reset}`);
    
    const repoFiles = autodiscovery.crawlRepository(process.cwd());
    const signals = autodiscovery.extractSignals(repoFiles, discoveryRules);
    const suggestedManifest = autodiscovery.generateManifestFromSignals(signals);

    console.log(`${C.gray}Analyzed ${repoFiles.length} files. Detected ${signals.length} signals.${C.reset}\n`);
    
    console.log(`${C.bold}Generated suggested manifest for ${C.cyan}${suggestedManifest.app_name}${C.reset}:`);
    console.log(JSON.stringify(suggestedManifest, null, 2));
    console.log("");

    if (suggestedManifest.autodiscovery_notes.length > 0) {
      console.log(`${C.yellow}${C.bold}Notes:${C.reset}`);
      suggestedManifest.autodiscovery_notes.forEach(note => console.log(`${C.yellow}- ${note}${C.reset}`));
      console.log("");
    }

    const manifestPath = path.join(process.cwd(), "sentinel.manifest.json");
    if (fs.existsSync(manifestPath)) {
      console.log(`${C.yellow}⚠️  A manifest already exists at ${manifestPath}. Skipping auto-save.${C.reset}`);
    } else {
      fs.writeFileSync(manifestPath, JSON.stringify(suggestedManifest, null, 2));
      console.log(`${C.green}${C.bold}✅ Suggested manifest saved to ${C.cyan}sentinel.manifest.json${C.reset}`);
      console.log(`${C.gray}You can now run: ${C.white}npx sentinel-scan ./sentinel.manifest.json${C.reset}`);
    }

    process.exit(0);
  }

  if (args[0] === "evidence" && args[1] === "generate") {
    let policyPath = "sentinel.policy.json";
    let policyPack = null;

    for (let i = 0; i < args.length; i++) {
      if (args[i] === "--policy" && args[i + 1]) {
        policyPath = args[i + 1];
        i++;
        continue;
      }

      if (args[i] === "--policy-pack" && args[i + 1]) {
        policyPack = args[i + 1];
        i++;
        continue;
      }
    }

    let policy;

    if (policyPack) {
      const pack = resolvePolicyPack(policyPack);

      if (!pack || pack.error) {
        console.error("");
        console.error(`Sentinel policy pack error: ${pack?.error || "Unable to load pack"}`);
        console.error("");
        process.exit(1);
      }

      policy = {
        path: pack.path,
        config: pack.config
      };
    } else {
      policy = loadPolicy(policyPath);

      if (policy.error) {
        console.error("");
        console.error(`Sentinel policy error: ${policy.error}`);
        console.error("");
        process.exit(1);
      }
    }

    generateEvidence(policy.config);
    process.exit(0);
  }

  if (args[0] === "policy-pack" && args[1] === "list") {
    printPolicyPackList();
    process.exit(0);
  }

  if (args[0] === "policy-pack" && args[1] === "show" && args[2]) {
    printPolicyPackDetails(args[2]);
    process.exit(0);
  }

  if (args[0] === "evidence" && args[1] === "push") {
    const dir = args[2] || "sentinel-evidence";
    const apiKeyIdx = args.indexOf('--api-key');
    const apiKey = apiKeyIdx !== -1 ? args[apiKeyIdx + 1] : process.env.SENTINEL_API_KEY || '';
    const endpointIdx = args.indexOf('--endpoint');
    const endpoint = endpointIdx !== -1 ? args[endpointIdx + 1] : 'https://sentinel-api.sentinel-moxo.workers.dev';

    if (!apiKey) {
      console.error(`${C.red}Error: --api-key or SENTINEL_API_KEY environment variable required for push.${C.reset}`);
      process.exit(1);
    }

    console.log(`${C.cyan}${C.bold}🚀 Porting Evidence Pack to Audit Ledger...${C.reset}`);
    pushEvidence(dir, apiKey, endpoint)
      .then(res => {
        console.log(`\n${C.green}${C.bold}✅ Evidence synchronized successfully.${C.reset}`);
        console.log(`${C.gray}Audit ID: ${res.audit_id || 'N/A'}${C.reset}`);
        console.log(`${C.gray}Status: ${res.status}${C.reset}`);
        process.exit(0);
      })
      .catch(err => {
        console.error(`${C.red}Sync failed: ${err.message}${C.reset}`);
        process.exit(1);
      });
    return; // Async
  }

  if (args.includes('--version') || args.includes('-v')) {
    printVersion(); process.exit(0);
  }
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printBanner(); printHelp(); process.exit(0);
  }

  const manifestPath = args.find(a => !a.startsWith('-'));
  const isRemote = args.includes('--remote');
  const isJson = args.includes('--json');
  const isSarif = args.includes('--sarif');
  const isEvidence = args.includes('--evidence');
  const isAutodiscover = args.includes('--autodiscover');

  let policyPath = "sentinel.policy.json";
  let baselinePath = null;
  let policyPack = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--policy" && args[i + 1]) {
      policyPath = args[i + 1];
      i++;
    }
    if (args[i] === "--baseline" && args[i + 1]) {
      baselinePath = args[i + 1];
      i++;
    }
    if (args[i] === "--policy-pack" && args[i + 1]) {
      policyPack = args[i + 1];
      i++;
    }
  }

  const apiKeyIdx = args.indexOf('--api-key');
  const apiKey = apiKeyIdx !== -1 ? args[apiKeyIdx + 1] : process.env.SENTINEL_API_KEY || '';
  const endpointIdx = args.indexOf('--endpoint');
  const endpoint = endpointIdx !== -1 ? args[endpointIdx + 1] : 'https://sentinel-api.sentinel-moxo.workers.dev';

  if (!fs.existsSync(manifestPath)) {
    console.error(`${C.red}Error: File not found: ${manifestPath}${C.reset}`);
    pauseAndExit(2);
  }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (e) {
    console.error(`${C.red}Error: Invalid JSON: ${e.message}${C.reset}`);
    pauseAndExit(2);
  }

  if (!isJson && !isSarif) {
    printBanner();
    console.log(`${C.gray}Scanning: ${path.resolve(manifestPath)}${C.reset}`);
    console.log(`${C.gray}Mode: ${isRemote ? '🌐 Remote Audit' : '⚡ Local Diagnostic'}${C.reset}\n`);
  }

  let alignmentIssues = [];
  if (isAutodiscover && !Array.isArray(manifest)) {
    if (!isJson && !isSarif) {
      console.log(`${C.cyan}${C.bold}🔍 Running Sentinel Autodiscovery...${C.reset}`);
    }
    
    const repoFiles = autodiscovery.crawlRepository(process.cwd());
    const signals = autodiscovery.extractSignals(repoFiles, discoveryRules);
    alignmentIssues = autodiscovery.verifyAlignment(manifest, signals);

    if (!isJson && !isSarif) {
      console.log(`${C.gray}Analyzed ${repoFiles.length} files. Detected ${signals.length} signals.${C.reset}`);
      if (alignmentIssues.length > 0) {
        console.log(`\n${C.yellow}${C.bold}⚠️  INTEGRITY ISSUES DETECTED:${C.reset}`);
        alignmentIssues.forEach(issue => {
          console.log(`${C.yellow}- [${issue.type}] ${issue.recommendation}${C.reset}`);
        });
        console.log("");
      } else {
        console.log(`${C.green}✅ No integrity discrepancies found between code and manifest.${C.reset}\n`);
      }
    }
  }

  try {
    let results;
    if (Array.isArray(manifest)) {
      const bar = new cliProgress.SingleBar({
        format: `${C.cyan}Scanning |${C.reset}{bar}${C.cyan}| {percentage}% || {value}/{total} Items`,
        barCompleteChar: '\u2588', barIncompleteChar: '\u2591', hideCursor: true
      });
      if (!isJson && !isSarif) bar.start(manifest.length, 0);
      results = [];
      const telemetry = {
        clientId: getOrCreateClientId(),
        scanId: require('crypto').randomBytes(8).toString('hex'),
        projectHash: computeProjectHash(),
        executionContext: detectExecutionContext()
      };
      for (const item of manifest) {
        results.push(isRemote ? await runRemote(item, apiKey, endpoint, telemetry) : await runOffline(item));
        if (!isJson && !isSarif) bar.increment();
      }
      if (!isJson && !isSarif) bar.stop();
    } else {
      const telemetry = {
        clientId: getOrCreateClientId(),
        scanId: require('crypto').randomBytes(8).toString('hex'),
        projectHash: computeProjectHash(),
        executionContext: detectExecutionContext()
      };
      results = isRemote ? await runRemote(manifest, apiKey, endpoint, telemetry) : await runOffline(manifest);
    }

    let policy;

    if (policyPack) {
      const pack = resolvePolicyPack(policyPack);

      if (pack.error) {
        console.error("");
        console.error(pack.error);
        console.error("");
        process.exit(1);
      }

      policy = {
        path: pack.path,
        config: pack.config
      };
    } else {
      policy = loadPolicy(policyPath);

      if (policy.error) {
        console.error("");
        console.error(`Sentinel policy error: ${policy.error}`);
        console.error("");
        process.exit(1);
      }
    }

    const baseline = loadBaseline(baselinePath);

    if (baseline.error) {
      console.error("");
      console.error(`Sentinel baseline error: ${baseline.error}`);
      console.error("");
      process.exit(1);
    }

    const missingPolicyFiles = checkRequiredDocuments(policy.config);
    const newMissingPolicyFiles = filterMissingFilesAgainstBaseline(
      missingPolicyFiles,
      baseline.config
    );

    const totalMissingFiles = newMissingPolicyFiles;
    
    // Aggregate ALL violations
    const combinedViolations = [];
    
    // 1. Add engine violations
    const engineVerdicts = Array.isArray(results) ? results : [results];
    for (const v of engineVerdicts) {
      if (v && Array.isArray(v.violations)) {
        combinedViolations.push(...v.violations);
      }
    }
    
    // 2. Add policy engine violations
    if (totalMissingFiles.length > 0) {
      combinedViolations.push(...totalMissingFiles.map(file => ({
        rule_id: "EUAI-DOC-001",
        description: `Missing required document: ${file}`,
        source: "filesystem"
      })));
    }

    const summary = {
      violations_total: combinedViolations.length,
      high: combinedViolations.filter(v => ['high', 'critical'].includes(v.severity?.toLowerCase())).length,
      medium: combinedViolations.filter(v => v.severity?.toLowerCase() === 'medium').length,
      low: combinedViolations.filter(v => v.severity?.toLowerCase() === 'low').length,
      informational: combinedViolations.filter(v => v.severity?.toLowerCase() === 'informational').length
    };

    let complianceStatus = combinedViolations.length > 0 ? "non_compliant" : "compliant";
    if (summary.high > 0) complianceStatus = "high_risk";
    if (combinedViolations.some(v => v.rule_id?.startsWith('EUAI-BLOCK-'))) complianceStatus = "blocked";

    const finalReport = {
      schema: "sentinel.audit.v1",
      schema_version: "2026-03",
      verdict: combinedViolations.length > 0 ? "NON_COMPLIANT" : "COMPLIANT",
      compliance_status: complianceStatus,
      summary,
      violations: combinedViolations.map(v => {
        let ruleId = v.rule_id;
        if (!ruleId && v.description) {
           const desc = v.description.toLowerCase();
           if (desc.includes('transparent about being an ai')) ruleId = 'EUAI-TECH-001';
           else if (desc.includes('human oversight')) ruleId = 'EUAI-GOV-002';
           else if (desc.includes('bias')) ruleId = 'EUAI-DATA-001';
        }
        return {
          ...v,
          rule_id: ruleId || "EUAI-GENERIC",
          source: v.source || (ruleId?.startsWith('EUAI-DOC-') ? 'filesystem' : 'engine')
        };
      })
    };

    // Evidence Pack Mode
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
      const { outDir, evidenceHash } = generateEvidencePack({
        report: finalReport,
        metadata: packMetadata,
        sarif: sarifData,
        policyPath: policy.path
      });

      console.log(`\n${C.green}${C.bold}✔ Evidence pack generated at ${outDir}${C.reset}`);
      console.log(`${C.gray}Integrity Hash: ${evidenceHash}${C.reset}`);
      console.log(`\nFiles:`);
      console.log(`- scan-metadata.json`);
      console.log(`- scan-report.json`);
      console.log(`- scan-report.sarif`);
      console.log(`- audit-evidence.json`);
      console.log(`- compliance-summary.md`);
      console.log("");
    }

    // SARIF Mode
    if (isSarif) {
      console.log(JSON.stringify(generateSarif(finalReport, manifestPath), null, 2));
      process.exit(finalReport.verdict === "NON_COMPLIANT" ? 1 : 0);
    }

    // JSON Mode
    if (isJson) {
      console.log(JSON.stringify(finalReport, null, 2));
      process.exit(finalReport.verdict === "NON_COMPLIANT" ? 1 : 0);
    }

    // Terminal Mode (Aggregated)
    if (finalReport.verdict === "NON_COMPLIANT") {
      printResult(finalReport, false, false, policy.path);
      process.exit(1);
    }

    printSuccess(policy.path);
    pauseAndExit(0);
  } catch (err) {
    console.error(`${C.red}Scan failed: ${err.message}${C.reset}`);
    await reportError(err);
    pauseAndExit(2);
  }
}

main();
