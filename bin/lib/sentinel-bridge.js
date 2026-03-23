/**
 * Sentinel Integrity Guard (SIG) MVP
 * Performs deterministic zero-trust validation of Sentinel CLI output.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Strips comments and strings from JS code to prevent signal poisoning.
 */
function stripJs(content) {
  // 1. Remove single-line comments
  let cleaned = content.replace(/\/\/.*$/gm, '');
  // 2. Remove multi-line comments
  cleaned = cleaned.replace(/\/\*[\s\S]*?\*\//g, '');
  // 3. Remove strings to prevent "keyword in string" bypasses
  cleaned = cleaned.replace(/(['"`])(\\.|(?!\1)[^\\\r\n])*\1/g, '""');
  return cleaned;
}

/**
 * Calculates a substance score based on unique word ratio.
 * High repetition = Low substance = Low trust.
 * 
 * MINIMAL FIX: Substance Floor
 * Any file under 100 chars is considered "Insufficient Substance" (Score 0).
 */
function computeSubstanceScore(content) {
  if (!content || content.length < 100) return 0;
  
  const words = content.toLowerCase().match(/\b\w+\b/g) || [];
  const uniqueWords = new Set(words);
  if (words.length === 0) return 0;
  
  const ratio = uniqueWords.size / words.length;
  
  // Apply a "Substance Penalty" for files between 100 and 300 chars
  if (content.length < 300) {
    return ratio * 0.5; // Stricter for small documents
  }
  
  return ratio;
}

/**
 * Main Integrity Check Logic
 */
async function runSig(cliResults, probingRulesPath, rootDir = process.cwd()) {
  const signalBreakdown = cliResults._internal?.signal_breakdown || {};
  let manifest = cliResults.manifest;
  
  // LOGIC UPGRADE: Auto-discover manifest if missing from JSON
  if (!manifest) {
    const potentialPaths = ['sentinel.manifest.json', 'manifest.json', '.sentinel.manifest.json'];
    for (const p of potentialPaths) {
      const fullP = path.resolve(rootDir, p);
      if (fs.existsSync(fullP)) {
        try {
           manifest = JSON.parse(fs.readFileSync(fullP, 'utf8'));
           break;
        } catch(e) {}
      }
    }
  }
  
  manifest = manifest || {}; 
  
  let probingRules = null;
  try {
    probingRules = JSON.parse(fs.readFileSync(probingRulesPath, 'utf8'));
  } catch (e) {
    throw new Error(`Failed to load probing rules from ${probingRulesPath}`);
  }

  const issues = [];

  // 1. Documentation Integrity (Scenario A)
  const evidencePath = manifest.evidence_path || manifest.artifact_path;
  let docSubstanceScore = 1.0;
  if (evidencePath) {
    const fullPath = path.resolve(rootDir, evidencePath);
    if (fs.existsSync(fullPath)) {
      const content = fs.readFileSync(fullPath, 'utf8');
      const substance = computeSubstanceScore(content);
      if (substance < 0.2) {
        docSubstanceScore = 0.3; // Penalty for low substance
        issues.push({
          id: 'SIG-DOC-001',
          severity: 'HIGH',
          message: `Documentation substance integrity failed: High repetition or insufficient substance detected (Score: ${substance.toFixed(2)}).`
        });
      }
    }
  }

  // 2. SURGICAL Signal Verification (Scenario B)
  // Instead of re-scanning the whole repo, we use the signals already discovered by the CLI.
  const cliSignals = cliResults._internal?.signals || [];
  const verifiedSignals = new Set();
  const reportedInSource = new Set();

  // Group by file for efficiency
  const fileMap = {};
  cliSignals.forEach(s => {
    if (s.kind === 'code_signature' || s.kind === 'hardening_probe') {
      if (!fileMap[s.source_path]) fileMap[s.source_path] = [];
      fileMap[s.source_path].push(s);
    }
  });

  Object.entries(fileMap).forEach(([relPath, signals]) => {
    const fullPath = path.resolve(rootDir, relPath);
    if (!fs.existsSync(fullPath)) return;

    try {
      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.split('\n');
      const cleaned = stripJs(content);

      signals.forEach(s => {
        reportedInSource.add(s.id);
        
        // Find the pattern for this signal ID
        let pattern = null;
        Object.values(probingRules.probes).forEach(probe => {
           const match = [...probe.strong_signals, ...(probe.weak_signals || []), ...(probe.traceability_signals || [])]
             .find(ps => ps.id === s.id);
           if (match) pattern = match.pattern;
        });

        if (!pattern) return; // Skip if no pattern mapping found

        const re = new RegExp(pattern, 'gi');
        if (re.test(cleaned)) {
           verifiedSignals.add(s.id);
        } else {
           // Poison detected
           issues.push({
             id: 'SIG-CODE-001',
             severity: 'CRITICAL',
             message: `Signal poison detected: Pattern '${s.id}' found only in comments or strings in ${relPath}.`,
             evidence_location: {
               file: relPath,
               line: s.line,
               snippet: s.snippet
             }
           });
        }
      });
    } catch (e) {}
  });

  // Signal Trust = Ratio of verified signals in source files
  const signalTrust = reportedInSource.size > 0 ? verifiedSignals.size / reportedInSource.size : 1.0;
  const enterpriseConfidence = (signalTrust * 0.7 + docSubstanceScore * 0.3);

  return {
    enterprise_confidence: parseFloat(enterpriseConfidence.toFixed(2)),
    defensibility: enterpriseConfidence > 0.8 ? 'STRONG' : (enterpriseConfidence > 0.5 ? 'MEDIUM' : 'WEAK'),
    integrity_issues: issues,
    _internal: {
      verified_signals: verifiedSignals.size,
      reported_signals: reportedInSource.size,
      signal_verification_ratio: signalTrust.toFixed(2),
      documentation_substance_score: docSubstanceScore === 1.0 ? 'PASS' : 'FAIL'
    }
  };
}

// CLI Wrapper for bridge
if (require.main === module) {
  const stdin = process.stdin;
  let inputData = '';

  stdin.on('data', data => { inputData += data; });
  stdin.on('end', async () => {
    try {
      if (!inputData.trim()) {
         console.error("Error: No JSON input received from Sentinel CLI.");
         process.exit(1);
      }
      const cliResults = JSON.parse(inputData);
      const probingRulesPath = path.join(__dirname, 'probing-rules.json');
      const sigReport = await runSig(cliResults, probingRulesPath, process.cwd());
      
      const finalReport = {
        ...cliResults,
        enterprise_confidence: sigReport.enterprise_confidence,
        defensibility: sigReport.defensibility,
        integrity_issues: sigReport.integrity_issues,
        _sig_internal: sigReport._sig_info
      };
      
      console.log(JSON.stringify(finalReport, null, 2));
    } catch (e) {
      console.error(`SIG Processing Error: ${e.message}`);
      process.exit(1);
    }
  });
}

module.exports = { runSig, stripJs, computeSubstanceScore };
