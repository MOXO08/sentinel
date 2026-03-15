/**
 * Sentinel Autodiscovery V1 - Phase 0 & 1
 * Core module for local repository scanning and signal extraction.
 */

const fs = require('fs');
const path = require('path');

/**
 * @typedef {Object} RepoFile
 * @property {string} path - Relative path to the file
 * @property {string} file_type - Extension or kind
 * @property {string} category - dependency | source | doc | config
 * @property {string} language - Programming language
 * @property {number} size_bytes - File size
 * @property {string} content - (Optional) Partial content for detection
 * @property {boolean} is_ignored - Whether the file is in exclude list
 */

/**
 * @typedef {Object} Signal
 * @property {string} id - Unique signal ID
 * @property {string} kind - dependency | code_signature | doc_hint
 * @property {string} source_path - File where it was found
 * @property {number} confidence - 0.0 to 1.0
 * @property {number} evidence_weight - Importance for the final verdict
 */

const EXCLUDED_DIRS = [
  'node_modules', 'dist', 'build', 'coverage', '.git', 'bin', 'pkg-node',
  'vendor', 'target', 'obj', 'bin-builds', '.next', '.astro'
];

const EXCLUDED_FILES = [
  '.DS_Store', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'
];

/**
 * Crawls a directory and collects relevant files for Autodiscovery.
 * @param {string} rootDir - The root directory of the repository.
 * @returns {RepoFile[]}
 */
function crawlRepository(rootDir) {
  const files = [];

  function walk(dir) {
    const list = fs.readdirSync(dir);
    for (const item of list) {
      const fullPath = path.join(dir, item);
      const stat = fs.statSync(fullPath);
      const relativePath = path.relative(rootDir, fullPath);

      if (stat.isDirectory()) {
        if (!EXCLUDED_DIRS.includes(item)) {
          walk(fullPath);
        }
      } else {
        if (!EXCLUDED_FILES.includes(item) && stat.size < 1024 * 512) { // Skip files > 512KB for security/perf
          files.push(classifyFile(relativePath, fullPath, stat.size));
        }
      }
    }
  }

  walk(rootDir);
  return files;
}

/**
 * Classifies a file based on its extension and path.
 */
function classifyFile(relativePath, fullPath, size) {
  const ext = path.extname(relativePath).toLowerCase();
  const name = path.basename(relativePath).toLowerCase();

  let category = 'source';
  let language = 'unknown';

  if (['.json', '.yaml', '.yml', '.toml', '.xml'].includes(ext)) {
    category = 'config';
    if (['package.json', 'requirements.txt', 'pyproject.toml', 'cargo.toml'].includes(name)) {
      category = 'dependency';
    }
  } else if (['.md', '.txt', '.pdf', '.docx'].includes(ext)) {
    category = 'doc';
  }

  // Language detection
  const langMap = {
    '.js': 'javascript', '.ts': 'typescript', '.py': 'python',
    '.rs': 'rust', '.go': 'go', '.java': 'java', '.cpp': 'cpp'
  };
  language = langMap[ext] || 'unknown';

  return {
    path: relativePath,
    file_type: ext || 'no-ext',
    category,
    language,
    size_bytes: size,
    is_ignored: false
  };
}

/**
 * Extracts signals from the collected files based on rules.
 */
function extractSignals(repoFiles, rules) {
  const signals = [];
  
  for (const file of repoFiles) {
    // 1. Dependency Signals
    if (file.category === 'dependency' && file.path.endsWith('package.json')) {
      try {
        const content = fs.readFileSync(path.join(process.cwd(), file.path), 'utf8');
        const pkg = JSON.parse(content);
        const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
        
        for (const [dep, ver] of Object.entries(deps)) {
          if (rules.dependencies[dep]) {
            signals.push({
              id: `DEP_${dep.toUpperCase()}`,
              kind: 'dependency',
              source_path: file.path,
              confidence: 1.0,
              evidence_weight: rules.dependencies[dep].weight || 0.5
            });
          }
        }
      } catch (e) {
        // Skip malformed JSON
      }
    }
    // 2. Code Signature & Doc Hint Signals
    if (['source', 'doc'].includes(file.category)) {
      try {
        const content = fs.readFileSync(path.join(process.cwd(), file.path), 'utf8');
        
        // Scan for code signatures if it's a source file
        if (file.category === 'source') {
          for (const rule of rules.code_signatures) {
            const regex = new RegExp(rule.pattern, 'gi');
            if (regex.test(content)) {
              signals.push({
                id: `CODE_${rule.id}`,
                kind: 'code_signature',
                source_path: file.path,
                confidence: 0.8, // RegEx is good but context-less
                evidence_weight: rule.weight || 0.5
              });
            }
          }
        }

        // Scan for doc hints if it's a doc file
        if (file.category === 'doc') {
          for (const rule of rules.doc_hints) {
            const regex = new RegExp(rule.pattern, 'gi');
            if (regex.test(content)) {
              signals.push({
                id: `DOC_${rule.id}`,
                kind: 'doc_hint',
                source_path: file.path,
                confidence: 0.6, // Doc mentions are less definitive
                evidence_weight: rule.weight || 0.3
              });
            }
          }
        }
      } catch (e) {
        // Skip files that can't be read
      }
    }
  }

  // 4. Enhanced Scoring (Inference)
  // If we have a dependency AND a code signature in the same category, bump confidence
  const categoryMap = {
    'biometric': ['BIOMETRIC', 'REKOGNITION', 'FACE-API'],
    'hr': ['RECRUITMENT', 'HR'],
    'social': ['SOCIAL_SCORING', 'CREDIT']
  };

  for (const [cat, keywords] of Object.entries(categoryMap)) {
    const matchingSignals = signals.filter(s => keywords.some(k => s.id.includes(k)));
    
    // If we have multiple types of signals for the same category, increase confidence
    const hasDep = matchingSignals.some(s => s.kind === 'dependency');
    const hasCode = matchingSignals.some(s => s.kind === 'code_signature');
    const hasDoc = matchingSignals.some(s => s.kind === 'doc_hint');

    if (hasDep && (hasCode || hasDoc)) {
      matchingSignals.forEach(s => {
        s.confidence = Math.min(1.0, s.confidence + 0.2);
        s.evidence_weight = Math.min(1.0, s.evidence_weight + 0.1);
      });
    }
  }

  return signals;
}

/**
 * Compares detected signals with the manifest declarations.
 */
function verifyAlignment(manifest, signals) {
  const issues = [];
  const declaredFlags = manifest.declared_flags || [];
  
  // 1. Check for missing flags (Something detected but not declared)
  const biometricSignals = signals.filter(s => s.id.includes('BIOMETRIC') || s.id.includes('REKOGNITION'));
  if (biometricSignals.length > 0 && !declaredFlags.includes('biometric_identification_enabled')) {
    issues.push({
      id: 'ALIGN_MISSING_BIOMETRIC',
      type: 'MISSING_FLAG',
      detected: 'Biometric Capability',
      severity: 'HIGH',
      recommendation: 'Add "biometric_identification_enabled" to your declared_flags and ensure compliance with Art. 10.'
    });
  }

  // 2. Check for risk mismatch
  if (manifest.risk_category === 'Minimal' && signals.some(s => s.evidence_weight >= 0.8)) {
     issues.push({
       id: 'ALIGN_RISK_MISMATCH',
       type: 'RISK_UNDERREPORTING',
       severity: 'CRITICAL',
       recommendation: 'Repository contains signals for High-Risk categories. Review Article 6 and Annex III.'
     });
  }

  return issues;
}

/**
 * Generates a suggested manifest structure from detected signals.
 */
function generateManifestFromSignals(signals) {
  const flags = new Set();
  let riskCategory = 'Minimal';
  const notes = [];

  // Check for high-risk indicators
  const hasBiometrics = signals.some(s => s.id.includes('BIOMETRIC') || s.id.includes('REKOGNITION'));
  const hasHR = signals.some(s => s.id.includes('HR') || s.id.includes('RECRUITMENT'));
  const hasSocial = signals.some(s => s.id.includes('SOCIAL') || s.id.includes('CREDIT'));

  if (hasBiometrics) {
    flags.add('biometric_identification_enabled');
    riskCategory = 'High';
    notes.push('Detected biometric identification components.');
  }

  if (hasHR) {
    flags.add('ai_recruitment_screening_enabled');
    riskCategory = 'High';
    notes.push('Detected HR/Recruitment automation patterns.');
  }

  if (hasSocial) {
    flags.add('social_scoring_logic_detected');
    riskCategory = 'Unacceptable';
    notes.push('CRITICAL: Detected social scoring or credit worthiness patterns.');
  }

  // Basic good practices
  flags.add('transparency_disclosure_provided');
  flags.add('human_oversight_enabled');

  return {
    app_name: path.basename(process.cwd()),
    version: '1.0.0',
    risk_category: riskCategory,
    app_description: 'Auto-generated manifest by Sentinel Autodiscovery.',
    declared_flags: Array.from(flags),
    autodiscovery_notes: notes,
    fallback_ai_verification: true
  };
}

module.exports = {
  crawlRepository,
  classifyFile,
  extractSignals,
  verifyAlignment,
  generateManifestFromSignals
};
