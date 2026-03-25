/**
 * Sentinel Autodiscovery V1 - Phase 0 & 1
 * Core module for local repository scanning and signal extraction.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Replaces comments with spaces of equal length to preserve line/column numbers.
 */
function stripComments(content, language) {
  if (language === 'python') {
    return content.replace(/#.*$/gm, match => ' '.repeat(match.length));
  }
  // JS/TS/CSS: /* */ and //
  // Regex covers multiline /* */ and single line // that are preceded by space or start of line
  return content.replace(/\/\*[\s\S]*?\*\/|(?:\s|^)\/\/.*$/gm, match => ' '.repeat(match.length));
}

/**
 * Heuristic structural analysis of a match context.
 */
function analyzeStructuralContext(content, index, text) {
  const head = content.substring(Math.max(0, index - 100), index);
  const tail = content.substring(index + text.length, Math.min(content.length, index + text.length + 100));

  const isCall = /[\(\<]\s*$/.test(text) || /^\s*[\(\<]/.test(tail); // Supports generateText( and generateText<
  const isImport = /(?:import|require|from)\s+[\{\*a-zA-Z0-9_\s,]*$/.test(head.trim());
  const isString = /['"`]\s*$/.test(head.substring(head.length - 2)) && /^\s*['"`]/.test(tail);

  if (isCall) return 'invocation';
  if (isImport) return 'import';
  if (isString) return 'literal';
  return 'mention';
}

/**
 * Extracts import/require targets from file content.
 */
function extractImports(content, language) {
  const imports = new Set();
  
  if (language === 'python') {
    const fromRegex = /^from\s+([a-zA-Z0-9_\.]+)\s+import/gm;
    const importRegex = /^import\s+([a-zA-Z0-9_\.]+)/gm;
    let m;
    while ((m = fromRegex.exec(content)) !== null) imports.add(m[1]);
    while ((m = importRegex.exec(content)) !== null) imports.add(m[1]);
  } else {
    // JS/TS
    const esmRegex = /import\s+(?:[\{\*a-zA-Z0-9_\s,]*from\s+)?['"]([^'"]+)['"]/g;
    const cjsRegex = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
    let m;
    while ((m = esmRegex.exec(content)) !== null) imports.add(m[1]);
    while ((m = cjsRegex.exec(content)) !== null) imports.add(m[1]);
  }
  
  return Array.from(imports);
}

/**
 * Builds a bi-directional dependency graph across the repository.
 */
function buildDependencyGraph(repoFiles) {
  const graph = {
    imports: {}, // file -> [imported targets]
    imported_by: {} // target -> [files]
  };

  repoFiles.forEach(file => {
    if (file.category !== 'source') return;
    try {
      const content = fs.readFileSync(file.fullPath, 'utf8');
      const foundImports = extractImports(content, file.language);
      
      graph.imports[file.path] = foundImports;
      foundImports.forEach(target => {
        if (!graph.imported_by[target]) graph.imported_by[target] = [];
        graph.imported_by[target].push(file.path);
      });
    } catch (e) {}
  });

  return graph;
}

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
  'vendor', 'target', 'obj', 'bin-builds', '.next', '.astro', '.sentinel'
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
  const extCounts = {};
  files.forEach(f => {
    const ext = path.extname(f.path) || 'no-ext';
    extCounts[ext] = (extCounts[ext] || 0) + 1;
  });
  return files;
}

/**
 * Normalizes a path to use forward slashes (Unix-style).
 */
function normalizePath(p) {
  return p.replace(/\\/g, '/');
}

/**
 * Classifies a file based on its extension and path.
 */
function classifyFile(relativePath, fullPath, size) {
  const ext = path.extname(relativePath).toLowerCase();
  const name = path.basename(relativePath).toLowerCase();

  let category = 'unknown'; // Hardened default to avoid noise
  let language = 'unknown';

  if (['.json', '.yaml', '.yml', '.toml', '.xml'].includes(ext)) {
    category = 'config';
    if (['package.json', 'requirements.txt', 'pyproject.toml', 'cargo.toml'].includes(name)) {
      category = 'dependency';
    }
  } else if (['.md', '.txt', '.pdf', '.docx'].includes(ext)) {
    category = 'doc';
  } else if (['.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs', '.mdx', '.py', '.rs', '.go', '.java', '.cpp'].includes(ext)) {
    category = 'source';
  }

  // Language detection
  const langMap = {
    '.js': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.jsx': 'javascript',
    '.mjs': 'javascript', '.cjs': 'javascript', '.mdx': 'markdown',
    '.py': 'python', '.rs': 'rust', '.go': 'go', '.java': 'java', '.cpp': 'cpp'
  };
  language = langMap[ext] || 'unknown';

  return {
    path: relativePath,
    fullPath: fullPath,
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
function extractSignals(repoFiles, rules, probingRules = null, dependencyGraph = null, commitId = 'unknown') {
  let signals = [];
  const isDebug = process.env.SENTINEL_DEBUG === 'true';
  const discoveryRules = rules; // for internal consistency
  
  for (const file of repoFiles) {
    const normalizedPath = normalizePath(file.path);
    if (isDebug) console.log(`[DEBUG-EXTRACT] File: ${normalizedPath} | Category: ${file.category}`);
    const isNoisePath = /(^|\/)(docs|migrations|dist|public)(\/|$)/i.test(normalizedPath);
    const isComplianceDoc = normalizedPath.startsWith('docs/compliance/') || normalizedPath.includes('/docs/compliance/');
    const fileImports = (dependencyGraph && dependencyGraph.imports[file.path]) || [];

    // 1. Dependency Check
    if (file.category === 'dependency') {
      try {
        const content = fs.readFileSync(file.fullPath, 'utf8');
        let deps = {};
        if (file.path.endsWith('package.json')) {
           const pkg = JSON.parse(content);
           deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}) };
        } else if (file.path.endsWith('requirements.txt')) {
           // Python Support: Scan requirements.txt
           content.split('\n').forEach(line => {
              const match = line.match(/^([a-zA-Z0-9_\-]+)/);
              if (match) deps[match[1].toLowerCase()] = true;
           });
        } else if (file.path.endsWith('pyproject.toml')) {
           // Python Support: Scan pyproject.toml
           const lines = content.split('\n');
           let inDeps = false;
           for (const line of lines) {
             if (line.match(/^\[.*dependencies\]/)) inDeps = true;
             else if (line.startsWith('[')) inDeps = false;
             else if (inDeps) {
               const match = line.match(/^([a-zA-Z0-9_\-]+)\s*=/);
               if (match) deps[match[1].toLowerCase()] = true;
             }
           }
        }
        for (const [dep, ver] of Object.entries(deps)) {
          const rule = rules.dependencies[dep];
          if (rule) {
            signals.push({
              id: `DEP_${dep.toUpperCase()}`,
              kind: 'dependency',
              source_path: file.path,
              confidence: 1.0,
              evidence_weight: rule.weight || 0.5,
              rule_id: rule.rule_id || `EUAI-DEP-${dep.toUpperCase()}`,
              source_type: rule.source_type || 'technical',
              source_reference: rule.source_reference,
              enforcement_level: rule.enforcement_level || 'informational',
              authority_mapping: rule.authority_mapping
            });
          }
        }
      } catch (e) {
        // Skip malformed JSON or unreadable files
      }
    }
    // 2. Code Signature & Hardening Probes (Forensic Layer)
    if (['source', 'doc'].includes(file.category)) {
      try {
        // Skip technical scanning if it's a known noise path like docs or tests, UNLESS it's a doc hint Check
        if (isNoisePath && !isComplianceDoc) continue;

        const content = fs.readFileSync(file.fullPath, 'utf8');
        const strippedContent = (file.category === 'source') ? stripComments(content, file.language) : content;
        
        // Phase 10: Alias Tracking
        const localAliases = new Set();
        if (file.category === 'source') {
           const aliasRegex = /(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:[a-zA-Z0-9_$]+\.)?(sentinelOverride|sentinelLogger|sentinelAudit)/g;
           let aliasMatch;
           while ((aliasMatch = aliasRegex.exec(content)) !== null) {
              localAliases.add(aliasMatch[1]);
           }
        }
        
        // --- Section 2: Code Signatures (from Manifest) ---
        if (file.category === 'source') {
          for (const rule of rules.code_signatures) {
            const regex = new RegExp(rule.pattern, 'gi');
            if (regex.test(strippedContent)) {
              // Structural check for code signatures (Simple check for first match)
              const firstMatch = strippedContent.match(regex);
              const structType = analyzeStructuralContext(strippedContent, strippedContent.search(regex), firstMatch[0]);
              
              signals.push({
                id: `CODE_${rule.id}`,
                kind: rule.kind || 'code_signature',
                source_path: file.path,
                confidence: 0.8,
                evidence_weight: rule.weight || 0.5,
                rule_id: rule.rule_id || `EUAI-CODE-${rule.id}`,
                source_type: rule.source_type || 'technical',
                source_reference: rule.source_reference,
                enforcement_level: rule.enforcement_level || 'informational',
                authority_mapping: rule.authority_mapping
              });
            }
          }
        }

        // --- Section 3: Hardening Probes (Art 13/14/20 technical proof) ---
        if (file.category === 'source' && probingRules && probingRules.probes) {
          Object.entries(probingRules.probes).forEach(([probeKey, probe]) => {
            // Helper for signal extraction
            const extractProbeSignals = (signalList, type, defaultWeight) => {
              if (!signalList) return;
              signalList.forEach(ps => {
                // Phase 10: Dynamic Alias Support
                const basePattern = ps.pattern;
                const aliases = [];
                const aliasRegex = new RegExp(`(?:var|let|const)\\s+([a-zA-Z0-9_$]+)\\s*=\\s*(?:[a-zA-Z0-9_$]+\\.)?(${basePattern})`, 'g');
                let am;
                while ((am = aliasRegex.exec(content)) !== null) {
                   aliases.push(am[1]);
                }
                
                // Phase 10: String Literal Access (e.g., mod["sentinelOverride"])
                const dynamicPropPattern = `\\[['"]${basePattern}['"]\\]`;
                const patterns = [basePattern, dynamicPropPattern, ...aliases];
                patterns.forEach(pattern => {
                  const regex = new RegExp(pattern, 'gi');
                  let match;
                  while ((match = regex.exec(strippedContent)) !== null) {
                    const lines = content.split('\n');
                    const lineNum = (content.substring(0, match.index).split('\n').length);
                  const structType = analyzeStructuralContext(strippedContent, match.index, match[0]);
                  
                  signals.push({
                    id: ps.id,
                    kind: ps.kind || 'hardening_probe',
                    source_path: file.path,
                    article: probe.article,
                    confidence: ps.weight || defaultWeight,
                    evidence_weight: ps.weight || defaultWeight,
                    line: lineNum,
                    snippet: (lines[lineNum - 1] || '').trim(),
                    rule_id: ps.rule_id || probe.rule_id || `EUAI-PROBE-${ps.id}`,
                    source_type: ps.source_type || probe.source_type || 'technical',
                    source_reference: ps.source_reference || probe.source_reference,
                    enforcement_level: ps.enforcement_level || probe.enforcement_level || 'mandatory',
                    authority_mapping: ps.authority_mapping || probe.authority_mapping
                  });
                  if (type === 'strong' && isDebug) {
                    console.log(`[FORENSIC] Signal Match: ${ps.id} in ${file.path}:${lineNum}`);
                  }
                    if (signals.length > 5000) break;
                  }
                });
              });
            };

            extractProbeSignals(probe.strong_signals, 'strong', 1.0);
            extractProbeSignals(probe.traceability_signals, 'traceability', 0.7);
            extractProbeSignals(probe.weak_signals, 'weak', 0.5);
          });
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

  // 4. Behavioral Heuristics Layer (Phase 16.4 fallback)
  if (signals.length === 0) {
    const suspicionScore = analyzeBehavioralSuspicion(repoFiles);
    if (suspicionScore >= 2) {
       signals.push({
         id: "BEHAVIORAL_SUSPICION_FLAG_HIGH_RISK",
         kind: "code_signature",
         source_path: "repository_behavior_analysis",
         sha256: "unknown",
         commit: "unknown",
         confidence: 1.0,
         evidence_weight: 1.0,
         category: "unrecognized_ai_system",
         articles: ["Art. 6", "Art. 13", "Art. 14"],
         line: 1,
         snippet: `[BEHAVIORAL HEURISTIC] High suspicion of obfuscated or non-standard AI integration. Score: ${suspicionScore}`,
         source_sha256: "unknown",
         evidence_sha256: "unknown",
         rule_id: "EUAI-BEHAVIOR-001",
         source_type: "inference",
         enforcement_level: "critical",
         authority_mapping: { "framework": "EU AI Act", "article": "Article 6", "notes": "Behavioral suspicion of high-risk obfuscation" }
       });
    }
  }

  // 5. Signal Validation Layer (Phase 16.5)
  if (signals.length > 0) {
    signals = validateSignalConnectivity(signals, repoFiles);
  }

  return signals;
}

/**
 * Validates that detected signals are functional and connected, not just decoys.
 */
function validateSignalConnectivity(signals, repoFiles) {
  const validated = [];
  const fileCache = new Map();

  for (const signal of signals) {
    if (signal.kind !== 'hardening_probe') {
      validated.push(signal);
      continue;
    }

    const filePath = path.join(process.cwd(), signal.source_path);
    if (!fileCache.has(filePath)) {
      try {
        fileCache.set(filePath, fs.readFileSync(filePath, 'utf8'));
      } catch (e) {
        fileCache.set(filePath, '');
      }
    }
    const content = fileCache.get(filePath);
    const lines = content.split('\n');

    let searchPattern = '';
    if (signal.matched_text) {
       searchPattern = signal.matched_text.replace(/\\b/g, '').replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
    } else {
       const word = signal.id.split('_').pop().toLowerCase();
       if (word.length > 3) searchPattern = word;
    }

    if (!searchPattern) {
      validated.push(signal);
      continue;
    }

    const regex = new RegExp(`\\b${searchPattern}\\b`, 'gi');
    const matches = content.match(regex) || [];
    
    // Heuristic 1: Call/Usage Pattern (e.g. .term or term() or term:)
    const isCalledOrAssigned = new RegExp(`\\b${searchPattern}\\b\\s*[\\(:=]|\\.\\b${searchPattern}\\b`, 'i').test(content);
    
    // Heuristic 2: Proximity to Logic
    const signalLineIdx = signal.line - 1;
    const start = Math.max(0, signalLineIdx - 5);
    const end = Math.min(lines.length, signalLineIdx + 10);
    const window = lines.slice(start, end).join('\n');
    const inLogic = /\b(if|return|await|process|handler|try|exports|module|function)\b/i.test(window);

    // Heuristic 3: Effect Check (Phase 16.6)
    let hasEffect = true;
    if (signal.id.includes('KILL_SWITCH') || signal.id.includes('OVERRIDE')) {
       // Must have a blocking or flow-altering keyword in proximity or body
       hasEffect = /\b(throw|process\.exit|exit\(|abort\(|return|stopExecution|break|continue|reject\(|@abort)\b/i.test(window);
       // Reject vacuous bodies: { return true; }
       if (hasEffect && /\{\s*return\s+(true|false|null|undefined|1|0)\s*;\s*\}/i.test(window)) {
          hasEffect = false;
       }
    } else if (signal.id.includes('DISCLOSURE')) {
       hasEffect = /\b(console\.(log|error|info|warn)|print\(|write\(|alert\(|Response|render|display|show|Toast|Label)\b/i.test(window);
    }
    
    const isIsolated = matches.length === 1;

    // VALID if:
    // 1. It's not isolated (appears in multiple places like def + usage)
    // 2. OR it is a Transparency Disclosure with a clear Output Effect (Phase 16.6 Fix)
    // AND it has some functional context (is called, assigned, or near logic)
    // AND it has a detectable effect (Phase 16.6)
    
    const isDisclosureWithEffect = signal.id.includes('DISCLOSURE') && hasEffect;

    if ((!isIsolated || isDisclosureWithEffect) && (isCalledOrAssigned || inLogic) && hasEffect) {
       validated.push(signal);
    } else if (process.env.SENTINEL_DEBUG === 'true') {
       console.error(`[INTEGRITY-LAYER] Dropping suspicious signal: ${signal.id} - Text: "${searchPattern}" (Matches: ${matches.length}, Logic: ${inLogic}, Effect: ${hasEffect}, DisclosureEffect: ${isDisclosureWithEffect})`);
    }
  }

  return validated;
}

/**
 * Analyzes the repository for behavioral suspicions of obfuscated AI usage.
 * @param {RepoFile[]} repoFiles - All audited files
 * @returns {number} The aggregated suspicion score
 */
function analyzeBehavioralSuspicion(repoFiles) {
  let score = 0;
  
  // 1. Config AI Endpoints and Params
  const configFiles = repoFiles.filter(f => f.path.match(/\.(json|yaml|yml|env|ini)$/i));
  for (const file of configFiles) {
    const normalizedPath = normalizePath(file.path);
    const isNoisePath = /(^|\/)(docs|content|examples|tests|test|spec|migrations|dist|assets|public)(\/|$)/i.test(normalizedPath);
    if (isNoisePath) continue;
    try {
      const content = fs.readFileSync(path.join(process.cwd(), file.path), 'utf8').toLowerCase();
      // Look for recognizable endpoints or system prompts in config
      if (content.match(/v1\/chat\/completions|api\.openai\.com|api\.anthropic\.com|bedrock\.aws/i)) {
        score += 2;
      }
      if (content.match(/("system_prompt"|"temperature"\s*:\s*0\.|"max_tokens"|sk-ant-)/)) {
        score += 1;
      }
    } catch(e) {}
  }

  // 2. Code Behavioral Obfuscation / Wrappers
  const codeFiles = repoFiles.filter(f => f.path.match(/\.(js|ts|py|go|java)$/i));
  for (const file of codeFiles) {
    const normalizedPath = normalizePath(file.path);
    const isNoisePath = /(^|\/)(docs|content|examples|tests|test|spec|migrations|dist|assets|public)(\/|$)/i.test(normalizedPath);
    if (isNoisePath) continue;

    try {
        // Skip technical scanning if it's a known noise path like docs or tests, UNLESS it's a doc hint Check
        if (file.category === 'source' && isNoisePath) continue;

        const content = fs.readFileSync(path.join(process.cwd(), file.path), 'utf8');

        // 2. Scan core code signatures
        // Dynamic import with string concat: import('open' + 'ai')
        if (content.match(/import\s*\(\s*['"][a-z]+['"]\s*\+\s*['"][a-z]+['"]\s*\)/i)) {
        score += 2;
      }
      // Require with string concat: require('sc' + 'ikit')
      if (content.match(/require\s*\(\s*['"][a-z]+['"]\s*\+\s*['"][a-z]+['"]\s*\)/i)) {
        score += 2;
      }
      
      // Generic wrapper: fetch + prompt/payload concept
      if (content.match(/(fetch|axios\.|request\(|httpx\.|requests\.)/)) {
          if (content.match(/(prompt|payload|messages|completion|input|generate)/i)) {
              if (content.match(/(Authorization|Bearer)/i)) {
                 score += 1.5;
              } else {
                 score += 0.5;
              }
          }
      }
    } catch(e) {}
  }

  return score;
}

/**
 * Detects AI intent based on project metadata.
 */
function detectHeuristicIntent(repoFiles) {
  const aiKeywords = [
    'ai-app', 'ai-service', 'ai-model', 'gpt', 'llm', 'bot', 'chat', 'intelligence', 'classifier', 'prediction',
    'transformer', 'hugging', 'torch', 'tensor', 'learning', 'embedding', 'vector', 'inference', 'vision', 'neural'
  ];
  
  // 1. Check ALL package.json files (Monorepo Support)
  const pkgFiles = repoFiles.filter(f => f.path.endsWith('package.json'));
  for (const pkgFile of pkgFiles) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgFile.fullPath, 'utf8'));
      const name = (pkg.name || '').toLowerCase();
      const desc = (pkg.description || '').toLowerCase();
      if (aiKeywords.some(k => name.includes(k) || desc.includes(k))) return true;
    } catch (e) {}
  }

  // 2. Check requirements.txt and pyproject.toml
  const pythonMeta = repoFiles.filter(f => f.path.endsWith('requirements.txt') || f.path.endsWith('pyproject.toml'));
  for (const pyFile of pythonMeta) {
    try {
      const content = fs.readFileSync(pyFile.fullPath, 'utf8').toLowerCase();
      if (aiKeywords.some(k => content.includes(k))) return true;
    } catch (e) {}
  }
  
  // 3. Check Directory Name
  const rootDirName = path.basename(process.cwd()).toLowerCase();
  if (aiKeywords.some(k => rootDirName.includes(k))) return true;

  return false;
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
      recommendation: 'Add "biometric_identification_enabled" to your declared_flags and ensure compliance with Article 10.'
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

/**
 * Extracts context around a match.
 */
function extractContext(lines, lineNum) {
  const start = Math.max(0, lineNum - 3);
  const end = Math.min(lines.length, lineNum + 3);
  return lines.slice(start, end).join('\n');
}

/**
 * Phase 14.3: CI/CD & Test Evidence Discovery Extensions
 */

function discoverCiCdSignals(repoFiles) {
  const ciCdFiles = [];
  const patterns = [
    { regex: /\.github\/workflows\/.*\.ya?ml$/i, type: 'github_actions' },
    { regex: /\.gitlab-ci\.yml$/i, type: 'gitlab_ci' },
    { regex: /azure-pipelines\.yml$/i, type: 'azure_pipelines' },
    { regex: /circle\.yml$/i, type: 'circle_ci' },
    { regex: /\.circleci\/config\.yml$/i, type: 'circle_ci' }
  ];

  for (const file of repoFiles) {
    const normalizedPath = normalizePath(file.path);
    for (const pattern of patterns) {
      if (pattern.regex.test(normalizedPath)) {
        const steps = _extractCiCdSteps(file.fullPath);
        ciCdFiles.push({
          path: normalizedPath,
          type: pattern.type,
          steps
        });
        break;
      }
    }
  }
  return ciCdFiles;
}

function _extractCiCdSteps(fullPath) {
  const steps = [];
  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    const lines = content.split('\n');
    let currentStep = null;

    for (let line of lines) {
      const nameMatch = line.match(/^\s*-?\s*name:\s*(.*?)\s*$/i);
      const runMatch = line.match(/^\s*-?\s*run:\s*(.*?)\s*$/i) || line.match(/^\s*-?\s*script:\s*(.*?)\s*$/i);

      if (nameMatch) {
        currentStep = { 
          name: nameMatch[1].trim().replace(/^['"]|['"]$/g, ''), 
          run: "" 
        };
        steps.push(currentStep);
      }

      if (runMatch) {
        const runVal = runMatch[1].trim().replace(/^['"]|['"]$/g, '');
        if (currentStep) {
          currentStep.run = runVal;
        } else {
          currentStep = { name: "unnamed", run: runVal };
          steps.push(currentStep);
        }
      }
    }

    // Phase 3: Classification pass (Deterministic)
    steps.forEach(s => {
      s.type = _classifyStep(s.name, s.run);
    });
  } catch (e) {}
  return steps;
}

function _classifyStep(name = '', run = '') {
  const content = (name + ' ' + run).toLowerCase();
  if (content.includes('test') || content.includes('jest') || content.includes('pytest') || content.includes('npm test')) return 'test';
  if (content.includes('build')) return 'build';
  if (content.includes('lint')) return 'lint';
  if (content.includes('security') || content.includes('scan')) return 'security';
  if (content.includes('deploy')) return 'deploy';
  return 'unknown';
}

function discoverTestFiles(repoFiles) {
  const testFiles = [];
  const testPatterns = [
    /(^|[\\/])tests?([\\/])/i,
    /(^|[\\/])__tests__([\\/])/i,
    /\.test\./i,
    /\.spec\./i
  ];

  for (const file of repoFiles) {
    const normalizedPath = normalizePath(file.path);
    if (testPatterns.some(pattern => pattern.test(normalizedPath))) {
      testFiles.push({
        path: normalizedPath,
        signals: _extractTestSignals(file.fullPath)
      });
    }
  }
  return testFiles;
}

function _extractTestSignals(fullPath) {
  const DEFAULT_SIGNALS = { has_assertions: false, has_test_blocks: false, mentions_logging: false };
  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    return {
      has_assertions: /expect\(|assert|should/i.test(content),
      has_test_blocks: /describe\(|it\(/i.test(content),
      mentions_logging: /log|trace|logger/i.test(content)
    };
  } catch (e) {
    return DEFAULT_SIGNALS;
  }
}

function correlateSignals(ciCdFiles, testFiles) {
  const correlation = {
    test_execution_pipeline: false,
    test_validation_signals: false
  };

  // Case 1: CI/CD step.type == "test" AND test_files.length > 0
  const hasTestStep = ciCdFiles.some(f => f.steps.some(s => s.type === 'test'));
  if (hasTestStep && testFiles.length > 0) {
    correlation.test_execution_pipeline = true;
  }

  // Case 2: test_files exist AND any test_file.signals.has_assertions == true
  const hasAssertions = testFiles.some(f => f.signals.has_assertions === true);
  if (testFiles.length > 0 && hasAssertions) {
    correlation.test_validation_signals = true;
  }

  return correlation;
}

module.exports = {
  crawlRepository,
  classifyFile,
  extractSignals,
  verifyAlignment,
  generateManifestFromSignals,
  detectHeuristicIntent,
  buildDependencyGraph,
  discoverCiCdSignals,
  discoverTestFiles,
  correlateSignals
};
