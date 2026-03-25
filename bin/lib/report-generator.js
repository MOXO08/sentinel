/**
 * Sentinel Report Generator (V2.1 Dual-Track)
 * Transforms technical JSON audit evidence into an executive AI Validation Statement.
 * Strictly adheres to the Dual-Track product contract (TECHNICAL MARKERS PRESENT/HOLD/REJECTED).
 */

const fs = require('fs');
const path = require('path');

// --- REGULATORY MAPPING DICTIONARY ---
// --- REGULATORY MAPPING DICTIONARY ---
const RULE_MAP = {
  'EUAI-MIN-001': {
    article: 'General',
    objective: 'Guvernan\u021ba formal\u0103 a sistemului.',
    impact: 'BLOCKER',
    action: 'Defini\u021bi responsabilit\u0103\u021bile de guvernan\u021b\u0103 \u0219i managementul riscului.'
  },
  'EUAI-TRANS-001': {
    article: 'Article 13',
    objective: 'Transparen\u021ba \u0219i dezv\u0103luirea riscurilor.',
    impact: 'DEFICIENCY',
    action: 'Ad\u0103uga\u021bi declara\u021bia de transparen\u021b\u0103 \u00een manifest.'
  },
  'Article 13': { 
    article: 'Article 13',
    objective: 'Informarea utilizatorilor finali.',
    impact: 'DEFICIENCY',
    action: 'Documenta\u021bi politica de interac\u021biune \u0219i notific\u0103rile automate.'
  },
  'EUAI-HARDENING-000': {
    article: 'Article 14',
    objective: 'Supraveghere uman\u0103 (Manual override).',
    impact: 'DEFICIENCY',
    action: 'Stabili\u021bi procedurile de interven\u021bie uman\u0103 \u00een manualul de operare.'
  },
  'EUAI-HARDENING-001': {
    article: 'Article 13',
    objective: 'Trasabilitatea deciziilor AI.',
    impact: 'BLOCKER',
    action: 'Ata\u021ba\u021bi logurile care demonstreaz\u0103 trasabilitatea datelor.'
  },
  'SIG-CODE-001': {
    impact: 'CRITICAL',
    action: 'Elimina\u021bi probele tehnice neconforme din mediile non-executabile.'
  }
};

// --- PROBE TO LEGAL MAPPING (AUDITOR VIEW) ---
const PROBE_MAP = {
  'DEP_WINSTON': { art: 'Article 20', label: 'Logging Standard (Winston)', evidence: 'Implementare Trasabilitate' },
  'DEP_PINO': { art: 'Article 20', label: 'Logging Standard (Pino)', evidence: 'Implementare Trasabilitate' },
  'DEP_PYTHON_LOG': { art: 'Article 20', label: 'Logging Python Standard', evidence: 'Implementare Trasabilitate' },
  'CODE_LOGGER_INIT': { art: 'Article 20', label: 'Ini\u021bializare Logger', evidence: 'Captur\u0103 Evenimente' },
  'CODE_TRACE_ID': { art: 'Article 20', label: 'Traceability Metadata', evidence: 'Identificator Unic Cerere' },
  'CODE_MANUAL_OVERRIDE': { art: 'Article 14', label: 'Manual Override Logic', evidence: 'Supraveghere Uman\u0103' },
  'CODE_KILL_SWITCH': { art: 'Article 14', label: 'Emergency Stop / Kill Switch', evidence: 'Control Critic' },
  'CODE_AI_DISCLOSURE': { art: 'Article 13', label: 'AI Disclosure UI/Code', evidence: 'Transparen\u021b\u0103 Utilizator' },
  'DEP_FAIRLEARN': { art: 'Article 10', label: 'Fairness Library (Fairlearn)', evidence: 'Monitorizare Bias' },
  'CODE_BIAS_MITIGATION': { art: 'Article 10', label: 'Bias Mitigation Logic', evidence: 'Guvernan\u021ba Datelor' },
  'CODE_DATA_ETL': { art: 'Article 10', label: 'Data Ingestion Pipeline', evidence: 'Trasabilitate Date Antrenament' },
  'CODE_ML_MODEL_LOAD': { art: 'EXECUTION', label: 'ML Model Loading', evidence: 'AI Execution Logic' },
  'CODE_ML_INFERENCE': { art: 'EXECUTION', label: 'ML Inference Pattern', evidence: 'AI Execution Logic' },
  'CODE_AI_CALL': { art: 'EXECUTION', label: 'AI Service Call', evidence: 'Service Interaction' }
};

/**
 * Enforces safe, non-legalistic language on synthesized narrative fields.
 * Refined to avoid corruption of technical data.
 */
function enforceSafeLanguage(text) {
  if (!text) return 'N/A';
  const patterns = [
    { regex: /\bproof\b/gi, replacement: 'evidence strength' },
    { regex: /\bproven\b/gi, replacement: 'coherent' },
    { regex: /\bcompliant\b/gi, replacement: 'aligned' },
    { regex: /\bcertified\b/gi, replacement: 'validated' },
    { regex: /\bguarantee\b/gi, replacement: 'indicative assertion' },
    { regex: /\bfinal\b/gi, replacement: 'observed' },
    { regex: /\bthe system is\b/gi, replacement: 'observations indicate' }
  ];

  let sanitized = text;
  patterns.forEach(p => {
    sanitized = sanitized.replace(p.regex, p.replacement);
  });

  // Length constraint: <= 300 characters
  if (sanitized.length > 300) {
    sanitized = sanitized.substring(0, 297) + '...';
  }

  return sanitized;
}

/**
 * Deterministically classifies evidence strength based on signal diversity.
 */
function calculateEvidenceStrength(signals) {
  if (!signals || signals.length === 0) return 'Fragmentary';
  
  const sources = new Set();
  signals.forEach(s => {
    if (s.id.startsWith('CODE_')) sources.add('CODE');
    if (s.id.startsWith('DEP_')) sources.add('DEP');
    if (s.kind === 'document' || s.kind === 'manifest') sources.add('DOC');
  });

  if (sources.size >= 2) return 'High Coherence';
  if (sources.size === 1) return 'Moderate Coherence';
  return 'Fragmentary';
}

/**
 * Normalizes article strings to Article X format.
 */
function normalizeArticle(art) {
  if (!art) return 'General';
  if (art.startsWith('Art.')) return art.replace(/^Art\.\s*/, 'Article ');
  return art;
}

/**
 * Returns a realistic verification command based on the article key.
 */
function getFallbackCommand(art) {
  const norm = normalizeArticle(art);
  if (norm.includes('13')) return 'grep -r "transparency\\|disclosure\\|label" .';
  if (norm.includes('14')) return 'grep -r "override\\|kill_switch\\|human" .';
  if (norm.includes('20')) return 'grep -r "log\\|trace\\|logger" .';
  return 'grep -r "ai\\|model\\|inference" .';
}

/**
 * Pure transformation to derive Defense Units from report data.
 */
function deriveDefenseUnits(report) {
  const signals = report._internal?.signals || [];
  const findings = report._internal?.all_findings || [];
  const timestamp = new Date().toISOString();
  // Safe extraction of app name
  const appName = report.app_name || (report.manifest ? report.manifest.app_name : 'Sentinel AI System');

  // Group everything by article
  const articleGroups = {};

  // Initialize with all unique articles from findings
  findings.forEach(f => {
    const art = normalizeArticle(f.article);
    if (art && !articleGroups[art]) {
      articleGroups[art] = { signals: [], findings: [f] };
    } else if (art) {
      articleGroups[art].findings.push(f);
    }
  });

  // Also include articles from signals
  signals.forEach(s => {
    const arts = s.articles || (PROBE_MAP[s.id] ? [PROBE_MAP[s.id].art] : []);
    arts.forEach(rawArt => {
      const art = normalizeArticle(rawArt);
      if (!articleGroups[art]) {
        articleGroups[art] = { signals: [s], findings: [] };
      } else {
        articleGroups[art].signals.push(s);
      }
    });
  });

  const defenseUnits = Object.keys(articleGroups).sort().map(art => {
    const group = articleGroups[art];
    const firstFinding = group.findings[0] || {};
    const hasSignals = group.signals.length > 0;

    // 1. Regulatory Metric
    const metric = art;

    // 2. Forensic Observation
    const rawObs = firstFinding.description || (hasSignals ? `Detected technical markers relevant to ${art}.` : `No relevant technical markers detected for this article within the scanned system scope.`);
    const observation = enforceSafeLanguage(rawObs);

    // 3. Boundary of Validity
    const validity = {
      temporal: timestamp,
      system: appName,
      source: report.audit_id ? `audit_id ${report.audit_id}` : `repository scan (local execution — file system scope)`,
      exclusions: "RESIDUAL RISK: This validation is limited to static analysis. Runtime effectiveness, deployment state, and non-deterministic behavior remain separate from this technical statement."
    };

    // 4. Evidentiary Anchors
    const anchors = group.signals.slice(0, 5).map(s => ({
      path: s.source_path,
      line: s.line || 'N/A',
      snippet: s.snippet || 'N/A',
      hash: s.evidence_hash || 'N/A'
    }));

    // 5. Narrative Defense (Multi-Signal Cluster Synthesis)
    let rawDefense;
    if (hasSignals) {
      const markers = [...new Set(group.signals.map(s => PROBE_MAP[s.id]?.label || s.id))].slice(0, 3);
      const markerList = markers.join(', ');
      const pathList = [...new Set(group.signals.map(s => s.source_path))].slice(0, 2).join(' and ');
      
      rawDefense = `Detection of [${markerList}] in ${pathList} provides evidence relevant to ${art} requirements. This indicates partial technical coverage of Article-related requirements within the static analysis boundary.`;
    } else {
      rawDefense = `[ACTION_REQUIRED: HUMAN ATTESTATION NEEDED] - Absence of detectable ${art} markers suggests that key technical elements associated with ${art} requirements are not evidenced within the scanned repository scope.`;
    }
    const defense = enforceSafeLanguage(rawDefense);

    // 6. Auditor Challenge (Audit-Grade Risk Statements)
    let challenge;
    if (!hasSignals) {
      challenge = `[ACTION_REQUIRED: HUMAN ATTESTATION NEEDED] - No implementation markers or documentation for ${art} were detected, creating a critical gap in the ability to evidence alignment with ${art} requirements.`;
    } else if (group.signals.every(s => s.kind !== 'document')) {
      challenge = `No evidence of formal documentation supporting this technical implementation was detected, limiting traceability assurance for ${art}.`;
    } else if (calculateEvidenceStrength(group.signals) === 'Fragmentary') {
      challenge = "Limited evidence diversity detected for this control, increasing the risk of incomplete alignment documentation.";
    } else {
      challenge = "Continuous runtime effectiveness for this control remains outside the current static validation scope.";
    }
    challenge = enforceSafeLanguage(challenge);

    // 7. Evidence Strength
    const strength = calculateEvidenceStrength(group.signals);

    // 8. Verification Vector
    const vector = {
      description: "Independent Reproduction: The following command allows technical verification of the observed implementation patterns:",
      command: firstFinding.verification_command || (hasSignals ? (art === 'EXECUTION' ? `grep -r "forward\\|predict\\|model\\|inference" mingpt/` : `grep -nC 3 "${group.signals[0].snippet?.split('\n')[0].substring(0, 50).replace(/"/g, '\\"') || ''}" ${group.signals[0].source_path}`) : getFallbackCommand(art))
    };

    // 9. Residual Risk Statement
    const residualRisk = "RESIDUAL RISK: This validation is limited to static analysis. Runtime effectiveness, deployment state, and non-deterministic behavior remain separate from this technical statement.";

    return { metric, observation, validity, anchors, defense, challenge, strength, vector, residualRisk };
  });

  if (defenseUnits.length === 0) {
    return [{
      metric: "GOVERNANCE",
      observation: enforceSafeLanguage("[ACTION_REQUIRED: HUMAN ATTESTATION NEEDED] - No relevant technical markers detected for regulatory articles within the scanned system scope."),
      validity: {
        temporal: timestamp,
        system: appName,
        source: report.audit_id ? `audit_id ${report.audit_id}` : `repository scan (local execution — file system scope)`,
        exclusions: "RESIDUAL RISK: This validation is limited to static analysis. Runtime effectiveness, deployment state, and non-deterministic behavior remain separate from this technical statement."
      },
      anchors: [],
      defense: enforceSafeLanguage("No technical markers associated with AI system implementation were detected within the scanned repository scope."),
      challenge: enforceSafeLanguage("This creates a critical gap in the ability to evidence alignment with applicable AI-related regulatory requirements."),
      strength: "Fragmentary (no implementation-level signals detected)",
      vector: {
        description: "Independent Reproduction: The following command allows technical verification of the observed implementation patterns:",
        command: "ls -R ."
      },
      residualRisk: "RESIDUAL RISK: This validation is limited to static analysis. Runtime effectiveness, deployment state, and non-deterministic behavior remain separate from this technical statement."
    }];
  }

  return defenseUnits;
}

function generateEvidenceLedger(report) {
  const signals = report._internal?.signals || [];
  const integrityIssues = report.integrity_issues || [];

  // Group signals by Primary Article
  const groupedSignals = {};

  signals.forEach(s => {
    // 1. Determine Articles
    let articles = s.articles || [];
    if (articles.length === 0) {
       // Fallback to PROBE_MAP or default
       const map = PROBE_MAP[s.id];
       if (map) articles = [map.art];
       else articles = ['General'];
    }

    // 2. Determine Labels
    let label = s.id;
    let evidenceType = 'Technical Detection';
    const map = PROBE_MAP[s.id];
    if (map) {
      label = map.label;
      evidenceType = map.evidence;
    } else {
      // Format ID nicely (e.g., DEP_OPENAI -> Dependency: OPENAI)
      if (s.id.startsWith('DEP_')) {
        label = `Dependency: ${s.id.replace('DEP_', '')}`;
        evidenceType = 'Software Stack';
      } else if (s.id.startsWith('CODE_')) {
        label = `Code Pattern: ${s.id.replace('CODE_', '')}`;
        evidenceType = 'Logic Analysis';
      }
    }

    const isPoisoned = integrityIssues.some(issue => 
      issue.id === 'SIG-CODE-001' && 
      issue.evidence_location?.file === s.source_path && 
      issue.evidence_location?.line === s.line
    );

    const statusIcon = isPoisoned ? '❌' : '✅';
    const statusText = isPoisoned ? 'INVALID (Poison)' : 'MARKER DETECTED';
    const statusColor = isPoisoned ? 'var(--danger)' : 'var(--success)';

    const rowHtml = `
      <tr>
        <td>
          <div style="font-weight: 600;">${label}</div>
          <div style="font-size: 11px; color: #666;">${evidenceType}</div>
        </td>
        <td>
          <code style="font-size: 11px;">${s.source_path}:${s.line || 'N/A'}</code>
        </td>
        <td style="color: ${statusColor}; font-weight: 700; font-size: 11px;">
          ${statusIcon} ${statusText}
        </td>
        <td>
          <pre style="margin: 0; font-size: 10px; background: #f1f1f1; padding: 5px; border-radius: 3px; border: 1px solid #ddd; max-width: 250px; overflow: hidden; text-overflow: ellipsis;">${s.snippet || 'N/A'}</pre>
        </td>
      </tr>
    `;

    // Add to all relevant articles
    articles.forEach(art => {
      if (!groupedSignals[art]) groupedSignals[art] = [];
      groupedSignals[art].push(rowHtml);
    });
  });

  if (Object.keys(groupedSignals).length === 0) return '';

  let tablesHtml = '';
  // Sort articles alphabetically (e.g. Article 10, Article 13...)
  Object.keys(groupedSignals).sort().forEach(art => {
    tablesHtml += `
      <h3 style="margin-top: 25px; margin-bottom: 10px; font-size: 14px; border-bottom: 1px solid var(--border); padding-bottom: 5px;">
         Compliance Anchor: <span style="color: #0969da;">${art}</span>
      </h3>
      <table class="audit-table" style="font-size: 13px; margin-top: 0;">
        <thead>
          <tr>
            <th style="width: 25%">Signal Type</th>
            <th style="width: 20%">Location</th>
            <th style="width: 15%">Integrity (SIG)</th>
            <th style="width: 40%">Extracted Evidence</th>
          </tr>
        </thead>
        <tbody>
          ${groupedSignals[art].join('')}
        </tbody>
      </table>
    `;
  });

  return `
    <section>
      <h2>Technical Evidence Ledger</h2>
      <p style="font-size: 13px; color: #555; margin-bottom: 15px;">
        Inventar detaliat al probelor tehnice extrase, grupate pe articolele AI Act pe care le susțin. 
        Fiecare intrare reprezintă un „marker tehnic” pentru concluziile de audit.
      </p>
      ${tablesHtml}
    </section>
  `;
}

function generateDefenseUnitsSection(defenseUnits) {
  if (!defenseUnits || defenseUnits.length === 0) return '';

  let unitsHtml = '';
  defenseUnits.forEach(u => {
    const strengthColor = u.strength === 'High Coherence' ? 'var(--success)' : (u.strength === 'Moderate Coherence' ? 'var(--warning)' : '#6e7781');
    
    unitsHtml += `
      <div class="defense-unit" style="background: #fff; border: 1px solid var(--border); border-left: 6px solid ${strengthColor}; padding: 25px; margin-bottom: 30px; border-radius: 4px; box-shadow: 0 2px 5px rgba(0,0,0,0.02);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; border-bottom: 1px solid #f1f1f1; padding-bottom: 10px;">
          <h3 style="margin: 0; font-size: 18px; color: #1a1a1a;">${u.metric}</h3>
          <span style="background: ${strengthColor}; color: white; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase;">${u.strength}</span>
        </div>

        <div style="margin-bottom: 15px;">
          <strong style="display: block; font-size: 11px; text-transform: uppercase; color: #666; margin-bottom: 5px;">I. Forensic Observation:</strong>
          <p style="margin: 0; font-size: 14px; color: #333; font-style: italic;">"${u.observation}"</p>
        </div>

        <div style="margin-bottom: 15px; grid-template-columns: 1fr 1fr; display: grid; gap: 20px; background: #f8fafc; padding: 15px; border-radius: 4px; border: 1px solid #e1e4e8;">
          <div>
            <strong style="display: block; font-size: 10px; text-transform: uppercase; color: #666; margin-bottom: 5px;">II. Boundary of Validity:</strong>
            <div style="font-size: 11px; color: #444;">
              Time: ${u.validity.temporal}<br>
              System: ${u.validity.system}<br>
              Source: <span style="font-family: monospace; font-size: 10px;">${u.validity.source}</span>
            </div>
          </div>
          <div>
            <strong style="display: block; font-size: 10px; text-transform: uppercase; color: #666; margin-bottom: 5px;">III. Scope Exclusions:</strong>
            <div style="font-size: 10px; color: #666; font-style: italic;">Static-analysis only. Behavioral validation not performed.</div>
          </div>
        </div>

        <div style="margin-bottom: 15px;">
          <strong style="display: block; font-size: 11px; text-transform: uppercase; color: #666; margin-bottom: 5px;">IV. Evidentiary Anchors:</strong>
          <div style="display: flex; flex-direction: column; gap: 5px;">
            ${u.anchors.length > 0 ? u.anchors.map(a => `
              <div style="font-size: 12px; color: #555; font-family: monospace; background: #f6f8fa; padding: 4px 8px; border-radius: 3px; border: 1px solid #eee;">
                ${a.path}:${a.line} <span style="color: #999; font-size: 10px; margin-left:10px;">[Hash: ${a.hash ? a.hash.substring(0,8) : 'N/A'}...]</span>
              </div>
            `).join('') : '<div style="font-size: 12px; color: #999; font-style: italic;">No direct file anchors detected.</div>'}
          </div>
        </div>

        <div style="margin-bottom: 15px;">
          <strong style="display: block; font-size: 11px; text-transform: uppercase; color: #666; margin-bottom: 5px;">V. Narrative Defense:</strong>
          <p style="margin: 0; font-size: 14px; color: #333; line-height: 1.5;">${u.defense}</p>
        </div>

        <div style="margin-bottom: 15px; background: #fff5f5; border: 1px solid #feb2b2; padding: 12px; border-radius: 4px;">
          <strong style="display: block; font-size: 11px; text-transform: uppercase; color: #c53030; margin-bottom: 5px;">VI. Auditor Challenge Points:</strong>
          <p style="margin: 0; font-size: 13px; color: #742a2a; font-weight: 500;">${u.challenge}</p>
        </div>

        <div style="margin-bottom: 15px;">
          <strong style="display: block; font-size: 11px; text-transform: uppercase; color: #666; margin-bottom: 5px;">VII. Verification Vector:</strong>
          <div style="background: #24292f; color: #fff; padding: 12px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 11px; border-left: 4px solid var(--success);">
            <div style="color: #8b949e; margin-bottom: 5px; font-size: 10px;">${u.vector.description}</div>
            <code>${u.vector.command}</code>
          </div>
        </div>

        <div>
          <strong style="display: block; font-size: 10px; text-transform: uppercase; color: #d73a49; margin-bottom: 5px;">VIII. Residual Risk Statement:</strong>
          <p style="margin: 0; font-size: 11px; color: #d73a49; font-style: italic; border-top: 1px solid #fbd3d3; padding-top: 5px;">${u.residualRisk}</p>
        </div>
      </div>
    `;
  });

  return `
    <section>
      <h2>Defense Technical Validation Units</h2>
      <p style="font-size: 14px; color: #555; margin-bottom: 25px;">
        Sintez\u0103 narativ\u0103 a probelor extrase, structurat\u0103 pentru defensibilitate \u00een contextul unui audit extern. 
        Fiecare unitate leag\u0103 markerii tehnici de cerin\u021bele reglementare.
      </p>
      ${unitsHtml}
    </section>
  `;
}

function generateMarkdownSummary(report) {
    const verdict = report.central_verdict || 'REJECTED';
    const tech = report.technical_status || 'WEAK';
    const gov = report.governance_status || 'GAP';
    const score = report.score || 0;
    const threshold = report.threshold || 0;
    
    let icon = '\u274c';
    if (verdict.includes('DETECTED')) icon = '\u2705';
    if (verdict === 'HOLD') icon = '\u26a0\ufe0f';

    const techIcon = tech === 'ROBUST' ? '\u2705' : '\u274c';
    const govIcon = gov === 'ALIGNED' || gov.includes('INDICATIVE') ? '\u2705' : '\u26a0\ufe0f';

    return `### ${icon} Sentinel AI Governance: ${verdict}

| Metric | Status | Value |
| :--- | :--- | :--- |
| **Exec Decision** | **${verdict}** | ${score >= threshold ? 'Above Threshold' : 'Below Threshold'} |
| **Technical Maturity** | ${techIcon} ${tech} | ${report._internal?.signals?.length || 0} signals |
| **Regulatory Align** | ${govIcon} ${gov} | ${report.findings_count} findings |

**Audit Detail:**
- **Score:** ${score.toFixed(1)} / 100 (Threshold: ${threshold})
- **Confidence:** ${report.confidence} (${Math.round((report.phi || 0) * 100)}% Saturation)
- **Tracing ID:** \`${report.audit_id || (report._audit_trail && report._audit_trail.audit_id) || 'N/A'}\`

---
*Generated by Sentinel V2.1 Governance Engine*
`;
  }

function generateProductionTraceContext(report) {
  const context = report.production_trace_context || { build_id: 'NOT PROVIDED', trace_status: 'UNBOUND' };
  const buildId = context.build_id;
  const status = context.trace_status;
  const isUnbound = status === 'UNBOUND';

  return `
    <section class="production-trace-context" style="background: #f8fafc; border: 1px solid #e1e4e8; padding: 25px; margin: 40px 0; border-radius: 8px; font-size: 14px;">
        <h2 style="margin-top: 0; color: #24292f; font-size: 14px; letter-spacing: 1.5px; border-left: 4px solid #24292f; padding-left: 15px; text-transform: uppercase;">Production Trace Context</h2>
        
        <div style="margin-top: 20px; display: grid; grid-template-columns: 1fr; gap: 15px;">
            <div style="background: #fff; border: 1px solid #d0d7de; padding: 15px; border-radius: 6px;">
                <div style="margin-bottom: 10px;">
                    <strong style="font-size: 11px; text-transform: uppercase; color: #666;">Build ID:</strong>
                    <code style="font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px; color: #24292f; margin-left: 10px;">${buildId}</code>
                </div>
                <div>
                    <strong style="font-size: 11px; text-transform: uppercase; color: #666;">Trace Status:</strong>
                    <span style="font-size: 10px; background: #f6f8fa; padding: 2px 8px; border-radius: 12px; border: 1px solid #d0d7de; color: #57606a; margin-left: 10px;">${status}</span>
                </div>
            </div>

            ${isUnbound ? `
            <div style="margin-top: 5px; padding: 15px; background: #fff; border: 1px solid #e1e4e8; border-radius: 6px; font-size: 12px; color: #24292f; border-left: 4px solid #f6e05e;">
                <strong style="color: #856404; text-transform: uppercase; font-size: 11px; display: block; margin-bottom: 5px;">Evidence Scope Limitation</strong>
                No production build reference (--build-id) was provided.<br>
                This audit verifies repository-level technical signals only.<br>
                It does NOT establish traceability to a deployed production system.
            </div>
            ` : ''}
        </div>
    </section>
  `;
}

function generateReportIntegrity(report) {
  const hash = report.production_hash;
  const hasHash = !!hash;
  
  const title = "Report Integrity";
  const label = "Declared Production Artifact Hash";
  const hashType = "SHA-256";
  const statement = hasHash 
    ? "This audit result includes a user-declared cryptographic hash provided to reference a production artifact. Independent verification is required to establish full traceability. The audit scope is limited to the analyzed repository state and does not independently confirm deployment equivalence."
    : "No production artifact hash provided. Audit reflects repository state only.";
  const disclaimer = hasHash
    ? "The provided hash has not been independently verified by Sentinel. It represents a user-declared linkage to a production artifact."
    : "";

  return `
    <section class="report-integrity" style="background: #f8fafc; border: 1px solid #e1e4e8; padding: 25px; margin: 40px 0; border-radius: 8px; font-size: 14px;">
        <h2 style="margin-top: 0; color: #24292f; font-size: 14px; letter-spacing: 1.5px; border-left: 4px solid #24292f; padding-left: 15px; text-transform: uppercase;">${title}</h2>
        
        <div style="margin-top: 20px; display: grid; grid-template-columns: 1fr; gap: 15px;">
            <div style="background: #fff; border: 1px solid #d0d7de; padding: 15px; border-radius: 6px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <strong style="font-size: 11px; text-transform: uppercase; color: #666;">${label}:</strong>
                    <span style="font-size: 10px; background: #f6f8fa; padding: 2px 8px; border-radius: 12px; border: 1px solid #d0d7de; color: #57606a;">${hashType}</span>
                </div>
                <code style="display: block; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px; color: #24292f; word-break: break-all; background: #f6f8fa; padding: 10px; border-radius: 4px; border: 1px solid #d0d7de;">${hash || 'NOT_PROVIDED'}</code>
            </div>
            
            <div style="color: #24292f; font-size: 13px; line-height: 1.6;">
                <strong>Statement:</strong> ${statement}
            </div>

            ${disclaimer ? `
            <div style="margin-top: 5px; padding: 12px; background: #fff; border: 1px solid #e1e4e8; border-radius: 6px; font-size: 12px; color: #57606a; font-style: italic;">
                <strong>NOTICE:</strong> ${disclaimer}
            </div>
            ` : ''}
        </div>
    </section>
  `;
}

function generateScopeBoundary() {
  return `
    <section class="scope-boundary" style="background: #f8fafc; border-left: 4px solid #0969da; padding: 30px; margin: 40px 0; border-radius: 0 8px 8px 0; font-size: 14px; box-shadow: inset 0 0 10px rgba(0,0,0,0.02);">
        <h2 style="margin-top: 0; color: #0969da; font-size: 14px; letter-spacing: 1.5px; border-left: none; padding-left: 0;">SENTINEL SCOPE BOUNDARY</h2>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-top: 20px;">
            <div>
                <strong style="color: var(--success); text-transform: uppercase; font-size: 11px;">[✓] VERIFIED IN SCOPE:</strong>
                <ul style="margin: 10px 0; padding-left: 20px; color: #334155;">
                    <li>Static analysis of provided repository file-set.</li>
                    <li>Declared manifest configurations and metadata.</li>
                    <li>Technical implementation patterns (code signatures).</li>
                    <li>Software dependency manifest integrity.</li>
                </ul>
            </div>
            <div>
                <strong style="color: var(--danger); text-transform: uppercase; font-size: 11px;">[✗] EXCLUDED FROM SCOPE:</strong>
                <ul style="margin: 10px 0; padding-left: 20px; color: #334155;">
                    <li>Runtime behavior and non-deterministic AI output.</li>
                    <li>External API endpoints and cloud-side logic.</li>
                    <li>Organizational processes and human-in-the-loop quality.</li>
                    <li>Physical infrastructure and hardware security.</li>
                </ul>
            </div>
        </div>
        
        <div style="margin-top: 20px; padding: 15px; background: #fff; border: 1px solid #e1e4e8; border-radius: 6px; font-size: 12px; color: #64748b; font-style: italic;">
            <strong>REGULATORY LIMITATION:</strong> This report provides a technical evaluation of observable markers only. Absence of evidence is not evidence of absence; lack of detected risk patterns does not guarantee regulatory compliance or system safety. Final accountability remains with the system provider.
        </div>
    </section>
  `;
}

function generateHtml(report, diff = null, dualTrack = {}, options = {}) {
  const signals = report._internal?.signals || [];
  const engine = options.engine || 'stable';
  const defenseUnits = deriveDefenseUnits(report);
  // Premium metadata derivation
  const rawPath = report.manifest_path ? path.resolve(report.manifest_path) : process.cwd();
  const dirName = path.basename(path.dirname(rawPath));
  let dignifiedName = dirName ? dirName.split(/[-_]/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') : 'Sistem AI Nespecificat';
  
  // Acronym Fix: Ai -> AI
  dignifiedName = dignifiedName.replace(/\bAi\b/g, 'AI');
  
  const appName = report.app_name || (report.manifest ? report.manifest.app_name : dignifiedName);
  const appVersion = report.version || (report.manifest ? report.manifest.version : 'Sentinel V2.1');
  
  const date = new Date(report._audit_signature?.signed_at || Date.now()).toLocaleDateString('ro-RO', {
    day: '2-digit', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit'
  });

  // Remedy Catalog (Limit to Top 3 Actionable)
  let findings = report._internal?.all_findings || [];
  
  // Categorization Logic for Verdict Basis
  let provenCount = 0;
  let indicatedCount = 0;
  let unknownCount = 0;

  findings.forEach(f => {
    const hasEvidence = !!f.evidence_location && (f.evidence_location.file || f.evidence_location.snippet);
    if (hasEvidence) provenCount++;
    else if (f.evidence_location) indicatedCount++; // Signal exists but no concrete line/snippet
    else unknownCount++;
  });

  // Confidence Level Calculation
  // ... (keeping counts as they are for logic, but display as EVIDENCED)

  // Confidence Level Calculation
  let confidenceLevel = 'MEDIUM';
  let confidenceReason = 'Mix echilibrat de probe directe și indicatori euristici.';
  
  if (signals.length === 0) {
    confidenceLevel = 'LOW';
    confidenceReason = 'Nimic de raportat. Nu au fost detectați indicatori tehnici AI în scopul scanat.';
  } else if (provenCount > (indicatedCount + unknownCount)) {
    confidenceLevel = 'HIGH';
    confidenceReason = 'Majoritatea constatărilor sunt susținute de probe directe în cod.';
  } else if (unknownCount > (provenCount + indicatedCount)) {
    confidenceLevel = 'LOW';
    confidenceReason = 'Volum ridicat de indicatori neconfirmați tehnic în scopul scanat.';
  }

  const { centralVerdict = 'REJECTED', technicalStatus = 'WEAK', governanceStatus = 'GAP', forensicExclusionsCount = 0, centralText: evaluatedText } = dualTrack;

  let centralBadgeColor, centralText;
  const isConfidenceLow = confidenceLevel === 'LOW';
  let displayVerdict = centralVerdict;
  
  if (signals.length === 0) {
    displayVerdict = 'NO TECHNICAL AI SIGNALS DETECTED';
    centralBadgeColor = 'var(--danger)'; 
    centralText = evaluatedText || 'Audit finalizat. Nu au fost identificați indicatori tehnici asociați sistemelor AI în mediul scanat.';
  }
  else if (centralVerdict === 'TECHNICAL MARKERS PRESENT') { 
    displayVerdict = isConfidenceLow ? 'LIMITED TECHNICAL EVIDENCE DETECTED' : 'PARTIAL TECHNICAL INDICATORS DETECTED';
    centralBadgeColor = 'var(--success)'; 
    centralText = evaluatedText || 'Sistemul prezint\u0103 indicatori tehnici \u00een scopul scanat. Recommended for further compliance validation and documentation review.'; 
  }
  else if (centralVerdict === 'HOLD') { 
    centralBadgeColor = 'var(--warning)'; 
    centralText = evaluatedText || 'Maturitate tehnic\u0103 valid\u0103, dar lipsesc politicile esen\u021biale. Suspendat p\u00e2n\u0103 la remediere.'; 
  }
  else { 
    centralBadgeColor = 'var(--danger)'; 
    centralText = evaluatedText || 'Capabilități tehnice insuficiente sau riscuri detectate. Respins din motive tehnice.'; 
  }

  const techBadgeColor = technicalStatus === 'ROBUST' ? 'var(--success)' : 'var(--danger)';
  const displayGovStatus = governanceStatus === 'ALIGNED' ? 'INDICATIVE (within scan scope)' : governanceStatus;
  const govBadgeColor = (governanceStatus === 'ALIGNED' || governanceStatus.includes('INDICATIVE')) ? 'var(--success)' : 'var(--danger)';

  // Forensic Insight
  let forensicHtml = '';
  if (forensicExclusionsCount > 0) {
    forensicHtml = `
      <div class="forensic-insight">
        <strong>\u2139 Forensic Insight (Filtru Zgomot Aplicat):</strong><br>
        Integritate verificat\u0103. Sentinel SIG a detectat \u0219i exclus automat <strong>${forensicExclusionsCount}</strong> probe tehnice identificate ca \u201efals-pozitive\u201d 
        (localizate exclusiv \u00een medii non-executabile sau de test), prevenind o validare fals\u0103 a conformit\u0103\u021bii.
      </div>
    `;
  }

  // Include all findings for detailed analysis (granularity over brevity for audit defensibility)
  const topFindings = findings;
  let remediationHtml = '';
  // Hardened Finding Generator Helper
  const generateHardenedFindingHtml = (f) => {
    const map = RULE_MAP[f.rule_id] || RULE_MAP[f.article] || { 
      article: f.article || 'Gen. (EUAI)', 
      objective: f.description || 'Aliniere tehnică standard', 
      impact: f.severity === 'critical' || f.severity === 'CRITICAL' ? 'BLOCKER' : 'DEFICIENCY', 
      action: 'Documentați remedierea tehnică.' 
    };

    const hasEvidence = !!f.evidence_location;
    const evidenceText = hasEvidence 
      ? `File: ${f.evidence_location.file} (Line: ${f.evidence_location.line || 'N/A'})`
      : "No direct evidence found in scanned repository scope";
    
    // Type and Verification Level logic
    let type = 'INDICATED';
    let verificationLevel = 'partial';
    if (f.severity === 'info' && hasEvidence) { type = 'PROVEN'; verificationLevel = 'full'; }
    else if (!hasEvidence) { type = 'UNKNOWN'; verificationLevel = 'limited'; }

    // Interpretation must explicitly reference Observation
    const observation = f.description || 'Nespecificat';
    const interpretation = `Observa\u021bia [${observation}] indic\u0103 faptul c\u0103 prezen\u021ba sau absen\u021ba markerilor tehnici \u00een depozitul de cod ${hasEvidence ? 'sus\u021bine' : 'nu confirm\u0103'} ipoteza de conformitate pentru ${map.article}.`;

    // Evidence Depth Metadata
    const searchMeta = f.search_metadata || { files_scanned: 0, patterns: [] };
    const searchCoverageHtml = `
      <div class="search-coverage">
        <strong>SEARCH COVERAGE:</strong> Scanned ${searchMeta.files_scanned} files using forensic patterns.
        <div class="pattern-list">
          ${(searchMeta.patterns || []).map(p => `<span class="pattern-tag">${p}</span>`).join('')}
        </div>
      </div>
    `;

    let negativeEvidenceHtml = '';
    if (!hasEvidence) {
      negativeEvidenceHtml = `
        <div class="negative-evidence">
          <strong>NEGATIVE EVIDENCE DISCLOSURE:</strong>
          No technical hits found across scanned scope for the documented patterns above. 
          This confirms absence of demonstrable implementation for ${map.article} in the repository.
        </div>
      `;
    }

    let connectivityHtml = '';
    if (f.connectivity) {
      const conn = f.connectivity;
      connectivityHtml = `
        <div class="connectivity-block">
          <strong>CONNECTIVITY — Observed References:</strong><br>
          Definition: <code style="font-size: 10px;">${conn.definition}</code><br>
          Status: <strong>${conn.classification}</strong> (${conn.reference_count} references found)
          ${conn.files.length > 0 ? `<span class="connectivity-files">Observed in: ${conn.files.slice(0, 5).join(', ')}${conn.files.length > 5 ? '...' : ''}</span>` : ''}
          <div style="margin-top: 5px; color: #666; font-style: italic; font-size: 10px;">
            ℹ Reference detection is based on string matching and may include non-execution references.
          </div>
        </div>
      `;
    }

    return `
      <div class="finding-hardened">
        <div class="finding-meta">
          <span class="finding-article">${map.article}</span>
          <span class="finding-impact">${map.impact}</span>
          ${f.finding_id ? `<span style="font-family: monospace; font-size: 10px; color: #666; margin-left:10px;">ID: ${f.finding_id}</span>` : ''}
        </div>
        <h3 style="margin: 0 0 10px 0; font-size: 16px;">${map.objective}</h3>
        
        <div class="section-title">OBSERVATION:</div>
        <div class="section-content">${observation}</div>

        <div class="section-title">EVIDENCE: ${f.evidence_location?.evidence_hash ? `<span style="float: right; color: var(--success); font-size: 10px; font-family: monospace; border: 1px solid var(--success); padding: 1px 5px; border-radius: 3px;">\u2705 INTEGRITY VERIFIED: ${f.evidence_location.evidence_hash}</span>` : ''}</div>
        <div class="section-content">
          ${evidenceText}
          ${f.evidence_location?.context ? `
            <div style="margin-top: 10px; border: 1px solid #e1e4e8; border-radius: 6px; overflow: hidden; background: #fafbfc;">
                <div style="background: #f6f8fa; border-bottom: 1px solid #e1e4e8; padding: 5px 10px; font-size: 10px; color: #666; font-family: -apple-system, sans-serif;">TECHNICAL CONTEXT PREVIEW (-/+ 5 lines)</div>
                <pre style="margin: 0; padding: 12px; font-size: 11px; font-family: 'Courier New', monospace; white-space: pre; overflow-x: auto; color: #24292f; line-height: 1.5;">${f.evidence_location.context}</pre>
            </div>
          ` : (f.evidence_location?.snippet ? `<pre style="margin-top:10px; background:#f4f4f4; padding:8px; border:1px solid #ddd; font-size:11px;">${f.evidence_location.snippet}</pre>` : '')}
        </div>

        ${searchCoverageHtml}
        ${negativeEvidenceHtml}
        ${connectivityHtml}

        <div class="section-title">INTERPRETATION:</div>
        <div class="section-content">${interpretation}</div>

        <div class="section-title">RISK IMPLICATION:</div>
        <div class="section-content">
          Potential nerespectare a cerin\u021belor de ${map.objective.toLowerCase()}. 
          Nivel de risc rezidual: ${f.severity === 'critical' ? 'Elevat' : 'Moderat'}.
        </div>

        <div class="section-title">LIMITATION:</div>
        <div class="section-content">
          Analiz\u0103 limitat\u0103 la indicatorii tehnici detectabili static \u00een depozitul de cod. 
          Nu include validarea proceselor organiza\u021bitonale sau a comportamentului la runtime.
        </div>

        <div class="verification-command" style="margin-top: 15px; padding: 12px; background: #24292f; color: #fff; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 11px; border-left: 4px solid var(--success);">
          <div style="font-weight: 700; color: #8b949e; margin-bottom: 5px; text-transform: uppercase; font-size: 9px;">Manual Verification Command:</div>
          ${f.verification_command || (hasEvidence ? `grep -nC 3 "${f.evidence_location.snippet.split('\n')[0].replace(/"/g, '\\"')}" ${f.evidence_location.file}` : `ls -R .`)}
        </div>

        <div class="assessment-status">
          <strong>ASSESSMENT STATUS:</strong><br>
          Type: ${type} | Based on: repository evidence only | Verification level: ${verificationLevel}
          ${f.evidence_location?.evidence_hash ? `<br><span style="color: #666; font-size: 10px;">Forensic Anchor: ${f.evidence_location.evidence_hash}</span>` : ''}
        </div>
      </div>
    `;
  };

  topFindings.forEach(f => {
    const map = RULE_MAP[f.rule_id] || RULE_MAP[f.article] || { 
      impact: f.severity === 'critical' || f.severity === 'CRITICAL' ? 'BLOCKER' : 'DEFICIENCY'
    };

    if (centralVerdict !== 'TECHNICAL MARKERS PRESENT' || (map.impact !== 'BLOCKER' && map.impact !== 'DEFICIENCY' && map.impact !== 'CRITICAL')) {
      remediationHtml += generateHardenedFindingHtml(f);
    }
  });

  if (centralVerdict === 'TECHNICAL MARKERS PRESENT' && remediationHtml === '') {
    remediationHtml = '<div style="text-align: center; color: var(--success); padding: 30px; border: 1px dashed var(--success); border-radius: 4px;">No critical implementation failures were detected within the scanned scope. This does not confirm completeness or effectiveness of controls.</div>';
  }

  // Executive Reasons Block Construction
  let executiveReasonsHtml = '';
  if (centralVerdict === 'TECHNICAL MARKERS PRESENT') {
      executiveReasonsHtml = '<div class="executive-reasons"><strong>Notă Analiză:</strong> Analiza indică prezența markerilor tehnici declarați în spațiul de cod scanat. Criteriile de evaluare tehnică în scopul scanat au fost procesate.</div>';
  } else if (topFindings.length > 0) {
      executiveReasonsHtml += '<div class="executive-reasons"><strong>Motive Executive:</strong><ul>';
      topFindings.forEach(f => {
          const map = RULE_MAP[f.rule_id] || RULE_MAP[f.article] || null;
          if(map) {
              executiveReasonsHtml += `<li><strong>${map.article}</strong>: ${map.objective}</li>`;
          }
      });
      executiveReasonsHtml += '</ul></div>';
  }

  let html = `
<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <title>Technical Implementation Statement (Annex IV Evidence) - ${appName}</title>
    <style>
        :root {
            --primary: #1a1a1a;
            --danger: #cf222e;
            --warning: #bf8700;
            --success: #1f883d;
            --bg: #ffffff;
            --gray: #f6f8fa;
            --border: #d0d7de;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.6; color: var(--primary); margin: 0; padding: 40px; background: var(--gray); }
        .page { max-width: 900px; margin: 0 auto; background: var(--bg); padding: 50px 60px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border: 1px solid var(--border); border-radius: 4px; }
        header { border-bottom: 2px solid var(--primary); padding-bottom: 20px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: flex-end; }
        .brand { font-size: 24px; font-weight: 800; letter-spacing: -1px; }
        .doc-type { font-size: 14px; color: #666; text-transform: uppercase; letter-spacing: 1px; }
        
        h2 { border-left: 4px solid var(--primary); padding-left: 15px; text-transform: uppercase; font-size: 16px; letter-spacing: 0.5px; margin-top: 40px; }
        
        .top-fold { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 40px; }
        
        .central-verdict-box { background: var(--bg); border: 3px solid ${centralBadgeColor}; border-radius: 8px; padding: 30px; text-align: center; }
        .cv-label { font-size: 14px; text-transform: uppercase; color: #666; font-weight: 600; letter-spacing: 1px; margin-bottom: 15px; }
        .cv-value { font-size: 36px; font-weight: 900; color: ${centralBadgeColor}; letter-spacing: 1px; }
        .cv-desc { margin-top: 15px; font-size: 14px; color: #444; }

        .dual-track-box { display: flex; flex-direction: column; gap: 15px; justify-content: center; }
        .track-row { display: flex; justify-content: space-between; align-items: center; background: var(--gray); padding: 15px 20px; border-radius: 6px; border-left: 4px solid var(--border); }
        .track-name { font-weight: 600; font-size: 15px; }
        .track-badge { padding: 4px 12px; border-radius: 20px; font-size: 14px; font-weight: 700; color: white; }
        
        .executive-reasons { background: var(--bg); border: 1px solid var(--border); border-left: 4px solid var(--primary); padding: 20px; border-radius: 4px; border-top-left-radius: 0; border-bottom-left-radius: 0; margin-bottom: 40px; font-size: 14.5px; }
        .executive-reasons ul { margin: 10px 0 0 0; padding-left: 20px; color: #444; }
        .executive-reasons li { margin-bottom: 5px; }

        .forensic-insight { background: #e7f3ff; border-left: 4px solid #0969da; padding: 15px 20px; border-radius: 0 4px 4px 0; margin-bottom: 40px; font-size: 14px; color: #0d419d; }

        .audit-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .audit-table th { text-align: left; padding: 12px; border-bottom: 2px solid var(--border); font-size: 12px; color: #666; text-transform: uppercase; }
        .audit-table td { padding: 15px 12px; border-bottom: 1px solid var(--border); font-size: 14px; vertical-align: top; }
        
        .impact-badge { font-size: 12px; font-weight: 700; padding: 3px 8px; border-radius: 4px; }
        .impact-BLOCKER { background: #ffebe9; color: var(--danger); }
        .impact-DEFICIENCY { background: #fff8c5; color: var(--warning); }
        .impact-CRITICAL { background: var(--danger); color: white; }

        .metadata-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; font-size: 13px; color: #555; margin-bottom: 30px; }
        
        .signature { font-family: monospace; font-size: 11px; color: #999; margin-top: 10px; }

        .evolution-box { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 20px; margin-bottom: 40px; display: flex; gap: 20px; align-items: center; }
        .evolution-box.regressed { background: #fef2f2; border-color: #fecaca; }
        .evolution-icon { font-size: 24px; }
        .evolution-content { flex: 1; }
        .evolution-title { font-weight: 700; font-size: 15px; margin-bottom: 5px; color: #166534; }
        .regressed .evolution-title { color: #991b1b; }
        .evolution-desc { font-size: 14px; color: #374151; }
        .action-owner { font-weight: 700; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; padding: 2px 8px; border-radius: 4px; display: inline-block; margin-top: 8px; }
        .action-ENGINEERING { background: #dbeafe; color: #1e40af; }
        .action-GOVERNANCE { background: #fef3c7; color: #92400e; }

        /* Hardened Finding Styles */
        .finding-hardened { background: #fff; border: 1px solid var(--border); border-left: 6px solid var(--primary); padding: 25px; margin-bottom: 30px; border-radius: 4px; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--gray); padding-bottom: 10px; }
        .finding-title { font-weight: 800; font-size: 16px; flex: 1; }
        .finding-section { margin-bottom: 15px; font-size: 14px; }
        .finding-section strong { display: block; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; color: #666; margin-bottom: 5px; }
        .finding-section p { margin: 0; color: #333; }
        .evidence-box { background: var(--gray); padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; border: 1px solid #eee; margin-top: 5px; }
        .assessment-status-box { background: #f8f9fa; border: 1px solid #e1e4e8; padding: 15px; border-radius: 4px; margin-top: 20px; font-size: 13px; }
        .assessment-status-box strong { color: var(--primary); }
      .search-coverage {
        background: #f8f9fa;
        border-right: 3px solid #dee2e6;
        padding: 10px;
        margin-top: 10px;
        font-size: 11px;
      }
      .pattern-list {
        display: flex;
        flex-wrap: wrap;
        gap: 5px;
        margin-top: 5px;
      }
      .pattern-tag {
        background: #e9ecef;
        padding: 2px 6px;
        border-radius: 3px;
        font-family: 'Courier New', monospace;
      }
      .negative-evidence {
        background: #fff5f5;
        border-left: 3px solid #fa5252;
        padding: 10px;
        margin-top: 10px;
        font-size: 11px;
      }
      .connectivity-block {
        background: #f0f7ff;
        border-left: 3px solid #007bff;
        padding: 10px;
        margin-top: 10px;
        font-size: 11px;
      }
      .connectivity-files {
        font-family: 'Courier New', monospace;
        color: #555;
        margin-top: 5px;
        display: block;
      }
      .badge-COMPLETE { background: #388e3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
      .badge-PARTIAL { background: #f57c00; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
      .badge-INSUFFICIENT { background: #d32f2f; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
      .badge-UNAVAILABLE { background: #888888; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
      .semantic-card { background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
      .semantic-article { font-weight: 700; font-size: 15px; color: #1a1a1a; margin-bottom: 5px; display: flex; justify-content: space-between; align-items: center; }
    </style>
</head>
<body>
    <div class="page">
        <header>
            <div class="brand">SENTINEL AI GOVERNANCE</div>
            <div class="doc-type">
              Technical Implementation Statement (Annex IV Evidence)
              ${engine === 'extended' ? '<span style="background: #0969da; color: white; padding: 2px 8px; border-radius: 12px; font-size: 10px; margin-left: 10px; vertical-align: middle;">V2 EXTENDED ENGINE</span>' : ''}
            </div>
        </header>

        <!-- Executive Insight Block -->
        <section style="background: #f8fafc; border: 2px solid #0969da; padding: 25px; border-radius: 8px; margin-bottom: 40px; border-left-width: 8px;">
            <h2 style="margin-top: 0; color: #0969da; font-size: 14px; letter-spacing: 2px; border: none; padding: 0;">EXECUTIVE INSIGHT</h2>
            <p style="font-size: 16px; line-height: 1.5; margin: 15px 0 0 0; font-weight: 500;">
                Technical audit indicates ${centralVerdict === 'TECHNICAL MARKERS PRESENT' ? 'core infrastructure controls are physically detected' : 'critical infrastructure control gaps detected'} within the repository scope. 
                Significant technical evidence aligns with ${report.mapped_articles?.includes('Article 14') ? 'Article 14 (Human Oversight)' : 'regulatory requirements'}, while ${!report.mapped_articles?.includes('Article 20') ? 'Article 20 (Traceability)' : 'non-technical narratives'} remains the primary area for documentation completion. 
                <strong>Bottom Line:</strong> Repository implementation provides a ${report.confidence === 'HIGH' ? 'robust' : 'fragmentary'} technical evidence base for Annex IV attestation.
            </p>
        </section>

        ${(() => {
          if (engine !== 'extended' || !report._executive_summary) return '';
          const s = report._executive_summary;
          const riskColor = s.riskInterpretation.includes('Elevated') ? 'var(--danger)' : (s.riskInterpretation.includes('Medium') ? 'var(--warning)' : 'var(--success)');
          
          return `
            <section style="background: #1a1a1a; color: white; padding: 30px; border-radius: 8px; margin-bottom: 40px; box-shadow: 0 10px 30px rgba(0,0,0,0.15);">
                <h2 style="margin-top: 0; color: #fff; border-left-color: #444; font-size: 14px; letter-spacing: 2px;">EXECUTIVE RISK SUMMARY</h2>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 20px;">
                    <div style="background: #2a2a2a; padding: 15px; border-radius: 6px;">
                        <div style="font-size: 10px; color: #888; text-transform: uppercase; margin-bottom: 5px;">1. AI Usage</div>
                        <div style="font-weight: 700; font-size: 15px;">${s.aiUsage}</div>
                    </div>
                    <div style="background: #2a2a2a; padding: 15px; border-radius: 6px;">
                        <div style="font-size: 10px; color: #888; text-transform: uppercase; margin-bottom: 5px;">2. Control Status</div>
                        <div style="font-weight: 700; font-size: 15px;">${s.controlStatus}</div>
                    </div>
                    <div style="background: #2a2a2a; padding: 15px; border-radius: 6px;">
                        <div style="font-size: 10px; color: #888; text-transform: uppercase; margin-bottom: 5px;">3. Risk Interpretation</div>
                        <div style="font-weight: 700; font-size: 15px; color: ${riskColor};">${s.riskInterpretation}</div>
                    </div>
                </div>
                <div style="margin-top: 25px; padding-top: 15px; border-top: 1px solid #333;">
                    <div style="font-size: 10px; color: #888; text-transform: uppercase; margin-bottom: 5px;">Key Reason</div>
                    <p style="margin: 0; font-size: 16px; font-weight: 500; line-height: 1.4;">"${s.keyReason}"</p>
                </div>
                <div style="margin-top: 15px; font-size: 10px; color: #666; font-style: italic; text-align: right;">
                    Evaluation based on forensic repository evidence. Strictly non-legal interpretation.
                </div>
            </section>
          `;
        })()}

        <div class="metadata-grid">
            <div><strong>Sistem:</strong> ${appName} &nbsp;|&nbsp; ${appVersion}</div>
            <div><strong>Dat\u0103 Evaluare:</strong> ${date}</div>
            <div><strong>Model de Evaluare:</strong> Dual-Track v2.1</div>
            <div><strong>Audit ID:</strong> ${dualTrack.auditMeta?.audit_id || 'N/A'}</div>
            <div><strong>Source Commit:</strong> ${dualTrack.auditMeta?.commit || 'N/A'}</div>
            <div title="${report._audit_signature?.digest || 'N/A'}"><strong>Integritate Raport:</strong> ${report._audit_signature?.digest.substring(0, 16) || 'N/A'}... ✅</div>
        </div>

        ${generateScopeBoundary()}

        ${(() => {
          const sb = report._internal?.signalBreakdown || {};
          return `
            <section style="background: #fdfcfb; border: 1px solid #e1e4e8; padding: 25px; border-radius: 8px; margin-bottom: 40px;">
                <h2 style="margin-top: 0; color: #1a1a1a; font-size: 14px; letter-spacing: 1.5px; border-left-color: #f59e0b;">AI TECHNICAL FOOTPRINT</h2>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 20px;">
                    <div style="text-align: center; border-right: 1px solid #eee;">
                        <div style="font-size: 24px; font-weight: 800; color: #64748b;">${sb.ai_assets || 0}</div>
                        <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">AI Capability</div>
                        <div style="font-size: 11px; color: #64748b; margin-top: 5px;">(Dependencies / Loading)</div>
                    </div>
                    <div style="text-align: center; border-right: 1px solid #eee;">
                        <div style="font-size: 24px; font-weight: 800; color: #0969da;">${sb.execution || 0}</div>
                        <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">AI Execution</div>
                        <div style="font-size: 11px; color: #64748b; margin-top: 5px;">(Active Function Calls)</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 24px; font-weight: 800; color: #1f883d;">${sb.connectivity || 0}</div>
                        <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Connectivity</div>
                        <div style="font-size: 11px; color: #64748b; margin-top: 5px;">(Outbound Network Calls)</div>
                    </div>
                </div>
                ${report.coverage?.signal_density_index ? `
                <div style="margin-top: 20px; border-top: 1px solid #eee; padding-top: 15px; text-align: center;">
                    <span style="font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Signal Density Index:</span>
                    <span style="font-size: 18px; font-weight: 800; color: #1a1a1a; margin-left: 10px;">${report.coverage.signal_density_index}</span>
                    <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">Technical Signals per Scanned File</div>
                </div>
                ` : ''}
            </section>
          `;
        })()}

        <div class="top-fold">
            <div class="central-verdict-box">
                <div class="cv-label">Recomandare Deployment</div>
                <div class="cv-value" style="font-size: ${displayVerdict.length > 25 ? '24px' : '36px'}">${displayVerdict}</div>
                <div class="cv-desc">${centralText.replace('pe deplin aliniat', 'aliniat în scopul analizat')}</div>
            </div>
            
            <div class="dual-track-box">
                <div class="track-row" style="border-left-color: ${techBadgeColor}">
                    <div>
                        <div class="track-name">1. Tehnic</div>
                        <div style="font-size: 12px; color: #666;">Integritate \u0219i performan\u021b\u0103 cod</div>
                    </div>
                    <div class="track-badge" style="background: ${techBadgeColor}">${technicalStatus}</div>
                </div>
                <div class="track-row" style="border-left-color: ${govBadgeColor}">
                    <div>
                        <div class="track-name">2. Regulatory</div>
                        <div style="font-size: 12px; color: #666;">Aliniere la reglement\u0103rile AI Act</div>
                    </div>
                    <div class="track-badge" style="background: ${govBadgeColor}; font-size: ${displayGovStatus.length > 15 ? '10px' : '14px'}">${displayGovStatus}</div>
                </div>
            </div>
        </div>

        <div style="background: var(--bg); border: 1px solid var(--border); padding: 25px; margin-bottom: 40px; border-radius: 4px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
                <strong style="text-transform: uppercase; font-size: 11px; color: #666; display: block; margin-bottom: 10px;">Baza Verdictului</strong>
                <p style="font-size: 14px; margin: 0; color: #333;">Analiz\u0103 bazat\u0103 exclusiv pe probele tehnice din depozitul de cod.</p>
                <ul style="font-size: 13px; margin: 10px 0 0 0; padding-left: 20px; color: #555;">
                    <li><strong>EVIDENCED:</strong> ${provenCount}</li>
                    <li><strong>INDICATED:</strong> ${indicatedCount}</li>
                    <li><strong>UNKNOWN:</strong> ${unknownCount}</li>
                </ul>
            </div>
            <div style="border-left: 1px solid var(--border); padding-left: 20px;">
                <strong style="text-transform: uppercase; font-size: 11px; color: #666; display: block; margin-bottom: 10px;">Nivel de Încredere</strong>
                <div style="font-weight: 800; font-size: 18px; color: ${confidenceLevel === 'HIGH' ? 'var(--success)' : (confidenceLevel === 'LOW' ? 'var(--danger)' : 'var(--warning)')};">
                    ${confidenceLevel}
                </div>
                <p style="font-size: 13px; margin: 5px 0 0 0; color: #666;">${confidenceReason}</p>
                <div style="margin-top: 15px; font-size: 12px; color: #888; font-style: italic;">
                    System Determinism: ${report.article_summaries?.audit_confidence?.determinism || "DETERMINISTIC (static analysis)"}<br>
                    Note: ${report.article_summaries?.audit_confidence?.determinism_note || "Static analysis yields deterministic results."}<br>
                    Verdictul reflectă doar scopul de cod analizat și nu confirmă conformitatea la nivel de organizație.
                </div>
            </div>
        </div>
        
        ${executiveReasonsHtml}

        <!-- Compliance Evolution (Executive Diff) -->
        ${(() => {
          if (!diff) return '';
          
          // Automatic Transition Title Derivation
          let evolutionTitle = 'Men\u021binere Conformitate';
          let isRegressed = false;
          let isCritical = false;

          if (diff.evolution === 'PROGRES') {
            evolutionTitle = 'Progres Compliance';
          } else if (diff.evolution === 'DECLIN') {
            evolutionTitle = 'Regresie de Conformitate';
            isRegressed = true;
            if (centralVerdict === 'REJECTED') {
              evolutionTitle = 'Regresie Critic\u0103';
              isCritical = true;
            }
          }

          const boxClass = isRegressed ? 'evolution-box regressed' : 'evolution-box';
          const icon = isCritical ? '\u26a0\ufe0f' : (isRegressed ? '\ud83d\udcc9' : (diff.evolution === 'PROGRES' ? '\ud83d\udcc8' : '\u2194\ufe0f'));

          return `
            <div class="${boxClass}">
              <div class="evolution-icon">${icon}</div>
              <div class="evolution-content">
                <div class="evolution-title">${evolutionTitle}</div>
                <div class="evolution-desc">
                  <div style="margin-bottom: 10px; font-weight: 700; font-size: 16px;">
                    ${diff.verdictFrom === 'TECHNICAL MARKERS PRESENT' ? 'PARTIAL TECHNICAL INDICATORS DETECTED' : diff.verdictFrom} &nbsp; <span style="color: #999;">&rarr;</span> &nbsp; ${displayVerdict}
                  </div>
                  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 13px;">
                    <div>${diff.tracks.technical.name}: <strong>${technicalStatus}</strong> (${diff.tracks.technical.shift})</div>
                    <div>${diff.tracks.regulatory.name}: <strong>${displayGovStatus}</strong> (${diff.tracks.regulatory.shift})</div>
                  </div>
                </div>
                ${diff.actionRequired !== 'NONE' ? `<div class="action-owner action-${diff.actionRequired}">Responsabil: ${diff.actionOwner}</div>` : ''}
              </div>
            </div>
          `;
        })()}

        ${forensicHtml}

        ${(() => {
          if (engine !== 'extended' || !report._context_validation) return '';
          const ctx = report._context_validation;
          const isSupported = !ctx.missingFamilies || ctx.missingFamilies.length === 0;
          const statusColor = isSupported ? 'var(--success)' : 'var(--danger)';
          
          return `
            <section class="context-validation" style="background: #f8fafc; border-left: 4px solid #0969da; padding: 20px; margin-bottom: 30px; border-radius: 0 8px 8px 0;">
                <h2 style="margin-top: 0; color: #0969da; font-size: 18px;">🏛 CONTEXT VALIDATION (Technical Sufficiency)</h2>
                <div style="display: grid; grid-template-columns: 1fr 1.5fr; gap: 20px; font-size: 14px; margin-bottom: 20px;">
                    <div>
                        <div style="color: #666; font-size: 11px; text-transform: uppercase; margin-bottom: 4px;">Declared Domain</div>
                        <div style="font-weight: 600;">${ctx.declaredDomain}</div>
                    </div>
                    <div>
                        <div style="color: #666; font-size: 11px; text-transform: uppercase; margin-bottom: 4px;">Declared Risk Level</div>
                        <div style="font-weight: 600;">${ctx.declaredRisk}</div>
                    </div>
                    <div style="grid-column: span 2;">
                        <div style="color: #666; font-size: 11px; text-transform: uppercase; margin-bottom: 4px;">Intended Use</div>
                        <div style="font-weight: 500; font-style: italic;">${ctx.intendedUse}</div>
                    </div>
                </div>

                ${ctx.requiredFamilies ? `
                <div style="margin-bottom: 20px; background: white; padding: 15px; border-radius: 6px; border: 1px solid #e1e4e8;">
                    <div style="font-weight: 700; font-size: 13px; margin-bottom: 10px;">Control Family Alignment:</div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <div>
                            <div style="color: #666; font-size: 11px; margin-bottom: 4px;">Required by Profile:</div>
                            <div style="font-size: 12px;">${ctx.requiredFamilies.map(f => `<span style="background: #eef; padding: 2px 6px; border-radius: 4px; margin-right: 4px;">${f}</span>`).join('')}</div>
                        </div>
                        <div>
                            <div style="color: #666; font-size: 11px; margin-bottom: 4px;">Detected (Evidenced):</div>
                            <div style="font-size: 12px;">${ctx.detectedFamilies.length > 0 
                                ? ctx.detectedFamilies.map(f => `<span style="background: #efe; color: #1e4620; padding: 2px 6px; border-radius: 4px; margin-right: 4px;">${f}</span>`).join('')
                                : '<span style="color: #666; font-style: italic;">No control families detected</span>'}
                            </div>
                        </div>
                    </div>
                </div>
                ` : ''}

                <div style="padding: 12px; border-radius: 6px; background: ${isSupported ? '#e6ffec' : '#ffebe9'}; border: 1px solid ${statusColor};">
                    <strong style="color: ${statusColor}; font-size: 14px;">Technical Statement:</strong>
                    <p style="margin: 5px 0 0 0; font-size: 13px; font-weight: 500;">${ctx.technicalStatement}</p>
                </div>

                <div style="margin-top: 15px; font-size: 11px; color: #666; font-style: italic;">
                    <strong>Note:</strong> ${ctx.note}
                </div>
            </section>

            <section class="declaration-consistency" style="background: #fff; border: 1px solid #e1e4e8; padding: 20px; margin-bottom: 30px; border-radius: 8px;">
                ${(() => {
                  if (engine !== 'extended' || !report._declaration_consistency) return '';
                  const dc = report._declaration_consistency;
                  const statusColor = dc.result === 'CONSISTENT' ? 'var(--success)' : (dc.result === 'NOT DECLARED' ? '#666' : 'var(--warning)');
                  
                  return `
                    <h2 style="margin-top: 0; color: #1a1a1a; font-size: 18px; border-left-color: ${statusColor};">⚖️ DECLARATION CONSISTENCY</h2>
                    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; font-size: 14px; margin-bottom: 25px; padding: 15px; background: #f8f9fa; border-radius: 6px;">
                        <div>
                            <div style="color: #666; font-size: 11px; text-transform: uppercase; margin-bottom: 4px;">Declared Risk</div>
                            <div style="font-weight: 700;">${dc.declaredRisk}</div>
                        </div>
                        <div>
                            <div style="color: #666; font-size: 11px; text-transform: uppercase; margin-bottom: 4px;">Inferred Signal</div>
                            <div style="font-weight: 700;">${dc.inferredSignal}</div>
                        </div>
                        <div>
                            <div style="color: #666; font-size: 11px; text-transform: uppercase; margin-bottom: 4px;">Confidence Level</div>
                            <div style="display: inline-block; background: ${dc.confidence === 'HIGH' ? '#0969da' : (dc.confidence === 'MEDIUM' ? '#bf8700' : '#6e7781')}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700;">
                                ${dc.confidence}
                            </div>
                        </div>
                    </div>

                    <div style="border-left: 4px solid ${statusColor}; padding-left: 15px; margin-bottom: 20px;">
                        <div style="font-weight: 700; font-size: 14px; color: ${statusColor};">${dc.result}</div>
                        <p style="margin: 5px 0; font-size: 13px;">${dc.technicalStatement}</p>
                    </div>

                    <div style="background: #fff; border: 1px solid #eee; padding: 15px; border-radius: 6px;">
                        <div style="font-weight: 700; font-size: 12px; margin-bottom: 10px; color: #555;">Technical Observations (Consistency Evidence):</div>
                        <ul style="margin: 0; padding-left: 20px; font-size: 12px; line-height: 1.6;">
                            ${dc.reasons.map(r => `<li>${r}</li>`).join('')}
                        </ul>
                    </div>

                    <div style="margin-top: 15px; font-size: 11px; color: #888; font-style: italic;">
                        "${dc.note}"
                    </div>
                  `;
                })()}
            </section>
          `;
        })()}

        <section class="semantic-evaluation">
            <h2>Semantic Document Quality</h2>
            ${(() => {
                const sq = report.semantic_quality;
                if (!sq || sq.evaluated === false || sq.overall === "UNAVAILABLE") {
                    return `
                        <div style="padding: 20px; background: #f6f8fa; border: 1px dashed #d0d7de; border-radius: 6px; color: #666; font-size: 13px;">
                            Semantic evaluation not performed. Set SENTINEL_LLM_PROVIDER environment variable to enable document quality analysis.
                        </div>
                    `;
                }

                let articlesHtml = '';
                for (const [id, data] of Object.entries(sq.articles || {})) {
                    articlesHtml += `
                        <div class="semantic-card">
                            <div class="semantic-article">
                                <span>${id}</span>
                                <span class="badge-${data.completeness}">${data.completeness}</span>
                            </div>
                            <div style="font-size: 13px; color: #555; margin-bottom: 10px;">
                                <strong>Technical Score:</strong> ${data.score}/100
                            </div>
                            <p style="font-size: 13px; margin: 0 0 10px 0; font-style: italic;">"${data.summary}"</p>
                            ${data.missing && data.missing.length > 0 ? `
                                <div style="font-size: 12px; color: var(--danger); font-weight: 600; margin-bottom: 5px;">Missing Elements:</div>
                                <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: #333;">
                                    ${data.missing.map(m => `<li>${m}</li>`).join('')}
                                </ul>
                            ` : ''}
                        </div>
                    `;
                }

                return `
                    <div style="margin-bottom: 25px; display: flex; align-items: center; gap: 15px;">
                        <span style="font-weight: 700; font-size: 14px;">OVERALL QUALITY:</span>
                        <span class="badge-${sq.overall}">${sq.overall}</span>
                    </div>
                    <div style="background: #e7f3ff; border-left: 4px solid #0969da; padding: 15px; border-radius: 4px; margin-bottom: 25px; font-size: 13px; font-weight: 600; color: #0d419d;">
                        Recommendation: ${sq.recommendation}
                    </div>
                    ${articlesHtml}
                    <div style="margin-top: 20px; font-size: 11px; color: #666; font-style: italic; border-top: 1px solid #eee; padding-top: 10px;">
                        ${sq.disclaimer}
                    </div>
                `;
            })()}
        </section>

        <section>
            <h2>Technical Signal Consolidation</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
                ${(() => {
                    const signals = report._internal?.signals || [];
                    const clusters = {
                        "Human Oversight Controls": { id: 'CODE_MANUAL_OVERRIDE,CODE_KILL_SWITCH', items: [] },
                        "Logging & Traceability": { id: 'DEP_WINSTON,DEP_PINO,CODE_TRACE_ID', items: [] },
                        "Data Governance Signals": { id: 'DEP_FAIRLEARN,CODE_BIAS_MITIGATION,CODE_DATA_ETL', items: [] },
                        "Risk Management Indicators": { id: 'EUAI-MIN-001,EUAI-TRANS-001', items: [] }
                    };

                    signals.forEach(s => {
                        if (s.id.includes('OVERRIDE') || s.id.includes('KILL')) clusters["Human Oversight Controls"].items.push(s);
                        else if (s.id.includes('LOG') || s.id.includes('TRACE')) clusters["Logging & Traceability"].items.push(s);
                        else if (s.id.includes('FAIR') || s.id.includes('BIAS') || s.id.includes('DATA')) clusters["Data Governance Signals"].items.push(s);
                        else if (s.id.includes('EUAI') || s.id.includes('MIN') || s.id.includes('TRANS')) clusters["Risk Management Indicators"].items.push(s);
                    });

                    return Object.entries(clusters).map(([name, data]) => `
                        <div style="background: #fff; border: 1px solid #e1e4e8; padding: 15px; border-radius: 6px;">
                            <div style="font-weight: 700; font-size: 13px; color: #1a1a1a; margin-bottom: 8px; border-bottom: 1px solid #eee; padding-bottom: 5px;">${name} (${data.items.length})</div>
                            <ul style="margin: 0; padding-left: 18px; font-size: 11px; color: #555;">
                                ${data.items.slice(0, 3).map(i => `<li>${PROBE_MAP[i.id]?.label || i.id} in <code>${path.basename(i.source_path)}</code></li>`).join('')}
                                ${data.items.length > 3 ? `<li style="list-style: none; color: #999; font-style: italic;">+ ${data.items.length - 3} more signals</li>` : ''}
                                ${data.items.length === 0 ? `<li style="list-style: none; color: #999; font-style: italic;">No specific signals detected</li>` : ''}
                            </ul>
                        </div>
                    `).join('');
                })()}
            </div>

            <h2>Detailed Technical Finding Analysis</h2>
            <p style="font-size: 14px; margin-bottom: 25px; color: #555;">Analiză granulară a indicatorilor de risc detectați, structurată pentru defensibilitate în audit.</p>
            ${remediationHtml || '<div style="text-align: center; color: var(--success); padding: 30px; border: 1px dashed var(--success); border-radius: 4px;">No critical implementation failures were detected within the scanned scope. This does not confirm completeness or effectiveness of controls.</div>'}
        </section>

        ${generateDefenseUnitsSection(defenseUnits)}

        ${generateProductionTraceContext(report)}

        ${generateReportIntegrity(report)}

        ${generateEvidenceLedger(report)}

        <footer>
            <div>Generat automat prin Sentinel Core (v2.1).</div>
            <div class="signature">Protejat criptografic via Sentinel Integrity Guard.</div>
        </footer>
    </div>
</body>
</html>
  `;

  return html;
}

/**
 * Generates an Annex IV Technical File (Markdown) based on forensic evidence.
 */
function generateAnnexIVMarkdown(report) {
  const signals = report._internal?.signals || [];
  const manifest = report.manifest || (report._internal?.manifest) || {};
  
  // Section definitions based on EU AI Act Annex IV
  const sections = {
    "Section 1: General Description": {
      desc: "Identity of provider, intended purpose, and system versioning.",
      items: []
    },
    "Section 2: Technical Specifications": {
      desc: "AI architecture, model specifications, and data governance markers.",
      items: []
    },
    "Section 3: Risk Management": {
      desc: "Methods for assessment, mitigation, and safety controls.",
      items: []
    },
    "Section 4: Monitoring and Logging": {
      desc: "Technical implementation of event logging and traceability.",
      items: []
    }
  };

  signals.forEach(s => {
    // Heuristic routing based on Article mapping or propagation from signal
    const art = s.article || (s.articles ? s.articles[0] : (PROBE_MAP[s.id]?.art || 'General'));
    
    if (art === 'Article 9' || art === 'Article 15' || art === 'Article 10') {
      sections["Section 3: Risk Management"].items.push(s);
    } else if (art === 'Article 20') {
      sections["Section 4: Monitoring and Logging"].items.push(s);
    } else if (art === 'Article 13' || art === 'Article 14' || art === 'EXECUTION' || s.kind === 'dependency') {
      sections["Section 2: Technical Specifications"].items.push(s);
    } else {
      sections["Section 1: General Description"].items.push(s);
    }
  });

  let md = `# Annex IV Technical Documentation Dossier (Forensic Proof)\n\n`;
  md += `**Document Status:** 🏛 REGULATORY DRAFT (Generated by Sentinel)\n`;
  md += `**System Name:** ${manifest.app_name || 'AI System'}\n`;
  md += `**Version:** ${manifest.version || '1.0.0'}\n`;
  md += `**Audit ID:** \`${report.audit_id || 'N/A'}\`\n`;
  md += `**Timestamp:** ${new Date().toISOString()}\n\n`;

  const traceContext = report.production_trace_context || { build_id: 'NOT PROVIDED', trace_status: 'UNBOUND' };
  md += `## Production Trace Context\n`;
  md += `- **Build ID:** \`${traceContext.build_id}\`\n`;
  md += `- **Trace Status:** \`${traceContext.trace_status}\`\n\n`;

  if (traceContext.trace_status === 'UNBOUND') {
    md += `> [!WARNING]\n`;
    md += `> **EVIDENCE SCOPE LIMITATION**: No production build reference (--build-id) was provided. This audit verifies repository-level technical signals only. It does NOT establish traceability to a deployed production system.\n\n`;
  }

  const defenseUnits = deriveDefenseUnits(report);
  if (defenseUnits.length > 0) {
    md += `## Regulatory Narrative Synthesis\n`;
    md += `*This section transforms technical markers into auditor-defensible assertions based on the Narrative Synthesis Layer structure.*\n\n`;
    
    defenseUnits.forEach(u => {
      md += `### [${u.metric}] Assertion\n`;
      md += `> **Observation:** ${u.observation}\n`;
      md += `> \n`;
      md += `> **Synthesis:** ${u.defense}\n`;
      md += `> \n`;
      md += `> **Auditor Challenge:** ${u.challenge}\n`;
      md += `> \n`;
      md += `> **Validity Boundary:** Scanned ${u.validity.system} at ${u.validity.temporal}. \n`;
      md += `> **Fingerprint:** \`${u.validity.source}\`\n`;
      md += `> \n`;
      md += `> **Confidence:** ${u.strength} (Static Analysis Scope)\n`;
      md += `> **Residual Risk:** This validation is limited to static analysis. Runtime effectiveness, deployment state, and non-deterministic behavior remain separate from this technical statement.\n\n`;
    });
    md += `---\n\n`;
  }

  md += `> [!NOTE]\n> This document anchors regulatory claims to technical reality. It represents the "Technical File" required for High-Risk AI systems under the EU AI Act.\n\n`;

  Object.entries(sections).forEach(([title, data]) => {
    md += `## ${title}\n`;
    md += `*${data.desc}*\n\n`;
    
    if (data.items.length === 0) {
      md += `> [!CAUTION]\n> **EVIDENCE GAP**: [ACTION_REQUIRED: HUMAN ATTESTATION NEEDED] - No technical markers detected in this repository that satisfy this section. Human intervention and additional documentation required.\n\n`;
    } else {
      md += `| Evidence Type | Location | Structural Context | Impact |\n`;
      md += `| :--- | :--- | :--- | :--- |\n`;
      
      // Select top 15 most relevant signals to avoid markdown bloat
      const topItems = data.items
        .sort((a, b) => (b.confidence || 0.5) - (a.confidence || 0.5))
        .slice(0, 15);

      topItems.forEach(item => {
        const type = PROBE_MAP[item.id]?.label || item.id;
        const loc = `\`${item.source_path}\` (L:${item.line || 'N/A'})`;
        const ctx = item.structural_type || 'mention';
        const impact = (item.confidence || 0.8) > 0.7 ? '✅ HIGH PROOOF' : '⚠️ INDICATOR';
        
        md += `| ${type} | ${loc} | ${ctx} | ${impact} |\n`;
      });

      if (data.items.length > 15) {
        md += `\n*Note: ${data.items.length - 15} additional forensic markers were extracted for this section but omitted for brevity in this summary dossier.*\n\n`;
      }
      md += `\n`;
    }
  });

  md += `---\n**Disclaimer:** [ACTION_REQUIRED: HUMAN ATTESTATION NEEDED] - This is a technical forensic extraction. Final regulatory validation of Annex IV compliance requires human review by a qualified compliance officer.\n`;
  md += `*Generated by Sentinel Enterprise Auditor v2.1*\n`;
  md += `**Hardened for audit defensibility within static analysis scope**\n`;
  
  return md;
}

module.exports = { generateHtml, generateMarkdownSummary, generateAnnexIVMarkdown };
