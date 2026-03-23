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
    article: 'Art. 13',
    objective: 'Transparen\u021ba \u0219i dezv\u0103luirea riscurilor.',
    impact: 'DEFICIENCY',
    action: 'Ad\u0103uga\u021bi declara\u021bia de transparen\u021b\u0103 \u00een manifest.'
  },
  'Article 13': { 
    article: 'Art. 13',
    objective: 'Informarea utilizatorilor finali.',
    impact: 'DEFICIENCY',
    action: 'Documenta\u021bi politica de interac\u021biune \u0219i notific\u0103rile automate.'
  },
  'EUAI-HARDENING-000': {
    article: 'Art. 14',
    objective: 'Supraveghere uman\u0103 (Manual override).',
    impact: 'DEFICIENCY',
    action: 'Stabili\u021bi procedurile de interven\u021bie uman\u0103 \u00een manualul de operare.'
  },
  'EUAI-HARDENING-001': {
    article: 'Art. 13',
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
  'DEP_WINSTON': { art: 'Art. 20', label: 'Logging Standard (Winston)', evidence: 'Implementare Trasabilitate' },
  'DEP_PINO': { art: 'Art. 20', label: 'Logging Standard (Pino)', evidence: 'Implementare Trasabilitate' },
  'DEP_PYTHON_LOG': { art: 'Art. 20', label: 'Logging Python Standard', evidence: 'Implementare Trasabilitate' },
  'CODE_LOGGER_INIT': { art: 'Art. 20', label: 'Ini\u021bializare Logger', evidence: 'Captur\u0103 Evenimente' },
  'CODE_TRACE_ID': { art: 'Art. 20', label: 'Traceability Metadata', evidence: 'Identificator Unic Cerere' },
  'CODE_MANUAL_OVERRIDE': { art: 'Art. 14', label: 'Manual Override Logic', evidence: 'Supraveghere Uman\u0103' },
  'CODE_KILL_SWITCH': { art: 'Art. 14', label: 'Emergency Stop / Kill Switch', evidence: 'Control Critic' },
  'CODE_AI_DISCLOSURE': { art: 'Art. 13', label: 'AI Disclosure UI/Code', evidence: 'Transparen\u021b\u0103 Utilizator' },
  'DEP_FAIRLEARN': { art: 'Art. 10', label: 'Fairness Library (Fairlearn)', evidence: 'Monitorizare Bias' },
  'CODE_BIAS_MITIGATION': { art: 'Art. 10', label: 'Bias Mitigation Logic', evidence: 'Guvernan\u021ba Datelor' },
  'CODE_DATA_ETL': { art: 'Art. 10', label: 'Data Ingestion Pipeline', evidence: 'Trasabilitate Date Antrenament' }
};

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
  // Sort articles alphabetically (e.g. Art. 10, Art. 13...)
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

function generateMarkdownSummary(report) {
    const verdict = report.central_verdict || 'REJECTED';
    const tech = report.technical_status || 'WEAK';
    const gov = report.governance_status || 'GAP';
    const score = report.score || 0;
    const threshold = report.threshold || 0;
    
    let icon = '\u274c';
    if (verdict === 'TECHNICAL MARKERS PRESENT') icon = '\u2705';
    if (verdict === 'HOLD') icon = '\u26a0\ufe0f';

    const techIcon = tech === 'ROBUST' ? '\u2705' : '\u274c';
    const govIcon = gov === 'ALIGNED' ? '\u2705' : '\u26a0\ufe0f';

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
            <strong>LEGAL LIMITATION:</strong> This report provides a technical evaluation of observable markers only. Absence of evidence is not evidence of absence; lack of detected risk patterns does not guarantee regulatory compliance or system safety. Final accountability remains with the system provider.
        </div>
    </section>
  `;
}

function generateHtml(report, diff = null, dualTrack = {}, options = {}) {
  const engine = options.engine || 'stable';
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

  const { centralVerdict = 'REJECTED', technicalStatus = 'WEAK', governanceStatus = 'GAP', forensicExclusionsCount = 0, centralText: evaluatedText } = dualTrack;

  let centralBadgeColor, centralText;
  if (centralVerdict === 'TECHNICAL MARKERS PRESENT') { 
    centralBadgeColor = 'var(--success)'; 
    centralText = evaluatedText || 'Sistemul prezintă indicatori de aliniere tehnică în scopul scanat. Recomandat pentru revizuire finală.'; 
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
  const govBadgeColor = governanceStatus === 'ALIGNED' ? 'var(--success)' : 'var(--danger)';

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
  let confidenceLevel = 'MEDIUM';
  let confidenceReason = 'Mix echilibrat de probe directe și indicatori euristici.';
  if (provenCount > (indicatedCount + unknownCount)) {
    confidenceLevel = 'HIGH';
    confidenceReason = 'Majoritatea constatărilor sunt susținute de probe directe în cod.';
  } else if (unknownCount > (provenCount + indicatedCount)) {
    confidenceLevel = 'LOW';
    confidenceReason = 'Volum ridicat de indicatori neconfirmați tehnic în scopul scanat.';
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
    remediationHtml = '<div style="text-align: center; color: var(--success); padding: 30px; border: 1px dashed var(--success); border-radius: 4px;">\u2705 Toate controalele critice sunt validate în scopul scanat. Nu exist\u0103 ac\u021biuni de remediere prioritare identificate.</div>';
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
    <title>Technical Assessment Report - ${appName}</title>
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
              Technical Assessment Report
              ${engine === 'extended' ? '<span style="background: #0969da; color: white; padding: 2px 8px; border-radius: 12px; font-size: 10px; margin-left: 10px; vertical-align: middle;">V2 EXTENDED ENGINE</span>' : ''}
            </div>
        </header>

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
            </section>
          `;
        })()}

        <div class="top-fold">
            <div class="central-verdict-box">
                <div class="cv-label">Recomandare Deployment</div>
                <div class="cv-value">${centralVerdict}</div>
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
                        <div class="track-name">2. Legal</div>
                        <div style="font-size: 12px; color: #666;">Aliniere la reglement\u0103rile AI Act</div>
                    </div>
                    <div class="track-badge" style="background: ${govBadgeColor}">${governanceStatus}</div>
                </div>
            </div>
        </div>

        <div style="background: var(--bg); border: 1px solid var(--border); padding: 25px; margin-bottom: 40px; border-radius: 4px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
                <strong style="text-transform: uppercase; font-size: 11px; color: #666; display: block; margin-bottom: 10px;">Baza Verdictului</strong>
                <p style="font-size: 14px; margin: 0; color: #333;">Analiză bazată exclusiv pe probele tehnice din depozitul de cod.</p>
                <ul style="font-size: 13px; margin: 10px 0 0 0; padding-left: 20px; color: #555;">
                    <li><strong>PROVEN:</strong> ${provenCount}</li>
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
                    ${diff.verdictFrom} &nbsp; <span style="color: #999;">&rarr;</span> &nbsp; ${centralVerdict}
                  </div>
                  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 13px;">
                    <div>${diff.tracks.technical.name}: <strong>${technicalStatus}</strong> (${diff.tracks.technical.shift})</div>
                    <div>${diff.tracks.regulatory.name}: <strong>${governanceStatus}</strong> (${diff.tracks.regulatory.shift})</div>
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
            <h2>Detailed Technical Finding Analysis</h2>
            <p style="font-size: 14px; margin-bottom: 25px; color: #555;">Analiză granulară a indicatorilor de risc detectați, structurată pentru defensibilitate în audit.</p>
            ${remediationHtml || '<p style="text-align:center; padding: 20px; color: #666;">Nu au fost identificate constatări prioritare în această sesiune.</p>'}
        </section>

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
    
    if (art === 'Art. 9' || art === 'Art. 15' || art === 'Art. 10') {
      sections["Section 3: Risk Management"].items.push(s);
    } else if (art === 'Art. 20') {
      sections["Section 4: Monitoring and Logging"].items.push(s);
    } else if (art === 'Art. 13' || art === 'Art. 14' || art === 'EXECUTION' || s.kind === 'dependency') {
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
  md += `> [!NOTE]\n> This document anchors legal claims to technical reality. It represents the "Technical File" required for High-Risk AI systems under the EU AI Act.\n\n`;

  Object.entries(sections).forEach(([title, data]) => {
    md += `## ${title}\n`;
    md += `*${data.desc}*\n\n`;
    
    if (data.items.length === 0) {
      md += `> [!CAUTION]\n> **EVIDENCE GAP**: No technical markers detected in this repository that satisfy this section. Human intervention and additional documentation required.\n\n`;
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

  md += `---\n**Disclaimer:** This is a technical forensic extraction. Final legal validation of Annex IV compliance requires human review by a qualified compliance officer.\n`;
  md += `*Generated by Sentinel Enterprise Auditor v2.1*\n`;
  
  return md;
}

module.exports = { generateHtml, generateMarkdownSummary, generateAnnexIVMarkdown };
