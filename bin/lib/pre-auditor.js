const fs = require('fs');
const path = require('path');
const { runSig } = require('./sentinel-bridge');
const CryptoUtils = require('./crypto-utils');
const Evaluator = require('./evaluator');
const AuditVault = require('./vault');
const AuditMetadata = require('./audit-metadata');
const DiffEngine = require('./diff-engine');
const { generateHtml } = require('./report-generator');

/**
 * Sentinel Pre-Auditor Orchestrator
 * High-level coordinator for Enterprise-grade audit processing.
 */

class PreAuditor {
  /**
   * Processes a raw scan result into an Enterprise-grade persistent audit.
   * @param {Object} cliResults The raw JSON output from sentinel-scan.
   * @param {string} rootDir The project root directory.
   * @param {Object} options Options for HTML generation and persistence.
   * @returns {Object} Final processed report.
   */
  static async upgrade(cliResults, rootDir = process.cwd(), options = {}) {
    const probingRulesPath = path.join(__dirname, 'probing-rules.json');
    
    const sigReport = await runSig(cliResults, probingRulesPath, rootDir);

    const finalReport = {
      ...cliResults,
      enterprise_confidence: sigReport.enterprise_confidence,
      defensibility: sigReport.defensibility,
      integrity_issues: sigReport.integrity_issues,
      _sig_internal: sigReport._internal
    };

    // --- FIX 2: SIGNAL DENSITY INDEX ---
    if (finalReport.coverage) {
      const totalSignals = (finalReport._internal && finalReport._internal.total_signals) || (finalReport.coverage.signals_detected) || 0;
      const totalFiles = (finalReport.audit_scope && finalReport.audit_scope.within_scope && finalReport.audit_scope.within_scope.files_analyzed) || 
                         (finalReport._internal && finalReport._internal.files) || 1;
      
      finalReport.coverage.signal_density_index = parseFloat((totalSignals / totalFiles).toFixed(2));
      delete finalReport.coverage.coverage_ratio;
    }

    // 2. Generate Audit Signature (P2)
    const auditSignature = CryptoUtils.generateAuditSignature(finalReport);
    finalReport._audit_signature = auditSignature;

    // 3. Dual-Track Evaluator (V2.1 Model)
    const dualTrack = Evaluator.evaluate(finalReport);
    finalReport._dual_track = dualTrack; // Sync for diffing

    // 4. Audit Trail Foundation (Persistence)
    const auditMeta = AuditMetadata.createMetadataBlock(rootDir);
    
    // 4b. Compliance Evolution (Diff)
    let diffResults = null;
    const latestAudit = AuditVault.getLatestAudit(rootDir);
    if (latestAudit) {
      diffResults = DiffEngine.compare(finalReport, latestAudit);
    }
    
    // Archive the snapshot (Note: we archive BEFORE generating HTML so vault is consistent)
    AuditVault.archiveAudit(rootDir, auditMeta, finalReport, dualTrack);
    
    // Inject metadata for HTML generator
    dualTrack.auditMeta = auditMeta;
    finalReport._audit_trail = auditMeta;

    // 5. Generate HTML Report (if requested or enabled by default)
    if (options.generateHtml !== false) {
      const html = generateHtml(finalReport, diffResults, dualTrack, { engine: options.engine });
      const outputHtmlName = options.outputHtmlName || 'sentinel-audit.html';
      fs.writeFileSync(path.join(rootDir, outputHtmlName), html);
    }

    return finalReport;
  }
}

module.exports = PreAuditor;
