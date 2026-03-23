/**
 * Sentinel Dual-Track Evaluator
 * Logic for determining Technical Maturity and Regulatory Alignment.
 */

class Evaluator {
  /**
   * Evaluates an audit report against the V2.1 Dual-Track model.
   * @param {Object} report The full audit report object.
   * @returns {Object} { centralVerdict, technicalStatus, governanceStatus, forensicExclusionsCount }
   */
  static evaluate(report) {
    const allFindings = report._internal?.all_findings || [];
    
    // Track A: Regulatory Governance (ALIGNED / GAP)
    // Procedural rules start with EUAI-MIN or EUAI-TRANS
    const proceduralFindings = allFindings.filter(f => 
      f.rule_id?.startsWith('EUAI-MIN') || f.rule_id?.startsWith('EUAI-TRANS')
    );
    const governanceStatus = proceduralFindings.length > 0 ? 'GAP' : 'ALIGNED';

    // Track B: Technical Maturity (ROBUST / WEAK)
    const validTechnicalSignals = report._internal?.signals?.length || 0;
    const technicalStatus = validTechnicalSignals > 0 ? 'ROBUST' : 'WEAK';

    // Track C: Score-based Hard-Gate (V2.1 Compliance)
    const score = report.score || 0;
    const threshold = report.threshold || 0;
    const isBelowThreshold = score < threshold;

    // Central Verdict Decision Matrix (V2.1 Model)
    // -------------------------------------------------------------------------
    // 1. REJECTED: Technical WEAKNESS (fundamental failure) or Critical Blocker.
    // 2. HOLD: Technical ROBUSTNESS but with Governance GAPs (Audit needed).
    // 3. TECHNICAL MARKERS PRESENT: Technical ROBUSTNESS + Governance ALIGNED + Above Threshold.
    
    let centralVerdict = 'REJECTED';
    let centralText = 'Capabilit\u0103\u021bi tehnice insuficiente sau riscuri critice identificate.';

    if (technicalStatus === 'ROBUST') {
      if (governanceStatus === 'GAP') {
        centralVerdict = 'HOLD';
        centralText = 'Maturitate tehnic\u0103 valid\u0103, dar exist\u0103 deficien\u021be de guvernan\u021b\u0103 care necesit\u0103 aten\u021bie.';
      } else {
        // Aligned - Now check the threshold
        if (isBelowThreshold) {
          centralVerdict = 'HOLD';
          centralText = 'Sistem aliniat procedural, dar scorul de conformitate este sub pragul minim stabilit.';
        } else {
          centralVerdict = 'TECHNICAL MARKERS PRESENT';
          centralText = 'Sistemul prezintă indicatori de aliniere tehnică în scopul scanat. Recomandat pentru revizuire finală.';
        }
      }
    }

    // Forensic Noise Reduction (SIG Exclusions)
    const forensicExclusionsCount = (report.integrity_issues || []).filter(i => i.id === 'SIG-CODE-001').length;

    return {
      centralVerdict,
      technicalStatus,
      governanceStatus,
      forensicExclusionsCount
    };
  }
}

module.exports = Evaluator;
