/**
 * Sentinel Diff Engine
 * Core logic for comparing two audit snapshots at an executive level.
 */

class DiffEngine {
  /**
   * Compares the current audit result against a base audit result.
   * @param {Object} current The current audit report object.
   * @param {Object} base The historical audit report object (from vault).
   * @returns {Object} { evolution, engineeringShift, governanceShift, actionRequired }
   */
  static compare(current, base) {
    if (!base) return null;

    // 1. Current state from pre-computed metadata (Ensures 1:1 match with Top Fold)
    const currentVerdict = current._dual_track?.centralVerdict || 'REJECTED';
    const currentTech = current._dual_track?.technicalStatus || 'WEAK';
    const currentGov = current._dual_track?.governanceStatus || 'GAP';

    // 2. Base state from stored metadata (Historical Truth)
    const mapVerdict = (v) => {
      if (v === 'COMPLIANT') return 'APPROVED';
      if (v === 'NON_COMPLIANT' || v === 'FAIL') return 'REJECTED';
      if (v === 'PASS') return 'APPROVED';
      return v;
    };

    const baseVerdict = mapVerdict(base.executive_state?.verdict || 'REJECTED');
    const baseTech = base.executive_state?.technical_status || 'WEAK';
    const baseGov = base.executive_state?.governance_status || 'GAP';

    // 2. Determine Evolution
    let evolution = 'STABIL';
    if (this._verdictToWeight(currentVerdict) > this._verdictToWeight(baseVerdict)) {
      evolution = 'PROGRES';
    } else if (this._verdictToWeight(currentVerdict) < this._verdictToWeight(baseVerdict)) {
      evolution = 'DECLIN';
    }

    // 3. Track Shifts
    const engineeringShift = (currentTech !== baseTech) 
      ? (currentTech === 'ROBUST' ? 'PROGRES' : 'DECLIN') 
      : 'STABIL';
      
    const governanceShift = (currentGov !== baseGov) 
      ? (currentGov === 'ALIGNED' ? 'PROGRES' : 'DECLIN') 
      : 'STABIL';

    // 4. Determine Primary Action Owner
    let actionRequired = 'NONE';
    if (currentVerdict !== 'APPROVED') {
      if (currentTech === 'WEAK') actionRequired = 'ENGINEERING';
      else if (currentGov === 'GAP') actionRequired = 'GOVERNANCE';
    }

    return {
      evolution,
      verdictFrom: baseVerdict,
      verdictTo: currentVerdict,
      tracks: {
        technical: {
          name: 'Tehnic',
          from: baseTech,
          to: currentTech,
          shift: engineeringShift
        },
        regulatory: {
          name: 'Legal',
          from: baseGov,
          to: currentGov,
          shift: governanceShift
        }
      },
      actionOwner: actionRequired === 'ENGINEERING' ? 'Engineering' : (actionRequired === 'GOVERNANCE' ? 'Legal / Compliance' : 'N/A'),
      actionRequired
    };
  }

  static _verdictToWeight(v) {
    const weights = { 'APPROVED': 2, 'HOLD': 1, 'REJECTED': 0 };
    // Map anything else (like COMPLIANT/NON_COMPLIANT) to REJECTED for safety
    return weights[v] !== undefined ? weights[v] : 0;
  }
}

module.exports = DiffEngine;
