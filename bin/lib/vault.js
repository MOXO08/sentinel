const fs = require('fs');
const path = require('path');

/**
 * Audit Vault Module
 * Handles local persistence of audit snapshots within .sentinel/vault
 */

class AuditVault {
  static VAULT_DIR = '.sentinel/vault';
  static INDEX_FILE = 'history.index.json';

  /**
   * Ensures the local vault directory structure exists.
   * @param {string} rootDir The project root directory
   */
  static ensureVault(rootDir = process.cwd()) {
    const vaultPath = path.join(rootDir, this.VAULT_DIR);
    if (!fs.existsSync(vaultPath)) {
      fs.mkdirSync(vaultPath, { recursive: true });
    }
  }

  /**
   * Reads the history index, or creates an empty template if it doesn't exist.
   * @param {string} rootDir The project root directory
   * @returns {Object} The parsed index object
   */
  static _readIndex(rootDir) {
    const indexPath = path.join(rootDir, this.VAULT_DIR, this.INDEX_FILE);
    if (fs.existsSync(indexPath)) {
      try {
        return JSON.parse(fs.readFileSync(indexPath, 'utf8'));
      } catch (e) {
        // Fallback if index is corrupted
        return null;
      }
    }
    return {
      project_name: path.basename(rootDir),
      last_audit_id: null,
      history: []
    };
  }

  /**
   * Saves the index object back to disk.
   * @param {string} rootDir The project root directory
   * @param {Object} indexObj The index object to save
   */
  static _writeIndex(rootDir, indexObj) {
    const indexPath = path.join(rootDir, this.VAULT_DIR, this.INDEX_FILE);
    fs.writeFileSync(indexPath, JSON.stringify(indexObj, null, 2));
  }

  /**
   * Saves a full audit snapshot to the vault and updates the history index.
   * @param {string} rootDir The project root directory
   * @param {Object} metadata The audit_metadata block from Step 1
   * @param {Object} fullReport The complete Sentinel JSON report to archive
   * @param {Object} dualTrack The executive status (verdict, tech, gov)
   * @returns {string} The path to the saved audit file
   */
  static archiveAudit(rootDir, metadata, fullReport, dualTrack) {
    this.ensureVault(rootDir);

    // 1. Prepare the persistent snapshot
    const snapshot = {
      audit_metadata: metadata,
      executive_state: {
        verdict: dualTrack.centralVerdict || 'UNKNOWN',
        technical_status: dualTrack.technicalStatus || 'UNKNOWN',
        governance_status: dualTrack.governanceStatus || 'UNKNOWN',
        // Optional: save top_actions or reasons here if passed
      },
      ...fullReport // Spreads the full JSON evidence and signature
    };

    const fileName = `audit_${metadata.audit_id}.json`;
    const filePath = path.join(rootDir, this.VAULT_DIR, fileName);

    // 2. Write snapshot to disk
    fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2));

    // 3. Update the registry index
    const index = this._readIndex(rootDir) || { project_name: path.basename(rootDir), history: [] };
    
    // We only save executive telemetry to the index for fast O(1) reads
    const indexEntry = {
      audit_id: metadata.audit_id,
      timestamp: metadata.timestamp,
      commit: metadata.commit,
      verdict: dualTrack.centralVerdict || 'UNKNOWN',
      technical_status: dualTrack.technicalStatus || 'UNKNOWN',
      governance_status: dualTrack.governanceStatus || 'UNKNOWN',
      file_path: fileName
    };

    index.history.push(indexEntry);
    index.last_audit_id = metadata.audit_id;

    this._writeIndex(rootDir, index);

    return filePath;
  }

  /**
   * Retrieves the full history index.
   * @param {string} rootDir The project root directory
   * @returns {Object|null} The index object, or null if empty
   */
  static getHistory(rootDir = process.cwd()) {
    const indexPath = path.join(rootDir, this.VAULT_DIR, this.INDEX_FILE);
    if (!fs.existsSync(indexPath)) return null;
    return this._readIndex(rootDir);
  }

  /**
   * Retrieves a specific audit snapshot by ID.
   * @param {string} rootDir The project root directory
   * @param {string} auditId The unique audit ID
   * @returns {Object|null} The parsed snapshot, or null if not found
   */
  static getAuditById(rootDir = process.cwd(), auditId) {
    const fileName = `audit_${auditId}.json`;
    const filePath = path.join(rootDir, this.VAULT_DIR, fileName);
    if (fs.existsSync(filePath)) {
      try {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
      } catch (e) {
        return null;
      }
    }
    return null;
  }

  /**
   * Retrieves the most recent audit snapshot.
   * @param {string} rootDir The project root directory
   * @returns {Object|null} The parsed snapshot, or null if history is empty
   */
  static getLatestAudit(rootDir = process.cwd()) {
    const index = this.getHistory(rootDir);
    if (index && index.last_audit_id) {
      return this.getAuditById(rootDir, index.last_audit_id);
    }
    return null;
  }
}

module.exports = AuditVault;
