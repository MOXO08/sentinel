const crypto = require('crypto');
const { execSync } = require('child_process');

/**
 * Audit Metadata Module
 * Handles generation of stable identifiers and environment metadata
 * for the Sentinel Audit Trail Foundation.
 */

class AuditMetadata {
  /**
   * Generates a stable, unique ID for the audit run.
   * This is entirely decoupled from the cryptographic SIG digest.
   * @returns {string} 16-character hex string
   */
  static generateAuditId() {
    return crypto.randomBytes(8).toString('hex');
  }

  /**
   * Generates a standard ISO8601 timestamp for the audit run.
   * @returns {string} e.g., "2026-03-21T13:45:00Z"
   */
  static getTimestamp() {
    return new Date().toISOString();
  }

  /**
   * Attempts to retrieve the current short git commit hash.
   * Returns null if git is not available or it's not a git repository.
   * @param {string} cwd The directory to check (defaults to process.cwd())
   * @returns {string|null} 7-character commit hash or null
   */
  static getGitCommit(cwd = process.cwd()) {
    try {
      const stdout = execSync('git rev-parse --short HEAD', {
        cwd,
        stdio: ['pipe', 'pipe', 'ignore'], // Ignore stderr to keep console clean
        timeout: 2000 // Prevent hanging
      });
      return stdout.toString().trim();
    } catch (e) {
      // Not a git repo, git not installed, or command failed
      return null;
    }
  }

  /**
   * Main factory function to generate a complete metadata block for a new audit.
   * @param {string} cwd The working directory of the project
   * @returns {Object} { audit_id, timestamp, commit }
   */
  static createMetadataBlock(cwd = process.cwd()) {
    return {
      audit_id: this.generateAuditId(),
      timestamp: this.getTimestamp(),
      commit: this.getGitCommit(cwd)
    };
  }
}

module.exports = AuditMetadata;
