const crypto = require('crypto');

/**
 * Sentinel Cryptographic Utilities
 * Handles deterministic canonicalization and P2 signing.
 */

class CryptoUtils {
  /**
   * Deterministic JSON Canonicalization (RFC8785-Lite)
   * Sorts keys recursively and removes whitespace.
   */
  static canonicalize(obj) {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }

    if (Array.isArray(obj)) {
      return '[' + obj.map(item => this.canonicalize(item)).join(',') + ']';
    }

    const sortedKeys = Object.keys(obj).sort();
    const pairs = sortedKeys.map(key => {
      return JSON.stringify(key) + ':' + this.canonicalize(obj[key]);
    });
    
    return '{' + pairs.join(',') + '}';
  }

  /**
   * Extracts the deterministic fields for hashing.
   */
  static getAuditSurface(report) {
    return {
      app_name: report.app_name || (report.manifest ? report.manifest.app_name : 'unknown'),
      version: report.version || (report.manifest ? report.manifest.version : '1.0.0'),
      risk_category: report.risk_category,
      score: report.score,
      status: report.status,
      verdict: report.verdict,
      top_findings: (report.top_findings || [])
        .map(f => ({
          rule_id: f.rule_id,
          description: f.description,
          evidence_location: f.evidence_location
        }))
        .sort((a, b) => {
          const keyA = `${a.rule_id || ''}-${a.evidence_location?.file || ''}-${a.evidence_location?.line || 0}`;
          const keyB = `${b.rule_id || ''}-${b.evidence_location?.file || ''}-${b.evidence_location?.line || 0}`;
          return keyA.localeCompare(keyB);
        }),
      all_findings: (report._internal?.all_findings || [])
        .map(f => ({
          rule_id: f.rule_id,
          article: f.article,
          description: f.description,
          severity: f.severity,
          evidence_location: f.evidence_location
        }))
        .sort((a, b) => {
          const keyA = `${a.article || ''}-${a.rule_id || ''}-${a.evidence_location?.file || ''}-${a.evidence_location?.line || 0}`;
          const keyB = `${b.article || ''}-${b.rule_id || ''}-${b.evidence_location?.file || ''}-${b.evidence_location?.line || 0}`;
          return keyA.localeCompare(keyB);
        }),
      integrity_issues: (report.integrity_issues || [])
        .map(i => ({
          id: i.id,
          severity: i.severity,
          message: i.message,
          evidence_location: i.evidence_location
        }))
        .sort((a, b) => {
          const keyA = `${a.id || ''}-${a.evidence_location?.file || ''}-${a.evidence_location?.line || 0}`;
          const keyB = `${b.id || ''}-${b.evidence_location?.file || ''}-${b.evidence_location?.line || 0}`;
          return keyA.localeCompare(keyB);
        })
    };
  }

  /**
   * Generates a SHA-256 digest of the critical audit data.
   */
  static generateAuditSignature(report) {
    const surface = this.getAuditSurface(report);
    const canonicalString = this.canonicalize(surface);
    const digest = crypto.createHash('sha256').update(canonicalString).digest('hex');

    return {
      algorithm: 'sha256',
      canonicalization: 'RFC8785-Lite',
      signed_at: new Date().toISOString(),
      digest: digest
    };
  }

  /**
   * Verifies if a report is authentic.
   */
  static verifyAuditSignature(report) {
    const sig = report._audit_signature;
    if (!sig || !sig.digest) return false;
    const surface = this.getAuditSurface(report);
    const calculatedDigest = crypto.createHash('sha256').update(this.canonicalize(surface)).digest('hex');
    return calculatedDigest === sig.digest;
  }

  /**
   * Generates a digital signature for a given digest using the authority's private key.
   * Returns base64 signature and raw buffer.
   */
  static signData(data, privateKeyPem) {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(data);
    sign.end();
    
    // Using RSASSA-PSS as requested for forensic grade security
    const signature = sign.sign({
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    });

    return {
      base64: signature.toString('base64'),
      binary: signature
    };
  }

  /**
   * Verifies a digital signature.
   */
  static verifyData(data, signature, publicKeyPem) {
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(data);
    verify.end();

    const signatureBuffer = Buffer.isBuffer(signature) ? signature : Buffer.from(signature, 'base64');
    
    return verify.verify({
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    }, signatureBuffer);
  }

  /**
   * Calculates the SHA256 fingerprint of a public key.
   */
  static calculateFingerprint(publicKeyPem) {
    return crypto.createHash('sha256').update(publicKeyPem).digest('hex');
  }
}

module.exports = CryptoUtils;
