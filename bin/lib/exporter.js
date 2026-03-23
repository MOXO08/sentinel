const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');
const CryptoUtils = require('./crypto-utils');
const ReportGenerator = require('./report-generator');

class AuditExporter {
  static async exportBundle(report, rootDir, outputPath) {
    const auditId = report.audit_id || (report._audit_trail && report._audit_trail.audit_id) || 'unknown';
    const tempDir = path.join(process.cwd(), `.sentinel_export_${Date.now()}`);
    
    try {
      // 1. Create structure
      if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
      if (!fs.existsSync(path.join(tempDir, 'rules'))) fs.mkdirSync(path.join(tempDir, 'rules'));
      if (!fs.existsSync(path.join(tempDir, 'evidence'))) fs.mkdirSync(path.join(tempDir, 'evidence'));

      // PHASE 1: ARTIFACT SYNTHESIS (Data & Metadata)
      
      // A. Write Core Audit Files (Canonical)
      const canonicalAudit = CryptoUtils.canonicalize(report);
      fs.writeFileSync(path.join(tempDir, 'audit.json'), canonicalAudit);
      
      const htmlReport = ReportGenerator.generateHtml(report, null, {
        centralVerdict: report.central_verdict,
        technicalStatus: report.technical_status,
        governanceStatus: report.governance_status,
        auditMeta: report._audit_trail || report.audit_metadata
      });
      fs.writeFileSync(path.join(tempDir, 'report.html'), htmlReport);

      // B. Copy Manifest & Rules (Canonical)
      const manifestPath = path.join(rootDir, 'sentinel.manifest.json');
      if (fs.existsSync(manifestPath)) {
        const manifestObj = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        fs.writeFileSync(path.join(tempDir, 'manifest.json'), CryptoUtils.canonicalize(manifestObj));
      }

      const discRules = JSON.parse(fs.readFileSync(path.join(__dirname, 'discovery-rules.json'), 'utf8'));
      const probRules = JSON.parse(fs.readFileSync(path.join(__dirname, 'probing-rules.json'), 'utf8'));
      fs.writeFileSync(path.join(tempDir, 'rules', 'discovery-rules.json'), CryptoUtils.canonicalize(discRules));
      fs.writeFileSync(path.join(tempDir, 'rules', 'probing-rules.json'), CryptoUtils.canonicalize(probRules));

      // C. Copy Evidence Snippets (Traceability Alignment)
      // We ensure the signals in report match the evidence folder
      const signals = report._internal?.signals || [];
      signals.forEach(s => {
        const evidenceFilename = `evidence_${s.id}_${s.evidence_sha256 ? s.evidence_sha256.substring(0, 8) : 'raw'}.txt`;
        const evidenceContent = s.snippet || '';
        fs.writeFileSync(path.join(tempDir, 'evidence', evidenceFilename), evidenceContent);
      });

      // D. Generate Initial Metadata (Skeleton)
      const metadata = {
        audit_id: auditId,
        source_commit: report._audit_trail?.commit || report.audit_metadata?.commit || 'N/A',
        generated_by_version: '1.2.18',
        timestamp: report.audit_metadata?.timestamp || new Date().toISOString(),
        deterministic_audit: true,
        artifact_sha256: null, // To be filled based on data payload
        environment: {
          os: "Sentinel Forensic OS",
          node_version: "v22.x"
        }
      };
      fs.writeFileSync(path.join(tempDir, 'metadata.json'), CryptoUtils.canonicalize(metadata));

      // E. Authority Security Anchors
      const pubKeyPath = path.join(__dirname, 'keys', 'sentinel-root-2026.pub');
      const publicKey = fs.readFileSync(pubKeyPath, 'utf8');
      fs.writeFileSync(path.join(tempDir, 'authority.pub'), publicKey);

      const verifyGuide = `SENTINEL AUDIT VERIFICATION GUIDE (Phase 13.1)
==============================================

1. Validarea Integrității Pachetului (Registry Check):
   Comanda: sha256sum -c checksums.sha256
   
   Rezultat așteptat: [OK] pentru toate fișierele.
   Note: signature.bin și signature.json sunt ancore de încredere externe manifestului.

2. Validarea Autenticității (Trust Check):
   Comanda: openssl dgst -sha256 -verify authority.pub -signature signature.bin checksums.sha256

   Rezultat așteptat: Verified OK
   Acest pas confirmă că manifestul (inteligența pachetului) este semnat de autoritate.

3. Validarea Trasabilității (Material Check):
   - "source_sha256" în audit.json -> hash-ul fișierului original din repo.
   - "evidence_sha256" în audit.json -> hash-ul probei din /evidence.

Dacă oricare dintre pași eșuează, AUDITUL ESTE INVALID.
`;
      fs.writeFileSync(path.join(tempDir, 'VERIFY.txt'), verifyGuide);

      // PHASE 2: MANIFEST GENERATION (Unsealable Contents)
      // Step 2.1: Calculate Artifact Fingerprint (Hash of Data Body only)
      const bodyHash = crypto.createHash('sha256');
      bodyHash.update(CryptoUtils.canonicalize(report));
      // Re-read metadata and update it before manifest
      metadata.artifact_sha256 = `sha256:${bodyHash.digest('hex')}`;
      fs.writeFileSync(path.join(tempDir, 'metadata.json'), CryptoUtils.canonicalize(metadata));

      // Step 2.2: Generate Manifest (Covers everything created so far)
      const checksums = this.generateChecksums(tempDir);
      fs.writeFileSync(path.join(tempDir, 'checksums.sha256'), checksums);

      // PHASE 3: CRYPTOGRAPHIC SEALING (The External Seal)
      const privKeyPath = path.join(__dirname, 'keys', 'sentinel-root-2026.key');
      if (fs.existsSync(privKeyPath)) {
        const privateKey = fs.readFileSync(privKeyPath, 'utf8');
        const signatureResult = CryptoUtils.signData(checksums, privateKey);
        const manifestDigest = crypto.createHash('sha256').update(checksums).digest('hex');

        // Write the SEAL files (Excluded from checksums.sha256)
        const sigJson = {
          signed_by: "Sentinel Enterprise Authority",
          authority_id: "sentinel-root-2026",
          contact: "security@sentinel.run",
          algorithm: "RSASSA-PSS-SHA256",
          public_key_ref: "./authority.pub",
          public_key_fingerprint: `sha256:${CryptoUtils.calculateFingerprint(publicKey)}`,
          signed_content_digest: `sha256:${manifestDigest}`,
          timestamp: metadata.timestamp
        };
        fs.writeFileSync(path.join(tempDir, 'signature.json'), CryptoUtils.canonicalize(sigJson));
        fs.writeFileSync(path.join(tempDir, 'signature.bin'), signatureResult.binary);
      }

      // 10. ZIP Determinism
      this.stabilizeTimestamps(tempDir);
      this.zipFolder(tempDir, outputPath);

      return true;

      // 10. ZIP Determinism: Stable Timestamps
      this.stabilizeTimestamps(tempDir);

      // 10. Zip it up
      this.zipFolder(tempDir, outputPath);

      return true;
    } finally {
      // Cleanup temp dir
      if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    }
  }

  static generateChecksums(dir, baseDir = dir) {
    let output = '';
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    // Deterministic ordering: Alphabetical sort
    entries.sort((a, b) => a.name.localeCompare(b.name));

    entries.forEach(entry => {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        output += this.generateChecksums(fullPath, baseDir);
      } else {
        if (entry.name === 'checksums.sha256' || entry.name === 'signature.bin') return; 
        const content = fs.readFileSync(fullPath);
        const hash = crypto.createHash('sha256').update(content).digest('hex');
        const relativePath = path.relative(baseDir, fullPath).replace(/\\/g, '/');
        output += `${hash}  ${relativePath}\n`;
      }
    });

    return output;
  }

  static stabilizeTimestamps(dir) {
    const epoch = new Date('1980-01-01T00:00:00Z'); 
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    entries.forEach(entry => {
      const fullPath = path.join(dir, entry.name);
      fs.utimesSync(fullPath, epoch, epoch);
      if (entry.isDirectory()) {
        this.stabilizeTimestamps(fullPath);
      }
    });
  }

  static zipFolder(sourceDir, outPath) {
    // Windows implementation using PowerShell
    if (process.platform === 'win32') {
      const psCmd = `Compress-Archive -Path '${sourceDir}/*' -DestinationPath '${outPath}' -Force`;
      execSync(`powershell -Command "${psCmd}"`, { stdio: 'inherit' });
    } else {
      // Unix implementation
      execSync(`cd "${sourceDir}" && zip -r "${outPath}" .`, { stdio: 'inherit' });
    }
  }
}

module.exports = AuditExporter;
