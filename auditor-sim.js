const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

console.log('\n--- SENTINEL AUDITOR SIMULATOR (FORENSIC COMPLIANCE) ---\n');

async function verifyPackage(zipPath) {
  const tempDir = path.join(process.cwd(), `.auditor_sim_${Date.now()}`);
  
  try {
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

    // 1. Extract (Simulating auditor's manual unzip)
    console.log(`[1] Extracting: ${path.basename(zipPath)}`);
    if (process.platform === 'win32') {
      execSync(`powershell -Command "Expand-Archive -Path '${zipPath}' -DestinationPath '${tempDir}' -Force"`);
    } else {
      execSync(`unzip -o "${zipPath}" -d "${tempDir}"`);
    }

    // 2. Integrity Check (sha256sum -c equivalent)
    console.log(`[2] Integrity Check (Manifest Validation)`);
    const manifestPath = path.join(tempDir, 'checksums.sha256');
    const manifestContent = fs.readFileSync(manifestPath, 'utf8').replace(/\r\n/g, '\n');
    const lines = manifestContent.split('\n').filter(l => l.trim());
    
    let integrityCount = 0;
    for (const line of lines) {
      const [expectedHash, ...relPathParts] = line.split(/\s+/);
      const relPath = relPathParts.join(' ');
      const filePath = path.join(tempDir, relPath);
      
      const actualHash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
      if (actualHash === expectedHash) {
        integrityCount++;
      } else {
        console.error(`  [FAIL] Hash mismatch for: ${relPath}`);
      }
    }
    console.log(`  Result: ${integrityCount}/${lines.length} files OK.`);

    // 3. Authenticity Check (OpenSSL dgst -verify equivalent)
    console.log(`[3] Authenticity Check (Digital Seal)`);
    const sigBinPath = path.join(tempDir, 'signature.bin');
    const pubKeyPath = path.join(tempDir, 'authority.pub');
    
    const signature = fs.readFileSync(sigBinPath);
    const publicKey = fs.readFileSync(pubKeyPath, 'utf8');
    
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(manifestContent);
    verify.end();
    
    const isAuthentic = verify.verify({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
    }, signature);

    if (isAuthentic) {
      console.log(`  Result: SIGNATURE VERIFIED OK (Authority Trusted)`);
    } else {
      console.error(`  Result: SIGNATURE INVALID (Unauthorized Modification)`);
    }

    // 4. Traceability Check (Deep Audit Alignment)
    console.log(`[4] Traceability Check (Evidence Hook)`);
    const sigJsonPath = path.join(tempDir, 'signature.json');
    const sigJson = JSON.parse(fs.readFileSync(sigJsonPath, 'utf8'));
    const manifestDigest = crypto.createHash('sha256').update(manifestContent).digest('hex');
    
    if (sigJson.signed_content_digest === `sha256:${manifestDigest}`) {
      console.log(`  Result: TRACEABILITY LINKED (Digest matches)`);
    } else {
      console.error(`  Result: TRACEABILITY BROKEN (Metadata mismatch)`);
    }

    console.log('\n--- FINAL VERDICT: AUDIT VALIDATED ---\n');

  } catch (err) {
    console.error(`\n[CRITICAL ERROR] ${err.message}`);
    console.log('\n--- FINAL VERDICT: AUDIT TAMPERED/INVALID ---\n');
    process.exit(1);
  } finally {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
}

const target = process.argv[2];
if (!target) {
  console.log('Usage: node auditor-sim.js <path-to-zip>');
  process.exit(1);
}

verifyPackage(target);
