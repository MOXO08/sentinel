const fs = require('fs');
const report = JSON.parse(fs.readFileSync('sentinel-verified/results/sovereign-output.json', 'utf8'));

// Mocking the simplified SARIF structure with no ANSI
const sarif = {
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Sentinel",
          "rules": []
        }
      },
      "results": [],
      "properties": {
        "claim_score": report.claim_score,
        "evidence_score": report.evidence_score,
        "confidence": report.confidence,
        "risk_category": report.risk_category || "high"
      }
    }
  ]
};

fs.writeFileSync('sentinel-verified/results/audit_proof.sarif', JSON.stringify(sarif, null, 2));
console.log('✅ Proof SARIF generated: sentinel-verified/results/audit_proof.sarif');
