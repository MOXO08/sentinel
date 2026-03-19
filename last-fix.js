const fs = require('fs');
const path = 'bin/sentinel-scan.js';
let content = fs.readFileSync(path, 'utf8');

const snippets = [
  { rule_id: 'EUAI-UNACCEPTABLE-001', snippet: "fix_snippet: 'Stop project immediately. This application category is prohibited by law.'" },
  { rule_id: 'EUAI-RISK-002', snippet: "fix_snippet: 'Add \"risk_category\": \"High\" (or Limited/Minimal) to manifest.json.'" },
  { rule_id: 'EUAI-MIN-001', snippet: "fix_snippet: 'Run \"sentinel fix --apply\" to generate the required compliance structure.'" }
];

for (const s of snippets) {
  const marker = "rule_id: '" + s.rule_id + "',";
  const startIdx = content.indexOf(marker);
  if (startIdx !== -1) {
    const endOfObjectIdx = content.indexOf('}', startIdx);
    if (endOfObjectIdx !== -1) {
       // Check if fix_snippet already exists
       const slice = content.substring(startIdx, endOfObjectIdx);
       if (!slice.includes('fix_snippet:')) {
         content = content.substring(0, endOfObjectIdx - 1) + ',\n      ' + s.snippet + '\n    ' + content.substring(endOfObjectIdx);
         console.log('Added snippet for ' + s.rule_id);
       }
    }
  }
}

fs.writeFileSync(path, content);
