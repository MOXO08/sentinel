const fs = require('fs');
const path = require('path');

const beforeFile = 'd:/AI Act Compliance API/sentinel-cli/before_integration.json';
const afterFile = 'd:/AI Act Compliance API/sentinel-cli/after_integration.json';

try {
  const before = JSON.parse(fs.readFileSync(beforeFile, 'utf8'));
  const after = JSON.parse(fs.readFileSync(afterFile, 'utf8'));

  console.log('--- Sentinel Regression Proof ---');

  // 1. Scoring & Verdict
  const scoreMatch = before.score === after.score;
  const verdictMatch = before.verdict === after.verdict;
  console.log(`[VERDICT] Match: ${verdictMatch} (Value: ${after.verdict})`);
  console.log(`[SCORE] Match: ${scoreMatch} (Value: ${after.score})`);

  // 2. Findings
  const findingsCountMatch = before.findings_count === after.findings_count;
  console.log(`[FINDINGS] Count Match: ${findingsCountMatch} (Count: ${after.findings_count})`);

  // IDs might change due to timestamp in seed? No, I used manifest timestamp if available.
  // Actually, I'll check rule_ids.
  const beforeRuleIds = before.top_findings.map(f => f.rule_id).sort();
  const afterRuleIds = after.top_findings.map(f => f.rule_id).sort();
  const ruleIdsMatch = JSON.stringify(beforeRuleIds) === JSON.stringify(afterRuleIds);
  console.log(`[RULES] Rule IDs Match: ${ruleIdsMatch}`);

  // 3. Additive Fields
  const additiveFields = ['ci_cd_files', 'test_files', 'correlation_signals'];
  const allAdded = additiveFields.every(f => !!after[f] && !before[f]);
  console.log(`[ADDITIVE] New Fields Added: ${allAdded}`);

  // 4. Existing Fields (Preservation)
  const legacyFields = ['command', 'manifest_path', 'audit_context', 'DETERMINISTIC_EVALUATION', 'AUDIT_SCOPE'];
  const allPreserved = legacyFields.every(f => !!after[f] && !!before[f]);
  console.log(`[PRESERVATION] Legacy Fields Preserved: ${allPreserved}`);

  // Regression Verdict
  const isSafe = scoreMatch && verdictMatch && findingsCountMatch && ruleIdsMatch && allAdded && allPreserved;
  console.log(`\n--- FINAL REGRESSION VERDICT: ${isSafe ? 'SAFE' : 'NOT SAFE'} ---`);

} catch (e) {
  console.error('[FAIL] Verification script error:', e.message);
  process.exit(1);
}
