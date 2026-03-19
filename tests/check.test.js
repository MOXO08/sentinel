const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const CLI_PATH = path.resolve(__dirname, '../bin/sentinel-scan.js');


function stripAnsi(str) {
  return str.replace(/[\u001b\u009b][[()#;?]*(?:[a-zA-Z\\d/](?:;[a-zA-Z\\d/]*)*)?/g, '');
}

class TestEnv {
  constructor(name) {
    this.dir = path.join(os.tmpdir(), `sentinel-check-test-${name}-${Math.random().toString(36).slice(2)}`);
    fs.mkdirSync(this.dir, { recursive: true });
  }

  createFile(filename, content) {
    const filePath = path.join(this.dir, filename);
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
    return filePath;
  }

  run(args = []) {
    return spawnSync('node', [CLI_PATH, ...args], {
      cwd: this.dir,
      encoding: 'utf8',
      env: { ...process.env, SENTINEL_INTERACTIVE: 'false' }
    });
  }

  cleanup() {
    try {
      fs.rmSync(this.dir, { recursive: true, force: true });
    } catch (e) {}
  }
}

test('sentinel check: missing threshold - should fail with guidance', (t) => {
  const env = new TestEnv('missing-threshold');
  env.createFile('manifest.json', { app_name: 'test' });
  
  const result = env.run(['check']);
  
  assert.strictEqual(result.status, 2);
  assert.strictEqual(result.stderr.includes('--threshold is required'), true);
  assert.strictEqual(stripAnsi(result.stdout).includes('Suggested thresholds:'), true);
  env.cleanup();
});

test('sentinel check: invalid threshold - should fail', (t) => {
  const env = new TestEnv('invalid-threshold');
  env.createFile('manifest.json', { app_name: 'test' });
  
  const result = env.run(['check', '--threshold', 'abc']);
  
  assert.strictEqual(result.status, 2);
  env.cleanup();
});

test('sentinel check: threshold pass - exits 0', (t) => {
  const env = new TestEnv('pass');
  env.createFile('manifest.json', { 
    app_name: 'test', 
    risk_category: 'Minimal',
    declared_flags: ['transparency_disclosure_provided']
  });
  
  const result = env.run(['check', '--threshold', '80']);
  
  assert.strictEqual(result.status, 0);
  assert.strictEqual(stripAnsi(result.stdout).includes('Sentinel Check: PASS'), true);
  assert.ok(stripAnsi(result.stdout).includes('Score:'), 'Should show score');
  env.cleanup();
});

test('sentinel check: threshold fail - exits 1 with guidance', (t) => {
  const env = new TestEnv('fail');
  env.createFile('manifest.json', { app_name: 'test', risk_category: 'High' });
  
  const result = env.run(['check', '--threshold', '80']);
  
  assert.strictEqual(result.status, 1);
    assert.ok(stripAnsi(result.stdout).includes('FAIL'));
  assert.ok(stripAnsi(result.stdout).includes('[Missing transparency flag]'), 'Should show the finding label');
  assert.ok(stripAnsi(result.stdout).includes('\u2192'), 'Should show fix guidance arrow');
  env.cleanup();
});

test('sentinel check: manifest ambiguity - exits 1', (t) => {
  const env = new TestEnv('ambiguity');
  env.createFile('manifest.json', { app_name: 'one' });
  env.createFile('sentinel.manifest.json', { app_name: 'two' });
  
  const result = env.run(['check', '--threshold', '80']);
  
  assert.strictEqual(result.status, 1);
  assert.strictEqual(result.stderr.includes('Both manifest.json and sentinel.manifest.json exist'), true);
  env.cleanup();
});

test('sentinel check: JSON output consistency', (t) => {
  const env = new TestEnv('json');
  env.createFile('manifest.json', { app_name: 'test', risk_category: 'High' });
  
  const result = env.run(['check', '--threshold', '80', '--json']);
  
  assert.strictEqual(result.status, 1);
  const report = JSON.parse(result.stdout);
  assert.strictEqual(report.command, 'check');
  assert.strictEqual(report.status, 'FAIL');
  assert.strictEqual(report.threshold, 80);
  assert.ok(report.score < 80);
  assert.ok(Array.isArray(report.top_findings));
  assert.ok(report.top_findings.some(f => f.rule_id === 'EUAI-TRANS-001'));
  env.cleanup();
});

test('sentinel check: risk_category case normalization', (t) => {
  const cases = ['high', 'High', 'HIGH'];
  for (const rc of cases) {
    const env = new TestEnv(`case-${rc}`);
    env.createFile('manifest.json', { app_name: 'test', risk_category: rc });
    
    const result = env.run(['check', '--threshold', '90']);
    
    assert.strictEqual(stripAnsi(result.stdout).includes('High-risk system detected'), true);
    assert.strictEqual(stripAnsi(result.stdout).includes('Recommended minimum threshold: 90'), true);
    env.cleanup();
  }
});

test('sentinel check: fail output includes fix guidance', (t) => {
  const env = new TestEnv('fix-guidance');
  env.createFile('manifest.json', { app_name: 'test', risk_category: 'High' });
  
  const result = env.run(['check', '--threshold', '90']);
  
  // Use robust checks for findings
  assert.ok(stripAnsi(result.stdout).includes('[Missing baseline structure]'), 'Should show minimum structure finding label');
  assert.ok(stripAnsi(result.stdout).includes('Add required top-level flags and evidence fields'), 'Should show fix snippet text');
  env.cleanup();
});
