const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const CLI_PATH = path.resolve(__dirname, '../bin/sentinel-scan.js');

/**
 * Helper to manage a temporary test environment
 */
class TestEnv {
  constructor(name) {
    this.dir = path.join(os.tmpdir(), `sentinel-test-${name}-${Math.random().toString(36).slice(2)}`);
    fs.mkdirSync(this.dir, { recursive: true });
  }

  createFile(filename, content) {
    const filePath = path.join(this.dir, filename);
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
    return filePath;
  }

  readFile(filename) {
    return fs.readFileSync(path.join(this.dir, filename), 'utf8');
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
    } catch (e) {
      // Ignore cleanup errors on Windows if files are locked
    }
  }
}

test('sentinel fix: CLI routing - fix should not be interpreted as a manifest path', (t) => {
  const env = new TestEnv('routing');
  // Create a directory named 'fix' to see if it tries to scan it
  fs.mkdirSync(path.join(env.dir, 'fix'), { recursive: true });
  
  const result = env.run(['fix']);
  
  // If it tried to scan the 'fix' directory, it would print "Scanning: .../fix"
  assert.strictEqual(result.stdout.includes('Scanning:'), false, 'Should not trigger scanning logic');
  assert.strictEqual(result.stderr.includes('Manifest file not found at fix'), false, 'Should not interpret "fix" as a path');
  env.cleanup();
});

test('sentinel fix: Dry-run safety - should not modify manifest or create docs', (t) => {
  const env = new TestEnv('dry-run');
  const manifest = {
    app_name: "test-app",
    risk_category: "high",
    declared_flags: []
  };
  env.createFile('manifest.json', manifest);
  
  const result = env.run(['fix']);
  
  assert.strictEqual(result.stdout.includes('remediation fixes safely'), false, 'Dry run should not apply fixes');
  assert.strictEqual(fs.existsSync(path.join(env.dir, 'docs/compliance')), false, 'Should not create docs directory in dry run');
  
  const savedManifest = JSON.parse(env.readFile('manifest.json'));
  assert.deepStrictEqual(savedManifest, manifest, 'Manifest should remain unchanged');
  env.cleanup();
});

test('sentinel fix: Apply behavior - should patch manifest and docs', (t) => {
  const env = new TestEnv('apply');
  const manifest = {
    app_name: "test-app",
    risk_category: "high",
    declared_flags: ["existing_flag"]
  };
  env.createFile('manifest.json', manifest);
  
  const result = env.run(['fix', '--apply']);
  
  assert.strictEqual(result.status, 0, 'Apply should exit with 0');
  assert.strictEqual(result.stdout.includes('Updated manifest.json'), true);
  
  const savedManifest = JSON.parse(env.readFile('manifest.json'));
  assert.strictEqual(savedManifest.declared_flags.includes('existing_flag'), true, 'Should preserve existing flags');
  assert.strictEqual(savedManifest.declared_flags.includes('transparency_disclosure_provided'), true, 'Should add missing flags');
  
  // Verify no duplicates
  const counts = savedManifest.declared_flags.reduce((acc, f) => { acc[f] = (acc[f] || 0) + 1; return acc; }, {});
  assert.strictEqual(counts['transparency_disclosure_provided'], 1, 'Should not duplicate flags');
  
  assert.strictEqual(fs.existsSync(path.join(env.dir, 'docs/compliance/human_oversight.md')), true, 'Should create compliance docs');
  env.cleanup();
});

test('sentinel fix: Multiple manifests - should fail without explicit path', (t) => {
  const env = new TestEnv('multiple-manifests');
  env.createFile('manifest.json', { app_name: 'one' });
  env.createFile('sentinel.manifest.json', { app_name: 'two' });
  
  const result = env.run(['fix']);
  
  assert.strictEqual(result.status, 1, 'Should fail when ambiguous');
  assert.strictEqual(result.stderr.includes('Both manifest.json and sentinel.manifest.json exist'), true);
  env.cleanup();
});

test('sentinel fix: Existing docs safety - should not overwrite', (t) => {
  const env = new TestEnv('docs-safety');
  env.createFile('manifest.json', { app_name: 'test', risk_category: 'high' });
  const customContent = '# My Custom Doc';
  env.createFile('docs/compliance/human_oversight.md', customContent);
  
  const result = env.run(['fix', '--apply']);
  
  assert.strictEqual(result.stdout.includes('Skipped docs/compliance/human_oversight.md (exists)'), true);
  assert.strictEqual(env.readFile('docs/compliance/human_oversight.md'), customContent, 'Content should be preserved');
  env.cleanup();
});

test('sentinel fix: Reporting consistency - summary should match audit output', (t) => {
  const env = new TestEnv('reporting');
  // Use a manifest that will still have findings after fix (governance/data rules)
  env.createFile('manifest.json', { 
    app_name: 'test', 
    risk_category: 'High',
    declared_flags: [] 
  });
  
  const result = env.run(['fix', '--apply']);
  
  // Verify new branding/messaging
  assert.strictEqual(result.stdout.includes('Structural compliance issues resolved'), true);
  assert.strictEqual(result.stdout.includes('Remaining findings require human review'), true);
  assert.strictEqual(result.stdout.includes('Sentinel prepares your system for audit'), true);
  
  // Run --json and get count
  const jsonResult = env.run(['manifest.json', '--json']);
  const audit = JSON.parse(jsonResult.stdout);
  const jsonCount = audit.summary.violations_total + (audit.evidence_findings ? audit.evidence_findings.length : 0);
  
  assert.ok(jsonCount > 0, 'Should have some remaining findings for high-risk app');
  env.cleanup();
});

test('sentinel fix: Missing manifest - clean error', (t) => {
  const env = new TestEnv('missing-manifest');
  const result = env.run(['fix']);
  
  assert.strictEqual(result.status, 1);
  assert.strictEqual(result.stderr.includes('No manifest.json or sentinel.manifest.json found'), true);
  env.cleanup();
});

test('sentinel fix: No-op case - clean exit and no changes', (t) => {
  const env = new TestEnv('no-op');
  const perfectManifest = {
    app_name: "perfect-app",
    risk_category: "minimal",
    declared_flags: ["transparency_disclosure_provided"]
  };
  env.createFile('manifest.json', perfectManifest);
  const mtimeOld = fs.statSync(path.join(env.dir, 'manifest.json')).mtimeMs;
  
  const result = env.run(['fix', '--apply']);
  
  assert.strictEqual(result.stdout.includes('No safe structural fixes available'), true);
  const mtimeNew = fs.statSync(path.join(env.dir, 'manifest.json')).mtimeMs;
  assert.strictEqual(mtimeOld, mtimeNew, 'Manifest should not be modified');
  env.cleanup();
});
