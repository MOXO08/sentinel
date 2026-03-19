const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const CLI_PATH = path.resolve(__dirname, '../bin/sentinel-scan.js');

class TestEnv {
  constructor(name) {
    this.dir = path.join(os.tmpdir(), `sentinel-init-test-${name}-${Math.random().toString(36).slice(2)}`);
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
    } catch (e) {}
  }
}

test('sentinel init: basic scaffolding', (t) => {
  const env = new TestEnv('basic');
  const result = env.run(['init']);
  
  assert.strictEqual(result.status, 0);
  assert.strictEqual(fs.existsSync(path.join(env.dir, 'manifest.json')), true);
  assert.strictEqual(fs.existsSync(path.join(env.dir, 'docs/compliance/human_oversight.md')), true);
  assert.strictEqual(fs.existsSync(path.join(env.dir, 'docs/compliance/data_governance.md')), true);
  assert.strictEqual(fs.existsSync(path.join(env.dir, 'docs/compliance/risk_assessment.md')), true);
  
  const manifest = JSON.parse(env.readFile('manifest.json'));
  assert.strictEqual(manifest.app_name, 'unnamed-ai-service');
  assert.strictEqual(manifest.risk_category, 'High');
  
  assert.strictEqual(result.stdout.includes('Created manifest.json'), true);
  assert.strictEqual(result.stdout.includes('Next steps:'), true);
  env.cleanup();
});

test('sentinel init: abort if manifest exists', (t) => {
  const env = new TestEnv('abort');
  env.createFile('manifest.json', { old: true });
  
  const result = env.run(['init']);
  
  assert.strictEqual(result.status, 1);
  assert.strictEqual(result.stderr.includes('Manifest already exists'), true);
  
  const manifest = JSON.parse(env.readFile('manifest.json'));
  assert.strictEqual(manifest.old, true, 'Should not have overwritten existing manifest');
  env.cleanup();
});

test('sentinel init: do not overwrite existing docs', (t) => {
  const env = new TestEnv('docs-no-overwrite');
  const customContent = '# My Custom Oversight';
  env.createFile('docs/compliance/human_oversight.md', customContent);
  
  const result = env.run(['init']);
  
  assert.strictEqual(result.status, 0);
  assert.strictEqual(env.readFile('docs/compliance/human_oversight.md'), customContent, 'Should not overwrite existing doc');
  assert.strictEqual(result.stdout.includes('Skipped 1 files (already exist)'), true);
  
  // Should still create the other ones
  assert.strictEqual(fs.existsSync(path.join(env.dir, 'docs/compliance/data_governance.md')), true);
  env.cleanup();
});
