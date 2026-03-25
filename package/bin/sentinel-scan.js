#!/usr/bin/env node
// sentinel-scan — EU AI Act Compliance CLI
// Usage: npx sentinel-scan ./manifest.json [--api-key <key>] [--endpoint <url>]

'use strict';

const fs = require('fs');
const path = require('path');
const cliProgress = require('cli-progress');

// ── ANSI Colors (no external deps) ──
const C = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m',
    gray: '\x1b[90m',
    white: '\x1b[97m',
};

function colorVerdict(verdict) {
    switch (verdict) {
        case 'COMPLIANT': return `${C.bold}${C.green}✅ COMPLIANT${C.reset}`;
        case 'COMPLIANT_VIA_AI_REVIEW': return `${C.bold}${C.green}✅ COMPLIANT (via AI Review)${C.reset}`;
        case 'NON_COMPLIANT': return `${C.bold}${C.red}❌ NON_COMPLIANT${C.reset}`;
        case 'HUMAN_INTERVENTION_REQUIRED': return `${C.bold}${C.yellow}⚠️  HUMAN_INTERVENTION_REQUIRED${C.reset}`;
        case 'INSUFFICIENT_DATA': return `${C.bold}${C.magenta}❓ INSUFFICIENT_DATA${C.reset}`;
    }
}

function pauseAndExit(code = 0) {
    if (process.stdout.isTTY && process.platform === 'win32' && !process.argv.includes('--json')) {
        process.stdout.write(`\n${C.gray}Scan finished. Press ENTER to close this window...${C.reset}`);
        process.stdin.resume();
        process.stdin.on('data', () => process.exit(code));
    } else {
        process.exit(code);
    }
}

function printBanner() {
    console.log(`\n${C.cyan}${C.bold}╔══════════════════════════════════════════════════╗`);
    console.log(`║  🛡  SENTINEL — LOCAL DIAGNOSTIC TOOL (OFFLINE)  ║`);
    console.log(`╚══════════════════════════════════════════════════╝${C.reset}\n`);
}

function printHelp() {
    console.log(`${C.bold}Usage:${C.reset}`);
    console.log(`  npx sentinel-scan <manifest.json>           Run offline diagnostic scan`);
    console.log(`  npx sentinel-scan <manifest.json> --remote  Real-time audit via Sentinel Edge API`);
    console.log(`\n${C.bold}Options:${C.reset}`);
    console.log(`  --api-key <key>     API Key (Developer or Pro)`);
    console.log(`  --json              Output raw JSON for CI/CD pipelines`);
    console.log(`  --endpoint <url>    Custom Edge API endpoint`);
    console.log(`  --help              Show this help`);
}

// ── Top 10 Reguli AI Act — Embedded offline ──
const OFFLINE_RULES = {
    rules: [
        { id: "ART5-001", description: "Subliminal manipulation", risk_category: "Unacceptable", required_flags: [], forbidden_flags: ["subliminal_techniques"] },
        { id: "ART5-003", description: "Social scoring", risk_category: "Unacceptable", required_flags: [], forbidden_flags: ["social_scoring"] },
        { id: "ART10-001", description: "Data governance & Bias assessment", risk_category: "High", required_flags: ["bias_assessment_performed", "data_governance_policy_documented"] },
        { id: "ART13-001", description: "User notification of AI interaction", risk_category: "High", required_flags: ["user_notification_ai_interaction"] },
        { id: "ART14-001", description: "Human oversight", risk_category: "High", required_flags: ["human_oversight_enabled"] },
        { id: "ART22-001", description: "Conformity assessment", risk_category: "High", required_flags: ["conformity_assessment_completed"] },
    ]
};

async function runOffline(manifest) {
    const { run_audit } = require('../pkg-node/sentinel_core.js');
    const verdictText = run_audit(JSON.stringify(manifest), JSON.stringify(OFFLINE_RULES));
    return JSON.parse(verdictText);
}

async function runRemote(manifest, apiKey, endpoint) {
    const https = require('https');
    const body = JSON.stringify(manifest);
    const url = new URL(endpoint);

    const pkg = require('../package.json');
    return new Promise((resolve, reject) => {
        const req = https.request({
            hostname: url.hostname,
            path: url.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`,
                'X-Sentinel-CLI-Version': pkg.version,
                'Content-Length': Buffer.byteLength(body),
            }
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode >= 400) return reject(new Error(`API Error (${res.statusCode}): ${data}`));
                const results = JSON.parse(data);
                if (typeof results === 'object' && !Array.isArray(results)) {
                    results._headers = res.headers;
                }
                resolve(results);
            });
        });
        req.on('error', reject); req.write(body); req.end();
    });
}

function printResult(verdict, isJson) {
    if (isJson) {
        console.log(JSON.stringify(verdict, null, 2));
        pauseAndExit(verdict.verdict === 'NON_COMPLIANT' ? 1 : 0);
    }

    const divider = `${C.gray}──────────────────────────────────────────────────${C.reset}`;
    console.log(divider);

    if (Array.isArray(verdict)) {
        console.log(`${C.bold}Bulk Diagnostic Result:${C.reset} ${verdict.length} items scanned.`);
        const compliant = verdict.filter(v => v.verdict.includes('COMPLIANT')).length;
        const nonCompliant = verdict.filter(v => v.verdict === 'NON_COMPLIANT').length;
        console.log(`  ${C.green}Compliant:${C.reset}     ${compliant}`);
        console.log(`  ${C.red}Non-Compliant:${C.reset} ${nonCompliant}`);
    } else {
        console.log(`${C.bold}App:${C.reset}          ${verdict.app_name} @ v${verdict.version}`);
        console.log(`${C.bold}Verdict:${C.reset}      ${colorVerdict(verdict.verdict)}`);
        console.log(`${C.bold}Risk Score:${C.reset}   ${verdict.risk_score}/100`);

        if (verdict.violations) {
            console.log(`\n${C.bold}Regulatory Frictions:${C.reset}`);
            verdict.violations.forEach(v => {
                const color = v.article === 'LOCKED' ? C.gray : (v.severity === 'CRITICAL' ? C.red : C.yellow);
                console.log(`  ${color}[${v.article}] ${v.description}${C.reset}`);
                if (v.fix_snippet) console.log(`    ${C.gray}Fix: ${v.fix_snippet}${C.reset}`);
            });
        }
    }

    console.log(divider);

    const expiration = verdict._headers ? verdict._headers['x-sentinel-draft-expiration'] : null;
    const penalty = verdict._headers ? verdict._headers['x-sentinel-reconstruction-penalty'] : null;
    const status = verdict._headers ? verdict._headers['x-sentinel-status'] : 'ACTIVE';

    if (expiration) {
        if (status === 'PAUSED') {
            console.log(`${C.green}${C.bold}✨ STATUS: AUDIT DATA RESERVED.${C.reset} Digital integrity locked for 72h.`);
            console.log(`${C.gray}Pending Proforma Verification / Enterprise Review.${C.reset}\n`);
        } else {
            const expDate = new Date(expiration);
            const now = new Date();
            const diffMs = expDate - now;
            if (diffMs > 0) {
                const hours = Math.floor(diffMs / 3600000);
                const minutes = Math.floor((diffMs % 3600000) / 60000);

                if (penalty) {
                    console.log(`${C.yellow}${C.bold}⚠️  DATA PERSISTENCE: Record Archiving Policy applies in ${minutes}m.${C.reset}`);
                } else {
                    console.log(`${C.cyan}${C.bold}ℹ️  NOTICE:${C.reset} Temporary Audit Buffer expires in ${C.bold}${hours}h ${minutes}m${C.reset}.`);
                }
                console.log(`${C.gray}Temporary reports are archived after 4h to maintain regulatory data hygiene.${C.reset}\n`);
            }
        }
    }

    console.log(`${C.gold}${C.bold}V8.5 SOVEREIGN PROTOCOL:${C.reset} To finalize ${C.bold}Technical Conformity Reports (Art 11)${C.reset} and`);
    console.log(`${C.white}access ${C.bold}Regulatory Liability Coverage (~$35M)${C.reset}${C.white}, visit:${C.reset}`);
    console.log(`   ${C.cyan}${C.bold}https://gettingsentinel.com/compliance-vault?ref=cli_v85${C.reset}`);
    console.log(`   ${C.magenta}${C.bold}Enterprise Onboarding: Global industrial standard for AI Act Art. 43${C.reset}\n`);

    const isFail = Array.isArray(verdict) ? verdict.some(v => v.verdict === 'NON_COMPLIANT') : verdict.verdict === 'NON_COMPLIANT';
    pauseAndExit(isFail ? 1 : 0);
}

async function main() {
    const args = process.argv.slice(2);
    if (args.length === 0 || args.includes('--help')) {
        printBanner(); printHelp(); pauseAndExit(0);
    }

    const manifestPath = args.find(a => !a.startsWith('--')) || args[0];
    const isRemote = args.includes('--remote');
    const isJson = args.includes('--json');

    const apiKeyIdx = args.indexOf('--api-key');
    const apiKey = apiKeyIdx !== -1 ? args[apiKeyIdx + 1] : process.env.SENTINEL_API_KEY || '';
    const endpointIdx = args.indexOf('--endpoint');
    const endpoint = endpointIdx !== -1 ? args[endpointIdx + 1] : 'https://sentinel-api.sentinel-moxo.workers.dev';

    if (!fs.existsSync(manifestPath)) {
        console.error(`${C.red}Error: File not found: ${manifestPath}${C.reset}`);
        pauseAndExit(2);
    }

    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch (e) {
        console.error(`${C.red}Error: Invalid JSON: ${e.message}${C.reset}`);
        pauseAndExit(2);
    }

    if (!isJson) {
        printBanner();
        console.log(`${C.gray}Scanning: ${path.resolve(manifestPath)}${C.reset}`);
        console.log(`${C.gray}Mode: ${isRemote ? '🌐 Remote Audit' : '⚡ Local Diagnostic'}${C.reset}\n`);
    }

    try {
        let results;
        if (Array.isArray(manifest)) {
            const bar = new cliProgress.SingleBar({
                format: `${C.cyan}Scanning |${C.reset}{bar}${C.cyan}| {percentage}% || {value}/{total} Items`,
                barCompleteChar: '\u2588', barIncompleteChar: '\u2591', hideCursor: true
            });
            if (!isJson) bar.start(manifest.length, 0);
            results = [];
            for (const item of manifest) {
                results.push(isRemote ? await runRemote(item, apiKey, endpoint) : await runOffline(item));
                if (!isJson) bar.increment();
            }
            if (!isJson) bar.stop();
        } else {
            results = isRemote ? await runRemote(manifest, apiKey, endpoint) : await runOffline(manifest);
        }

        printResult(results, isJson);
    } catch (err) {
        console.error(`${C.red}Scan failed: ${err.message}${C.reset}`);
        pauseAndExit(2);
    }
}

main();
