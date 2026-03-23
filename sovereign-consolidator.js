const fs = require('fs');
const path = require('path');

// 1. Setup Relative Paths
const projectRoot = process.cwd();
const resultsDir = path.join(projectRoot, 'audit-results');
const outputDir = path.join(projectRoot, 'sovereign-reports');
const outputMd = path.join(outputDir, 'sovereign-portfolio-report.md');
const outputHtml = path.join(outputDir, 'sovereign-portfolio-report.html');

if (!fs.existsSync(resultsDir)) {
    console.error(`Error: Results directory '${resultsDir}' not found.`);
    process.exit(1);
}
if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

const files = fs.readdirSync(resultsDir).filter(f => f.endsWith('.json'));
const reports = [];

// 2. Aggregate Data (Zero Recalculation Policy)
files.forEach(file => {
    try {
        const raw = fs.readFileSync(path.join(resultsDir, file), 'utf8');
        const jsonStart = raw.indexOf('{');
        if (jsonStart === -1) return;
        const data = JSON.parse(raw.substring(jsonStart));
        
        // Finalized metrics from SSoT (CLI JSON)
        reports.push({
            name: file.replace('-report.json', '').replace('sentinel-', ''),
            score: data.score,
            claim_score: data.claim_score,
            phi: data.phi || 0,
            exposure: data.exposure || 0,
            confidence: data.confidence,
            verdict: data.verdict,
            risk_category: data.risk_category,
            findings: data.top_findings || [],
            manifest_path: data.manifest_path,
            signals: data._internal ? data._internal.total_signals : 0,
            breakdown: data._internal ? data._internal.signal_breakdown : null
        });
    } catch (e) {
        console.error(`Skipped ${file}: ${e.message}`);
    }
});

if (reports.length === 0) {
    console.log("No audit results found to consolidate.");
    process.exit(0);
}

// 3. Portfolio Global Stats (Derived from finalized reports)
const totalSignals = reports.reduce((acc, r) => acc + (r.signals || 0), 0);
const totalScore = reports.reduce((acc, r) => acc + r.score, 0);
const avgScore = (totalScore / reports.length).toFixed(1);
const compliantCount = reports.filter(r => r.verdict === 'PASS' || r.verdict === 'COMPLIANT').length;
const complianceRate = ((compliantCount / reports.length) * 100).toFixed(0);

// --- GENERIC MD OUTPUT ---
let md = `# Sovereign Portfolio Audit Report\n\n`;
md += `**Date**: ${new Date().toLocaleDateString()} | **Assets**: ${reports.length} | **Portfolio Score**: ${avgScore}/100 | **Total Signals**: ${totalSignals}\n\n`;
md += `| Repository | Score | Trust | Signals | Status | Primary Finding |\n`;
md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
reports.forEach(r => {
    const statusIcon = (r.verdict === 'PASS' || r.verdict === 'COMPLIANT') ? '✅' : '❌';
    const firstFinding = r.findings.length > 0 ? r.findings[0].description : 'Optimal';
    md += `| **${r.name}** | ${r.score} | ${r.confidence} | ${r.signals} | ${statusIcon} | ${firstFinding} |\n`;
});
fs.writeFileSync(outputMd, md);

// --- PREMIUM HTML OUTPUT ---
const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sovereign Framework Portfolio Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Playfair+Display:wght@700&display=swap" rel="stylesheet">
    <style>
        :root { --primary: #1a237e; --secondary: #3949ab; --bg: #f8f9fa; --text: #2c3e50; --success: #2e7d32; --danger: #c62828; --border: #e0e6ed; }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 0; }
        .container { max-width: 1000px; margin: 0 auto; background: #fff; box-shadow: 0 10px 40px rgba(0,0,0,0.05); min-height: 100vh; }
        .cover { height: 35vh; display: flex; flex-direction: column; justify-content: center; align-items: center; background: linear-gradient(135deg, #1a237e 0%, #0d124a 100%); color: #fff; text-align: center; }
        section { padding: 40px 60px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 40px; }
        .stat-card { background: #fdfdfd; border: 1px solid var(--border); padding: 15px; border-radius: 8px; text-align: center; }
        .stat-card .value { font-size: 28px; font-weight: 700; color: var(--primary); }
        .stat-card .label { font-size: 10px; text-transform: uppercase; color: #666; margin-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #f8f9fa; text-align: left; padding: 12px; font-size: 10px; text-transform: uppercase; color: #666; border-bottom: 2px solid var(--border); }
        td { padding: 15px 12px; border-bottom: 1px solid var(--border); font-size: 12px; }
        .trust-tag { font-size: 9px; padding: 2px 6px; border-radius: 10px; font-weight: bold; text-transform: uppercase; }
        .trust-high { background: #e8f5e9; color: #2e7d32; }
        .trust-medium { background: #fff3e0; color: #ef6c00; }
        .trust-low { background: #ffebee; color: #c62828; }
        .score-bar { width: 100%; height: 6px; background: #eee; border-radius: 3px; position: relative; }
        .score-fill { height: 100%; border-radius: 3px; background: var(--secondary); }
        .status-badge { padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 9px; }
        .badge-pass { background: rgba(46,125,50,0.1); color: var(--success); }
        .badge-fail { background: rgba(198,40,40,0.1); color: var(--danger); }
        .signal-pill { font-size: 8px; background: #eee; padding: 1px 4px; border-radius: 3px; color: #555; margin-right: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="cover">
            <div style="text-transform: uppercase; letter-spacing: 5px; opacity: 0.7; font-size: 11px;">Sentinel Ecosystem</div>
            <h1 style="font-family: 'Playfair Display', serif; font-size: 40px; margin: 10px 0;">SOVEREIGN</h1>
            <div style="font-weight: 300; font-size: 14px; opacity: 0.9;">Portfolio Compliance Intelligence</div>
        </div>
        <section>
            <div class="stats-grid">
                <div class="stat-card"><div class="label">Avg Score</div><div class="value">${avgScore}</div></div>
                <div class="stat-card"><div class="label">Compliance</div><div class="value">${complianceRate}%</div></div>
                <div class="stat-card"><div class="label">Assets</div><div class="value">${reports.length}</div></div>
                <div class="stat-card"><div class="label">Audit Rigor</div><div class="value">${totalSignals}</div></div>
            </div>
            <table>
                <thead>
                    <tr><th>Repository</th><th>Signals</th><th>Trust</th><th>Score</th><th>Status</th></tr>
                </thead>
                <tbody>
                    ${reports.map(r => `
                    <tr>
                        <td style="font-weight: 600;">${r.name}</td>
                        <td style="min-width: 140px;">
                            <div style="font-size: 11px; font-weight: bold;">${r.signals} signals (φ: ${Math.round(r.phi * 100)}%)</div>
                            ${r.breakdown ? `
                            <div style="margin-top: 4px;">
                                <span class="signal-pill">A:${r.breakdown.ai_assets}</span>
                                <span class="signal-pill">T:${r.breakdown.transparency}</span>
                                <span class="signal-pill">O:${r.breakdown.oversight}</span>
                                <span class="signal-pill">L:${r.breakdown.logging}</span>
                            </div>` : ''}
                        </td>
                        <td>
                            <span class="trust-tag trust-${r.confidence.toLowerCase()}">${r.confidence}</span><br/>
                            <span style="font-size: 9px; color: #999;">Exp: ${r.exposure}</span>
                        </td>
                        <td>
                            <div class="score-bar"><div class="score-fill" style="width: ${r.score}%"></div></div>
                            <div style="font-size: 9px; margin-top: 4px;">Compliance Score: ${r.score}/100</div>
                        </td>
                        <td>
                            <span class="status-badge ${r.verdict === 'PASS' || r.verdict === 'COMPLIANT' ? 'badge-pass' : 'badge-fail'}">
                                ${r.verdict}
                            </span>
                        </td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
        </section>
        <footer style="text-align: center; padding: 20px; color: #999; font-size: 11px; border-top: 1px solid #eee;">
            Generated by Sovereign CLI Portfolio Orchestrator. Finalized metrics from Audit JSON SSoT.
        </footer>
    </div>
</body>
</html>`;

fs.writeFileSync(outputHtml, html);
console.log(`✅ Reports updated: \n   - MD: ${outputMd}\n   - HTML: ${outputHtml}`);
