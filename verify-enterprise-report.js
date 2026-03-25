const { generateEnterpriseReport } = require('./bin/lib/enterprise-report');
const fs = require('fs');

try {
    const scanData = JSON.parse(fs.readFileSync('scan_output_ent.json', 'utf8'));
    const reportPath = generateEnterpriseReport(scanData);
    console.log(`ENTERPRISE AUDIT REPORT GENERATED: ${reportPath}`);
} catch (err) {
    console.error(`Verification failed: ${err.message}`);
}
