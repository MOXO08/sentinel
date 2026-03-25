const fs = require('fs');
const path = require('path');

const targetFile = 'D:/AI Act Compliance API/sentinel-cli/bin/sentinel-scan.js';
if (!fs.existsSync(targetFile)) {
    console.error(`Error: ${targetFile} not found.`);
    process.exit(1);
}

let content = fs.readFileSync(targetFile, 'utf8');

const proTip = `\\n\\x1b[36m\\x1b[1mPro-Tip:\\x1b[0m\\x1b[36m Consult the official Compliance Guide at \\x1b[97mUSER_MANUAL.md\\x1b[0m\\n`;

// Clear old Romanian pro-tip if exists
const oldProTipRo = `\\n\\x1b[36m\\x1b[1mPro-Tip:\\x1b[0m\\x1b[36m Consult the official Compliance Guide at \\x1b[97mMANUAL_DE_UTILIZARE.md\\x1b[0m\\n`;
content = content.replace(new RegExp(escapeRegex(oldProTipRo), 'g'), proTip);

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// 1. Inject into printBanner (Universal visibility)
const oldPos = '╚══════════════════════════════════════════════════╝\\${C.reset}\\n\`);';
const replacement = '╚══════════════════════════════════════════════════╝\\${C.reset}\\n\`);\n  console.log(\`' + proTip + '\`);';

if (content.indexOf(proTip) === -1) {
    // If not found, look for help or banner
    if (content.indexOf('USER_MANUAL.md') === -1) {
         // This is a fresh injection or replacement of MANUAL_DE_UTILIZARE
         content = content.replace(/MANUAL_DE_UTILIZARE\.md/g, 'USER_MANUAL.md');
    }
}

fs.writeFileSync(targetFile, content);
console.log('✅ Successfully reinforced English manual reference in sentinel-scan.js');
