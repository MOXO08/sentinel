const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const sentinelCli = "d:/AI Act Compliance API/sentinel-cli/bin/sentinel-scan.js";
const expectedDir = "d:/AI Act Compliance API/sentinel-cli/tests/reproducibility/expected_outputs";
const repos = [
    { name: "vercel-ai", manifest: "d:/AI Act Compliance API/validation-repos/vercel-ai/sentinel.manifest.json", cwd: "d:/AI Act Compliance API/validation-repos/vercel-ai" },
    { name: "minGPT", manifest: "d:/AI Act Compliance API/validation-repos/minGPT/sentinel.manifest.json", cwd: "d:/AI Act Compliance API/validation-repos/minGPT" }
];

console.log("\n🚀 Running Sentinel Reproducibility Tests (Node.js)...");

let allPassed = true;

const maskFields = (obj) => {
    if (typeof obj !== 'object' || obj === null) return obj;
    if (Array.isArray(obj)) return obj.map(maskFields);
    
    const masked = { ...obj };
    if ('manifest_path' in masked) masked.manifest_path = "MASKED";
    if ('audit_id' in masked) masked.audit_id = "MASKED";
    if ('signed_at' in masked) masked.signed_at = "MASKED";
    
    for (const key in masked) {
        masked[key] = maskFields(masked[key]);
    }
    return masked;
};

repos.forEach(repo => {
    process.stdout.write(`Checking ${repo.name}... `);
    
    try {
        // 1. Run Scan
        let currentJsonStr;
        try {
            currentJsonStr = execSync(`node "${sentinelCli}" check --manifest "${repo.manifest}" --threshold 10 --engine extended --json`, { stdio: ['ignore', 'pipe', 'ignore'], cwd: repo.cwd, maxBuffer: 10 * 1024 * 1024 }).toString();

        } catch (e) {
            // If it failed due to exit code 1 (below threshold), the output is still in e.stdout
            if (e.stdout) {
                currentJsonStr = e.stdout.toString();
            } else {
                throw e;
            }
        }
        
        const currentJson = maskFields(JSON.parse(currentJsonStr));
        
        // 2. Load Expected
        const expectedPath = path.join(expectedDir, `${repo.name}.json`);
        const expectedJson = maskFields(JSON.parse(fs.readFileSync(expectedPath, 'utf8')));
        
        // 3. Compare (Deep Sort/Normalize if needed, but here we just stringify)
        const currentStr = JSON.stringify(currentJson);
        const expectedStr = JSON.stringify(expectedJson);
        
        if (currentStr === expectedStr) {
            console.log("[\x1b[32mPASS\x1b[0m]");
        } else {
            console.log("[\x1b[31mFAIL: Mismatch\x1b[0m]");
            allPassed = false;
            fs.writeFileSync(path.join(expectedDir, `${repo.name}.current.json`), JSON.stringify(currentJson, null, 2));
        }
    } catch (err) {
        console.log(`[\x1b[31mFAIL: ${err.message}\x1b[0m]`);
        allPassed = false;
    }
});

if (allPassed) {
    console.log("\n\x1b[32m✔ ALL REPRODUCIBILITY TESTS PASSED.\x1b[0m\n");
    process.exit(0);
} else {
    console.log("\n\x1b[31m✖ REPRODUCIBILITY TEST FAILURE.\x1b[0m\n");
    process.exit(1);
}
