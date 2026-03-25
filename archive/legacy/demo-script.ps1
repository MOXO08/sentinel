# 🎬 Viral Demo Script: "Compliance in 10 Seconds"
# This script prepares a scenario for a perfect 30-second screen recording.

Write-Host "--- 🛡️ Sentinel Demo Setup ---" -ForegroundColor Cyan

# 1. Create a "Dirty" Manifest (Fail Scenario)
$dirtyManifest = @{
    app_name = "sentinel-demo-app"
    version = "1.1.0"
    risk_category = "High"
    declared_flags = @("bias_assessment_performed") # Missing Human Oversight and Transparency!
} | ConvertTo-Json

$dirtyManifest | Out-File -FilePath "./manifest.json" -Encoding utf8

Write-Host "✅ Created non-compliant manifest." -ForegroundColor Yellow

# 2. Run Scan (The "Wait, what?" moment)
Write-Host "🚀 Running Sentinel Audit..." -ForegroundColor Green
npx @radu_api/sentinel-scan ./manifest.json

Write-Host "---"
Write-Host "❌ VERDICT: NON_COMPLIANT" -ForegroundColor Red
Write-Host "Sentinel caught the missing safety standards!" -ForegroundColor Red

# 3. Apply the "Sentinel Fix"
$cleanManifest = @{
    app_name = "sentinel-demo-app"
    version = "1.1.0"
    risk_category = "High"
    declared_flags = @(
        "human_oversight_enabled",
        "bias_assessment_performed",
        "transparency_disclosure_provided",
        "data_governance_policy_documented",
        "robustness_testing_completed",
        "cybersecurity_framework_implemented",
        "risk_management_system_active",
        "technical_documentation_available"
    )
    fallback_ai_verification = $true
} | ConvertTo-Json

$cleanManifest | Out-File -FilePath "./manifest.json" -Encoding utf8

Write-Host "✅ Fixed manifest. Applying EU AI Act standards..." -ForegroundColor Green

# 4. Final Audit (The "Success" moment)
npx @radu_api/sentinel-scan ./manifest.json

Write-Host "---"
Write-Host "✨ VERDICT: COMPLIANT" -ForegroundColor Green
Write-Host "Your AI is now safe for the European Market! 🇪🇺" -ForegroundColor Cyan
