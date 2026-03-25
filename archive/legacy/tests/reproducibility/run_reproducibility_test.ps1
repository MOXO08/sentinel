$ErrorActionPreference = "Continue"

$sentinelCli = "d:/AI Act Compliance API/sentinel-cli/bin/sentinel-scan.js"
$expectedDir = "d:/AI Act Compliance API/sentinel-cli/tests/reproducibility/expected_outputs"
$repos = @(
    @{ name = "vercel-ai"; manifest = "d:/AI Act Compliance API/validation-repos/vercel-ai/sentinel.manifest.json" },
    @{ name = "minGPT"; manifest = "d:/AI Act Compliance API/validation-repos/minGPT/sentinel.manifest.json" }
)

Write-Host "Running Sentinel Reproducibility Tests..."

$allPassed = $true

foreach ($repo in $repos) {
    Write-Host "Checking $($repo.name)... " -NoNewline
    
    # Run Scan
    $currentJsonStr = node "$sentinelCli" check --manifest "$($repo.manifest)" --threshold 10 --engine extended --json 2>$null | Out-String
    
    if (-not $currentJsonStr) {
        Write-Host "FAIL: No Output"
        $allPassed = $false
        continue
    }

    $currentJson = $currentJsonStr | ConvertFrom-Json
    
    # Load Expected
    $expectedPath = "$expectedDir/$($repo.name).json"
    $expectedJson = Get-Content $expectedPath | Out-String | ConvertFrom-Json
    
    # Mask
    $currentJson.manifest_path = "MASKED"
    $expectedJson.manifest_path = "MASKED"
    
    # Compare
    $currentCompressed = $currentJson | ConvertTo-Json -Depth 100 -Compress
    $expectedCompressed = $expectedJson | ConvertTo-Json -Depth 100 -Compress
    
    if ($currentCompressed -eq $expectedCompressed) {
        Write-Host "PASS"
    } else {
        Write-Host "FAIL: Mismatch"
        $allPassed = $false
        $currentJson | ConvertTo-Json -Depth 100 | Out-File "$expectedDir/$($repo.name).current.json"
    }
}

if ($allPassed) {
    Write-Host "ALL REPRODUCIBILITY TESTS PASSED."
    exit 0
} else {
    Write-Host "REPRODUCIBILITY TEST FAILURE."
    exit 1
}
