# SovereignSync.ps1 - Total Portfolio Alignment Script

$repositories = @(
    "sentinel",
    "sentinel-scan-action",
    "sentinel-landing",
    "sentinel-ai-demo",
    "sentinel-demo-hr-ai",
    "sentinel-verified",
    "sentinel-example-ai-app",
    "sentinel-python-api-example",
    "sentinel-nextjs-starter",
    "sentinel-ci-template",
    "rustwasm-worker-template"
)

$githubUser = "MOXO08"
$basePath = Get-Location
$sentinelBin = Join-Path $basePath "bin/sentinel-scan.js"
$reportGen = Join-Path $basePath "generate_reports.js"

$workflowContent = @"
name: Sentinel Compliance Scan

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  compliance-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run Sentinel Compliance Scan
        run: |
          npx @radu_api/sentinel-scan check --threshold 90 --manifest sentinel.manifest.json || npx @radu_api/sentinel-scan check --threshold 90 --manifest manifest.json
"@

Write-Host "--- Starting Sovereign Total Sync & Audit ---" -ForegroundColor Cyan

foreach ($repo in $repositories) {
    $repoPath = Join-Path -Path $basePath -ChildPath $repo
    Write-Host ""
    Write-Host ">>> Processing: $repo <<<" -ForegroundColor Yellow
    
    # 1. Sync
    if (Test-Path -Path $repoPath) {
        Write-Host "Updating local repo..." -ForegroundColor Gray
        Set-Location -Path $repoPath
        git pull origin main 2>$null; git pull origin master 2>$null
    } else {
        Write-Host "Cloning from GitHub..." -ForegroundColor Gray
        git clone "https://github.com/$githubUser/$repo.git" $repoPath 2>$null
        Set-Location -Path $repoPath
    }

    # 2. Scaffolding (Manifest)
    $manifest = "sentinel.manifest.json"
    if (!(Test-Path -Path $manifest) -and !(Test-Path -Path "manifest.json")) {
        Write-Host "Initializing manifest..." -ForegroundColor Cyan
        node $sentinelBin init | Out-Null
    } else {
        if (!(Test-Path -Path $manifest)) { $manifest = "manifest.json" }
    }

    # 3. GitHub Workflow
    $workflowDir = ".github/workflows"
    if (!(Test-Path -Path $workflowDir)) { New-Item -Path $workflowDir -ItemType Directory -Force | Out-Null }
    $workflowPath = Join-Path $workflowDir "sentinel.yml"
    $workflowContent | Out-File -FilePath $workflowPath -Encoding utf8 -Force
    Write-Host "CI Workflow updated." -ForegroundColor Gray

    # 4. Audit Técnica
    if (!(Test-Path -Path "results")) { New-Item -Path "results" -ItemType Directory -Force | Out-Null }
    $reportFile = "results/sentinel-report.json"
    Write-Host "Running Audit..." -ForegroundColor White
    node $sentinelBin check --manifest $manifest --threshold 90 --json > $reportFile 2>results/error.log

    # 5. Boardroom Report
    if ((Get-Item -Path $reportFile).Length -gt 2) {
        node $reportGen --repo $repo
        Write-Host "SUCCESS: Audit and Boardroom report generated." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Audit failed for $repo. Check results/error.log" -ForegroundColor Red
    }

    Set-Location -Path $basePath
}

Write-Host ""
Write-Host "--- Portfolio Synchronization and Audit Complete ---" -ForegroundColor Cyan
