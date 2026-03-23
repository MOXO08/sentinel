# _antigravity-audit.ps1
# Testare completă Sentinel pentru toate repo-urile

$rootPath = "D:\AI Act Compliance API\sentinel-cli"
$reportGen = Join-Path $rootPath "generate_reports.js"

# Lista repo-urilor de auditat (excluzând folderele de sistem/build)
$repos = Get-ChildItem -Path $rootPath -Directory | Where-Object { $_.Name -notmatch "node_modules|audit-results|sovereign-reports|.git|bin|dist|docs|configs|bin-builds" }

foreach ($repo in $repos) {
    $repoPath = $repo.FullName
    $resultsDir = Join-Path $repoPath "results"
    
    # Navigăm în repo pentru execuție (IMPORTANTE pentru generate_reports.js)
    Push-Location -Path $repoPath
    
    Write-Host "`n--- Start audit repo: $($repo.Name) ---" -ForegroundColor Cyan

    # Prioritate pentru sentinel.manifest.json, fallback la manifest.json
    $manifestFile = "sentinel.manifest.json"
    if (!(Test-Path $manifestFile)) { $manifestFile = "manifest.json" }
    
    if (Test-Path $manifestFile) {
        # Asigură existența folderului results
        if (!(Test-Path "results")) { New-Item -ItemType Directory -Path "results" -Force | Out-Null }

        # Rulează audit Sentinel și extrage datele pentru feedback imediat
        Write-Host "Execuție scan Sentinel..." -ForegroundColor Gray
        $reportJson = npx @radu_api/sentinel-scan check --manifest $manifestFile --policy eu-ai-act-minimal --threshold 90 --json 2>$null
        $reportJson | Out-File -Encoding utf8 "results\sentinel-report.json" -Force

        try {
            $data = $reportJson | ConvertFrom-Json
            $confColor = if ($data.confidence -eq "HIGH") { "Green" } elseif ($data.confidence -eq "MEDIUM") { "Yellow" } else { "Red" }
            
            Write-Host "   - Claim Score: $($data.claim_score)/100" -ForegroundColor Gray
            Write-Host "   - Evidence:    $($data.evidence_score)/100" -ForegroundColor Gray
            Write-Host "   - Confidence:  $($data.confidence)" -ForegroundColor $confColor
        } catch { }

        # Generare raport Boardroom (Executiv)
        Write-Host "Generare raport Boardroom..." -ForegroundColor Cyan
        node $reportGen --repo $($repo.Name)
        
        Write-Host "✅ Audit și Raport complet pentru $($repo.Name)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  SKIP: Manifest JSON nu există în $($repo.Name)" -ForegroundColor Red
    }
    
    Pop-Location
}

Write-Host "`n--- Audit complet pentru toate repo-urile ---" -ForegroundColor Cyan
