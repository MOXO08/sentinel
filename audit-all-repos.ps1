# --- Script automatizare Scan + Raport Boardroom pentru toate repo-urile ---

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

$basePath = "D:\AI Act Compliance API\sentinel-cli"

Write-Host "--- Start audit portofoliu Sentinel ---"

foreach ($repo in $repositories) {
    $repoPath = Join-Path $basePath $repo
    Write-Host ""
    Write-Host "Procesare repo: $repo"

    if (Test-Path $repoPath) {
        Set-Location $repoPath

        # Creează folder results dacă nu există
        if (!(Test-Path results)) { New-Item -ItemType Directory -Path results -Force | Out-Null }

        # Verifică manifest (prioritate sentinel.manifest.json)
        $manifestFile = "manifest.json"
        if (Test-Path "$repoPath\sentinel.manifest.json") { $manifestFile = "sentinel.manifest.json" }

        Write-Host "Rulăm audit Sentinel..."
        # Rulează scan Sentinel și generează JSON (Comanda CLI exactă conform solicitării)
        npx @radu_api/sentinel-scan check --manifest "$repoPath\$manifestFile" --policy eu-ai-act-minimal --threshold 90 --json 2>$null | Out-File -Encoding utf8 "$repoPath\results\sentinel-report.json"

        # Verificăm dacă JSON-ul a fost creat și este valid
        if (Test-Path "$repoPath\results\sentinel-report.json") {
            $jsonSize = (Get-Item "$repoPath\results\sentinel-report.json").Length
            if ($jsonSize -gt 2) {
                Write-Host "JSON valid: rezultate salvate în $repo\results\sentinel-report.json"
                
                # Generăm raport Boardroom (Executiv)
                Write-Host "Generăm raport Boardroom..."
                node "$basePath\generate_reports.js" --repo $repo
            } else {
                Write-Host "ERR: JSON-ul generat pentru $repo este gol. Verificați manifestul."
            }
        } else {
            Write-Host "ERR: Raportul JSON nu a fost generat pentru $repo."
        }

        Set-Location $basePath
    } else {
        Write-Host "SKIP: Repo-ul $repo nu a fost găsit la calea $repoPath."
    }
}

Write-Host ""
Write-Host "--- Proces finalizat: toate rapoartele au fost actualizate ---"
