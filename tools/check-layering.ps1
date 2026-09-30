<#
.SYNOPSIS
    Verify that ecdsa-ocaml respects layering constraints.

.NOTES
    Part of ecdsa-ocaml Phase 0 governance (Task #5).
#>

param([string]$ProjectRoot = $PWD)

Write-Host "=== ecdsa-ocaml Layering Check ===" -ForegroundColor Cyan
Write-Host ""

$layerOrder = @{ common=1; crypto=2; bitcoin=3; analysis=4; storage=5; application=6 }
$libToLayer = @{
    common="common"; field="crypto"; scalar="crypto"; curve="crypto"; ecdsa_der="crypto"; hash="crypto"; encoding="crypto";
    bitcoin_tx="bitcoin"; script_types="bitcoin"; sighash="bitcoin"; bitcoin="bitcoin";
    nonce="analysis"; observation="analysis"; statistics="analysis"; analysis_signature="analysis"; analysis="analysis"
}

$violations = 0

$files = @(
    "lib\common\dune", "lib\crypto\field\dune", "lib\crypto\scalar\dune", "lib\crypto\curve\dune",
    "lib\crypto\ecdsa\dune", "lib\crypto\hash\dune", "lib\crypto\encoding\dune",
    "lib\bitcoin\transaction\dune", "lib\bitcoin\script\dune", "lib\bitcoin\sighash\dune", "lib\bitcoin\dune",
    "lib\analysis\signature\dune", "lib\analysis\nonce\dune", "lib\analysis\statistics\dune"
)

foreach ($relPath in $files) {
    $fullPath = Join-Path $ProjectRoot $relPath
    if (-not (Test-Path $fullPath)) { continue }
    
    # Extract layer
    if ($relPath -match "\\lib\\([a-z_]+)\\") { $layer = $Matches[1] } else { continue }
    
    # Read file and extract libraries manually (without regex to avoid hang)
    $content = Get-Content -Path $fullPath -Raw
    $start = $content.IndexOf("(libraries")
    if ($start -lt 0) { continue }
    
    $end = $content.IndexOf(")", $start)
    if ($end -lt 0) { continue }
    
    $libString = $content.Substring($start + 10, $end - $start - 10)
    $libs = $libString -split '\s+' | Where-Object { $_ -and $_ -match '^[a-z_][-a-z0-9_]*$' }
    
    foreach ($lib in $libs) {
        $depLayer = if ($libToLayer.ContainsKey($lib)) { $libToLayer[$lib] } else { "external" }
        if ($depLayer -eq "external" -or $depLayer -eq $layer) { continue }
        
        $curOrder = $layerOrder[$layer]
        $depOrder = $layerOrder[$depLayer]
        if ($depOrder -gt $curOrder) {
            Write-Host "ERROR: $relPath" -ForegroundColor Red
            Write-Host "  $layer depends on $lib (from $depLayer)" -ForegroundColor Red
            $violations++
        }
    }
}

Write-Host ""
if ($violations -eq 0) {
    Write-Host "=== LAYERING CHECK PASSED ===" -ForegroundColor Green
    exit 0
} else {
    Write-Host "=== $violations VIOLATIONS ===" -ForegroundColor Red
    exit 1
}
