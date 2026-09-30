#!/usr/bin/env pwsh
# run-server.ps1 — start the analysis console (OCaml compute server + browser UI).
#
# WHY THIS SCRIPT EXISTS
#
# On this host, anything linked against Zarith aborts at start with exit code
# 0xC0000135 (STATUS_DLL_NOT_FOUND) unless two directories are on PATH:
#
#   1. a directory containing libgmp-10.dll — Zarith's C dependency. It is NOT in
#      the opam switch; it ships with Git for Windows' mingw64 build, and with
#      Octave. The Git one is used below.
#   2. the opam switch's lib\stublibs — which holds dllzarith.dll and every other
#      DLL the compiled binaries need (dllalcotest_stubs.dll, dllstdune_stubs.dll,
#      dllzarith.dll, ...).
#
# Without them, `dune build` still succeeds (compilation is unaffected) but every
# resulting .exe dies instantly. That failure mode is easy to misread as "the
# binaries are broken" rather than "PATH is wrong", which is exactly how this was
# first diagnosed incorrectly in this repository.
#
# Usage:
#   .\run-server.ps1              # build if needed, start server, open browser
#   .\run-server.ps1 -NoBrowser   # do not open a browser
#   .\run-server.ps1 -Port 9000   # override the listen port
#   .\run-server.ps1 -SkipBuild   # start without rebuilding

[CmdletBinding()]
param(
    [int]$Port = 8787,
    [switch]$NoBrowser,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
# Not named $PSScriptRoot-adjacent: assigning to a parameter name, or shadowing a
# reserved automatic variable, breaks binding. $RepoRoot is computed once here.
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $RepoRoot) { $RepoRoot = (Get-Location).Path }

# ---------------------------------------------------------------------- environment

function Resolve-SwitchDir {
    # Prefer the active switch, then the known local one.
    #
    # Every candidate is guarded. Join-Path throws ParameterBindingValidationException
    # when its -Path is empty or null, and because this script sets
    # $ErrorActionPreference = 'Stop', one unset environment variable (LOCALAPPDATA is
    # routinely absent in service and CI shells) would abort startup before the server
    # was even reached. A missing candidate must be skipped, not fatal.
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($env:OPAM_SWITCH_PREFIX)) {
        $candidates += $env:OPAM_SWITCH_PREFIX
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates += (Join-Path $env:LOCALAPPDATA 'opam\5.2.1')
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $candidates += (Join-Path $env:USERPROFILE 'AppData\Local\opam\5.2.1')
    }
    $candidates += 'C:\Users\profe\AppData\Local\opam\5.2.1'
    foreach ($c in $candidates) {
        if ($c -and (Test-Path (Join-Path $c 'lib\stublibs'))) { return $c }
    }
    return $null
}

$SwitchDir = Resolve-SwitchDir
if (-not $SwitchDir) {
    Write-Error "Could not find an opam switch with lib\stublibs. Set OPAM_SWITCH_PREFIX, or edit `$candidates in this script."
}

# dllzarith.dll may live in the switch's bin as well as lib\stublibs. Add both,
# plus a stublibs found anywhere under the switch, so a layout difference does not
# turn into a 0xC0000135 that reads like a broken build.
$stubExtra = @()
foreach ($cand in @((Join-Path $SwitchDir 'lib\stublibs'), (Join-Path $SwitchDir 'bin'))) {
    if (Test-Path $cand) { $stubExtra += $cand }
}
if (-not (Test-Path (Join-Path $SwitchDir 'lib\stublibs\dllzarith.dll'))) {
    $found = Get-ChildItem $SwitchDir -Recurse -Filter 'dllzarith.dll' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($found) {
        $stubExtra += $found.DirectoryName
        Write-Host "zarith : $($found.DirectoryName)" -ForegroundColor DarkGray
    }
}

# Locate a directory holding libgmp-10.dll. Zarith needs it at runtime.
$gmpCandidates = @(
    'C:\Program Files\Git\mingw64\bin',
    'C:\Program Files\GNU Octave\Octave-11.3.0\mingw64\bin'
)
# Also accept any gmp dll the switch itself carries.
$stubExtra | ForEach-Object {
    if (Get-ChildItem $_ -Filter '*gmp*.dll' -ErrorAction SilentlyContinue) { $gmpCandidates += $_ }
}
$GmpDir = $null
foreach ($d in $gmpCandidates) {
    if ((Test-Path $d) -and (Get-ChildItem $d -Filter 'libgmp*.dll' -ErrorAction SilentlyContinue)) {
        $GmpDir = $d; break
    }
}
if (-not $GmpDir) {
    Write-Warning "libgmp-10.dll was not found. Zarith-linked binaries will fail with 0xC0000135."
} else {
    $env:PATH = "$GmpDir;$env:PATH"
    Write-Host "gmp    : $GmpDir" -ForegroundColor DarkGray
}

$env:PATH = (($stubExtra -join ';') + ';' + $env:PATH)
Write-Host "switch : $SwitchDir" -ForegroundColor DarkGray

# The before-startup probe is deliberately absent. `server.exe --version` is not a
# version check: the binary ignores argv and starts a real server on the default
# port, then blocks. Probing that way launched a second server and made this script
# look like it had hung. Startup is verified after launch instead (see "serve").

$env:ECDSAC_ANALYZER_PORT = "$Port"
$env:ECDSAC_ANALYZER_ROOT = $RepoRoot

# ---------------------------------------------------------------------- port check
#
# 8787 is easy to leave occupied by an earlier run — a console that was closed
# without stopping it, or a server started from another shell. Without this check
# the new process dies on bind and the browser opens the OLD instance, which then
# serves a stale interface. That reads as "my change did nothing".

function Get-PortOwner([int]$p) {
    try {
        $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction Stop
        $owning = $conns | Select-Object -First 1 -ExpandProperty OwningProcess
        return Get-Process -Id $owning -ErrorAction Stop
    } catch {
        return $null
    }
}

$owner = Get-PortOwner $Port
if ($owner) {
    Write-Warning "Port $Port is already held by $($owner.ProcessName) (pid $($owner.Id))."
    $answer = Read-Host "Stop that process and continue? [y/N]"
    if ($answer -eq 'y' -or $answer -eq 'Y') {
        Stop-Process -Id $owner.Id -Force
        Start-Sleep -Milliseconds 600
        Write-Host "stopped pid $($owner.Id)" -ForegroundColor DarkGray
    } else {
        Write-Error "Cannot start: port $Port is in use. Pass -Port <other> or stop the process yourself."
    }
}

# ---------------------------------------------------------------------- build

if (-not $SkipBuild) {
    Write-Host "building..." -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        & dune build
        if ($LASTEXITCODE -ne 0) { Write-Error "dune build failed (exit $LASTEXITCODE)." }
    } finally { Pop-Location }
}

$serverExe = Join-Path $RepoRoot '_build\default\bin\server.exe'
if (-not (Test-Path $serverExe)) {
    Write-Error "Server binary not found at $serverExe. Run without -SkipBuild."
}

# ---------------------------------------------------------------------- frontend

$webDir = Join-Path $RepoRoot 'web'
$outDir = Join-Path $webDir 'out'
$indexHtml = Join-Path $outDir 'index.html'

if (Test-Path (Join-Path $webDir 'package.json')) {
    # Rebuild when the build is missing OR older than any source file. The server
    # serves web/out verbatim, so a stale build silently ships the old interface.
    $needsBuild = -not (Test-Path $indexHtml)
    if (-not $needsBuild) {
        $newestSrc = Get-ChildItem (Join-Path $webDir 'src') -Recurse -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newestSrc -and $newestSrc.LastWriteTime -gt (Get-Item $indexHtml).LastWriteTime) {
            $needsBuild = $true
            Write-Host "frontend source changed since the last build" -ForegroundColor DarkGray
        }
    }

    if ($needsBuild) {
        Write-Host "building the frontend (npm run build)..." -ForegroundColor Yellow
        Push-Location $webDir
        try {
            & npm run build
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "npm run build failed. The server will start API-only; the browser will show the route list instead of the UI."
            }
        } finally { Pop-Location }
    }
    if (Test-Path $indexHtml) { Write-Host "frontend: $indexHtml" -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------- serve

# A probe such as `server.exe --version` is NOT safe here: the binary ignores argv
# and simply starts listening on its default port, so probing by running it starts a
# second server that blocks forever while this script appears to hang. Startup is
# verified by watching the real process instead.

Write-Host ""
Write-Host "starting analysis server on http://127.0.0.1:$Port" -ForegroundColor Green

$proc = Start-Process -FilePath $serverExe -PassThru -NoNewWindow

# Wait for the port to actually accept, so the browser is opened against a live
# server rather than racing it. Bounded, so a failure surfaces instead of hanging.
$deadline = (Get-Date).AddSeconds(20)
$listening = $false
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
        $listening = $true; break
    }
    Start-Sleep -Milliseconds 250
}

if ($proc.HasExited) {
    $code = $proc.ExitCode
    $unsigned = if ($code -lt 0) { $code + 4294967296 } else { $code }
    Write-Host ""
    Write-Host "The server exited immediately (code $code)." -ForegroundColor Red
    if ($unsigned -eq 3221225781) {
        Write-Host @"
0xC0000135 = STATUS_DLL_NOT_FOUND. A DLL the binary links is missing from PATH.
Zarith needs libgmp-10.dll; the compiled binaries also need the switch's dllzarith.dll.
PATH was:
  $env:PATH
"@ -ForegroundColor Yellow
    }
    exit 1
}

if (-not $listening) {
    Write-Warning "The server process is alive but nothing is listening on port $Port yet. Continuing anyway."
}

if (-not $NoBrowser) {
    Start-Process "http://127.0.0.1:$Port/" | Out-Null
    Write-Host "opened the interface in the default browser" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Ctrl+C stops the server." -ForegroundColor DarkGray
while (-not $proc.HasExited) { Start-Sleep -Milliseconds 500 }
exit $proc.ExitCode
