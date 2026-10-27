# Asks the running Tor proxy for a new exit IP right now.

$ErrorActionPreference = "SilentlyContinue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pidFile = Join-Path $here "proxy.pid"

$daemonPid = $null
if (Test-Path $pidFile) {
    $daemonPid = Get-Content $pidFile | Select-Object -First 1
}

if (-not $daemonPid -or -not (Get-Process -Id $daemonPid -ErrorAction SilentlyContinue)) {
    Write-Host "Tor proxy is not running. Start it with .\start-proxy.ps1" -ForegroundColor Red
    exit 1
}

New-Item -ItemType File -Path (Join-Path $here "rotate.now") -Force | Out-Null
Write-Host "Rotation requested (pid $daemonPid). Check proxy.err.log for the new IP."
