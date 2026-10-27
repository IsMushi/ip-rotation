# Requests a clean shutdown of the background Tor proxy.
# Falls back to killing the processes if it does not stop in time.

$ErrorActionPreference = "SilentlyContinue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pidFile = Join-Path $here "proxy.pid"
$torPidFile = Join-Path $here "tor.pid"
$stopFile = Join-Path $here "stop.now"

$daemonPid = $null
if (Test-Path $pidFile) {
    $daemonPid = Get-Content $pidFile | Select-Object -First 1
}

if (-not $daemonPid -or -not (Get-Process -Id $daemonPid -ErrorAction SilentlyContinue)) {
    Write-Host "Tor proxy is not running."
} else {
    New-Item -ItemType File -Path $stopFile -Force | Out-Null
    Write-Host "Stopping Tor proxy (pid $daemonPid)..."

    for ($i = 0; $i -lt 25; $i++) {
        if (-not (Get-Process -Id $daemonPid -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Seconds 1
    }

    if (Get-Process -Id $daemonPid -ErrorAction SilentlyContinue) {
        Write-Host "Graceful stop timed out; killing processes." -ForegroundColor Yellow
        Stop-Process -Id $daemonPid -Force -ErrorAction SilentlyContinue
        if (Test-Path $torPidFile) {
            $torPid = Get-Content $torPidFile | Select-Object -First 1
            if ($torPid) { Stop-Process -Id $torPid -Force -ErrorAction SilentlyContinue }
        }
    }
    Write-Host "Stopped." -ForegroundColor Green
}

Remove-Item $pidFile, $torPidFile, $stopFile -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $here "proxy.env"), (Join-Path $here "proxy.env.ps1"), (Join-Path $here "proxy.env.cmd") -Force -ErrorAction SilentlyContinue
Write-Host "Environment files removed. Open shells still hold the old variables."
