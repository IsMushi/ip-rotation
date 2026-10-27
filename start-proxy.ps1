# Starts tor_proxy.py in the background and loads the proxy environment into
# this PowerShell session. Extra arguments are passed through to tor_proxy.py:
#
#   .\start-proxy.ps1
#   .\start-proxy.ps1 --rotate 120 --socks-port 9050

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$TorArgs
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path $here "tor_proxy.py"
$envFile = Join-Path $here "proxy.env.ps1"
$pidFile = Join-Path $here "proxy.pid"
$outLog = Join-Path $here "proxy.out.log"
$errLog = Join-Path $here "proxy.err.log"

if (-not (Test-Path $script)) {
    Write-Host "tor_proxy.py not found next to this script." -ForegroundColor Red
    exit 1
}

# Already running?
if (Test-Path $pidFile) {
    $daemonPid = Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($daemonPid -and (Get-Process -Id $daemonPid -ErrorAction SilentlyContinue)) {
        if (Test-Path $envFile) {
            . $envFile
            Write-Host "Tor proxy already running (pid $daemonPid)." -ForegroundColor Green
            Write-Host "SOCKS: $env:TOR_SOCKS_URL"
            return
        }
    }
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}

Remove-Item $envFile, $pidFile -Force -ErrorAction SilentlyContinue

$python = (Get-Command python -ErrorAction Stop).Source
$argList = @("`"$script`"")
if ($TorArgs) { $argList += $TorArgs }

Write-Host "Starting Tor proxy (first run can take a few minutes)..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $python -ArgumentList $argList -WorkingDirectory $here `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput $outLog -RedirectStandardError $errLog

for ($i = 0; $i -lt 300; $i++) {
    if (Test-Path $envFile) { break }
    if ($proc.HasExited) {
        # python may be a launcher that exits while the real process keeps running
        Start-Sleep -Seconds 2
        break
    }
    Start-Sleep -Seconds 1
}

if (-not (Test-Path $envFile)) {
    Write-Host "Tor proxy failed to start." -ForegroundColor Red
    Write-Host "--- last errors ---"
    Get-Content $errLog -Tail 20 -ErrorAction SilentlyContinue
    Get-Content $outLog -Tail 20 -ErrorAction SilentlyContinue
    exit 1
}

. $envFile

$realPid = $proc.Id
if (Test-Path $pidFile) {
    $fromFile = Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($fromFile) { $realPid = $fromFile }
}

Write-Host "Tor proxy running (pid $realPid)." -ForegroundColor Green
Write-Host "  SOCKS:  $env:TOR_SOCKS_URL"
if ($env:TOR_HTTP_PROXY) { Write-Host "  HTTP:   $env:TOR_HTTP_PROXY" }
Write-Host "  Rotate: .\rotate-now.ps1"
Write-Host "  Stop:   .\stop-proxy.ps1"
Write-Host "Environment variables are set for this shell only; new shells can run: . .\proxy.env.ps1"
