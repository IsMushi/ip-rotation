#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Opens Chrome or Edge through the local Tor proxy, with WebRTC leaks blocked.

.DESCRIPTION
    Chrome/Edge do NOT use the Windows proxy setting when they are launched with
    their own profile, and even with --proxy-server they still leak the real IP
    through WebRTC (STUN over UDP bypasses the proxy).

    This launcher starts a separate browser profile with:
      --proxy-server=socks5://127.0.0.1:<port>     all traffic through Tor
      --webrtc-ip-handling-policy=disable_non_proxied_udp
                                                   WebRTC cannot use direct UDP
    and opens check.torproject.org so you can see the result immediately.

.EXAMPLE
    .\start-browser.ps1
    .\start-browser.ps1 -Url https://browserleaks.com/ip
    .\start-browser.ps1 -Browser edge
#>
param(
    [string]$Url = "https://check.torproject.org/",
    [int]$SocksPort = 9050,
    [ValidateSet("chrome", "edge")]
    [string]$Browser = "chrome",
    [string]$ProfileDir = "$env:TEMP\tor-browser-profile",
    [switch]$PrintOnly
)

$ErrorActionPreference = "Stop"

# Pick up the port the daemon is actually using, if it is running.
$envFile = Join-Path $PSScriptRoot "proxy.env"
if (Test-Path $envFile) {
    $line = Get-Content $envFile | Where-Object { $_ -match '^TOR_SOCKS=127\.0\.0\.1:(\d+)$' }
    if ($line -and $line -match ':(\d+)$') { $SocksPort = [int]$Matches[1] }
}

$listening = Get-NetTCPConnection -State Listen -LocalPort $SocksPort -ErrorAction SilentlyContinue
if (-not $listening) {
    Write-Error "No SOCKS proxy on 127.0.0.1:$SocksPort - run .\start-proxy.ps1 first."
}

$paths = @{
    chrome = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    )
    edge = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
    )
}
$exe = $paths[$Browser] | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { Write-Error "$Browser is not installed." }

$browserArgs = @(
    "--proxy-server=socks5://127.0.0.1:$SocksPort"
    "--webrtc-ip-handling-policy=disable_non_proxied_udp"
    "--user-data-dir=$ProfileDir"
    "--no-first-run"
    "--no-default-browser-check"
    "--disable-background-networking"
    $Url
)

if ($PrintOnly) {
    Write-Host "$exe $($browserArgs -join ' ')"
    return
}

Start-Process -FilePath $exe -ArgumentList $browserArgs
Write-Host "Started $Browser through Tor (SOCKS 127.0.0.1:$SocksPort)."
Write-Host "  profile: $ProfileDir  (separate from your normal browsing)"
Write-Host "  WebRTC:  direct UDP disabled, so the real IP cannot leak"
Write-Host "Check https://check.torproject.org/ -> 'Congratulations' means it works."
