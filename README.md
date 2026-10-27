# tor-ip-swapper

Rotate your public IP by asking Tor for a new circuit, then verify the change.

Works in two modes:

- **Attach** to a running Tor (Tor Browser or a system `tor` daemon).
- **Launch** its own private Tor instance if none is running (uses Tor Browser's
  `tor.exe` if it is installed).

## Requirements

- Python 3.10+
- `stem`, `requests`, `PySocks` (already installed on this machine)
- A Tor binary: Tor Browser, the Tor Expert Bundle, or a `tor` package

```powershell
python -m pip install -r requirements.txt
```

## Quick start

```powershell
cd C:\Users\USER\Documents\tor-ip-swapper

# One rotation (launches a private Tor if nothing is running)
python tor_ip_swapper.py

# Show your real IP, then rotate 3 times
python tor_ip_swapper.py --show-direct --count 3

# Keep rotating every 30 seconds forever
python tor_ip_swapper.py --loop 30

# Only print the current Tor exit IP
python tor_ip_swapper.py --count 0

# JSON lines for scripts / pipelines
python tor_ip_swapper.py --json --loop 60

# Attach to Tor Browser that is already running
python tor_ip_swapper.py --no-launch
```

Exit codes: `0` = every rotation changed the IP, `1` = error, `2` = an IP could
not be changed (limited exit pool), `130` = interrupted.

## Background proxy for other tools

`tor_proxy.py` keeps Tor alive, rotates the exit IP on a timer (or on demand),
and writes environment files so curl, yt-dlp, Playwright, and other programs can
use it without touching their code.

```powershell
.\start-proxy.ps1                              # rotate every 5 minutes
.\start-proxy.ps1 --rotate 120 --socks-port 9050
```

`start-proxy.ps1` loads the variables into the current shell and prints the SOCKS
and HTTP proxy URLs. To use the proxy from a different shell:

```powershell
. .\proxy.env.ps1        # PowerShell
call proxy.env.cmd       # cmd.exe
```

Variables written to `proxy.env*`: `TOR_SOCKS_URL`, `TOR_SOCKS`, `TOR_CONTROL`,
`TOR_HTTP_PROXY`, `TOR_ROTATE_FILE`, `TOR_ROTATE_DONE`, `ALL_PROXY`,
`HTTP_PROXY`, `HTTPS_PROXY` (upper and lower case), and `NO_PROXY` for localhost.

### Examples

```powershell
curl.exe -x $env:TOR_SOCKS_URL https://api.ipify.org
yt-dlp --proxy $env:TOR_SOCKS_URL "https://example.com/video"
```

```python
import os
import requests

proxy = os.environ["TOR_SOCKS_URL"]
print(requests.get("https://api.ipify.org",
                   proxies={"http": proxy, "https": proxy}, timeout=30).text)
```

```python
import os
from playwright.sync_api import sync_playwright

server = os.environ["TOR_SOCKS_URL"].replace("socks5h://", "socks5://")
with sync_playwright() as p:
    browser = p.chromium.launch(proxy={"server": server})
    page = browser.new_page()
    page.goto("https://check.torproject.org")
    print(page.title())
    browser.close()
```

### HTTP proxy (Windows / apps without SOCKS)

The daemon also listens on `http://127.0.0.1:8080` and forwards everything
through Tor. Use it for programs that only understand HTTP proxies:

```powershell
curl.exe -x http://127.0.0.1:8080 https://api.ipify.org
Invoke-WebRequest -Proxy http://127.0.0.1:8080 https://api.ipify.org -UseBasicParsing
```

Windows-wide:

1. Settings -> Network & Internet -> Proxy -> Manual proxy setup
2. Address `127.0.0.1`, port `8080`
3. Save

Change the port with `--http-port 8081`, disable the bridge with `--no-http`.
It binds to localhost only - do not expose it to your network. For scripts,
prefer the SOCKS URL (`socks5h://`), which avoids the extra hop.

### Browser through Tor (no real-IP leaks)

A browser only uses the proxy if it is told to. The Windows proxy setting is
ignored by Chrome/Edge profiles that were started without it, and even with
`--proxy-server` Chrome still leaks the real IP through **WebRTC**: its STUN
checks send UDP straight out, bypassing SOCKS.

Measured on this machine, Chrome 155, SOCKS 9050, no WebRTC flag:

| Check | Result |
|---|---|
| HTTP IP (browserleaks.com/ip) | `185.129.61.7` - Tor exit |
| WebRTC public IP | `196.12.130.108` - **real IP, leaked** |

`start-browser.ps1` fixes both:

```powershell
.\start-browser.ps1                                   # opens check.torproject.org
.\start-browser.ps1 -Url https://browserleaks.com/ip
.\start-browser.ps1 -Browser edge
```

It launches a separate profile (`%TEMP%\tor-browser-profile`) with:

```
--proxy-server=socks5://127.0.0.1:9050
--webrtc-ip-handling-policy=disable_non_proxied_udp
```

With that flag the same test reports the Tor exit for both HTTP and WebRTC
(`2001:67c:89c:702:...`), so the real address never appears.

Notes:

- Use the **separate profile**; reusing your normal profile keeps its cookies and
  logins, which identify you regardless of IP.
- `--force-webrtc-ip-handling-policy` is ignored by current Chrome and still
  leaks - use the flag without `force-`.
- whatismyipaddress.com sits behind Cloudflare and answers `403 CF1` to scripted
  access; through Tor it usually serves a challenge. `check.torproject.org` and
  `browserleaks.com/ip` are better tests.
- Tor Browser does all of this by itself; use it when you want maximum
  protection rather than this Chrome profile.

### Rotate and stop

```powershell
.\rotate-now.ps1     # new exit IP immediately
.\stop-proxy.ps1     # clean shutdown, removes proxy.env* and pid files
```

Notes:

- The proxy only lives while `tor_proxy.py` runs; `stop-proxy.ps1` (or Ctrl+C in
  the foreground) shuts it down.
- `--socks-port 9050` gives a fixed port across restarts; otherwise a launched Tor
  picks a random free port (the env files always contain the right one).
- `ALL_PROXY`/`HTTP(S)_PROXY` apply to the whole shell, so every CLI tool started
  from it uses Tor (including `pip`). Open a fresh shell to get normal networking
  back.
- Existing connections keep their circuit; only new connections use the new IP.
- Different destinations can use different exit relays at the same time, so two
  sites may see two different IPs even without a rotation.
- Logs go to `proxy.err.log` and `proxy.out.log`.

## Handling HTTP 429 (rate limits)

`tor_fetch.py` detects rate limits, asks the running proxy for a new exit IP,
and retries:

```powershell
. .\proxy.env.ps1
python tor_fetch.py https://httpbin.org/status/429 --max-attempts 2 --show-headers
```

Treated as a rate limit:

- `429 Too Many Requests`
- `403` with `X-RateLimit-Remaining: 0` or a `Retry-After` header

It honours `Retry-After` (capped at 120s), closes keep-alive connections before
retrying (otherwise Tor would reuse the old circuit), and gives up after
`--max-attempts`.

From Python:

```python
from tor_fetch import fetch

response = fetch("https://example.com", max_attempts=5)
print(response.status_code)
```

Offline tests (no Tor, no network):

```powershell
python test_429.py
```

Notes:

- Rotation only helps with per-IP limits; account, API-key, and cookie quotas
  stay used up.
- A 429/403 from Cloudflare may mean "Tor is blocked", not "slow down" -
  rotating will not help.
- Each rotation costs roughly 10-20s because of Tor's NEWNYM throttle, so keep
  `--max-attempts` small for interactive work.

## Prove the visible IP is from Tor

`--check` asks check.torproject.org through the proxy and fails unless the
answer says `"IsTor": true`:

```powershell
. .\proxy.env.ps1
python tor_fetch.py --check
```

```
verified Tor exit IP: 185.220.101.99
```

Add `--verify` to a fetch to check before sending it:

```powershell
python tor_fetch.py --verify https://httpbin.org/ip
```

```
verified Tor exit IP: 185.220.101.99
HTTP 200
{"origin": "185.220.101.99"}
```

From Python:

```python
from tor_fetch import tor_session, verify_tor

session = tor_session()        # explicit socks5h proxy, trust_env=False
print(verify_tor(session))     # raises if the traffic is not Tor
response = session.get("https://example.com")
```

Playwright:

```python
page.goto("https://check.torproject.org/api/ip")
print(page.inner_text("body"))   # {"IsTor": true, "IP": "..."}
```

Leak rules:

- Only use the Tor session/proxy; never mix in direct requests.
- Keep `socks5h://` so DNS lookups also go through Tor.
- `trust_env=False` stops other proxy variables (`HTTP_PROXY`, `NO_PROXY`) from
  silently changing the route.
- After a rotation, close/recreate connections (or use `Connection: close`) or
  the old circuit keeps being reused.

## How it works

1. Connect to the Tor control port (9151 for Tor Browser, 9051 for a daemon),
   authenticating with a cookie or password.
2. Read the current exit IP through the SOCKS proxy
   (`socks5h://127.0.0.1:...`, so DNS is resolved inside Tor).
3. Send `SIGNAL NEWNYM`, which tells Tor to use fresh circuits. Tor ignores
   this signal more often than once every 10 seconds, so the script waits.
4. Re-check the IP and retry a few times until it differs.

## Use it from Python

```python
from tor_ip_swapper import TorIPSwapper

with TorIPSwapper().start() as tor:
    print(tor.check_ip())          # ('185.x.x.x', True)

    result = tor.rotate()
    print(result.old_ip, "->", result.new_ip, result.changed)

    # All traffic on this session goes through Tor
    print(tor.session.get("https://httpbin.org/ip").json())
```

Rotate inside a scraper loop:

```python
with TorIPSwapper(attempts=5, settle=4).start() as tor:
    for url in urls:
        try:
            r = tor.session.get(url, timeout=30)
            if r.status_code in (403, 429):
                tor.rotate()
                r = tor.session.get(url, timeout=30)
        except Exception:
            tor.rotate()
```

## Attaching to a system Tor

Use `torrc.example` as a starting point, then:

```powershell
python tor_ip_swapper.py --control-port 9051 --socks-port 9050
python tor_ip_swapper.py --control-port 9051 --control-password SECRET
python tor_ip_swapper.py --control-port 9151 --cookie-path "C:\path\to\control_auth_cookie"
```

If Tor Browser is running, `--no-launch` finds it on 9151/9150 automatically.

## Notes and limitations

- **Not every rotation yields a new IP.** Tor has a finite pool of exits, and
  `NEWNYM` only guarantees a new *circuit*, not a new *exit*. The script retries
  (`--attempts`) and exits with code `2` if nothing changed.
- **10-second floor.** Tor rate-limits `NEWNYM`; `--loop 0` still ends up around
  one rotation per 10-20 seconds.
- **First launch is slow.** A fresh Tor instance downloads the network consensus
  and can take 1-3 minutes; later launches reuse the cache in
  `%TEMP%\tor-ip-swapper`. Raise `--bootstrap-timeout` on a slow connection.
- **Some sites block Tor.** Rotating the IP does not defeat logins, CAPTCHAs, or
  fingerprinting.
- **Use it lawfully.** Respect the terms of service of the sites you access.
- A launched Tor instance stores its data in `%TEMP%\tor-ip-swapper`. Two
  simultaneous launched instances will conflict over that directory; pass
  `--data-dir` to separate them.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `no tor binary found` | Install Tor Browser / Tor Expert Bundle, or pass `--tor-bin` |
| `authentication on control port ... failed` | Pass `--control-password` or `--cookie-path`; make sure `ControlPort` is enabled in `torrc` |
| `control port ... is open but not Tor` | Another app owns the port; choose a different `--control-port` |
| `IP unchanged` repeatedly | Wait a bit (exit pool churn), raise `--attempts`, or lower `--settle` to 2 |
| `Missing dependencies for SOCKS support` | `python -m pip install "requests[socks]"` |
| Bootstrap takes forever | Corporate network / firewall blocking Tor; try a bridge or another network |
| `.ps1` scripts blocked by execution policy | `powershell -ExecutionPolicy Bypass -File .\start-proxy.ps1`, or `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `Tor proxy is not running` from `rotate-now.ps1` | Start it with `.\start-proxy.ps1`; check `proxy.err.log` |
"# SHINGA" 
"# ip-rotation" 
"# ip-rotation" 
"# ip-rotation" 
"# ip-rotation" 
