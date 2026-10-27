#!/usr/bin/env python3
"""Fetch pages with a real Chrome through Tor.

Cloudflare and similar bot filters reject curl because of its TLS fingerprint,
not because of the IP: the same URL answers ``403 CF1`` directly and through
Tor. A real browser gets through. This script drives the Chrome already
installed on the machine over the DevTools protocol, so the request looks like
a normal browser while still exiting through Tor.

    python browser_fetch.py https://whatismyipaddress.com/
    python browser_fetch.py https://example.com --text
    python browser_fetch.py https://site/page --rotate-on-block --json

The browser is launched with the SOCKS proxy and with WebRTC pinned to the
proxy, so the page cannot learn the real IP through STUN.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

from websockets.sync.client import connect

BLOCK_MARKERS = (
    "Access Denied (CF1)",
    "Scripted access is not permitted",
    "Just a moment",
    "Verifying you are human",
    "Enable JavaScript and cookies to continue",
    "challenge-platform",
    "Attention Required",
    "Sorry, you have been blocked",
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

CHROME_PATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)


class BrowserError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Chrome / DevTools plumbing
# --------------------------------------------------------------------------- #


def find_chrome(explicit: str | None = None) -> str:
    if explicit:
        if not Path(explicit).exists():
            raise BrowserError(f"browser not found: {explicit}")
        return explicit
    for candidate in CHROME_PATHS:
        if Path(candidate).exists():
            return candidate
    raise BrowserError("Chrome or Edge not found; pass --browser PATH")


def _wait_for_devtools(profile: Path, proc: subprocess.Popen, timeout: float) -> tuple[int, str]:
    port_file = profile / "DevToolsActivePort"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise BrowserError(f"browser exited with code {proc.returncode}")
        if port_file.exists():
            try:
                first, second = port_file.read_text(encoding="utf-8").splitlines()[:2]
            except (OSError, ValueError):
                time.sleep(0.1)
                continue
            if first.strip().isdigit():
                return int(first), second.strip()
        time.sleep(0.1)
    raise BrowserError("browser did not open a DevTools port")


def _http_json(url: str, timeout: float = 5.0):
    with urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


class Chrome:
    """A Chrome instance pinned to the local Tor SOCKS port."""

    def __init__(
        self,
        *,
        socks_port: int = 9050,
        browser: str | None = None,
        headless: bool = False,
        profile: Path | None = None,
        startup_timeout: float = 30.0,
        verbose: bool = False,
    ) -> None:
        self.exe = find_chrome(browser)
        self.socks_port = socks_port
        self.headless = headless
        self.verbose = verbose
        self._own_profile = profile is None
        self.profile = profile or Path(
            tempfile.mkdtemp(prefix="tor-browser-fetch-", dir=tempfile.gettempdir())
        )
        self.proc: subprocess.Popen | None = None
        self.port = 0
        self._start(startup_timeout)

    # -- lifecycle ---------------------------------------------------------- #

    def _start(self, startup_timeout: float) -> None:
        args = [
            self.exe,
            "--remote-debugging-port=0",
            f"--user-data-dir={self.profile}",
            f"--proxy-server=socks5://127.0.0.1:{self.socks_port}",
            "--webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "about:blank",
        ]
        if self.headless:
            args.insert(1, "--headless=new")
            args.insert(2, "--disable-gpu")

        self.proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.port, _ = _wait_for_devtools(self.profile, self.proc, startup_timeout)
        if self.verbose:
            print(f"chrome pid {self.proc.pid} devtools :{self.port}", file=sys.stderr)

    def close(self) -> None:
        if self.proc is None:
            return
        try:
            version = _http_json(f"http://127.0.0.1:{self.port}/json/version", timeout=3)
            with connect(version["webSocketDebuggerUrl"], open_timeout=3) as ws:
                ws.send(json.dumps({"id": 1, "method": "Browser.close"}))
                ws.recv(timeout=3)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None
        if self._own_profile:
            shutil.rmtree(self.profile, ignore_errors=True)

    def restart(self) -> None:
        """Drop every open connection so a rotation really changes the exit."""
        self.close()
        self._own_profile = True
        self._start(30.0)

    def __enter__(self) -> "Chrome":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- targets ------------------------------------------------------------ #

    def page_websocket(self) -> str:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            for target in _http_json(f"http://127.0.0.1:{self.port}/json/list"):
                if target.get("type") == "page" and target.get("webSocketDebuggerUrl"):
                    return target["webSocketDebuggerUrl"]
            time.sleep(0.2)
        raise BrowserError("no page target in the browser")

    def new_page(self, timeout: float = 60.0) -> "Page":
        return Page(self.page_websocket(), timeout=timeout)


# --------------------------------------------------------------------------- #
# Minimal DevTools client
# --------------------------------------------------------------------------- #


class Page:
    def __init__(self, ws_url: str, timeout: float = 60.0) -> None:
        self.timeout = timeout
        self.ws = connect(ws_url, max_size=None, open_timeout=timeout)
        self._id = 0
        self._events: list[dict] = []
        self.send("Page.enable")

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass

    def send(self, method: str, **params):
        self._id += 1
        message_id = self._id
        self.ws.send(json.dumps({"id": message_id, "method": method, "params": params}))
        while True:
            raw = self.ws.recv(timeout=self.timeout)
            message = json.loads(raw)
            if message.get("id") == message_id:
                if "error" in message:
                    raise BrowserError(f"{method}: {message['error']}")
                return message.get("result", {})
            self._events.append(message)

    def wait_event(self, name: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            for index, event in enumerate(self._events):
                if event.get("method") == name:
                    del self._events[index]
                    return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                self._events.append(json.loads(self.ws.recv(timeout=remaining)))
            except TimeoutError:
                return False

    def evaluate(self, expression: str):
        result = self.send(
            "Runtime.evaluate",
            expression=expression,
            returnByValue=True,
            awaitPromise=True,
        )
        if "exceptionDetails" in result:
            raise BrowserError(result["exceptionDetails"].get("text", "evaluate failed"))
        return result.get("result", {}).get("value")

    def navigate(self, url: str, settle: float = 1.5) -> None:
        self._events.clear()
        self.send("Page.navigate", url=url)
        self.wait_event("Page.loadEventFired", self.timeout)
        if settle:
            time.sleep(settle)

    def snapshot(self, html: bool = False) -> dict:
        script = """
        (() => ({
            url: location.href,
            title: document.title || "",
            text: document.body ? document.body.innerText : "",
            html: %s,
        }))()
        """ % ("document.documentElement.outerHTML" if html else "''")
        data = self.evaluate(script) or {}
        text = data.get("text") or ""
        markup = data.get("html") or ""
        title = data.get("title") or ""
        blocked = _looks_blocked(title, text, markup)
        ips = sorted({ip for ip in IP_RE.findall(text) if not _is_private(ip)})
        return {
            "url": data.get("url", ""),
            "title": title,
            "text": text,
            "html": markup,
            "blocked": blocked,
            "ips": ips,
        }

    def wait_until_clear(self, timeout: float, poll: float = 0.5) -> None:
        """Give a Cloudflare-style challenge time to solve itself."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.evaluate(
                "({t: document.title || '', b: document.body ? document.body.innerText.slice(0, 400) : ''})"
            ) or {}
            if not _looks_blocked(state.get("t", ""), state.get("b", ""), ""):
                return
            time.sleep(poll)


def _looks_blocked(title: str, text: str, markup: str) -> bool:
    haystack = f"{title}\n{text}\n{markup}".lower()
    return any(marker.lower() in haystack for marker in BLOCK_MARKERS)


def _is_private(ip: str) -> bool:
    parts = [int(part) for part in ip.split(".")]
    if parts[0] in (0, 10, 127):
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 169 and parts[1] == 254:
        return True
    return False


# --------------------------------------------------------------------------- #
# High level fetch
# --------------------------------------------------------------------------- #


def fetch_page(
    url: str,
    *,
    socks_port: int = 9050,
    browser: str | None = None,
    headless: bool = False,
    attempts: int = 3,
    timeout: float = 60.0,
    settle: float = 1.5,
    challenge_wait: float = 15.0,
    rotate_on_block: bool = False,
    keep_html: bool = False,
    verbose: bool = False,
) -> dict:
    from tor_fetch import rotate_via_daemon

    chrome = Chrome(
        socks_port=socks_port,
        browser=browser,
        headless=headless,
        startup_timeout=timeout,
        verbose=verbose,
    )
    try:
        for attempt in range(1, attempts + 1):
            page = chrome.new_page(timeout=timeout)
            try:
                page.navigate(url, settle=settle)
                if challenge_wait > 0:
                    page.wait_until_clear(challenge_wait)
                snapshot = page.snapshot(html=keep_html)
            finally:
                page.close()

            snapshot["attempt"] = attempt
            if not snapshot["blocked"]:
                return snapshot
            if not rotate_on_block or attempt == attempts:
                return snapshot

            if verbose:
                print(f"attempt {attempt}: blocked, rotating exit", file=sys.stderr)
            if not rotate_via_daemon():
                if verbose:
                    print("rotation failed or daemon not running", file=sys.stderr)
                return snapshot
            chrome.restart()

        raise BrowserError("unreachable")
    finally:
        chrome.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch a page with a real Chrome through Tor (beats curl blocks).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url")
    parser.add_argument("--socks-port", type=int, default=9050)
    parser.add_argument("--browser", help="path to chrome.exe or msedge.exe")
    parser.add_argument("--headless", action="store_true", help="run without a window")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--settle", type=float, default=1.5, help="seconds to wait after load")
    parser.add_argument(
        "--challenge-wait",
        type=float,
        default=15.0,
        help="seconds to let a bot challenge solve itself (0 disables)",
    )
    parser.add_argument(
        "--rotate-on-block",
        action="store_true",
        help="ask the daemon for a new exit IP when a challenge page appears",
    )
    parser.add_argument("--text", action="store_true", help="print page text")
    parser.add_argument("--html", action="store_true", help="include the HTML in --json output")
    parser.add_argument("--out", help="write the HTML to this file")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = fetch_page(
            args.url,
            socks_port=args.socks_port,
            browser=args.browser,
            headless=args.headless,
            attempts=args.attempts,
            timeout=args.timeout,
            settle=args.settle,
            challenge_wait=args.challenge_wait,
            rotate_on_block=args.rotate_on_block,
            keep_html=bool(args.html or args.out),
            verbose=not args.quiet,
        )
    except (BrowserError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.out:
        Path(args.out).write_text(result["html"], encoding="utf-8")

    if args.json:
        payload = {key: result[key] for key in ("url", "title", "blocked", "ips", "attempt")}
        if args.html:
            payload["html"] = result["html"]
        print(json.dumps(payload, indent=2))
    else:
        print(f"url:     {result['url']}")
        print(f"title:   {result['title']}")
        print(f"blocked: {result['blocked']}")
        if result["ips"]:
            print(f"ips:     {', '.join(result['ips'])}")
        if args.text:
            print()
            print(result["text"].strip())

    return 2 if result["blocked"] else 0


if __name__ == "__main__":
    sys.exit(main())
