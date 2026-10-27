#!/usr/bin/env python3
"""Fetch URLs through the Tor proxy, rotating the exit IP on HTTP 429.

Works with the background proxy from tor_proxy.py / start-proxy.ps1:

    . .\\proxy.env.ps1
    python tor_fetch.py https://httpbin.org/status/429 --max-attempts 2

Or import it:

    from tor_fetch import fetch
    response = fetch("https://example.com")

Rotation is requested by creating the daemon's trigger file (rotate.now); the
function then waits for the daemon's rotate.done file, so callers know exactly
when the new circuit is ready.
"""

from __future__ import annotations

import argparse
import email.utils
import os
import sys
import time
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
DEFAULT_ROTATE_FILE = HERE / "rotate.now"
DEFAULT_DONE_FILE = HERE / "rotate.done"
TOR_CHECK_URL = "https://check.torproject.org/api/ip"


# --------------------------------------------------------------------------- #
# Proxy helpers
# --------------------------------------------------------------------------- #


def tor_session(proxy_url: str | None = None) -> requests.Session:
    """A requests session routed through the Tor SOCKS proxy."""
    proxy_url = proxy_url or os.environ.get("TOR_SOCKS_URL")
    if not proxy_url:
        raise RuntimeError(
            "TOR_SOCKS_URL is not set - run .\\start-proxy.ps1 "
            "or load . .\\proxy.env.ps1 first"
        )
    session = requests.Session()
    session.proxies = {"http": proxy_url, "https": proxy_url}
    session.headers["User-Agent"] = "tor-fetch/1.0"
    # Ignore HTTP(S)_PROXY / NO_PROXY from the environment: only the explicit
    # SOCKS proxy above may be used.
    session.trust_env = False
    return session


def verify_tor(session: requests.Session, timeout: float = 20.0) -> str:
    """Return the exit IP, or raise if the traffic is not going through Tor."""
    response = session.get(
        TOR_CHECK_URL, timeout=timeout, headers={"Connection": "close"}
    )
    response.raise_for_status()
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError(f"unexpected response from {TOR_CHECK_URL}") from exc

    if not data.get("IsTor"):
        raise RuntimeError(
            f"traffic is not going through Tor (visible IP: {data.get('IP')})"
        )
    return str(data.get("IP"))


def exit_ip(session: requests.Session, timeout: float = 15.0) -> str:
    response = session.get("https://api.ipify.org", timeout=timeout)
    response.raise_for_status()
    return response.text.strip()


def rotate_via_daemon(
    rotate_file: str | os.PathLike | None = None,
    *,
    done_file: str | os.PathLike | None = None,
    wait: float = 60.0,
    poll: float = 0.5,
    sleep=time.sleep,
) -> bool:
    """Ask tor_proxy.py for a new exit IP and wait until it finishes.

    Returns True when the daemon reported a completed rotation, False on
    timeout (for example when the daemon is not running).
    """
    trigger = Path(rotate_file or os.environ.get("TOR_ROTATE_FILE") or DEFAULT_ROTATE_FILE)
    done = Path(done_file or os.environ.get("TOR_ROTATE_DONE") or DEFAULT_DONE_FILE)

    before = done.stat().st_mtime if done.exists() else 0.0

    trigger.parent.mkdir(parents=True, exist_ok=True)
    trigger.touch()

    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        sleep(poll)
        if done.exists() and done.stat().st_mtime > before:
            return True
    return False


# --------------------------------------------------------------------------- #
# Rate-limit detection
# --------------------------------------------------------------------------- #


def is_rate_limited(response: requests.Response) -> bool:
    """True for 429, or a 403 that carries rate-limit signals."""
    if response.status_code == 429:
        return True
    if response.status_code == 403:
        if response.headers.get("X-RateLimit-Remaining") == "0":
            return True
        if "Retry-After" in response.headers:
            return True
    return False


def retry_after_seconds(response: requests.Response) -> float | None:
    """Parse Retry-After as seconds or an HTTP date."""
    value = response.headers.get("Retry-After")
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    return max(0.0, when.timestamp() - time.time())


# --------------------------------------------------------------------------- #
# Fetch with rotation
# --------------------------------------------------------------------------- #


def fetch(
    url: str,
    *,
    session: requests.Session | None = None,
    rotate=None,
    max_attempts: int = 5,
    timeout: float = 30.0,
    max_retry_after: float = 120.0,
    require_tor: bool = False,
    sleep=time.sleep,
    verbose: bool = True,
) -> requests.Response:
    """GET a URL, rotating the Tor exit IP whenever a rate limit is hit.

    With ``require_tor=True`` the proxy is verified first and a leak raises.
    ``rotate`` defaults to rotate_via_daemon and can be replaced in tests.
    """
    session = session or tor_session()
    rotate = rotate or (lambda: rotate_via_daemon(sleep=sleep))

    if require_tor:
        verify_tor(session, timeout=timeout)

    attempts = max(1, max_attempts)
    response: requests.Response | None = None

    for attempt in range(1, attempts + 1):
        response = session.get(url, timeout=timeout)
        if not is_rate_limited(response):
            return response

        if attempt >= attempts:
            break

        delay = retry_after_seconds(response)
        if verbose:
            print(
                f"rate limited (HTTP {response.status_code}), rotating "
                f"[attempt {attempt}/{attempts}]",
                file=sys.stderr,
                flush=True,
            )
        rotate()
        # Drop keep-alive connections so the retry uses a fresh Tor circuit.
        close = getattr(session, "close", None)
        if callable(close):
            close()
        if delay:
            sleep(min(delay, max_retry_after))

    assert response is not None
    return response


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch a URL through Tor, rotating on HTTP 429.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", nargs="?")
    parser.add_argument(
        "--proxy",
        help="SOCKS URL (default: $TOR_SOCKS_URL)",
    )
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--check",
        action="store_true",
        help="only verify that the proxy is Tor, then exit",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="verify Tor before sending the request",
    )
    parser.add_argument("--show-headers", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.url and not args.check:
        parser.error("a URL is required unless --check is used")

    try:
        session = tor_session(args.proxy)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.check or args.verify:
        try:
            tor_ip = verify_tor(session, timeout=args.timeout)
        except (RuntimeError, requests.RequestException) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"verified Tor exit IP: {tor_ip}")
        if args.check:
            return 0

    try:
        response = fetch(
            args.url,
            session=session,
            max_attempts=args.max_attempts,
            timeout=args.timeout,
            verbose=not args.quiet,
        )
    except requests.RequestException as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"HTTP {response.status_code}")
    if args.show_headers:
        for key, value in response.headers.items():
            print(f"{key}: {value}")
    if response.text:
        print(response.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
