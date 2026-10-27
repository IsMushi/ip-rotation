#!/usr/bin/env python3
"""Rotate your public IP address using Tor.

Attaches to an already running Tor (Tor Browser or a system tor daemon) or
launches a private Tor instance, then asks Tor for a new circuit (NEWNYM) and
verifies that the exit IP actually changed.

Examples
--------
    python tor_ip_swapper.py                    # one rotation
    python tor_ip_swapper.py --count 5          # five rotations
    python tor_ip_swapper.py --loop 30          # rotate forever, 30s apart
    python tor_ip_swapper.py --launch           # force a private Tor instance
    python tor_ip_swapper.py --json --loop 60   # machine readable output

Library use
-----------
    from tor_ip_swapper import TorIPSwapper

    with TorIPSwapper().start() as tor:
        print(tor.check_ip())
        tor.rotate()
        tor.session.get("https://example.com")   # goes through Tor
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import requests
from stem import Signal
from stem.connection import authenticate_cookie
from stem.control import Controller

# Tor silently ignores NEWNYM signals sent more often than once every 10s.
MIN_NEWNYM_WAIT = 10.0

DEFAULT_CHECK_URLS = (
    # ipify is fast; check.torproject.org is kept as a fallback that also
    # reports whether the IP really is a Tor exit.
    "https://api.ipify.org?format=json",
    "https://icanhazip.com",
    "https://check.torproject.org/api/ip",
)

# (control port, socks port) pairs to probe when attaching to a running Tor.
# Tor Browser uses 9151/9150, a system tor daemon usually 9051/9050.
CANDIDATE_ENDPOINTS = ((9151, 9150), (9051, 9050))

USER_AGENT = "tor-ip-swapper/1.0"


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def log(message: str, *, quiet: bool = False) -> None:
    """Log to stderr so that --json keeps stdout clean."""
    if quiet:
        return
    print(f"[{datetime.now():%H:%M:%S}] {message}", file=sys.stderr, flush=True)


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def find_tor_binary(explicit: str | None = None) -> str | None:
    """Locate a tor executable on this machine."""
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"tor binary not found: {path}")
        return str(path)

    for name in ("tor", "tor.exe"):
        found = shutil.which(name)
        if found:
            return found

    home = Path.home()
    local_appdata = os.environ.get("LOCALAPPDATA")
    candidates = [
        home / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        home / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor",
        Path("C:/Program Files/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
        Path("C:/Program Files (x86)/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
        Path("C:/Program Files/Tor/tor.exe"),
        Path("/usr/bin/tor"),
        Path("/usr/local/bin/tor"),
        Path("/usr/sbin/tor"),
        Path("/opt/homebrew/bin/tor"),
        Path("/Applications/Tor Browser.app/Contents/MacOS/Tor/tor"),
    ]
    if local_appdata:
        candidates.insert(
            2,
            Path(local_appdata) / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        )

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def parse_ip_response(response: requests.Response) -> tuple[str | None, bool | None]:
    """Extract (ip, is_tor) from a check endpoint response."""
    try:
        data = response.json()
    except ValueError:
        text = response.text.strip()
        return (text or None), None

    if not isinstance(data, dict):
        return None, None

    ip = data.get("IP") or data.get("ip") or data.get("origin")
    is_tor = data.get("IsTor")
    if isinstance(is_tor, str):
        is_tor = is_tor.strip().lower() == "true"
    elif is_tor is not None:
        is_tor = bool(is_tor)

    if isinstance(ip, str):
        ip = ip.strip() or None
    else:
        ip = None
    return ip, is_tor


def read_log_tail(path: Path, lines: int = 5) -> str:
    """Last few lines of the tor log, for error messages."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "no log available"
    tail = " | ".join(line.strip() for line in content[-lines:])
    return tail or "no log available"


def direct_ip(timeout: float = 10.0) -> str | None:
    """Best-effort lookup of the real (non-Tor) IP, for comparison only."""
    for url in ("https://api.ipify.org?format=json", "https://icanhazip.com"):
        try:
            response = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()
            ip, _ = parse_ip_response(response)
            if ip:
                return ip
        except requests.RequestException:
            continue
    return None


@dataclass
class Rotation:
    old_ip: str
    new_ip: str
    is_tor: bool | None
    attempts: int

    @property
    def changed(self) -> bool:
        return self.old_ip != self.new_ip


# --------------------------------------------------------------------------- #
# Main class
# --------------------------------------------------------------------------- #


class TorIPSwapper:
    """Attach to (or launch) Tor and rotate the exit IP on demand."""

    def __init__(
        self,
        *,
        socks_port: int | None = None,
        control_port: int | None = None,
        control_password: str | None = None,
        cookie_path: str | None = None,
        tor_bin: str | None = None,
        data_dir: str | None = None,
        launch: bool | None = None,
        check_urls: tuple[str, ...] = DEFAULT_CHECK_URLS,
        timeout: float = 20.0,
        settle: float = 3.0,
        attempts: int = 4,
        bootstrap_timeout: float = 300.0,
        quiet: bool = False,
        verbose: bool = False,
    ) -> None:
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password
        self.cookie_path = cookie_path
        self.tor_bin = tor_bin
        self.data_dir = data_dir
        self.launch = launch
        self.check_urls = check_urls
        self.timeout = timeout
        self.settle = settle
        self.attempts = attempts
        self.bootstrap_timeout = bootstrap_timeout
        self.quiet = quiet
        self.verbose = verbose

        self.mode: str | None = None
        self._controller: Controller | None = None
        self._proc = None
        self._log_handle = None
        self._session: requests.Session | None = None
        self._last_newnym = 0.0

    # -- lifecycle ---------------------------------------------------------- #

    def start(self) -> "TorIPSwapper":
        """Attach to a running Tor, or launch a private one if needed."""
        if self.control_port is not None:
            socks = self.socks_port or (self.control_port - 1)
            controller = self._attach(socks, self.control_port)
            if controller is not None:
                self._finish_attach(controller, socks, self.control_port, "attached")
                return self
            if self.launch is False:
                raise RuntimeError(
                    f"could not attach to Tor on control port {self.control_port}"
                )
        else:
            for control, socks in CANDIDATE_ENDPOINTS:
                controller = self._attach(socks, control)
                if controller is not None:
                    self._finish_attach(controller, socks, control, "attached")
                    return self

        if self.launch is False:
            raise RuntimeError(
                "no running Tor found and --no-launch was given "
                "(start Tor Browser or a tor daemon first)"
            )

        self._launch_private_tor()
        return self

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None
        if self._controller is not None:
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=10)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            except Exception:
                pass
            self._log_handle = None

    def __enter__(self) -> "TorIPSwapper":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- attaching / launching --------------------------------------------- #

    def _attach(self, socks_port: int, control_port: int) -> Controller | None:
        if not port_open(control_port):
            return None

        try:
            controller = Controller.from_port(address="127.0.0.1", port=control_port)
        except Exception as exc:
            log(f"control port {control_port} is open but not Tor: {exc}", quiet=self.quiet)
            return None

        try:
            self._authenticate(controller)
        except Exception as exc:
            controller.close()
            log(
                f"authentication on control port {control_port} failed: {exc} "
                "(set --control-password or --cookie-path)",
                quiet=self.quiet,
            )
            return None

        if not port_open(socks_port):
            controller.close()
            log(
                f"control port {control_port} works but SOCKS port {socks_port} is closed",
                quiet=self.quiet,
            )
            return None
        return controller

    def _launch_private_tor(self) -> None:
        tor_bin = find_tor_binary(self.tor_bin)
        if not tor_bin:
            raise RuntimeError(
                "no tor binary found - install Tor Browser or the Tor Expert Bundle, "
                "add tor to PATH, or pass --tor-bin PATH"
            )

        socks = self.socks_port or free_port()
        control = self.control_port or free_port()
        while control == socks:
            control = free_port()

        data_dir = (
            Path(self.data_dir).expanduser().resolve()
            if self.data_dir
            else Path(tempfile.gettempdir()) / "tor-ip-swapper"
        )
        data_dir.mkdir(parents=True, exist_ok=True)
        cookie_file = data_dir / "control_auth_cookie"
        log_file = data_dir / "tor.log"
        torrc_file = data_dir / "torrc"

        # Relative paths + cwd=data_dir avoid tor's Windows path-escaping rules.
        torrc = "\n".join(
            [
                f"SocksPort 127.0.0.1:{socks}",
                f"ControlPort 127.0.0.1:{control}",
                "CookieAuthentication 1",
                "DataDirectory .",
                "ClientOnly 1",
            ]
        )
        torrc_file.write_text(torrc + "\n", encoding="utf-8")

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        log(f"launching private tor: {tor_bin}", quiet=self.quiet)
        self._log_handle = open(log_file, "wb")
        try:
            self._proc = subprocess.Popen(
                [tor_bin, "-f", "torrc"],
                cwd=str(data_dir),
                stdout=self._log_handle,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
        except Exception:
            self._log_handle.close()
            self._log_handle = None
            raise

        controller = self._await_bootstrap(control, log_file)
        self._finish_attach(controller, socks, control, "launched")

    def _await_bootstrap(self, control_port: int, log_file: Path) -> Controller:
        """Wait until tor's control port is usable and it has bootstrapped."""
        assert self._proc is not None
        deadline = time.monotonic() + self.bootstrap_timeout
        controller: Controller | None = None
        last_phase = ""

        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(
                    f"tor exited during startup (code {self._proc.returncode}): "
                    f"{read_log_tail(log_file)}"
                )

            if controller is None:
                candidate = None
                try:
                    candidate = Controller.from_port(address="127.0.0.1", port=control_port)
                    self._authenticate(candidate)
                    controller = candidate
                except Exception:
                    if candidate is not None:
                        candidate.close()
                    time.sleep(0.5)
                    continue

            try:
                phase = controller.get_info("status/bootstrap-phase", None) or ""
            except Exception:
                phase = ""

            if self.verbose and phase and phase != last_phase:
                print(f"  {phase}", file=sys.stderr, flush=True)
                last_phase = phase

            if "PROGRESS=100" in phase:
                return controller

            time.sleep(0.5)

        if controller is not None:
            controller.close()
        raise RuntimeError(
            f"tor did not finish bootstrapping within {self.bootstrap_timeout:.0f}s "
            f"(network may block Tor): {read_log_tail(log_file)}"
        )

    def _authenticate(self, controller: Controller) -> None:
        if self.cookie_path:
            authenticate_cookie(controller, cookie_path=self.cookie_path)
        elif self.control_password:
            controller.authenticate(password=self.control_password)
        else:
            # stem discovers the cookie path from the PROTOCOLINFO response.
            controller.authenticate()

    def _finish_attach(
        self, controller: Controller, socks_port: int, control_port: int, mode: str
    ) -> None:
        self._controller = controller
        self.socks_port = socks_port
        self.control_port = control_port
        self.mode = mode

    # -- requests ----------------------------------------------------------- #

    @property
    def proxy_url(self) -> str:
        # socks5h = let Tor resolve DNS (important for privacy and .onion).
        return f"socks5h://127.0.0.1:{self.socks_port}"

    @property
    def tor_pid(self) -> int | None:
        """PID of the Tor process this instance launched, if any."""
        return self._proc.pid if self._proc is not None else None

    @property
    def session(self) -> requests.Session:
        """A requests session whose traffic goes through Tor."""
        if self._session is None:
            session = requests.Session()
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
            session.headers["User-Agent"] = USER_AGENT
            self._session = session
        return self._session

    # -- IP checks ---------------------------------------------------------- #

    def check_ip(self) -> tuple[str, bool | None]:
        """Return (exit ip, is_tor) as seen through the Tor circuit."""
        errors: list[str] = []
        for url in self.check_urls:
            try:
                # A fresh connection is required: keep-alive would reuse the old
                # circuit and report the previous exit IP after NEWNYM.
                response = self.session.get(
                    url, timeout=self.timeout, headers={"Connection": "close"}
                )
                response.raise_for_status()
                ip, is_tor = parse_ip_response(response)
                if ip:
                    return ip, is_tor
                errors.append(f"{url}: empty response")
            except requests.RequestException as exc:
                errors.append(f"{url}: {exc}")
        raise RuntimeError("could not determine IP through Tor - " + "; ".join(errors))

    # -- rotation ----------------------------------------------------------- #

    def _request_newnym(self) -> None:
        if self._controller is None:
            raise RuntimeError("Tor controller is not connected")

        try:
            wait = float(self._controller.get_newnym_wait())
        except Exception:
            wait = max(0.0, MIN_NEWNYM_WAIT - (time.monotonic() - self._last_newnym))
        if wait > 0:
            time.sleep(wait)

        self._controller.signal(Signal.NEWNYM)
        self._last_newnym = time.monotonic()

    def rotate(self, attempts: int | None = None, settle: float | None = None) -> Rotation:
        """Ask Tor for a new circuit and wait until the exit IP differs."""
        attempts = self.attempts if attempts is None else attempts
        settle = self.settle if settle is None else settle

        old_ip, _ = self.check_ip()
        new_ip, is_tor = old_ip, None

        for attempt in range(1, max(1, attempts) + 1):
            self._request_newnym()
            time.sleep(settle)
            new_ip, is_tor = self.check_ip()
            if new_ip != old_ip:
                return Rotation(old_ip, new_ip, is_tor, attempt)

        return Rotation(old_ip, new_ip, is_tor, attempts)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rotate your public IP address using Tor.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="number of rotations to perform (0 = just print the current IP)",
    )
    parser.add_argument(
        "--loop",
        type=float,
        metavar="SECONDS",
        help="rotate forever, waiting SECONDS between rotations (0 = as fast as Tor allows)",
    )
    parser.add_argument(
        "--settle",
        type=float,
        default=3.0,
        help="seconds to wait after NEWNYM before checking the new IP",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=4,
        help="NEWNYM attempts per rotation until the IP changes",
    )
    parser.add_argument("--socks-port", type=int, help="Tor SOCKS port")
    parser.add_argument("--control-port", type=int, help="Tor control port")
    parser.add_argument("--control-password", help="Tor control password, if any")
    parser.add_argument("--cookie-path", help="path to the control auth cookie")
    parser.add_argument("--tor-bin", help="path to the tor executable")
    parser.add_argument("--data-dir", help="data directory for a launched Tor instance")
    parser.add_argument(
        "--launch",
        action="store_true",
        help="always launch a private Tor instance instead of attaching",
    )
    parser.add_argument(
        "--no-launch",
        action="store_true",
        help="never launch Tor; fail if no running instance is found",
    )
    parser.add_argument("--check-url", help="custom IP check URL (replaces the default first one)")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds")
    parser.add_argument(
        "--bootstrap-timeout",
        type=float,
        default=300.0,
        help="seconds to wait for a launched Tor instance to bootstrap",
    )
    parser.add_argument("--json", action="store_true", help="print JSON lines on stdout")
    parser.add_argument(
        "--show-direct",
        action="store_true",
        help="also print your real (non-Tor) IP before starting",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress log lines on stderr")
    parser.add_argument("--verbose", action="store_true", help="print Tor bootstrap output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.launch and args.no_launch:
        print("error: --launch and --no-launch are mutually exclusive", file=sys.stderr)
        return 2

    check_urls = DEFAULT_CHECK_URLS
    if args.check_url:
        check_urls = (args.check_url,) + DEFAULT_CHECK_URLS

    swapper = TorIPSwapper(
        socks_port=args.socks_port,
        control_port=args.control_port,
        control_password=args.control_password,
        cookie_path=args.cookie_path,
        tor_bin=args.tor_bin,
        data_dir=args.data_dir,
        launch=True if args.launch else (False if args.no_launch else None),
        check_urls=check_urls,
        timeout=args.timeout,
        settle=args.settle,
        attempts=args.attempts,
        bootstrap_timeout=args.bootstrap_timeout,
        quiet=args.quiet,
        verbose=args.verbose,
    )

    try:
        swapper.start()
    except Exception as exc:
        swapper.close()
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        if args.show_direct:
            real = direct_ip(timeout=args.timeout)
            if real:
                log(f"direct (non-Tor) IP: {real}", quiet=args.quiet)
            else:
                log("could not determine the direct IP", quiet=args.quiet)

        log(
            f"tor ready via {swapper.proxy_url} "
            f"(control port {swapper.control_port}, {swapper.mode})",
            quiet=args.quiet,
        )

        current_ip, is_tor = swapper.check_ip()
        log(
            f"current exit IP: {current_ip}" + (" (Tor)" if is_tor else ""),
            quiet=args.quiet,
        )

        if args.count == 0 and args.loop is None:
            if args.json:
                print(json.dumps({"ip": current_ip, "is_tor": is_tor}), flush=True)
            return 0

        infinite = args.loop is not None
        rotations = 0
        unchanged = 0

        while infinite or rotations < args.count:
            rotations += 1
            started = time.monotonic()
            try:
                rotation = swapper.rotate()
            except RuntimeError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            elapsed = time.monotonic() - started

            if rotation.changed:
                message = (
                    f"IP changed: {rotation.old_ip} -> {rotation.new_ip} "
                    f"(attempt {rotation.attempts}, {elapsed:.1f}s)"
                )
            else:
                unchanged += 1
                message = (
                    f"IP unchanged: {rotation.new_ip} after {rotation.attempts} attempt(s) "
                    f"- Tor's exit pool is limited, try again later"
                )

            if args.json:
                print(
                    json.dumps(
                        {
                            "time": datetime.now().isoformat(timespec="seconds"),
                            "old_ip": rotation.old_ip,
                            "new_ip": rotation.new_ip,
                            "changed": rotation.changed,
                            "is_tor": rotation.is_tor,
                            "attempts": rotation.attempts,
                            "elapsed": round(elapsed, 2),
                        }
                    ),
                    flush=True,
                )
            else:
                log(message, quiet=args.quiet)

            if infinite:
                if args.loop and args.loop > 0:
                    time.sleep(args.loop)
            elif rotations >= args.count:
                break

        return 0 if unchanged == 0 else 2

    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        swapper.close()


if __name__ == "__main__":
    sys.exit(main())
