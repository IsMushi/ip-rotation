#!/usr/bin/env python3
"""Minimal HTTP proxy that forwards everything through Tor's SOCKS5 port.

Some programs only understand HTTP proxies (Windows Internet Options,
Invoke-WebRequest, older apps). This bridge accepts normal HTTP proxy requests
and tunnels them through Tor.

    python http_bridge.py --listen-port 8080 --socks-port 9050

Then point the client at http://127.0.0.1:8080.

tor_proxy.py starts this automatically on port 8080 (disable with --no-http).
"""

from __future__ import annotations

import argparse
import select
import socket
import socketserver
import sys
from urllib.parse import urlsplit

import socks

MAX_HEADER_BYTES = 65536
CONNECT_TIMEOUT = 30.0
IDLE_TIMEOUT = 300.0


class _ProxyHandler(socketserver.StreamRequestHandler):
    # Unbuffered: after the headers are read, the raw socket relay must see
    # every remaining byte (request body, TLS handshake, ...).
    rbufsize = 0

    def handle(self) -> None:
        upstream: socket.socket | None = None
        try:
            self.connection.settimeout(CONNECT_TIMEOUT)

            request_line = self.rfile.readline(MAX_HEADER_BYTES)
            if not request_line:
                return
            try:
                method, target, version = request_line.decode("latin-1").split()
            except ValueError:
                self._send_error(400, "Bad Request")
                return

            headers = self._read_headers()
            if headers is None:
                self._send_error(431, "Request Header Fields Too Large")
                return

            if method.upper() == "CONNECT":
                upstream = self._connect_target(target, default_port=443)
                if upstream is None:
                    self._send_error(502, "Bad Gateway")
                    return
                self.connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if self.server.verbose:
                    print(f"CONNECT {target}", file=sys.stderr, flush=True)
                _relay(self.connection, upstream)
                return

            upstream = self._connect_absolute(target)
            if upstream is None:
                self._send_error(502, "Bad Gateway")
                return
            if self.server.verbose:
                print(f"{method} {target}", file=sys.stderr, flush=True)
            upstream.sendall(self._rewrite_request(method, target, version, headers))
            _relay(self.connection, upstream)

        except (OSError, ValueError):
            return
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass

    # -- request helpers ---------------------------------------------------- #

    def _read_headers(self) -> list[bytes] | None:
        headers: list[bytes] = []
        total = 0
        while True:
            line = self.rfile.readline(MAX_HEADER_BYTES)
            if not line or line in (b"\r\n", b"\n"):
                break
            total += len(line)
            if total > MAX_HEADER_BYTES:
                return None
            headers.append(line)
        return headers

    def _connect_target(self, target: str, default_port: int) -> socket.socket | None:
        host, sep, port_text = target.rpartition(":")
        if sep and port_text.isdigit():
            host, port = host, int(port_text)
        else:
            host, port = target, default_port
        return self._socks_connect(host.strip("[]"), port)

    def _connect_absolute(self, target: str) -> socket.socket | None:
        parts = urlsplit(target)
        if parts.scheme.lower() != "http" or not parts.hostname:
            return None
        return self._socks_connect(parts.hostname, parts.port or 80)

    def _socks_connect(self, host: str, port: int) -> socket.socket | None:
        try:
            return socks.create_connection(
                (host, port),
                timeout=CONNECT_TIMEOUT,
                proxy_type=socks.SOCKS5,
                proxy_addr=self.server.socks_host,
                proxy_port=self.server.socks_port,
                proxy_rdns=True,
            )
        except (socks.ProxyError, OSError):
            return None

    def _rewrite_request(
        self, method: str, target: str, version: str, headers: list[bytes]
    ) -> bytes:
        parts = urlsplit(target)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        lines = [f"{method} {path} {version}\r\n".encode("latin-1")]
        has_host = False
        for header in headers:
            name = header.split(b":", 1)[0].strip().lower()
            if name in (b"proxy-connection", b"connection", b"keep-alive"):
                continue
            if name == b"host":
                has_host = True
            lines.append(header)

        if not has_host:
            host = parts.hostname or ""
            if parts.port and parts.port != 80:
                host = f"{host}:{parts.port}"
            lines.append(f"Host: {host}\r\n".encode("latin-1"))

        lines.append(b"Connection: close\r\n\r\n")
        return b"".join(lines)

    def _send_error(self, code: int, message: str) -> None:
        body = message.encode("latin-1")
        response = (
            f"HTTP/1.1 {code} {message}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            self.connection.sendall(response + body)
        except OSError:
            pass


def _relay(left: socket.socket, right: socket.socket) -> None:
    """Copy bytes both ways until one side closes."""
    peers = [left, right]
    try:
        while True:
            readable, _, errored = select.select(peers, [], peers, IDLE_TIMEOUT)
            if errored or not readable:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                destination = right if source is left else left
                destination.sendall(data)
    except OSError:
        return


class _ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def create_server(
    listen_host: str,
    listen_port: int,
    socks_host: str,
    socks_port: int,
    *,
    verbose: bool = False,
) -> _ThreadingServer:
    server = _ThreadingServer((listen_host, listen_port), _ProxyHandler)
    server.socks_host = socks_host
    server.socks_port = socks_port
    server.verbose = verbose
    return server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HTTP proxy that forwards through Tor's SOCKS5 port.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8080)
    parser.add_argument("--socks-host", default="127.0.0.1")
    parser.add_argument("--socks-port", type=int, default=9050)
    parser.add_argument("--verbose", action="store_true", help="log every request")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        with socket.create_connection(
            (args.socks_host, args.socks_port), timeout=2
        ):
            pass
    except OSError:
        print(
            f"error: no SOCKS proxy on {args.socks_host}:{args.socks_port} "
            "- start tor_proxy.py first",
            file=sys.stderr,
        )
        return 1

    server = create_server(
        args.listen_host,
        args.listen_port,
        args.socks_host,
        args.socks_port,
        verbose=args.verbose,
    )
    print(
        f"HTTP proxy http://{args.listen_host}:{args.listen_port} -> "
        f"socks5h://{args.socks_host}:{args.socks_port}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
