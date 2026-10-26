from __future__ import annotations

import select
import socket
import threading
import time
from http.client import HTTPConnection
from socketserver import ThreadingMixIn, TCPServer, BaseRequestHandler
from urllib.parse import urlsplit

from . import util

class TokenBucket:

    def __init__(self, rate: float) -> None:
        self.rate = float(rate)
        self.capacity = float(rate)
        self.tokens = float(rate)
        self.timestamp = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.timestamp
                self.timestamp = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                deficit = 1.0 - self.tokens
                wait = deficit / self.rate
            time.sleep(min(wait, 0.25))

class RateLimiter:

    def __init__(self, rate: float) -> None:
        self.rate = rate
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def acquire(self, host: str) -> None:
        with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                bucket = TokenBucket(self.rate)
                self._buckets[host] = bucket
        bucket.acquire()

class _ThreadingTCPServer(ThreadingMixIn, TCPServer):
    daemon_threads = True
    allow_reuse_address = True

class _ProxyHandler(BaseRequestHandler):
    limiter: RateLimiter

    def handle(self) -> None:
        try:
            self._handle()
        except (ConnectionError, OSError):
            pass
        except Exception as exc:
            util.log(f"proxy handler error: {exc}", level="dim")

    def _handle(self) -> None:
        conn = self.request
        conn.settimeout(30)
        request_line = self._read_line(conn)
        if not request_line:
            return
        parts = request_line.split(" ")
        if len(parts) != 3:
            return
        method, target, version = parts

        headers_raw = self._read_headers(conn)

        if method.upper() == "CONNECT":
            self._do_connect(conn, target)
            return
        self._do_http(conn, method, target, headers_raw)

    def _do_connect(self, conn: socket.socket, target: str) -> None:
        host, _, port_s = target.partition(":")
        port = int(port_s or 443)
        self.limiter.acquire(host)
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._tunnel(conn, upstream)

    @staticmethod
    def _tunnel(a: socket.socket, b: socket.socket) -> None:
        sockets = [a, b]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, 30)
                if errored or not readable:
                    break
                for s in readable:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    def _do_http(self, conn: socket.socket, method: str, target: str,
                 headers_raw: list[str]) -> None:
        split = urlsplit(target)
        host = split.hostname or ""
        port = split.port or 80
        path = split.path or "/"
        if split.query:
            path += "?" + split.query
        if not host:
            host = self._header_value(headers_raw, "host")
            if ":" in host:
                host, _, p = host.partition(":")
                port = int(p or 80)
            path = target

        if not host:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        self.limiter.acquire(host)

        body = self._maybe_read_body(conn, headers_raw)
        header_map: dict[str, str] = {}
        for line in headers_raw:
            name, _, value = line.partition(":")
            name = name.strip()
            value = value.strip()
            if name.lower() in ("proxy-connection", "connection", "keep-alive"):
                continue
            header_map[name] = value
        header_map["Connection"] = "close"
        header_map.setdefault("Host", f"{host}:{port}" if port != 80 else host)

        try:
            upstream = HTTPConnection(host, port, timeout=15)
            upstream.request(method, path, body=body, headers=header_map)
            resp = upstream.getresponse()
            payload = resp.read()
        except OSError:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        head = [f"HTTP/1.1 {resp.status} {resp.reason}".encode()]
        for name, value in resp.getheaders():
            if name.lower() in ("transfer-encoding", "connection",
                                "keep-alive", "content-length"):
                continue
            head.append(f"{name}: {value}".encode())
        head.append(f"Content-Length: {len(payload)}".encode())
        head.append(b"Connection: close")
        try:
            conn.sendall(b"\r\n".join(head) + b"\r\n\r\n" + payload)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except Exception:
                pass

    @staticmethod
    def _read_line(conn: socket.socket) -> str:
        data = bytearray()
        while not data.endswith(b"\r\n"):
            chunk = conn.recv(1)
            if not chunk:
                break
            data += chunk
        return data.decode("latin-1").rstrip("\r\n")

    def _read_headers(self, conn: socket.socket) -> list[str]:
        headers = []
        while True:
            line = self._read_line(conn)
            if line == "":
                break
            headers.append(line)
        return headers

    @staticmethod
    def _header_value(headers: list[str], name: str) -> str:
        for line in headers:
            k, _, v = line.partition(":")
            if k.strip().lower() == name.lower():
                return v.strip()
        return ""

    def _maybe_read_body(self, conn: socket.socket, headers: list[str]) -> bytes:
        length = self._header_value(headers, "content-length")
        if not length.isdigit():
            return b""
        remaining = int(length)
        body = bytearray()
        while remaining > 0:
            chunk = conn.recv(min(65536, remaining))
            if not chunk:
                break
            body += chunk
            remaining -= len(chunk)
        return bytes(body)

class ThrottleProxy:

    def __init__(self, host: str, port: int, rate: float) -> None:
        self.host = host
        self.port = port
        self.limiter = RateLimiter(rate)
        self._server: _ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def proxy_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        handler = _ProxyHandler
        server = _ThreadingTCPServer((self.host, self.port), handler)
        server.limiter = self.limiter
        _ProxyHandler.limiter = self.limiter
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        util.log(f"throttling proxy up at {self.proxy_url} "
                 f"({self.limiter.rate:.0f} req/s per host)", level="ok")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
