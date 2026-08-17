"""
fingerprinter.py
-----------------
Connects to open TCP ports found by masscan and collects lightweight,
passive/semi-active identification data:

  * Raw banners for text-based protocols (SSH, FTP, SMTP, Telnet, POP3...)
  * HTTP response headers + <title> for web-ish ports
  * TCP TTL (already provided by masscan, used as a coarse OS hint)

No exploitation, brute-forcing, or authentication bypass is performed --
only what a normal client (browser, ssh client, etc.) would see on connect.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .signatures import PORT_SERVICE_MAP

HTTP_LIKE_PORTS = {80, 81, 443, 5000, 8080, 8081, 8443, 32400, 10000}
TLS_PORTS = {443, 8443, 8291}

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SERVER_HEADER_RE = re.compile(rb"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


@dataclass
class HostFingerprint:
    ip: str
    ttl_by_port: dict[int, int] = field(default_factory=dict)
    banners: dict[int, str] = field(default_factory=dict)   # lowercased text, for matching
    raw_banners: dict[int, str] = field(default_factory=dict)  # original case, for display
    http_titles: dict[int, str] = field(default_factory=dict)
    http_servers: dict[int, str] = field(default_factory=dict)


def _grab_generic_banner(ip: str, port: int, timeout: float) -> str | None:
    """Open a TCP connection and read whatever the service sends first."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(1024)
            except socket.timeout:
                data = b""
            return data.decode(errors="ignore").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _grab_http(ip: str, port: int, timeout: float, use_tls: bool) -> tuple[str | None, str | None, str | None]:
    """
    Send a minimal HTTP/1.1 GET and return (raw_response_text, server_header, title).
    """
    try:
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw_sock = socket.create_connection((ip, port), timeout=timeout)
            sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
        else:
            sock = socket.create_connection((ip, port), timeout=timeout)

        with sock:
            sock.settimeout(timeout)
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: netscan-fingerprinter/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            sock.sendall(req)

            chunks = []
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if sum(len(c) for c in chunks) > 65536:
                        break
            except socket.timeout:
                pass

            data = b"".join(chunks)
            if not data:
                return None, None, None

            server_match = SERVER_HEADER_RE.search(data)
            server = server_match.group(1).decode(errors="ignore").strip() if server_match else None

            title_match = TITLE_RE.search(data)
            title = None
            if title_match:
                title = re.sub(rb"\s+", b" ", title_match.group(1)).decode(errors="ignore").strip()

            return data.decode(errors="ignore"), server, title
    except (socket.timeout, ConnectionRefusedError, OSError, Exception):
        return None, None, None


def fingerprint_host(ip: str, open_ports: list[int], ttl_map: dict[int, int] | None = None,
                      timeout: float = 2.5) -> HostFingerprint:
    """Fingerprint a single host across all of its open ports (sequential)."""
    fp = HostFingerprint(ip=ip, ttl_by_port=dict(ttl_map or {}))

    for port in open_ports:
        if port in HTTP_LIKE_PORTS:
            raw, server, title = _grab_http(ip, port, timeout, use_tls=port in TLS_PORTS)
            if raw:
                fp.raw_banners[port] = raw[:500]
                fp.banners[port] = raw[:500].lower()
            if server:
                fp.http_servers[port] = server
                fp.banners[port] = fp.banners.get(port, "") + " " + server.lower()
            if title:
                fp.http_titles[port] = title
        else:
            banner = _grab_generic_banner(ip, port, timeout)
            if banner:
                fp.raw_banners[port] = banner[:500]
                fp.banners[port] = banner[:500].lower()

    return fp


def fingerprint_hosts(
    host_ports: dict[str, list[int]],
    ttl_maps: dict[str, dict[int, int]] | None = None,
    timeout: float = 2.5,
    max_workers: int = 50,
) -> dict[str, HostFingerprint]:
    """
    Fingerprint many hosts concurrently. `host_ports` maps ip -> list of open ports
    (as discovered by masscan). Returns ip -> HostFingerprint.
    """
    ttl_maps = ttl_maps or {}
    results: dict[str, HostFingerprint] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                fingerprint_host, ip, ports, ttl_maps.get(ip, {}), timeout
            ): ip
            for ip, ports in host_ports.items()
        }
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                results[ip] = fut.result()
            except Exception:
                results[ip] = HostFingerprint(ip=ip)

    return results


def service_name(port: int) -> str:
    return PORT_SERVICE_MAP.get(port, "unknown")
