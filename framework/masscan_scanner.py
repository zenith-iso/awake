"""
masscan_scanner.py
-------------------
Thin, safe wrapper around the `masscan` CLI.

Responsibilities:
  * Build a correct masscan command line (ports, rate, target, JSON output).
  * Run it as a subprocess and stream/collect results.
  * Parse masscan's JSON output into simple Python structures.

This module does NOT interpret results (see device_classifier.py) and does
NOT decide scan scope -- that's the caller's responsibility. Always ensure
you have explicit authorization to scan the target range.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Iterable


class MasscanNotFoundError(RuntimeError):
    pass


class MasscanExecutionError(RuntimeError):
    pass


@dataclass
class OpenPort:
    ip: str
    port: int
    proto: str = "tcp"
    ttl: int | None = None
    timestamp: str | None = None


@dataclass
class ScanResult:
    open_ports: list[OpenPort] = field(default_factory=list)

    def hosts(self) -> list[str]:
        """Unique list of IPs that had at least one open port."""
        seen = []
        for op in self.open_ports:
            if op.ip not in seen:
                seen.append(op.ip)
        return seen

    def ports_for_host(self, ip: str) -> list[OpenPort]:
        return [op for op in self.open_ports if op.ip == ip]


class MasscanScanner:
    """
    Wraps `masscan` for scanning an IP range / CIDR for open ports.

    Example:
        scanner = MasscanScanner(rate=1000)
        result = scanner.scan("192.168.1.0/24", ports=[22, 80, 443])
        for ip in result.hosts():
            print(ip, result.ports_for_host(ip))
    """

    def __init__(
        self,
        rate: int = 1000,
        masscan_path: str | None = None,
        extra_args: list[str] | None = None,
        interface: str | None = None,
    ):
        self.masscan_path = masscan_path or shutil.which("masscan")
        if not self.masscan_path:
            raise MasscanNotFoundError(
                "masscan executable not found on PATH. Install it first, e.g.\n"
                "  Debian/Ubuntu: sudo apt-get install masscan\n"
                "  macOS (brew):  brew install masscan"
            )
        self.rate = rate
        self.extra_args = extra_args or []
        self.interface = interface

    def scan(
        self,
        target: str,
        ports: Iterable[int],
        timeout: int | None = None,
        cancel_event: "threading.Event | None" = None,
    ) -> ScanResult:
        """
        Run masscan against `target` (CIDR, range, or comma-separated list)
        for the given `ports`. Requires root/CAP_NET_RAW privileges, as
        masscan uses raw sockets.

        If `cancel_event` is provided, it is polled while masscan runs;
        setting it (from another thread) terminates the masscan process
        early and returns whatever partial results were already written
        to its output file.
        """
        port_spec = ",".join(str(p) for p in ports)

        with tempfile.NamedTemporaryFile(
            prefix="masscan_", suffix=".json", delete=False
        ) as tmp:
            out_path = tmp.name

        cmd = [
            self.masscan_path,
            target,
            "-p", port_spec,
            "--rate", str(self.rate),
            "-oJ", out_path,
        ]
        if self.interface:
            cmd += ["-e", self.interface]
        cmd += self.extra_args

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except PermissionError as e:
            raise MasscanExecutionError(
                "Permission denied running masscan. It typically needs to be "
                "run as root (or with CAP_NET_RAW/CAP_NET_ADMIN)."
            ) from e

        start = time.monotonic()
        stdout, stderr = "", ""
        cancelled = False
        while True:
            try:
                stdout, stderr = proc.communicate(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    proc.terminate()
                    try:
                        proc.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.communicate()
                    break
                if timeout is not None and (time.monotonic() - start) > timeout:
                    proc.kill()
                    proc.communicate()
                    raise MasscanExecutionError(f"masscan timed out after {timeout}s")

        if not cancelled and proc.returncode not in (0, None):
            raise MasscanExecutionError(
                f"masscan exited with code {proc.returncode}.\n"
                f"stdout: {stdout}\nstderr: {stderr}"
            )

        result = self._parse_json_output(out_path)
        try:
            os.remove(out_path)
        except OSError:
            pass
        return result

    @staticmethod
    def _parse_json_output(path: str) -> ScanResult:
        result = ScanResult()
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return result

        with open(path, "r") as f:
            raw = f.read().strip()

        # masscan's -oJ output is a JSON array, but can be left with a
        # trailing comma / missing closing bracket if interrupted.
        if not raw:
            return result
        if not raw.endswith("]"):
            raw = raw.rstrip(",\n") + "\n]"
        if not raw.startswith("["):
            raw = "[" + raw.lstrip("[")

        try:
            records = json.loads(raw)
        except json.JSONDecodeError:
            # Fall back to line-by-line best-effort parse.
            records = []
            for line in raw.splitlines():
                line = line.strip().strip(",")
                if line.startswith("{"):
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for rec in records:
            ip = rec.get("ip")
            ts = rec.get("timestamp")
            for p in rec.get("ports", []):
                result.open_ports.append(
                    OpenPort(
                        ip=ip,
                        port=p.get("port"),
                        proto=p.get("proto", "tcp"),
                        ttl=p.get("ttl"),
                        timestamp=ts,
                    )
                )
        return result
