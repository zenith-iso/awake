"""
config_store.py
-----------------
Scan configuration model + on-disk persistence for the curses TUI.

Everything the old CLI required you to pass as flags (or hand-edit) --
target range, ports, rate, timeout, workers, interface, output path --
lives in `ScanConfig` and is saved/loaded as named "profiles" plus a
"last used" state file, all driven from the TUI. No manual file/text
editing required.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .signatures import DEFAULT_TOP_PORTS

CONFIG_DIR = Path(
    os.environ.get("NETSCAN_CONFIG_DIR", str(Path.home() / ".config" / "netscan"))
)
PROFILES_PATH = CONFIG_DIR / "profiles.json"
STATE_PATH = CONFIG_DIR / "state.json"  # last-used config + recent targets


@dataclass
class ScanConfig:
    target: str = ""
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_TOP_PORTS))
    rate: int = 1000
    timeout: float = 2.5
    workers: int = 50
    interface: str = ""
    json_output: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "ScanConfig":
        cfg = ScanConfig()
        cfg.target = d.get("target", "")
        cfg.ports = list(d.get("ports", DEFAULT_TOP_PORTS))
        cfg.rate = int(d.get("rate", 1000))
        cfg.timeout = float(d.get("timeout", 2.5))
        cfg.workers = int(d.get("workers", 50))
        cfg.interface = d.get("interface", "")
        cfg.json_output = d.get("json_output", "")
        return cfg

    def clone(self) -> "ScanConfig":
        return ScanConfig.from_dict(self.to_dict())

    def summary(self) -> str:
        port_str = f"{len(self.ports)} ports" if self.ports else "NO PORTS SET"
        return (
            f"target: {self.target or '(not set)'}   {port_str}   "
            f"rate={self.rate}   timeout={self.timeout}s   workers={self.workers}"
            + (f"   iface={self.interface}" if self.interface else "")
        )


def _ensure_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_profiles() -> dict[str, ScanConfig]:
    if not PROFILES_PATH.exists():
        return {}
    try:
        raw = json.loads(PROFILES_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return {name: ScanConfig.from_dict(d) for name, d in raw.items()}


def save_profiles(profiles: dict[str, ScanConfig]):
    _ensure_dir()
    raw = {name: cfg.to_dict() for name, cfg in profiles.items()}
    PROFILES_PATH.write_text(json.dumps(raw, indent=2))


def load_state() -> dict:
    if not STATE_PATH.exists():
        return {"last_config": None, "recent_targets": []}
    try:
        return json.loads(STATE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {"last_config": None, "recent_targets": []}


def save_state(config: ScanConfig, recent_targets: list[str]):
    _ensure_dir()
    state = {
        "last_config": config.to_dict(),
        "recent_targets": recent_targets[-10:],
    }
    STATE_PATH.write_text(json.dumps(state, indent=2))


def parse_port_spec(spec: str) -> list[int]:
    """
    Parse a user-entered port spec like "22,80,443,8000-8010" into a sorted
    list of unique ints. Raises ValueError with a human-readable message on
    malformed input, so the TUI can show it directly.
    """
    ports: set[int] = set()
    spec = spec.strip()
    if not spec:
        return []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            parts = chunk.split("-", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError(f"'{chunk}' is not a valid port range")
            if lo > hi:
                lo, hi = hi, lo
            if hi - lo > 5000:
                raise ValueError(f"Range '{chunk}' is too large (>5000 ports)")
            ports.update(range(lo, hi + 1))
        else:
            try:
                ports.add(int(chunk))
            except ValueError:
                raise ValueError(f"'{chunk}' is not a valid port number")
    for p in ports:
        if not (0 < p < 65536):
            raise ValueError(f"Port {p} is out of range (1-65535)")
    return sorted(ports)
