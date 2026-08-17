"""
device_classifier.py
---------------------
Turns (open_ports, banners) for a host into a ranked list of candidate
device types using the rule set in signatures.py, plus a coarse OS guess
derived from TTL.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .signatures import DEVICE_RULES
from .fingerprinter import HostFingerprint


@dataclass
class Classification:
    device_type: str
    vendor: str | None
    confidence: float
    matched_on: str  # human-readable reason


@dataclass
class HostReport:
    ip: str
    open_ports: list[int]
    services: dict[int, str]
    os_guess: str | None
    top_classification: Classification | None
    candidates: list[Classification] = field(default_factory=list)
    http_titles: dict[int, str] = field(default_factory=dict)
    http_servers: dict[int, str] = field(default_factory=dict)


def guess_os_from_ttl(ttl_values: list[int]) -> str | None:
    """
    Very coarse OS family guess from initial TTL. Real stacks decrement TTL
    per hop, so we bucket toward the nearest common starting value
    (64 = Linux/Unix/macOS, 128 = Windows, 255 = network gear/Solaris/Cisco).
    This is a heuristic, not a reliable OS fingerprint.
    """
    if not ttl_values:
        return None
    ttl = max(ttl_values)  # closest hop wins
    if ttl > 128:
        return "Network device / Unix variant (TTL~255)"
    elif ttl > 64:
        return "Windows (TTL~128)"
    elif ttl > 0:
        return "Linux/Unix/macOS (TTL~64)"
    return None


def classify_host(ip: str, open_ports: list[int], fp: HostFingerprint,
                   service_map: dict[int, str]) -> HostReport:
    banners = fp.banners  # port -> lowercased text
    port_set = set(open_ports)

    candidates: list[Classification] = []

    for rule in DEVICE_RULES:
        require_ports = rule.get("require_ports") or []
        if require_ports and not set(require_ports).issubset(port_set):
            continue

        patterns = rule["_compiled"]
        matched_text = None
        if patterns:
            found = False
            for port, text in banners.items():
                for pat in patterns:
                    if pat.search(text):
                        found = True
                        matched_text = f"banner on port {port} matched /{pat.pattern}/"
                        break
                if found:
                    break
            if not found:
                continue
        else:
            if require_ports:
                matched_text = f"required ports open: {require_ports}"
            else:
                continue  # rule has neither ports nor patterns -> unusable alone

        candidates.append(
            Classification(
                device_type=rule["device_type"],
                vendor=rule["vendor"],
                confidence=rule["confidence"],
                matched_on=matched_text,
            )
        )

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    top = candidates[0] if candidates else None

    ttl_values = [v for v in fp.ttl_by_port.values() if v]
    os_guess = guess_os_from_ttl(ttl_values)

    return HostReport(
        ip=ip,
        open_ports=sorted(open_ports),
        services={p: service_map.get(p, "unknown") for p in open_ports},
        os_guess=os_guess,
        top_classification=top,
        candidates=candidates,
        http_titles=fp.http_titles,
        http_servers=fp.http_servers,
    )
