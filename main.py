#!/usr/bin/env python3
"""
main.py
-------
CLI entry point for the scan -> fingerprint -> classify pipeline.

USAGE
    sudo python3 main.py 192.168.1.0/24
    sudo python3 main.py 10.0.0.1-10.0.0.254 --ports 22,80,443,8080 --rate 2000
    sudo python3 main.py 192.168.1.0/24 --json report.json

IMPORTANT
    * masscan requires raw-socket privileges -> run as root / with sudo,
      or grant the binary CAP_NET_RAW/CAP_NET_ADMIN.
    * Only scan networks/ranges you own or are explicitly authorized to test.
      Unauthorized port scanning may violate the law (e.g. CFAA in the US)
      and/or your ISP's / employer's acceptable use policy.
"""

import argparse
import json
import sys
from collections import defaultdict

from netscan import (
    MasscanScanner,
    MasscanNotFoundError,
    MasscanExecutionError,
    fingerprint_hosts,
    classify_host,
    PORT_SERVICE_MAP,
    DEFAULT_TOP_PORTS,
)


def parse_args():
    p = argparse.ArgumentParser(
        description="Scan an IP range with masscan, then fingerprint and "
                    "classify discovered devices."
    )
    p.add_argument("target", help="CIDR, IP range, or comma-separated IPs (e.g. 192.168.1.0/24)")
    p.add_argument(
        "--ports", default=None,
        help="Comma-separated ports to scan. Defaults to a curated list of "
             "high-signal ports (see signatures.py:DEFAULT_TOP_PORTS)."
    )
    p.add_argument("--rate", type=int, default=1000, help="masscan packets/sec rate (default: 1000)")
    p.add_argument("--timeout", type=float, default=2.5, help="Per-port banner-grab timeout in seconds")
    p.add_argument("--workers", type=int, default=50, help="Concurrent fingerprinting threads")
    p.add_argument("--interface", default=None, help="Network interface for masscan to use")
    p.add_argument("--json", default=None, help="Write full JSON report to this path")
    p.add_argument("--masscan-timeout", type=int, default=None, help="Overall timeout for the masscan process (seconds)")
    return p.parse_args()


def build_host_port_maps(scan_result):
    host_ports = defaultdict(list)
    ttl_maps = defaultdict(dict)
    for op in scan_result.open_ports:
        host_ports[op.ip].append(op.port)
        if op.ttl:
            ttl_maps[op.ip][op.port] = op.ttl
    return dict(host_ports), dict(ttl_maps)


def print_report(reports):
    for r in sorted(reports, key=lambda x: x.ip):
        print(f"\n=== {r.ip} ===")
        port_list = ", ".join(f"{p}/{r.services.get(p,'?')}" for p in r.open_ports)
        print(f"  Open ports : {port_list}")
        if r.os_guess:
            print(f"  OS guess   : {r.os_guess}")
        if r.top_classification:
            c = r.top_classification
            vendor = f" ({c.vendor})" if c.vendor else ""
            print(f"  Device     : {c.device_type}{vendor}  [confidence {c.confidence:.2f}]")
            print(f"               via {c.matched_on}")
        else:
            print("  Device     : Unclassified")
        if r.http_titles:
            for port, title in r.http_titles.items():
                print(f"  HTTP title (port {port}): {title[:80]}")
        if len(r.candidates) > 1:
            others = ", ".join(f"{c.device_type} ({c.confidence:.2f})" for c in r.candidates[1:4])
            print(f"  Other candidates: {others}")


def main():
    args = parse_args()

    ports = (
        [int(p) for p in args.ports.split(",")]
        if args.ports
        else DEFAULT_TOP_PORTS
    )

    print(f"[*] Scanning {args.target} on {len(ports)} ports (rate={args.rate}) ...")
    try:
        scanner = MasscanScanner(rate=args.rate, interface=args.interface)
        scan_result = scanner.scan(args.target, ports, timeout=args.masscan_timeout)
    except MasscanNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)
    except MasscanExecutionError as e:
        print(f"[!] masscan failed: {e}", file=sys.stderr)
        sys.exit(1)

    hosts = scan_result.hosts()
    print(f"[*] masscan found {len(hosts)} host(s) with open ports, "
          f"{len(scan_result.open_ports)} open port(s) total.")

    if not hosts:
        print("[*] Nothing to fingerprint. Done.")
        return

    host_ports, ttl_maps = build_host_port_maps(scan_result)

    print(f"[*] Fingerprinting {len(hosts)} host(s) with up to {args.workers} concurrent workers ...")
    fingerprints = fingerprint_hosts(
        host_ports, ttl_maps, timeout=args.timeout, max_workers=args.workers
    )

    reports = []
    for ip, fp in fingerprints.items():
        report = classify_host(ip, host_ports[ip], fp, PORT_SERVICE_MAP)
        reports.append(report)

    print_report(reports)

    if args.json:
        serializable = []
        for r in reports:
            serializable.append({
                "ip": r.ip,
                "open_ports": r.open_ports,
                "services": r.services,
                "os_guess": r.os_guess,
                "device_type": r.top_classification.device_type if r.top_classification else None,
                "vendor": r.top_classification.vendor if r.top_classification else None,
                "confidence": r.top_classification.confidence if r.top_classification else None,
                "matched_on": r.top_classification.matched_on if r.top_classification else None,
                "candidates": [
                    {"device_type": c.device_type, "vendor": c.vendor, "confidence": c.confidence}
                    for c in r.candidates
                ],
                "http_titles": r.http_titles,
                "http_servers": r.http_servers,
            })
        with open(args.json, "w") as f:
            json.dump(serializable, f, indent=2)
        print(f"\n[*] Full JSON report written to {args.json}")


if __name__ == "__main__":
    main()
