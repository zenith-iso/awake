#!/usr/bin/env python3
"""
tui.py
------
Curses front-end for awakescan. Configure targets, ports, and scan settings,
save/load named profiles, launch scans, and browse results -- all from
navigable menus. No text files to hand-edit.

USAGE
    sudo python3 tui.py

Keys, in general:
    Up/Down or j/k   move
    Enter             select / confirm
    q or ESC          back / cancel
    Space             toggle (checklists)

IMPORTANT: masscan needs raw-socket privileges, so run this as root (or
grant the masscan binary CAP_NET_RAW/CAP_NET_ADMIN). Only scan ranges you
own or are explicitly authorized to test.
"""

from __future__ import annotations

import curses
import json
import queue
import threading
import time
from collections import defaultdict

from framework.config_store import (
    ScanConfig,
    load_profiles,
    save_profiles,
    load_state,
    save_state,
    parse_port_spec,
)
from framework.tui_widgets import (
    init_colors,
    menu,
    checklist,
    text_input,
    scrollable_text,
    message_box,
    confirm,
    safe_addstr,
    draw_header,
    draw_footer,
)
from framework.masscan_scanner import MasscanScanner, MasscanNotFoundError, MasscanExecutionError
from framework.fingerprinter import fingerprint_hosts
from framework.device_classifier import classify_host
from framework.signatures import PORT_SERVICE_MAP, DEFAULT_TOP_PORTS
from framework.http_universal_bruter import (
    UniversalHTTPBruter,
    brute_hosts_from_scan,
    BruteResult,
)




# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------

def screen_target(stdscr, app: App):
    while True:
        options = ["Enter new target..."]
        for t in reversed(app.recent_targets):
            options.append(f"Recent: {t}")
        options.append("Back")

        choice = menu(
            stdscr, "Set Target Range(s)", options,
            subtitle="Examples: 192.168.1.0/24    10.0.0.1-10.0.0.254    192.168.1.5,192.168.1.10",
        )
        if choice in (-1, len(options) - 1):
            return
        if choice == 0:
            val = text_input(stdscr, "Enter target (CIDR / range / comma list)", app.config.target)
            if val:
                app.config.target = val
                app.add_recent_target(val)
            return
        else:
            app.config.target = list(reversed(app.recent_targets))[choice - 1]
            return


def screen_ports(stdscr, app: App):
    while True:
        options = [
            f"Use default curated list ({len(DEFAULT_TOP_PORTS)} ports)",
            "Toggle common services (checklist)",
            "Enter custom port spec (e.g. 22,80,443,8000-8010)",
            f"View current selection ({len(app.config.ports)} ports)",
            "Back",
        ]
        choice = menu(stdscr, "Configure Ports", options,
                       subtitle=f"Currently: {len(app.config.ports)} port(s) selected")
        if choice in (-1, 4):
            return

        if choice == 0:
            app.config.ports = list(DEFAULT_TOP_PORTS)
            message_box(stdscr, "Ports Updated", [f"Using the default {len(DEFAULT_TOP_PORTS)}-port list."])

        elif choice == 1:
            all_ports_sorted = sorted(PORT_SERVICE_MAP)
            labels = [f"{p:<6} {PORT_SERVICE_MAP[p]}" for p in all_ports_sorted]
            current = {i for i, p in enumerate(all_ports_sorted) if p in app.config.ports}
            result = checklist(stdscr, "Toggle Ports (known services)", labels, current)
            if result is not None:
                app.config.ports = sorted(all_ports_sorted[i] for i in result)

        elif choice == 2:
            current_spec = ",".join(str(p) for p in app.config.ports)
            val = text_input(
                stdscr, "Custom port spec", current_spec,
                help_line="Comma-separated ports and/or ranges, e.g. 22,80,443,8000-8010",
            )
            if val is not None:
                try:
                    app.config.ports = parse_port_spec(val)
                    message_box(stdscr, "Ports Updated", [f"{len(app.config.ports)} port(s) set."])
                except ValueError as e:
                    message_box(stdscr, "Invalid Port Spec", [str(e)])

        elif choice == 3:
            spec = ", ".join(str(p) for p in app.config.ports) or "(none)"
            scrollable_text(stdscr, "Current Port Selection", [spec])


def screen_settings(stdscr, app: App):
    while True:
        options = [
            f"Rate (packets/sec): {app.config.rate}",
            f"Banner-grab timeout (sec): {app.config.timeout}",
            f"Fingerprint worker threads: {app.config.workers}",
            f"Network interface: {app.config.interface or '(auto)'}",
            f"JSON report output path: {app.config.json_output or '(none)'}",
            "Back",
        ]
        choice = menu(stdscr, "Scan Settings", options)
        if choice in (-1, 5):
            return

        if choice == 0:
            val = text_input(stdscr, "Packet rate (packets/sec)", str(app.config.rate))
            if val:
                try:
                    app.config.rate = max(1, int(val))
                except ValueError:
                    message_box(stdscr, "Invalid Value", ["Rate must be a whole number."])
        elif choice == 1:
            val = text_input(stdscr, "Banner-grab timeout, seconds", str(app.config.timeout))
            if val:
                try:
                    app.config.timeout = max(0.1, float(val))
                except ValueError:
                    message_box(stdscr, "Invalid Value", ["Timeout must be a number."])
        elif choice == 2:
            val = text_input(stdscr, "Fingerprint worker threads", str(app.config.workers))
            if val:
                try:
                    app.config.workers = max(1, int(val))
                except ValueError:
                    message_box(stdscr, "Invalid Value", ["Workers must be a whole number."])
        elif choice == 3:
            val = text_input(stdscr, "Network interface (blank = auto)", app.config.interface)
            if val is not None:
                app.config.interface = val
        elif choice == 4:
            val = text_input(stdscr, "JSON report output path (blank = none)", app.config.json_output)
            if val is not None:
                app.config.json_output = val


def screen_save_profile(stdscr, app: App):
    name = text_input(stdscr, "Save current config as profile named:")
    if not name:
        return
    if name in app.profiles and not confirm(stdscr, f"Profile '{name}' exists. Overwrite?"):
        return
    app.profiles[name] = app.config.clone()
    save_profiles(app.profiles)
    message_box(stdscr, "Saved", [f"Profile '{name}' saved."])


def screen_load_profile(stdscr, app: App):
    if not app.profiles:
        message_box(stdscr, "Load Profile", ["No saved profiles yet. Save one first."])
        return
    names = sorted(app.profiles.keys())
    choice = menu(stdscr, "Load Profile", names + ["Back"])
    if choice in (-1, len(names)):
        return
    app.config = app.profiles[names[choice]].clone()
    message_box(stdscr, "Loaded", [f"Profile '{names[choice]}' loaded."])


def screen_delete_profile(stdscr, app: App):
    if not app.profiles:
        message_box(stdscr, "Delete Profile", ["No saved profiles yet."])
        return
    names = sorted(app.profiles.keys())
    choice = menu(stdscr, "Delete Profile", names + ["Back"])
    if choice in (-1, len(names)):
        return
    name = names[choice]
    if confirm(stdscr, f"Delete profile '{name}'? This cannot be undone."):
        del app.profiles[name]
        save_profiles(app.profiles)
        message_box(stdscr, "Deleted", [f"Profile '{name}' deleted."])


def show_host_detail(stdscr, r):
    lines = [f"IP: {r.ip}", ""]
    if r.os_guess:
        lines.append(f"OS guess: {r.os_guess}")
        lines.append("")
    lines.append("Open ports:")
    for p in r.open_ports:
        lines.append(f"  {p}/{r.services.get(p, '?')}")
    lines.append("")
    if r.top_classification:
        c = r.top_classification
        vendor = f" ({c.vendor})" if c.vendor else ""
        lines.append(f"Device type : {c.device_type}{vendor}")
        lines.append(f"Confidence  : {c.confidence:.2f}")
        lines.append(f"Matched on  : {c.matched_on}")
    else:
        lines.append("Device type : Unclassified")
    if len(r.candidates) > 1:
        lines.append("")
        lines.append("Other candidates:")
        for c in r.candidates[1:]:
            lines.append(f"  {c.device_type} ({c.vendor or '-'})  confidence={c.confidence:.2f}")
    if r.http_titles:
        lines.append("")
        lines.append("HTTP titles:")
        for port, title in r.http_titles.items():
            lines.append(f"  port {port}: {title}")
    if r.http_servers:
        lines.append("")
        lines.append("HTTP Server headers:")
        for port, s in r.http_servers.items():
            lines.append(f"  port {port}: {s}")
    scrollable_text(stdscr, f"Host Detail", lines, subtitle=r.ip)


def view_results_screen(stdscr, app: App):
    if not app.last_reports:
        message_box(stdscr, "Results", ["No results yet. Run a scan first."])
        return
    while True:
        sorted_reports = sorted(app.last_reports, key=lambda x: tuple(int(o) for o in x.ip.split(".")) if x.ip.count(".") == 3 else (0,))
        labels = []
        for r in sorted_reports:
            dev = r.top_classification.device_type if r.top_classification else "Unclassified"
            vendor = f" ({r.top_classification.vendor})" if r.top_classification and r.top_classification.vendor else ""
            labels.append(f"{r.ip:<16} {dev}{vendor}  [{len(r.open_ports)} port(s)]")
        labels.append("Export to JSON...")
        labels.append("Back")

        target = app.last_scan_meta.get("target", "")
        choice = menu(
            stdscr, "Scan Results", labels,
            subtitle=f"{target}  \u2014  {len(app.last_reports)} host(s) found",
        )
        if choice in (-1, len(labels) - 1):
            return
        if choice == len(labels) - 2:
            default_path = app.config.json_output or "report.json"
            path = text_input(stdscr, "Export path", default_path)
            if path:
                try:
                    write_json_report(path, app.last_reports)
                    message_box(stdscr, "Exported", [f"Written to {path}"])
                except OSError as e:
                    message_box(stdscr, "Export Failed", [str(e)])
            continue

        show_host_detail(stdscr, sorted_reports[choice])


def run_scan_screen(stdscr, app: App):
    if not app.config.target:
        message_box(stdscr, "Cannot Scan", ["Set a target range first (Main Menu > Target Range(s))."])
        return
    if not app.config.ports:
        message_box(stdscr, "Cannot Scan", ["Select at least one port first (Main Menu > Ports)."])
        return
    if not confirm(stdscr, f"Scan {app.config.target}? Only scan networks you're authorized to test."):
        return

    log_lines: list[str] = []
    log_q: "queue.Queue[str]" = queue.Queue()
    cancel_event = threading.Event()
    result_holder = {"reports": None, "error": None, "hosts_found": 0, "ports_found": 0}

    def worker():
        try:
            log_q.put(f"[*] Scanning {app.config.target} on {len(app.config.ports)} port(s) (rate={app.config.rate}) ...")
            scanner = MasscanScanner(rate=app.config.rate, interface=app.config.interface or None)
            scan_result = scanner.scan(app.config.target, app.config.ports, cancel_event=cancel_event)

            if cancel_event.is_set():
                log_q.put("[!] Scan cancelled by user.")
                result_holder["error"] = "cancelled"
                return

            hosts = scan_result.hosts()
            result_holder["hosts_found"] = len(hosts)
            result_holder["ports_found"] = len(scan_result.open_ports)
            log_q.put(f"[*] masscan found {len(hosts)} host(s), {len(scan_result.open_ports)} open port(s) total.")

            if not hosts:
                result_holder["reports"] = []
                return

            host_ports = defaultdict(list)
            ttl_maps = defaultdict(dict)
            for op in scan_result.open_ports:
                host_ports[op.ip].append(op.port)
                if op.ttl:
                    ttl_maps[op.ip][op.port] = op.ttl

            log_q.put(f"[*] Fingerprinting {len(hosts)} host(s) ({app.config.workers} workers) ...")
            fingerprints = fingerprint_hosts(
                dict(host_ports), dict(ttl_maps),
                timeout=app.config.timeout, max_workers=app.config.workers,
            )

            reports = []
            for ip, fp in fingerprints.items():
                reports.append(classify_host(ip, host_ports[ip], fp, PORT_SERVICE_MAP))
            log_q.put(f"[*] Done. Classified {len(reports)} host(s).")
            result_holder["reports"] = reports

        except MasscanNotFoundError as e:
            result_holder["error"] = str(e)
        except MasscanExecutionError as e:
            result_holder["error"] = str(e)
        except Exception as e:  # keep the TUI alive no matter what goes wrong
            result_holder["error"] = f"Unexpected error: {e}"

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    stdscr.nodelay(True)
    curses.curs_set(0)
    spinner = "|/-\\"
    spin_idx = 0
    start_time = time.time()

    while t.is_alive():
        while not log_q.empty():
            log_lines.append(log_q.get())

        stdscr.erase()
        draw_header(stdscr, "Running Scan", app.config.summary())
        elapsed = time.time() - start_time
        safe_addstr(stdscr, 3, 2, f"{spinner[spin_idx % len(spinner)]} in progress... {elapsed:0.1f}s elapsed")
        h, w = stdscr.getmaxyx()
        visible = max(1, h - 6)
        for row, line in enumerate(log_lines[-visible:]):
            safe_addstr(stdscr, 5 + row, 2, line)
        draw_footer(stdscr, "q to cancel (stops the masscan phase; fingerprinting still finishes)")
        stdscr.refresh()

        key = stdscr.getch()
        if key == ord('q') and not cancel_event.is_set():
            cancel_event.set()
            log_lines.append("[!] Cancel requested, stopping masscan...")
        spin_idx += 1
        time.sleep(0.15)

    stdscr.nodelay(False)
    while not log_q.empty():
        log_lines.append(log_q.get())

    if result_holder["error"] and result_holder["error"] != "cancelled":
        log_lines.append(f"[!] Error: {result_holder['error']}")
        scrollable_text(stdscr, "Scan Failed", log_lines)
        return
    if result_holder["error"] == "cancelled":
        scrollable_text(stdscr, "Scan Cancelled", log_lines)
        return

    app.last_reports = result_holder["reports"] or []
    app.last_scan_meta = {
        "target": app.config.target,
        "hosts_found": result_holder["hosts_found"],
        "ports_found": result_holder["ports_found"],
    }

    if app.config.json_output and app.last_reports:
        try:
            write_json_report(app.config.json_output, app.last_reports)
            log_lines.append(f"[*] JSON report written to {app.config.json_output}")
        except OSError as e:
            log_lines.append(f"[!] Failed to write JSON report: {e}")

    scrollable_text(stdscr, "Scan Complete", log_lines)
    if app.last_reports:
        view_results_screen(stdscr, app)
    else:
        message_box(stdscr, "Scan Complete", ["No open ports found on any host in range."])


# ---------------------------------------------------------------------------
# Main menu / app loop
# ---------------------------------------------------------------------------

class App:
    def __init__(self):
        self.profiles: dict[str, ScanConfig] = load_profiles()
        state = load_state()
        self.recent_targets: list[str] = state.get("recent_targets", [])
        last_cfg = state.get("last_config")
        self.config: ScanConfig = ScanConfig.from_dict(last_cfg) if last_cfg else ScanConfig()
        self.last_reports = []
        self.last_scan_meta = {}
        self.last_brute_results: list[BruteResult] = []  # NEW


def main_menu(stdscr, app: App):
    while True:
        results_label = "View Last Results"
        if app.last_reports:
            results_label += f" ({len(app.last_reports)} host(s))"
        else:
            results_label += " (none yet)"

        # Add bruteforce result indicator
        brute_label = "HTTP Auth Bruteforce"
        if hasattr(app, 'last_brute_results') and app.last_brute_results:
            brute_label += f" ({len(app.last_brute_results)} found)"

        items = [
            f"Target Range(s)   [{app.config.target or 'not set'}]",
            f"Ports             [{len(app.config.ports)} selected]",
            f"Scan Settings     [rate={app.config.rate}  timeout={app.config.timeout}s  workers={app.config.workers}]",
            "Save Profile As...",
            f"Load Profile      [{len(app.profiles)} saved]",
            "Delete Profile",
            "Run Scan",
            results_label,
            brute_label,  # NEW
            "Quit",
        ]
        choice = menu(
            stdscr, "AWAKE", items,
            subtitle=app.config.summary(),
            footer="\u2191/\u2193 move   Enter select   q quit",
        )

        if choice in (-1, 9):  # Updated quit index
            return
        elif choice == 0:
            screen_target(stdscr, app)
        elif choice == 1:
            screen_ports(stdscr, app)
        elif choice == 2:
            screen_settings(stdscr, app)
        elif choice == 3:
            screen_save_profile(stdscr, app)
        elif choice == 4:
            screen_load_profile(stdscr, app)
        elif choice == 5:
            screen_delete_profile(stdscr, app)
        elif choice == 6:
            run_scan_screen(stdscr, app)
        elif choice == 7:
            view_results_screen(stdscr, app)
        elif choice == 8:  # NEW
            run_bruteforce_screen(stdscr, app)
        elif choice == 9:
            return

        app.persist()

def run_bruteforce_screen(stdscr, app: App):
    """Run HTTP Basic Auth bruteforce against last scan results."""
    if not app.last_reports:
        message_box(stdscr, "No Results", ["Run a scan first to get targets."])
        return

    # Configure bruteforce options
    options = [
        "Use default credentials (common admin passwords)",
        "Use custom wordlist files",
        "Back",
    ]

    choice = menu(stdscr, "HTTP Auth Bruteforce", options,
                  subtitle=f"Targets: {len(app.last_reports)} hosts")

    if choice in (-1, 2):
        return

    usernames = None
    passwords = None

    if choice == 1:
        # Get wordlist paths
        user_path = text_input(stdscr, "Username wordlist path (blank for defaults)", "")
        pass_path = text_input(stdscr, "Password wordlist path (blank for defaults)", "")

        if user_path:
            try:
                with open(user_path) as f:
                    usernames = [l.strip() for l in f if l.strip()]
            except OSError as e:
                message_box(stdscr, "Error", [f"Cannot read username list: {e}"])
                return

        if pass_path:
            try:
                with open(pass_path) as f:
                    passwords = [l.strip() for l in f if l.strip()]
            except OSError as e:
                message_box(stdscr, "Error", [f"Cannot read password list: {e}"])
                return

    # Confirm and run
    if not confirm(stdscr, f"Bruteforce {len(app.last_reports)} hosts? This may take a while."):
        return

    # Convert reports to format expected by bruteforce module
    scan_data = []
    for r in app.last_reports:
        scan_data.append({
            'ip': r.ip,
            'open_ports': r.open_ports,
        })

    # Run bruteforce with progress display
    log_lines = ["[*] Starting HTTP Basic Auth bruteforce..."]

    def log_callback(msg):
        log_lines.append(msg)

    # Monkey-patch print to capture output
    original_print = print
    def capture_print(*args, **kwargs):
        msg = ' '.join(str(a) for a in args)
        log_lines.append(msg)
        stdscr.erase()
        draw_header(stdscr, "Bruteforce Progress", "")
        h, w = stdscr.getmaxyx()
        visible = max(1, h - 6)
        for row, line in enumerate(log_lines[-visible:]):
            safe_addstr(stdscr, 3 + row, 2, line[:w-4])
        draw_footer(stdscr, "q to cancel")
        stdscr.refresh()

    import builtins
    builtins.print = capture_print

    try:
        bruter = UniversalHTTPBruter(
            usernames=usernames,
            passwords=passwords,
            auto_open=True,
            max_workers=10
        )

        all_results = []
        for host_data in scan_data:
            ip = host_data['ip']
            ports = host_data['open_ports']

            log_callback(f"[*] Scanning {ip}...")
            results = bruter.scan_host(ip, ports)
            all_results.extend(results)

            # Check for cancel
            stdscr.nodelay(True)
            key = stdscr.getch()
            stdscr.nodelay(False)
            if key == ord('q'):
                log_callback("[!] Cancelled by user")
                break

        app.last_brute_results = all_results

    finally:
        builtins.print = original_print

    # Show results
    if app.last_brute_results:
        result_lines = [f"[+] Found {len(app.last_brute_results)} valid credentials:"]
        for r in app.last_brute_results:
            result_lines.append(f"    {r.url}")
            result_lines.append(f"        -> {r.username}:{r.password}")
        scrollable_text(stdscr, "Bruteforce Results", result_lines)
    else:
        message_box(stdscr, "Complete", ["No valid credentials found."])





def run(stdscr):
    init_colors()
    curses.curs_set(0)
    app = App()
    try:
        main_menu(stdscr, app)
    finally:
        app.persist()


def main():
    curses.wrapper(run)


if __name__ == "__main__":
    main()
