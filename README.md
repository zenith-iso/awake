# awake

A small framework that:

1. Uses **masscan** to quickly find open ports across an IP range.
2. **Fingerprints** each discovered host by connecting to its open ports and
   grabbing banners / HTTP headers / TLS-wrapped HTTP responses.
3. **Classifies** each host into a likely device type (router, IP camera,
   NAS, printer, PLC/ICS, Windows/Linux server, etc.) using a rule-based
   signature engine, plus a coarse OS guess from TCP TTL.

## ⚠️ Legal / ethical use

Only scan IP ranges you **own** or have **explicit written authorization**
to test. Port scanning networks you don't control can violate laws (e.g.
the U.S. CFAA), your ISP's acceptable-use policy, or your employer's
policies. This tool is intended for network inventory, asset management,
and authorized security assessments.

## Requirements

- Python 3.10+
- `masscan` installed and on `PATH`
  - Debian/Ubuntu: `sudo apt-get install masscan`
  - macOS: `brew install masscan`
- Root privileges (or `CAP_NET_RAW`/`CAP_NET_ADMIN`) — masscan uses raw
  sockets for its SYN scan.

No third-party Python packages are required; the framework uses only the
standard library.

## Project layout

```
netscan/
├── main.py                     # CLI: scan -> fingerprint -> classify -> report
├── tui.py                      # curses TUI: same pipeline, all config done in-app
├── requirements.txt
└── netscan/
    ├── __init__.py              # public API
    ├── masscan_scanner.py       # subprocess wrapper + JSON parser for masscan
    ├── fingerprinter.py         # banner grabbing (TCP/HTTP/TLS)
    ├── device_classifier.py     # rule engine: (ports, banners) -> device type
    ├── signatures.py            # port map + device signature rule database
    ├── config_store.py          # ScanConfig model, profile save/load, port-spec parsing
    └── tui_widgets.py           # curses menu/checklist/text-input/scroll widgets
```

## Usage: TUI (recommended — no file editing required)

```bash
sudo python3 tui.py
```

Everything is configured from in-app menus: target ranges, port selection,
scan rate/timeout/workers/interface, and named profiles you can save,
reload, and delete. Nothing to hand-edit in a text file or in source code.

**Main menu:**

```
netscan
target: 192.168.1.0/24   48 ports   rate=1000   timeout=2.5s   workers=50

› Target Range(s)   [192.168.1.0/24]
  Ports             [48 selected]
  Scan Settings     [rate=1000  timeout=2.5s  workers=50]
  Save Profile As...
  Load Profile      [2 saved]
  Delete Profile
  Run Scan
  View Last Results (12 host(s))
  Quit
```

- **Target Range(s)** — type a CIDR/range/comma list, or pick from your
  last 10 recently-used targets.
- **Ports** — use the curated default list, flip individual well-known
  ports on/off in a checklist (Space to toggle, `a`/`n` for all/none), or
  type a custom spec like `22,80,443,8000-8010`. Invalid specs show an
  error instead of crashing.
- **Scan Settings** — edit rate, banner-grab timeout, worker thread count,
  network interface, and JSON output path, each via a small text prompt.
- **Save/Load/Delete Profile** — name and persist full configs (target +
  ports + settings) to `~/.config/netscan/profiles.json`; your last-used
  config is also remembered automatically between runs.
- **Run Scan** — runs masscan in a background thread with a live log and
  elapsed timer; press `q` to cancel the masscan phase mid-run. On
  completion it drops you straight into the results browser.
- **View Last Results** — a navigable host list (device type, vendor,
  port count); Enter a host for full detail (ports, banners, HTTP
  titles/headers, OS guess, alternate classification candidates); export
  the whole report to JSON from here too.

Global keys: `↑`/`↓` (or `j`/`k`) to move, `Enter` to select/confirm,
`q`/`Esc` to back out or cancel, `Space` to toggle checklist items.

## Usage: CLI (scriptable / non-interactive)

```bash
# Scan a /24, default high-signal port list
sudo python3 main.py 192.168.1.0/24

# Custom ports and scan rate
sudo python3 main.py 10.0.0.1-10.0.0.254 --ports 22,80,443,8080,554,9100 --rate 2000

# Write a full machine-readable report
sudo python3 main.py 192.168.1.0/24 --json report.json
```

Example output:

```
=== 192.168.1.1 ===
  Open ports : 80/http, 443/https, 8291/mikrotik-winbox
  OS guess   : Network device / Unix variant (TTL~255)
  Device     : Router/Firewall (MikroTik)  [confidence 0.90]
               via banner on port 8291 matched /mikrotik/

=== 192.168.1.64 ===
  Open ports : 80/http, 554/rtsp
  OS guess   : Linux/Unix/macOS (TTL~64)
  Device     : IP Camera / DVR (Hikvision)  [confidence 0.90]
               via banner on port 80 matched /hikvision/
  HTTP title (port 80): Web Service
```

## Extending the classifier

All classification logic lives in `netscan/signatures.py` as a list of
`DEVICE_RULES`. Each rule can require specific open ports, banner regex
matches, or both. Add new vendors/device types by appending rules there —
no other code changes needed. Rules are evaluated in list order and the
highest-confidence match wins; all matches are kept as `candidates` in the
report for review.

## Design notes

- **masscan_scanner.py** only shells out to masscan and parses its `-oJ`
  output — it has no opinion about what the results mean.
- **fingerprinter.py** performs only benign, client-like connections (a
  single GET request for HTTP-like ports, a passive read for text
  protocols). No credentials, exploits, or brute-forcing.
- **device_classifier.py** is pure and side-effect free: given ports +
  banners, it returns a ranked list of `Classification` candidates.
- TTL-based OS guessing is a coarse heuristic (Linux/macOS ~64, Windows
  ~128, network gear ~255), not a reliable fingerprint — treat it as a
  hint, not ground truth. For more precise OS fingerprinting, integrate
  a proper tool like `nmap -O` or `p0f` alongside this framework.
