# ☀️awake👁️

## a powerful python framework and cli tool that:

1. uses **masscan** to fetch open ports on set ip ranges.
2. **fingerprints** each discovered host by connecting to its open ports and
   grabbing banners / http headers / tls-wrapped http responses.
3. **classifies** hosts into likely device types (router, ip camera,
   nas, printer, plc/ics, windows/linux server, etc.) using a rule-based
   signature engine, plus a coarse os guess from tcp ttl.

## ⚠️ legal / ethical use

tha owners of dis tool (me) are **not** responsible for what you do with it.
dont be an idiot.

## requirements

- python 3.10+
- `masscan` installed and on `path`
  - debian/ubuntu: `sudo apt-get install masscan`
  - macos: `brew install masscan`
- root privileges (or `cap_net_raw`/`cap_net_admin`) — masscan uses raw
  sockets for its syn scan :)

no third-party python packages are required; the framework uses only the
standard library.

## usage: tui (recommended — no file editing required)

```bash
sudo python3 tui.py
```

everythin is configured from in-app menus: target ranges, port selection,
scan rate/timeout/workers/interface, and named profiles you can save,
reload, and delete. nothing to hand-edit in a text file or in source code.

🔊"thanks zen!" you all scream with joy.

**main menu:**

```
netscan
target: 192.168.1.0/24   48 ports   rate=1000   timeout=2.5s   workers=50

› target range(s)   [192.168.1.0/24]
  ports             [48 selected]
  scan settings     [rate=1000  timeout=2.5s  workers=50]
  save profile as...
  load profile      [2 saved]
  delete profile
  run scan
  view last results (12 host(s))
  quit
```

- **target range(s)** — type a cidr/range/comma list, or pick from your
  last 10 recently-used targets.
- **ports** — use the curated default list, flip individual well-known
  ports on/off in a checklist (space to toggle, `a`/`n` for all/none), or
  type a custom spec like `22,80,443,8000-8010`. invalid specs show an
  error instead of crashing.
- **scan settings** — edit rate, banner-grab timeout, worker thread count,
  network interface, and json output path, each via a small text prompt.
- **save/load/delete profile** — name and persist full configs (target +
  ports + settings) to `~/.config/netscan/profiles.json`; your last-used
  config is also remembered automatically between runs.
- **run scan** — runs masscan in a background thread with a live log and
  elapsed timer; press `q` to cancel the masscan phase mid-run. on
  completion it drops you straight into the results browser.
- **view last results** — a navigable host list (device type, vendor,
  port count); enter a host for full detail (ports, banners, http
  titles/headers, os guess, alternate classification candidates); export
  the whole report to json from here too.

global keys: `↑`/`↓` (or `j`/`k`) to move, `enter` to select/confirm,
`q`/`esc` to back out or cancel, `space` to toggle checklist items.

## usage: cli (scriptable / non-interactive)

```bash
# scan a /24, default high-signal port list
sudo python3 main.py 192.168.1.0/24

# custom ports and scan rate
sudo python3 main.py 10.0.0.1-10.0.0.254 --ports 22,80,443,8080,554,9100 --rate 2000

# write a full machine-readable report
sudo python3 main.py 192.168.1.0/24 --json report.json
```

example output:

```
=== 192.168.1.1 ===
  open ports : 80/http, 443/https, 8291/mikrotik-winbox
  os guess   : network device / unix variant (ttl~255)
  device     : router/firewall (mikrotik)  [confidence 0.90]
               via banner on port 8291 matched /mikrotik/

=== 192.168.1.64 ===
  open ports : 80/http, 554/rtsp
  os guess   : linux/unix/macos (ttl~64)
  device     : ip camera / dvr (hikvision)  [confidence 0.90]
               via banner on port 80 matched /hikvision/
  http title (port 80): web service
```

## extending the classifier

all classification logic lives in `netscan/signatures.py` as a list of
`device_rules`. each rule can require specific open ports, banner regex
matches, or both. add new vendors/device types by appending rules there —
no other code changes needed. rules are evaluated in list order and the
highest-confidence match wins; all matches are kept as `candidates` in the
report for review.

## design notes

- **masscan_scanner.py** only shells out to masscan and parses its `-oj`
  output — it has no opinion about what the results mean.
- **fingerprinter.py** performs only benign, client-like connections (a
  single get request for http-like ports, a passive read for text
  protocols). no credentials, exploits, or brute-forcing.
- **device_classifier.py** is pure and side-effect free: given ports +
  banners, it returns a ranked list of `classification` candidates.
- ttl-based os guessing is a coarse heuristic (linux/macos ~64, windows
  ~128, network gear ~255), not a reliable fingerprint — treat it as a
  hint, not ground truth. for more precise os fingerprinting, integrate
  a proper tool like `nmap -o` or `p0f` alongside this framework :)

# credits, licenses, & transparency
i dont get how licensing works. fork it, go crazy. - zen

note: the curses, tui menu's code was written by claude. i dont get that either.

### [masscan](github.com/robertdavidgraham/masscan) by @robertdavidgraham
### inspired by @S0Ulle33 's [asleep_scanner](https://github.com/S0Ulle33/asleep_scanner)
### made with love by zenith-iso <3
