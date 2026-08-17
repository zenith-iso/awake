"""
signatures.py
-------------
Static knowledge base used by the classifier: well-known ports and
regex/keyword rules mapped to device types and vendors.

This is intentionally data-only (no scanning/exploit logic) so it can be
extended or swapped out independently of the rest of the framework.
"""

import re

# ---------------------------------------------------------------------------
# Common port -> service name (used for reporting / banner-grab target list)
# ---------------------------------------------------------------------------
PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    81: "http-alt",
    102: "s7comm",          # Siemens S7 PLC
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    179: "bgp",
    443: "https",
    445: "microsoft-ds",
    502: "modbus",          # ICS / PLC
    515: "printer-lpd",
    554: "rtsp",            # IP cameras / streaming
    631: "ipp",             # CUPS printers
    623: "ipmi",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1883: "mqtt",           # IoT broker
    1900: "upnp",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker",
    3306: "mysql",
    3389: "rdp",
    5000: "upnp/http-alt",
    5060: "sip",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    8080: "http-alt",
    8081: "http-alt",
    8291: "mikrotik-winbox",
    8443: "https-alt",
    9100: "jetdirect-printer",
    9200: "elasticsearch",
    10000: "webmin",
    20000: "dnp3",          # ICS / SCADA
    27017: "mongodb",
    32400: "plex",
}

# A reasonably small, high-signal port list for fast masscan sweeps.
DEFAULT_TOP_PORTS = sorted(PORT_SERVICE_MAP.keys())

# ---------------------------------------------------------------------------
# Device classification rules
#
# Each rule is checked against:
#   - open_ports: set[int]
#   - banners: dict[int, str]  (raw text collected per port, lowercased)
#
# A rule matches if ALL "require_ports" are open (if given) AND at least one
# "banner_patterns" regex matches any collected banner (if given). Rules with
# neither are never used standalone. First matching rule (in list order,
# highest confidence first) wins; multiple can be reported as candidates.
# ---------------------------------------------------------------------------
DEVICE_RULES = [
    # --- Industrial control systems (highest priority, high impact) ---
    {
        "device_type": "ICS/PLC (Siemens S7)",
        "vendor": "Siemens",
        "require_ports": [102],
        "banner_patterns": [],
        "confidence": 0.9,
    },
    {
        "device_type": "ICS/PLC (Modbus)",
        "vendor": None,
        "require_ports": [502],
        "banner_patterns": [],
        "confidence": 0.85,
    },
    {
        "device_type": "ICS/SCADA (DNP3)",
        "vendor": None,
        "require_ports": [20000],
        "banner_patterns": [],
        "confidence": 0.85,
    },

    # --- Network infrastructure ---
    {
        "device_type": "Router/Firewall",
        "vendor": "MikroTik",
        "require_ports": [8291],
        "banner_patterns": [r"mikrotik"],
        "confidence": 0.9,
    },
    {
        "device_type": "Router/Modem",
        "vendor": None,
        "require_ports": [],
        "banner_patterns": [r"rompager", r"boa/", r"httpd.*router", r"dd-wrt", r"openwrt"],
        "confidence": 0.75,
    },

    # --- IP cameras / DVRs ---
    {
        "device_type": "IP Camera / DVR",
        "vendor": "Hikvision",
        "require_ports": [],
        "banner_patterns": [r"hikvision", r"dvrdvs"],
        "confidence": 0.9,
    },
    {
        "device_type": "IP Camera / DVR",
        "vendor": "Dahua",
        "require_ports": [],
        "banner_patterns": [r"dahua"],
        "confidence": 0.9,
    },
    {
        "device_type": "IP Camera",
        "vendor": None,
        "require_ports": [554],
        "banner_patterns": [],
        "confidence": 0.6,
    },

    # --- Printers ---
    {
        "device_type": "Network Printer",
        "vendor": None,
        "require_ports": [9100],
        "banner_patterns": [],
        "confidence": 0.85,
    },
    {
        "device_type": "Network Printer",
        "vendor": None,
        "require_ports": [631],
        "banner_patterns": [r"cups"],
        "confidence": 0.8,
    },
    {
        "device_type": "Network Printer",
        "vendor": "HP",
        "require_ports": [],
        "banner_patterns": [r"hp-chaisoe", r"jetdirect"],
        "confidence": 0.85,
    },

    # --- NAS / storage ---
    {
        "device_type": "NAS",
        "vendor": "Synology",
        "require_ports": [],
        "banner_patterns": [r"synology", r"diskstation"],
        "confidence": 0.9,
    },
    {
        "device_type": "NAS",
        "vendor": "QNAP",
        "require_ports": [],
        "banner_patterns": [r"qnap"],
        "confidence": 0.9,
    },

    # --- Hypervisors / management ---
    {
        "device_type": "Server (Baseboard Mgmt / IPMI)",
        "vendor": None,
        "require_ports": [623],
        "banner_patterns": [],
        "confidence": 0.8,
    },
    {
        "device_type": "Server (Docker host)",
        "vendor": None,
        "require_ports": [2375],
        "banner_patterns": [],
        "confidence": 0.75,
    },
    {
        "device_type": "Server (Webmin managed)",
        "vendor": None,
        "require_ports": [10000],
        "banner_patterns": [r"webmin"],
        "confidence": 0.7,
    },

    # --- Windows hosts ---
    {
        "device_type": "Windows Host (Server/Workstation)",
        "vendor": "Microsoft",
        "require_ports": [445, 139],
        "banner_patterns": [],
        "confidence": 0.75,
    },
    {
        "device_type": "Windows Host (RDP enabled)",
        "vendor": "Microsoft",
        "require_ports": [3389],
        "banner_patterns": [],
        "confidence": 0.7,
    },

    # --- IoT hub / broker ---
    {
        "device_type": "IoT Hub (MQTT broker)",
        "vendor": None,
        "require_ports": [1883],
        "banner_patterns": [],
        "confidence": 0.6,
    },

    # --- General purpose servers (lower priority, catch-alls) ---
    {
        "device_type": "Database Server",
        "vendor": None,
        "require_ports": [3306],
        "banner_patterns": [],
        "confidence": 0.6,
    },
    {
        "device_type": "Database Server",
        "vendor": None,
        "require_ports": [5432],
        "banner_patterns": [],
        "confidence": 0.6,
    },
    {
        "device_type": "Database Server",
        "vendor": None,
        "require_ports": [27017],
        "banner_patterns": [],
        "confidence": 0.6,
    },
    {
        "device_type": "Media Server",
        "vendor": "Plex",
        "require_ports": [32400],
        "banner_patterns": [r"plex"],
        "confidence": 0.85,
    },
    {
        "device_type": "Linux Server (SSH)",
        "vendor": None,
        "require_ports": [22],
        "banner_patterns": [r"openssh"],
        "confidence": 0.4,
    },
    {
        "device_type": "Embedded/IoT Device (SSH)",
        "vendor": None,
        "require_ports": [22],
        "banner_patterns": [r"dropbear"],
        "confidence": 0.6,
    },
    {
        "device_type": "Web Server",
        "vendor": None,
        "require_ports": [],
        "banner_patterns": [r"nginx", r"apache", r"lighttpd", r"iis"],
        "confidence": 0.3,
    },
]

# Pre-compile regexes for speed.
for _rule in DEVICE_RULES:
    _rule["_compiled"] = [re.compile(p, re.IGNORECASE) for p in _rule["banner_patterns"]]
