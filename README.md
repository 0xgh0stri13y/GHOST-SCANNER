# 👻 GHOST Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-black.svg?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg?style=for-the-badge" alt="Status">
</p>

<p align="center">
  <strong>The Ultimate Phantom Web Security Testing Framework</strong>
</p>

<p align="center">
  <a href="#-core-capabilities">Capabilities</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-interactive-modules">Modules</a> •
  <a href="#-reporting">Reporting</a>
</p>

---

## 📖 Overview

**GHOST Scanner** is an advanced, automated web pentesting and reconnaissance toolkit. Designed to strike silently and surface critical vulnerabilities, it seamlessly integrates industry-standard OWASP methodologies into a single, cohesive workflow.

From stealthy reconnaissance and directory fuzzing to deep source code analysis and targeted Active Directory enumeration, GHOST Scanner equips bug bounty hunters and red teamers with the ultimate arsenal.

## ⚡ Core Capabilities

- **Phantom Reconnaissance**: Fast and reliable port scanning using Nmap, alongside deep service detection.
- **Deep Web Spidering**: Crawls target applications to map the attack surface, detecting hidden forms, parameters, and endpoints.
- **Source Code Secrets**: Analyzes exposed JS, JSON, and HTML files for hardcoded API keys, JWTs, PEM keys, and sensitive comments.
- **Vulnerability Discovery**: Native integration with **Nuclei** to rapidly scan against thousands of known CVEs and misconfigurations.
- **Brute Force & Fuzzing**: Powerful directory and virtual host fuzzing via `ffuf`.
- **Targeted Injection Tests**: Automates the discovery of SQLi, XSS, Path Traversal, and Open Redirects.
- **API & Cloud Security**: Tests for modern API flaws including IDOR, Mass Assignment, and JWT misconfigurations.
- **WordPress Intelligence**: Uncovers vulnerable plugins, themes, and conducts user enumeration on WP instances.
- **Active Directory Operations**: Built-in AD module utilizing Kerbrute, NetExec, and Impacket for comprehensive domain enumeration and credential attacks.

## 🛠️ Prerequisites

- **Python**: 3.8 or higher.
- **OS**: The Python core is cross-platform (Linux, macOS, Windows). The external recon tools below are easiest on **Kali Linux / Ubuntu / Debian** (or WSL on Windows).
- **Python packages** (installed via `requirements.txt`): `requests`, `beautifulsoup4`, `colorama`, `tqdm`. The scanner degrades gracefully if `beautifulsoup4`/`colorama`/`tqdm` are missing, but installing them is recommended.
  - *Optional:* `prompt_toolkit` enables tab path-completion in the interactive prompts on Windows.
- **External tools (optional but recommended):** `nmap`, `ffuf`, `nuclei`, `wpscan`, `whatweb`, `hydra`, `SecLists`, and for the AD module `kerbrute`, `ldapsearch`, `netexec`/`nxc`, and Impacket (`impacket-GetNPUsers`, `impacket-GetUserSPNs`). GHOST Scanner prompts to install several of these at runtime if they're missing.

## 📦 Installation

Get GHOST Scanner up and running in seconds:

```bash
git clone https://github.com/0xgh0stri13y/GHOST-SCANNER.git
cd GHOST-SCANNER

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

*Note: GHOST Scanner will automatically prompt you to install missing external tools (like Nuclei or ffuf) during runtime.*

## 🚀 Usage

Launch the interactive console:

```bash
python3 ghost-scanner.py
```

Or run it directly from the CLI:

```bash
python3 ghost-scanner.py --url https://target.local --threads 10 --timeout 15
```

### CLI Options

| Flag | Description |
| --- | --- |
| `--url`, `-u` | Target URL (omit for interactive mode) |
| `--output`, `-o` | Report output file (e.g. `report.html`) |
| `--threads`, `-t` | Number of threads (default: 5) |
| `--timeout` | Per-request timeout in seconds (default: 10) |
| `--delay`, `-d` | Delay between requests in seconds, applied globally for evasion/throttling |
| `--insecure`, `-k` | Disable TLS certificate verification (labs / intercepting proxies) |
| `--cookie` | Session cookie string sent on every request, e.g. `"PHPSESSID=...; token=..."` |
| `--user-agent`, `-A` | Custom User-Agent for every request |
| `--proxy` | Route all traffic through a proxy, e.g. `http://127.0.0.1:8080` (Burp/ZAP) |
| `--header`, `-H` | Extra header on every request; repeatable (e.g. `-H "Authorization: Bearer x"`) |
| `--no-color` | Disable colored output |

```bash
# Scan through Burp with a bearer token and an authenticated cookie
python3 ghost-scanner.py -u https://target.local \
  --proxy http://127.0.0.1:8080 -k \
  -H "Authorization: Bearer eyJ..." \
  --cookie "session=abc123"
```

### Authentication Handling
Need to scan behind a login? Run the scanner interactively and select **Option 1** to configure your authentication payload, or pass `--cookie` / `-H "Authorization: ..."` on the CLI. GHOST Scanner maintains a persistent session across all subsequent modules.

> **Tip:** options that affect every request — `--delay`, `--cookie`, `--user-agent`, `--proxy`, and `-H` — are applied globally to all sessions and modules, so throttling and intercepting-proxy workflows work consistently across the whole scan.

## 🧩 Interactive Modules

Launching without `--url` drops you into a menu. Each module can be run on its own, or chained automatically via **Full Pentest**:

| # | Module |
| --- | --- |
| 1 | Configure authentication (Basic Auth, form login, or manual cookie/token) |
| 2 | General information & enumeration (headers, cookies, tech detection, TLS, CORS) |
| 3 | Port scan with Nmap (`-sV` + targeted NSE) |
| 4 | Vulnerability analysis with Nuclei |
| 5 | Subdomain fuzzing (vhost) with ffuf |
| 6 | Directory fuzzing (ffuf, with internal fallback) |
| 7 | Spidering / full site mapping |
| 8 | Source code analysis (credentials/secrets in HTML & JS) |
| 9 | Injection tests (SQLi, XSS, Path Traversal, Command Injection, Open Redirect) |
| 10 | API tests (discovery, IDOR/BOLA, mass assignment, GraphQL, JWT, CORS, rate limiting) |
| 11 | User/email enumeration & password brute force |
| 12 | WordPress enumeration & attacks (WPScan) |
| 13 | Active Directory pentesting (Kerbrute / LDAP / NXC / Impacket) |
| 14 | **Full Pentest** — runs all of the above in sequence |
| 15 | Show Markdown summary |
| 16 | Show result tables (visual format) |
| 17 | Exit (offers to save the report) |

## 📊 Reporting

GHOST Scanner doesn't just find vulnerabilities; it presents them beautifully. On exit (or with `--output`), reports are generated locally in the `reports/<target>/` directory in four formats simultaneously:

- **SaaS-Style HTML Dashboard**: A dark-themed interactive report featuring live search, severity filters, browser PDF export, and severity-based KPI cards.
- **Markdown & TXT**: Clean, readable summaries perfect for GitBook, Obsidian, or client deliverables.
- **JSON Export**: Raw structured data for easy ingestion into other pipeline tools.

## 🤝 Contributing

We welcome pull requests and feature suggestions! 
1. Fork the repo
2. Create your feature branch (`git checkout -b feature/NewGhostFeature`)
3. Commit your changes (`git commit -m 'Add NewGhostFeature'`)
4. Push to the branch (`git push origin feature/NewGhostFeature`)
5. Open a Pull Request

## ⚠️ Disclaimer

**WARNING**: GHOST Scanner is built exclusively for authorized security testing and educational purposes.
Unauthorized access to computer systems is illegal and strictly prohibited. The developer `@0xgh0stri13y` assumes no liability for any misuse of this software. Always secure explicit, written permission before targeting any infrastructure.
