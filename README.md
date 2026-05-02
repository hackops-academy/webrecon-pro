<div align="center">

```
██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝
```

### Professional Web Penetration Testing Framework

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=linux&logoColor=white)](https://kali.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-ef4444?style=for-the-badge)]()
[![GitHub](https://img.shields.io/badge/GitHub-hackops--academy-181717?style=for-the-badge&logo=github)](https://github.com/hackops-academy/webrecon-pro)

<br>

> **WebRecon Pro** is a powerful, modular, async web penetration testing framework  
> built for security professionals on Kali Linux.  
> One tool. Every phase. Professional reports.

<br>

**⚠️ FOR AUTHORIZED PENETRATION TESTING ONLY ⚠️**  
*Unauthorized use against systems you do not own or have explicit written permission to test is illegal.*

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Folder Structure](#-folder-structure)
- [Usage](#-usage)
- [Commands & Flags](#-commands--flags)
- [All Flags Reference](#-all-flags-reference)
- [Real-World Examples](#-real-world-examples)
- [What Each Module Detects](#-what-each-module-detects)
- [Report Formats](#-report-formats)
- [Legal Practice Targets](#-legal-practice-targets)
- [Uninstall](#-uninstall)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 🔍 Overview

**WebRecon Pro** is an all-in-one web penetration testing framework that chains **6 powerful modules** into a single automated pipeline. Unlike single-purpose tools, it handles everything from initial recon to vulnerability detection and generates a professional report — all from one command.

```
webrecon scan https://target.com
```

It runs fully asynchronously for maximum speed, stores every scan in a local SQLite database, and outputs dark-themed HTML reports that look professional enough to hand to a client.

---

## ✨ Features

| Module | What It Does |
|--------|-------------|
| 🛡️ **Headers** | Checks 10+ security headers, scores target 0–100, audits cookies |
| 🌐 **Subdomains** | DNS brute-force + crt.sh certificate transparency logs |
| 🔎 **Fingerprint** | Detects CMS, WAF, frameworks, server tech, 40+ sensitive paths |
| 💥 **Vuln Scanner** | SQLi, XSS, SSRF, CORS, Path Traversal, Command Injection, Clickjacking |
| 🔐 **Auth Tester** | Default creds, JWT attacks, session entropy, brute-force protection |
| 🔌 **API Tester** | IDOR, GraphQL introspection, mass assignment, broken auth, Swagger exposure |
| 📊 **Reporter** | Professional HTML, JSON, and plain text reports |
| 💾 **Database** | SQLite scan history — compare and track results over time |

---

## ⚙️ Installation

### One-Line Install (Recommended)

```bash
git clone https://github.com/hackops-academy/webrecon-pro.git
cd webrecon-pro
sudo bash install.sh
```

That's it. The installer will:

- ✅ Check Python 3.9+ is installed
- ✅ Verify all source files exist
- ✅ Install Python dependencies (`typer`, `rich`, `httpx`, `beautifulsoup4`)
- ✅ Copy all files to `/opt/webrecon/`
- ✅ Create the global `webrecon` command at `/usr/local/bin/webrecon`
- ✅ Create a desktop icon in your apps menu (Network / Security)
- ✅ Add shell aliases for quick access
- ✅ Verify the tool runs correctly
- ✅ Create an uninstaller at `/opt/webrecon/uninstall.sh`

### After Install — Start Immediately

```bash
webrecon --help
webrecon scan https://target.com
```

### Manual Dependency Install (if needed)

```bash
pip3 install typer rich httpx beautifulsoup4 --break-system-packages
```

---

## 📁 Folder Structure

```
webrecon-pro/
│
├── main.py                    ← CLI entry point (run with: webrecon)
├── install.sh                 ← One-command installer
├── requirements.txt           ← Python dependencies
├── setup.py                   ← Package setup
├── webrecon.desktop           ← Desktop app entry (icon + right-click actions)
├── .gitignore
│
├── modules/
│   ├── __init__.py
│   ├── subdomain_enum.py      ← DNS brute-force + crt.sh
│   ├── fingerprint.py         ← CMS, WAF, framework, sensitive path detection
│   ├── vuln_scanner.py        ← SQLi, XSS, SSRF, CORS, CMDi, etc.
│   ├── header_checker.py      ← Security header analysis + scoring
│   ├── auth_tester.py         ← Default creds, JWT, session testing
│   ├── api_tester.py          ← IDOR, GraphQL, mass assignment, broken auth
│   └── reporter.py            ← HTML / JSON / TXT report generator
│
└── utils/
    ├── __init__.py
    ├── db.py                  ← SQLite scan history database
    └── logger.py              ← Logging setup
```

**After install, files live at:**
```
/opt/webrecon/          ← Tool files
/usr/local/bin/webrecon ← Global command
~/.webrecon/reports/    ← Your scan reports
~/.webrecon/scans.db    ← Scan history database
```

---

## 🚀 Usage

### Show Help Menu

```bash
webrecon --help
webrecon --version
```

### Full Penetration Test

```bash
webrecon scan https://target.com
```

### Individual Modules

```bash
webrecon headers     https://target.com
webrecon vuln        https://target.com
webrecon subdomains  target.com
webrecon fingerprint https://target.com
webrecon api         https://target.com
webrecon list-scans
```

---

## 📋 Commands & Flags

### `webrecon scan` — Full Pentest (All 6 Modules)

```
webrecon scan TARGET [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output PATH` | `-o` | `./reports` | Directory to save the report |
| `--threads INT` | `-t` | `10` | Number of concurrent threads |
| `--wordlist PATH` | `-w` | built-in | Custom subdomain wordlist file |
| `--format [html\|json\|txt]` | `-f` | `html` | Report output format |
| `--verbose` | `-v` | off | Show detailed output for all phases |
| `--skip-subdomains` | — | off | Skip subdomain enumeration phase |
| `--skip-vuln` | — | off | Skip vulnerability scanning phase |
| `--skip-auth` | — | off | Skip authentication testing phase |
| `--skip-api` | — | off | Skip API security testing phase |

---

### `webrecon subdomains` — Subdomain Enumeration

```
webrecon subdomains DOMAIN [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--threads INT` | `-t` | `20` | Concurrent DNS resolution threads |
| `--wordlist PATH` | `-w` | built-in | Custom wordlist file path |
| `--output PATH` | `-o` | none | Save subdomain list to a file |
| `--verbose` | `-v` | off | Show every resolution attempt |

---

### `webrecon vuln` — Vulnerability Scanner

```
webrecon vuln TARGET [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--threads INT` | `-t` | `10` | Concurrent request threads |
| `--verbose` | `-v` | off | Show all payloads being tested |

---

### `webrecon headers` — Security Headers Check

```
webrecon headers TARGET [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--verbose` | `-v` | off | Show full header values and details |

---

### `webrecon fingerprint` — Web Fingerprinting

```
webrecon fingerprint TARGET [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--verbose` | `-v` | off | Show every path probe attempt |

---

### `webrecon api` — API Security Testing

```
webrecon api TARGET [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--spec URL/PATH` | `-s` | auto-discover | OpenAPI/Swagger spec URL or local path |
| `--verbose` | `-v` | off | Show all API test details |

---

### `webrecon list-scans` — Scan History

```
webrecon list-scans
```

Displays all previous scans with target, date, and total findings count.  
History is stored at `~/.webrecon/scans.db`.

---

## 🎯 All Flags Reference

Quick single-table reference for every flag in the tool:

| Command | Flag | Short | Default | Description |
|---------|------|-------|---------|-------------|
| `scan` | `--output` | `-o` | `./reports` | Report save directory |
| `scan` | `--threads` | `-t` | `10` | Concurrent threads |
| `scan` | `--wordlist` | `-w` | built-in | Subdomain wordlist path |
| `scan` | `--format` | `-f` | `html` | `html` / `json` / `txt` |
| `scan` | `--verbose` | `-v` | off | Detailed output |
| `scan` | `--skip-subdomains` | — | off | Skip subdomain phase |
| `scan` | `--skip-vuln` | — | off | Skip vuln scan phase |
| `scan` | `--skip-auth` | — | off | Skip auth test phase |
| `scan` | `--skip-api` | — | off | Skip API test phase |
| `subdomains` | `--threads` | `-t` | `20` | DNS threads |
| `subdomains` | `--wordlist` | `-w` | built-in | Wordlist path |
| `subdomains` | `--output` | `-o` | none | Save to file |
| `subdomains` | `--verbose` | `-v` | off | Show each attempt |
| `vuln` | `--threads` | `-t` | `10` | Request threads |
| `vuln` | `--verbose` | `-v` | off | Show all payloads |
| `headers` | `--verbose` | `-v` | off | Show header values |
| `fingerprint` | `--verbose` | `-v` | off | Show path probes |
| `api` | `--spec` | `-s` | auto | Swagger spec URL/path |
| `api` | `--verbose` | `-v` | off | Show test details |

---

## 💡 Real-World Examples

```bash
# ── Full Scans ─────────────────────────────────────────────────────

# Full scan — verbose, 20 threads
webrecon scan https://target.com -v -t 20

# Full scan — save JSON report to custom folder
webrecon scan https://target.com -f json -o ~/Desktop/reports

# Full scan — plain text output
webrecon scan https://target.com -f txt -o ~/reports

# Skip the slowest phase (subdomains) for a faster scan
webrecon scan https://target.com --skip-subdomains -t 30

# Quick recon only — no vuln, auth, or API testing
webrecon scan https://target.com --skip-vuln --skip-auth --skip-api

# Auth testing only
webrecon scan https://target.com --skip-subdomains --skip-vuln --skip-api -v

# API-focused pentest
webrecon scan https://target.com --skip-subdomains --skip-auth -v

# Stealth mode — low threads to avoid detection
webrecon scan https://target.com -t 2 -v

# ── Individual Modules ─────────────────────────────────────────────

# Subdomain enum with SecLists — 100 threads
webrecon subdomains target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 100 -o subs.txt

# Vulnerability scan — verbose
webrecon vuln https://target.com -v -t 15

# Security headers quick audit
webrecon headers https://target.com -v

# Fingerprint tech stack
webrecon fingerprint https://target.com -v

# API test with known Swagger spec
webrecon api https://target.com -s https://target.com/swagger.json -v

# API auto-discovery
webrecon api https://target.com -v

# View scan history
webrecon list-scans

# ── Practice Targets (Legal) ───────────────────────────────────────

webrecon scan http://testphp.vulnweb.com --skip-subdomains -v
webrecon headers https://example.com
webrecon fingerprint https://example.com -v
```

---

## 🧩 What Each Module Detects

### 🛡️ Headers Module
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options` (Clickjacking protection)
- `X-Content-Type-Options` (MIME sniffing)
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy` (COOP)
- `Cross-Origin-Resource-Policy` (CORP)
- `Cross-Origin-Embedder-Policy` (COEP)
- Cookie flags — `HttpOnly`, `Secure`, `SameSite`
- Information disclosure — `Server`, `X-Powered-By`, `X-AspNet-Version`
- **Scores target 0–100 with letter grade A–F**

### 🌐 Subdomains Module
- DNS brute-force with 100+ built-in common subdomains
- Certificate Transparency logs via **crt.sh**
- Live host detection with HTTP status checking
- IP address resolution for all discovered hosts
- Compatible with **SecLists** wordlists

### 🔎 Fingerprint Module
| Category | Detected |
|----------|---------|
| **CMS** | WordPress, Drupal, Joomla, Magento, Shopify |
| **Frameworks** | Laravel, Django, Ruby on Rails, React, Angular, Vue.js, Next.js, Nuxt.js |
| **WAF** | Cloudflare, Akamai, Imperva/Incapsula, Sucuri, ModSecurity, F5 BIG-IP, Barracuda, Fortinet |
| **Sensitive Paths** | `.env`, `.git/config`, `wp-config.php`, `phpinfo.php`, `backup.zip`, `admin/`, Swagger docs, actuator endpoints, and 30+ more |

### 💥 Vuln Scanner Module
| Vulnerability | Detection Method |
|---------------|-----------------|
| SQL Injection | Error-based + time-based (14 payloads) |
| Reflected XSS | 14 payloads including filter bypasses |
| Open Redirect | 15 redirect parameters × 10 bypass payloads |
| SSRF | AWS/GCP metadata, internal network, file:// protocol |
| Path Traversal | Unix + Windows traversal with encoding bypasses |
| Command Injection | Shell metacharacter injection with output detection |
| CORS Misconfiguration | Arbitrary origin, null origin, credentials bypass |
| Clickjacking | X-Frame-Options + CSP frame-ancestors validation |

### 🔐 Auth Module
- **20 default credential pairs** tested on discovered login pages
- **JWT attacks**: algorithm:none, weak secret brute-force (16 secrets), missing expiration, sensitive data in payload
- **Session security**: ID entropy checking, predictable session ID detection
- **Brute force protection**: rate-limit and CAPTCHA detection
- Supports form-based and JSON-based login endpoints

### 🔌 API Module
- **Swagger/OpenAPI** — auto-discovers and parses exposed API documentation
- **IDOR** — enumerates ID-based endpoints for unauthorized object access
- **GraphQL** — introspection enabled check, sensitive type exposure, playground exposure
- **Mass assignment** — privilege escalation via field injection (role, is_admin, permissions)
- **Broken authentication** — unauthenticated access, invalid token acceptance
- **Verbose errors** — stack traces, SQL errors, internal paths in API responses

---

## 📊 Report Formats

All reports are saved to `./reports/` by default (or your custom `--output` path).

### HTML Report `--format html` *(default)*
- Dark-themed, professional security report
- Severity-colored finding cards (Critical / High / Medium / Low)
- Executive summary with risk score
- Full fingerprinting results
- Subdomain discovery table
- Remediation guidance per finding
- Open in any browser — no internet required

### JSON Report `--format json`
- Machine-readable full scan data
- Integrate with Jira, Burp Suite, or custom scripts
- All findings, subdomains, fingerprint data in one file

### Plain Text Report `--format txt`
- Minimal summary for quick review
- Pipe output to `grep`, `awk`, or other tools
- Lightweight — ideal for scripted environments

---

## 🧪 Legal Practice Targets

Only test on systems you own or have permission to test. Use these intentionally vulnerable environments to practice:

| Target | Type | URL |
|--------|------|-----|
| **VulnWeb** | Live intentionally vulnerable site | `http://testphp.vulnweb.com` |
| **DVWA** | Local vulnerable web app | `http://localhost/dvwa` |
| **OWASP Juice Shop** | Modern vulnerable app | Local Docker |
| **HackTheBox** | Professional CTF labs | `https://hackthebox.com` |
| **TryHackMe** | Beginner-friendly guided labs | `https://tryhackme.com` |
| **PortSwigger Web Academy** | Web vulnerability labs | `https://portswigger.net/web-security` |
| **bWAPP** | Buggy web application | Local setup |

**Quick legal test:**
```bash
webrecon scan http://testphp.vulnweb.com --skip-subdomains -v
```

---

## 🔧 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `typer` | ≥ 0.9.0 | CLI framework |
| `rich` | ≥ 13.0.0 | Terminal UI, tables, progress bars, colors |
| `httpx` | ≥ 0.25.0 | Async HTTP client |
| `beautifulsoup4` | ≥ 4.12.0 | HTML parsing for form/parameter extraction |

```bash
pip3 install typer rich httpx beautifulsoup4 --break-system-packages
```

---

## 🗑️ Uninstall

```bash
sudo bash /opt/webrecon/uninstall.sh
```

This removes:
- `/opt/webrecon/` — all tool files
- `/usr/local/bin/webrecon` — global command
- `/usr/share/applications/webrecon.desktop` — desktop entry
- All icons from `/usr/share/icons/`
- Shell aliases from `/etc/bash.bashrc`

---

## ⚖️ Legal Disclaimer

```
WebRecon Pro is intended for authorized security testing and educational purposes only.

You are solely responsible for ensuring you have explicit written authorization
from the system owner before running any scans or tests.

Unauthorized scanning, probing, or testing of computer systems is a criminal
offense in most jurisdictions including:
  - Computer Fraud and Abuse Act (CFAA) — United States
  - Computer Misuse Act — United Kingdom
  - Section 66 IT Act — India
  - And similar laws worldwide

The developers of WebRecon Pro and HackOps Academy assume NO liability and are
NOT responsible for any misuse, damage, or illegal activity conducted with this tool.

By using WebRecon Pro, you agree that:
  1. You own the target system OR have explicit written permission to test it.
  2. You will not use this tool for any unauthorized or illegal activities.
  3. You take full legal responsibility for your actions.
```

---

<div align="center">

**WebRecon Pro v1.0.0**

Built with ❤️ by [HackOps Academy](https://github.com/hackops-academy) · Python 3.9+ · Kali Linux

[⭐ Star on GitHub](https://github.com/hackops-academy/webrecon-pro) · [🐛 Report a Bug](https://github.com/hackops-academy/webrecon-pro/issues) · [💡 Request a Feature](https://github.com/hackops-academy/webrecon-pro/issues)

*For authorized penetration testing only*

</div>
