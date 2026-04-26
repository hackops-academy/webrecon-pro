
<div align="center">

```
██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ 
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝
```

**WebRecon Pro** — Professional Web Penetration Testing Framework

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple?style=flat-square&logo=linux)](https://www.kali.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-red?style=flat-square)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()

> A powerful, modular, async web penetration testing framework built for security professionals.  
> Combines recon, fingerprinting, vulnerability scanning, auth testing, and API auditing in one CLI tool.

---

⚠️ **FOR AUTHORIZED PENETRATION TESTING ONLY** ⚠️  
*Unauthorized use against systems you do not own or have explicit written permission to test is illegal.*

---

</div>

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Tool Architecture](#-tool-architecture)
- [Installation](#-installation)
- [Folder Structure](#-folder-structure)
- [Usage](#-usage)
  - [Full Scan](#full-scan)
  - [Subdomain Enumeration](#subdomain-enumeration)
  - [Vulnerability Scanner](#vulnerability-scanner)
  - [Security Headers](#security-headers)
  - [Web Fingerprinting](#web-fingerprinting)
  - [Authentication Testing](#authentication-testing)
  - [API Security Testing](#api-security-testing)
  - [List Past Scans](#list-past-scans)
- [Command Reference](#-command-reference)
- [Report Formats](#-report-formats)
- [Real-World Examples](#-real-world-examples)
- [Legal Practice Targets](#-legal-practice-targets)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 🔍 Overview

**WebRecon Pro** is a professional-grade, all-in-one web penetration testing framework written in Python. Unlike single-purpose tools like Nikto or WPScan, WebRecon Pro is a **complete workflow** — it chains recon, scanning, and exploitation detection into one seamless pipeline, saving state between runs and generating professional HTML reports.

Built for **Kali Linux**, it uses fully asynchronous HTTP requests for maximum speed and supports multithreading for large-scale subdomain enumeration.

---

## ✨ Features

### 🌐 Subdomain Enumeration
- Async DNS brute-force with a built-in wordlist of 100+ common subdomains
- Certificate Transparency log harvesting via **crt.sh**
- Live host detection with HTTP status checking
- Custom wordlist support (compatible with SecLists)
- IP resolution for all discovered hosts

### 🔎 Web Fingerprinting
- **CMS Detection:** WordPress, Drupal, Joomla, Magento, Shopify
- **Framework Detection:** Laravel, Django, Rails, React, Angular, Vue.js, Next.js, Nuxt.js
- **WAF Detection:** Cloudflare, Akamai, Imperva/Incapsula, Sucuri, ModSecurity, F5 BIG-IP, Barracuda, Fortinet
- **Sensitive Path Discovery:** `.env`, `.git/config`, `wp-config.php`, `phpinfo.php`, backup files, admin panels, API docs, and 40+ more

### 💥 Vulnerability Scanning
- **SQL Injection** — GET, POST, and cookie parameters with error-based and time-based detection
- **Cross-Site Scripting (XSS)** — Reflected XSS with 14+ payloads including filter bypasses
- **Open Redirect** — Tests 15 redirect parameters with 10 bypass payloads
- **SSRF** — AWS metadata, GCP metadata, internal network probing
- **Path Traversal** — Unix and Windows file system traversal with encoding bypasses
- **Command Injection** — Shell metacharacter injection with output detection
- **CORS Misconfiguration** — Arbitrary origin reflection, null origin, credentials bypass
- **Clickjacking** — X-Frame-Options and CSP frame-ancestors validation

### 🛡️ Security Headers Analysis
- Checks 10 critical security headers with severity scoring
- Detects dangerous information disclosure headers
- Cookie security flag validation (HttpOnly, Secure, SameSite)
- Generates a **security score out of 100** with a letter grade (A–F)
- Full remediation guidance for every missing header

### 🔐 Authentication Testing
- **Default credential testing** with 20 common username/password combinations
- **JWT security analysis** — algorithm none attack, weak secret brute-force, missing expiration, sensitive data in payload
- **Session security** — entropy checking, predictable session ID detection
- **Brute force protection** — rate limiting and CAPTCHA detection
- Supports form-based and JSON-based login endpoints

### 🔌 API Security Testing
- **Swagger/OpenAPI spec discovery** — auto-detects exposed API documentation
- **IDOR testing** — enumeration of ID-based endpoints for unauthorized access
- **GraphQL security** — introspection enabled, sensitive types, playground exposure
- **Mass assignment** — tests for privilege escalation via field injection
- **Broken API authentication** — unauthenticated access, invalid token acceptance
- **Verbose error detection** — stack traces, SQL errors, internal paths in responses

### 📊 Professional Reporting
- **HTML report** — dark-themed, professional security report with severity-colored findings
- **JSON export** — machine-readable for integration with other tools
- **Plain text report** — simple output for quick review
- All scans stored in **SQLite database** for history and comparison

---

## 🏗️ Tool Architecture

```
web-scanner/
├── main.py                    # CLI entry point (Typer)
├── modules/
│   ├── __init__.py
│   ├── subdomain_enum.py      # DNS brute-force + crt.sh
│   ├── fingerprint.py         # CMS, WAF, framework detection
│   ├── vuln_scanner.py        # SQLi, XSS, SSRF, CORS, etc.
│   ├── header_checker.py      # Security header analysis
│   ├── auth_tester.py         # JWT, default creds, session
│   ├── api_tester.py          # OpenAPI, IDOR, GraphQL
│   └── reporter.py            # HTML/JSON/TXT report generator
├── utils/
│   ├── __init__.py
│   ├── db.py                  # SQLite scan history
│   └── logger.py              # Logging setup
└── reports/                   # Auto-generated scan reports
```

**Data Flow:**
```
Target URL
    │
    ▼
┌─────────────────────────────────────────┐
│              main.py (CLI)              │
└─────────────┬───────────────────────────┘
              │
    ┌─────────┼──────────────────────┐
    ▼         ▼          ▼           ▼
 Subdomain  Fingerprint  Headers   Vulns
 Enum       Module       Checker   Scanner
    │         │          │           │
    └─────────┴──────────┴───────────┘
              │
    ┌─────────┼──────────────────────┐
    ▼         ▼
  Auth      API
  Tester    Tester
              │
              ▼
    ┌─────────────────┐
    │  Reporter       │
    │  HTML/JSON/TXT  │
    └─────────────────┘
              │
              ▼
    ┌─────────────────┐
    │  SQLite DB      │
    │  ~/.webrecon/   │
    └─────────────────┘
```

---

## ⚙️ Installation

### Prerequisites

- Kali Linux (recommended) or any Debian/Ubuntu-based system
- Python 3.9 or higher
- pip3

### Step 1 — Clone or create the tool folder

```bash
mkdir ~/web-scanner && cd ~/web-scanner
```

### Step 2 — Set up the folder structure

```bash
mkdir -p modules utils
touch modules/__init__.py utils/__init__.py
```

### Step 3 — Install dependencies

```bash
pip3 install typer rich httpx beautifulsoup4 --break-system-packages
```

### Step 4 — Verify installation

```bash
python3 main.py --help
```

You should see the WebRecon Pro banner and command menu.

### Optional — Install SecLists for better wordlists

```bash
sudo apt install seclists -y
# Wordlists will be at: /usr/share/seclists/Discovery/DNS/
```

---

## 📁 Folder Structure

After setup, your directory should look like this:

```
~/web-scanner/
├── main.py
├── modules/
│   ├── __init__.py
│   ├── api_tester.py
│   ├── auth_tester.py
│   ├── fingerprint.py
│   ├── header_checker.py
│   ├── reporter.py
│   ├── subdomain_enum.py
│   └── vuln_scanner.py
├── utils/
│   ├── __init__.py
│   ├── db.py
│   └── logger.py
└── reports/              ← auto-created on first scan
```

---

## 🚀 Usage

### Full Scan

Run all modules against a target in one command:

```bash
python3 main.py scan https://target.com
```

**With options:**

```bash
python3 main.py scan https://target.com [OPTIONS]

Options:
  -o, --output    PATH      Output directory for reports     [default: ./reports]
  -t, --threads   INT       Number of concurrent threads     [default: 10]
  -w, --wordlist  PATH      Custom subdomain wordlist
  -f, --format    TEXT      Report format: html, json, txt   [default: html]
  -v, --verbose             Show detailed output
  --skip-subdomains         Skip subdomain enumeration
  --skip-vuln               Skip vulnerability scanning
  --skip-auth               Skip authentication testing
  --skip-api                Skip API security testing
```

---

### Subdomain Enumeration

```bash
python3 main.py subdomains <DOMAIN> [OPTIONS]

Options:
  -t, --threads   INT   Concurrent threads          [default: 20]
  -w, --wordlist  PATH  Custom wordlist file
  -o, --output    PATH  Save results to file
  -v, --verbose         Show each resolution attempt
```

**Example:**
```bash
python3 main.py subdomains target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -o subs.txt
```

---

### Vulnerability Scanner

```bash
python3 main.py vuln <URL> [OPTIONS]

Options:
  -t, --threads   INT   Concurrent threads   [default: 10]
  -v, --verbose         Show all test attempts

Vulnerability Checks:
  ✦ SQL Injection (error-based + time-based)
  ✦ Cross-Site Scripting (reflected)
  ✦ Open Redirect
  ✦ Server-Side Request Forgery (SSRF)
  ✦ Path Traversal
  ✦ Command Injection
  ✦ CORS Misconfiguration
  ✦ Clickjacking
```

**Example:**
```bash
python3 main.py vuln https://target.com -t 15 -v
```

---

### Security Headers

```bash
python3 main.py headers <URL> [OPTIONS]

Options:
  -v, --verbose   Show all header details

Headers Checked:
  ✦ Strict-Transport-Security (HSTS)
  ✦ Content-Security-Policy (CSP)
  ✦ X-Frame-Options
  ✦ X-Content-Type-Options
  ✦ Referrer-Policy
  ✦ Permissions-Policy
  ✦ Cross-Origin-Opener-Policy (COOP)
  ✦ Cross-Origin-Resource-Policy (CORP)
  ✦ Cross-Origin-Embedder-Policy (COEP)
  ✦ X-XSS-Protection
  ✦ Cookie flags (HttpOnly, Secure, SameSite)
  ✦ Information disclosure (Server, X-Powered-By)
```

**Example:**
```bash
python3 main.py headers https://target.com -v
```

---

### Web Fingerprinting

```bash
python3 main.py fingerprint <URL> [OPTIONS]

Options:
  -v, --verbose   Show all path probe attempts

Detects:
  ✦ CMS: WordPress, Drupal, Joomla, Magento, Shopify
  ✦ Frameworks: Laravel, Django, Rails, React, Angular, Vue, Next.js
  ✦ WAF: Cloudflare, Akamai, Imperva, Sucuri, ModSecurity, F5, Barracuda
  ✦ 40+ sensitive exposed paths
```

**Example:**
```bash
python3 main.py fingerprint https://target.com -v
```

---

### Authentication Testing

Run auth-only by skipping other modules:

```bash
python3 main.py scan https://target.com --skip-subdomains --skip-vuln --skip-api

Tests:
  ✦ 20 default credential pairs
  ✦ JWT algorithm:none attack
  ✦ JWT weak secret brute-force (16 common secrets)
  ✦ JWT missing expiration claim
  ✦ Sensitive data in JWT payload
  ✦ Session ID entropy analysis
  ✦ Brute force rate-limit detection
  ✦ CAPTCHA bypass detection
```

---

### API Security Testing

```bash
python3 main.py api <URL> [OPTIONS]

Options:
  -s, --spec  URL/PATH   OpenAPI/Swagger spec URL or local path
  -v, --verbose          Show all test details

Tests:
  ✦ Auto-discover Swagger/OpenAPI docs
  ✦ IDOR via ID enumeration
  ✦ GraphQL introspection
  ✦ Mass assignment (privilege escalation)
  ✦ Unauthenticated endpoint access
  ✦ Broken authentication (invalid tokens)
  ✦ Verbose error message leakage
```

**Examples:**
```bash
python3 main.py api https://target.com
python3 main.py api https://target.com -s https://target.com/swagger.json -v
```

---

### List Past Scans

```bash
python3 main.py list-scans
```

Displays a table of all previous scans with target URL, date, and total finding count. Scan data is persisted in `~/.webrecon/scans.db`.

---

## 📋 Command Reference

| Command | Description |
|---|---|
| `scan <url>` | Full pentest — runs all modules |
| `scan <url> --skip-subdomains` | Skip subdomain enumeration phase |
| `scan <url> --skip-vuln` | Skip vulnerability scanning phase |
| `scan <url> --skip-auth` | Skip authentication testing phase |
| `scan <url> --skip-api` | Skip API security testing phase |
| `scan <url> -t 30` | Set thread count to 30 |
| `scan <url> -f json` | Export report as JSON |
| `scan <url> -f txt` | Export report as plain text |
| `scan <url> -o ~/reports/` | Save report to custom directory |
| `scan <url> -v` | Enable verbose output |
| `scan <url> -w wordlist.txt` | Use custom subdomain wordlist |
| `subdomains <domain>` | Subdomain enumeration only |
| `subdomains <domain> -t 50` | Subdomain enum with 50 threads |
| `subdomains <domain> -o out.txt` | Save subdomains to file |
| `vuln <url>` | Vulnerability scan only |
| `vuln <url> -v` | Verbose vulnerability scan |
| `headers <url>` | Security headers check only |
| `fingerprint <url>` | Technology fingerprinting only |
| `api <url>` | API security test only |
| `api <url> -s /swagger.json` | API test with custom spec |
| `list-scans` | Show all past scans |

---

## 📊 Report Formats

### HTML Report (Default)
A full dark-themed, professional security report saved to `./reports/`. Open in any browser.

```bash
python3 main.py scan https://target.com -f html -o ~/Desktop/reports/
```

Includes:
- Executive summary with risk score
- Severity-color-coded finding cards
- Fingerprinting results
- Full subdomain table
- Remediation guidance per finding

### JSON Report
Machine-readable export for integration with other tools or ticketing systems.

```bash
python3 main.py scan https://target.com -f json
```

### Plain Text Report
Minimal output for quick review or piping to other tools.

```bash
python3 main.py scan https://target.com -f txt
```

---

## 💡 Real-World Examples

```bash
# Quick recon only — fast, no vuln scanning
python3 main.py scan https://target.com --skip-vuln --skip-auth --skip-api -t 30

# Deep vulnerability scan on a known live target
python3 main.py scan https://target.com --skip-subdomains -v -t 15

# API-focused pentest (REST/GraphQL audit)
python3 main.py scan https://target.com --skip-subdomains --skip-auth -v

# Full professional engagement — JSON output, high threads
python3 main.py scan https://target.com -f json -o ~/Desktop/reports/ -t 20 -v

# Subdomain hunt with SecLists wordlist
python3 main.py subdomains target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 100 -o subs.txt

# Auth test only — check for default creds and JWT issues
python3 main.py scan https://target.com \
  --skip-subdomains --skip-vuln --skip-api -v

# Stealth scan — low threads to avoid detection
python3 main.py scan https://target.com -t 2 -f html

# Check API with known Swagger spec
python3 main.py api https://target.com -s https://target.com/api/swagger.json -v

# Headers audit only — quick security posture check
python3 main.py headers https://target.com
```

---

## 🧪 Legal Practice Targets

The following are **intentionally vulnerable** practice environments where you can legally use WebRecon Pro:

| Target | Description | URL |
|---|---|---|
| **DVWA** | Damn Vulnerable Web App (local) | `http://localhost/dvwa` |
| **VulnWeb** | Acunetix test site | `http://testphp.vulnweb.com` |
| **HackTheBox** | Professional CTF labs | `https://hackthebox.com` |
| **TryHackMe** | Beginner-friendly labs | `https://tryhackme.com` |
| **PortSwigger Web Academy** | Web vuln labs | `https://portswigger.net/web-security` |
| **OWASP Juice Shop** | Intentionally vulnerable app | Local Docker |
| **bWAPP** | Buggy Web Application | Local setup |

**Quick test:**
```bash
python3 main.py scan http://testphp.vulnweb.com -v --skip-subdomains
```

---

## 🛠️ Dependencies

| Package | Version | Purpose |
|---|---|---|
| `typer` | Latest | CLI framework |
| `rich` | Latest | Terminal UI, tables, progress bars |
| `httpx` | Latest | Async HTTP client |
| `beautifulsoup4` | Latest | HTML parsing for form extraction |

Install all:
```bash
pip3 install typer rich httpx beautifulsoup4 --break-system-packages
```

---

## ⚖️ Legal Disclaimer

```
WebRecon Pro is intended for legal security testing and educational purposes only.

You are solely responsible for ensuring that you have explicit written authorization
from the system owner before running any tests. Unauthorized scanning, probing, or
testing of computer systems is a criminal offense in most jurisdictions, including
under the Computer Fraud and Abuse Act (CFAA) in the USA, the Computer Misuse Act
in the UK, and similar laws worldwide.

The developers of WebRecon Pro assume NO liability and are NOT responsible for any
misuse, damage, or illegal activity conducted with this tool.

By using this tool, you agree that:
  1. You own the target system OR have explicit written permission to test it.
  2. You will not use this tool for any illegal or unauthorized activities.
  3. You take full responsibility for your actions.
```

---

<div align="center">

**WebRecon Pro v1.0.0**  
Built for Kali Linux · Python 3.9+ · For Authorized Use Only

</div>
