#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  WebRecon Pro — Professional Web Penetration Testing Framework   ║
║  Version  : 1.0.0                                                ║
║  Author   : HackOps Academy                                      ║
║  GitHub   : github.com/hackops-academy/webrecon-pro              ║
║  License  : MIT                                                  ║
╚══════════════════════════════════════════════════════════════════╝
FOR AUTHORIZED PENETRATION TESTING ONLY
"""

import asyncio
import sys
import os
from datetime import datetime
from pathlib import Path

# Always resolve modules relative to this file
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.text import Text
from rich.padding import Padding
from rich import box
from rich.rule import Rule

from modules.subdomain_enum import SubdomainEnumerator
from modules.fingerprint import WebFingerprinter
from modules.vuln_scanner import VulnerabilityScanner
from modules.auth_tester import AuthTester
from modules.api_tester import APITester
from modules.reporter import ReportGenerator
from modules.header_checker import HeaderChecker
from utils.db import Database
from utils.logger import setup_logger

console = Console()
logger  = setup_logger()

# ─────────────────────────────────────────────────────────────────────────────
app = typer.Typer(
    name="webrecon",
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=False,   # We handle --help ourselves for full control
    rich_markup_mode="rich",
)

# ─────────────────────────────────────────────────────────────────────────────
BANNER = """\
██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ 
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝"""


def print_banner():
    console.print(f"\n[bold red]{BANNER}[/bold red]")
    console.print(Panel(
        "[bold green]v1.0.0[/bold green]  [dim]│[/dim]  "
        "[cyan]Professional Web Penetration Testing Framework[/cyan]  "
        "[dim]│[/dim]  [yellow]⚠  Authorized Testing Only[/yellow]  "
        "[dim]│[/dim]  [dim]github.com/hackops-academy/webrecon-pro[/dim]",
        border_style="red",
        padding=(0, 2),
    ))
    console.print()


def print_help():
    """Print the full beautiful help menu."""
    print_banner()

    # ── Description ──────────────────────────────────────────────────────────
    console.print(Panel(
        "[white]WebRecon Pro is a modular, async web penetration testing framework.\n"
        "It combines recon, fingerprinting, vulnerability scanning, auth testing\n"
        "and API auditing into one tool with professional HTML/JSON/TXT reports.[/white]",
        title="[bold cyan]About[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()

    # ── Commands table ────────────────────────────────────────────────────────
    cmd_table = Table(
        box=box.ROUNDED,
        border_style="red",
        show_header=True,
        header_style="bold red",
        title="[bold red]⚡ Commands[/bold red]",
        title_justify="left",
        padding=(0, 1),
        min_width=80,
    )
    cmd_table.add_column("Command",     style="bold cyan",  min_width=18, no_wrap=True)
    cmd_table.add_column("Description", style="white",      min_width=45)
    cmd_table.add_column("Example",     style="dim yellow", min_width=30)

    cmd_table.add_row(
        "scan",
        "Full pentest — runs ALL modules in sequence",
        "webrecon scan https://target.com",
    )
    cmd_table.add_row(
        "headers",
        "Security headers check + cookie audit + score",
        "webrecon headers https://target.com",
    )
    cmd_table.add_row(
        "vuln",
        "Vulnerability scan: SQLi, XSS, SSRF, CORS, etc.",
        "webrecon vuln https://target.com",
    )
    cmd_table.add_row(
        "subdomains",
        "Subdomain enum via DNS brute-force + crt.sh",
        "webrecon subdomains target.com",
    )
    cmd_table.add_row(
        "fingerprint",
        "Detect CMS, WAF, frameworks, sensitive paths",
        "webrecon fingerprint https://target.com",
    )
    cmd_table.add_row(
        "api",
        "API security: IDOR, GraphQL, mass assignment",
        "webrecon api https://target.com",
    )
    cmd_table.add_row(
        "list-scans",
        "View all previous scans from local database",
        "webrecon list-scans",
    )
    console.print(cmd_table)
    console.print()

    # ── scan flags ────────────────────────────────────────────────────────────
    scan_table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="yellow",
        show_header=True,
        header_style="bold yellow",
        title="[bold yellow]🔍 scan — Flags[/bold yellow]",
        title_justify="left",
        padding=(0, 1),
        min_width=80,
    )
    scan_table.add_column("Flag",         style="bold green", min_width=22, no_wrap=True)
    scan_table.add_column("Short", style="cyan",        min_width=6,  no_wrap=True)
    scan_table.add_column("Default",      style="dim",         min_width=12)
    scan_table.add_column("Description",  style="white",       min_width=38)

    scan_table.add_row("--output",          "-o", "./reports", "Directory to save the report")
    scan_table.add_row("--threads",         "-t", "10",        "Number of concurrent threads")
    scan_table.add_row("--wordlist",        "-w", "built-in",  "Custom subdomain wordlist path")
    scan_table.add_row("--format",          "-f", "html",      "Report format: html | json | txt")
    scan_table.add_row("--verbose",         "-v", "off",       "Show detailed output for all phases")
    scan_table.add_row("--skip-subdomains", "—",  "off",       "Skip subdomain enumeration phase")
    scan_table.add_row("--skip-vuln",       "—",  "off",       "Skip vulnerability scanning phase")
    scan_table.add_row("--skip-auth",       "—",  "off",       "Skip authentication testing phase")
    scan_table.add_row("--skip-api",        "—",  "off",       "Skip API security testing phase")
    console.print(scan_table)
    console.print()

    # ── Other commands flags ──────────────────────────────────────────────────
    other_table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        title="[bold cyan]🔧 Other Commands — Flags[/bold cyan]",
        title_justify="left",
        padding=(0, 1),
        min_width=80,
    )
    other_table.add_column("Command",    style="bold cyan",  min_width=16, no_wrap=True)
    other_table.add_column("Flag",       style="bold green", min_width=20, no_wrap=True)
    other_table.add_column("Short", style="cyan",       min_width=6,  no_wrap=True)
    other_table.add_column("Default",   style="dim",        min_width=12)
    other_table.add_column("Description",style="white",      min_width=30)

    other_table.add_row("subdomains", "--threads",  "-t", "20",       "Concurrent DNS resolution threads")
    other_table.add_row("subdomains", "--wordlist", "-w", "built-in", "Custom wordlist file path")
    other_table.add_row("subdomains", "--output",   "-o", "none",     "Save subdomain list to file")
    other_table.add_row("subdomains", "--verbose",  "-v", "off",      "Show every resolution attempt")
    other_table.add_row("─────────", "──────────", "─",  "───────",  "────────────────────────────────")
    other_table.add_row("vuln",      "--threads",  "-t", "10",       "Concurrent request threads")
    other_table.add_row("vuln",      "--verbose",  "-v", "off",      "Show all payloads being tested")
    other_table.add_row("─────────", "──────────", "─",  "───────",  "────────────────────────────────")
    other_table.add_row("headers",   "--verbose",  "-v", "off",      "Show full header value details")
    other_table.add_row("─────────", "──────────", "─",  "───────",  "────────────────────────────────")
    other_table.add_row("fingerprint","--verbose", "-v", "off",      "Show every path probe attempt")
    other_table.add_row("─────────", "──────────", "─",  "───────",  "────────────────────────────────")
    other_table.add_row("api",       "--spec",     "-s", "auto",     "OpenAPI/Swagger spec URL or path")
    other_table.add_row("api",       "--verbose",  "-v", "off",      "Show all API test details")
    console.print(other_table)
    console.print()

    # ── Examples ──────────────────────────────────────────────────────────────
    examples_panel = Panel(
        "[dim]# Full scan with verbose output and 20 threads[/dim]\n"
        "[bold green]webrecon scan https://target.com -v -t 20[/bold green]\n\n"
        "[dim]# Full scan — save JSON report to custom folder[/dim]\n"
        "[bold green]webrecon scan https://target.com -f json -o ~/reports[/bold green]\n\n"
        "[dim]# Fast scan — skip subdomains (slowest phase)[/dim]\n"
        "[bold green]webrecon scan https://target.com --skip-subdomains -t 30[/bold green]\n\n"
        "[dim]# Quick recon only — no vuln/auth/api scanning[/dim]\n"
        "[bold green]webrecon scan https://target.com --skip-vuln --skip-auth --skip-api[/bold green]\n\n"
        "[dim]# Subdomain enum with SecLists wordlist[/dim]\n"
        "[bold green]webrecon subdomains target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 100[/bold green]\n\n"
        "[dim]# Vulnerability scan only — verbose[/dim]\n"
        "[bold green]webrecon vuln https://target.com -v -t 15[/bold green]\n\n"
        "[dim]# Check security headers only[/dim]\n"
        "[bold green]webrecon headers https://target.com -v[/bold green]\n\n"
        "[dim]# API test with a known Swagger spec[/dim]\n"
        "[bold green]webrecon api https://target.com -s https://target.com/swagger.json -v[/bold green]\n\n"
        "[dim]# Practice on legal targets[/dim]\n"
        "[bold green]webrecon scan http://testphp.vulnweb.com --skip-subdomains -v[/bold green]",
        title="[bold green]💡 Examples[/bold green]",
        border_style="green",
        padding=(1, 2),
    )
    console.print(examples_panel)
    console.print()

    # ── Modules info ──────────────────────────────────────────────────────────
    modules_table = Table(
        box=box.ROUNDED,
        border_style="dim",
        show_header=True,
        header_style="bold white",
        title="[bold white]🧩 What Each Module Detects[/bold white]",
        title_justify="left",
        padding=(0, 1),
        min_width=80,
    )
    modules_table.add_column("Module",   style="bold cyan", min_width=16, no_wrap=True)
    modules_table.add_column("Detects",  style="white",     min_width=64)

    modules_table.add_row(
        "headers",
        "HSTS · CSP · X-Frame-Options · X-Content-Type-Options · Referrer-Policy · "
        "Permissions-Policy · COOP · CORP · COEP · Cookie flags · Info disclosure headers"
    )
    modules_table.add_row(
        "subdomains",
        "DNS brute-force (100+ built-in words) · Certificate Transparency (crt.sh) · "
        "Live host detection · IP resolution · HTTP status checking"
    )
    modules_table.add_row(
        "fingerprint",
        "CMS: WordPress/Drupal/Joomla/Magento/Shopify · "
        "WAF: Cloudflare/Akamai/Imperva/Sucuri/ModSecurity/F5 · "
        "Frameworks: React/Angular/Vue/Laravel/Django/Rails · "
        "40+ sensitive paths: .env/.git/backup/phpinfo/admin"
    )
    modules_table.add_row(
        "vuln",
        "SQL Injection (error+time based) · XSS (reflected) · Open Redirect · "
        "SSRF (AWS/GCP metadata) · Path Traversal · Command Injection · "
        "CORS Misconfiguration · Clickjacking"
    )
    modules_table.add_row(
        "auth",
        "Default credentials (20 pairs) · JWT: alg:none / weak secret / no expiry / "
        "sensitive payload · Session ID entropy · Brute-force protection · CAPTCHA detection"
    )
    modules_table.add_row(
        "api",
        "Swagger/OpenAPI exposure · IDOR via ID enumeration · GraphQL introspection · "
        "Mass assignment (privilege escalation) · Broken auth · Unauthenticated access · "
        "Verbose error leakage"
    )
    console.print(modules_table)
    console.print()

    # ── Reports ───────────────────────────────────────────────────────────────
    console.print(Panel(
        "[bold]HTML[/bold]  [cyan]--format html[/cyan]  [dim](default)[/dim] — "
        "Dark-themed professional report with severity cards, open in any browser\n"
        "[bold]JSON[/bold]  [cyan]--format json[/cyan]              — "
        "Machine-readable export, integrate with other tools or ticketing systems\n"
        "[bold]TXT [/bold]  [cyan]--format txt [/cyan]              — "
        "Plain text summary for quick review or piping to other tools\n\n"
        "[dim]Reports saved to:[/dim] [yellow]./reports/[/yellow]  "
        "[dim]  History DB at:[/dim] [yellow]~/.webrecon/scans.db[/yellow]",
        title="[bold magenta]📄 Report Formats[/bold magenta]",
        border_style="magenta",
        padding=(0, 2),
    ))
    console.print()

    # ── Legal ─────────────────────────────────────────────────────────────────
    console.print(Panel(
        "[bold red]⚠  FOR AUTHORIZED PENETRATION TESTING ONLY[/bold red]\n"
        "[dim]Only use this tool on systems you own or have explicit written permission to test.\n"
        "Unauthorized scanning is illegal under CFAA, Computer Misuse Act, and similar laws.[/dim]\n\n"
        "[dim]Safe practice targets:[/dim]\n"
        "  [cyan]http://testphp.vulnweb.com[/cyan]   [dim]Acunetix test site[/dim]\n"
        "  [cyan]https://hackthebox.com[/cyan]       [dim]Professional CTF labs[/dim]\n"
        "  [cyan]https://tryhackme.com[/cyan]        [dim]Beginner-friendly labs[/dim]\n"
        "  [cyan]http://localhost/dvwa[/cyan]        [dim]DVWA — local vulnerable app[/dim]",
        title="[bold red]⚖  Legal Notice[/bold red]",
        border_style="red",
        padding=(0, 2),
    ))
    console.print()


def normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


# ─────────────────────────────────────────────────────────────────────────────
# Root callback — show full help when no command given or --help passed
# ─────────────────────────────────────────────────────────────────────────────
@app.callback()
def root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit", is_eager=True),
):
    if version:
        console.print("[bold green]WebRecon Pro[/bold green] [cyan]v1.0.0[/cyan]")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        print_help()
        raise typer.Exit()


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: scan
# ══════════════════════════════════════════════════════════════════════════════
@app.command("scan", help="Run a full penetration test — all modules — against the target.")
def full_scan(
    target:          str  = typer.Argument(...,        metavar="TARGET", help="Target URL  e.g. https://example.com"),
    output:          str  = typer.Option("./reports",  "--output",          "-o",  help="Directory to save reports  [default: ./reports]"),
    threads:         int  = typer.Option(10,           "--threads",         "-t",  help="Concurrent threads  [default: 10]"),
    wordlist:        str  = typer.Option(None,         "--wordlist",        "-w",  help="Custom subdomain wordlist path"),
    report_format:   str  = typer.Option("html",       "--format",          "-f",  help="Report format: html | json | txt  [default: html]"),
    verbose:         bool = typer.Option(False,        "--verbose",         "-v",  help="Show detailed output for all phases"),
    skip_subdomains: bool = typer.Option(False,        "--skip-subdomains",        help="Skip subdomain enumeration phase"),
    skip_vuln:       bool = typer.Option(False,        "--skip-vuln",              help="Skip vulnerability scanning phase"),
    skip_auth:       bool = typer.Option(False,        "--skip-auth",              help="Skip authentication testing phase"),
    skip_api:        bool = typer.Option(False,        "--skip-api",               help="Skip API security testing phase"),
):
    print_banner()
    target = normalize_url(target)

    # Print scan config
    config = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    config.add_column(style="bold green", min_width=12)
    config.add_column(style="cyan")
    config.add_row("🎯 Target",   target)
    config.add_row("📁 Output",   output)
    config.add_row("🧵 Threads",  str(threads))
    config.add_row("📄 Format",   report_format)
    config.add_row("🔍 Verbose",  "yes" if verbose else "no")
    skipped = []
    if skip_subdomains: skipped.append("subdomains")
    if skip_vuln:       skipped.append("vuln")
    if skip_auth:       skipped.append("auth")
    if skip_api:        skipped.append("api")
    if skipped:
        config.add_row("⏭  Skipping", ", ".join(skipped))
    console.print(Panel(config, title="[bold yellow]Scan Configuration[/bold yellow]", border_style="yellow"))
    console.print()

    db      = Database()
    scan_id = db.create_scan(target)

    results = {
        "target":          target,
        "scan_id":         scan_id,
        "start_time":      datetime.now().isoformat(),
        "subdomains":      [],
        "fingerprint":     {},
        "vulnerabilities": [],
        "auth_findings":   [],
        "api_findings":    [],
        "header_findings": [],
    }

    asyncio.run(_run_full_scan(
        target, results, db, scan_id, threads, wordlist,
        skip_subdomains, skip_vuln, skip_auth, skip_api,
        verbose, output, report_format,
    ))


async def _run_full_scan(
    target, results, db, scan_id, threads, wordlist,
    skip_subdomains, skip_vuln, skip_auth, skip_api,
    verbose, output, report_format,
):
    # Phase 1 — Headers
    console.rule("[bold yellow]🔍 Phase 1 of 6 — Security Headers Analysis[/bold yellow]")
    checker = HeaderChecker(target, verbose=verbose)
    results["header_findings"] = await checker.check_all()
    db.save_findings(scan_id, "headers", results["header_findings"])

    # Phase 2 — Subdomains
    if not skip_subdomains:
        console.rule("[bold yellow]🌐 Phase 2 of 6 — Subdomain Enumeration[/bold yellow]")
        enumerator = SubdomainEnumerator(target, threads=threads, wordlist=wordlist, verbose=verbose)
        results["subdomains"] = await enumerator.enumerate()
        db.save_findings(scan_id, "subdomains", results["subdomains"])
    else:
        console.print("[dim]⏭  Phase 2 — Subdomain Enumeration skipped[/dim]")

    # Phase 3 — Fingerprint
    console.rule("[bold yellow]🔎 Phase 3 of 6 — Web Fingerprinting[/bold yellow]")
    fp = WebFingerprinter(target, verbose=verbose)
    results["fingerprint"] = await fp.fingerprint()
    db.save_findings(scan_id, "fingerprint", [results["fingerprint"]])

    # Phase 4 — Vulns
    if not skip_vuln:
        console.rule("[bold yellow]💥 Phase 4 of 6 — Vulnerability Scanning[/bold yellow]")
        scanner = VulnerabilityScanner(target, threads=threads, verbose=verbose)
        results["vulnerabilities"] = await scanner.scan_all()
        db.save_findings(scan_id, "vulnerabilities", results["vulnerabilities"])
    else:
        console.print("[dim]⏭  Phase 4 — Vulnerability Scanning skipped[/dim]")

    # Phase 5 — Auth
    if not skip_auth:
        console.rule("[bold yellow]🔐 Phase 5 of 6 — Authentication Testing[/bold yellow]")
        auth = AuthTester(target, verbose=verbose)
        results["auth_findings"] = await auth.test_all()
        db.save_findings(scan_id, "auth", results["auth_findings"])
    else:
        console.print("[dim]⏭  Phase 5 — Authentication Testing skipped[/dim]")

    # Phase 6 — API
    if not skip_api:
        console.rule("[bold yellow]🔌 Phase 6 of 6 — API Security Testing[/bold yellow]")
        api = APITester(target, verbose=verbose)
        results["api_findings"] = await api.test_all()
        db.save_findings(scan_id, "api", results["api_findings"])
    else:
        console.print("[dim]⏭  Phase 6 — API Security Testing skipped[/dim]")

    # Report
    console.rule("[bold green]📊 Generating Report[/bold green]")
    results["end_time"] = datetime.now().isoformat()
    reporter    = ReportGenerator(results, output_dir=output)
    report_path = reporter.generate(format=report_format)

    _print_summary(results, report_path)
    db.complete_scan(scan_id)


def _print_summary(results, report_path):
    console.print()
    console.rule("[bold green]✅ Scan Complete[/bold green]")

    vulns    = results.get("vulnerabilities", [])
    critical = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high     = sum(1 for v in vulns if v.get("severity") == "HIGH")
    medium   = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    low      = sum(1 for v in vulns if v.get("severity") == "LOW")

    t = Table(
        title="Scan Summary",
        box=box.DOUBLE_EDGE,
        border_style="green",
        show_lines=True,
        min_width=55,
    )
    t.add_column("Category",  style="cyan",  min_width=26)
    t.add_column("Count",     style="white", justify="center", min_width=8)
    t.add_column("Details",   style="dim",   min_width=26)

    t.add_row("Subdomains Found",      str(len(results.get("subdomains", []))),      "Active hosts discovered")
    t.add_row("Total Vulnerabilities", str(len(vulns)),                               "All severity levels")
    t.add_row("[bold red]🔴 Critical[/bold red]",   str(critical), "Immediate action required")
    t.add_row("[red]🟠 High[/red]",                 str(high),     "High priority fixes")
    t.add_row("[yellow]🟡 Medium[/yellow]",         str(medium),   "Should be addressed")
    t.add_row("[cyan]🟢 Low[/cyan]",                str(low),      "Best practice improvements")
    t.add_row("Header Issues",         str(len(results.get("header_findings", []))), "Security header misconfigs")
    t.add_row("Auth Findings",         str(len(results.get("auth_findings", []))),   "Authentication issues")
    t.add_row("API Findings",          str(len(results.get("api_findings", []))),    "API security issues")

    console.print(t)
    console.print(f"\n[bold green]📄 Report:[/bold green] [cyan]{report_path}[/cyan]")
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: subdomains
# ══════════════════════════════════════════════════════════════════════════════
@app.command("subdomains", help="Enumerate subdomains via DNS brute-force and certificate transparency.")
def enum_subdomains(
    target:   str  = typer.Argument(...,        metavar="DOMAIN",  help="Target domain  e.g. example.com"),
    threads:  int  = typer.Option(20,           "--threads",  "-t", help="Concurrent DNS threads  [default: 20]"),
    wordlist: str  = typer.Option(None,         "--wordlist", "-w", help="Custom wordlist file path"),
    output:   str  = typer.Option(None,         "--output",   "-o", help="Save results to a file"),
    verbose:  bool = typer.Option(False,        "--verbose",  "-v", help="Show each resolution attempt"),
):
    print_banner()
    asyncio.run(_run_subdomains(target, threads, wordlist, output, verbose))


async def _run_subdomains(target, threads, wordlist, output, verbose):
    target     = normalize_url(target)
    enumerator = SubdomainEnumerator(target, threads=threads, wordlist=wordlist, verbose=verbose)
    subdomains = await enumerator.enumerate()
    if output:
        with open(output, "w") as f:
            for s in subdomains:
                f.write(f"{s['subdomain']}\t{s['ip']}\t{s['status']}\n")
        console.print(f"[green]✓ Saved to {output}[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: vuln
# ══════════════════════════════════════════════════════════════════════════════
@app.command("vuln", help="Scan for web vulnerabilities: SQLi, XSS, SSRF, CORS, Path Traversal and more.")
def vuln_scan(
    target:  str  = typer.Argument(...,   metavar="TARGET", help="Target URL  e.g. https://example.com"),
    threads: int  = typer.Option(10,      "--threads", "-t", help="Concurrent threads  [default: 10]"),
    verbose: bool = typer.Option(False,   "--verbose", "-v", help="Show all payloads being tested"),
):
    print_banner()
    asyncio.run(_run_vulns(target, threads, verbose))


async def _run_vulns(target, threads, verbose):
    target  = normalize_url(target)
    scanner = VulnerabilityScanner(target, threads=threads, verbose=verbose)
    await scanner.scan_all()


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: headers
# ══════════════════════════════════════════════════════════════════════════════
@app.command("headers", help="Analyse HTTP security headers and score the target's security posture.")
def check_headers(
    target:  str  = typer.Argument(...,  metavar="TARGET", help="Target URL  e.g. https://example.com"),
    verbose: bool = typer.Option(False,  "--verbose", "-v", help="Show full header values"),
):
    print_banner()
    asyncio.run(_run_headers(target, verbose))


async def _run_headers(target, verbose):
    target  = normalize_url(target)
    checker = HeaderChecker(target, verbose=verbose)
    await checker.check_all()


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: fingerprint
# ══════════════════════════════════════════════════════════════════════════════
@app.command("fingerprint", help="Detect CMS, WAF, frameworks, server tech and exposed sensitive files.")
def fingerprint_target(
    target:  str  = typer.Argument(...,  metavar="TARGET", help="Target URL  e.g. https://example.com"),
    verbose: bool = typer.Option(False,  "--verbose", "-v", help="Show every path probe attempt"),
):
    print_banner()
    asyncio.run(_run_fingerprint(target, verbose))


async def _run_fingerprint(target, verbose):
    target = normalize_url(target)
    fp     = WebFingerprinter(target, verbose=verbose)
    await fp.fingerprint()


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: api
# ══════════════════════════════════════════════════════════════════════════════
@app.command("api", help="Test API security: IDOR, GraphQL introspection, mass assignment, broken auth.")
def api_test(
    target:  str  = typer.Argument(...,   metavar="TARGET", help="Target URL  e.g. https://example.com"),
    spec:    str  = typer.Option(None,    "--spec",    "-s", help="OpenAPI/Swagger spec URL or local file path"),
    verbose: bool = typer.Option(False,   "--verbose", "-v", help="Show all API test details"),
):
    print_banner()
    asyncio.run(_run_api(target, spec, verbose))


async def _run_api(target, spec, verbose):
    target = normalize_url(target)
    tester = APITester(target, spec_url=spec, verbose=verbose)
    await tester.test_all()


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: list-scans
# ══════════════════════════════════════════════════════════════════════════════
@app.command("list-scans", help="Display all previous scans stored in the local database (~/.webrecon/scans.db).")
def list_scans():
    print_banner()
    db    = Database()
    scans = db.get_all_scans()

    if not scans:
        console.print(Panel(
            "[yellow]No previous scans found.[/yellow]\n\n"
            "Run your first scan:\n"
            "[bold green]webrecon scan https://target.com[/bold green]",
            border_style="yellow",
        ))
        return

    t = Table(
        title=f"Scan History  ({len(scans)} scans)",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
    )
    t.add_column("ID",       style="dim",    justify="center", min_width=5)
    t.add_column("Target",   style="cyan",   min_width=35)
    t.add_column("Date",     style="green",  min_width=20)
    t.add_column("Findings", style="yellow", justify="center", min_width=10)

    for scan in scans:
        t.add_row(
            str(scan["id"]),
            scan["target"],
            scan["created_at"][:19].replace("T", " "),
            str(scan["finding_count"]),
        )
    console.print(t)


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app()
