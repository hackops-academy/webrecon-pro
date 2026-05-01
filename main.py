#!/usr/bin/env python3
import asyncio, sys, os
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Intercept --help and no-args BEFORE typer loads
if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ("--help", "-h")):
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    console = Console()

    BANNER = """\
██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ 
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝"""

    console.print(f"\n[bold red]{BANNER}[/bold red]")
    console.print(Panel(
        "[bold green]v1.0.0[/bold green]  [dim]│[/dim]  [cyan]Professional Web Penetration Testing Framework[/cyan]  [dim]│[/dim]  [yellow]⚠  Authorized Testing Only[/yellow]  [dim]│[/dim]  [dim]github.com/hackops-academy/webrecon-pro[/dim]",
        border_style="red", padding=(0, 2),
    ))
    console.print()

    console.print(Panel(
        "[white]WebRecon Pro is a modular async web penetration testing framework.\n"
        "Combines recon · fingerprinting · vuln scanning · auth testing · API auditing\n"
        "into one tool with professional HTML / JSON / TXT reports.[/white]",
        title="[bold cyan]About[/bold cyan]", border_style="cyan", padding=(0, 2),
    ))
    console.print()

    # Commands table
    cmd = Table(box=box.ROUNDED, border_style="red", header_style="bold red",
                title="[bold red]⚡ Commands[/bold red]", title_justify="left",
                padding=(0, 1), min_width=90, show_lines=True)
    cmd.add_column("Command",     style="bold cyan",  min_width=14, no_wrap=True)
    cmd.add_column("Description", style="white",      min_width=48)
    cmd.add_column("Quick Example", style="dim yellow", min_width=38)
    cmd.add_row("scan",        "Full pentest — runs ALL 6 modules in sequence",        "webrecon scan https://target.com")
    cmd.add_row("headers",     "Security headers check + cookie audit + score/100",    "webrecon headers https://target.com")
    cmd.add_row("vuln",        "SQLi · XSS · SSRF · CORS · Path Traversal · CMDi",    "webrecon vuln https://target.com")
    cmd.add_row("subdomains",  "DNS brute-force + certificate transparency (crt.sh)",  "webrecon subdomains target.com")
    cmd.add_row("fingerprint", "CMS · WAF · Frameworks · 40+ sensitive path checks",  "webrecon fingerprint https://target.com")
    cmd.add_row("api",         "IDOR · GraphQL · Mass assignment · Broken auth",       "webrecon api https://target.com")
    cmd.add_row("list-scans",  "View all previous scans from local database",          "webrecon list-scans")
    console.print(cmd)
    console.print()

    # Scan flags
    sf = Table(box=box.SIMPLE_HEAVY, border_style="yellow", header_style="bold yellow",
               title="[bold yellow]🔍 webrecon scan — All Flags[/bold yellow]",
               title_justify="left", padding=(0, 1), min_width=90, show_lines=True)
    sf.add_column("Flag",              style="bold green", min_width=22, no_wrap=True)
    sf.add_column("Short",             style="cyan",       min_width=6,  no_wrap=True)
    sf.add_column("Default",           style="dim",        min_width=12)
    sf.add_column("Description",       style="white",      min_width=40)
    sf.add_row("--output PATH",        "-o", "./reports",  "Directory to save the HTML/JSON/TXT report")
    sf.add_row("--threads INT",        "-t", "10",         "Number of concurrent threads")
    sf.add_row("--wordlist PATH",      "-w", "built-in",   "Custom subdomain wordlist file")
    sf.add_row("--format [html|json|txt]","-f","html",     "Report output format")
    sf.add_row("--verbose",            "-v", "off",        "Show detailed output for every phase")
    sf.add_row("--skip-subdomains",    "—",  "off",        "Skip subdomain enumeration phase")
    sf.add_row("--skip-vuln",          "—",  "off",        "Skip vulnerability scanning phase")
    sf.add_row("--skip-auth",          "—",  "off",        "Skip authentication testing phase")
    sf.add_row("--skip-api",           "—",  "off",        "Skip API security testing phase")
    console.print(sf)
    console.print()

    # Other command flags
    of = Table(box=box.SIMPLE_HEAVY, border_style="cyan", header_style="bold cyan",
               title="[bold cyan]🔧 Other Commands — Flags[/bold cyan]",
               title_justify="left", padding=(0, 1), min_width=90, show_lines=True)
    of.add_column("Command",       style="bold cyan",  min_width=14, no_wrap=True)
    of.add_column("Flag",          style="bold green", min_width=20, no_wrap=True)
    of.add_column("Short",         style="cyan",       min_width=6,  no_wrap=True)
    of.add_column("Default",       style="dim",        min_width=10)
    of.add_column("Description",   style="white",      min_width=36)
    of.add_row("subdomains", "--threads INT",   "-t", "20",       "Concurrent DNS resolution threads")
    of.add_row("subdomains", "--wordlist PATH", "-w", "built-in", "Custom wordlist file path")
    of.add_row("subdomains", "--output PATH",   "-o", "none",     "Save subdomain list to a file")
    of.add_row("subdomains", "--verbose",       "-v", "off",      "Show every resolution attempt")
    of.add_row("───────────","─────────────────","─","──────────","────────────────────────────────────")
    of.add_row("vuln",       "--threads INT",   "-t", "10",       "Concurrent request threads")
    of.add_row("vuln",       "--verbose",       "-v", "off",      "Show all payloads being tested")
    of.add_row("───────────","─────────────────","─","──────────","────────────────────────────────────")
    of.add_row("headers",    "--verbose",       "-v", "off",      "Show full header values and details")
    of.add_row("───────────","─────────────────","─","──────────","────────────────────────────────────")
    of.add_row("fingerprint","--verbose",       "-v", "off",      "Show every path probe attempt")
    of.add_row("───────────","─────────────────","─","──────────","────────────────────────────────────")
    of.add_row("api",        "--spec URL/PATH", "-s", "auto",     "OpenAPI/Swagger spec URL or local path")
    of.add_row("api",        "--verbose",       "-v", "off",      "Show all API test details")
    console.print(of)
    console.print()

    # Examples
    console.print(Panel(
        "[dim]# Full scan — verbose, 20 threads[/dim]\n"
        "[bold green]webrecon scan https://target.com -v -t 20[/bold green]\n\n"
        "[dim]# Full scan — JSON report saved to custom folder[/dim]\n"
        "[bold green]webrecon scan https://target.com -f json -o ~/reports[/bold green]\n\n"
        "[dim]# Skip subdomains (fastest scan)[/dim]\n"
        "[bold green]webrecon scan https://target.com --skip-subdomains -t 30[/bold green]\n\n"
        "[dim]# Recon only — no vuln/auth/api scanning[/dim]\n"
        "[bold green]webrecon scan https://target.com --skip-vuln --skip-auth --skip-api[/bold green]\n\n"
        "[dim]# Subdomain enum with SecLists[/dim]\n"
        "[bold green]webrecon subdomains target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 100[/bold green]\n\n"
        "[dim]# Vulnerability scan only[/dim]\n"
        "[bold green]webrecon vuln https://target.com -v -t 15[/bold green]\n\n"
        "[dim]# Security headers check[/dim]\n"
        "[bold green]webrecon headers https://target.com -v[/bold green]\n\n"
        "[dim]# API test with known Swagger spec[/dim]\n"
        "[bold green]webrecon api https://target.com -s https://target.com/swagger.json -v[/bold green]\n\n"
        "[dim]# Safe practice target (legal)[/dim]\n"
        "[bold green]webrecon scan http://testphp.vulnweb.com --skip-subdomains -v[/bold green]",
        title="[bold green]💡 Examples[/bold green]", border_style="green", padding=(1, 2),
    ))
    console.print()

    # Modules detected
    mt = Table(box=box.ROUNDED, border_style="dim", header_style="bold white",
               title="[bold white]🧩 What Each Module Detects[/bold white]",
               title_justify="left", padding=(0, 1), min_width=90, show_lines=True)
    mt.add_column("Module",   style="bold cyan", min_width=14, no_wrap=True)
    mt.add_column("Detects",  style="white",     min_width=70)
    mt.add_row("headers",     "HSTS · CSP · X-Frame-Options · X-Content-Type-Options · Referrer-Policy · Permissions-Policy · COOP · CORP · COEP · Cookie flags (HttpOnly/Secure/SameSite) · Info-disclosure headers")
    mt.add_row("subdomains",  "DNS brute-force (100+ built-in) · crt.sh CT logs · Live host detection · IP resolution · HTTP status")
    mt.add_row("fingerprint", "CMS: WordPress/Drupal/Joomla/Magento/Shopify · WAF: Cloudflare/Akamai/Imperva/Sucuri/ModSecurity/F5 · Frameworks: React/Angular/Vue/Laravel/Django/Rails · 40+ sensitive paths")
    mt.add_row("vuln",        "SQL Injection (error+time-based) · Reflected XSS · Open Redirect · SSRF (AWS/GCP metadata) · Path Traversal · Command Injection · CORS Misconfiguration · Clickjacking")
    mt.add_row("auth",        "20 default credential pairs · JWT: alg:none/weak-secret/no-expiry/sensitive-payload · Session ID entropy · Brute-force protection · CAPTCHA detection")
    mt.add_row("api",         "Swagger/OpenAPI exposure · IDOR · GraphQL introspection · Mass assignment · Broken auth · Unauthenticated access · Verbose error leakage")
    console.print(mt)
    console.print()

    # Report formats
    console.print(Panel(
        "[bold]HTML[/bold]  [cyan]-f html[/cyan]  [dim](default)[/dim]  Dark-themed professional report · open in any browser · severity-colored finding cards\n"
        "[bold]JSON[/bold]  [cyan]-f json[/cyan]              Machine-readable · integrate with Jira/Burp/other tools\n"
        "[bold]TXT [/bold]  [cyan]-f txt [/cyan]              Plain text summary · pipe to other tools\n\n"
        "[dim]Saved to:[/dim]  [yellow]./reports/[/yellow]   [dim]History DB:[/dim]  [yellow]~/.webrecon/scans.db[/yellow]   [dim]Uninstall:[/dim]  [yellow]sudo bash /opt/webrecon/uninstall.sh[/yellow]",
        title="[bold magenta]📄 Report Formats[/bold magenta]", border_style="magenta", padding=(0, 2),
    ))
    console.print()

    # Legal
    console.print(Panel(
        "[bold red]⚠  FOR AUTHORIZED PENETRATION TESTING ONLY[/bold red]\n"
        "[dim]Only test systems you own or have explicit written permission to test.\n"
        "Unauthorized scanning is illegal under CFAA, Computer Misuse Act and similar laws worldwide.[/dim]\n\n"
        "[dim]Legal practice targets:[/dim]\n"
        "  [cyan]http://testphp.vulnweb.com[/cyan]   Acunetix intentionally vulnerable site\n"
        "  [cyan]https://hackthebox.com[/cyan]       Professional CTF lab environment\n"
        "  [cyan]https://tryhackme.com[/cyan]        Beginner-friendly guided labs\n"
        "  [cyan]http://localhost/dvwa[/cyan]        DVWA — local vulnerable web app",
        title="[bold red]⚖  Legal Notice[/bold red]", border_style="red", padding=(0, 2),
    ))
    console.print()
    sys.exit(0)

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

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

app = typer.Typer(
    name="webrecon",
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=False,
    rich_markup_mode=None,
)

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
        "[bold green]v1.0.0[/bold green]  [dim]│[/dim]  [cyan]Professional Web Penetration Testing Framework[/cyan]  [dim]│[/dim]  [yellow]⚠  Authorized Testing Only[/yellow]  [dim]│[/dim]  [dim]github.com/hackops-academy/webrecon-pro[/dim]",
        border_style="red", padding=(0, 2),
    ))
    console.print()

def normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target

@app.callback()
def root(ctx: typer.Context,
         version: bool = typer.Option(False, "--version", "-V", help="Show version and exit", is_eager=True)):
    if version:
        Console().print("[bold green]WebRecon Pro[/bold green] [cyan]v1.0.0[/cyan]")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        raise typer.Exit()

@app.command("scan", help="Run a full penetration test (all modules) against the target.")
def full_scan(
    target:          str  = typer.Argument(..., metavar="TARGET", help="Target URL  e.g. https://example.com"),
    output:          str  = typer.Option("./reports", "--output",          "-o", help="Directory to save reports"),
    threads:         int  = typer.Option(10,          "--threads",         "-t", help="Concurrent threads [default: 10]"),
    wordlist:        str  = typer.Option(None,        "--wordlist",        "-w", help="Custom subdomain wordlist path"),
    report_format:   str  = typer.Option("html",      "--format",          "-f", help="Report format: html | json | txt"),
    verbose:         bool = typer.Option(False,       "--verbose",         "-v", help="Show detailed output"),
    skip_subdomains: bool = typer.Option(False,       "--skip-subdomains",       help="Skip subdomain enumeration"),
    skip_vuln:       bool = typer.Option(False,       "--skip-vuln",             help="Skip vulnerability scanning"),
    skip_auth:       bool = typer.Option(False,       "--skip-auth",             help="Skip authentication testing"),
    skip_api:        bool = typer.Option(False,       "--skip-api",              help="Skip API security testing"),
):
    print_banner()
    target = normalize_url(target)
    cfg = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    cfg.add_column(style="bold green", min_width=14)
    cfg.add_column(style="cyan")
    cfg.add_row("🎯 Target",  target)
    cfg.add_row("📁 Output",  output)
    cfg.add_row("🧵 Threads", str(threads))
    cfg.add_row("📄 Format",  report_format)
    cfg.add_row("🔍 Verbose", "yes" if verbose else "no")
    skipped = [s for s, skip in [("subdomains", skip_subdomains), ("vuln", skip_vuln), ("auth", skip_auth), ("api", skip_api)] if skip]
    if skipped: cfg.add_row("⏭  Skipping", ", ".join(skipped))
    console.print(Panel(cfg, title="[bold yellow]Scan Configuration[/bold yellow]", border_style="yellow"))
    console.print()
    db = Database(); scan_id = db.create_scan(target)
    results = {"target": target, "scan_id": scan_id, "start_time": datetime.now().isoformat(),
                "subdomains": [], "fingerprint": {}, "vulnerabilities": [],
                "auth_findings": [], "api_findings": [], "header_findings": []}
    asyncio.run(_run_full_scan(target, results, db, scan_id, threads, wordlist,
                               skip_subdomains, skip_vuln, skip_auth, skip_api, verbose, output, report_format))

async def _run_full_scan(target, results, db, scan_id, threads, wordlist,
                         skip_subdomains, skip_vuln, skip_auth, skip_api, verbose, output, report_format):
    console.rule("[bold yellow]🔍 Phase 1 of 6 — Security Headers[/bold yellow]")
    checker = HeaderChecker(target, verbose=verbose)
    results["header_findings"] = await checker.check_all()
    db.save_findings(scan_id, "headers", results["header_findings"])

    if not skip_subdomains:
        console.rule("[bold yellow]🌐 Phase 2 of 6 — Subdomain Enumeration[/bold yellow]")
        e = SubdomainEnumerator(target, threads=threads, wordlist=wordlist, verbose=verbose)
        results["subdomains"] = await e.enumerate()
        db.save_findings(scan_id, "subdomains", results["subdomains"])
    else:
        console.print("[dim]⏭  Phase 2 — Subdomain Enumeration skipped[/dim]")

    console.rule("[bold yellow]🔎 Phase 3 of 6 — Web Fingerprinting[/bold yellow]")
    fp = WebFingerprinter(target, verbose=verbose)
    results["fingerprint"] = await fp.fingerprint()
    db.save_findings(scan_id, "fingerprint", [results["fingerprint"]])

    if not skip_vuln:
        console.rule("[bold yellow]💥 Phase 4 of 6 — Vulnerability Scanning[/bold yellow]")
        s = VulnerabilityScanner(target, threads=threads, verbose=verbose)
        results["vulnerabilities"] = await s.scan_all()
        db.save_findings(scan_id, "vulnerabilities", results["vulnerabilities"])
    else:
        console.print("[dim]⏭  Phase 4 — Vulnerability Scanning skipped[/dim]")

    if not skip_auth:
        console.rule("[bold yellow]🔐 Phase 5 of 6 — Authentication Testing[/bold yellow]")
        a = AuthTester(target, verbose=verbose)
        results["auth_findings"] = await a.test_all()
        db.save_findings(scan_id, "auth", results["auth_findings"])
    else:
        console.print("[dim]⏭  Phase 5 — Authentication Testing skipped[/dim]")

    if not skip_api:
        console.rule("[bold yellow]🔌 Phase 6 of 6 — API Security Testing[/bold yellow]")
        api = APITester(target, verbose=verbose)
        results["api_findings"] = await api.test_all()
        db.save_findings(scan_id, "api", results["api_findings"])
    else:
        console.print("[dim]⏭  Phase 6 — API Security Testing skipped[/dim]")

    console.rule("[bold green]📊 Generating Report[/bold green]")
    results["end_time"] = datetime.now().isoformat()
    reporter = ReportGenerator(results, output_dir=output)
    report_path = reporter.generate(format=report_format)
    _print_summary(results, report_path)
    db.complete_scan(scan_id)

def _print_summary(results, report_path):
    console.print()
    console.rule("[bold green]✅ Scan Complete[/bold green]")
    vulns = results.get("vulnerabilities", [])
    critical = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high     = sum(1 for v in vulns if v.get("severity") == "HIGH")
    medium   = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    low      = sum(1 for v in vulns if v.get("severity") == "LOW")
    t = Table(title="Scan Summary", box=box.DOUBLE_EDGE, border_style="green", show_lines=True, min_width=55)
    t.add_column("Category", style="cyan",  min_width=26)
    t.add_column("Count",    style="white", justify="center", min_width=8)
    t.add_column("Details",  style="dim",   min_width=26)
    t.add_row("Subdomains Found",      str(len(results.get("subdomains", []))),      "Active hosts discovered")
    t.add_row("Total Vulnerabilities", str(len(vulns)),                               "All severity levels")
    t.add_row("[bold red]🔴 Critical[/bold red]",   str(critical), "Immediate action required")
    t.add_row("[red]🟠 High[/red]",                 str(high),     "High priority fixes")
    t.add_row("[yellow]🟡 Medium[/yellow]",         str(medium),   "Should be addressed")
    t.add_row("[cyan]🟢 Low[/cyan]",                str(low),      "Best practice improvements")
    t.add_row("Header Issues",  str(len(results.get("header_findings", []))), "Security header misconfigs")
    t.add_row("Auth Findings",  str(len(results.get("auth_findings", []))),   "Authentication issues")
    t.add_row("API Findings",   str(len(results.get("api_findings", []))),    "API security issues")
    console.print(t)
    console.print(f"\n[bold green]📄 Report:[/bold green] [cyan]{report_path}[/cyan]\n")

@app.command("subdomains", help="Enumerate subdomains via DNS brute-force + certificate transparency logs.")
def enum_subdomains(
    target:   str  = typer.Argument(...,   metavar="DOMAIN", help="Target domain  e.g. example.com"),
    threads:  int  = typer.Option(20,      "--threads",  "-t", help="Concurrent threads [default: 20]"),
    wordlist: str  = typer.Option(None,    "--wordlist", "-w", help="Custom wordlist path"),
    output:   str  = typer.Option(None,    "--output",   "-o", help="Save results to file"),
    verbose:  bool = typer.Option(False,   "--verbose",  "-v", help="Show each attempt"),
):
    print_banner()
    asyncio.run(_run_subdomains(target, threads, wordlist, output, verbose))

async def _run_subdomains(target, threads, wordlist, output, verbose):
    target = normalize_url(target)
    e = SubdomainEnumerator(target, threads=threads, wordlist=wordlist, verbose=verbose)
    subs = await e.enumerate()
    if output:
        with open(output, "w") as f:
            for s in subs: f.write(f"{s['subdomain']}\t{s['ip']}\t{s['status']}\n")
        console.print(f"[green]✓ Saved to {output}[/green]")

@app.command("vuln", help="Scan for vulnerabilities: SQLi, XSS, SSRF, CORS, Path Traversal, CMDi.")
def vuln_scan(
    target:  str  = typer.Argument(...,  metavar="TARGET", help="Target URL  e.g. https://example.com"),
    threads: int  = typer.Option(10,     "--threads", "-t", help="Concurrent threads [default: 10]"),
    verbose: bool = typer.Option(False,  "--verbose", "-v", help="Show all payloads tested"),
):
    print_banner()
    asyncio.run(_run_vulns(target, threads, verbose))

async def _run_vulns(target, threads, verbose):
    target = normalize_url(target)
    await VulnerabilityScanner(target, threads=threads, verbose=verbose).scan_all()

@app.command("headers", help="Analyse HTTP security headers and score the target out of 100.")
def check_headers(
    target:  str  = typer.Argument(...,  metavar="TARGET", help="Target URL  e.g. https://example.com"),
    verbose: bool = typer.Option(False,  "--verbose", "-v", help="Show full header values"),
):
    print_banner()
    asyncio.run(_run_headers(target, verbose))

async def _run_headers(target, verbose):
    target = normalize_url(target)
    await HeaderChecker(target, verbose=verbose).check_all()

@app.command("fingerprint", help="Detect CMS, WAF, frameworks and exposed sensitive paths.")
def fingerprint_target(
    target:  str  = typer.Argument(...,  metavar="TARGET", help="Target URL  e.g. https://example.com"),
    verbose: bool = typer.Option(False,  "--verbose", "-v", help="Show every probe attempt"),
):
    print_banner()
    asyncio.run(_run_fingerprint(target, verbose))

async def _run_fingerprint(target, verbose):
    target = normalize_url(target)
    await WebFingerprinter(target, verbose=verbose).fingerprint()

@app.command("api", help="Test API security: IDOR, GraphQL, mass assignment, broken auth, Swagger exposure.")
def api_test(
    target:  str  = typer.Argument(...,  metavar="TARGET", help="Target URL  e.g. https://example.com"),
    spec:    str  = typer.Option(None,   "--spec",    "-s", help="OpenAPI/Swagger spec URL or path"),
    verbose: bool = typer.Option(False,  "--verbose", "-v", help="Show all test details"),
):
    print_banner()
    asyncio.run(_run_api(target, spec, verbose))

async def _run_api(target, spec, verbose):
    target = normalize_url(target)
    await APITester(target, spec_url=spec, verbose=verbose).test_all()

@app.command("list-scans", help="Show all previous scans stored in ~/.webrecon/scans.db")
def list_scans():
    print_banner()
    db = Database(); scans = db.get_all_scans()
    if not scans:
        console.print(Panel("[yellow]No scans yet.\n\nRun:[/yellow]\n[bold green]webrecon scan https://target.com[/bold green]", border_style="yellow"))
        return
    t = Table(title=f"Scan History ({len(scans)} scans)", box=box.ROUNDED, border_style="cyan", show_lines=True)
    t.add_column("ID",       style="dim",    justify="center", min_width=5)
    t.add_column("Target",   style="cyan",   min_width=38)
    t.add_column("Date",     style="green",  min_width=20)
    t.add_column("Findings", style="yellow", justify="center", min_width=10)
    for scan in scans:
        t.add_row(str(scan["id"]), scan["target"], scan["created_at"][:19].replace("T"," "), str(scan["finding_count"]))
    console.print(t)

if __name__ == "__main__":
    app()
