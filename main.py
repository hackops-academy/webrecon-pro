#!/usr/bin/env python3
"""
WebRecon Pro - Professional Web Penetration Testing Framework
Author: WebRecon Pro Team
Version: 1.0.0
"""

import asyncio
import sys
import os
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
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

app = typer.Typer(
    name="webrecon",
    help="WebRecon Pro - Professional Web Penetration Testing Framework",
    add_completion=False,
)
console = Console()
logger = setup_logger()

BANNER = """
██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ 
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
"""


def print_banner():
    """Display the tool banner."""
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(
        Panel(
            "[bold green]v1.0.0[/bold green] | [cyan]Professional Web Penetration Testing Framework[/cyan] | [yellow]For authorized testing only[/yellow]",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()


@app.command("scan")
def full_scan(
    target: str = typer.Argument(..., help="Target URL or domain (e.g., https://example.com)"),
    output: str = typer.Option("./reports", "--output", "-o", help="Output directory for reports"),
    threads: int = typer.Option(10, "--threads", "-t", help="Number of concurrent threads"),
    wordlist: str = typer.Option(None, "--wordlist", "-w", help="Custom wordlist for subdomain enum"),
    skip_subdomains: bool = typer.Option(False, "--skip-subdomains", help="Skip subdomain enumeration"),
    skip_vuln: bool = typer.Option(False, "--skip-vuln", help="Skip vulnerability scanning"),
    skip_auth: bool = typer.Option(False, "--skip-auth", help="Skip auth testing"),
    skip_api: bool = typer.Option(False, "--skip-api", help="Skip API testing"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, txt"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Run a full penetration test against the target."""
    print_banner()
    
    # Validate target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    console.print(f"[bold green]🎯 Target:[/bold green] [cyan]{target}[/cyan]")
    console.print(f"[bold green]📁 Output:[/bold green] [cyan]{output}[/cyan]")
    console.print(f"[bold green]🧵 Threads:[/bold green] [cyan]{threads}[/cyan]")
    console.print()
    
    # Initialize database
    db = Database()
    scan_id = db.create_scan(target)
    
    results = {
        "target": target,
        "scan_id": scan_id,
        "start_time": datetime.now().isoformat(),
        "subdomains": [],
        "fingerprint": {},
        "vulnerabilities": [],
        "auth_findings": [],
        "api_findings": [],
        "header_findings": [],
    }
    
    asyncio.run(_run_full_scan(
        target, results, db, scan_id, threads, wordlist,
        skip_subdomains, skip_vuln, skip_auth, skip_api,
        verbose, output, format
    ))


async def _run_full_scan(
    target, results, db, scan_id, threads, wordlist,
    skip_subdomains, skip_vuln, skip_auth, skip_api,
    verbose, output, format
):
    """Async full scan runner."""
    
    # 1. Header Security Check
    console.rule("[bold yellow]🔍 Phase 1: Security Headers Analysis[/bold yellow]")
    checker = HeaderChecker(target, verbose=verbose)
    header_findings = await checker.check_all()
    results["header_findings"] = header_findings
    db.save_findings(scan_id, "headers", header_findings)
    
    # 2. Subdomain Enumeration
    if not skip_subdomains:
        console.rule("[bold yellow]🌐 Phase 2: Subdomain Enumeration[/bold yellow]")
        enumerator = SubdomainEnumerator(target, threads=threads, wordlist=wordlist, verbose=verbose)
        subdomains = await enumerator.enumerate()
        results["subdomains"] = subdomains
        db.save_findings(scan_id, "subdomains", subdomains)
    
    # 3. Web Fingerprinting
    console.rule("[bold yellow]🔎 Phase 3: Web Fingerprinting[/bold yellow]")
    fingerprinter = WebFingerprinter(target, verbose=verbose)
    fingerprint = await fingerprinter.fingerprint()
    results["fingerprint"] = fingerprint
    db.save_findings(scan_id, "fingerprint", [fingerprint])
    
    # 4. Vulnerability Scanning
    if not skip_vuln:
        console.rule("[bold yellow]💥 Phase 4: Vulnerability Scanning[/bold yellow]")
        scanner = VulnerabilityScanner(target, threads=threads, verbose=verbose)
        vulns = await scanner.scan_all()
        results["vulnerabilities"] = vulns
        db.save_findings(scan_id, "vulnerabilities", vulns)
    
    # 5. Auth Testing
    if not skip_auth:
        console.rule("[bold yellow]🔐 Phase 5: Authentication Testing[/bold yellow]")
        auth = AuthTester(target, verbose=verbose)
        auth_findings = await auth.test_all()
        results["auth_findings"] = auth_findings
        db.save_findings(scan_id, "auth", auth_findings)
    
    # 6. API Testing
    if not skip_api:
        console.rule("[bold yellow]🔌 Phase 6: API Security Testing[/bold yellow]")
        api = APITester(target, verbose=verbose)
        api_findings = await api.test_all()
        results["api_findings"] = api_findings
        db.save_findings(scan_id, "api", api_findings)
    
    # 7. Generate Report
    console.rule("[bold yellow]📊 Phase 7: Generating Report[/bold yellow]")
    results["end_time"] = datetime.now().isoformat()
    reporter = ReportGenerator(results, output_dir=output)
    report_path = reporter.generate(format=format)
    
    # Final Summary
    _print_summary(results, report_path)


def _print_summary(results, report_path):
    """Print final scan summary."""
    console.print()
    console.rule("[bold green]✅ Scan Complete[/bold green]")
    
    total_vulns = len(results.get("vulnerabilities", []))
    critical = sum(1 for v in results.get("vulnerabilities", []) if v.get("severity") == "CRITICAL")
    high = sum(1 for v in results.get("vulnerabilities", []) if v.get("severity") == "HIGH")
    medium = sum(1 for v in results.get("vulnerabilities", []) if v.get("severity") == "MEDIUM")
    low = sum(1 for v in results.get("vulnerabilities", []) if v.get("severity") == "LOW")
    
    table = Table(title="Scan Summary", box=box.DOUBLE_EDGE, border_style="green")
    table.add_column("Category", style="cyan", width=25)
    table.add_column("Count", style="white", justify="center")
    table.add_column("Details", style="dim")
    
    table.add_row("Subdomains Found", str(len(results.get("subdomains", []))), "Active hosts discovered")
    table.add_row("Total Vulnerabilities", str(total_vulns), "All severity levels")
    table.add_row("🔴 Critical", str(critical), "Immediate action required")
    table.add_row("🟠 High", str(high), "High priority fixes")
    table.add_row("🟡 Medium", str(medium), "Should be addressed")
    table.add_row("🟢 Low", str(low), "Best practice improvements")
    table.add_row("Header Issues", str(len(results.get("header_findings", []))), "Security header misconfigs")
    table.add_row("Auth Findings", str(len(results.get("auth_findings", []))), "Authentication issues")
    table.add_row("API Findings", str(len(results.get("api_findings", []))), "API security issues")
    
    console.print(table)
    console.print(f"\n[bold green]📄 Report saved:[/bold green] [cyan]{report_path}[/cyan]")


@app.command("subdomains")
def enum_subdomains(
    target: str = typer.Argument(..., help="Target domain"),
    threads: int = typer.Option(20, "--threads", "-t"),
    wordlist: str = typer.Option(None, "--wordlist", "-w"),
    output: str = typer.Option(None, "--output", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Only run subdomain enumeration."""
    print_banner()
    asyncio.run(_run_subdomains(target, threads, wordlist, output, verbose))


async def _run_subdomains(target, threads, wordlist, output, verbose):
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    enumerator = SubdomainEnumerator(target, threads=threads, wordlist=wordlist, verbose=verbose)
    subdomains = await enumerator.enumerate()
    if output:
        with open(output, "w") as f:
            for s in subdomains:
                f.write(f"{s['subdomain']}\t{s['ip']}\t{s['status']}\n")
        console.print(f"[green]Results saved to {output}[/green]")


@app.command("vuln")
def vuln_scan(
    target: str = typer.Argument(..., help="Target URL"),
    threads: int = typer.Option(10, "--threads", "-t"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Only run vulnerability scanning."""
    print_banner()
    asyncio.run(_run_vulns(target, threads, verbose))


async def _run_vulns(target, threads, verbose):
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    scanner = VulnerabilityScanner(target, threads=threads, verbose=verbose)
    await scanner.scan_all()


@app.command("headers")
def check_headers(
    target: str = typer.Argument(..., help="Target URL"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Check security headers of a target."""
    print_banner()
    asyncio.run(_run_headers(target, verbose))


async def _run_headers(target, verbose):
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    checker = HeaderChecker(target, verbose=verbose)
    await checker.check_all()


@app.command("fingerprint")
def fingerprint_target(
    target: str = typer.Argument(..., help="Target URL"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Fingerprint web technologies of a target."""
    print_banner()
    asyncio.run(_run_fingerprint(target, verbose))


async def _run_fingerprint(target, verbose):
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    fp = WebFingerprinter(target, verbose=verbose)
    await fp.fingerprint()


@app.command("api")
def api_test(
    target: str = typer.Argument(..., help="Target URL"),
    spec: str = typer.Option(None, "--spec", "-s", help="OpenAPI/Swagger spec URL or path"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Test API security of a target."""
    print_banner()
    asyncio.run(_run_api(target, spec, verbose))


async def _run_api(target, spec, verbose):
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    tester = APITester(target, spec_url=spec, verbose=verbose)
    await tester.test_all()


@app.command("list-scans")
def list_scans():
    """List all previous scans."""
    print_banner()
    db = Database()
    scans = db.get_all_scans()
    
    table = Table(title="Previous Scans", box=box.ROUNDED, border_style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Target", style="cyan")
    table.add_column("Date", style="green")
    table.add_column("Findings", style="yellow")
    
    for scan in scans:
        table.add_row(
            str(scan["id"]),
            scan["target"],
            scan["created_at"],
            str(scan["finding_count"]),
        )
    console.print(table)


if __name__ == "__main__":
    app()
