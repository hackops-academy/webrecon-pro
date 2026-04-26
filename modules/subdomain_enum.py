"""
Subdomain Enumeration Module
- DNS brute-force with async resolution
- Certificate transparency logs (crt.sh)
- Live host detection
"""

import asyncio
import socket
import json
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Optional

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich import box

console = Console()

# Built-in wordlist (top subdomains)
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "ns3", "mail2", "vpn", "admin", "blog", "dev", "staging", "api",
    "app", "portal", "shop", "store", "support", "help", "forum", "wiki",
    "secure", "login", "remote", "web", "server", "beta", "cdn", "static",
    "img", "images", "media", "upload", "uploads", "download", "downloads",
    "files", "assets", "css", "js", "javascript", "gateway", "proxy", "monitor",
    "dashboard", "internal", "intranet", "corp", "corporate", "private",
    "mobile", "wap", "demo", "docs", "documentation", "backup", "old", "new",
    "v1", "v2", "v3", "api2", "api3", "graphql", "rest", "soap", "service",
    "services", "auth", "oauth", "sso", "identity", "id", "accounts",
    "account", "billing", "pay", "payment", "payments", "checkout",
    "uat", "qa", "testing", "sandbox", "preview", "pre", "preprod",
    "production", "prod", "live", "origin", "edge", "relay",
    "smtp2", "mail3", "mx", "mx1", "mx2", "ns4", "dns", "dns1", "dns2",
    "pop3", "imap2", "exchange", "owa", "outlook",
    "database", "db", "mysql", "postgres", "mongo", "redis", "elastic",
    "jenkins", "gitlab", "git", "svn", "jira", "confluence", "sonar",
    "grafana", "kibana", "prometheus", "metrics", "logs", "logging",
    "status", "uptime", "health", "ping", "heartbeat",
]


class SubdomainEnumerator:
    def __init__(
        self,
        target: str,
        threads: int = 20,
        wordlist: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = target
        self.domain = urlparse(target).netloc or target
        # Strip www if present
        if self.domain.startswith("www."):
            self.domain = self.domain[4:]
        self.threads = threads
        self.wordlist_path = wordlist
        self.verbose = verbose
        self.found_subdomains: List[Dict] = []
        self.semaphore = asyncio.Semaphore(threads)

    def _load_wordlist(self) -> List[str]:
        """Load wordlist from file or use built-in."""
        if self.wordlist_path and Path(self.wordlist_path).exists():
            with open(self.wordlist_path) as f:
                words = [line.strip() for line in f if line.strip()]
            console.print(f"[green]📋 Loaded {len(words)} words from wordlist[/green]")
            return words
        return DEFAULT_SUBDOMAINS

    async def _resolve_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Attempt to resolve a subdomain."""
        async with self.semaphore:
            fqdn = f"{subdomain}.{self.domain}"
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                
                # Try to get HTTP status
                status = await self._check_http(fqdn)
                
                result = {
                    "subdomain": fqdn,
                    "ip": ip,
                    "status": status,
                    "source": "bruteforce",
                }
                
                if self.verbose:
                    console.print(f"  [green]✓[/green] {fqdn} → {ip} ({status})")
                
                return result
            except (socket.gaierror, OSError):
                return None

    async def _check_http(self, fqdn: str) -> str:
        """Check HTTP status of a subdomain."""
        for scheme in ["https", "http"]:
            try:
                async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=True) as client:
                    resp = await client.get(f"{scheme}://{fqdn}")
                    return str(resp.status_code)
            except Exception:
                pass
        return "No HTTP"

    async def _fetch_crtsh(self) -> List[str]:
        """Fetch subdomains from certificate transparency logs."""
        console.print(f"  [cyan]🔍 Querying crt.sh for {self.domain}...[/cyan]")
        subdomains = []
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{self.domain}&output=json",
                    headers={"User-Agent": "WebReconPro/1.0"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        names = entry.get("name_value", "").split("\n")
                        for name in names:
                            name = name.strip().lstrip("*.")
                            if name.endswith(f".{self.domain}") and name not in subdomains:
                                subdomains.append(name)
                    console.print(f"  [green]✓ crt.sh returned {len(subdomains)} entries[/green]")
        except Exception as e:
            console.print(f"  [yellow]⚠ crt.sh query failed: {e}[/yellow]")
        return subdomains

    async def _resolve_known(self, fqdn: str) -> Optional[Dict]:
        """Resolve a known FQDN from CT logs."""
        async with self.semaphore:
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                status = await self._check_http(fqdn)
                return {
                    "subdomain": fqdn,
                    "ip": ip,
                    "status": status,
                    "source": "crt.sh",
                }
            except Exception:
                return None

    async def enumerate(self) -> List[Dict]:
        """Run full subdomain enumeration."""
        console.print(f"\n[bold cyan]🌐 Enumerating subdomains for:[/bold cyan] [white]{self.domain}[/white]")
        
        wordlist = self._load_wordlist()
        
        # Phase 1: Certificate Transparency
        console.print("\n[bold]Phase 2a: Certificate Transparency Logs[/bold]")
        ct_subdomains = await self._fetch_crtsh()
        
        # Phase 2: DNS Brute-force
        console.print(f"\n[bold]Phase 2b: DNS Brute-Force ({len(wordlist)} words)[/bold]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Resolving subdomains...", total=len(wordlist))
            
            tasks = []
            for word in wordlist:
                tasks.append(self._resolve_subdomain(word))
            
            results = []
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    results.append(result)
                progress.advance(task)
        
        # Phase 3: Resolve CT log subdomains
        if ct_subdomains:
            console.print(f"\n[bold]Phase 2c: Resolving {len(ct_subdomains)} CT log entries[/bold]")
            ct_tasks = [self._resolve_known(fqdn) for fqdn in ct_subdomains]
            ct_results = await asyncio.gather(*ct_tasks)
            results.extend([r for r in ct_results if r])
        
        # Deduplicate
        seen = set()
        unique_results = []
        for r in results:
            if r["subdomain"] not in seen:
                seen.add(r["subdomain"])
                unique_results.append(r)
        
        self.found_subdomains = sorted(unique_results, key=lambda x: x["subdomain"])
        self._print_results()
        return self.found_subdomains

    def _print_results(self):
        """Display results in a table."""
        console.print(f"\n[bold green]✅ Found {len(self.found_subdomains)} live subdomains[/bold green]\n")
        
        if not self.found_subdomains:
            console.print("[yellow]No subdomains found.[/yellow]")
            return
        
        table = Table(box=box.ROUNDED, border_style="cyan", show_lines=True)
        table.add_column("Subdomain", style="cyan", min_width=30)
        table.add_column("IP Address", style="white")
        table.add_column("HTTP Status", justify="center")
        table.add_column("Source", style="dim")
        
        for sub in self.found_subdomains:
            status = sub["status"]
            if status.startswith("2"):
                status_style = f"[green]{status}[/green]"
            elif status.startswith("3"):
                status_style = f"[yellow]{status}[/yellow]"
            elif status.startswith("4"):
                status_style = f"[red]{status}[/red]"
            else:
                status_style = f"[dim]{status}[/dim]"
            
            table.add_row(
                sub["subdomain"],
                sub["ip"],
                status_style,
                sub.get("source", "unknown"),
            )
        
        console.print(table)
