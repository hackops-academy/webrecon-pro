"""
Security Headers Checker Module
- Checks all important security response headers
- Scores the target security posture
- Provides remediation advice
"""

import asyncio
from typing import Dict, List, Optional

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": "HIGH",
        "description": "Forces HTTPS connections",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "good_value": "max-age=",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "description": "Prevents MIME sniffing attacks",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "good_value": "nosniff",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "description": "Prevents clickjacking attacks",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "good_value": ["deny", "sameorigin"],
    },
    "content-security-policy": {
        "name": "Content Security Policy",
        "severity": "HIGH",
        "description": "Prevents XSS and data injection",
        "remediation": "Add a restrictive Content-Security-Policy header",
        "good_value": "default-src",
    },
    "referrer-policy": {
        "name": "Referrer Policy",
        "severity": "LOW",
        "description": "Controls referrer information",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "good_value": "no-referrer",
    },
    "permissions-policy": {
        "name": "Permissions Policy",
        "severity": "LOW",
        "description": "Controls browser feature access",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "good_value": None,
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "LOW",
        "description": "Legacy XSS filter (mostly deprecated)",
        "remediation": "Add: X-XSS-Protection: 1; mode=block (legacy browsers)",
        "good_value": "1",
    },
    "cross-origin-opener-policy": {
        "name": "COOP",
        "severity": "LOW",
        "description": "Prevents cross-origin attacks",
        "remediation": "Add: Cross-Origin-Opener-Policy: same-origin",
        "good_value": "same-origin",
    },
    "cross-origin-resource-policy": {
        "name": "CORP",
        "severity": "LOW",
        "description": "Controls cross-origin resource loading",
        "remediation": "Add: Cross-Origin-Resource-Policy: same-origin",
        "good_value": "same-origin",
    },
    "cross-origin-embedder-policy": {
        "name": "COEP",
        "severity": "LOW",
        "description": "Prevents embedding from untrusted origins",
        "remediation": "Add: Cross-Origin-Embedder-Policy: require-corp",
        "good_value": "require-corp",
    },
}

DANGEROUS_HEADERS = {
    "x-powered-by": {
        "name": "X-Powered-By",
        "severity": "LOW",
        "issue": "Reveals technology stack",
        "remediation": "Remove X-Powered-By header from server config",
    },
    "server": {
        "name": "Server",
        "severity": "LOW",
        "issue": "Reveals server version",
        "remediation": "Remove or mask the Server header (e.g., 'Server: webserver')",
    },
    "x-aspnet-version": {
        "name": "X-AspNet-Version",
        "severity": "LOW",
        "issue": "Reveals .NET version",
        "remediation": "Set <httpRuntime enableVersionHeader='false' /> in web.config",
    },
    "x-aspnetmvc-version": {
        "name": "X-AspNetMvc-Version",
        "severity": "LOW",
        "issue": "Reveals ASP.NET MVC version",
        "remediation": "Remove in Global.asax: MvcHandler.DisableMvcResponseHeader = true",
    },
}


class HeaderChecker:
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.findings: List[Dict] = []

    async def check_all(self) -> List[Dict]:
        """Check all security headers."""
        console.print(f"\n[bold cyan]🔍 Checking Security Headers for:[/bold cyan] [white]{self.target}[/white]")
        
        try:
            async with httpx.AsyncClient(
                timeout=10,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "WebReconPro/1.0"},
            ) as client:
                resp = await client.get(self.target)
        except Exception as e:
            console.print(f"[red]❌ Failed to connect: {e}[/red]")
            return []
        
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        
        score = 100
        missing_headers = []
        present_headers = []
        dangerous_headers = []
        
        # Check security headers
        for header_key, info in SECURITY_HEADERS.items():
            if header_key in headers_lower:
                val = headers_lower[header_key]
                good_val = info["good_value"]
                
                # Validate the value
                if good_val is None:
                    status = "✅ Present"
                    is_good = True
                elif isinstance(good_val, list):
                    is_good = any(g in val.lower() for g in good_val)
                    status = "✅ Good" if is_good else "⚠️ Weak"
                else:
                    is_good = good_val.lower() in val.lower()
                    status = "✅ Good" if is_good else "⚠️ Weak"
                
                present_headers.append({
                    "header": info["name"],
                    "value": val[:60],
                    "status": status,
                    "good": is_good,
                })
            else:
                sev = info["severity"]
                deduction = {"HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(sev, 5)
                score -= deduction
                
                missing_headers.append({
                    "header": info["name"],
                    "severity": sev,
                    "description": info["description"],
                    "remediation": info["remediation"],
                })
                
                finding = {
                    "type": f"Missing {info['name']} Header",
                    "severity": sev,
                    "url": self.target,
                    "parameter": info["name"],
                    "payload": "N/A",
                    "detail": info["description"],
                    "remediation": info["remediation"],
                }
                self.findings.append(finding)
        
        # Check dangerous headers
        for header_key, info in DANGEROUS_HEADERS.items():
            if header_key in headers_lower:
                val = headers_lower[header_key]
                dangerous_headers.append({
                    "header": info["name"],
                    "value": val[:60],
                    "issue": info["issue"],
                    "remediation": info["remediation"],
                })
                
                self.findings.append({
                    "type": f"Exposed {info['name']} Header",
                    "severity": info["severity"],
                    "url": self.target,
                    "parameter": info["name"],
                    "payload": val,
                    "detail": info["issue"],
                    "remediation": info["remediation"],
                })
        
        # Check cookie security
        cookie_findings = self._check_cookies(resp)
        self.findings.extend(cookie_findings)
        
        score = max(0, score)
        
        self._print_results(present_headers, missing_headers, dangerous_headers, cookie_findings, score)
        return self.findings

    def _check_cookies(self, resp: httpx.Response) -> List[Dict]:
        """Check cookie security flags."""
        findings = []
        
        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else []
        if not set_cookie_headers:
            # Try alternate approach
            raw = str(resp.headers)
            import re
            set_cookie_headers = re.findall(r'set-cookie: ([^\r\n]+)', raw, re.IGNORECASE)
        
        for cookie in set_cookie_headers:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()
            
            issues = []
            if "httponly" not in cookie_lower:
                issues.append("Missing HttpOnly flag")
            if "secure" not in cookie_lower:
                issues.append("Missing Secure flag")
            if "samesite" not in cookie_lower:
                issues.append("Missing SameSite attribute")
            
            if issues:
                findings.append({
                    "type": "Insecure Cookie",
                    "severity": "MEDIUM",
                    "url": self.target,
                    "parameter": f"Cookie: {cookie_name}",
                    "payload": "N/A",
                    "detail": ", ".join(issues),
                    "remediation": "Set HttpOnly; Secure; SameSite=Strict on all cookies",
                })
                
                if self.verbose:
                    console.print(f"  [yellow]⚠ Insecure cookie: {cookie_name} — {', '.join(issues)}[/yellow]")
        
        return findings

    def _print_results(self, present, missing, dangerous, cookie_findings, score):
        """Display header analysis results."""
        
        # Score color
        if score >= 80:
            score_color = "green"
            grade = "A"
        elif score >= 60:
            score_color = "yellow"
            grade = "B"
        elif score >= 40:
            score_color = "orange3"
            grade = "C"
        else:
            score_color = "red"
            grade = "F"
        
        console.print(Panel(
            f"Security Score: [{score_color}]{score}/100 (Grade: {grade})[/{score_color}]",
            title="🛡️ Header Security Analysis",
            border_style=score_color,
        ))
        
        # Present headers
        if present:
            table = Table(title="✅ Security Headers Present", box=box.SIMPLE, border_style="green")
            table.add_column("Header", style="cyan")
            table.add_column("Value", style="dim")
            table.add_column("Status")
            
            for h in present:
                status_style = "green" if "Good" in h["status"] or "Present" in h["status"] else "yellow"
                table.add_row(h["header"], h["value"], f"[{status_style}]{h['status']}[/{status_style}]")
            
            console.print(table)
        
        # Missing headers
        if missing:
            table = Table(title=f"❌ Missing Security Headers ({len(missing)})", box=box.ROUNDED, border_style="red")
            table.add_column("Header", style="cyan", min_width=25)
            table.add_column("Severity", justify="center")
            table.add_column("Description", style="dim")
            
            for h in missing:
                sev = h["severity"]
                sev_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
                table.add_row(
                    h["header"],
                    f"[{sev_color}]{sev}[/{sev_color}]",
                    h["description"],
                )
            
            console.print(table)
        
        # Dangerous headers
        if dangerous:
            table = Table(title=f"⚠️  Information Disclosure Headers ({len(dangerous)})", box=box.ROUNDED, border_style="yellow")
            table.add_column("Header", style="cyan")
            table.add_column("Value", style="red")
            table.add_column("Issue", style="dim")
            
            for h in dangerous:
                table.add_row(h["header"], h["value"], h["issue"])
            
            console.print(table)
        
        # Cookie findings
        if cookie_findings:
            console.print(f"[yellow]⚠  {len(cookie_findings)} insecure cookie(s) found[/yellow]")
