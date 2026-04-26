"""
Web Fingerprinting Module
- CMS detection (WordPress, Drupal, Joomla, etc.)
- Framework detection (React, Angular, Laravel, Django, etc.)
- WAF detection
- Server technology detection
- Exposed sensitive files/paths
"""

import asyncio
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# WAF signatures
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-request-id"],
    "AWS WAF": ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "Akamai": ["akamai", "akamaighost", "x-akamai-transformed"],
    "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
    "Imperva": ["incapsula", "visid_incap", "x-iinfo"],
    "F5 BIG-IP": ["bigipserver", "f5", "x-wa-info"],
    "Barracuda": ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"],
    "Fortinet": ["fortiwafsid", "x-cdn", "FORTIWAFSID"],
    "Nginx": ["x-nginx", "nginx"],
}

# CMS signatures
CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/"],
        "headers": [],
        "body": ["wp-content", "wp-includes", "WordPress"],
        "meta": ["WordPress"],
    },
    "Drupal": {
        "paths": ["/user/login", "/admin/config", "/sites/default/"],
        "headers": ["x-drupal-cache", "x-generator"],
        "body": ["Drupal.settings", "drupal.org"],
        "meta": ["Drupal"],
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/"],
        "headers": [],
        "body": ["/media/jui/", "Joomla!"],
        "meta": [],
    },
    "Magento": {
        "paths": ["/admin/", "/skin/frontend/", "/js/mage/"],
        "headers": ["x-magento-cache-debug"],
        "body": ["Mage.Cookies", "magento"],
        "meta": [],
    },
    "Shopify": {
        "paths": [],
        "headers": ["x-shopify-stage", "x-shopid"],
        "body": ["cdn.shopify.com", "Shopify.theme"],
        "meta": [],
    },
    "Laravel": {
        "paths": [],
        "headers": [],
        "body": ["laravel_session", "XSRF-TOKEN"],
        "meta": [],
    },
    "Django": {
        "paths": ["/admin/", "/static/admin/"],
        "headers": [],
        "body": ["django", "csrfmiddlewaretoken"],
        "meta": [],
    },
    "Ruby on Rails": {
        "paths": [],
        "headers": ["x-runtime", "x-powered-by"],
        "body": ["_rails_", "authenticity_token"],
        "meta": [],
    },
}

# Framework signatures
FRAMEWORK_SIGNATURES = {
    "React": ["react", "ReactDOM", "_reactRootContainer", "__REACT_DEVTOOLS"],
    "Angular": ["ng-version", "ng-app", "angular.min.js", "_nghost"],
    "Vue.js": ["vue.min.js", "__vue__", "v-bind:", "v-on:"],
    "Next.js": ["__NEXT_DATA__", "_next/static", "next/dist"],
    "Nuxt.js": ["__NUXT__", "_nuxt/", "nuxt.js"],
    "jQuery": ["jquery.min.js", "jQuery(", "$.ajax"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
    "Tailwind CSS": ["tailwind.css", "tw-", "text-gray-"],
}

# Sensitive paths to check
SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.env.backup",
    "/config.php", "/wp-config.php", "/configuration.php", "/config.yml",
    "/config.yaml", "/settings.py", "/web.config", "/appsettings.json",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql",
    "/admin", "/administrator", "/manager", "/login", "/wp-admin",
    "/phpmyadmin", "/phpMyAdmin", "/pma", "/myadmin",
    "/api/swagger", "/api/swagger.json", "/api/openapi.json", "/swagger-ui.html",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/.htaccess", "/.htpasswd", "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/debug", "/test", "/phpinfo.php", "/info.php",
    "/.DS_Store", "/Thumbs.db",
    "/api/v1/users", "/api/v2/users", "/api/users",
    "/graphql", "/graphiql", "/playground",
    "/console", "/rails/info/properties",
]


class WebFingerprinter:
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.base_url = target.rstrip("/")
        self.results: Dict = {}

    async def _get(self, path: str = "") -> Optional[httpx.Response]:
        """Make a GET request."""
        url = f"{self.base_url}{path}" if path else self.base_url
        try:
            async with httpx.AsyncClient(
                timeout=10,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"},
            ) as client:
                return await client.get(url)
        except Exception:
            return None

    async def _detect_waf(self, response: httpx.Response) -> Optional[str]:
        """Detect WAF from response headers and cookies."""
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        cookies = str(response.cookies)
        body = response.text.lower() if response.text else ""
        
        for waf, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                if (sig_lower in headers_lower or
                    sig_lower in headers_lower.values() or
                    sig_lower in cookies.lower() or
                    sig_lower in body[:500]):
                    return waf
        return None

    async def _detect_cms(self, response: httpx.Response) -> List[str]:
        """Detect CMS from response."""
        detected = []
        body = response.text if response.text else ""
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for cms, sigs in CMS_SIGNATURES.items():
            # Check headers
            for h in sigs["headers"]:
                if h.lower() in headers_lower:
                    detected.append(cms)
                    break
            
            # Check body
            if cms not in detected:
                for pattern in sigs["body"]:
                    if pattern.lower() in body.lower():
                        detected.append(cms)
                        break
        
        # Check CMS-specific paths
        cms_path_tasks = []
        for cms, sigs in CMS_SIGNATURES.items():
            if cms not in detected:
                for path in sigs["paths"]:
                    cms_path_tasks.append((cms, path, self._check_path_exists(path)))
        
        for cms, path, task in cms_path_tasks:
            exists = await task
            if exists and cms not in detected:
                detected.append(cms)
        
        return detected

    async def _check_path_exists(self, path: str) -> bool:
        """Check if a path returns non-404."""
        resp = await self._get(path)
        if resp and resp.status_code not in [404, 403, 410]:
            return True
        return False

    async def _detect_frameworks(self, body: str) -> List[str]:
        """Detect JS frameworks."""
        detected = []
        for framework, patterns in FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in body.lower():
                    detected.append(framework)
                    break
        return detected

    async def _check_sensitive_paths(self) -> List[Dict]:
        """Check for exposed sensitive files."""
        found = []
        semaphore = asyncio.Semaphore(20)
        
        async def check_one(path):
            async with semaphore:
                url = f"{self.base_url}{path}"
                try:
                    async with httpx.AsyncClient(timeout=5, verify=False) as client:
                        resp = await client.get(
                            url,
                            headers={"User-Agent": "Mozilla/5.0"},
                            follow_redirects=False,
                        )
                        if resp.status_code in [200, 301, 302]:
                            severity = "HIGH"
                            if path in ["/.git/config", "/.env", "/wp-config.php", "/config.php"]:
                                severity = "CRITICAL"
                            elif path in ["/robots.txt", "/sitemap.xml"]:
                                severity = "INFO"
                            
                            result = {
                                "path": path,
                                "url": url,
                                "status": resp.status_code,
                                "severity": severity,
                                "size": len(resp.content),
                            }
                            if self.verbose:
                                color = "red" if severity == "CRITICAL" else "yellow"
                                console.print(f"  [{color}]✓ Found: {path} ({resp.status_code})[/{color}]")
                            return result
                except Exception:
                    pass
                return None
        
        tasks = [check_one(path) for path in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks)
        found = [r for r in results if r]
        return found

    async def fingerprint(self) -> Dict:
        """Run full fingerprinting."""
        console.print(f"\n[bold cyan]🔎 Fingerprinting:[/bold cyan] [white]{self.target}[/white]")
        
        # Get main page
        response = await self._get()
        if not response:
            console.print("[red]❌ Could not reach target[/red]")
            return {}
        
        server = response.headers.get("server", "Unknown")
        powered_by = response.headers.get("x-powered-by", "Unknown")
        content_type = response.headers.get("content-type", "Unknown")
        
        # Run detections in parallel
        waf_task = self._detect_waf(response)
        cms_task = self._detect_cms(response)
        framework_task = self._detect_frameworks(response.text or "")
        sensitive_task = self._check_sensitive_paths()
        
        waf, cms_list, frameworks, sensitive = await asyncio.gather(
            waf_task, cms_task, framework_task, sensitive_task
        )
        
        self.results = {
            "target": self.target,
            "status_code": response.status_code,
            "server": server,
            "powered_by": powered_by,
            "content_type": content_type,
            "waf": waf or "None detected",
            "cms": cms_list,
            "frameworks": frameworks,
            "sensitive_paths": sensitive,
            "response_size": len(response.content),
            "redirect_url": str(response.url) if str(response.url) != self.target else None,
        }
        
        self._print_results()
        return self.results

    def _print_results(self):
        """Display fingerprinting results."""
        r = self.results
        
        # Main info panel
        info_text = (
            f"[bold]Server:[/bold] {r['server']}\n"
            f"[bold]X-Powered-By:[/bold] {r['powered_by']}\n"
            f"[bold]Status Code:[/bold] {r['status_code']}\n"
            f"[bold]Content-Type:[/bold] {r['content_type']}\n"
            f"[bold]Response Size:[/bold] {r['response_size']} bytes\n"
            f"[bold]WAF Detected:[/bold] [{'red' if r['waf'] != 'None detected' else 'green'}]{r['waf']}[/{'red' if r['waf'] != 'None detected' else 'green'}]\n"
            f"[bold]CMS:[/bold] {', '.join(r['cms']) if r['cms'] else 'None detected'}\n"
            f"[bold]Frameworks:[/bold] {', '.join(r['frameworks']) if r['frameworks'] else 'None detected'}"
        )
        
        console.print(Panel(info_text, title="[bold green]🔎 Fingerprint Results[/bold green]", border_style="green"))
        
        # Sensitive paths table
        if r["sensitive_paths"]:
            table = Table(
                title=f"⚠️  Exposed Paths ({len(r['sensitive_paths'])} found)",
                box=box.ROUNDED,
                border_style="red",
            )
            table.add_column("Path", style="cyan")
            table.add_column("Status", justify="center")
            table.add_column("Severity", justify="center")
            table.add_column("Size", justify="right")
            
            for p in r["sensitive_paths"]:
                sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "INFO": "blue"}.get(p["severity"], "white")
                table.add_row(
                    p["path"],
                    str(p["status"]),
                    f"[{sev_color}]{p['severity']}[/{sev_color}]",
                    f"{p['size']} bytes",
                )
            
            console.print(table)
        else:
            console.print("[green]✅ No sensitive paths exposed[/green]")
