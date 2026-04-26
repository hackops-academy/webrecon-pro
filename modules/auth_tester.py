"""
Authentication Testing Module
- Default credential testing
- JWT security analysis
- Session security checks
- Brute force detection bypass
- Password policy testing
"""

import asyncio
import base64
import json
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Common default credentials
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("test", "test"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("demo", "demo"),
    ("admin", "letmein"),
    ("admin", "welcome"),
    ("admin", "qwerty"),
    ("admin", "changeme"),
    ("admin", "1234"),
]

# Common login paths
LOGIN_PATHS = [
    "/login", "/admin/login", "/wp-login.php", "/user/login",
    "/auth/login", "/signin", "/sign-in", "/account/login",
    "/api/login", "/api/auth", "/api/v1/login", "/api/v1/auth",
    "/administrator", "/admin", "/panel",
]

# Common JWT weak secrets
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "your-secret-key",
    "changeme", "supersecret", "secret123", "mysecret", "jwttoken",
    "admin", "test", "key", "private", "qwerty", "letmein",
]


class AuthTester:
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.base_url = target.rstrip("/")
        self.findings: List[Dict] = []
        self.semaphore = asyncio.Semaphore(5)

    def _add_finding(self, vuln_type: str, severity: str, url: str, detail: str, extra: Dict = None):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "detail": detail,
            **(extra or {}),
        }
        self.findings.append(finding)
        
        sev_color = {
            "CRITICAL": "bold red", "HIGH": "red",
            "MEDIUM": "yellow", "LOW": "cyan", "INFO": "blue"
        }.get(severity, "white")
        console.print(f"  [{sev_color}]🔐 [{severity}] {vuln_type}[/{sev_color}] — {detail[:70]}")

    async def _get(self, path: str = "") -> Optional[httpx.Response]:
        url = f"{self.base_url}{path}" if path else self.base_url
        async with self.semaphore:
            try:
                async with httpx.AsyncClient(
                    timeout=10, verify=False, follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 WebReconPro/1.0"},
                ) as client:
                    return await client.get(url)
            except Exception:
                return None

    async def _post(self, url: str, data: Dict = None, json_data: Dict = None, headers: Dict = None) -> Optional[httpx.Response]:
        async with self.semaphore:
            try:
                h = {"User-Agent": "Mozilla/5.0 WebReconPro/1.0", **(headers or {})}
                async with httpx.AsyncClient(
                    timeout=10, verify=False, follow_redirects=True, headers=h,
                ) as client:
                    if json_data:
                        return await client.post(url, json=json_data)
                    return await client.post(url, data=data)
            except Exception:
                return None

    async def find_login_pages(self) -> List[str]:
        """Discover login pages."""
        console.print("\n[bold]  🔍 Discovering login pages...[/bold]")
        login_pages = []
        
        tasks = []
        for path in LOGIN_PATHS:
            tasks.append(self._check_login_path(path))
        
        results = await asyncio.gather(*tasks)
        login_pages = [r for r in results if r]
        
        if login_pages:
            console.print(f"  [green]✓ Found {len(login_pages)} login page(s)[/green]")
            for page in login_pages:
                console.print(f"    [cyan]→ {page}[/cyan]")
        
        return login_pages

    async def _check_login_path(self, path: str) -> Optional[str]:
        resp = await self._get(path)
        if resp and resp.status_code in [200, 401, 403]:
            body = resp.text or ""
            if any(kw in body.lower() for kw in ["password", "username", "login", "email", "signin"]):
                return f"{self.base_url}{path}"
        return None

    async def test_default_credentials(self, login_urls: List[str]):
        """Test default/common credentials."""
        console.print("\n[bold]  🔍 Testing default credentials...[/bold]")
        
        for url in login_urls[:3]:  # Limit to first 3 login pages
            for username, password in DEFAULT_CREDENTIALS[:10]:  # Top 10 creds
                await self._try_login(url, username, password)
                await asyncio.sleep(0.2)  # Rate limit ourselves

    async def _try_login(self, url: str, username: str, password: str):
        """Attempt a login with given credentials."""
        # Try common field names
        for user_field, pass_field in [("username", "password"), ("user", "pass"), ("email", "password"), ("login", "password")]:
            resp = await self._post(url, data={user_field: username, pass_field: password})
            
            if not resp:
                continue
            
            # Check for successful login indicators
            if resp.status_code in [200, 302]:
                body = resp.text or ""
                # Check for failure indicators
                failure_indicators = [
                    "invalid", "incorrect", "wrong", "failed", "error",
                    "unauthorized", "denied", "bad credentials",
                ]
                
                is_failure = any(ind in body.lower() for ind in failure_indicators)
                is_redirect = resp.status_code == 302 and any(
                    kw in resp.headers.get("location", "").lower()
                    for kw in ["dashboard", "admin", "home", "welcome", "panel"]
                )
                
                # Also check if response is drastically different (logged in content)
                if is_redirect or (not is_failure and len(body) > 1000):
                    self._add_finding(
                        "Default Credentials",
                        "CRITICAL",
                        url,
                        f"Login succeeded with {username}:{password}",
                        {"credentials": f"{username}:{password}"},
                    )
                    return

    async def test_jwt_security(self):
        """Test JWT token security."""
        console.print("\n[bold]  🔍 Testing JWT security...[/bold]")
        
        # Check for JWT in responses
        resp = await self._get()
        if not resp:
            return
        
        # Look for JWT patterns in response body and cookies
        jwt_pattern = r"eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=_-]+"
        body = resp.text or ""
        
        # Check cookies for JWT
        cookie_header = str(resp.headers)
        found_jwts = re.findall(jwt_pattern, body + cookie_header)
        
        if found_jwts:
            for jwt_token in found_jwts[:3]:  # Analyze up to 3 JWTs
                await self._analyze_jwt(jwt_token)
        
        # Try common API auth endpoints
        api_paths = ["/api/auth", "/api/login", "/api/token", "/auth/token"]
        for path in api_paths:
            resp = await self._post(
                f"{self.base_url}{path}",
                json_data={"username": "test", "password": "test"}
            )
            if resp and resp.status_code == 200:
                body = resp.text or ""
                found = re.findall(jwt_pattern, body)
                for jwt_token in found:
                    await self._analyze_jwt(jwt_token)

    async def _analyze_jwt(self, token: str):
        """Analyze a JWT token for vulnerabilities."""
        parts = token.split(".")
        if len(parts) != 3:
            return
        
        try:
            # Decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.b64decode(header_padded).decode("utf-8", errors="ignore"))
            
            # Decode payload
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.b64decode(payload_padded).decode("utf-8", errors="ignore"))
            
            alg = header.get("alg", "").upper()
            
            # Check for weak algorithms
            if alg == "NONE":
                self._add_finding(
                    "JWT Algorithm None Attack",
                    "CRITICAL",
                    self.base_url,
                    "JWT uses 'none' algorithm — token signature not verified",
                )
            elif alg == "HS256":
                # Try to brute-force the secret
                console.print("  [dim]  ↳ Attempting JWT secret brute-force...[/dim]")
                cracked = self._crack_jwt_secret(token, parts)
                if cracked:
                    self._add_finding(
                        "Weak JWT Secret",
                        "CRITICAL",
                        self.base_url,
                        f"JWT signed with weak secret: '{cracked}'",
                        {"jwt_secret": cracked},
                    )
            
            # Check payload for sensitive data
            sensitive_keys = ["password", "passwd", "secret", "key", "token", "ssn", "credit"]
            for key in sensitive_keys:
                if key in str(payload).lower():
                    self._add_finding(
                        "Sensitive Data in JWT",
                        "HIGH",
                        self.base_url,
                        f"Sensitive field '{key}' found in JWT payload",
                    )
            
            # Check expiration
            exp = payload.get("exp")
            if not exp:
                self._add_finding(
                    "JWT No Expiration",
                    "MEDIUM",
                    self.base_url,
                    "JWT has no expiration (exp) claim — token is valid forever",
                )
            
            if self.verbose:
                console.print(f"  [dim]JWT Header: {header}[/dim]")
                console.print(f"  [dim]JWT Payload: {payload}[/dim]")
                
        except Exception:
            pass

    def _crack_jwt_secret(self, token: str, parts: List[str]) -> Optional[str]:
        """Try to crack JWT secret with common passwords."""
        try:
            import hmac
            import hashlib
            
            message = f"{parts[0]}.{parts[1]}".encode()
            signature_padded = parts[2] + "=" * (4 - len(parts[2]) % 4)
            expected_sig = base64.urlsafe_b64decode(signature_padded)
            
            for secret in WEAK_JWT_SECRETS:
                try:
                    sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
                    if sig == expected_sig:
                        return secret
                except Exception:
                    pass
        except Exception:
            pass
        return None

    async def test_session_security(self):
        """Test session token security."""
        console.print("\n[bold]  🔍 Testing session security...[/bold]")
        
        resp = await self._get()
        if not resp:
            return
        
        cookies = resp.cookies
        set_cookie = resp.headers.get("set-cookie", "")
        
        if not set_cookie and not cookies:
            console.print("  [dim]No cookies found[/dim]")
            return
        
        # Check session cookie entropy (simplified)
        import re
        session_patterns = re.findall(r"([A-Za-z_-]*session[A-Za-z_-]*)=([^;]+)", set_cookie, re.IGNORECASE)
        
        for name, value in session_patterns:
            value = value.strip()
            
            # Check if session ID is predictable (too short)
            if len(value) < 16:
                self._add_finding(
                    "Weak Session ID",
                    "HIGH",
                    self.base_url,
                    f"Session cookie '{name}' appears too short ({len(value)} chars) — may be predictable",
                )
            
            # Check if session looks sequential or simple
            if value.isdigit() and int(value) < 1000000:
                self._add_finding(
                    "Predictable Session ID",
                    "CRITICAL",
                    self.base_url,
                    f"Session ID '{name}={value}' appears to be a simple integer",
                )

    async def test_brute_force_protection(self):
        """Test if brute force protection exists."""
        console.print("\n[bold]  🔍 Testing brute force protection...[/bold]")
        
        login_pages = await self.find_login_pages()
        
        for url in login_pages[:1]:
            # Send 5 rapid failed requests
            failed_responses = []
            for _ in range(5):
                resp = await self._post(url, data={"username": "admin", "password": "wrongpassword_test"})
                if resp:
                    failed_responses.append(resp.status_code)
                await asyncio.sleep(0.1)
            
            # Check if we got rate-limited or blocked
            if all(code == 200 for code in failed_responses):
                self._add_finding(
                    "No Brute Force Protection",
                    "MEDIUM",
                    url,
                    "Login endpoint doesn't appear to rate-limit failed attempts",
                )
            
            # Check for CAPTCHA in responses
            if failed_responses:
                # Just check the last response
                resp = await self._post(url, data={"username": "admin", "password": "wrongpassword_test"})
                if resp and resp.text:
                    if "captcha" not in resp.text.lower() and "recaptcha" not in resp.text.lower():
                        if "lockout" not in resp.text.lower() and "locked" not in resp.text.lower():
                            self._add_finding(
                                "No CAPTCHA on Login",
                                "LOW",
                                url,
                                "No CAPTCHA detected after multiple failed login attempts",
                            )

    async def test_all(self) -> List[Dict]:
        """Run all authentication tests."""
        console.print(f"\n[bold cyan]🔐 Testing Authentication for:[/bold cyan] [white]{self.target}[/white]")
        
        login_pages = await self.find_login_pages()
        
        if login_pages:
            await self.test_default_credentials(login_pages)
            await self.test_brute_force_protection()
        
        await self.test_jwt_security()
        await self.test_session_security()
        
        self._print_summary()
        return self.findings

    def _print_summary(self):
        """Print auth testing summary."""
        console.print()
        
        if not self.findings:
            console.print("[green]✅ No authentication vulnerabilities found[/green]")
            return
        
        table = Table(
            title=f"🔐 Auth Findings ({len(self.findings)})",
            box=box.ROUNDED,
            border_style="red",
        )
        table.add_column("Type", style="cyan", min_width=28)
        table.add_column("Severity", justify="center")
        table.add_column("Detail", style="dim")
        
        for f in self.findings:
            sev = f["severity"]
            sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
            table.add_row(
                f["type"],
                f"[{sev_color}]{sev}[/{sev_color}]",
                f.get("detail", "")[:55],
            )
        
        console.print(table)
