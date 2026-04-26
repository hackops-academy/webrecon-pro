"""
API Security Testing Module
- Swagger/OpenAPI spec discovery and parsing
- Endpoint enumeration
- IDOR testing
- Mass assignment detection
- Broken auth on API endpoints
- GraphQL introspection
- Verbose error detection
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Common API paths to discover
API_DISCOVERY_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/v1", "/v2", "/v3",
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/swagger-ui.html", "/swagger-ui/",
    "/api/swagger.json", "/api/openapi.json",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs",
    "/graphql", "/graphiql", "/playground",
    "/api/graphql",
    "/actuator", "/actuator/mappings",
    "/.well-known/openapi",
]

# Common API endpoints to test
COMMON_API_ENDPOINTS = [
    "/api/v1/users", "/api/v1/user",
    "/api/v1/admin", "/api/v1/accounts",
    "/api/v1/orders", "/api/v1/products",
    "/api/v1/files", "/api/v1/upload",
    "/api/v1/config", "/api/v1/settings",
    "/api/users", "/api/accounts",
    "/api/admin", "/api/products",
    "/users", "/user/profile",
    "/admin/users", "/admin/config",
]

# GRAPHQL introspection query
GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
"""


class APITester:
    def __init__(self, target: str, spec_url: Optional[str] = None, verbose: bool = False):
        self.target = target
        self.spec_url = spec_url
        self.verbose = verbose
        self.base_url = target.rstrip("/")
        self.findings: List[Dict] = []
        self.discovered_endpoints: List[Dict] = []
        self.semaphore = asyncio.Semaphore(10)

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
        console.print(f"  [{sev_color}]🔌 [{severity}] {vuln_type}[/{sev_color}] — {detail[:70]}")

    async def _request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        async with self.semaphore:
            try:
                headers = {
                    "User-Agent": "WebReconPro/1.0",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    **kwargs.pop("headers", {})
                }
                async with httpx.AsyncClient(
                    timeout=10, verify=False, follow_redirects=True, headers=headers
                ) as client:
                    return await client.request(method, url, **kwargs)
            except Exception:
                return None

    async def discover_api_endpoints(self) -> List[Dict]:
        """Discover API endpoints."""
        console.print("\n[bold]  🔍 Discovering API endpoints...[/bold]")
        
        found = []
        tasks = [self._check_endpoint(path) for path in API_DISCOVERY_PATHS + COMMON_API_ENDPOINTS]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                found.append(result)
                if self.verbose:
                    console.print(f"  [green]✓ {result['method']} {result['url']} [{result['status']}][/green]")
        
        self.discovered_endpoints = found
        console.print(f"  [green]✓ Discovered {len(found)} API endpoint(s)[/green]")
        return found

    async def _check_endpoint(self, path: str) -> Optional[Dict]:
        """Check if an API endpoint exists."""
        url = f"{self.base_url}{path}"
        resp = await self._request("GET", url)
        
        if resp and resp.status_code not in [404]:
            content_type = resp.headers.get("content-type", "")
            is_api = "application/json" in content_type or "application/xml" in content_type
            
            return {
                "url": url,
                "path": path,
                "method": "GET",
                "status": resp.status_code,
                "content_type": content_type,
                "is_api": is_api,
                "size": len(resp.content),
            }
        return None

    async def test_swagger_spec(self) -> Optional[Dict]:
        """Try to fetch and parse OpenAPI/Swagger spec."""
        console.print("\n[bold]  🔍 Looking for API spec (Swagger/OpenAPI)...[/bold]")
        
        spec_paths = [
            "/swagger.json", "/swagger.yaml",
            "/api/swagger.json", "/api/openapi.json",
            "/openapi.json", "/v1/swagger.json",
            "/api-docs", "/api/docs",
        ]
        
        if self.spec_url:
            spec_paths.insert(0, self.spec_url)
        
        for path in spec_paths:
            url = f"{self.base_url}{path}" if not path.startswith("http") else path
            resp = await self._request("GET", url)
            
            if resp and resp.status_code == 200:
                try:
                    spec = resp.json()
                    if "paths" in spec or "swagger" in spec or "openapi" in spec:
                        console.print(f"  [green]✓ Found API spec at: {url}[/green]")
                        
                        self._add_finding(
                            "Exposed API Documentation",
                            "MEDIUM",
                            url,
                            "OpenAPI/Swagger spec is publicly accessible",
                        )
                        
                        # Extract endpoints from spec
                        endpoints = self._parse_openapi_spec(spec, url)
                        self.discovered_endpoints.extend(endpoints)
                        return spec
                except Exception:
                    pass
        
        return None

    def _parse_openapi_spec(self, spec: Dict, spec_url: str) -> List[Dict]:
        """Parse OpenAPI spec and extract endpoints."""
        endpoints = []
        base_url = self.base_url
        
        # Get base path
        if "basePath" in spec:
            base_url += spec["basePath"]
        
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    full_url = f"{base_url}{path}"
                    endpoints.append({
                        "url": full_url,
                        "path": path,
                        "method": method.upper(),
                        "status": "discovered",
                        "from_spec": True,
                        "requires_auth": bool(details.get("security")),
                        "parameters": details.get("parameters", []),
                    })
        
        console.print(f"  [cyan]→ Extracted {len(endpoints)} endpoints from spec[/cyan]")
        return endpoints

    async def test_idor(self):
        """Test for Insecure Direct Object Reference (IDOR)."""
        console.print("\n[bold]  🔍 Testing for IDOR...[/bold]")
        
        # Common ID-based patterns
        idor_paths = [
            ("/api/v1/users/{id}", [1, 2, 3, 100]),
            ("/api/v1/orders/{id}", [1, 2, 3]),
            ("/api/v1/files/{id}", [1, 2, 3]),
            ("/api/users/{id}", [1, 2, 3]),
            ("/user/{id}", [1, 2, 3]),
            ("/profile/{id}", [1, 2, 3]),
        ]
        
        for path_template, ids in idor_paths:
            responses = []
            for id_val in ids:
                path = path_template.replace("{id}", str(id_val))
                url = f"{self.base_url}{path}"
                resp = await self._request("GET", url)
                if resp:
                    responses.append((id_val, resp.status_code, len(resp.content)))
            
            # If multiple IDs return 200 with different content sizes, potential IDOR
            success_responses = [(id_val, code, size) for id_val, code, size in responses if code == 200]
            if len(success_responses) >= 2:
                sizes = [size for _, _, size in success_responses]
                # Different content = different records = IDOR likely
                if len(set(sizes)) > 1:
                    self._add_finding(
                        "Potential IDOR",
                        "HIGH",
                        f"{self.base_url}{path_template}",
                        f"Multiple user records accessible without auth (IDs: {[r[0] for r in success_responses]})",
                    )

    async def test_graphql(self):
        """Test GraphQL security."""
        console.print("\n[bold]  🔍 Testing GraphQL security...[/bold]")
        
        graphql_paths = ["/graphql", "/api/graphql", "/graphiql", "/playground"]
        
        for path in graphql_paths:
            url = f"{self.base_url}{path}"
            
            # Test introspection
            resp = await self._request(
                "POST", url,
                json={"query": GRAPHQL_INTROSPECTION_QUERY}
            )
            
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "__schema" in str(data):
                        self._add_finding(
                            "GraphQL Introspection Enabled",
                            "MEDIUM",
                            url,
                            "GraphQL introspection is enabled — full schema exposed to attackers",
                        )
                        
                        # Extract types and fields
                        schema = data.get("data", {}).get("__schema", {})
                        types = schema.get("types", [])
                        sensitive_types = [
                            t["name"] for t in types
                            if any(kw in t["name"].lower() for kw in ["user", "admin", "password", "secret", "token", "key"])
                        ]
                        
                        if sensitive_types:
                            self._add_finding(
                                "GraphQL Sensitive Types Exposed",
                                "HIGH",
                                url,
                                f"Sensitive schema types visible: {', '.join(sensitive_types[:5])}",
                            )
                except Exception:
                    pass
            
            # Test for GraphQL playground exposure
            resp_get = await self._request("GET", url)
            if resp_get and resp_get.status_code == 200:
                body = resp_get.text or ""
                if "graphiql" in body.lower() or "playground" in body.lower() or "graphql" in body.lower():
                    self._add_finding(
                        "GraphQL Playground Exposed",
                        "LOW",
                        url,
                        "Interactive GraphQL IDE is publicly accessible",
                    )

    async def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities."""
        console.print("\n[bold]  🔍 Testing for Mass Assignment...[/bold]")
        
        # Try common registration/update endpoints with admin-level fields
        test_endpoints = [
            "/api/v1/users/register",
            "/api/v1/user/update",
            "/api/register",
            "/api/user",
            "/register",
        ]
        
        # Payload with privilege escalation attempt
        mass_assignment_payload = {
            "username": "testuser",
            "email": "test@test.com",
            "password": "test1234",
            "role": "admin",         # Attempt privilege escalation
            "is_admin": True,
            "admin": True,
            "is_staff": True,
            "permissions": ["admin", "superuser"],
            "account_type": "premium",
        }
        
        for endpoint in test_endpoints:
            url = f"{self.base_url}{endpoint}"
            resp = await self._request("POST", url, json=mass_assignment_payload)
            
            if resp and resp.status_code in [200, 201]:
                body = resp.text or ""
                # Check if any admin fields were accepted
                if any(field in body.lower() for field in ["admin", "role", "is_admin", "permission"]):
                    self._add_finding(
                        "Mass Assignment",
                        "HIGH",
                        url,
                        "API may accept privileged fields (role, is_admin) in request body",
                    )

    async def test_broken_auth_on_api(self):
        """Test API endpoints for broken authentication."""
        console.print("\n[bold]  🔍 Testing API broken authentication...[/bold]")
        
        # Test endpoints without auth
        auth_required_paths = [
            "/api/v1/users", "/api/v1/admin",
            "/api/admin", "/api/users",
            "/api/v1/config", "/api/config",
        ]
        
        tasks = []
        for path in auth_required_paths:
            tasks.append(self._test_no_auth_access(path))
        
        await asyncio.gather(*tasks)
        
        # Test with invalid tokens
        test_tokens = [
            "invalid_token",
            "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",  # alg:none JWT
            "null",
            "undefined",
            "",
        ]
        
        for path in auth_required_paths[:3]:
            url = f"{self.base_url}{path}"
            for token in test_tokens:
                resp = await self._request(
                    "GET", url,
                    headers={"Authorization": f"Bearer {token}"}
                )
                if resp and resp.status_code == 200 and len(resp.content) > 100:
                    self._add_finding(
                        "Broken API Authentication",
                        "CRITICAL",
                        url,
                        f"API returns data with invalid token: '{token[:30]}'",
                    )
                    break

    async def _test_no_auth_access(self, path: str):
        """Check if path is accessible without authentication."""
        url = f"{self.base_url}{path}"
        resp = await self._request("GET", url)
        
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                # If it returns a non-empty JSON response, it might be an unprotected endpoint
                if data and (isinstance(data, list) or (isinstance(data, dict) and len(data) > 0)):
                    self._add_finding(
                        "Unauthenticated API Access",
                        "HIGH",
                        url,
                        f"API endpoint returns data without authentication ({len(resp.content)} bytes)",
                    )
            except Exception:
                pass

    async def test_verbose_errors(self):
        """Test for verbose error messages."""
        console.print("\n[bold]  🔍 Testing for verbose API errors...[/bold]")
        
        # Send malformed requests
        test_cases = [
            ("GET", "?id='; DROP TABLE users--", {}),
            ("POST", "", {"data": None}),
            ("GET", "?limit=-1&offset=abc", {}),
        ]
        
        for method, suffix, data in test_cases:
            url = f"{self.base_url}/api/v1/users{suffix}"
            if method == "GET":
                resp = await self._request("GET", url)
            else:
                resp = await self._request("POST", url, json=data)
            
            if not resp:
                continue
            
            body = resp.text or ""
            
            # Check for stack traces or internal errors
            error_patterns = [
                r"Traceback \(most recent",
                r"at .+\.java:\d+",
                r"Exception in thread",
                r"System\.Exception",
                r"NullPointerException",
                r"mysql_fetch",
                r"SQLSTATE",
                r"ORA-\d{5}",
                r"Warning: .+\(\)",
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    self._add_finding(
                        "Verbose Error Messages",
                        "MEDIUM",
                        url,
                        f"Stack trace or internal error exposed: pattern '{pattern}'",
                    )
                    break

    async def test_all(self) -> List[Dict]:
        """Run all API security tests."""
        console.print(f"\n[bold cyan]🔌 Testing API Security for:[/bold cyan] [white]{self.target}[/white]")
        
        await self.discover_api_endpoints()
        await self.test_swagger_spec()
        await self.test_idor()
        await self.test_graphql()
        await self.test_mass_assignment()
        await self.test_broken_auth_on_api()
        await self.test_verbose_errors()
        
        self._print_summary()
        return self.findings

    def _print_summary(self):
        """Print API testing summary."""
        console.print()
        
        if self.discovered_endpoints:
            table = Table(title=f"🔌 API Endpoints ({len(self.discovered_endpoints)})", box=box.SIMPLE, border_style="cyan")
            table.add_column("Method", style="bold", justify="center")
            table.add_column("URL", style="cyan")
            table.add_column("Status", justify="center")
            
            for ep in self.discovered_endpoints[:15]:
                status = str(ep.get("status", "-"))
                color = "green" if status.startswith("2") else "yellow" if status.startswith("3") else "red"
                table.add_row(
                    f"[blue]{ep['method']}[/blue]",
                    ep["url"],
                    f"[{color}]{status}[/{color}]",
                )
            
            console.print(table)
        
        if not self.findings:
            console.print("[green]✅ No API vulnerabilities found[/green]")
            return
        
        table = Table(
            title=f"🚨 API Security Findings ({len(self.findings)})",
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
