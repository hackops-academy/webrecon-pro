"""
Report Generator Module
- Professional HTML report with charts
- JSON export
- Plain text report
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

from rich.console import Console

console = Console()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebRecon Pro — Penetration Test Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;600;800&display=swap');

  :root {
    --bg: #0a0a0f;
    --surface: #111118;
    --surface2: #1a1a24;
    --border: #2a2a3a;
    --accent: #ff3b3b;
    --accent2: #ff6b35;
    --cyan: #00d4ff;
    --green: #00ff88;
    --yellow: #ffd700;
    --orange: #ff8c00;
    --text: #e0e0f0;
    --muted: #7070a0;
    --critical: #ff2020;
    --high: #ff6020;
    --medium: #ffd020;
    --low: #20c0ff;
    --info: #8080ff;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    line-height: 1.6;
    min-height: 100vh;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,212,255,0.015) 2px, rgba(0,212,255,0.015) 4px);
    pointer-events: none;
    z-index: 1000;
  }

  .report-header {
    background: linear-gradient(135deg, #0d0d1a 0%, #1a0a0a 100%);
    border-bottom: 2px solid var(--accent);
    padding: 3rem 4rem;
    position: relative;
    overflow: hidden;
  }

  .report-header::after {
    content: 'CONFIDENTIAL';
    position: absolute;
    top: 50%;
    right: -60px;
    transform: translateY(-50%) rotate(90deg);
    font-size: 0.65rem;
    letter-spacing: 0.5em;
    color: rgba(255,59,59,0.15);
    font-weight: 800;
  }

  .header-grid {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: center;
    gap: 2rem;
  }

  .tool-name {
    font-size: 0.75rem;
    letter-spacing: 0.4em;
    color: var(--accent);
    text-transform: uppercase;
    margin-bottom: 0.5rem;
  }

  .report-title {
    font-size: 2.8rem;
    font-weight: 800;
    line-height: 1.1;
    background: linear-gradient(135deg, #fff 0%, var(--cyan) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  .target-info {
    margin-top: 1.5rem;
    display: flex;
    gap: 2rem;
    flex-wrap: wrap;
  }

  .target-info-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .target-info-item .label {
    font-size: 0.65rem;
    letter-spacing: 0.3em;
    color: var(--muted);
    text-transform: uppercase;
  }

  .target-info-item .value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.9rem;
    color: var(--cyan);
  }

  .risk-badge {
    padding: 1.5rem 2rem;
    border-radius: 8px;
    text-align: center;
    border: 2px solid;
    min-width: 140px;
  }

  .risk-badge .risk-label {
    font-size: 0.6rem;
    letter-spacing: 0.4em;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
    opacity: 0.8;
  }

  .risk-badge .risk-score {
    font-size: 3rem;
    font-weight: 800;
    line-height: 1;
    font-family: 'JetBrains Mono', monospace;
  }

  .risk-badge .risk-level {
    font-size: 0.75rem;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    margin-top: 0.5rem;
  }

  .risk-critical { border-color: var(--critical); color: var(--critical); }
  .risk-high { border-color: var(--high); color: var(--high); }
  .risk-medium { border-color: var(--medium); color: var(--medium); }
  .risk-low { border-color: var(--low); color: var(--low); }

  .main-content {
    max-width: 1400px;
    margin: 0 auto;
    padding: 3rem 4rem;
  }

  /* Summary cards */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 3rem;
  }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }

  .stat-card:hover { border-color: var(--cyan); }

  .stat-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
  }

  .stat-card.critical::before { background: var(--critical); }
  .stat-card.high::before { background: var(--high); }
  .stat-card.medium::before { background: var(--medium); }
  .stat-card.low::before { background: var(--low); }
  .stat-card.info::before { background: var(--cyan); }

  .stat-label {
    font-size: 0.65rem;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.75rem;
  }

  .stat-number {
    font-size: 2.5rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
  }

  .stat-card.critical .stat-number { color: var(--critical); }
  .stat-card.high .stat-number { color: var(--high); }
  .stat-card.medium .stat-number { color: var(--medium); }
  .stat-card.low .stat-number { color: var(--low); }
  .stat-card.info .stat-number { color: var(--cyan); }

  /* Sections */
  .section {
    margin-bottom: 3rem;
  }

  .section-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.5rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border);
  }

  .section-icon {
    font-size: 1.5rem;
  }

  .section-title {
    font-size: 1.4rem;
    font-weight: 700;
    color: var(--text);
  }

  .section-count {
    background: var(--surface2);
    border: 1px solid var(--border);
    padding: 0.2rem 0.75rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-family: 'JetBrains Mono', monospace;
    color: var(--muted);
    margin-left: auto;
  }

  /* Finding cards */
  .finding-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 4px solid;
    border-radius: 4px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 0.75rem;
    transition: transform 0.1s;
  }

  .finding-card:hover { transform: translateX(4px); }

  .finding-card.CRITICAL { border-left-color: var(--critical); }
  .finding-card.HIGH { border-left-color: var(--high); }
  .finding-card.MEDIUM { border-left-color: var(--medium); }
  .finding-card.LOW { border-left-color: var(--low); }
  .finding-card.INFO { border-left-color: var(--info); }

  .finding-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.5rem;
    flex-wrap: wrap;
  }

  .finding-title {
    font-weight: 600;
    font-size: 0.95rem;
    flex: 1;
  }

  .sev-badge {
    padding: 0.15rem 0.6rem;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
  }

  .sev-badge.CRITICAL { background: rgba(255,32,32,0.2); color: var(--critical); border: 1px solid var(--critical); }
  .sev-badge.HIGH { background: rgba(255,96,32,0.2); color: var(--high); border: 1px solid var(--high); }
  .sev-badge.MEDIUM { background: rgba(255,208,32,0.2); color: var(--medium); border: 1px solid var(--medium); }
  .sev-badge.LOW { background: rgba(32,192,255,0.2); color: var(--low); border: 1px solid var(--low); }
  .sev-badge.INFO { background: rgba(128,128,255,0.2); color: var(--info); border: 1px solid var(--info); }

  .finding-url {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: var(--muted);
    word-break: break-all;
    margin-bottom: 0.5rem;
  }

  .finding-detail {
    font-size: 0.85rem;
    color: var(--text);
    opacity: 0.85;
  }

  .finding-meta {
    display: flex;
    gap: 1.5rem;
    margin-top: 0.75rem;
    flex-wrap: wrap;
  }

  .meta-item {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .meta-label {
    font-size: 0.6rem;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    color: var(--muted);
  }

  .meta-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: var(--cyan);
    word-break: break-all;
  }

  /* Subdomain table */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }

  .data-table th {
    text-align: left;
    padding: 0.75rem 1rem;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    font-size: 0.65rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--muted);
    font-weight: 600;
  }

  .data-table td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid rgba(42,42,58,0.5);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
  }

  .data-table tr:hover td { background: var(--surface2); }

  .status-200 { color: var(--green); }
  .status-301, .status-302 { color: var(--yellow); }
  .status-403, .status-401 { color: var(--orange); }
  .status-error { color: var(--muted); }

  /* Fingerprint section */
  .fingerprint-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
  }

  .fp-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1.25rem;
  }

  .fp-card-label {
    font-size: 0.65rem;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.5rem;
  }

  .fp-card-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.9rem;
    color: var(--cyan);
    word-break: break-all;
  }

  /* Footer */
  .report-footer {
    background: var(--surface);
    border-top: 1px solid var(--border);
    padding: 2rem 4rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
  }

  .footer-text {
    font-size: 0.75rem;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
  }

  .disclaimer {
    background: rgba(255,59,59,0.05);
    border: 1px solid rgba(255,59,59,0.2);
    border-radius: 6px;
    padding: 1.5rem;
    margin-bottom: 3rem;
    font-size: 0.8rem;
    color: var(--muted);
    line-height: 1.8;
  }

  .disclaimer strong { color: var(--accent); }

  /* Empty state */
  .empty-state {
    text-align: center;
    padding: 3rem;
    color: var(--muted);
    border: 1px dashed var(--border);
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
  }
</style>
</head>
<body>

<header class="report-header">
  <div class="header-grid">
    <div>
      <div class="tool-name">WebRecon Pro · Penetration Test Report</div>
      <h1 class="report-title">Security Assessment<br>Report</h1>
      <div class="target-info">
        <div class="target-info-item">
          <span class="label">Target</span>
          <span class="value">{{TARGET}}</span>
        </div>
        <div class="target-info-item">
          <span class="label">Scan ID</span>
          <span class="value">#{{SCAN_ID}}</span>
        </div>
        <div class="target-info-item">
          <span class="label">Started</span>
          <span class="value">{{START_TIME}}</span>
        </div>
        <div class="target-info-item">
          <span class="label">Completed</span>
          <span class="value">{{END_TIME}}</span>
        </div>
      </div>
    </div>
    <div class="risk-badge {{RISK_CLASS}}">
      <div class="risk-label">Risk Level</div>
      <div class="risk-score">{{RISK_SCORE}}</div>
      <div class="risk-level">{{RISK_LEVEL}}</div>
    </div>
  </div>
</header>

<main class="main-content">

  <div class="disclaimer">
    <strong>⚠️ CONFIDENTIAL — FOR AUTHORIZED USE ONLY</strong><br>
    This report contains sensitive security findings. It must only be used for authorized penetration testing purposes.
    Unauthorized use of these techniques against systems you do not own or have explicit permission to test is illegal.
    The WebRecon Pro team assumes no liability for misuse.
  </div>

  <!-- Summary -->
  <section class="section">
    <div class="section-header">
      <span class="section-icon">📊</span>
      <h2 class="section-title">Executive Summary</h2>
    </div>
    <div class="summary-grid">
      <div class="stat-card critical">
        <div class="stat-label">Critical</div>
        <div class="stat-number">{{COUNT_CRITICAL}}</div>
      </div>
      <div class="stat-card high">
        <div class="stat-label">High</div>
        <div class="stat-number">{{COUNT_HIGH}}</div>
      </div>
      <div class="stat-card medium">
        <div class="stat-label">Medium</div>
        <div class="stat-number">{{COUNT_MEDIUM}}</div>
      </div>
      <div class="stat-card low">
        <div class="stat-label">Low</div>
        <div class="stat-number">{{COUNT_LOW}}</div>
      </div>
      <div class="stat-card info">
        <div class="stat-label">Subdomains</div>
        <div class="stat-number">{{COUNT_SUBDOMAINS}}</div>
      </div>
    </div>
  </section>

  <!-- Fingerprint -->
  {{FINGERPRINT_SECTION}}

  <!-- Vulnerabilities -->
  <section class="section">
    <div class="section-header">
      <span class="section-icon">💥</span>
      <h2 class="section-title">Vulnerabilities</h2>
      <span class="section-count">{{TOTAL_VULNS}} findings</span>
    </div>
    {{VULN_CARDS}}
  </section>

  <!-- Auth -->
  <section class="section">
    <div class="section-header">
      <span class="section-icon">🔐</span>
      <h2 class="section-title">Authentication Issues</h2>
      <span class="section-count">{{COUNT_AUTH}} findings</span>
    </div>
    {{AUTH_CARDS}}
  </section>

  <!-- API -->
  <section class="section">
    <div class="section-header">
      <span class="section-icon">🔌</span>
      <h2 class="section-title">API Security Issues</h2>
      <span class="section-count">{{COUNT_API}} findings</span>
    </div>
    {{API_CARDS}}
  </section>

  <!-- Subdomains -->
  <section class="section">
    <div class="section-header">
      <span class="section-icon">🌐</span>
      <h2 class="section-title">Discovered Subdomains</h2>
      <span class="section-count">{{COUNT_SUBDOMAINS}} found</span>
    </div>
    {{SUBDOMAIN_TABLE}}
  </section>

</main>

<footer class="report-footer">
  <span class="footer-text">WebRecon Pro v1.0.0 · Generated {{GENERATED_AT}}</span>
  <span class="footer-text">FOR AUTHORIZED PENETRATION TESTING ONLY</span>
</footer>

</body>
</html>
"""


class ReportGenerator:
    def __init__(self, results: Dict, output_dir: str = "./reports"):
        self.results = results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _calc_risk(self) -> tuple:
        """Calculate overall risk score."""
        all_findings = (
            self.results.get("vulnerabilities", []) +
            self.results.get("auth_findings", []) +
            self.results.get("api_findings", []) +
            self.results.get("header_findings", [])
        )
        
        critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
        
        score = critical * 40 + high * 20 + medium * 10
        score = min(score, 100)
        
        if critical > 0:
            return score, "CRITICAL", "risk-critical"
        elif high > 2:
            return score, "HIGH", "risk-high"
        elif medium > 0 or high > 0:
            return score, "MEDIUM", "risk-medium"
        else:
            return score, "LOW", "risk-low"

    def _render_finding_card(self, f: Dict) -> str:
        sev = f.get("severity", "INFO")
        return f"""
        <div class="finding-card {sev}">
          <div class="finding-header">
            <span class="finding-title">{f.get('type', 'Unknown')}</span>
            <span class="sev-badge {sev}">{sev}</span>
          </div>
          <div class="finding-url">🔗 {f.get('url', '-')}</div>
          <div class="finding-detail">{f.get('detail', '')}</div>
          <div class="finding-meta">
            {'<div class="meta-item"><div class="meta-label">Parameter</div><div class="meta-value">' + str(f.get('parameter', '')) + '</div></div>' if f.get('parameter') else ''}
            {'<div class="meta-item"><div class="meta-label">Payload</div><div class="meta-value">' + str(f.get('payload', ''))[:80] + '</div></div>' if f.get('payload') and f.get('payload') != 'N/A' else ''}
            {'<div class="meta-item"><div class="meta-label">Remediation</div><div class="meta-value">' + str(f.get('remediation', '')) + '</div></div>' if f.get('remediation') else ''}
          </div>
        </div>"""

    def _render_findings_section(self, findings: List[Dict]) -> str:
        if not findings:
            return '<div class="empty-state">✅ No findings in this category</div>'
        
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get("severity"), 5))
        
        return "\n".join(self._render_finding_card(f) for f in sorted_findings)

    def _render_fingerprint_section(self) -> str:
        fp = self.results.get("fingerprint", {})
        if not fp:
            return ""
        
        items = [
            ("Server", fp.get("server", "Unknown")),
            ("X-Powered-By", fp.get("powered_by", "Unknown")),
            ("WAF", fp.get("waf", "None detected")),
            ("CMS", ", ".join(fp.get("cms", [])) or "None detected"),
            ("Frameworks", ", ".join(fp.get("frameworks", [])) or "None detected"),
            ("Status Code", str(fp.get("status_code", "-"))),
        ]
        
        cards = "\n".join(f"""
        <div class="fp-card">
          <div class="fp-card-label">{label}</div>
          <div class="fp-card-value">{value}</div>
        </div>""" for label, value in items)
        
        return f"""
    <section class="section">
      <div class="section-header">
        <span class="section-icon">🔎</span>
        <h2 class="section-title">Fingerprinting Results</h2>
      </div>
      <div class="fingerprint-grid">{cards}</div>
    </section>"""

    def _render_subdomain_table(self) -> str:
        subdomains = self.results.get("subdomains", [])
        if not subdomains:
            return '<div class="empty-state">No subdomains discovered</div>'
        
        rows = ""
        for s in subdomains:
            status = s.get("status", "-")
            status_class = f"status-{status}" if status.isdigit() else "status-error"
            rows += f"""
          <tr>
            <td>{s.get('subdomain', '-')}</td>
            <td>{s.get('ip', '-')}</td>
            <td class="{status_class}">{status}</td>
            <td>{s.get('source', '-')}</td>
          </tr>"""
        
        return f"""
        <table class="data-table">
          <thead>
            <tr><th>Subdomain</th><th>IP Address</th><th>HTTP Status</th><th>Source</th></tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>"""

    def generate(self, format: str = "html") -> str:
        """Generate report in specified format."""
        target = self.results.get("target", "Unknown")
        domain = urlparse(target).netloc or target
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "json":
            return self._generate_json(domain, timestamp)
        elif format == "txt":
            return self._generate_txt(domain, timestamp)
        else:
            return self._generate_html(domain, timestamp)

    def _generate_html(self, domain: str, timestamp: str) -> str:
        """Generate HTML report."""
        all_vulns = self.results.get("vulnerabilities", [])
        auth_findings = self.results.get("auth_findings", [])
        api_findings = self.results.get("api_findings", [])
        header_findings = self.results.get("header_findings", [])
        subdomains = self.results.get("subdomains", [])
        
        all_findings = all_vulns + auth_findings + api_findings + header_findings
        
        critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in all_findings if f.get("severity") == "LOW")
        
        risk_score, risk_level, risk_class = self._calc_risk()
        
        html = HTML_TEMPLATE
        replacements = {
            "{{TARGET}}": self.results.get("target", "Unknown"),
            "{{SCAN_ID}}": str(self.results.get("scan_id", "N/A")),
            "{{START_TIME}}": self.results.get("start_time", "-")[:19].replace("T", " "),
            "{{END_TIME}}": self.results.get("end_time", "-")[:19].replace("T", " "),
            "{{RISK_CLASS}}": risk_class,
            "{{RISK_SCORE}}": str(risk_score),
            "{{RISK_LEVEL}}": risk_level,
            "{{COUNT_CRITICAL}}": str(critical),
            "{{COUNT_HIGH}}": str(high),
            "{{COUNT_MEDIUM}}": str(medium),
            "{{COUNT_LOW}}": str(low),
            "{{COUNT_SUBDOMAINS}}": str(len(subdomains)),
            "{{TOTAL_VULNS}}": str(len(all_vulns) + len(header_findings)),
            "{{COUNT_AUTH}}": str(len(auth_findings)),
            "{{COUNT_API}}": str(len(api_findings)),
            "{{FINGERPRINT_SECTION}}": self._render_fingerprint_section(),
            "{{VULN_CARDS}}": self._render_findings_section(all_vulns + header_findings),
            "{{AUTH_CARDS}}": self._render_findings_section(auth_findings),
            "{{API_CARDS}}": self._render_findings_section(api_findings),
            "{{SUBDOMAIN_TABLE}}": self._render_subdomain_table(),
            "{{GENERATED_AT}}": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        for key, value in replacements.items():
            html = html.replace(key, str(value))
        
        filename = f"webrecon_{domain.replace('.', '_')}_{timestamp}.html"
        filepath = self.output_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        
        console.print(f"[green]✅ HTML report generated: {filepath}[/green]")
        return str(filepath)

    def _generate_json(self, domain: str, timestamp: str) -> str:
        """Generate JSON report."""
        filename = f"webrecon_{domain.replace('.', '_')}_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        
        console.print(f"[green]✅ JSON report generated: {filepath}[/green]")
        return str(filepath)

    def _generate_txt(self, domain: str, timestamp: str) -> str:
        """Generate plain text report."""
        filename = f"webrecon_{domain.replace('.', '_')}_{timestamp}.txt"
        filepath = self.output_dir / filename
        
        lines = [
            "=" * 70,
            "WEBRECON PRO - PENETRATION TEST REPORT",
            "=" * 70,
            f"Target:    {self.results.get('target', '-')}",
            f"Started:   {self.results.get('start_time', '-')}",
            f"Completed: {self.results.get('end_time', '-')}",
            "",
            "VULNERABILITIES",
            "-" * 40,
        ]
        
        all_findings = (
            self.results.get("vulnerabilities", []) +
            self.results.get("auth_findings", []) +
            self.results.get("api_findings", []) +
            self.results.get("header_findings", [])
        )
        
        for f in all_findings:
            lines.append(f"[{f.get('severity')}] {f.get('type')} — {f.get('detail', '')}")
        
        lines.extend(["", "SUBDOMAINS", "-" * 40])
        for s in self.results.get("subdomains", []):
            lines.append(f"{s.get('subdomain')} → {s.get('ip')} ({s.get('status')})")
        
        with open(filepath, "w") as f:
            f.write("\n".join(lines))
        
        console.print(f"[green]✅ Text report generated: {filepath}[/green]")
        return str(filepath)
