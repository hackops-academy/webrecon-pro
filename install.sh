#!/bin/bash
# =============================================================================
#  WebRecon Pro - Automatic Installer
#  Works from any directory, any username, any clone location
#
#  Usage:
#    git clone https://github.com/hackops-academy/webrecon-pro.git
#    cd webrecon-pro
#    sudo bash install.sh
# =============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

# CRITICAL: Always detect the real location of THIS script
SCRIPT_DIR="$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && pwd)"

INSTALL_DIR="/opt/webrecon"
BIN_LINK="/usr/local/bin/webrecon"
DESKTOP_FILE="/usr/share/applications/webrecon.desktop"
ICON_DIR="/usr/share/icons/hicolor/256x256/apps"
LOG_FILE="/tmp/webrecon_install.log"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

log()     { echo -e "${GREEN}[✓]${RESET} $1"; }
info()    { echo -e "${CYAN}[*]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗] ERROR: $1${RESET}"; exit 1; }
section() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

print_banner() {
  clear
  echo -e "${RED}${BOLD}"
  echo " ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ "
  echo " ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗"
  echo " ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║"
  echo " ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║"
  echo " ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝"
  echo "  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝"
  echo -e "${RESET}"
  echo -e "${BOLD}${CYAN}   WebRecon Pro v1.0.0 — Professional Web Penetration Testing Framework${RESET}"
  echo -e "${YELLOW}                  FOR AUTHORIZED PENETRATION TESTING ONLY${RESET}"
  echo ""
  echo -e "  ${BOLD}Installing from:${RESET} ${CYAN}$SCRIPT_DIR${RESET}"
  echo -e "  ${BOLD}Installing to:  ${RESET} ${CYAN}$INSTALL_DIR${RESET}"
  echo -e "  ${BOLD}User:           ${RESET} ${CYAN}$REAL_USER${RESET}"
  echo ""
}

check_root() {
  [[ $EUID -ne 0 ]] && error "Run with sudo: sudo bash install.sh"
  log "Running as root"
}

check_python() {
  command -v python3 &>/dev/null || error "Python 3 not found. Run: sudo apt install python3"
  PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  log "Python $PY_VER found"
}

check_source_files() {
  section "Verifying Source Files"
  info "Source: $SCRIPT_DIR"
  [[ ! -f "$SCRIPT_DIR/main.py" ]]   && error "main.py not found in $SCRIPT_DIR — run from inside the cloned repo"
  [[ ! -d "$SCRIPT_DIR/modules" ]]   && error "modules/ folder not found in $SCRIPT_DIR"
  [[ ! -d "$SCRIPT_DIR/utils" ]]     && error "utils/ folder not found in $SCRIPT_DIR"
  log "main.py found"
  log "modules/ found ($(ls $SCRIPT_DIR/modules/*.py 2>/dev/null | wc -l) files)"
  log "utils/ found ($(ls $SCRIPT_DIR/utils/*.py 2>/dev/null | wc -l) files)"
}

install_system_deps() {
  section "Installing System Dependencies"
  apt-get update -qq >> "$LOG_FILE" 2>&1 || warn "apt update had issues"
  apt-get install -y python3-pip curl wget git >> "$LOG_FILE" 2>&1 || warn "Some packages had issues"
  log "System dependencies ready"
}

install_python_deps() {
  section "Installing Python Packages"
  info "Installing: typer rich httpx beautifulsoup4"
  pip3 install --break-system-packages --quiet typer rich httpx beautifulsoup4 >> "$LOG_FILE" 2>&1 \
  || pip3 install --quiet typer rich httpx beautifulsoup4 >> "$LOG_FILE" 2>&1 \
  || error "pip install failed — check $LOG_FILE"
  log "Python packages installed"
}

install_tool_files() {
  section "Copying Tool Files"
  [[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR" && info "Removed old installation"
  mkdir -p "$INSTALL_DIR/modules" "$INSTALL_DIR/utils" "$INSTALL_DIR/reports" "$INSTALL_DIR/wordlists"
  cp "$SCRIPT_DIR/main.py"          "$INSTALL_DIR/main.py"
  cp "$SCRIPT_DIR/modules/"*.py     "$INSTALL_DIR/modules/"
  cp "$SCRIPT_DIR/utils/"*.py       "$INSTALL_DIR/utils/"
  [[ -f "$SCRIPT_DIR/README.md" ]]  && cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"
  [[ -f "$SCRIPT_DIR/requirements.txt" ]] && cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
  chmod -R 755 "$INSTALL_DIR"
  chmod 644 "$INSTALL_DIR/modules/"*.py "$INSTALL_DIR/utils/"*.py
  chmod 755 "$INSTALL_DIR/main.py"
  log "All files installed to $INSTALL_DIR"
}

create_global_command() {
  section "Creating Global Command"
  rm -f "$BIN_LINK"
  printf '#!/bin/bash\nexec python3 /opt/webrecon/main.py "$@"\n' > "$BIN_LINK"
  chmod +x "$BIN_LINK"
  log "Global command ready: webrecon"
}

create_icon() {
  section "Creating Application Icon"
  mkdir -p "$ICON_DIR" /usr/share/icons/hicolor/scalable/apps
  cat > /tmp/webrecon.svg << 'SVGEOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <defs>
    <radialGradient id="bg" cx="50%" cy="50%" r="50%">
      <stop offset="0%" style="stop-color:#1a0a2e"/>
      <stop offset="100%" style="stop-color:#0a0a0f"/>
    </radialGradient>
  </defs>
  <rect width="256" height="256" rx="32" fill="url(#bg)"/>
  <line x1="0" y1="64" x2="256" y2="64" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="0" y1="128" x2="256" y2="128" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="0" y1="192" x2="256" y2="192" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="64" y1="0" x2="64" y2="256" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="128" y1="0" x2="128" y2="256" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="192" y1="0" x2="192" y2="256" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <circle cx="128" cy="128" r="80" fill="none" stroke="#ff3b3b" stroke-width="2" opacity="0.8"/>
  <circle cx="128" cy="128" r="55" fill="none" stroke="#ff3b3b" stroke-width="1.5" opacity="0.6"/>
  <circle cx="128" cy="128" r="30" fill="none" stroke="#ff3b3b" stroke-width="1.5" opacity="0.5"/>
  <circle cx="128" cy="128" r="6" fill="#ff3b3b"/>
  <line x1="128" y1="40" x2="128" y2="90" stroke="#ff3b3b" stroke-width="2"/>
  <line x1="128" y1="166" x2="128" y2="216" stroke="#ff3b3b" stroke-width="2"/>
  <line x1="40" y1="128" x2="90" y2="128" stroke="#ff3b3b" stroke-width="2"/>
  <line x1="166" y1="128" x2="216" y2="128" stroke="#ff3b3b" stroke-width="2"/>
  <path d="M20,20 L20,50 M20,20 L50,20" stroke="#00d4ff" stroke-width="3" fill="none" stroke-linecap="round"/>
  <path d="M236,20 L236,50 M236,20 L206,20" stroke="#00d4ff" stroke-width="3" fill="none" stroke-linecap="round"/>
  <path d="M20,236 L20,206 M20,236 L50,236" stroke="#00d4ff" stroke-width="3" fill="none" stroke-linecap="round"/>
  <path d="M236,236 L236,206 M236,236 L206,236" stroke="#00d4ff" stroke-width="3" fill="none" stroke-linecap="round"/>
  <rect x="20" y="115" width="216" height="2" fill="#00d4ff" opacity="0.4" rx="1"/>
  <text x="128" y="135" font-family="monospace" font-size="22" font-weight="bold" fill="#ffffff" text-anchor="middle" opacity="0.9">WR</text>
</svg>
SVGEOF
  cp /tmp/webrecon.svg /usr/share/icons/hicolor/scalable/apps/webrecon.svg
  command -v rsvg-convert &>/dev/null && rsvg-convert -w 256 -h 256 /tmp/webrecon.svg -o "$ICON_DIR/webrecon.png" 2>/dev/null && log "PNG icon created" || warn "SVG icon installed (PNG converter not found)"
  gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
  log "Icon installed"
}

create_desktop_entry() {
  section "Creating Desktop Entry"
  cat > "$DESKTOP_FILE" << 'DESKTOP'
[Desktop Entry]
Version=1.0
Type=Application
Name=WebRecon Pro
GenericName=Web Penetration Testing
Comment=Professional Web Penetration Testing Framework
Exec=bash -c 'python3 /opt/webrecon/main.py --help; exec bash'
Icon=webrecon
Terminal=true
StartupNotify=true
Categories=Network;Security;System;
Keywords=pentest;security;hacking;recon;web;scanner;vulnerability;
Actions=FullScan;VulnScan;HeadersCheck;Fingerprint;SubdomainEnum;APITest;ListScans;

[Desktop Action FullScan]
Name=🔴 Full Penetration Scan
Exec=bash -c 'clear; read -p "  Target URL: " T; python3 /opt/webrecon/main.py scan "$T" -v; read -p "  Press Enter to close..."; exec bash'
Terminal=true

[Desktop Action VulnScan]
Name=💥 Vulnerability Scan
Exec=bash -c 'clear; read -p "  Target URL: " T; python3 /opt/webrecon/main.py vuln "$T" -v; read -p "  Press Enter to close..."; exec bash'
Terminal=true

[Desktop Action HeadersCheck]
Name=🛡️ Security Headers Check
Exec=bash -c 'clear; read -p "  Target URL: " T; python3 /opt/webrecon/main.py headers "$T" -v; read -p "  Press Enter to close..."; exec bash'
Terminal=true

[Desktop Action Fingerprint]
Name=🔎 Web Fingerprinting
Exec=bash -c 'clear; read -p "  Target URL: " T; python3 /opt/webrecon/main.py fingerprint "$T" -v; read -p "  Press Enter to close..."; exec bash'
Terminal=true

[Desktop Action SubdomainEnum]
Name=🌐 Subdomain Enumeration
Exec=bash -c 'clear; read -p "  Domain: " T; python3 /opt/webrecon/main.py subdomains "$T" -v; read -p "  Press Enter to close..."; exec bash'
Terminal=true

[Desktop Action APITest]
Name=🔌 API Security Testing
Exec=bash -c 'clear; read -p "  Target URL: " T; python3 /opt/webrecon/main.py api "$T" -v; read -p "  Press Enter to close..."; exec bash'
Terminal=true

[Desktop Action ListScans]
Name=📋 View Scan History
Exec=bash -c 'python3 /opt/webrecon/main.py list-scans; read -p "  Press Enter to close..."; exec bash'
Terminal=true
DESKTOP
  chmod 644 "$DESKTOP_FILE"
  update-desktop-database /usr/share/applications/ 2>/dev/null || true
  log "Desktop entry created"
}

add_shell_aliases() {
  section "Adding Shell Aliases"
  ALIAS_BLOCK='
# ── WebRecon Pro ──────────────────────────────────────────
alias webrecon-scan="python3 /opt/webrecon/main.py scan"
alias webrecon-vuln="python3 /opt/webrecon/main.py vuln"
alias webrecon-subs="python3 /opt/webrecon/main.py subdomains"
alias webrecon-headers="python3 /opt/webrecon/main.py headers"
alias webrecon-api="python3 /opt/webrecon/main.py api"
alias webrecon-fp="python3 /opt/webrecon/main.py fingerprint"
alias webrecon-history="python3 /opt/webrecon/main.py list-scans"
# ─────────────────────────────────────────────────────────'
  grep -q "WebRecon Pro" /etc/bash.bashrc 2>/dev/null || echo "$ALIAS_BLOCK" >> /etc/bash.bashrc
  for rcfile in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
    [[ -f "$rcfile" ]] && ! grep -q "WebRecon Pro" "$rcfile" && echo "$ALIAS_BLOCK" >> "$rcfile"
  done
  log "Shell aliases added"
}

create_reports_dir() {
  mkdir -p "$REAL_HOME/.webrecon/reports"
  chown -R "$REAL_USER":"$REAL_USER" "$REAL_HOME/.webrecon" 2>/dev/null || true
  log "Reports directory: $REAL_HOME/.webrecon/reports/"
}

create_uninstaller() {
  cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
echo "Uninstalling WebRecon Pro..."
rm -rf /opt/webrecon
rm -f /usr/local/bin/webrecon
rm -f /usr/share/applications/webrecon.desktop
rm -f /usr/share/icons/hicolor/256x256/apps/webrecon.png
rm -f /usr/share/icons/hicolor/scalable/apps/webrecon.svg
sed -i '/WebRecon Pro/,/─────────────────────────────────────────────────────────/d' /etc/bash.bashrc 2>/dev/null || true
update-desktop-database /usr/share/applications/ 2>/dev/null || true
echo "✓ WebRecon Pro removed."
EOF
  chmod +x "$INSTALL_DIR/uninstall.sh"
  log "Uninstaller: sudo bash /opt/webrecon/uninstall.sh"
}

verify_install() {
  section "Verifying Installation"
  python3 /opt/webrecon/main.py --help &>/dev/null && log "Tool verified — runs correctly" || error "Tool failed to start"
  [[ -x "$BIN_LINK" ]] && log "Global command verified: webrecon" || warn "Global command issue"
}

print_success() {
  echo ""
  echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${GREEN}${BOLD}   ✅  WebRecon Pro Installed Successfully!${RESET}"
  echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
  echo -e "  ${BOLD}webrecon --help${RESET}                     show all commands"
  echo -e "  ${BOLD}webrecon scan https://target.com${RESET}    full pentest"
  echo -e "  ${BOLD}webrecon headers https://target.com${RESET} headers check"
  echo -e "  ${BOLD}webrecon vuln https://target.com${RESET}    vuln scan"
  echo -e "  ${BOLD}webrecon subdomains target.com${RESET}      subdomain enum"
  echo ""
  echo -e "  ${CYAN}Desktop:${RESET} Find WebRecon Pro in Apps Menu → Network / Security"
  echo -e "  ${CYAN}Reports:${RESET} $REAL_HOME/.webrecon/reports/"
  echo -e "  ${CYAN}Remove: ${RESET} sudo bash /opt/webrecon/uninstall.sh"
  echo ""
  echo -e "${YELLOW}  ⚠  Only test systems you own or have written permission to test${RESET}"
  echo ""
}

main() {
  print_banner
  check_root
  check_python
  check_source_files
  install_system_deps
  install_python_deps
  install_tool_files
  create_global_command
  create_icon
  create_desktop_entry
  add_shell_aliases
  create_reports_dir
  create_uninstaller
  verify_install
  print_success
}

main "$@"
