#!/bin/bash
# =============================================================================
#  WebRecon Pro - One-Line Installer
#  Usage: sudo bash install.sh
# =============================================================================

set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Config ────────────────────────────────────────────────────────────────────
TOOL_NAME="webrecon"
INSTALL_DIR="/opt/webrecon"
BIN_LINK="/usr/local/bin/webrecon"
DESKTOP_FILE="/usr/share/applications/webrecon.desktop"
ICON_DIR="/usr/share/icons/hicolor/256x256/apps"
CONFIG_DIR="$HOME/.webrecon"
LOG_FILE="/tmp/webrecon_install.log"

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
  echo -e "${RED}"
  cat << 'EOF'
██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝
EOF
  echo -e "${RESET}"
  echo -e "${BOLD}${CYAN}         WebRecon Pro v1.0.0 — Professional Web Penetration Testing Framework${RESET}"
  echo -e "${YELLOW}                       FOR AUTHORIZED PENETRATION TESTING ONLY${RESET}"
  echo ""
}

# ── Helpers ───────────────────────────────────────────────────────────────────
log()     { echo -e "${GREEN}[✓]${RESET} $1"; }
info()    { echo -e "${CYAN}[*]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; exit 1; }
section() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

check_root() {
  if [[ $EUID -ne 0 ]]; then
    error "This installer must be run as root. Use: sudo bash install.sh"
  fi
}

check_os() {
  if ! grep -qi "kali\|debian\|ubuntu\|parrot" /etc/os-release 2>/dev/null; then
    warn "This tool is optimized for Kali Linux. Continuing anyway..."
  else
    log "Operating system check passed"
  fi
}

check_python() {
  if ! command -v python3 &>/dev/null; then
    error "Python 3 is not installed. Install it with: sudo apt install python3"
  fi
  PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  PYTHON_MAJOR=$(echo $PYTHON_VER | cut -d. -f1)
  PYTHON_MINOR=$(echo $PYTHON_VER | cut -d. -f2)
  if [[ $PYTHON_MAJOR -lt 3 || ($PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 9) ]]; then
    error "Python 3.9+ required. Found: Python $PYTHON_VER"
  fi
  log "Python $PYTHON_VER detected"
}

# ── Install Steps ─────────────────────────────────────────────────────────────

install_system_deps() {
  section "Installing System Dependencies"
  info "Updating package list..."
  apt-get update -qq >> "$LOG_FILE" 2>&1
  info "Installing required packages..."
  apt-get install -y python3-pip python3-venv curl wget git \
    libssl-dev libffi-dev >> "$LOG_FILE" 2>&1
  log "System dependencies installed"
}

install_python_deps() {
  section "Installing Python Dependencies"
  info "Installing Python packages..."
  pip3 install --break-system-packages --quiet \
    typer \
    rich \
    httpx \
    beautifulsoup4 \
    >> "$LOG_FILE" 2>&1
  log "Python packages installed: typer, rich, httpx, beautifulsoup4"
}

install_files() {
  section "Installing WebRecon Pro"

  info "Creating install directory: $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR/modules"
  mkdir -p "$INSTALL_DIR/utils"
  mkdir -p "$INSTALL_DIR/reports"
  mkdir -p "$INSTALL_DIR/wordlists"

  # Copy all files from current directory
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  info "Copying tool files..."
  cp "$SCRIPT_DIR/main.py" "$INSTALL_DIR/"
  cp "$SCRIPT_DIR/modules/"*.py "$INSTALL_DIR/modules/"
  cp "$SCRIPT_DIR/utils/"*.py "$INSTALL_DIR/utils/"
  cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/" 2>/dev/null || true

  # Set permissions
  chmod -R 755 "$INSTALL_DIR"
  chmod 644 "$INSTALL_DIR/modules/"*.py
  chmod 644 "$INSTALL_DIR/utils/"*.py
  chmod 755 "$INSTALL_DIR/main.py"

  log "Tool files installed to $INSTALL_DIR"
}

create_launcher_script() {
  section "Creating System Command"

  cat > "$BIN_LINK" << 'LAUNCHER'
#!/bin/bash
# WebRecon Pro Launcher
exec python3 /opt/webrecon/main.py "$@"
LAUNCHER

  chmod +x "$BIN_LINK"
  log "Global command created: webrecon"
  log "You can now run: webrecon scan https://target.com"
}

create_icon() {
  section "Creating Application Icon"

  mkdir -p "$ICON_DIR"

  # Generate SVG icon
  cat > "/tmp/webrecon_icon.svg" << 'SVGEOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <defs>
    <radialGradient id="bg" cx="50%" cy="50%" r="50%">
      <stop offset="0%" style="stop-color:#1a0a2e"/>
      <stop offset="100%" style="stop-color:#0a0a0f"/>
    </radialGradient>
    <radialGradient id="glow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" style="stop-color:#ff3b3b;stop-opacity:0.3"/>
      <stop offset="100%" style="stop-color:#ff3b3b;stop-opacity:0"/>
    </radialGradient>
  </defs>
  <!-- Background -->
  <rect width="256" height="256" rx="32" fill="url(#bg)"/>
  <rect width="256" height="256" rx="32" fill="url(#glow)"/>
  <!-- Grid lines -->
  <line x1="0" y1="64" x2="256" y2="64" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="0" y1="128" x2="256" y2="128" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="0" y1="192" x2="256" y2="192" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="64" y1="0" x2="64" y2="256" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="128" y1="0" x2="128" y2="256" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <line x1="192" y1="0" x2="192" y2="256" stroke="#ff3b3b" stroke-width="0.5" opacity="0.2"/>
  <!-- Crosshair / target circle -->
  <circle cx="128" cy="128" r="80" fill="none" stroke="#ff3b3b" stroke-width="2" opacity="0.8"/>
  <circle cx="128" cy="128" r="55" fill="none" stroke="#ff3b3b" stroke-width="1.5" opacity="0.6"/>
  <circle cx="128" cy="128" r="30" fill="none" stroke="#ff3b3b" stroke-width="1.5" opacity="0.5"/>
  <circle cx="128" cy="128" r="6" fill="#ff3b3b"/>
  <!-- Crosshair lines -->
  <line x1="128" y1="40" x2="128" y2="90" stroke="#ff3b3b" stroke-width="2"/>
  <line x1="128" y1="166" x2="128" y2="216" stroke="#ff3b3b" stroke-width="2"/>
  <line x1="40" y1="128" x2="90" y2="128" stroke="#ff3b3b" stroke-width="2"/>
  <line x1="166" y1="128" x2="216" y2="128" stroke="#ff3b3b" stroke-width="2"/>
  <!-- Corner brackets -->
  <path d="M20,20 L20,50 M20,20 L50,20" stroke="#00d4ff" stroke-width="3" fill="none" stroke-linecap="round"/>
  <path d="M236,20 L236,50 M236,20 L206,20" stroke="#00d4ff" stroke-width="3" fill="none" stroke-linecap="round"/>
  <path d="M20,236 L20,206 M20,236 L50,236" stroke="#00d4ff" stroke-width="3" fill="none" stroke-linecap="round"/>
  <path d="M236,236 L236,206 M236,236 L206,236" stroke="#00d4ff" stroke-width="3" fill="none" stroke-linecap="round"/>
  <!-- Scan line animation hint -->
  <rect x="20" y="115" width="216" height="2" fill="#00d4ff" opacity="0.4" rx="1"/>
  <!-- Text: WR -->
  <text x="128" y="135" font-family="monospace" font-size="22" font-weight="bold"
        fill="#ffffff" text-anchor="middle" opacity="0.9">WR</text>
</svg>
SVGEOF

  # Try to convert SVG to PNG using rsvg-convert or inkscape
  if command -v rsvg-convert &>/dev/null; then
    rsvg-convert -w 256 -h 256 /tmp/webrecon_icon.svg -o "$ICON_DIR/webrecon.png" 2>/dev/null
    log "Icon created (PNG via rsvg-convert)"
  elif command -v inkscape &>/dev/null; then
    inkscape --export-png="$ICON_DIR/webrecon.png" --export-width=256 /tmp/webrecon_icon.svg 2>/dev/null
    log "Icon created (PNG via inkscape)"
  else
    # Install rsvg-convert if not present
    apt-get install -y librsvg2-bin -qq >> "$LOG_FILE" 2>&1
    if command -v rsvg-convert &>/dev/null; then
      rsvg-convert -w 256 -h 256 /tmp/webrecon_icon.svg -o "$ICON_DIR/webrecon.png" 2>/dev/null
      log "Icon created"
    else
      # Fallback: copy SVG as icon
      cp /tmp/webrecon_icon.svg "$ICON_DIR/webrecon.svg"
      warn "PNG conversion unavailable, using SVG icon"
    fi
  fi

  # Also copy SVG for scalable icons
  mkdir -p /usr/share/icons/hicolor/scalable/apps
  cp /tmp/webrecon_icon.svg /usr/share/icons/hicolor/scalable/apps/webrecon.svg

  # Update icon cache
  gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
  log "Icon cache updated"
}

create_desktop_entry() {
  section "Creating Desktop Entry"

  cat > "$DESKTOP_FILE" << DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=WebRecon Pro
GenericName=Web Penetration Testing Tool
Comment=Professional Web Penetration Testing Framework
Exec=bash -c 'python3 /opt/webrecon/main.py --help; exec bash'
Icon=webrecon
Terminal=true
StartupNotify=true
Categories=Network;Security;System;
Keywords=pentest;security;hacking;recon;web;scanner;vulnerability;
Actions=FullScan;Headers;Fingerprint;ListScans;

[Desktop Action FullScan]
Name=Run Full Scan (Interactive)
Exec=bash -c 'read -p "Enter target URL: " TARGET; python3 /opt/webrecon/main.py scan "$TARGET" -v; exec bash'
Terminal=true

[Desktop Action Headers]
Name=Check Security Headers
Exec=bash -c 'read -p "Enter target URL: " TARGET; python3 /opt/webrecon/main.py headers "$TARGET" -v; exec bash'
Terminal=true

[Desktop Action Fingerprint]
Name=Fingerprint Target
Exec=bash -c 'read -p "Enter target URL: " TARGET; python3 /opt/webrecon/main.py fingerprint "$TARGET" -v; exec bash'
Terminal=true

[Desktop Action ListScans]
Name=View Past Scans
Exec=bash -c 'python3 /opt/webrecon/main.py list-scans; exec bash'
Terminal=true
DESKTOP

  chmod 644 "$DESKTOP_FILE"
  update-desktop-database /usr/share/applications/ 2>/dev/null || true
  log "Desktop entry created"
  log "Right-click the icon to access quick actions"
}

create_terminal_shortcut() {
  section "Creating Terminal Shortcuts"

  # Add shell aliases
  ALIAS_BLOCK="
# ── WebRecon Pro Aliases ──────────────────────────────────
alias webrecon-scan='python3 /opt/webrecon/main.py scan'
alias webrecon-vuln='python3 /opt/webrecon/main.py vuln'
alias webrecon-subs='python3 /opt/webrecon/main.py subdomains'
alias webrecon-headers='python3 /opt/webrecon/main.py headers'
alias webrecon-api='python3 /opt/webrecon/main.py api'
alias webrecon-fp='python3 /opt/webrecon/main.py fingerprint'
alias webrecon-history='python3 /opt/webrecon/main.py list-scans'
# ─────────────────────────────────────────────────────────"

  # Add to /etc/bash.bashrc (system-wide)
  if ! grep -q "WebRecon Pro Aliases" /etc/bash.bashrc 2>/dev/null; then
    echo "$ALIAS_BLOCK" >> /etc/bash.bashrc
    log "Shell aliases added to /etc/bash.bashrc"
  else
    log "Shell aliases already present"
  fi

  # Also add to current user's .bashrc and .zshrc
  REAL_USER="${SUDO_USER:-$USER}"
  REAL_HOME=$(eval echo "~$REAL_USER")

  for rcfile in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
    if [[ -f "$rcfile" ]] && ! grep -q "WebRecon Pro Aliases" "$rcfile" 2>/dev/null; then
      echo "$ALIAS_BLOCK" >> "$rcfile"
      log "Aliases added to $rcfile"
    fi
  done
}

create_config_dir() {
  section "Setting Up Config & Reports Directory"
  REAL_USER="${SUDO_USER:-$USER}"
  REAL_HOME=$(eval echo "~$REAL_USER")

  mkdir -p "$REAL_HOME/.webrecon"
  mkdir -p "$REAL_HOME/.webrecon/reports"
  chown -R "$REAL_USER":"$REAL_USER" "$REAL_HOME/.webrecon" 2>/dev/null || true
  log "Config directory: $REAL_HOME/.webrecon/"
  log "Default reports:  $REAL_HOME/.webrecon/reports/"
}

create_uninstaller() {
  cat > /opt/webrecon/uninstall.sh << 'UNINSTALL'
#!/bin/bash
echo "[*] Uninstalling WebRecon Pro..."
rm -rf /opt/webrecon
rm -f /usr/local/bin/webrecon
rm -f /usr/share/applications/webrecon.desktop
rm -f /usr/share/icons/hicolor/256x256/apps/webrecon.png
rm -f /usr/share/icons/hicolor/scalable/apps/webrecon.svg
sed -i '/WebRecon Pro Aliases/,/─────────────────────────────────────────────────────────/d' /etc/bash.bashrc
update-desktop-database /usr/share/applications/ 2>/dev/null || true
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
echo "[✓] WebRecon Pro has been uninstalled."
UNINSTALL
  chmod +x /opt/webrecon/uninstall.sh
  log "Uninstaller created at /opt/webrecon/uninstall.sh"
}

print_success() {
  echo ""
  echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${GREEN}${BOLD}   ✅  WebRecon Pro Installed Successfully!${RESET}"
  echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
  echo -e "${CYAN}  How to use:${RESET}"
  echo -e "  ${BOLD}webrecon --help${RESET}                          — Show all commands"
  echo -e "  ${BOLD}webrecon scan https://target.com${RESET}         — Full pentest"
  echo -e "  ${BOLD}webrecon headers https://target.com${RESET}      — Headers check"
  echo -e "  ${BOLD}webrecon vuln https://target.com${RESET}         — Vuln scan"
  echo -e "  ${BOLD}webrecon subdomains target.com${RESET}           — Subdomain enum"
  echo ""
  echo -e "${CYAN}  Quick aliases (after restarting terminal):${RESET}"
  echo -e "  ${BOLD}webrecon-scan${RESET}  ${BOLD}webrecon-vuln${RESET}  ${BOLD}webrecon-subs${RESET}  ${BOLD}webrecon-headers${RESET}"
  echo ""
  echo -e "${CYAN}  Desktop:${RESET}"
  echo -e "  Find ${BOLD}WebRecon Pro${RESET} in your Applications → Network/Security menu"
  echo -e "  Right-click the icon for quick scan actions"
  echo ""
  echo -e "${CYAN}  Files installed to:${RESET}"
  echo -e "  ${YELLOW}/opt/webrecon/${RESET}              — Tool files"
  echo -e "  ${YELLOW}/usr/local/bin/webrecon${RESET}     — Global command"
  echo -e "  ${YELLOW}~/.webrecon/reports/${RESET}        — Your scan reports"
  echo ""
  echo -e "${YELLOW}  ⚠️  Only use on systems you own or have written permission to test${RESET}"
  echo ""
  echo -e "  To uninstall: ${BOLD}sudo bash /opt/webrecon/uninstall.sh${RESET}"
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  print_banner
  check_root
  check_os
  check_python
  install_system_deps
  install_python_deps
  install_files
  create_launcher_script
  create_icon
  create_desktop_entry
  create_terminal_shortcut
  create_config_dir
  create_uninstaller
  print_success
}

main "$@"
