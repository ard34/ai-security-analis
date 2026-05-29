#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

PACKAGES=(
  python3 python3-venv python3-pip git curl wget jq unzip tree build-essential
  golang-go whatweb zaproxy nuclei nmap nikto default-jre chromium whois dnsutils
)

RECOMMENDED_TOOLS=(subfinder amass assetfinder dnsx httpx katana nuclei nmap whatweb whois dig jq)
OPTIONAL_TOOLS=(wafw00f gowitness)

echo "[*] This script will run the following commands:"
echo "    sudo apt update"
echo "    sudo apt install -y ${PACKAGES[*]}"
echo "    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
echo "    go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
echo "    go install github.com/projectdiscovery/katana/cmd/katana@latest"
echo "    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
echo "    optional checks: ${OPTIONAL_TOOLS[*]} (warnings only)"
echo "    nuclei -update"
echo "    nuclei -update-templates"

sudo apt update
sudo apt install -y "${PACKAGES[@]}"

if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
  SHELL_RC="$HOME/.profile"
  if [[ -n "${SHELL:-}" && "$(basename "$SHELL")" == "zsh" ]]; then
    SHELL_RC="$HOME/.zshrc"
  fi
  if ! grep -q 'export PATH="$HOME/go/bin:$PATH"' "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH="$HOME/go/bin:$PATH"' >> "$SHELL_RC"
    echo "[*] Added \$HOME/go/bin to PATH in $SHELL_RC"
  fi
  export PATH="$HOME/go/bin:$PATH"
fi

install_go_tool() {
  local binary="$1"
  local package="$2"
  if ! command -v "$binary" >/dev/null 2>&1; then
    go install "$package"
  fi
}

install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@latest
install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install_go_tool assetfinder github.com/tomnomnom/assetfinder@latest
install_go_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@latest

if command -v nuclei >/dev/null 2>&1; then
  nuclei -update || true
  nuclei -update-templates || true
fi

echo "[*] Tool versions:"
python3 --version || true
python3 -m pip --version || true
go version || true
git --version || true
curl --version | head -n 1 || true
jq --version || true
chromium --version || true
zaproxy -version || zap.sh -version || true
nuclei -version || true
subfinder -version || true
httpx -version || true
katana -version || true
whatweb --version || true
nmap --version | head -n 1 || true

echo "[*] Recon tool availability:"
for tool in "${RECOMMENDED_TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "    [ok] $tool"
  else
    echo "    [warn] $tool missing or not on PATH"
  fi
done

echo "[*] Optional evidence/WAF tools:"
for tool in "${OPTIONAL_TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "    [ok] $tool"
  else
    echo "    [warn] optional $tool missing; continuing"
  fi
done
