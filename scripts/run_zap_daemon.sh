#!/usr/bin/env bash
set -euo pipefail

echo "[*] Starting OWASP ZAP daemon on 127.0.0.1:8090"

if command -v zaproxy >/dev/null 2>&1; then
  zaproxy -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true
elif command -v zap.sh >/dev/null 2>&1; then
  zap.sh -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true
else
  echo "[!] OWASP ZAP not found. Install zaproxy first."
  exit 1
fi
