#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${DECOMPILE_APT_REPO_URL:-https://admin12121.github.io/decompile/apt}"
LIST_FILE="/etc/apt/sources.list.d/decompile.list"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root:" >&2
  echo "  curl -fsSL https://admin12121.github.io/decompile/install.sh | sudo bash" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer supports apt-based Linux distributions only." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "[+] Installing apt prerequisites"
apt-get update
apt-get install -y ca-certificates

echo "[+] Adding decompile apt repository"
printf 'deb [trusted=yes] %s ./\n' "${REPO_URL}" > "${LIST_FILE}"

echo "[+] Installing decompile"
apt-get update
apt-get install -y decompile

echo "[+] Installed decompile"
decompile --help >/dev/null || true
