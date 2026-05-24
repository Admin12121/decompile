#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${DECOMPILE_VERSION:-0.1.1}"
ARCH="${DECOMPILE_DEB_ARCH:-all}"
OUT_DIR="${ROOT_DIR}/dist"
PKG_ROOT="${OUT_DIR}/deb-root"
OUT_DEB="${OUT_DIR}/decompile_${VERSION}_${ARCH}.deb"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb not found. Install dpkg/dpkg-dev, then rerun this script." >&2
  exit 127
fi

install -d "${OUT_DIR}"
rm -rf "${PKG_ROOT}"
trap 'rm -rf "${PKG_ROOT}"' EXIT
install -d "${PKG_ROOT}/DEBIAN"
install -d "${PKG_ROOT}/usr/bin"
install -d "${PKG_ROOT}/usr/share/decompile"
install -d "${PKG_ROOT}/usr/share/doc/decompile"

install -m 0755 "${ROOT_DIR}/decompile" "${PKG_ROOT}/usr/bin/decompile"
cp -a "${ROOT_DIR}/decompile_tool" "${PKG_ROOT}/usr/share/decompile/decompile_tool"
find "${PKG_ROOT}/usr/share/decompile/decompile_tool" -type d -exec chmod 0755 {} +
find "${PKG_ROOT}/usr/share/decompile/decompile_tool" -type f -exec chmod 0644 {} +
chmod 0755 "${PKG_ROOT}/usr/share/decompile/decompile_tool/cli.py"
chmod 0755 "${PKG_ROOT}/usr/share/decompile/decompile_tool/enhance_with_copilot"

install -m 0644 "${ROOT_DIR}/README.md" "${PKG_ROOT}/usr/share/doc/decompile/README.md"
sed \
  -e "s/@VERSION@/${VERSION}/g" \
  -e "s/@ARCH@/${ARCH}/g" \
  "${ROOT_DIR}/packaging/deb/control" > "${PKG_ROOT}/DEBIAN/control"

dpkg-deb --root-owner-group --build "${PKG_ROOT}" "${OUT_DEB}"
echo "${OUT_DEB}"
