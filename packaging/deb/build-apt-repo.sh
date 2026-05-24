#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${DECOMPILE_VERSION:-0.1.2}"
ARCH="${DECOMPILE_DEB_ARCH:-all}"
DEB="${ROOT_DIR}/dist/decompile_${VERSION}_${ARCH}.deb"
APT_DIR="${ROOT_DIR}/dist/apt"
APT_DEB="${APT_DIR}/$(basename "${DEB}")"
PACKAGES="${APT_DIR}/Packages"
INSTALLER="${ROOT_DIR}/dist/install.sh"
INDEX="${ROOT_DIR}/dist/index.html"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb not found. Build this repo inside the decompile Docker image or install dpkg." >&2
  exit 127
fi

if [[ ! -f "${DEB}" ]]; then
  "${ROOT_DIR}/packaging/deb/build-deb.sh"
fi

rm -rf "${APT_DIR}"
install -d "${APT_DIR}"
install -m 0644 "${DEB}" "${APT_DEB}"

size="$(stat -c '%s' "${APT_DEB}")"
md5="$(md5sum "${APT_DEB}" | awk '{print $1}')"
sha1="$(sha1sum "${APT_DEB}" | awk '{print $1}')"
sha256="$(sha256sum "${APT_DEB}" | awk '{print $1}')"

dpkg-deb -f "${APT_DEB}" > "${PACKAGES}"
{
  printf 'Filename: ./%s\n' "$(basename "${APT_DEB}")"
  printf 'Size: %s\n' "${size}"
  printf 'MD5sum: %s\n' "${md5}"
  printf 'SHA1: %s\n' "${sha1}"
  printf 'SHA256: %s\n\n' "${sha256}"
} >> "${PACKAGES}"

gzip -9nc "${PACKAGES}" > "${PACKAGES}.gz"
install -m 0755 "${ROOT_DIR}/packaging/deb/install.sh" "${INSTALLER}"

cat > "${INDEX}" <<EOF
<!doctype html>
<title>decompile installer</title>
<pre>
curl -fsSL https://admin12121.github.io/decompile/install.sh | sudo bash
</pre>
EOF

cat > "${APT_DIR}/index.html" <<EOF
<!doctype html>
<title>decompile apt repository</title>
<pre>
deb [trusted=yes] https://admin12121.github.io/decompile/apt ./
</pre>
EOF

echo "${APT_DIR}"
echo "${INSTALLER}"
