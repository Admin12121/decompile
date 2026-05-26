#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="decompile"
AUR_REMOTE="${DECOMPILE_AUR_REMOTE:-ssh://aur@aur.archlinux.org/decompile.git}"
PYTHON="${PYTHON:-python3}"
RELEASE_VENV="${DECOMPILE_RELEASE_VENV:-${ROOT_DIR}/.release-venv}"
AUR_DIR="${DECOMPILE_AUR_DIR:-/tmp/decompile-aur-release}"

PUBLISH_PYPI=1
PUBLISH_AUR=1
VERSION=""

usage() {
  cat <<'EOF'
Usage:
  packaging/release.sh <version> [options]

Default:
  update version, build Python artifacts, commit, tag, upload PyPI, publish AUR

Examples:
  packaging/release.sh 0.1.4
  packaging/release.sh 0.1.4 --skip-pypi
  packaging/release.sh 0.1.4 --skip-aur

Options:
  --skip-pypi   Build artifacts but do not upload to PyPI
  --skip-aur    Do not publish the AUR package
  -h, --help    Show this help

Environment:
  TWINE_USERNAME=__token__
  TWINE_PASSWORD=pypi-...
  DECOMPILE_AUR_REMOTE=ssh://aur@aur.archlinux.org/decompile.git
EOF
}

die() {
  echo "[-] $*" >&2
  exit 1
}

info() {
  echo "[+] $*"
}

run() {
  info "$*"
  "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-pypi) PUBLISH_PYPI=0 ;;
    --skip-aur) PUBLISH_AUR=0 ;;
    -h|--help) usage; exit 0 ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      [[ -z "${VERSION}" ]] || die "version already set: ${VERSION}"
      VERSION="$1"
      ;;
  esac
  shift
done

[[ -n "${VERSION}" ]] || { usage; exit 1; }
[[ "${VERSION}" =~ ^[0-9]+[.][0-9]+[.][0-9]+([a-zA-Z0-9._+-]*)?$ ]] || die "version must look like 0.1.4"

cd "${ROOT_DIR}"

branch="$(git branch --show-current)"
[[ "${branch}" == "main" ]] || die "run releases from main, current branch is ${branch}"

if [[ -n "$(git status --porcelain)" ]]; then
  die "working tree is dirty; commit or stash changes before releasing"
fi

release_files=(
  pyproject.toml
  decompile_tool/__init__.py
  packaging/aur/PKGBUILD
  packaging/aur/.SRCINFO
  packaging/deb/build-deb.sh
  packaging/deb/build-apt-repo.sh
  packaging/README.md
)

update_versions() {
  info "Updating version to ${VERSION}"
  "${PYTHON}" - "${VERSION}" <<'PY'
from pathlib import Path
import re
import sys

version = sys.argv[1]
rules = {
    "pyproject.toml": [(r'(?m)^version = "[^"]+"$', f'version = "{version}"')],
    "decompile_tool/__init__.py": [(r'(?m)^__version__ = "[^"]+"$', f'__version__ = "{version}"')],
    "packaging/aur/PKGBUILD": [(r'(?m)^pkgver=.*$', f'pkgver={version}'), (r'(?m)^pkgrel=.*$', 'pkgrel=1')],
    "packaging/deb/build-deb.sh": [(r'VERSION="\$\{DECOMPILE_VERSION:-[^}]+\}"', f'VERSION="${{DECOMPILE_VERSION:-{version}}}"')],
    "packaging/deb/build-apt-repo.sh": [(r'VERSION="\$\{DECOMPILE_VERSION:-[^}]+\}"', f'VERSION="${{DECOMPILE_VERSION:-{version}}}"')],
    "packaging/README.md": [
        (r'(?m)(packaging/release[.]sh )[0-9][0-9A-Za-z._+-]*', rf'\g<1>{version}'),
        (r'v[0-9]+\.[0-9]+\.[0-9]+', f'v{version}'),
        (r'decompile_[0-9]+\.[0-9]+\.[0-9]+_all[.]deb', f'decompile_{version}_all.deb'),
    ],
}

for filename, replacements in rules.items():
    path = Path(filename)
    text = path.read_text(encoding="utf-8")
    original = text
    for pattern, replacement in replacements:
        text = re.sub(pattern, replacement, text)
    if text != original:
        path.write_text(text, encoding="utf-8")
PY

  if [[ "${PUBLISH_AUR}" == "1" ]]; then
    command -v makepkg >/dev/null 2>&1 || die "makepkg is required when publishing AUR"
    (
      cd packaging/aur
      makepkg --printsrcinfo > .SRCINFO
    )
  else
    info "Skipping .SRCINFO refresh because AUR publish is disabled"
  fi
}

build_artifacts() {
  info "Building Python artifacts"
  rm -rf build dist "${PROJECT}.egg-info" decompile_tool/__pycache__
  [[ -x "${RELEASE_VENV}/bin/python" ]] || run "${PYTHON}" -m venv "${RELEASE_VENV}"
  run "${RELEASE_VENV}/bin/python" -m pip install --upgrade pip build twine
  run "${RELEASE_VENV}/bin/python" -m build
  run "${RELEASE_VENV}/bin/python" -m twine check dist/*.whl dist/*.tar.gz
}

commit_and_tag() {
  run git add "${release_files[@]}"
  run git commit -m "Release v${VERSION}"
  run git push origin HEAD:main
  run git tag "v${VERSION}"
  run git push origin "v${VERSION}"
  run curl -fsSLI "https://github.com/Admin12121/decompile/archive/refs/tags/v${VERSION}.tar.gz"
}

publish_pypi() {
  [[ "${PUBLISH_PYPI}" == "1" ]] || { info "Skipping PyPI upload"; return; }
  run "${RELEASE_VENV}/bin/python" -m twine upload --skip-existing dist/*.whl dist/*.tar.gz
}

publish_aur() {
  [[ "${PUBLISH_AUR}" == "1" ]] || { info "Skipping AUR publish"; return; }

  if [[ -d "${AUR_DIR}/.git" ]]; then
    run git -C "${AUR_DIR}" fetch origin master
    run git -C "${AUR_DIR}" checkout master
    run git -C "${AUR_DIR}" pull --ff-only origin master
  else
    rm -rf "${AUR_DIR}"
    run git clone "${AUR_REMOTE}" "${AUR_DIR}"
    run git -C "${AUR_DIR}" checkout -B master
  fi

  install -m 0644 packaging/aur/PKGBUILD "${AUR_DIR}/PKGBUILD"
  (
    cd "${AUR_DIR}"
    makepkg --printsrcinfo > .SRCINFO
    makepkg -sf --noconfirm
    rm -rf src pkg *.tar.gz *.pkg.tar.*
    git add PKGBUILD .SRCINFO
    git commit -m "Update to v${VERSION}"
    git push origin master
  )
}

update_versions
build_artifacts
commit_and_tag
publish_pypi
publish_aur

info "Release v${VERSION} complete"
info "PyPI: pip install -U decompile==${VERSION}"
info "AUR: yay -Syu decompile"
