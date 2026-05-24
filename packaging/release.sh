#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="decompile"
IMAGE="${DECOMPILE_IMAGE:-admin12121/decompile}"
AUR_REMOTE="${DECOMPILE_AUR_REMOTE:-ssh://aur@aur.archlinux.org/decompile.git}"
PAGES_REMOTE="${DECOMPILE_PAGES_REMOTE:-$(git -C "${ROOT_DIR}" remote get-url origin)}"
PYTHON="${PYTHON:-python3}"
RELEASE_VENV="${DECOMPILE_RELEASE_VENV:-${ROOT_DIR}/.release-venv}"
AUR_DIR="${DECOMPILE_AUR_DIR:-/tmp/decompile-aur-release}"
PAGES_DIR="${DECOMPILE_PAGES_DIR:-/tmp/decompile-gh-pages-release}"

PUBLISH_DOCKER=1
PUBLISH_PYPI=1
PUBLISH_AUR=1
PUBLISH_PAGES=1
VERSION=""

usage() {
  cat <<'EOF'
Usage:
  packaging/release.sh <version> [options]

Example:
  packaging/release.sh 0.1.1

Options:
  --skip-docker   Do not build/push Docker image
  --skip-pypi     Do not upload to PyPI
  --skip-aur      Do not push AUR package
  --skip-pages    Do not publish install.sh and apt repo to GitHub Pages
  -h, --help      Show this help

Environment:
  DECOMPILE_IMAGE=admin12121/decompile
  TWINE_USERNAME=__token__
  TWINE_PASSWORD=pypi-...
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
    --skip-docker) PUBLISH_DOCKER=0 ;;
    --skip-pypi) PUBLISH_PYPI=0 ;;
    --skip-aur) PUBLISH_AUR=0 ;;
    --skip-pages) PUBLISH_PAGES=0 ;;
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
[[ "${VERSION}" =~ ^[0-9]+[.][0-9]+[.][0-9]+([a-zA-Z0-9._+-]*)?$ ]] || die "version must look like 0.1.1"

cd "${ROOT_DIR}"

branch="$(git branch --show-current)"
[[ "${branch}" == "main" ]] || die "run releases from main, current branch is ${branch}"

release_files=(
  pyproject.toml
  decompile_tool/__init__.py
  packaging/aur/PKGBUILD
  packaging/aur/.SRCINFO
  packaging/deb/build-deb.sh
  packaging/deb/build-apt-repo.sh
  packaging/README.md
)

dirty_release_files="$(git status --porcelain -- "${release_files[@]}")"
[[ -z "${dirty_release_files}" ]] || die "release files have uncommitted changes:
${dirty_release_files}"

update_versions() {
  info "Updating version to ${VERSION}"
  "${PYTHON}" - "${VERSION}" <<'PY'
from pathlib import Path
import re
import sys

version = sys.argv[1]

replacements = {
    "pyproject.toml": [
        (r'(?m)^version = "[^"]+"$', f'version = "{version}"'),
    ],
    "decompile_tool/__init__.py": [
        (r'(?m)^__version__ = "[^"]+"$', f'__version__ = "{version}"'),
    ],
    "packaging/aur/PKGBUILD": [
        (r'(?m)^pkgver=.*$', f'pkgver={version}'),
        (r'(?m)^pkgrel=.*$', 'pkgrel=1'),
    ],
    "packaging/deb/build-deb.sh": [
        (r'VERSION="\$\{DECOMPILE_VERSION:-[^}]+\}"', f'VERSION="${{DECOMPILE_VERSION:-{version}}}"'),
    ],
    "packaging/deb/build-apt-repo.sh": [
        (r'VERSION="\$\{DECOMPILE_VERSION:-[^}]+\}"', f'VERSION="${{DECOMPILE_VERSION:-{version}}}"'),
    ],
    "packaging/README.md": [
        (r'VERSION=[0-9][0-9A-Za-z._+-]*', f'VERSION={version}'),
        (r'v[0-9]+\.[0-9]+\.[0-9]+', f'v{version}'),
        (r'decompile_[0-9]+\.[0-9]+\.[0-9]+_all[.]deb', f'decompile_{version}_all.deb'),
    ],
}

for filename, rules in replacements.items():
    path = Path(filename)
    text = path.read_text(encoding="utf-8")
    original = text
    for pattern, replacement in rules:
        text = re.sub(pattern, replacement, text)
    if text != original:
        path.write_text(text, encoding="utf-8")
PY

  (
    cd packaging/aur
    makepkg --printsrcinfo > .SRCINFO
  )
}

build_python_artifacts() {
  info "Building Python artifacts"
  rm -rf build dist "${PROJECT}.egg-info" decompile_tool/__pycache__
  [[ -x "${RELEASE_VENV}/bin/python" ]] || run "${PYTHON}" -m venv "${RELEASE_VENV}"
  run "${RELEASE_VENV}/bin/python" -m pip install --upgrade pip build twine
  run "${RELEASE_VENV}/bin/python" -m build
  run "${RELEASE_VENV}/bin/python" -m twine check dist/*.whl dist/*.tar.gz
}

commit_release() {
  run git add "${release_files[@]}"
  if git diff --cached --quiet; then
    info "No release metadata changes to commit"
  else
    run git commit -m "Release v${VERSION}"
  fi
}

publish_git_tag() {
  local tag="v${VERSION}"
  local head
  head="$(git rev-parse HEAD)"

  run git push origin HEAD:main

  if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    local local_tag
    local_tag="$(git rev-parse "${tag}^{commit}")"
    [[ "${local_tag}" == "${head}" ]] || die "local tag ${tag} points to ${local_tag}, not ${head}"
    info "Local tag ${tag} already points to HEAD"
  else
    run git tag "${tag}"
  fi

  local remote_tag
  remote_tag="$(git ls-remote origin "refs/tags/${tag}" | awk '{print $1}')"
  if [[ -n "${remote_tag}" ]]; then
    [[ "${remote_tag}" == "${head}" ]] || die "remote tag ${tag} points to ${remote_tag}, not ${head}"
    info "Remote tag ${tag} already exists"
  else
    run git push origin "${tag}"
  fi

  run curl -fsSLI "https://github.com/Admin12121/decompile/archive/refs/tags/${tag}.tar.gz"
}

publish_docker() {
  [[ "${PUBLISH_DOCKER}" == "1" ]] || { info "Skipping Docker publish"; return; }
  run docker build -t "${IMAGE}:${VERSION}" -t "${IMAGE}:stable" .
  run docker push "${IMAGE}:${VERSION}"
  run docker push "${IMAGE}:stable"
}

publish_pypi() {
  [[ "${PUBLISH_PYPI}" == "1" ]] || { info "Skipping PyPI upload"; return; }
  info "Uploading to PyPI"
  "${RELEASE_VENV}/bin/python" -m twine upload --skip-existing dist/*.whl dist/*.tar.gz
}

publish_aur() {
  [[ "${PUBLISH_AUR}" == "1" ]] || { info "Skipping AUR publish"; return; }
  command -v makepkg >/dev/null 2>&1 || die "makepkg is required for AUR publish"

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
    if git diff --cached --quiet; then
      info "AUR already up to date"
    else
      git commit -m "Update to v${VERSION}"
      git push origin master
    fi
  )
}

build_apt_repo() {
  [[ "${PUBLISH_PAGES}" == "1" ]] || { info "Skipping apt repo build"; return; }
  info "Building apt repository"
  if command -v dpkg-deb >/dev/null 2>&1; then
    DECOMPILE_VERSION="${VERSION}" packaging/deb/build-apt-repo.sh
  else
    local builder_image="${DECOMPILE_DEB_BUILDER_IMAGE:-${IMAGE}:${VERSION}}"
    run docker run --rm --user "$(id -u):$(id -g)" \
      -e "DECOMPILE_VERSION=${VERSION}" \
      -v "${ROOT_DIR}:/src" -w /src \
      --entrypoint bash "${builder_image}" \
      -lc 'packaging/deb/build-apt-repo.sh'
  fi
}

publish_pages() {
  [[ "${PUBLISH_PAGES}" == "1" ]] || { info "Skipping GitHub Pages publish"; return; }

  if [[ -d "${PAGES_DIR}/.git" ]]; then
    run git -C "${PAGES_DIR}" fetch origin gh-pages
    run git -C "${PAGES_DIR}" checkout gh-pages
    run git -C "${PAGES_DIR}" pull --ff-only origin gh-pages
  else
    rm -rf "${PAGES_DIR}"
    if git ls-remote --exit-code "${PAGES_REMOTE}" refs/heads/gh-pages >/dev/null 2>&1; then
      run git clone --branch gh-pages --single-branch "${PAGES_REMOTE}" "${PAGES_DIR}"
    else
      run git init -b gh-pages "${PAGES_DIR}"
      run git -C "${PAGES_DIR}" remote add origin "${PAGES_REMOTE}"
    fi
  fi

  rm -rf "${PAGES_DIR}/apt"
  install -d "${PAGES_DIR}/apt"
  cp -a dist/apt/. "${PAGES_DIR}/apt/"
  install -m 0755 dist/install.sh "${PAGES_DIR}/install.sh"
  install -m 0644 dist/index.html "${PAGES_DIR}/index.html"

  run git -C "${PAGES_DIR}" add apt install.sh index.html
  if git -C "${PAGES_DIR}" diff --cached --quiet; then
    info "GitHub Pages already up to date"
  else
    run git -C "${PAGES_DIR}" commit -m "Update apt repo to v${VERSION}"
    run git -C "${PAGES_DIR}" push origin gh-pages
  fi
}

update_versions
build_python_artifacts
commit_release
publish_docker
publish_git_tag
publish_pypi
publish_aur
build_apt_repo
publish_pages

info "Release v${VERSION} complete"
info "AUR: yay -S decompile"
info "PyPI: pip install decompile"
info "Installer: curl -fsSL https://admin12121.github.io/decompile/install.sh | sudo bash"
