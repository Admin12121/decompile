# Publishing decompile

This project publishes a small host CLI. The heavy reverse-engineering tools stay in the Docker image.

## Release checklist

```sh
packaging/release.sh 0.1.1
```

The release script updates versions, builds and pushes the Docker image, pushes the GitHub tag, uploads PyPI artifacts, updates AUR, and publishes the GitHub Pages installer/apt repo.

## PyPI / pip

```sh
python3 -m pip install --user --upgrade build twine
python3 -m build
python3 -m twine check dist/*
python3 -m twine upload dist/*
```

Users install it with:

```sh
python3 -m pip install decompile
decompile --update
decompile ./sample
```

## AUR

```sh
git clone ssh://aur@aur.archlinux.org/decompile.git /tmp/aur-decompile
cp packaging/aur/PKGBUILD /tmp/aur-decompile/PKGBUILD
cd /tmp/aur-decompile
makepkg --printsrcinfo > .SRCINFO
makepkg -si
git add PKGBUILD .SRCINFO
git commit -m "Initial release v0.1.0"
git push
```

Users install it with:

```sh
yay -S decompile
decompile --update
decompile ./sample
```

## Debian .deb / simple apt repository

Build the package:

```sh
packaging/deb/build-deb.sh
sudo apt install ./dist/decompile_0.1.0_all.deb
```

On Arch-based development machines, install `dpkg` first if `dpkg-deb` is missing.

Create a simple unsigned apt repository for testing:

```sh
packaging/deb/build-apt-repo.sh
cd dist
python3 -m http.server 8000
```

On a test client:

```sh
curl -fsSL http://127.0.0.1:8000/install.sh | sudo env DECOMPILE_APT_REPO_URL=http://127.0.0.1:8000/apt bash
```

For public apt distribution, use a signed repository or a package-hosting service instead of `trusted=yes`.
