# Publishing decompile

This project publishes a small host CLI. The heavy reverse-engineering tools stay in the Docker image.

## Release checklist

```sh
VERSION=0.1.0
IMAGE=admin12121/decompile

git tag "v$VERSION"
git push origin main "v$VERSION"

docker build -t "$IMAGE:$VERSION" -t "$IMAGE:stable" .
docker push "$IMAGE:$VERSION"
docker push "$IMAGE:stable"
```

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
mkdir -p dist/apt
cp dist/decompile_0.1.0_all.deb dist/apt/
cd dist/apt
dpkg-scanpackages . /dev/null | gzip -9c > Packages.gz
python3 -m http.server 8000
```

On a test client:

```sh
echo "deb [trusted=yes] http://127.0.0.1:8000 ./" | sudo tee /etc/apt/sources.list.d/decompile.list
sudo apt update
sudo apt install decompile
```

For public apt distribution, use a signed repository or a package-hosting service instead of `trusted=yes`.
