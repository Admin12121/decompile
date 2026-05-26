# Publishing

The normal release path publishes the small host CLI to PyPI and AUR. The heavy reverse-engineering tools stay in the Docker image and are updated separately.

## PyPI + AUR

```sh
packaging/release.sh 0.1.4
```

The script:

1. updates version files
2. builds and checks Python artifacts
3. commits and tags `v0.1.4`
4. pushes GitHub `main` and the tag
5. uploads PyPI artifacts
6. updates the AUR package

Skip one target when needed:

```sh
packaging/release.sh 0.1.4 --skip-pypi
packaging/release.sh 0.1.4 --skip-aur
```

PyPI token setup:

```sh
export TWINE_USERNAME=__token__
export TWINE_PASSWORD='pypi-your-token'
```

Manual PyPI upload from an already-built `dist/`:

```sh
.release-venv/bin/python -m twine upload --skip-existing dist/*.whl dist/*.tar.gz
```

Users update with:

```sh
uv tool upgrade decompile
yay -Syu decompile
```

## Debian .deb

Build a local `.deb`:

```sh
packaging/deb/build-deb.sh
sudo apt install ./dist/decompile_0.1.3_all.deb
```

Build a simple unsigned apt repo for testing:

```sh
packaging/deb/build-apt-repo.sh
cd dist
python3 -m http.server 8000
```

For public apt distribution, use a signed repository or a package-hosting service instead of `trusted=yes`.
