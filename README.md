# decompile

`decompile` is a Docker-isolated static reverse-engineering orchestrator. The host install is a small Python launcher; Ghidra, JADX, apktool, ILSpy, binutils, and optional GitHub Copilot enhancement run inside the Docker image.

```sh
decompile ./sample
decompile --no-ai ./sample
decompile --update
decompile --image docker.io/yourname/decompile:dev ./sample
decompile --local ./sample
```

Published installs use `docker.io/admin12121/decompile:stable` by default. The image is pulled only when it is missing locally, or when `decompile --update` is run.

Supported static routes include native ELF/PE/Mach-O binaries, APK/AAB/DEX, Java archives/classes, .NET assemblies, IPA files, and `.app` bundles. See `CAPABILITIES.md` for output layout, environment variables, and limitations.
