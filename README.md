# decompile

`decompile` is a Docker-first static reverse-engineering CLI.

Install the small host command, run `decompile ./file`, and the heavy tools run inside the Docker image. The host does not need Ghidra, JADX, apktool, ILSpy, or binutils installed.

## Install

```sh
pip install decompile
decompile --update
```

Other package targets:

```sh
yay -S decompile
sudo apt install ./decompile_0.1.0_all.deb
```

Docker is required for the normal published workflow.

## Quick Start

```sh
decompile ./crackme
decompile --no-ai ./crackme
decompile --image docker.io/admin12121/decompile:stable ./crackme
decompile --local ./crackme
```

Default output goes to:

```text
./crackme.ghidra-out/
```

You can choose the output directory:

```sh
decompile ./crackme ./out
```

## What It Does

`decompile` detects the input format, chooses the matching static toolchain, and writes useful reverse-engineering output into one directory.

Supported routes:

| Input | Tooling | Output |
| --- | --- | --- |
| ELF, PE, EXE, DLL, SYS, Mach-O | Ghidra headless, objdump, optional AI cleanup | ASM, pseudocode C, enhanced C, summary |
| APK, AAB, DEX | JADX, apktool | Java/Kotlin source, resources, summary |
| JAR, WAR, EAR, `.class` | JADX | Java source, summary |
| .NET EXE/DLL | ilspycmd | C# source, summary |
| IPA, `.app` bundle | IPA/app extraction plus native analysis | Native output and app metadata |

Native binary output:

```text
<name>.disassembly.asm
<name>.pseudocode.c
<name>.enhanced.c
<name>.summary.txt
```

Android, Java, and .NET output usually includes:

```text
source/
resources/
<name>.summary.txt
```

## Docker Model

Published installs use this image by default:

```text
docker.io/admin12121/decompile:stable
```

The image is pulled only when it is missing locally. Normal runs reuse the local image and do not check the registry.

Update manually:

```sh
decompile --update
```

Use a custom image:

```sh
decompile --image ghcr.io/you/decompile:dev ./file
```

Run host tools directly:

```sh
decompile --local ./file
```

Inside Docker:

- input is mounted read-only
- output is mounted read-write
- the container runs as your current UID/GID
- temporary projects and scratch files are removed
- `--no-ai` disables network access for the analysis container

## AI Enhancement

For native binaries, `enhanced.c` can be generated from pseudocode, disassembly, objdump context, and summary data.

Use this when you want cleaner function names, variables, and reconstructed C-like output:

```sh
decompile ./file
```

Disable it for malware, private samples, offline work, or reproducible local-only output:

```sh
decompile --no-ai ./file
```

When AI is enabled, analysis context may be sent to GitHub Copilot through `gh`. Pass authentication with `GH_TOKEN`, `GITHUB_TOKEN`, or your local GitHub CLI config.

## Options

```text
decompile <file-or-bundle> [output-dir]
decompile --no-ai <file-or-bundle> [output-dir]
decompile --update [--image <image>]
decompile --image <image> <file-or-bundle> [output-dir]
decompile --local <file-or-bundle> [output-dir]
decompile --type <native|apk|aab|dex|jar|class|dotnet|ipa|app-bundle> <file> [output-dir]
```

Useful environment variables:

```text
DECOMPILE_DOCKER_IMAGE      override the Docker image
DECOMPILE_USE_DOCKER=0      run local host tools
DECOMPILE_NO_AI=1           skip AI enhancement
DECOMPILE_KEEP_DEBUG=1      keep objdump and prompt/debug files
GHIDRA_TIMEOUT=120          per-function decompile timeout
```

## Limits

This is static analysis only. It does not run the target, debug it, emulate it, unpack it, or bypass runtime protections.

Packed binaries, heavy obfuscation, anti-disassembly tricks, encrypted IPA files, and protected mobile apps can still produce weak or incomplete output.

Docker isolation reduces host writes, but it is not a malware sandbox. Do not execute unknown samples with this tool.

## Development

Build the Docker image:

```sh
docker build -t decompile:latest .
```

Use the local image:

```sh
decompile --image decompile:latest ./sample
```

Build Python release artifacts:

```sh
python3 -m build
```
