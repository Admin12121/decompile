#!/usr/bin/env python3
import os
import hashlib
import json
import math
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path


try:
    sys.stdout.reconfigure(line_buffering=True)
except AttributeError:
    pass

APP_NAME = "decompile"
DEFAULT_SUFFIX = ".ghidra-out"
DEFAULT_DOCKER_IMAGE = "docker.io/admin12121/decompile:stable"
DOCKER_PASSTHROUGH_ENV = {
    "GHIDRA_TIMEOUT",
}
SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
ASCII_SPINNER_FRAMES = ["|", "/", "-", "\\"]
NATIVE_KINDS = {"native", "elf", "pe", "macho", "native-unknown"}
ANDROID_KINDS = {"apk", "aab", "dex"}
JAVA_KINDS = {"jar", "class"}
DOTNET_KINDS = {"dotnet"}


class DecompileError(Exception):
    pass


def color_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def style(text: str, code: str) -> str:
    if not color_enabled():
        return text
    return f"\033[{code}m{text}\033[0m"


def dim(text: str) -> str:
    return style(text, "2")


def green(text: str) -> str:
    return style(text, "32")


def cyan(text: str) -> str:
    return style(text, "36")


def yellow(text: str) -> str:
    return style(text, "33")


def bold(text: str) -> str:
    return style(text, "1")


def symbol(name: str) -> str:
    symbols = {
        "ok": "✓",
        "question": "?",
        "dot": "•",
        "folder": "▸",
    }
    ascii_symbols = {
        "ok": "+",
        "question": "?",
        "dot": "-",
        "folder": ">",
    }
    if os.environ.get("DECOMPILE_ASCII") == "1":
        return ascii_symbols.get(name, "")
    return symbols.get(name, "")


def tree_mid() -> str:
    return "|-" if os.environ.get("DECOMPILE_ASCII") == "1" else "├─"


def tree_last() -> str:
    return "`-" if os.environ.get("DECOMPILE_ASCII") == "1" else "└─"


def tree_pipe() -> str:
    return "|  " if os.environ.get("DECOMPILE_ASCII") == "1" else "│  "


def spinner_frames() -> list[str]:
    if os.environ.get("DECOMPILE_ASCII") == "1":
        return ASCII_SPINNER_FRAMES
    return SPINNER_FRAMES


class StatusLine:
    def __init__(self) -> None:
        self.enabled = sys.stdout.isatty() and os.environ.get("DECOMPILE_VERBOSE") != "1"
        self.message = ""
        self.active = False
        self.index = 0
        self.width = 0
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None

    def start(self, message: str) -> None:
        if not self.enabled:
            return
        with self.lock:
            self.message = message
            if self.active:
                return
            self.active = True
            self.thread = threading.Thread(target=self._spin, daemon=True)
            self.thread.start()

    def update(self, message: str) -> None:
        if not self.enabled:
            return
        with self.lock:
            self.message = message

    def stop(self, final: str | None = None) -> None:
        if not self.enabled:
            if final:
                print(final)
            return
        thread = None
        with self.lock:
            self.active = False
            thread = self.thread
            self.thread = None
        if thread:
            thread.join(timeout=0.3)
        self.clear()
        if final:
            print(final)

    def clear(self) -> None:
        if not self.enabled:
            return
        sys.stdout.write("\r" + " " * max(self.width, 1) + "\r")
        sys.stdout.flush()
        self.width = 0

    def _spin(self) -> None:
        while True:
            with self.lock:
                if not self.active:
                    return
                frames = spinner_frames()
                frame = frames[self.index % len(frames)]
                self.index += 1
                text = f"{cyan(frame)} {dim(self.message)}"
            text = text[: shutil.get_terminal_size((100, 20)).columns - 1]
            self.width = max(self.width, len(text))
            sys.stdout.write("\r" + text + " " * max(self.width - len(text), 0))
            sys.stdout.flush()
            time.sleep(0.12)


STATUS = StatusLine()


def is_verbose() -> bool:
    return os.environ.get("DECOMPILE_VERBOSE") == "1"


def status(message: str) -> None:
    if STATUS.enabled:
        STATUS.update(message)
    elif is_verbose():
        print(f"[+] {message}")


def status_start(message: str) -> None:
    if STATUS.enabled:
        STATUS.start(message)
    elif is_verbose():
        print(f"[+] {message}")


def status_done(message: str) -> None:
    STATUS.stop(message)


def print_clean(message: str = "") -> None:
    STATUS.clear()
    print(message)


@dataclass
class Context:
    input_path: Path
    output_dir: Path
    base_name: str
    root_dir: Path
    resource_dirs: list[Path]
    keep_debug: bool
    timeout: int
    force_kind: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    tool_statuses: list[dict[str, object]] = field(default_factory=list)


@dataclass
class CliOptions:
    force_local: bool = False
    ai: bool = False
    no_ai: bool = False
    no_open: bool = False
    keep_debug: bool = False
    docker_image: str | None = None
    copilot_model: str | None = None
    copilot_effort: str | None = None
    update_image: bool = False


def main() -> int:
    try:
        args = normalize_args(sys.argv[1:])
        if not args or args[0] in {"-h", "--help", "help"}:
            print_usage()
            return 0 if args else 1

        args, options = parse_global_options(args)
        apply_global_options(options)

        if options.update_image:
            if args:
                raise DecompileError("--update does not take an input file")
            return update_docker_image()

        if args and args[0] == "doctor":
            if len(args) > 1:
                raise DecompileError("doctor does not take extra arguments")
            return run_doctor(options)

        if should_use_docker(options.force_local):
            return run_in_docker(args)

        force_kind = None
        if args and args[0] == "--type":
            if len(args) < 3:
                raise DecompileError("--type requires a type and input file")
            force_kind = args[1]
            args = args[2:]

        if len(args) > 2:
            raise DecompileError("too many arguments")

        input_path = Path(args[0]).expanduser().resolve()
        if not input_path.exists():
            raise DecompileError(f"file not found: {input_path}")

        base_name = sanitize_name(input_path.name)
        output_dir = Path(args[1]).expanduser().resolve() if len(args) == 2 else Path.cwd() / f"{base_name}{DEFAULT_SUFFIX}"
        output_dir.mkdir(parents=True, exist_ok=True)

        root_dir = Path(__file__).resolve().parent
        ctx = Context(
            input_path=input_path,
            output_dir=output_dir,
            base_name=base_name,
            root_dir=root_dir,
            resource_dirs=resource_dirs(root_dir),
            keep_debug=os.environ.get("DECOMPILE_KEEP_DEBUG") == "1" or os.environ.get("DECOMPILE_KEEP_COPILOT_DEBUG") == "1",
            timeout=parse_timeout(),
            force_kind=force_kind,
        )

        kind = force_kind or detect_kind(input_path)
        local_ai_candidate = kind in NATIVE_KINDS and os.environ.get("DECOMPILE_NO_AI") != "1"
        local_ai_deferred = local_ai_candidate and os.environ.get("DECOMPILE_AI_CONFIRMED") != "1"
        original_keep_debug = ctx.keep_debug
        if local_ai_deferred:
            ctx.keep_debug = True

        initialize_metadata(ctx, kind)
        status_start(f"analyzing {ctx.input_path.name} as {kind}")

        if kind in NATIVE_KINDS:
            reverse_native(ctx, ctx.input_path, ctx.base_name)
        elif kind in ANDROID_KINDS:
            reverse_android(ctx, kind)
        elif kind in JAVA_KINDS:
            reverse_java(ctx, kind)
        elif kind in DOTNET_KINDS:
            reverse_dotnet(ctx)
        elif kind == "ipa":
            reverse_ipa(ctx)
        elif kind == "app-bundle":
            reverse_app_bundle(ctx)
        else:
            status("unknown format; falling back to native analysis")
            reverse_native(ctx, ctx.input_path, ctx.base_name)

        finalize_outputs(ctx, kind)

        completion_printed = False
        if local_ai_deferred and (ctx.output_dir / "pseudocode.c").is_file():
            if confirm_ai_enhancement(ctx.output_dir):
                run_host_ai_enhancement(ctx.input_path, ctx.output_dir, ctx.base_name, original_keep_debug)
                print_outputs(ctx)
                completion_printed = True
            elif not original_keep_debug:
                safe_unlink(ctx.output_dir / "enhanced.c")
                safe_unlink(ctx.output_dir / "report.md")
                cleanup_host_ai_temp(ctx.output_dir, ctx.base_name, keep_debug=False)
                sync_output_reports(ctx.output_dir)
                print_output_manifest_line(ctx.output_dir)
                open_output_dir(ctx.output_dir)
                completion_printed = True

        if not completion_printed:
            print_outputs(ctx)
        return 0
    except DecompileError as exc:
        STATUS.stop()
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        STATUS.stop()
        print("[-] interrupted", file=sys.stderr)
        return 130


def normalize_args(args: list[str]) -> list[str]:
    if args and args[0] == "decompile":
        return args[1:]
    return args


def parse_global_options(args: list[str]) -> tuple[list[str], CliOptions]:
    cleaned = []
    options = CliOptions()
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--local":
            options.force_local = True
        elif arg == "--ai":
            options.ai = True
        elif arg == "--no-ai":
            options.no_ai = True
        elif arg == "--no-open":
            options.no_open = True
        elif arg == "--keep-debug":
            options.keep_debug = True
        elif arg == "--update":
            options.update_image = True
        elif arg in {"--image", "--docker-image"}:
            index += 1
            if index >= len(args):
                raise DecompileError(f"{arg} requires an image name")
            options.docker_image = args[index]
        elif arg == "--model":
            index += 1
            if index >= len(args):
                raise DecompileError("--model requires a Copilot model name")
            model = args[index].strip()
            if not model or model.startswith("-"):
                raise DecompileError("--model requires a Copilot model name")
            options.copilot_model = model
        elif arg == "--effort":
            index += 1
            if index >= len(args):
                raise DecompileError("--effort requires one of: low, medium, high, xhigh")
            effort = args[index].lower()
            if effort not in {"low", "medium", "high", "xhigh"}:
                raise DecompileError("--effort must be one of: low, medium, high, xhigh")
            options.copilot_effort = effort
        else:
            cleaned.append(arg)
        index += 1
    return cleaned, options


def apply_global_options(options: CliOptions) -> None:
    if options.ai and options.no_ai:
        raise DecompileError("--ai and --no-ai cannot be used together")
    if options.ai:
        os.environ["DECOMPILE_AI_CONFIRMED"] = "1"
    if options.no_ai:
        os.environ["DECOMPILE_NO_AI"] = "1"
    if options.keep_debug:
        os.environ["DECOMPILE_KEEP_DEBUG"] = "1"
    if options.no_open:
        os.environ["DECOMPILE_NO_OPEN"] = "1"
    if options.docker_image:
        os.environ["DECOMPILE_DOCKER_IMAGE"] = options.docker_image
    if options.copilot_model:
        os.environ["DECOMPILE_COPILOT_MODEL"] = options.copilot_model
    if options.copilot_effort:
        os.environ["DECOMPILE_COPILOT_EFFORT"] = options.copilot_effort


def should_use_docker(force_local: bool) -> bool:
    if force_local or os.environ.get("DECOMPILE_IN_DOCKER") == "1":
        return False

    mode = os.environ.get("DECOMPILE_USE_DOCKER", "auto").lower()
    if mode in {"0", "false", "no", "off", "local"}:
        return False

    docker = which("docker")
    if docker:
        return True

    raise DecompileError(
        "Docker is not installed or not in PATH. Install Docker, then run this command again. "
        "Use --local only when Ghidra/JADX/apktool/ilspycmd are installed on the host."
    )


def run_in_docker(args: list[str]) -> int:
    parsed = parse_docker_args(args)
    image = docker_image_name()
    ensure_docker_available()
    ensure_docker_image(image)
    host_ai_enabled = os.environ.get("DECOMPILE_NO_AI") != "1"
    keep_debug = os.environ.get("DECOMPILE_KEEP_DEBUG") == "1" or os.environ.get("DECOMPILE_KEEP_COPILOT_DEBUG") == "1"

    input_path = parsed["input"].expanduser().resolve()
    output_dir = parsed["output"].expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    input_mount = input_path.parent if input_path.is_file() else input_path.parent
    input_in_container = Path("/input") / input_path.name

    command = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--hostname",
        "decompile",
        "--add-host",
        "decompile:127.0.0.1",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges",
        "--network",
        "none",
    ]

    command.extend([
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-e", "DECOMPILE_IN_DOCKER=1",
        "-e", "HOME=/tmp/decompile-home",
        "-e", "DECOMPILE_NO_AI=1",
        "-v", f"{input_mount}:/input:ro",
        "-v", f"{output_dir}:/out",
    ])

    if host_ai_enabled or keep_debug:
        command.extend(["-e", "DECOMPILE_KEEP_DEBUG=1"])

    for name in sorted(DOCKER_PASSTHROUGH_ENV):
        if name in os.environ:
            command.extend(["-e", f"{name}={os.environ[name]}"])

    command.append(image)
    if parsed["force_kind"]:
        command.extend(["--type", parsed["force_kind"]])
    command.extend([str(input_in_container), "/out"])

    status_start(f"running isolated static analysis in {image}")
    result = run_process(command, "running isolated static analysis", check=False)
    if result.returncode == 125:
        STATUS.stop()
        print("[-] Docker could not start the analysis container. Check Docker daemon status, image name, and mount permissions.", file=sys.stderr)
        return result.returncode
    elif result.returncode != 0:
        STATUS.stop()
        print(f"[-] Analysis container exited with code {result.returncode}", file=sys.stderr)
        if result.stdout:
            print(compact_error(str(result.stdout), limit=800), file=sys.stderr)
        return result.returncode

    normalize_docker_reports(output_dir, input_path)

    if not host_ai_enabled:
        safe_unlink(output_dir / "enhanced.c")
        safe_unlink(output_dir / "report.md")
        sync_output_reports(output_dir)
        print_completed(output_dir, ai_ran=False)
        return 0

    if host_ai_enabled and (output_dir / "pseudocode.c").is_file():
        if confirm_ai_enhancement(output_dir):
            result_code = run_host_ai_enhancement(input_path, output_dir, sanitize_name(input_path.name), keep_debug)
            print_completed(output_dir, ai_ran=result_code == 0)
            return result_code
        safe_unlink(output_dir / "enhanced.c")
        safe_unlink(output_dir / "report.md")
        cleanup_host_ai_temp(output_dir, sanitize_name(input_path.name), keep_debug=False)
        sync_output_reports(output_dir)
        print_output_manifest_line(output_dir)
        open_output_dir(output_dir)
        return 0

    print_completed(output_dir, ai_ran=False)
    return 0


def parse_docker_args(args: list[str]) -> dict:
    force_kind = None
    remaining = list(args)
    if remaining and remaining[0] == "--type":
        if len(remaining) < 3:
            raise DecompileError("--type requires a type and input file")
        force_kind = remaining[1]
        remaining = remaining[2:]

    if not remaining:
        raise DecompileError("missing input file")
    if len(remaining) > 2:
        raise DecompileError("too many arguments")

    input_path = Path(remaining[0])
    if not input_path.exists():
        raise DecompileError(f"file not found: {input_path}")

    if len(remaining) == 2:
        output_dir = Path(remaining[1])
    else:
        output_dir = Path.cwd() / f"{sanitize_name(input_path.name)}{DEFAULT_SUFFIX}"

    return {"force_kind": force_kind, "input": input_path, "output": output_dir}


def ensure_docker_image(image: str) -> None:
    if subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        return

    status_start(f"pulling missing Docker image {image}")
    pull_docker_image(image)


def update_docker_image() -> int:
    image = docker_image_name()
    status_start(f"updating Docker image {image}")
    pull_docker_image(image)
    status_done("Docker image is up to date locally")
    return 0


def pull_docker_image(image: str) -> None:
    ensure_docker_available()

    result = run(["docker", "pull", image], check=False, status_message=f"pulling Docker image {image}")
    if result.returncode == 0:
        return

    dockerfile = Path(__file__).resolve().parent / "Dockerfile"
    if dockerfile.exists():
        raise DecompileError(
            f"could not pull Docker image: {image}. "
            f"For local development, build it with: docker build -t {image} ."
        )
    raise DecompileError(
        f"could not pull Docker image: {image}. Check network access, image name, and Docker registry credentials."
    )


def docker_image_name() -> str:
    return os.environ.get("DECOMPILE_DOCKER_IMAGE", DEFAULT_DOCKER_IMAGE)


def normalize_docker_reports(output_dir: Path, input_path: Path) -> None:
    container_input = str(Path("/input") / input_path.name)
    replacements = {
        container_input: str(input_path),
        "/out": str(output_dir),
    }

    summary = output_dir / "summary.txt"
    if summary.exists():
        text = summary.read_text(encoding="utf-8", errors="replace")
        for old, new in replacements.items():
            text = text.replace(old, new)
        summary.write_text(text, encoding="utf-8")

    metadata = output_dir / "metadata.json"
    if metadata.exists():
        try:
            data = json.loads(metadata.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            input_data = data.setdefault("input", {})
            if isinstance(input_data, dict):
                input_data["path"] = str(input_path)
            analysis = data.setdefault("analysis", {})
            if isinstance(analysis, dict):
                analysis["output_dir"] = str(output_dir)
            data["outputs"] = build_output_manifest(output_dir)
            metadata.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    sync_output_reports(output_dir)


def find_resource_path(name: str, dirs: list[Path]) -> Path:
    env_path = os.environ.get("GHIDRA_SCRIPT_PATH")
    search_dirs = [Path(env_path)] if env_path else []
    search_dirs.extend(dirs)
    for directory in search_dirs:
        candidate = directory / name
        if candidate.exists():
            return candidate
    raise DecompileError(f"required resource not found: {name}")


def run_host_ai_enhancement(input_path: Path, output_dir: Path, base_name: str, keep_debug: bool) -> int:
    if not (output_dir / "pseudocode.c").is_file():
        status("no native pseudocode output found; skipping AI")
        return 0

    try:
        if not which("gh"):
            raise DecompileError(
                "AI enhancement runs on the host, but 'gh' is not installed. "
                "Install GitHub CLI/Copilot tools or rerun with --no-ai."
            )

        copilot = subprocess.run(["gh", "copilot", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if copilot.returncode != 0:
            raise DecompileError(
                "AI enhancement runs on the host, but 'gh copilot' is not available. "
                "Install/enable GitHub Copilot CLI or rerun with --no-ai."
            )

        root_dir = Path(__file__).resolve().parent
        enhancer = find_resource_path("enhance_with_copilot", resource_dirs(root_dir))
        if not os.access(enhancer, os.X_OK):
            raise DecompileError(f"host enhancer is not executable: {enhancer}")

        debug_dir = output_dir / "debug"
        objdump = debug_dir / "objdump.txt"
        if not objdump.is_file():
            raise DecompileError(
                "host AI enhancement needs debug/objdump.txt from the extraction container. "
                "Rerun without deleting the output directory, or use --no-ai."
            )

        legacy_files = {
            output_dir / "pseudocode.c": output_dir / f"{base_name}.pseudocode.c",
            output_dir / "disassembly.asm": output_dir / f"{base_name}.disassembly.asm",
            output_dir / "summary.txt": output_dir / f"{base_name}.summary.txt",
            objdump: output_dir / f"{base_name}.objdump.txt",
        }
        objdump_err = debug_dir / "objdump.err"
        if objdump_err.exists():
            legacy_files[objdump_err] = output_dir / f"{base_name}.objdump.err"

        for source, target in legacy_files.items():
            if source.exists():
                shutil.copyfile(source, target)

        env = os.environ.copy()
        env["DECOMPILE_PYTHON"] = sys.executable
        if keep_debug:
            env["DECOMPILE_KEEP_COPILOT_DEBUG"] = "1"
        else:
            env.pop("DECOMPILE_KEEP_COPILOT_DEBUG", None)

        status("running AI reconstruction and report generation")
        result = run(
            [str(enhancer), str(input_path), str(output_dir), base_name],
            check=False,
            env=env,
            status_message="running AI reconstruction and report generation",
        )
        if result.returncode != 0:
            raise DecompileError(
                "host AI enhancement failed. Check 'gh auth status' and GitHub Copilot CLI availability, "
                "or rerun with --no-ai."
            )

        enhanced_legacy = output_dir / f"{base_name}.enhanced.c"
        report_legacy = output_dir / f"{base_name}.report.md"
        summary_legacy = output_dir / f"{base_name}.summary.txt"
        if enhanced_legacy.exists():
            move_generated_file(enhanced_legacy, output_dir / "enhanced.c")
        if report_legacy.exists():
            move_generated_file(report_legacy, output_dir / "report.md")
        if summary_legacy.exists():
            move_generated_file(summary_legacy, output_dir / "summary.txt")

        cleanup_host_ai_temp(output_dir, base_name, keep_debug)
        for _ in range(2):
            update_metadata_after_host_ai(output_dir)
            update_summary_after_host_ai(output_dir)
        update_metadata_after_host_ai(output_dir)

        status("AI reconstruction complete")
        return 0
    except Exception:
        cleanup_host_ai_temp(output_dir, base_name, keep_debug)
        sync_output_reports(output_dir)
        raise


def host_ai_debug_files(base_name: str) -> dict[str, str]:
    return {
        f"{base_name}.enhanced.raw.jsonl": "enhanced.raw.jsonl",
        f"{base_name}.enhanced.response.txt": "enhanced.response.txt",
        f"{base_name}.report.raw.jsonl": "report.raw.jsonl",
        f"{base_name}.report.response.md": "report.response.md",
        f"{base_name}.enhanced.syntax.log": "enhanced.syntax.log",
        f"{base_name}.enhance.prompt.txt": "enhance.prompt.txt",
        f"{base_name}.report.prompt.txt": "report.prompt.txt",
        f"{base_name}.enhance.fix.prompt.txt": "enhance.fix.prompt.txt",
        f"{base_name}.enhanced.fix.raw.jsonl": "enhanced.fix.raw.jsonl",
        f"{base_name}.enhanced.fix.response.txt": "enhanced.fix.response.txt",
    }


def cleanup_host_ai_temp(output_dir: Path, base_name: str, keep_debug: bool) -> None:
    for suffix in [
        "pseudocode.c",
        "disassembly.asm",
        "summary.txt",
        "objdump.txt",
        "objdump.err",
    ]:
        safe_unlink(output_dir / f"{base_name}.{suffix}")

    debug_dir = output_dir / "debug"
    if keep_debug:
        debug_dir.mkdir(exist_ok=True)
        for source_name, target_name in host_ai_debug_files(base_name).items():
            move_generated_file(output_dir / source_name, debug_dir / target_name)
    else:
        for source_name in host_ai_debug_files(base_name):
            safe_unlink(output_dir / source_name)
        shutil.rmtree(debug_dir, ignore_errors=True)


def sync_output_reports(output_dir: Path) -> None:
    for _ in range(2):
        refresh_metadata_outputs(output_dir)
        refresh_summary_output_section_file(output_dir)
    refresh_metadata_outputs(output_dir)


def refresh_metadata_outputs(output_dir: Path) -> None:
    path = output_dir / "metadata.json"
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    data["outputs"] = build_output_manifest(output_dir)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def update_summary_after_host_ai(output_dir: Path) -> None:
    summary = output_dir / "summary.txt"
    if not summary.exists():
        return
    text = summary.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"(?m)^Enhanced file\s*:.*\n?", "", text)
    text = re.sub(r"(?m)^AI report\s*:.*\n?", "", text)
    text = re.sub(r"(?m)^AI runner\s*:.*\n?", "", text)
    text = re.sub(r"(?m)^enhancer\s+skipped\s+DECOMPILE_NO_AI=1\s*\n?", "", text)
    text = append_summary_tool_status(text, "host-enhancer            ok       host GitHub CLI/Copilot")
    text = text.rstrip() + "\n"
    text += f"Enhanced file      : {output_dir / 'enhanced.c'}\n"
    if (output_dir / "report.md").exists():
        text += f"AI report          : {output_dir / 'report.md'}\n"
    text += "AI runner          : host GitHub CLI/Copilot\n"
    text = refresh_summary_outputs(text, output_dir)
    summary.write_text(text.rstrip() + "\n", encoding="utf-8")


def refresh_summary_outputs(text: str, output_dir: Path) -> str:
    section = "\n".join(["OUTPUTS", "-" * 80, *format_output_manifest(output_dir)]) + "\n"
    pattern = r"(?ms)^OUTPUTS\n-{80}\n.*?(?=\n[A-Z][A-Z ]+\n-{80}\n|\Z)"
    if re.search(pattern, text):
        return re.sub(pattern, section, text)
    return text


def refresh_summary_output_section_file(output_dir: Path) -> bool:
    summary = output_dir / "summary.txt"
    if not summary.exists():
        return False
    original = summary.read_text(encoding="utf-8", errors="replace")
    updated = refresh_summary_outputs(original, output_dir).rstrip() + "\n"
    if updated == original:
        return False
    summary.write_text(updated, encoding="utf-8")
    return True


def append_summary_tool_status(text: str, line: str) -> str:
    if line in text:
        return text
    pattern = r"(?ms)^(TOOL STATUS\n-{80}\n)(.*?)(?=\n[A-Z][A-Z ]+\n-{80}\n|\Z)"
    match = re.search(pattern, text)
    if not match:
        return text

    body = match.group(2).rstrip()
    if body == "No external tool status recorded.":
        body = line
    else:
        body = body + "\n" + line
    return text[: match.start()] + match.group(1) + body + text[match.end():]


def update_metadata_after_host_ai(output_dir: Path) -> None:
    path = output_dir / "metadata.json"
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    analysis = data.setdefault("analysis", {})
    if isinstance(analysis, dict):
        analysis["ai_runner"] = "host"
        analysis["ai_enabled"] = True
    statuses = data.setdefault("tool_statuses", [])
    if isinstance(statuses, list):
        if not any(isinstance(item, dict) and item.get("name") == "host-enhancer" for item in statuses):
            statuses.append({"name": "host-enhancer", "status": "ok"})
    data["outputs"] = build_output_manifest(output_dir)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def ensure_docker_available() -> None:
    if not which("docker"):
        raise DecompileError(
            "Docker CLI not found. Install Docker Engine/Desktop and make sure 'docker' is in PATH. "
            "Use --local only when all reverse-engineering tools are installed on the host."
        )

    result = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        detail = compact_error(result.stderr)
        raise DecompileError(
            "Docker is installed but the daemon is not reachable. Start Docker and verify with 'docker info'."
            + (f" Details: {detail}" if detail else "")
        )


def print_usage() -> None:
    print(
"""Usage:
  decompile <file-or-bundle> [output-dir]
  decompile --local <file-or-bundle> [output-dir]
  decompile --ai <file-or-bundle> [output-dir]
  decompile --no-ai <file-or-bundle> [output-dir]
  decompile --no-open <file-or-bundle> [output-dir]
  decompile <file-or-bundle> --model <model> [output-dir]
  decompile <file-or-bundle> --effort <low|medium|high|xhigh> [output-dir]
  decompile --update [--image <image>]
  decompile doctor [--image <image>]
  decompile --image <image> <file-or-bundle> [output-dir]
  decompile --type <native|apk|aab|dex|jar|class|dotnet|ipa|app-bundle> <file> [output-dir]

Supported static routes:
  native       ELF, PE/EXE/DLL, Mach-O, raw native binaries via Ghidra
  apk/aab/dex  Android packages and dex files via JADX, apktool when available
  jar/class    Java archives/classes via JADX when available
  dotnet       .NET EXE/DLL via ilspycmd when available, native fallback
  ipa          iOS IPA extraction plus Mach-O analysis of app executable
  app-bundle   macOS/iOS .app bundle executable analysis

Environment:
  DECOMPILE_USE_DOCKER=0      disable Docker wrapper and run tools on host
  DECOMPILE_DOCKER_IMAGE      image used by wrapper, default docker.io/admin12121/decompile:stable
  GHIDRA_ANALYZE_HEADLESS     path to analyzeHeadless
  GHIDRA_SCRIPT_PATH          directory containing DumpAllDecompile.java
  GHIDRA_TIMEOUT              per-function timeout in seconds, default 120
  DECOMPILE_NO_AI=1           skip Copilot enhanced C and copy pseudocode instead
  DECOMPILE_NO_OPEN=1         do not open the output directory in an editor
  DECOMPILE_VERBOSE=1         print full tool logs instead of compact progress
  DECOMPILE_KEEP_DEBUG=1      keep objdump/prompt/raw debug files
  DECOMPILE_COPILOT_MODEL     optional Copilot model for enhanced.c
  DECOMPILE_COPILOT_EFFORT    optional low, medium, high, xhigh"""
    )


def run_doctor(options: CliOptions) -> int:
    checks: list[tuple[str, str, str]] = []

    def add(status: str, name: str, detail: str) -> None:
        checks.append((status, name, detail))

    add("OK", "python", sys.version.split()[0])

    docker = which("docker")
    if docker:
        version = subprocess.run(["docker", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        add("OK" if version.returncode == 0 else "WARN", "docker cli", version.stdout.strip() or compact_error(version.stderr))
        info_result = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if info_result.returncode == 0:
            add("OK", "docker daemon", "reachable")
            image = docker_image_name()
            inspect = subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if inspect.returncode == 0:
                add("OK", "docker image", image)
            else:
                add("WARN", "docker image", f"{image} missing; first run or decompile --update will pull it")
        else:
            add("FAIL", "docker daemon", compact_error(info_result.stderr) or "not reachable")
    else:
        add("FAIL", "docker cli", "not installed; Docker is required unless using --local with host tools")

    root_dir = Path(__file__).resolve().parent
    dirs = resource_dirs(root_dir)
    for resource in ["DumpAllDecompile.java", "enhance_with_copilot"]:
        found = next((directory / resource for directory in dirs if (directory / resource).exists()), None)
        if found:
            executable_note = ""
            if resource == "enhance_with_copilot" and not os.access(found, os.X_OK):
                add("FAIL", resource, f"{found} exists but is not executable")
                continue
            add("OK", resource, str(found) + executable_note)
        else:
            add("FAIL", resource, "not found")

    analyze = None
    try:
        analyze = find_analyze_headless()
    except DecompileError as exc:
        add("WARN", "analyzeHeadless", str(exc))
    if analyze:
        add("OK", "analyzeHeadless", str(analyze))

    for tool in ["jadx", "apktool", "ilspycmd", "objdump", "readelf", "nm", "file", "gcc"]:
        path = which(tool)
        add("OK" if path else "WARN", tool, path or "missing; needed only for related input types")

    gh = which("gh")
    if gh:
        add("OK", "gh", gh)
        if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
            add("OK", "github auth", "GH_TOKEN/GITHUB_TOKEN is set")
        else:
            auth = subprocess.run(["gh", "auth", "status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            detail = compact_error(auth.stdout + "\n" + auth.stderr)
            add("OK" if auth.returncode == 0 else "WARN", "github auth", detail or "not authenticated; AI enhancement may fail")
    else:
        add("WARN", "gh", "missing; AI enhancement requires GitHub CLI")

    if gh:
        copilot = subprocess.run(["gh", "copilot", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        add(
            "OK" if copilot.returncode == 0 else "WARN",
            "gh copilot",
            "available" if copilot.returncode == 0 else "missing/unavailable; AI enhancement will fail unless --no-ai is used",
        )

    print("decompile doctor")
    print("=" * 80)
    for status, name, detail in checks:
        print(f"{status:<5} {name:<22} {detail}")

    return 1 if any(status == "FAIL" for status, _, _ in checks) else 0


def sanitize_name(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return cleaned or "input"


def parse_timeout() -> int:
    raw = os.environ.get("GHIDRA_TIMEOUT", "120")
    try:
        value = int(raw)
        if value <= 0:
            raise ValueError
        return value
    except ValueError:
        raise DecompileError("GHIDRA_TIMEOUT must be a positive integer")


def resource_dirs(root_dir: Path) -> list[Path]:
    dirs = [
        root_dir,
        Path("/usr/local/share/decompile"),
        Path("/usr/share/decompile"),
        Path("/scripts"),
    ]
    return unique_paths([d for d in dirs if d.exists()])


def unique_paths(paths: list[Path]) -> list[Path]:
    seen = set()
    out = []
    for path in paths:
        key = str(path.resolve())
        if key not in seen:
            seen.add(key)
            out.append(path)
    return out


def find_resource(ctx: Context, name: str) -> Path:
    return find_resource_path(name, ctx.resource_dirs)


def which(name: str) -> str | None:
    return shutil.which(name)


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    stdout=None,
    stderr=None,
    env: dict[str, str] | None = None,
    status_message: str | None = None,
) -> subprocess.CompletedProcess:
    display = " ".join(cmd)
    result = run_process(cmd, status_message or display, cwd=cwd, check=False, stdout=stdout, stderr=stderr, env=env)
    if check and result.returncode != 0:
        raise DecompileError(f"command failed ({result.returncode}): {display}")
    return result


def run_process(
    cmd: list[str],
    message: str,
    *,
    cwd: Path | None = None,
    check: bool = True,
    stdout=None,
    stderr=None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    display = " ".join(cmd)
    if is_verbose():
        print(f"[+] $ {display}")
    status(message)

    if is_verbose() or stdout is not None or stderr is not None:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=stdout,
            stderr=stderr,
            text=False,
            env=env,
        )
    else:
        last_lines: deque[str] = deque(maxlen=30)
        process = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=env,
        )
        assert process.stdout is not None
        for line in process.stdout:
            cleaned = " ".join(line.strip().split())
            if cleaned:
                last_lines.append(cleaned)
                status(cleaned)
        return_code = process.wait()
        result = subprocess.CompletedProcess(cmd, return_code, stdout="\n".join(last_lines), stderr="")

    if check and result.returncode != 0:
        raise DecompileError(f"command failed ({result.returncode}): {display}")
    return result


def capture_tool(ctx: Context, name: str, cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess | None:
    if not cmd or not which(cmd[0]):
        ctx.tool_statuses.append({"name": name, "status": "missing", "command": cmd[0] if cmd else ""})
        return None
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        record_tool(ctx, name, result)
        return result
    except subprocess.TimeoutExpired:
        ctx.tool_statuses.append({"name": name, "status": "timeout", "command": " ".join(cmd), "timeout": timeout})
        return None


def record_tool(ctx: Context, name: str, result: subprocess.CompletedProcess) -> None:
    entry: dict[str, object] = {
        "name": name,
        "status": "ok" if result.returncode == 0 else "failed",
        "exit_code": result.returncode,
    }
    args = getattr(result, "args", None)
    if args:
        entry["command"] = " ".join(str(part) for part in args) if isinstance(args, list) else str(args)
    stderr = getattr(result, "stderr", None)
    if isinstance(stderr, str) and stderr.strip():
        entry["stderr"] = compact_error(stderr)
    ctx.tool_statuses.append(entry)


def compact_error(text: str, limit: int = 240) -> str:
    cleaned = " ".join(text.strip().split())
    if len(cleaned) > limit:
        return cleaned[: limit - 3] + "..."
    return cleaned


def summary_path(ctx: Context) -> Path:
    return ctx.output_dir / "summary.txt"


def metadata_path(ctx: Context) -> Path:
    return ctx.output_dir / "metadata.json"


def initialize_metadata(ctx: Context, kind: str) -> None:
    ctx.metadata = {
        "tool": APP_NAME,
        "schema": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input": {
            "path": str(ctx.input_path),
            "name": ctx.input_path.name,
            "kind": kind,
        },
        "analysis": {
            "output_dir": str(ctx.output_dir),
            "base_name": ctx.base_name,
            "timeout_seconds": ctx.timeout,
            "ai_enabled": os.environ.get("DECOMPILE_NO_AI") != "1",
        },
    }

    if ctx.input_path.is_file():
        size, sha256, entropy = file_size_hash_entropy(ctx.input_path)
        ctx.metadata["input"].update({"size": size, "sha256": sha256, "entropy": entropy})
        collect_static_metadata(ctx)


def collect_static_metadata(ctx: Context) -> None:
    binary = ctx.input_path
    kind = str(ctx.metadata.get("input", {}).get("kind", ""))
    file_result = capture_tool(ctx, "file", ["file", "-b", str(binary)])
    file_description = file_result.stdout.strip() if file_result and file_result.returncode == 0 else ""

    native_metadata = kind in NATIVE_KINDS or kind in DOTNET_KINDS
    if native_metadata:
        objdump_file = capture_tool(ctx, "objdump-file", ["objdump", "-f", str(binary)])
        objdump_header = objdump_file.stdout if objdump_file and objdump_file.returncode == 0 else ""
        ctx.metadata["architecture"] = parse_architecture(file_description, objdump_header)
        ctx.metadata["sections"] = collect_sections(ctx, binary)
        ctx.metadata["imports"] = collect_imports(ctx, binary)
        ctx.metadata["symbols"] = collect_symbols(ctx, binary)
    else:
        ctx.metadata["architecture"] = parse_architecture(file_description, "")
        ctx.metadata["sections"] = []
        ctx.metadata["imports"] = {"count": 0, "items": [], "truncated": False}
        ctx.metadata["symbols"] = {"count": 0, "items": [], "truncated": False}

    ctx.metadata["strings"] = extract_ascii_strings(binary)


def file_size_hash_entropy(path: Path) -> tuple[int, str, float]:
    sha256 = hashlib.sha256()
    counts = [0] * 256
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
            size += len(chunk)
            for byte in chunk:
                counts[byte] += 1

    if size == 0:
        return 0, sha256.hexdigest(), 0.0

    entropy = 0.0
    for count in counts:
        if count:
            probability = count / size
            entropy -= probability * math.log2(probability)
    return size, sha256.hexdigest(), round(entropy, 4)


def parse_architecture(file_description: str, objdump_header: str) -> dict[str, str]:
    data: dict[str, str] = {}
    if file_description:
        data["file"] = file_description
    match = re.search(r"architecture:\s*([^,\n]+)", objdump_header)
    if match:
        data["objdump"] = match.group(1).strip()
    match = re.search(r"file format\s+(\S+)", objdump_header)
    if match:
        data["format"] = match.group(1).strip()
    return data


def collect_sections(ctx: Context, binary: Path) -> list[dict[str, object]]:
    result = capture_tool(ctx, "objdump-sections", ["objdump", "-h", str(binary)])
    if not result or result.returncode != 0:
        return []

    sections = []
    section_re = re.compile(
        r"^\s*(\d+)\s+(\S+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+(.+)$"
    )
    for line in result.stdout.splitlines():
        match = section_re.match(line)
        if not match:
            continue
        index, name, size, vma, lma, file_offset, align = match.groups()
        sections.append(
            {
                "index": int(index),
                "name": name,
                "size": int(size, 16),
                "vma": "0x" + vma,
                "lma": "0x" + lma,
                "file_offset": "0x" + file_offset,
                "alignment": align.strip(),
            }
        )
    return sections


def collect_imports(ctx: Context, binary: Path) -> dict[str, object]:
    imports: dict[str, object] = {"count": 0, "items": []}
    items: list[str] = []

    readelf = which("readelf")
    if readelf:
        result = capture_tool(ctx, "readelf-symbols", [readelf, "-Ws", str(binary)])
        if result and result.returncode == 0:
            for line in result.stdout.splitlines():
                if " UND " not in line:
                    continue
                name_part = line.split(" UND ", 1)[1].strip().split()
                if name_part:
                    name = name_part[0].split("@", 1)[0]
                    if name and name not in {"UND", "0"}:
                        items.append(name)

    objdump = which("objdump")
    if objdump:
        result = capture_tool(ctx, "objdump-private-headers", [objdump, "-p", str(binary)])
        if result and result.returncode == 0:
            current_dll = None
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("DLL Name:"):
                    current_dll = stripped.split(":", 1)[1].strip()
                    items.append(current_dll)
                elif current_dll and re.match(r"^[0-9a-fA-F]+\s+[0-9]+\s+\S+", stripped):
                    items.append(f"{current_dll}:{stripped.split()[-1]}")

    unique = sorted(set(items))
    imports["count"] = len(unique)
    imports["items"] = unique[:200]
    imports["truncated"] = len(unique) > 200
    return imports


def collect_symbols(ctx: Context, binary: Path) -> dict[str, object]:
    symbols: list[str] = []
    readelf = which("readelf")
    if readelf:
        result = capture_tool(ctx, "readelf-defined-symbols", [readelf, "-Ws", str(binary)])
        if result and result.returncode == 0:
            for line in result.stdout.splitlines():
                match = re.match(r"\s*\d+:\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s*(.*)$", line)
                if not match:
                    continue
                ndx, rest = match.groups()
                if ndx == "UND":
                    continue
                fields = rest.split()
                if fields:
                    symbols.append(fields[0].split("@", 1)[0])

    nm = which("nm")
    if nm and not symbols:
        result = capture_tool(ctx, "nm-symbols", [nm, "-an", str(binary)])
        if result and result.returncode == 0:
            symbols.extend(parse_symbol_lines(result.stdout))

    if not symbols:
        objdump = which("objdump")
        if objdump:
            result = capture_tool(ctx, "objdump-symbols", [objdump, "-t", str(binary)])
            if result and result.returncode == 0:
                symbols.extend(parse_symbol_lines(result.stdout))

    unique = sorted(set(symbols))
    return {"count": len(unique), "items": unique[:200], "truncated": len(unique) > 200}


def parse_symbol_lines(text: str) -> list[str]:
    symbols = []
    for line in text.splitlines():
        if "SYMBOL TABLE" in line or "no symbols" in line or "file format" in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[-1]
        if not name or name in {"*ABS*", "*UND*", ".text", ".data", ".bss"}:
            continue
        if re.fullmatch(r"[0-9A-Fa-f]+", name):
            continue
        symbols.append(name)
    return symbols


def extract_ascii_strings(path: Path, min_length: int = 4, limit: int = 200, max_scan: int = 50 * 1024 * 1024) -> dict[str, object]:
    sample = []
    count = 0
    current = bytearray()
    scanned = 0

    def flush() -> None:
        nonlocal count, current
        if len(current) >= min_length:
            count += 1
            if len(sample) < limit:
                sample.append(current.decode("ascii", errors="replace"))
        current = bytearray()

    with path.open("rb") as fh:
        while scanned < max_scan:
            chunk = fh.read(min(1024 * 1024, max_scan - scanned))
            if not chunk:
                break
            scanned += len(chunk)
            for byte in chunk:
                if 32 <= byte <= 126:
                    current.append(byte)
                else:
                    flush()
        flush()

    return {"count": count, "items": sample, "truncated": len(sample) < count or path.stat().st_size > scanned}


def isolated_tool_env(home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_CACHE_HOME"] = str(home / ".cache")
    env["XDG_DATA_HOME"] = str(home / ".local" / "share")
    env["DOTNET_CLI_HOME"] = str(home / ".dotnet")
    for key in ["XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "DOTNET_CLI_HOME"]:
        Path(env[key]).mkdir(parents=True, exist_ok=True)
    return env


def detect_kind(path: Path) -> str:
    if path.is_dir():
        if path.suffix.lower() == ".app":
            return "app-bundle"
        return "directory"

    suffix = path.suffix.lower()
    data = read_prefix(path, 8192)

    if suffix == ".dex" or data.startswith(b"dex\n"):
        return "dex"
    if suffix in {".class"} and data.startswith(b"\xca\xfe\xba\xbe"):
        return "class"

    if zipfile.is_zipfile(path):
        return detect_zip_kind(path, suffix)

    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ"):
        if contains_dotnet_metadata(path):
            return "dotnet"
        return "pe"
    if is_macho_magic(data[:4]):
        return "macho"

    if suffix in {".exe", ".dll", ".sys"}:
        return "pe"
    if suffix in {".so", ".o", ".bin", ".out"}:
        return "native-unknown"

    return "unknown"


def contains_dotnet_metadata(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"BSJB" in fh.read(8 * 1024 * 1024)
    except OSError:
        return False


def detect_zip_kind(path: Path, suffix: str) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            name_set = set(names)
            lower_names = [n.lower() for n in names]
            if suffix == ".ipa" or any(n.startswith("Payload/") and ".app/" in n for n in names):
                return "ipa"
            if suffix == ".apk" or ("AndroidManifest.xml" in name_set and any(n.startswith("classes") and n.endswith(".dex") for n in names)):
                return "apk"
            if suffix == ".aab" or any(n.endswith("/manifest/AndroidManifest.xml") for n in names):
                return "aab"
            if suffix in {".jar", ".war", ".ear"} or any(n.endswith(".class") for n in lower_names):
                return "jar"
    except zipfile.BadZipFile:
        return "unknown"
    return "archive"


def read_prefix(path: Path, size: int) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def is_macho_magic(magic: bytes) -> bool:
    return magic in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    }


def find_analyze_headless() -> Path:
    env_path = os.environ.get("GHIDRA_ANALYZE_HEADLESS")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        raise DecompileError(f"GHIDRA_ANALYZE_HEADLESS is not executable: {candidate}")

    from_path = which("analyzeHeadless")
    if from_path:
        return Path(from_path)

    for root in [Path("/usr/share/ghidra"), Path("/opt")]:
        if not root.exists():
            continue
        for current, _, files in os.walk(root):
            if "analyzeHeadless" in files:
                candidate = Path(current) / "analyzeHeadless"
                if os.access(candidate, os.X_OK):
                    return candidate
    raise DecompileError("analyzeHeadless not found. Install Ghidra or set GHIDRA_ANALYZE_HEADLESS.")


def reverse_native(ctx: Context, binary: Path, output_base: str) -> None:
    dump_script = find_resource(ctx, "DumpAllDecompile.java")
    analyze = find_analyze_headless()

    project_dir = Path(tempfile.mkdtemp(prefix="ghidra-project."))
    try:
        status("running Ghidra headless analysis")
        with tempfile.TemporaryDirectory(prefix="decompile-home.") as home:
            result = run(
                [
                    str(analyze),
                    str(project_dir),
                    "reverse_project",
                    "-import",
                    str(binary),
                    "-scriptPath",
                    str(dump_script.parent),
                    "-postScript",
                    dump_script.name,
                    str(ctx.output_dir),
                    output_base,
                    str(ctx.timeout),
                    "-deleteProject",
                ],
                env=isolated_tool_env(Path(home)),
                status_message="running Ghidra headless analysis",
            )
            record_tool(ctx, "ghidra", result)
    finally:
        shutil.rmtree(project_dir, ignore_errors=True)

    require_file(ctx.output_dir / f"{output_base}.pseudocode.c")
    require_file(ctx.output_dir / f"{output_base}.disassembly.asm")
    require_file(ctx.output_dir / f"{output_base}.summary.txt")

    objdump_path = ctx.output_dir / f"{output_base}.objdump.txt"
    objdump_err = ctx.output_dir / f"{output_base}.objdump.err"
    result = generate_objdump(binary, objdump_path, objdump_err)
    if result:
        record_tool(ctx, "objdump", result)
    run_enhancer(ctx, binary, output_base)

    canonicalize_native_outputs(ctx, output_base)


def generate_objdump(binary: Path, output: Path, error_output: Path) -> subprocess.CompletedProcess | None:
    objdump = which("objdump")
    if not objdump:
        output.write_text("objdump not found\n")
        return None
    with output.open("wb") as stdout, error_output.open("wb") as stderr:
        return subprocess.run([objdump, "-d", "-Mintel", "-s", str(binary)], stdout=stdout, stderr=stderr, check=False)


def run_enhancer(ctx: Context, binary: Path, output_base: str) -> None:
    if os.environ.get("DECOMPILE_NO_AI") == "1" or os.environ.get("DECOMPILE_AI_CONFIRMED") != "1":
        status("static decompile complete; AI reconstruction deferred")
        safe_unlink(ctx.output_dir / f"{output_base}.enhanced.c")
        safe_unlink(ctx.output_dir / f"{output_base}.report.md")
        safe_unlink(ctx.output_dir / "enhanced.c")
        safe_unlink(ctx.output_dir / "report.md")
        reason = "DECOMPILE_NO_AI=1" if os.environ.get("DECOMPILE_NO_AI") == "1" else "waiting for user confirmation"
        ctx.tool_statuses.append({"name": "enhancer", "status": "skipped", "reason": reason})
        return

    enhancer = find_resource(ctx, "enhance_with_copilot")
    if not os.access(enhancer, os.X_OK):
        raise DecompileError(f"enhancer is not executable: {enhancer}")
    result = run([str(enhancer), str(binary), str(ctx.output_dir), output_base], status_message="running AI reconstruction")
    record_tool(ctx, "enhancer", result)


def reverse_android(ctx: Context, kind: str) -> None:
    summary = summary_path(ctx)
    write_summary_header(summary, ctx, kind)

    source_dir = ctx.output_dir / "source"
    source_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="decompile-home.") as home:
        tool_env = isolated_tool_env(Path(home))
        jadx = which("jadx")
        if jadx:
            args = [jadx, "-d", str(source_dir)]
            extra = os.environ.get("DECOMPILE_JADX_ARGS", "").strip()
            if extra:
                args.extend(extra.split())
            args.append(str(ctx.input_path))
            result = run(args, check=False, env=tool_env)
            record_tool(ctx, "jadx", result)
            append_summary(summary, f"JADX exit code       : {result.returncode}")
        else:
            append_summary(summary, "JADX               : missing; install jadx for Android/Java source output")

        if kind == "apk":
            apktool = which("apktool")
            if apktool:
                resources_dir = ctx.output_dir / "resources"
                with tempfile.TemporaryDirectory(prefix="apktool-framework.") as frame_dir:
                    result = run([apktool, "d", "-f", "-p", frame_dir, "-o", str(resources_dir), str(ctx.input_path)], check=False, env=tool_env)
                record_tool(ctx, "apktool", result)
                append_summary(summary, f"apktool exit code    : {result.returncode}")
            else:
                append_summary(summary, "apktool            : missing; resources were not decoded")

    write_android_summary(summary, ctx, source_dir)


def reverse_java(ctx: Context, kind: str) -> None:
    summary = summary_path(ctx)
    write_summary_header(summary, ctx, kind)

    source_dir = ctx.output_dir / "source"
    source_dir.mkdir(exist_ok=True)
    jadx = which("jadx")
    if not jadx:
        append_summary(summary, "JADX               : missing; install jadx for Java archive decompilation")
        raise DecompileError("jadx not found; cannot decompile Java/Dex input")

    with tempfile.TemporaryDirectory(prefix="decompile-home.") as home:
        result = run([jadx, "-d", str(source_dir), str(ctx.input_path)], check=False, env=isolated_tool_env(Path(home)))
    record_tool(ctx, "jadx", result)
    append_summary(summary, f"JADX exit code       : {result.returncode}")
    write_android_summary(summary, ctx, source_dir)


def reverse_dotnet(ctx: Context) -> None:
    ilspy = which("ilspycmd")
    if not ilspy:
        status("detected .NET metadata, but ilspycmd is missing; falling back to native analysis")
        reverse_native(ctx, ctx.input_path, ctx.base_name)
        summary = summary_path(ctx)
        append_summary(summary, "Detected .NET       : yes")
        append_summary(summary, "ilspycmd            : missing; used native fallback")
        return

    summary = summary_path(ctx)
    write_summary_header(summary, ctx, "dotnet")
    source_dir = ctx.output_dir / "source"
    source_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="decompile-home.") as home:
        result = run([ilspy, "-p", "-o", str(source_dir), str(ctx.input_path)], check=False, env=isolated_tool_env(Path(home)))
    record_tool(ctx, "ilspycmd", result)
    append_summary(summary, f"ilspycmd exit code  : {result.returncode}")
    append_summary(summary, f"C# source directory : {source_dir}")
    append_summary(summary, f"C# files            : {count_files(source_dir, {'.cs'})}")


def reverse_ipa(ctx: Context) -> None:
    summary = summary_path(ctx)
    with tempfile.TemporaryDirectory(prefix="decompile-ipa.") as tmp:
        tmp_path = Path(tmp)
        executable, app_name, info = extract_ipa_executable(ctx.input_path, tmp_path)
        if info:
            ios_dir = ctx.output_dir / "ios"
            ios_dir.mkdir(exist_ok=True)
            with (ios_dir / "Info.plist").open("wb") as fh:
                plistlib.dump(info, fh)

        reverse_native(ctx, executable, ctx.base_name)
        append_summary(summary, "")
        append_summary(summary, "Container            : IPA")
        append_summary(summary, f"App bundle           : {app_name}")
        append_summary(summary, f"Extracted executable : {executable.name}")


def reverse_app_bundle(ctx: Context) -> None:
    executable, info = find_app_bundle_executable(ctx.input_path)
    if info:
        ios_dir = ctx.output_dir / "app"
        ios_dir.mkdir(exist_ok=True)
        with (ios_dir / "Info.plist").open("wb") as fh:
            plistlib.dump(info, fh)
    reverse_native(ctx, executable, ctx.base_name)
    append_summary(summary_path(ctx), f"App executable       : {executable}")


def extract_ipa_executable(ipa: Path, tmp_path: Path) -> tuple[Path, str, dict | None]:
    with zipfile.ZipFile(ipa) as archive:
        names = archive.namelist()
        app_roots = sorted({n.split("/", 2)[1] for n in names if n.startswith("Payload/") and ".app/" in n})
        if not app_roots:
            raise DecompileError("IPA does not contain Payload/*.app")

        app_name = app_roots[0]
        info_path = f"Payload/{app_name}/Info.plist"
        info = None
        executable_name = None
        if info_path in names:
            info = plistlib.loads(archive.read(info_path))
            executable_name = info.get("CFBundleExecutable")

        executable_member = f"Payload/{app_name}/{executable_name}" if executable_name else None
        if executable_member not in names:
            executable_member = find_macho_member(archive, names, f"Payload/{app_name}/")
        if not executable_member:
            raise DecompileError("could not find Mach-O executable inside IPA")

        extracted = tmp_path / Path(executable_member).name
        extracted.write_bytes(archive.read(executable_member))
        extracted.chmod(0o755)
        return extracted, app_name, info


def find_macho_member(archive: zipfile.ZipFile, names: list[str], prefix: str) -> str | None:
    for name in names:
        if not name.startswith(prefix) or name.endswith("/") or "/" in name[len(prefix):]:
            continue
        try:
            if is_macho_magic(archive.read(name)[:4]):
                return name
        except KeyError:
            continue
    return None


def find_app_bundle_executable(bundle: Path) -> tuple[Path, dict | None]:
    info = None
    info_path = bundle / "Info.plist"
    if not info_path.exists():
        info_path = bundle / "Contents" / "Info.plist"
    if info_path.exists():
        info = plistlib.loads(info_path.read_bytes())
        executable_name = info.get("CFBundleExecutable")
        if executable_name:
            for candidate in [bundle / executable_name, bundle / "Contents" / "MacOS" / executable_name]:
                if candidate.exists():
                    return candidate, info

    for candidate in bundle.iterdir():
        if candidate.is_file() and is_macho_magic(read_prefix(candidate, 4)):
            return candidate, info
    macos_dir = bundle / "Contents" / "MacOS"
    if macos_dir.exists():
        for candidate in macos_dir.iterdir():
            if candidate.is_file() and is_macho_magic(read_prefix(candidate, 4)):
                return candidate, info
    raise DecompileError(f"could not find app executable in {bundle}")


def write_summary_header(summary: Path, ctx: Context, kind: str) -> None:
    summary.write_text(
        "\n".join(
            [
                "REVERSE EXTRACTION SUMMARY",
                "=" * 100,
                f"Input      : {ctx.input_path}",
                f"Type       : {kind}",
                f"Output dir : {ctx.output_dir}",
                "=" * 100,
                "",
            ]
        )
    )


def write_android_summary(summary: Path, ctx: Context, source_dir: Path) -> None:
    java_count = count_files(source_dir, {".java"})
    kt_count = count_files(source_dir, {".kt"})
    smali_count = count_files(ctx.output_dir / "resources", {".smali"})
    append_summary(summary, f"Source directory     : {source_dir}")
    append_summary(summary, f"Java files           : {java_count}")
    append_summary(summary, f"Kotlin files         : {kt_count}")
    if (ctx.output_dir / "resources").exists():
        append_summary(summary, f"Resources directory  : {ctx.output_dir / 'resources'}")
        append_summary(summary, f"Smali files          : {smali_count}")


def count_files(root: Path, suffixes: set[str]) -> int:
    if not root.exists():
        return 0
    return sum(1 for p in root.rglob("*") if p.is_file() and p.suffix.lower() in suffixes)


def append_summary(summary: Path, line: str) -> None:
    with summary.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def require_file(path: Path) -> None:
    if not path.is_file():
        raise DecompileError(f"expected output was not created: {path}")


def safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def move_generated_file(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    src.replace(dst)


def canonicalize_native_outputs(ctx: Context, output_base: str) -> None:
    move_generated_file(ctx.output_dir / f"{output_base}.pseudocode.c", ctx.output_dir / "pseudocode.c")
    move_generated_file(ctx.output_dir / f"{output_base}.disassembly.asm", ctx.output_dir / "disassembly.asm")
    move_generated_file(ctx.output_dir / f"{output_base}.enhanced.c", ctx.output_dir / "enhanced.c")
    move_generated_file(ctx.output_dir / f"{output_base}.report.md", ctx.output_dir / "report.md")
    move_generated_file(ctx.output_dir / f"{output_base}.summary.txt", summary_path(ctx))

    debug_files = {
        f"{output_base}.objdump.txt": "objdump.txt",
        f"{output_base}.objdump.err": "objdump.err",
        f"{output_base}.enhanced.raw.jsonl": "enhanced.raw.jsonl",
        f"{output_base}.enhanced.response.txt": "enhanced.response.txt",
        f"{output_base}.report.raw.jsonl": "report.raw.jsonl",
        f"{output_base}.report.response.md": "report.response.md",
        f"{output_base}.enhanced.syntax.log": "enhanced.syntax.log",
        f"{output_base}.enhance.prompt.txt": "enhance.prompt.txt",
        f"{output_base}.report.prompt.txt": "report.prompt.txt",
        f"{output_base}.enhance.fix.prompt.txt": "enhance.fix.prompt.txt",
        f"{output_base}.enhanced.fix.raw.jsonl": "enhanced.fix.raw.jsonl",
        f"{output_base}.enhanced.fix.response.txt": "enhanced.fix.response.txt",
    }

    if ctx.keep_debug:
        debug_dir = ctx.output_dir / "debug"
        for source_name, target_name in debug_files.items():
            move_generated_file(ctx.output_dir / source_name, debug_dir / target_name)
    else:
        for source_name in debug_files:
            safe_unlink(ctx.output_dir / source_name)

    for leftover in ctx.output_dir.glob(f"{output_base}.*"):
        if leftover.is_file():
            safe_unlink(leftover)


def finalize_outputs(ctx: Context, kind: str) -> None:
    summary = summary_path(ctx)
    existing_summary = summary.read_text(encoding="utf-8", errors="replace") if summary.exists() else ""
    write_final_summary(ctx, kind, existing_summary)
    ctx.metadata["tool_statuses"] = ctx.tool_statuses
    for _ in range(3):
        write_metadata(ctx)
        refresh_summary_output_section_file(ctx.output_dir)
    write_metadata(ctx)


def write_metadata(ctx: Context) -> None:
    ctx.metadata["outputs"] = output_manifest(ctx)
    metadata_path(ctx).write_text(json.dumps(ctx.metadata, indent=2, sort_keys=True), encoding="utf-8")


def output_manifest(ctx: Context) -> list[dict[str, object]]:
    return build_output_manifest(ctx.output_dir)


def build_output_manifest(output_dir: Path) -> list[dict[str, object]]:
    outputs = []
    if not output_dir.exists():
        return outputs
    for child in sorted(output_dir.iterdir()):
        if child.is_file():
            outputs.append({"path": child.name, "type": "file", "size": child.stat().st_size})
        elif child.is_dir():
            outputs.append({"path": child.name + "/", "type": "directory", "files": count_all_files(child)})
    return outputs


def format_output_manifest(output_dir: Path) -> list[str]:
    lines = []
    for item in build_output_manifest(output_dir):
        if item["type"] == "file":
            lines.append(f"{item['path']:<24} file      {item['size']} bytes")
        else:
            lines.append(f"{item['path']:<24} directory {item['files']} files")
    return lines or ["No outputs created."]


def count_all_files(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(1 for path in root.rglob("*") if path.is_file())


def write_final_summary(ctx: Context, kind: str, existing_summary: str) -> None:
    input_info = ctx.metadata.get("input", {})
    architecture = ctx.metadata.get("architecture", {})
    sections = ctx.metadata.get("sections", [])
    imports = ctx.metadata.get("imports", {})
    symbols = ctx.metadata.get("symbols", {})
    strings = ctx.metadata.get("strings", {})

    lines = [
        "DECOMPILE SUMMARY",
        "=" * 80,
        f"Input              : {ctx.input_path}",
        f"Type               : {kind}",
        f"Output dir         : {ctx.output_dir}",
    ]

    if isinstance(input_info, dict):
        if "size" in input_info:
            lines.append(f"Size               : {input_info['size']} bytes")
        if "sha256" in input_info:
            lines.append(f"SHA256             : {input_info['sha256']}")
        if "entropy" in input_info:
            lines.append(f"Entropy            : {input_info['entropy']} bits/byte")

    if isinstance(architecture, dict) and architecture:
        if architecture.get("file"):
            lines.append(f"File type          : {architecture['file']}")
        if architecture.get("objdump"):
            lines.append(f"Architecture       : {architecture['objdump']}")
        if architecture.get("format"):
            lines.append(f"Object format      : {architecture['format']}")

    lines.extend(
        [
            "",
            "OUTPUTS",
            "-" * 80,
        ]
    )
    lines.extend(format_output_manifest(ctx.output_dir))

    lines.extend(["", "TOOL STATUS", "-" * 80])
    if ctx.tool_statuses:
        for entry in ctx.tool_statuses:
            status = entry.get("status", "unknown")
            detail = f"exit={entry.get('exit_code')}" if "exit_code" in entry else str(entry.get("reason", ""))
            lines.append(f"{entry.get('name', 'tool'):<24} {status:<8} {detail}")
    else:
        lines.append("No external tool status recorded.")

    lines.extend(["", "SECTIONS", "-" * 80])
    if isinstance(sections, list) and sections:
        for section in sections[:80]:
            if not isinstance(section, dict):
                continue
            lines.append(
                f"{section.get('name', ''):<20} size={section.get('size', ''):<10} "
                f"vma={section.get('vma', ''):<14} file_offset={section.get('file_offset', '')}"
            )
        if len(sections) > 80:
            lines.append(f"... {len(sections) - 80} more sections")
    else:
        lines.append("No section table available.")

    append_counted_items(lines, "IMPORTS", imports)
    append_counted_items(lines, "SYMBOLS", symbols)
    append_counted_items(lines, "STRINGS", strings)

    cleaned_existing = existing_summary.strip()
    if cleaned_existing:
        lines.extend(["", "DECOMPILER DETAILS", "-" * 80, cleaned_existing])

    summary_path(ctx).write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_counted_items(lines: list[str], title: str, data: object) -> None:
    lines.extend(["", title, "-" * 80])
    if not isinstance(data, dict):
        lines.append("Not available.")
        return
    count = data.get("count", 0)
    lines.append(f"Count: {count}")
    items = data.get("items", [])
    if isinstance(items, list) and items:
        for item in items[:80]:
            lines.append(f"  {item}")
        if data.get("truncated") or len(items) > 80:
            lines.append("  ... truncated")
    else:
        lines.append("  none")


def confirm_ai_enhancement(output_dir: Path) -> bool:
    if os.environ.get("DECOMPILE_AI_CONFIRMED") == "1":
        status("starting AI reconstruction")
        return True
    if os.environ.get("DECOMPILE_NO_AI") == "1":
        return False

    STATUS.stop(f"{green(symbol('ok'))} {bold('decompile completed')} {dim(str(output_dir))}")
    if not sys.stdin.isatty():
        print(f"{dim('AI skipped: stdin is not interactive. Rerun with --ai to continue automatically.')}")
        return False

    prompt = f"{green(symbol('question'))} {bold('Continue with AI reconstruction and report.md?')} {dim('Yes /')} {cyan('No')} "
    answer = input(prompt).strip().lower()
    accepted = answer in {"y", "yes"}
    if accepted:
        print(f"{green(symbol('ok'))} AI reconstruction: {green('Yes')}")
    else:
        print(f"{dim('AI reconstruction: No')}")
    return accepted


def print_completed(output_dir: Path, *, ai_ran: bool = False) -> None:
    suffix = " with AI" if ai_ran else ""
    status_done(f"{green(symbol('ok'))} {bold('decompile completed' + suffix)} {dim(str(output_dir))}")
    print_output_manifest_line(output_dir)
    open_output_dir(output_dir)


def print_output_manifest_line(output_dir: Path) -> None:
    items = build_output_manifest(output_dir)
    if not items:
        return
    print_tree(output_dir, items)


def print_tree(output_dir: Path, items: list[dict[str, object]]) -> None:
    print(f"{dim('Output tree:')}")
    print(f"{symbol('folder')} {bold(output_dir.name + '/')}")

    groups: list[tuple[str, list[str]]] = [
        ("core", ["summary.txt", "metadata.json"]),
        ("native", ["disassembly.asm", "pseudocode.c", "enhanced.c"]),
        ("ai", ["report.md"]),
        ("source", ["source/", "resources/", "ios/", "app/"]),
        ("debug", ["debug/"]),
    ]
    available = {str(item.get("path")): item for item in items if isinstance(item.get("path"), str)}
    used: set[str] = set()
    rendered_groups: list[tuple[str, list[dict[str, object]]]] = []

    for title, names in groups:
        group_items = []
        for name in names:
            item = available.get(name)
            if item:
                used.add(name)
                group_items.append(item)
        if group_items:
            rendered_groups.append((title, group_items))

    other_items = [item for name, item in sorted(available.items()) if name not in used]
    if other_items:
        rendered_groups.append(("other", other_items))

    for group_index, (title, group_items) in enumerate(rendered_groups):
        group_last = group_index == len(rendered_groups) - 1
        group_branch = tree_last() if group_last else tree_mid()
        group_prefix = "   " if group_last else tree_pipe()
        print(f"{group_branch} {cyan(title)}/")
        for item_index, item in enumerate(group_items):
            item_last = item_index == len(group_items) - 1
            item_branch = tree_last() if item_last else tree_mid()
            path = str(item.get("path"))
            detail = output_item_detail(item)
            print(f"{group_prefix}{item_branch} {path} {dim(detail)}")


def output_item_detail(item: dict[str, object]) -> str:
    if item.get("type") == "file":
        size = item.get("size")
        return f"{size} bytes" if isinstance(size, int) else "file"
    files = item.get("files")
    return f"{files} files" if isinstance(files, int) else "directory"


def open_output_dir(output_dir: Path) -> None:
    if os.environ.get("DECOMPILE_NO_OPEN") == "1":
        return
    if os.environ.get("DECOMPILE_IN_DOCKER") == "1":
        return
    if not sys.stdout.isatty():
        return

    for editor in ["zed", "code", "nvim"]:
        executable = which(editor)
        if not executable:
            continue
        if editor == "nvim":
            print(f"{green(symbol('ok'))} opening {dim(str(output_dir))} in {cyan(editor)}")
            subprocess.run([executable, str(output_dir)])
            return
        try:
            subprocess.Popen(
                [executable, str(output_dir)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            continue
        print(f"{green(symbol('ok'))} opened {dim(str(output_dir))} in {cyan(editor)}")
        return

    print(f"{dim('No editor found: install zed, code, or nvim; or open the output directory manually.')}")


def print_outputs(ctx: Context) -> None:
    print_completed(ctx.output_dir, ai_ran=(ctx.output_dir / "report.md").exists())


if __name__ == "__main__":
    sys.exit(main())
