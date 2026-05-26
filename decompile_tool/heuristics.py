from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


HEADER_RE = re.compile(
    r"=+\nFUNCTION:\s*(?P<name>\S+)\nADDRESS\s*:\s*(?P<address>[0-9A-Fa-f]+)\n=+\n",
    re.MULTILINE,
)
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*|FUN_[0-9A-Fa-f]+)\s*\(")
DAT_RE = re.compile(r"\bDAT_([0-9A-Fa-f]+)\b")
HEX_RE = re.compile(r"\b0x[0-9A-Fa-f]+\b")
STRING_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')

RUNTIME_NAMES = {
    "_DT_INIT",
    "_DT_FINI",
    "_INIT_0",
    "_FINI_0",
    "__cxa_finalize",
    "__stack_chk_fail",
    "__libc_start_main",
    "__gmon_start__",
    "__printf_chk",
    "__isoc99_scanf",
    "puts",
    "printf",
    "scanf",
    "strcmp",
    "strncmp",
    "strlen",
    "exit",
    "malloc",
    "free",
    "memcpy",
    "memset",
}

NOISE_PREFIXES = ("_DT_", "_INIT", "_FINI")


@dataclass
class FunctionInfo:
    name: str
    address: str
    body: str
    calls: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    constants: list[str] = field(default_factory=list)
    data_refs: list[str] = field(default_factory=list)
    suggested_name: str = ""
    role: str = "unknown"
    confidence: float = 0.0
    noise: bool = False
    reasons: list[str] = field(default_factory=list)


def run_heuristic_analysis(
    *,
    output_dir: Path,
    base_name: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    pseudocode = first_existing(output_dir / f"{base_name}.pseudocode.c", output_dir / "pseudocode.c")
    disassembly = first_existing(output_dir / f"{base_name}.disassembly.asm", output_dir / "disassembly.asm")
    objdump = first_existing(output_dir / f"{base_name}.objdump.txt", output_dir / "debug" / "objdump.txt")

    functions = parse_pseudocode(pseudocode)
    classify_functions(functions)
    main_name = find_main_function(functions)
    if main_name and main_name in functions:
        apply_name(functions[main_name], "main", "program entry from __libc_start_main/call graph", 0.95)
    rodata = parse_objdump_bytes(objdump)
    image_base = parse_image_base(pseudocode)
    data_values = resolve_data_refs(functions, rodata, image_base=image_base)

    logic = build_logic(functions, data_values, metadata)
    write_json(output_dir / f"{base_name}.logic.json", logic)
    write_ai_context(output_dir / f"{base_name}.ai_context.md", functions, logic, data_values, metadata)
    write_enhanced_c(output_dir / f"{base_name}.enhanced.c", functions, logic, data_values)
    write_report(output_dir / f"{base_name}.report.md", functions, logic, data_values, metadata, disassembly)
    return logic


def first_existing(*paths: Path) -> Path:
    for path in paths:
        if path.exists():
            return path
    return paths[0]


def parse_pseudocode(path: Path) -> dict[str, FunctionInfo]:
    text = path.read_text(encoding="utf-8", errors="replace")
    matches = list(HEADER_RE.finditer(text))
    functions: dict[str, FunctionInfo] = {}
    for index, match in enumerate(matches):
        body_start = match.end()
        body_end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[body_start:body_end].strip()
        name = match.group("name")
        info = FunctionInfo(name=name, address=match.group("address"), body=body)
        info.calls = unique(CALL_RE.findall(body))
        info.strings = unique(unescape_string(s) for s in STRING_RE.findall(body))
        info.constants = unique(HEX_RE.findall(body))
        info.data_refs = unique("DAT_" + value for value in DAT_RE.findall(body))
        functions[name] = info
    return functions


def parse_image_base(path: Path) -> int | None:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")[:2000]
    match = re.search(r"ImageBase:\s*([0-9A-Fa-fx]+)", text)
    if not match:
        return None
    value = match.group(1)
    try:
        return int(value, 16)
    except ValueError:
        return None


def classify_functions(functions: dict[str, FunctionInfo]) -> None:
    for info in functions.values():
        body = info.body
        calls = set(info.calls)
        strings = " ".join(info.strings).lower()

        if is_runtime_noise(info):
            mark_noise(info, "runtime/import/thunk noise")
            continue

        if "[debug]" in strings:
            apply_name(info, "print_debug_info", "prints debug strings", 0.9)
            continue

        if is_fake_flag_printer(info):
            apply_name(info, "print_fake_flag", "prints fake flag string", 0.95)
            continue

        if is_xor_decode(info):
            apply_name(info, "xor_decode", "byte loop xor-decodes input into output buffer", 0.9)
            continue

        if looks_like_binary_name_check(info):
            apply_name(info, "check_binary_name", "validates executable basename and exits on mismatch", 0.88)
            continue

        if looks_like_magic_checker(info):
            apply_name(info, "check_magic_and_print_flag", "compares input constant and prints flag/fake flag", 0.9)
            continue

        if is_arithmetic_helper(info):
            apply_name(info, "transform_number", "small arithmetic transform helper", 0.72)
            continue

        if calls & {"__isoc99_scanf", "scanf"} and any("printf" in call for call in calls):
            apply_name(info, "main", "reads user input and dispatches checks", 0.82)
            continue

        if len(body.splitlines()) <= 4 and "return;" in body:
            mark_noise(info, "empty or compiler-generated function")


def find_main_function(functions: dict[str, FunctionInfo]) -> str | None:
    for info in functions.values():
        match = re.search(r"__libc_start_main\((FUN_[0-9A-Fa-f]+)", info.body)
        if match:
            return match.group(1)
    for info in functions.values():
        if info.suggested_name == "main":
            return info.name
    return None


def is_runtime_noise(info: FunctionInfo) -> bool:
    if info.name in RUNTIME_NAMES or info.name.startswith(NOISE_PREFIXES):
        return True
    if info.name == "entry":
        return True
    if info.name in info.calls and len(info.calls) <= 2:
        return True
    if re.search(r"\(\*\(code \*\).*0x0\)\(\)", info.body):
        return True
    return False


def mark_noise(info: FunctionInfo, reason: str) -> None:
    info.noise = True
    info.role = "noise"
    info.confidence = max(info.confidence, 0.8)
    info.reasons.append(reason)


def apply_name(info: FunctionInfo, name: str, reason: str, confidence: float) -> None:
    info.suggested_name = name
    info.role = "core_logic"
    info.confidence = max(info.confidence, confidence)
    info.reasons.append(reason)


def is_fake_flag_printer(info: FunctionInfo) -> bool:
    if len(info.strings) != 1:
        return False
    text = info.strings[0].lower()
    return ("flag" in text or "ctf{" in text) and ("puts" in info.calls or "__printf_chk" in info.calls)


def is_xor_decode(info: FunctionInfo) -> bool:
    body = info.body
    return (
        "^" in body
        and re.search(r"while\s*\([^)]*!=\s*0", body) is not None
        and re.search(r"\[[^\]]+\]\s*=", body) is not None
        and re.search(r"\*\w+\s*=\s*0", body) is not None
    )


def looks_like_magic_checker(info: FunctionInfo) -> bool:
    joined_strings = " ".join(info.strings).lower()
    has_magic_compare = bool(re.search(r"if\s*\([^)]*==\s*0x[0-9a-fA-F]+", info.body))
    has_flag_output = "flag" in joined_strings or "ctf{" in joined_strings or "FLAG:" in info.body
    return has_magic_compare and has_flag_output


def looks_like_binary_name_check(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    joined_strings = " ".join(info.strings).lower()
    if "strcmp" not in calls or "exit" not in calls:
        return False
    if "crackme" in joined_strings or "move along" in joined_strings or "nothing interesting" in joined_strings:
        return True
    compact = info.body.replace(" ", "")
    return "=='/'" in compact or "strrchr" in info.body


def is_arithmetic_helper(info: FunctionInfo) -> bool:
    body = strip_comments(info.body)
    return (
        len(body.splitlines()) <= 8
        and "return" in body
        and "*" in body
        and "+" in body
        and "^" in body
        and not info.calls
    )


def parse_objdump_bytes(path: Path) -> dict[int, int]:
    if not path.exists():
        return {}
    memory: dict[int, int] = {}
    line_re = re.compile(r"^\s*([0-9A-Fa-f]+)\s+((?:[0-9A-Fa-f]{2,8}\s+)+)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = line_re.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        offset = 0
        for group in match.group(2).split():
            if len(group) % 2 != 0:
                continue
            for index in range(0, len(group), 2):
                memory[address + offset] = int(group[index:index + 2], 16)
                offset += 1
    return memory


def resolve_data_refs(
    functions: dict[str, FunctionInfo],
    memory: dict[int, int],
    *,
    image_base: int | None = None,
) -> dict[str, dict[str, Any]]:
    refs = sorted({ref for info in functions.values() if info.role == "core_logic" for ref in info.data_refs})
    values: dict[str, dict[str, Any]] = {}
    for ref in refs:
        address = int(ref.split("_", 1)[1], 16)
        resolved_address, raw = read_data_ref(memory, address, image_base=image_base)
        item: dict[str, Any] = {"address": "0x" + ref.split("_", 1)[1], "bytes": raw[:256]}
        if resolved_address != address:
            item["resolved_address"] = f"0x{resolved_address:x}"
        if raw:
            ascii_text = bytes(raw).decode("ascii", errors="replace")
            if is_readable(ascii_text):
                item["ascii"] = ascii_text
            for key in likely_xor_keys(functions, ref):
                decoded = bytes(byte ^ key for byte in raw).decode("ascii", errors="replace")
                if is_readable(decoded):
                    item[f"xor_0x{key:02x}"] = decoded
            seed = find_xor_seed_for_ref(functions, ref)
            if seed is not None:
                seeded = [seed, *raw]
                item["seed_byte"] = seed
                for key in likely_xor_keys(functions, ref):
                    decoded = bytes(byte ^ key for byte in seeded).decode("ascii", errors="replace")
                    if is_readable(decoded):
                        item[f"seeded_xor_0x{key:02x}"] = decoded
        values[ref] = item
    return values


def read_data_ref(memory: dict[int, int], address: int, *, image_base: int | None) -> tuple[int, list[int]]:
    for candidate in data_address_candidates(address, image_base):
        raw = read_c_string_bytes(memory, candidate)
        if raw:
            return candidate, raw
    return address, []


def data_address_candidates(address: int, image_base: int | None) -> list[int]:
    candidates = [address]
    if image_base and address >= image_base:
        candidates.append(address - image_base)
    for base in (0x100000, 0x400000, 0x10000000, 0x140000000):
        if address >= base:
            candidates.append(address - base)
    if address > 0x100000:
        candidates.append(address & 0xFFFFF)
    return unique(candidates)


def find_xor_seed_for_ref(functions: dict[str, FunctionInfo], ref: str) -> int | None:
    for info in functions.values():
        if ref not in info.data_refs or "^" not in info.body:
            continue
        byte_vars = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9A-Fa-f]{1,2})\s*;", info.body)
        for variable, value in byte_vars:
            if re.search(rf"{re.escape(variable)}\s*\^\s*0x[0-9A-Fa-f]{{1,2}}", info.body):
                return int(value, 16)
    return None


def read_c_string_bytes(memory: dict[int, int], address: int, limit: int = 512) -> list[int]:
    out: list[int] = []
    for offset in range(limit):
        value = memory.get(address + offset)
        if value is None:
            break
        if value == 0:
            break
        out.append(value)
    return out


def likely_xor_keys(functions: dict[str, FunctionInfo], ref: str | None = None) -> list[int]:
    keys = set()
    for info in functions.values():
        if ref and ref not in info.data_refs:
            continue
        for constant in info.constants:
            value = int(constant, 16)
            if 0 < value <= 0xFF and "^" in info.body:
                keys.add(value)
    return sorted(keys)


def build_logic(functions: dict[str, FunctionInfo], data_values: dict[str, dict[str, Any]], metadata: dict[str, Any]) -> dict[str, Any]:
    function_items = []
    for info in sorted(functions.values(), key=lambda item: int(item.address, 16)):
        function_items.append(
            {
                "address": "0x" + info.address,
                "original_name": info.name,
                "suggested_name": info.suggested_name or info.name,
                "role": info.role,
                "confidence": round(info.confidence, 2),
                "noise": info.noise,
                "reasons": info.reasons,
                "calls": info.calls,
                "strings": info.strings,
                "constants": info.constants,
                "data_refs": info.data_refs,
            }
        )
    return {
        "schema": 1,
        "main": next((item for item in function_items if item["suggested_name"] == "main"), None),
        "core_functions": [item for item in function_items if item["role"] == "core_logic"],
        "noise_functions": [item for item in function_items if item["noise"]],
        "data_refs": data_values,
        "packer": metadata.get("packer", {}),
        "debug_symbols": metadata.get("debug_symbols", {}),
        "functions": function_items,
    }


def write_ai_context(
    path: Path,
    functions: dict[str, FunctionInfo],
    logic: dict[str, Any],
    data_values: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
) -> None:
    lines = ["# Offline Reverse-Engineering Context", ""]
    lines.append("## Core Functions")
    for item in logic["core_functions"]:
        lines.append(f"- `{item['original_name']}` at `{item['address']}` -> `{item['suggested_name']}` ({item['confidence']})")
        for reason in item["reasons"]:
            lines.append(f"  - {reason}")
        info = functions.get(str(item["original_name"]))
        if info:
            if info.strings:
                lines.append(f"  - strings: {', '.join(repr(s) for s in info.strings[:5])}")
            if info.constants:
                lines.append(f"  - constants: {', '.join(info.constants[:8])}")
            if info.data_refs:
                lines.append(f"  - data refs: {', '.join(info.data_refs)}")
    lines.extend(["", "## Resolved Data"])
    for ref, value in data_values.items():
        display = best_decoded_value(value)
        lines.append(f"- `{ref}`: {display!r} bytes={value.get('bytes', [])[:32]}")
    lines.extend(["", "## Packer / Debug Symbols"])
    lines.append(json.dumps({"packer": metadata.get("packer", {}), "debug_symbols": metadata.get("debug_symbols", {})}, indent=2))
    lines.extend(["", "## Selected Pseudocode"])
    for item in logic["core_functions"][:12]:
        info = functions.get(str(item["original_name"]))
        if info:
            lines.append(f"\n### {info.name} -> {item['suggested_name']}\n")
            lines.append("```c")
            lines.append(info.body[:6000])
            lines.append("```")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_enhanced_c(
    path: Path,
    functions: dict[str, FunctionInfo],
    logic: dict[str, Any],
    data_values: dict[str, dict[str, Any]],
) -> None:
    lines = [
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "#include <stdint.h>",
        "",
    ]
    prototypes = function_prototypes(logic)
    if prototypes:
        lines.extend(prototypes)
        lines.append("")
    for ref, value in data_values.items():
        bytes_value = value.get("bytes", [])
        if isinstance(bytes_value, list) and bytes_value:
            name = data_symbol_name(ref)
            joined = ", ".join(f"0x{int(byte) & 0xff:02x}" for byte in bytes_value[:256])
            lines.append(f"static const unsigned char {name}[] = {{{joined}, 0x00}};")
            decoded = best_decoded_value(value)
            if decoded:
                lines.append(f"static const char {name}_decoded[] = {json.dumps(decoded)};")
    if data_values:
        lines.append("")

    for item in logic["core_functions"]:
        info = functions.get(str(item["original_name"]))
        if not info:
            continue
        suggested = str(item["suggested_name"])
        body = rewrite_high_level_function(info, suggested, logic, data_values)
        if not body:
            body = rewrite_function_body(info, suggested, logic)
        lines.append(body.rstrip())
        lines.append("")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def rewrite_high_level_function(
    info: FunctionInfo,
    suggested_name: str,
    logic: dict[str, Any],
    data_values: dict[str, dict[str, Any]],
) -> str:
    if suggested_name == "main":
        prompt = next((s for s in info.strings if "enter" in s.lower() or "number" in s.lower()), "Enter value: ")
        checker = renamed_function_for_role(logic, "check_magic_and_print_flag") or "check_magic_and_print_flag"
        name_check = renamed_function_for_role(logic, "check_binary_name")
        if not name_check and not renamed_function_for_role(logic, "check_magic_and_print_flag"):
            return ""
        if "scanf" not in set(info.calls) and "__isoc99_scanf" not in set(info.calls):
            return ""
        lines = [
            "int main(int argc, char **argv)",
            "{",
            "    int input = 0;",
        ]
        if name_check:
            lines.append("    (void)argc;")
            lines.append(f"    {name_check}(argv[0]);")
        lines.extend(
            [
                f"    printf({json.dumps(prompt)});",
                '    scanf("%d", &input);',
                f"    {checker}(input);",
                "    return 0;",
                "}",
            ]
        )
        return "\n".join(lines)

    if suggested_name == "check_binary_name":
        expected = best_identifier_string(info.strings) or "crackme"
        reject = next((s for s in info.strings if "interesting" in s.lower() or "move" in s.lower()), "")
        lines = [
            "void check_binary_name(const char *path)",
            "{",
            '    const char *name = strrchr(path, \'/\');',
            "    name = name ? name + 1 : path;",
            f"    if (strcmp(name, {json.dumps(expected)}) != 0) {{",
        ]
        if reject:
            lines.append(f"        puts({json.dumps(reject)});")
        lines.extend(["        exit(0);", "    }", "}"])
        return "\n".join(lines)

    if suggested_name == "xor_decode":
        return "\n".join(
            [
                "void xor_decode(char *out, const unsigned char *input, unsigned char key)",
                "{",
                "    while (*input != 0) {",
                "        *out++ = (char)(*input++ ^ key);",
                "    }",
                "    *out = '\\0';",
                "}",
            ]
        )

    if suggested_name == "check_magic_and_print_flag":
        magic = first_hex_after(info.body, "==") or "0"
        decoded = first_decoded_for_refs(info.data_refs, data_values)
        decoded_expr = first_decoded_expr_for_refs(info.data_refs, data_values)
        fake_flag = best_fake_flag_string(info.strings)
        lines = [
            "void check_magic_and_print_flag(int input)",
            "{",
            f"    if (input == {magic}) {{",
        ]
        if decoded:
            lines.append(f"        printf(\"FLAG: %s\\n\", {decoded_expr or json.dumps(decoded)});")
        else:
            lines.append('        puts("FLAG: <decoded data unavailable>");')
        lines.append("        return;")
        lines.append("    }")
        if fake_flag:
            lines.append(f"    puts({json.dumps(fake_flag)});")
        lines.append("}")
        return "\n".join(lines)

    if suggested_name == "print_fake_flag":
        text = info.strings[0] if info.strings else ""
        return "\n".join(["void print_fake_flag(void)", "{", f"    puts({json.dumps(text)});", "}"])

    if suggested_name == "print_debug_info":
        lines = ["void print_debug_info(void)", "{"]
        for text in info.strings:
            if text:
                lines.append(f"    printf({json.dumps(text)});")
        lines.append("}")
        return "\n".join(lines)

    return ""


def function_prototypes(logic: dict[str, Any]) -> list[str]:
    prototypes: list[str] = []
    for item in logic["core_functions"]:
        name = str(item["suggested_name"])
        if name == "main":
            continue
        if name == "check_binary_name":
            prototypes.append("void check_binary_name(const char *path);")
        elif name == "xor_decode":
            prototypes.append("void xor_decode(char *out, const unsigned char *input, unsigned char key);")
        elif name == "check_magic_and_print_flag":
            prototypes.append("void check_magic_and_print_flag(int input);")
        elif name == "print_fake_flag":
            prototypes.append("void print_fake_flag(void);")
        elif name == "print_debug_info":
            prototypes.append("void print_debug_info(void);")
    return unique(prototypes)


def renamed_function_for_role(logic: dict[str, Any], role_name: str) -> str:
    for item in logic["core_functions"]:
        if item["suggested_name"] == role_name:
            return str(item["suggested_name"])
    return ""


def first_decoded_for_refs(refs: list[str], data_values: dict[str, dict[str, Any]]) -> str:
    for ref in refs:
        decoded = best_decoded_value(data_values.get(ref, {}))
        if decoded:
            return decoded
    return ""


def first_decoded_expr_for_refs(refs: list[str], data_values: dict[str, dict[str, Any]]) -> str:
    for ref in refs:
        if best_decoded_value(data_values.get(ref, {})):
            return f"{data_symbol_name(ref)}_decoded"
    return ""


def best_decoded_value(value: dict[str, Any]) -> str:
    keys = sorted((key for key in value if key.startswith("seeded_xor_")), reverse=True)
    keys.extend(sorted(key for key in value if key.startswith("xor_")))
    keys.append("ascii")
    for key in keys:
        decoded = value.get(key)
        if isinstance(decoded, str) and is_readable(decoded):
            return decoded
    return ""


def best_fake_flag_string(strings: list[str]) -> str:
    for text in strings:
        lowered = text.lower()
        if "ctf{" in lowered or ("flag" in lowered and "%" not in text and not lowered.startswith("flag:")):
            return text
    return ""


def first_hex_after(text: str, operator: str) -> str:
    match = re.search(rf"{re.escape(operator)}\s*(0x[0-9A-Fa-f]+)", text)
    return match.group(1) if match else ""


def rewrite_function_body(info: FunctionInfo, suggested_name: str, logic: dict[str, Any]) -> str:
    text = remove_ghidra_noise(info.body)
    text = re.sub(rf"\b{re.escape(info.name)}\b", suggested_name, text, count=1)
    for item in logic["functions"]:
        original = str(item["original_name"])
        renamed = str(item["suggested_name"])
        if original != renamed and item["role"] == "core_logic":
            text = re.sub(rf"\b{re.escape(original)}\b", renamed, text)
    text = re.sub(r"\bDAT_([0-9A-Fa-f]+)\b", lambda m: data_symbol_name("DAT_" + m.group(1)), text)
    text = text.replace("undefined8", "uint64_t")
    text = text.replace("undefined4", "uint32_t")
    text = text.replace("undefined1", "uint8_t")
    text = text.replace("byte", "uint8_t")
    text = re.sub(r"\blong in_FS_OFFSET;\n", "", text)
    text = re.sub(r"\s*long local_10;\n", "", text)
    text = re.sub(r"\s*local_10 = \*\(long \*\)\(in_FS_OFFSET \+ 0x28\);\n", "", text)
    text = re.sub(r"\s*if \([^{}]*local_10[^{}]*\)\s*\{\s*return;\s*\}", "return;", text, flags=re.DOTALL)
    text = re.sub(r"\s*/\* WARNING:.*?\*/", "", text)
    return text


def remove_ghidra_noise(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if "Subroutine does not return" in stripped:
            continue
        if "Unknown calling convention" in stripped:
            continue
        if "Removing unreachable block" in stripped:
            continue
        lines.append(line.rstrip())
    return "\n".join(lines)


def write_report(
    path: Path,
    functions: dict[str, FunctionInfo],
    logic: dict[str, Any],
    data_values: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
    disassembly: Path,
) -> None:
    lines = ["# Heuristic Reverse-Engineering Report", ""]
    lines.append("## Summary")
    core_count = len(logic["core_functions"])
    noise_count = len(logic["noise_functions"])
    lines.append(f"- Core functions identified: {core_count}")
    lines.append(f"- Noise/runtime functions filtered: {noise_count}")
    packer = metadata.get("packer", {})
    if isinstance(packer, dict) and packer.get("likely"):
        lines.append(f"- Packer indicators: {'; '.join(packer.get('indicators', []))}")
    pdb = metadata.get("debug_symbols", {}).get("pdb") if isinstance(metadata.get("debug_symbols"), dict) else None
    if isinstance(pdb, dict) and pdb.get("path"):
        lines.append(f"- PDB detected: `{pdb['path']}`")
    lines.extend(["", "## Function Roles"])
    for item in logic["core_functions"]:
        lines.append(f"- `{item['original_name']}` -> `{item['suggested_name']}` at `{item['address']}`")
        for reason in item["reasons"][:3]:
            lines.append(f"  - {reason}")
    lines.extend(["", "## Resolved Data"])
    if data_values:
        for ref, value in data_values.items():
            decoded = best_decoded_value(value)
            lines.append(f"- `{ref}`: {decoded!r}")
    else:
        lines.append("- No `DAT_*` references resolved from objdump bytes.")
    lines.extend(["", "## Notes"])
    lines.append("- This is heuristic output for CTF/reversing triage, not original source recovery.")
    lines.append("- Review `ai_context.md`, `logic.json`, `pseudocode.c`, and `disassembly.asm` for confidence.")
    if disassembly.exists():
        lines.append(f"- Disassembly available: `{disassembly.name}`")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def best_identifier_string(strings: list[str]) -> str:
    for text in strings:
        if re.match(r"^[A-Za-z0-9_.-]{3,64}$", text):
            return text
    return ""


def data_symbol_name(ref: str) -> str:
    return "data_" + ref.lower().replace("dat_", "")


def is_readable(text: str) -> bool:
    if not text:
        return False
    if any(ord(char) < 32 and char not in "\n\t\r" for char in text):
        return False
    printable = sum(1 for char in text if char == "\n" or char == "\t" or 32 <= ord(char) <= 126)
    if printable / max(len(text), 1) < 0.85:
        return False
    return any(char.isalnum() for char in text)


def unescape_string(text: str) -> str:
    try:
        return bytes(text, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return text


def unique(items) -> list:
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
