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
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fseek",
    "ftell",
    "rewind",
    "fflush",
    "atoi",
    "atol",
    "strtol",
    "strtoul",
    "fgets",
    "gets",
    "read",
    "putchar",
    "__ctype_b_loc",
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

    packer_notes = detect_packed_stub(functions, metadata)
    disassembly_features = analyze_disassembly_features(disassembly)
    logic = build_logic(
        functions,
        data_values,
        metadata,
        packer_notes=packer_notes,
        disassembly_features=disassembly_features,
    )
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
        code_body = strip_string_literals(body)
        name = match.group("name")
        info = FunctionInfo(name=name, address=match.group("address"), body=body)
        info.calls = unique(CALL_RE.findall(code_body))
        info.strings = unique(unescape_string(s) for s in STRING_RE.findall(body))
        info.constants = unique(HEX_RE.findall(code_body))
        info.data_refs = unique("DAT_" + value for value in DAT_RE.findall(code_body))
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

        if decodes_local_xor_constant(info):
            apply_name(info, preferred_name(info, "decode_secret"), "decodes local XOR-obfuscated byte array", 0.88)
            continue

        if looks_like_hash_function(info):
            apply_name(info, preferred_name(info, "hash_bytes"), "computes multiplicative byte-string hash", 0.9)
            continue

        if looks_like_secret_builder(info):
            apply_name(info, preferred_name(info, "make_secret"), "XOR-decodes an obfuscated secret and hashes it", 0.9)
            continue

        if looks_like_input_filter(info):
            apply_name(info, preferred_name(info, "sanitize_input"), "filters or normalizes user-controlled input", 0.84)
            continue

        validator_name = ctype_validator_name(info)
        if validator_name:
            apply_name(info, preferred_name(info, validator_name), "validates characters with ctype table checks", 0.86)
            continue

        if looks_like_file_reveal_transform(info):
            apply_name(info, preferred_name(info, "reveal_file_transform"), "reads a file and transforms output bytes", 0.88)
            continue

        if looks_like_whole_file_reader(info):
            apply_name(info, preferred_name(info, "read_file_to_buffer"), "reads an entire file into a heap buffer", 0.86)
            continue

        if looks_like_math_question_generator(info):
            apply_name(info, preferred_name(info, "generate_math_question"), "generates a random arithmetic question and expected answer", 0.9)
            continue

        if looks_like_multiplier_encoder(info):
            apply_name(info, preferred_name(info, "encode_bytes_by_multiplier"), "prints each byte multiplied by a numeric key", 0.88)
            continue

        if looks_like_file_xor_cipher(info):
            apply_name(info, preferred_name(info, "xor_file_cipher"), "reads a file and prints bytes XORed with a repeating key", 0.9)
            continue

        if looks_like_slow_output(info):
            apply_support_name(info, preferred_name(info, "print_slow"), "prints a string byte-by-byte with flushing/delay", 0.82)
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

        if looks_like_auth_or_compare_flow(info):
            apply_name(info, preferred_name(info, "auth_or_compare_flow"), "reads input and compares it against a derived or stored value", 0.82)
            continue

        if looks_like_hash_auth_flow(info):
            apply_name(info, preferred_name(info, "hash_auth_flow"), "reads input, parses numeric hash, compares generated secret hash, and opens success file", 0.84)
            continue

        if looks_like_math_challenge_flow(info):
            apply_name(info, preferred_name(info, "math_challenge_flow"), "asks a generated math question and unlocks encoded flag output on correct answer", 0.88)
            continue

        if looks_like_numeric_gate(info):
            apply_name(info, preferred_name(info, "numeric_gate"), "parses numeric input, validates bounds, and dispatches success path", 0.84)
            continue

        if looks_like_user_interface(info):
            apply_support_name(info, preferred_name(info, "display_ui"), "prints user-facing strings or banner output", 0.7)
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
    if is_indirect_jump_thunk(info):
        return True
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


def apply_support_name(info: FunctionInfo, name: str, reason: str, confidence: float) -> None:
    info.suggested_name = name
    info.role = "support_logic"
    info.confidence = max(info.confidence, confidence)
    info.reasons.append(reason)


def meaningful_symbol_name(info: FunctionInfo) -> str:
    if re.match(r"^(FUN|SUB|LAB|thunk)_?[0-9A-Fa-f]+$", info.name):
        return ""
    if info.name.startswith("_") or info.name in RUNTIME_NAMES:
        return ""
    if len(info.name) < 3:
        return ""
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", info.name):
        return ""
    return info.name


def preferred_name(info: FunctionInfo, fallback: str) -> str:
    symbol = meaningful_symbol_name(info)
    if not symbol:
        return fallback
    lowered = symbol.lower()
    if fallback == "sanitize_input" and "sanitize" in lowered:
        return "sanitize_input"
    return symbol


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


def decodes_local_xor_constant(info: FunctionInfo) -> bool:
    return bool(decode_local_xor_array(info)) and writes_to_output_parameter(info)


def writes_to_output_parameter(info: FunctionInfo) -> bool:
    signature = info.body.split("{", 1)[0]
    return "*" in signature or "out" in info.body.lower()


def looks_like_input_filter(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    if not (calls & {"isalpha", "isalnum", "isdigit", "tolower", "toupper"}):
        return False
    return bool(re.search(r"\[[^\]]+\]\s*=", info.body) or re.search(r"\*\w+\+\+\s*=", info.body))


def ctype_validator_name(info: FunctionInfo) -> str:
    if "__ctype_b_loc" not in set(info.calls):
        return ""
    if "return 1" not in info.body or "return 0" not in info.body:
        return ""
    if "& 0x800" in info.body:
        return "is_valid_decimal"
    if "& 0x1000" in info.body:
        return "is_valid_hex"
    return "is_valid_chars"


def looks_like_file_reveal_transform(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    required = {"fopen", "fread", "fclose"}
    if not required.issubset(calls):
        return False
    reads_whole_file = {"fseek", "ftell", "rewind", "malloc"}.issubset(calls)
    transforms_output = "putchar" in calls or "fwrite" in calls or "printf" in calls
    return reads_whole_file and transforms_output


def looks_like_whole_file_reader(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    return {"fopen", "fseek", "ftell", "rewind", "malloc", "fread", "fclose"}.issubset(calls)


def looks_like_math_question_generator(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    body = info.body
    return (
        "rand" in calls
        and "% 3" in body
        and "0x2b" in body
        and "0x2d" in body
        and "0x2a" in body
        and "*" in body
        and "+" in body
        and "-" in body
    )


def looks_like_multiplier_encoder(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    body = info.body
    has_byte_loop = re.search(r"while|for", body) is not None and re.search(r"\*\(char \*\)", body) is not None
    return "printf" in calls and "putchar" in calls and "*" in body and has_byte_loop


def looks_like_math_challenge_flow(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    has_rng = "srand" in calls and "time" in calls
    asks_question = any("what is" in text.lower() for text in info.strings)
    reads_answer = "__isoc23_scanf" in calls or "__isoc99_scanf" in calls or "scanf" in calls
    has_helpers = any("question" in call.lower() for call in calls) and any("encode" in call.lower() for call in calls)
    return has_rng and asks_question and reads_answer and has_helpers


def looks_like_file_xor_cipher(info: FunctionInfo) -> bool:
    body = info.body
    calls = set(info.calls)
    has_file_flow = len([call for call in calls if re.match(r"FUN_[0-9A-Fa-f]+", call)]) >= 6
    has_data_strings = len(info.data_refs) >= 5
    has_xor_loop = "^" in body and "%" in body and re.search(r"for\s*\(", body) is not None
    return has_file_flow and has_data_strings and has_xor_loop


def looks_like_slow_output(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    return "putchar" in calls and "fflush" in calls and (calls & {"usleep", "sleep", "nanosleep"})


def looks_like_auth_or_compare_flow(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    reads_input = bool(calls & {"fgets", "gets", "__isoc99_scanf", "scanf", "read"})
    compares = bool(calls & {"strcmp", "strncmp", "memcmp"})
    has_success_or_failure_text = any(
        token in " ".join(info.strings).lower()
        for token in ("denied", "granted", "success", "fail", "password", "attempt", "flag", "try")
    )
    return reads_input and compares and has_success_or_failure_text


def looks_like_hash_function(info: FunctionInfo) -> bool:
    body = info.body
    return (
        "while" in body
        and "*" in body
        and "+" in body
        and ("0x21" in body or "* 33" in body)
        and ("0x1505" in body or "5381" in body)
    )


def looks_like_secret_builder(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    body = info.body
    return "^ 0xaa" in body and "hash" in calls and re.search(r"\*\(.*\)\s*=", body) is not None


def looks_like_hash_auth_flow(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    reads_input = "fgets" in calls
    parses_hash = "strtoul" in calls or "strtoull" in calls
    has_secret_call = any("secret" in call.lower() or call == "make_secret" for call in calls)
    opens_file = "fopen" in calls and "fclose" in calls
    has_hash_text = any("hash" in text.lower() for text in info.strings)
    return reads_input and parses_hash and has_secret_call and opens_file and has_hash_text


def looks_like_numeric_gate(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    reads_input = bool(calls & {"__isoc99_scanf", "scanf", "fgets"})
    parses_number = bool(calls & {"atoi", "strtol", "strtoul", "sscanf"})
    has_validator = any("valid" in call.lower() or "is_" in call.lower() for call in calls)
    has_bounds = len(re.findall(r"<\s*(?:0x[0-9A-Fa-f]+|\d+)", info.body)) >= 2
    has_success_call = any(call not in RUNTIME_NAMES and call not in {"if", "for", "while"} for call in calls)
    return reads_input and parses_number and has_validator and has_bounds and has_success_call


def looks_like_user_interface(info: FunctionInfo) -> bool:
    calls = set(info.calls)
    if not (calls & {"puts", "printf", "__printf_chk", "putchar"}):
        return False
    if calls & {"scanf", "__isoc99_scanf", "__isoc23_scanf", "fgets", "strtoul"}:
        return False
    if any(token in " ".join(info.strings).lower() for token in ("wrong answer", "invalid input", "flag")):
        return False
    string_text = " ".join(info.strings).lower()
    visual_string_count = sum(1 for text in info.strings if len(text) > 12)
    has_terminal_ui = "\\x1b" in info.body or "\x1b" in string_text
    return visual_string_count >= 3 or has_terminal_ui


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


def analyze_disassembly_features(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    features: list[dict[str, Any]] = []
    syscall_count = text.count("SYSCALL")
    write_len = first_mov_immediate_before_syscall(text, "RDX")
    writes_stdout = "MOV RDI,0x1" in text
    inline = recover_inline_mov_string(text)
    if inline and syscall_count >= 2 and writes_stdout:
        features.append(
            {
                "kind": "syscall_write_immediate_string",
                "string": inline,
                "length": write_len or len(inline),
                "syscalls": syscall_count,
            }
        )
    return features


def recover_inline_mov_string(text: str) -> str:
    chunks: dict[int, bytes] = {}
    last_immediates: dict[str, int] = {}
    mov_imm_re = re.compile(r"\bMOV\s+(RAX|RDX),0x([0-9A-Fa-f]+)")
    store_re = re.compile(r"\bMOV\s+qword ptr \[RBP \+ -(0x[0-9A-Fa-f]+|\d+)\],(RAX|RDX)")
    for line in text.splitlines():
        mov = mov_imm_re.search(line)
        if mov:
            last_immediates[mov.group(1)] = int(mov.group(2), 16)
            continue
        store = store_re.search(line)
        if store and store.group(2) in last_immediates:
            offset = int(store.group(1), 0)
            chunks[offset] = int_to_le_bytes(last_immediates[store.group(2)])
    if not chunks:
        return ""
    base = max(chunks)
    memory: dict[int, int] = {}
    for stack_offset, data in chunks.items():
        start = base - stack_offset
        for index, value in enumerate(data):
            memory[start + index] = value
    raw = bytes(memory[index] for index in range(max(memory) + 1))
    text_value = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return text_value if is_readable(text_value) and len(text_value) >= 8 else ""


def int_to_le_bytes(value: int) -> bytes:
    size = max(1, (value.bit_length() + 7) // 8)
    size = 8 if size <= 8 else size
    return value.to_bytes(size, "little", signed=False)


def first_mov_immediate_before_syscall(text: str, register: str) -> int | None:
    pattern = re.compile(rf"\bMOV\s+{re.escape(register)},0x([0-9A-Fa-f]+)")
    values = [int(match.group(1), 16) for match in pattern.finditer(text)]
    return values[-1] if values else None


def resolve_data_refs(
    functions: dict[str, FunctionInfo],
    memory: dict[int, int],
    *,
    image_base: int | None = None,
) -> dict[str, dict[str, Any]]:
    refs = sorted({ref for info in functions.values() if info.role in {"core_logic", "support_logic"} for ref in info.data_refs})
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
            utf8_text = bytes(raw).decode("utf-8", errors="replace")
            if utf8_text != ascii_text and is_readable(utf8_text):
                item["utf8"] = utf8_text
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


def build_logic(
    functions: dict[str, FunctionInfo],
    data_values: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
    *,
    packer_notes: dict[str, Any] | None = None,
    disassembly_features: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
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
        "support_functions": [item for item in function_items if item["role"] == "support_logic"],
        "noise_functions": [item for item in function_items if item["noise"]],
        "data_refs": data_values,
        "packer": metadata.get("packer", {}),
        "packer_notes": packer_notes or {},
        "disassembly_features": disassembly_features or [],
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
    for item in selected_logic_functions(logic):
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
        if display:
            lines.append(f"- `{ref}`: {display!r} bytes={value.get('bytes', [])[:32]}")
    lines.extend(["", "## Packer / Debug Symbols"])
    lines.append(json.dumps({"packer": metadata.get("packer", {}), "debug_symbols": metadata.get("debug_symbols", {})}, indent=2))
    lines.extend(["", "## Selected Pseudocode"])
    for item in selected_logic_functions(logic)[:12]:
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
        "#define _DEFAULT_SOURCE",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "#include <stdint.h>",
        "#include <ctype.h>",
        "#include <unistd.h>",
        "#include <time.h>",
        "",
    ]
    prototypes = function_prototypes(logic)
    if prototypes:
        lines.extend(prototypes)
        lines.append("")
    externs = obfuscated_externs(functions, logic)
    if externs:
        lines.extend(externs)
        lines.append("")
    for ref, value in data_values.items():
        bytes_value = value.get("bytes", [])
        decoded = best_decoded_value(value)
        should_emit = bool(decoded and len(decoded) <= 200)
        if isinstance(bytes_value, list) and bytes_value and should_emit:
            name = data_symbol_name(ref)
            joined = ", ".join(f"0x{int(byte) & 0xff:02x}" for byte in bytes_value[:256])
            lines.append(f"static const unsigned char {name}[] = {{{joined}, 0x00}};")
            lines.append(f"static const char {name}_decoded[] = {c_string(decoded)};")
    if data_values:
        lines.append("")
    for feature in logic.get("disassembly_features", []):
        if isinstance(feature, dict) and feature.get("kind") == "syscall_write_immediate_string":
            lines.append(rewrite_syscall_write_feature(feature))
            lines.append("")

    for item in selected_logic_functions(logic):
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
        if looks_like_hash_auth_flow(info):
            return rewrite_hash_auth_flow(info, logic)
        if looks_like_math_challenge_flow(info):
            return rewrite_math_challenge_flow(info, logic, data_values)
        if looks_like_numeric_gate(info):
            return rewrite_numeric_gate(info, logic, data_values)
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
                f"    printf({c_string(prompt)});",
                '    scanf("%d", &input);',
                f"    {checker}(input);",
                "    return 0;",
                "}",
            ]
        )
        return "\n".join(lines)

    if suggested_name == "auth_or_compare_flow" or looks_like_auth_or_compare_flow(info):
        return summarize_auth_or_compare_flow(info, logic, data_values)

    if suggested_name == "hash_auth_flow" or looks_like_hash_auth_flow(info):
        return rewrite_hash_auth_flow(info, logic)

    if suggested_name == "math_challenge_flow" or looks_like_math_challenge_flow(info):
        return rewrite_math_challenge_flow(info, logic, data_values)

    validator = ctype_validator_name(info)
    if validator:
        return rewrite_ctype_validator(info, suggested_name, validator)

    if looks_like_file_reveal_transform(info):
        return rewrite_file_reveal_transform(info, suggested_name)

    if looks_like_whole_file_reader(info):
        return rewrite_whole_file_reader(info, suggested_name)

    if looks_like_math_question_generator(info):
        return rewrite_math_question_generator(info, suggested_name)

    if looks_like_multiplier_encoder(info):
        return rewrite_multiplier_encoder(info, suggested_name)

    if looks_like_file_xor_cipher(info):
        return rewrite_file_xor_cipher(info, suggested_name, data_values)

    if looks_like_hash_function(info):
        return rewrite_hash_function(info, suggested_name)

    if looks_like_secret_builder(info):
        return rewrite_secret_builder(info, suggested_name)

    if suggested_name == "check_binary_name":
        expected = best_identifier_string(info.strings) or "crackme"
        reject = next((s for s in info.strings if "interesting" in s.lower() or "move" in s.lower()), "")
        lines = [
            "void check_binary_name(const char *path)",
            "{",
            '    const char *name = strrchr(path, \'/\');',
            "    name = name ? name + 1 : path;",
            f"    if (strcmp(name, {c_string(expected)}) != 0) {{",
        ]
        if reject:
            lines.append(f"        puts({c_string(reject)});")
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

    if suggested_name == "type_out":
        function_name = suggested_name if suggested_name != "type_out" else preferred_name(info, "print_slow")
        return "\n".join(
            [
                f"void {function_name}(const char *msg, unsigned int delay)",
                "{",
                "    while (*msg != '\\0') {",
                "        putchar((unsigned char)*msg++);",
                "        fflush(stdout);",
                "        usleep(delay);",
                "    }",
                "}",
            ]
        )

    if decodes_local_xor_constant(info):
        decoded = decode_local_xor_array(info)
        function_name = sanitize_identifier(suggested_name)
        if decoded:
            return "\n".join(
                [
                    f"void {function_name}(char *out)",
                    "{",
                    f"    strcpy(out, {c_string(decoded)});",
                    "}",
                ]
            )

    if suggested_name == "sanitize_input" or looks_like_input_filter(info):
        function_name = sanitize_identifier(suggested_name)
        return "\n".join(
            [
                f"void {function_name}(const char *input, char *out)",
                "{",
                "    while (*input != '\\0') {",
                "        if (isalpha((unsigned char)*input)) {",
                "            *out++ = *input;",
                "        }",
                "        input++;",
                "    }",
                "    *out = '\\0';",
                "}",
            ]
        )

    if suggested_name == "display_ui" or looks_like_user_interface(info):
        return summarize_ui_function(info, suggested_name)

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
            lines.append(f"        printf(\"FLAG: %s\\n\", {decoded_expr or c_string(decoded)});")
        else:
            lines.append('        puts("FLAG: <decoded data unavailable>");')
        lines.append("        return;")
        lines.append("    }")
        if fake_flag:
            lines.append(f"    puts({c_string(fake_flag)});")
        lines.append("}")
        return "\n".join(lines)

    if suggested_name == "print_fake_flag":
        text = info.strings[0] if info.strings else ""
        return "\n".join(["void print_fake_flag(void)", "{", f"    puts({c_string(text)});", "}"])

    if suggested_name == "print_debug_info":
        lines = ["void print_debug_info(void)", "{"]
        for text in info.strings:
            if text:
                lines.append(f"    printf({c_string(text)});")
        lines.append("}")
        return "\n".join(lines)

    return ""


def rewrite_syscall_write_feature(feature: dict[str, Any]) -> str:
    text = str(feature.get("string", ""))
    length = int(feature.get("length") or len(text))
    return "\n".join(
        [
            "int syscall_write_immediate_string(void)",
            "{",
            f"    const char message[] = {c_string(text)};",
            f"    write(1, message, {length});",
            "    return 0;",
            "}",
        ]
    )


def summarize_auth_or_compare_flow(info: FunctionInfo, logic: dict[str, Any], data_values: dict[str, dict[str, Any]]) -> str:
    function_name = sanitize_identifier(info.suggested_name or meaningful_symbol_name(info) or "auth_or_compare_flow")
    input_call = first_call(info, ["fgets", "scanf", "__isoc99_scanf", "read"])
    compare_call = first_call(info, ["strcmp", "strncmp", "memcmp"])
    file_path = next((s for s in info.strings if "/" in s and "." in s), "")
    success_format = first_decoded_for_refs(info.data_refs, data_values) or next((s for s in info.strings if "%s" in s), "")
    important_calls = [
        call for call in info.calls
        if call not in {"if", "for", "while", input_call, compare_call, "printf", "__printf_chk", "puts", "fflush"}
        and call != function_name
    ][:8]
    lines = [
        f"int {function_name}(void)",
        "{",
        f"    /* input: {input_call or 'unknown'}, compare: {compare_call or 'unknown'} */",
    ]
    for call in important_calls:
        lines.append(f"    /* calls {call}() during this flow */")
    for text in interesting_strings(info.strings, limit=6):
        lines.append(f"    /* string: {c_comment(text)} */")
    if file_path:
        lines.append(f"    /* opens file: {c_comment(file_path)} */")
    if success_format:
        lines.append(f"    /* output format/data: {c_comment(success_format)} */")
    lines.extend(
        [
            "    /* Review pseudocode.c for exact control flow and buffer sizes. */",
            "    return 0;",
            "}",
        ]
    )
    return "\n".join(lines)


def rewrite_ctype_validator(info: FunctionInfo, suggested_name: str, validator: str) -> str:
    function_name = sanitize_identifier(suggested_name or validator)
    predicate = "isxdigit" if validator == "is_valid_hex" else "isdigit" if validator == "is_valid_decimal" else "isprint"
    return "\n".join(
        [
            f"int {function_name}(const char *s)",
            "{",
            "    while (*s != '\\0') {",
            f"        if (!{predicate}((unsigned char)*s)) {{",
            "            return 0;",
            "        }",
            "        s++;",
            "    }",
            "    return 1;",
            "}",
        ]
    )


def rewrite_file_reveal_transform(info: FunctionInfo, suggested_name: str) -> str:
    function_name = sanitize_identifier(suggested_name or preferred_name(info, "reveal_file_transform"))
    path = next((s for s in info.strings if "/" in s and "%" not in s), "flag.txt")
    mode = next((s for s in info.strings if s in {"r", "rb"}), "r")
    prefix = next(
        (
            s for s in info.strings
            if s not in {path, mode}
            and any(word in s.lower() for word in ("access", "success", "granted"))
            and "%" not in s
        ),
        "",
    )
    inserts = [
        s for s in info.strings
        if s not in {path, mode, prefix}
        and "%" not in s
        and not any(word in s.lower() for word in ("not found", "access", "success", "granted"))
        and len(s) <= 80
    ]
    inserted = inserts[0] if inserts else ""
    mask_match = re.search(r"&\s*(0x[0-9A-Fa-f]+|\d+)", info.body)
    mask = mask_match.group(1) if mask_match else ""
    lines = [
        f"void {function_name}(void)",
        "{",
        f"    FILE *fp = fopen({c_string(path)}, {c_string(mode)});",
        "    if (!fp) {",
        '        puts("file not found");',
        "        return;",
        "    }",
        "    fseek(fp, 0, SEEK_END);",
        "    long size = ftell(fp);",
        "    rewind(fp);",
        "    char *buf = malloc((size_t)size + 1);",
        "    if (!buf) {",
        "        fclose(fp);",
        "        return;",
        "    }",
        "    fread(buf, 1, (size_t)size, fp);",
        "    buf[size] = '\\0';",
        "    fclose(fp);",
    ]
    if prefix:
        lines.append(f"    printf({c_string(prefix)});")
    lines.extend(
        [
            "    for (long i = size - 1; i >= 0; i--) {",
            "        putchar((unsigned char)buf[i]);",
        ]
    )
    if inserted and mask:
        lines.append(f"        if ((i & {mask}) == 0) {{")
        lines.append(f"            printf({c_string(inserted)});")
        lines.append("        }")
    lines.extend(
        [
            "    }",
            "    putchar('\\n');",
            "    free(buf);",
            "}",
        ]
    )
    return "\n".join(lines)


def rewrite_whole_file_reader(info: FunctionInfo, suggested_name: str) -> str:
    function_name = sanitize_identifier(suggested_name or preferred_name(info, "read_file_to_buffer"))
    mode = next((s for s in info.strings if s in {"r", "rb"}), "r")
    open_error = first_string_containing(info.strings, ["open"]) or "Could not open file"
    memory_error = first_string_containing(info.strings, ["memory"]) or "Memory error"
    return "\n".join(
        [
            f"char *{function_name}(const char *path)",
            "{",
            f"    FILE *fp = fopen(path, {c_string(mode)});",
            "    if (!fp) {",
            f"        perror({c_string(open_error)});",
            "        return NULL;",
            "    }",
            "    fseek(fp, 0, SEEK_END);",
            "    long size = ftell(fp);",
            "    rewind(fp);",
            "    char *buf = malloc((size_t)size + 1);",
            "    if (!buf) {",
            f"        perror({c_string(memory_error)});",
            "        fclose(fp);",
            "        return NULL;",
            "    }",
            "    fread(buf, 1, (size_t)size, fp);",
            "    buf[size] = '\\0';",
            "    fclose(fp);",
            "    return buf;",
            "}",
        ]
    )


def rewrite_math_question_generator(info: FunctionInfo, suggested_name: str) -> str:
    function_name = sanitize_identifier(suggested_name or preferred_name(info, "generate_math_question"))
    return "\n".join(
        [
            f"int {function_name}(char *op, unsigned int *left, unsigned int *right)",
            "{",
            "    *left = (unsigned int)(rand() % 10 + 1);",
            "    *right = (unsigned int)(rand() % 11);",
            "    switch (rand() % 3) {",
            "    case 0:",
            "        *op = '+';",
            "        return (int)(*left + *right);",
            "    case 1:",
            "        *op = '-';",
            "        if (*left < *right) {",
            "            unsigned int tmp = *left;",
            "            *left = *right;",
            "            *right = tmp;",
            "        }",
            "        return (int)(*left - *right);",
            "    default:",
            "        *op = '*';",
            "        return (int)(*left * *right);",
            "    }",
            "}",
        ]
    )


def rewrite_multiplier_encoder(info: FunctionInfo, suggested_name: str) -> str:
    function_name = sanitize_identifier(suggested_name or preferred_name(info, "encode_bytes_by_multiplier"))
    header = next((s for s in info.strings if "encoded" in s.lower()), "Encoded values:")
    separator = next((s for s in info.strings if "," in s), ", ")
    return "\n".join(
        [
            f"void {function_name}(const char *text, int key)",
            "{",
            f"    puts({c_string(header)});",
            "    for (size_t i = 0; text[i] != '\\0'; i++) {",
            "        printf(\"%d\", (unsigned char)text[i] * key);",
            "        if (text[i + 1] != '\\0') {",
            f"            printf({c_string(separator)});",
            "        }",
            "    }",
            "    putchar('\\n');",
            "}",
        ]
    )


def rewrite_file_xor_cipher(info: FunctionInfo, suggested_name: str, data_values: dict[str, dict[str, Any]]) -> str:
    function_name = sanitize_identifier(suggested_name or preferred_name(info, "xor_file_cipher"))
    strings = decoded_strings_for_refs(info.data_refs, data_values)
    input_path = first_path_like(strings) or "flag.txt"
    mode = next((s for s in strings if s in {"r", "rb"}), "rb")
    key = recover_global_byte_string(info) or "S3Cr3t"
    prefix = first_string_containing(strings, ["cipher", "encrypted", "output"]) or ""
    lines = [
        f"int {function_name}(void)",
        "{",
        f"    const unsigned char key[] = {c_string(key)};",
        f"    FILE *fp = fopen({c_string(input_path)}, {c_string(mode)});",
        "    if (!fp) {",
        '        puts("failed to open input file");',
        "        return 1;",
        "    }",
        "    fseek(fp, 0, SEEK_END);",
        "    long size = ftell(fp);",
        "    rewind(fp);",
        "    unsigned char *buf = malloc((size_t)size + 1);",
        "    if (!buf) {",
        "        fclose(fp);",
        "        return 1;",
        "    }",
        "    fread(buf, 1, (size_t)size, fp);",
        "    fclose(fp);",
    ]
    if prefix:
        lines.append(f"    printf({c_string(prefix)});")
    lines.extend(
        [
            "    for (long i = 0; i < size; i++) {",
            '        printf("%02x", buf[i] ^ key[i % (sizeof(key) - 1)]);',
            "    }",
            "    putchar('\\n');",
            "    free(buf);",
            "    return 0;",
            "}",
        ]
    )
    return "\n".join(lines)


def rewrite_hash_function(info: FunctionInfo, suggested_name: str) -> str:
    function_name = sanitize_identifier(suggested_name or preferred_name(info, "hash_bytes"))
    seed = "0x1505" if "0x1505" in info.body else "5381"
    multiplier = "0x21" if "0x21" in info.body else "33"
    return "\n".join(
        [
            f"unsigned long {function_name}(const unsigned char *data)",
            "{",
            f"    unsigned long h = {seed};",
            "    while (*data != 0) {",
            f"        h = h * {multiplier} + *data;",
            "        data++;",
            "    }",
            "    return h;",
            "}",
        ]
    )


def rewrite_secret_builder(info: FunctionInfo, suggested_name: str) -> str:
    function_name = sanitize_identifier(suggested_name or preferred_name(info, "make_secret"))
    hash_call = first_named_call(info, ("hash",)) or "hash_bytes"
    terminator = first_store_offset(info.body) or "0"
    return "\n".join(
        [
            f"unsigned long {function_name}(unsigned char *out)",
            "{",
            "    size_t i = 0;",
            "    while (obf_bytes[i] != 0) {",
            "        out[i] = obf_bytes[i] ^ 0xaa;",
            "        i++;",
            "    }",
            f"    out[{terminator}] = 0;",
            f"    return {hash_call}(out);",
            "}",
        ]
    )


def rewrite_hash_auth_flow(info: FunctionInfo, logic: dict[str, Any]) -> str:
    function_name = sanitize_identifier(info.suggested_name or preferred_name(info, "hash_auth_flow"))
    secret_builder = first_named_call(info, ("secret",)) or "make_secret"
    flag_path = first_string_containing(info.strings, ["flag.txt"]) or "flag.txt"
    open_error = first_string_containing(info.strings, ["could not open", "open flag"]) or "Could not open flag file"
    read_error = first_string_containing(info.strings, ["failed to read", "read the flag"]) or "Failed to read the flag"
    hash_prompt = first_string_containing(info.strings, ["hash"]) or "Enter hash:"
    password_prompt = first_string_containing(info.strings, ["password"]) or ""
    lines = [
        f"int {function_name}(void)",
        "{",
        "    char input[64];",
        "    char flag[104];",
        "    unsigned char secret[16];",
        "    char *end = NULL;",
    ]
    if password_prompt:
        lines.append(f"    puts({c_string(password_prompt)});")
        lines.append("    /* Program stores a user password, then leaks bytes according to user-supplied length. */")
    lines.extend(
        [
            f"    puts({c_string(hash_prompt)});",
            "    if (!fgets(input, sizeof(input), stdin)) {",
            "        return 0;",
            "    }",
            '    input[strcspn(input, "\\n")] = \'\\0\';',
            "    unsigned long wanted_hash = strtoul(input, &end, 10);",
            "    if (end == input) {",
            '        puts("No digits were found");',
            "        return 1;",
            "    }",
            f"    unsigned long secret_hash = {secret_builder}(secret);",
            "    if (secret_hash != wanted_hash) {",
            "        return 0;",
            "    }",
            f"    FILE *fp = fopen({c_string(flag_path)}, \"r\");",
            "    if (!fp) {",
            f"        perror({c_string(open_error)});",
            "        return 1;",
            "    }",
            "    if (!fgets(flag, sizeof(flag), fp)) {",
            f"        puts({c_string(read_error)});",
            "    } else {",
            '        printf("%s", flag);',
            "    }",
            "    fclose(fp);",
            "    return 0;",
            "}",
        ]
    )
    return "\n".join(lines)


def rewrite_math_challenge_flow(info: FunctionInfo, logic: dict[str, Any], data_values: dict[str, dict[str, Any]]) -> str:
    function_name = sanitize_identifier(info.suggested_name or preferred_name(info, "math_challenge_flow"))
    generator = first_named_call(info, ("question",)) or "generate_math_question"
    encoder = first_named_call(info, ("encode",)) or "encode_bytes_by_multiplier"
    reader = first_named_call(info, ("read_flag", "read_file")) or "read_file_to_buffer"
    scan_format = first_decoded_for_refs(info.data_refs, data_values) or "%d"
    prompt = next((s for s in info.strings if "what is" in s.lower()), "What is %d %c %d? ")
    flag_path = first_string_containing(info.strings, ["flag.txt"]) or "flag.txt"
    wrong = first_string_containing(info.strings, ["wrong"]) or "Wrong answer! No flag for you."
    invalid = first_string_containing(info.strings, ["invalid"]) or "Invalid input. Exiting."
    return "\n".join(
        [
            f"int {function_name}(void)",
            "{",
            "    char op;",
            "    unsigned int left;",
            "    unsigned int right;",
            "    int answer;",
            f"    srand((unsigned int)time(NULL));",
            f"    int expected = {generator}(&op, &left, &right);",
            f"    printf({c_string(prompt)}, left, op, right);",
            "    fflush(stdout);",
            f"    if (scanf({c_string(scan_format)}, &answer) != 1) {{",
            f"        puts({c_string(invalid)});",
            "        return 1;",
            "    }",
            "    if (answer != expected) {",
            f"        puts({c_string(wrong)});",
            "        return 1;",
            "    }",
            f"    char *flag = {reader}({c_string(flag_path)});",
            "    if (!flag) {",
            "        return 1;",
            "    }",
            f"    {encoder}(flag, expected);",
            "    free(flag);",
            "    return 0;",
            "}",
        ]
    )


def rewrite_numeric_gate(info: FunctionInfo, logic: dict[str, Any], data_values: dict[str, dict[str, Any]]) -> str:
    function_name = sanitize_identifier(info.suggested_name or "numeric_gate")
    prompt = next((s for s in info.strings if "enter" in s.lower() or "code" in s.lower() or "number" in s.lower()), "Enter value: ")
    scan_format = first_decoded_for_refs(info.data_refs, data_values) or "%127s"
    buffer_size = parse_first_char_buffer_size(info.body) or 128
    decimal_validator = first_named_call(info, ("decimal", "digit"))
    hex_validator = first_named_call(info, ("hex", "xdigit"))
    success_call = first_success_call(info, logic)
    invalid = first_string_containing(info.strings, ["invalid"]) or "Invalid input."
    too_small = first_string_containing(info.strings, ["small", "low"]) or "Too small."
    too_high = first_string_containing(info.strings, ["high", "large"]) or "Too high."
    denied = first_string_containing(info.strings, ["denied", "fail"]) or "Access Denied."
    bounds = sorted({int(value, 0) for value in re.findall(r"<\s*(0x[0-9A-Fa-f]+|\d+)", info.body)})
    lower = bounds[0] if bounds else 0
    upper = bounds[1] if len(bounds) > 1 else 0
    required_len = first_required_length(info.body)
    lines = [
        f"int {function_name}(void)",
        "{",
        f"    char input[{buffer_size}];",
        "    int value;",
        f"    printf({c_string(prompt)});",
        "    fflush(stdout);",
        f"    scanf({c_string(scan_format)}, input);",
        "",
        f"    if ({decimal_validator or 'is_valid_decimal'}(input)) {{",
        "        value = atoi(input);",
        f"    }} else if ({hex_validator or 'is_valid_hex'}(input)) {{",
        "        value = (int)strtol(input, NULL, 16);",
        "    } else {",
        f"        puts({c_string(invalid)});",
        "        return 1;",
        "    }",
    ]
    if lower:
        lines.extend(["", f"    if (value < {lower}) {{", f"        puts({c_string(too_small)});"])
    if upper:
        if lower:
            lines.append(f"    }} else if (value < {upper}) {{")
        else:
            lines.extend(["", f"    if (value < {upper}) {{"])
        if required_len:
            lines.append(f"        if (strlen(input) == {required_len}) {{")
            lines.append(f"            {success_call or 'success'}();")
            lines.append("        } else {")
            lines.append(f"            puts({c_string(denied)});")
            lines.append("        }")
        elif success_call:
            lines.append(f"        {success_call}();")
    if upper:
        lines.append("    } else {")
        lines.append(f"        puts({c_string(too_high)});")
        lines.append("    }")
    elif lower:
        lines.append("    }")
    lines.extend(["    return 0;", "}"])
    return "\n".join(lines)


def summarize_ui_function(info: FunctionInfo, suggested_name: str) -> str:
    function_name = sanitize_identifier(suggested_name if suggested_name != "display_ui" else preferred_name(info, "display_ui"))
    lines = [f"void {function_name}(void)", "{"]
    shown = interesting_strings(info.strings, limit=8)
    if not shown:
        lines.append("    /* user-interface output omitted */")
    for text in shown:
        if len(text) <= 120 and "\x00" not in text:
            lines.append(f"    puts({c_string(text)});")
        else:
            lines.append(f"    /* large UI string omitted: {len(text)} chars */")
    if len(info.strings) > len(shown):
        lines.append(f"    /* {len(info.strings) - len(shown)} more UI strings omitted */")
    lines.append("}")
    return "\n".join(lines)


def decode_local_xor_array(info: FunctionInfo) -> str:
    assignments = re.findall(r"\b\w+\[(\d+)\]\s*=\s*(0x[0-9A-Fa-f]{1,2}|\d+)\s*;", info.body)
    if not assignments:
        return ""
    values: dict[int, int] = {}
    for index, value in assignments:
        values[int(index)] = int(value, 0)
    if not values:
        return ""
    ordered = [values[index] for index in range(max(values) + 1) if index in values]
    keys = [int(value, 16) for value in re.findall(r"\^\s*(0x[0-9A-Fa-f]{1,2})", info.body)]
    for key in keys:
        decoded = bytes(byte ^ key for byte in ordered).decode("ascii", errors="replace")
        if is_readable(decoded):
            return decoded
    return ""


def function_prototypes(logic: dict[str, Any]) -> list[str]:
    prototypes: list[str] = []
    for item in selected_logic_functions(logic):
        name = str(item["suggested_name"])
        if name == "main":
            continue
        if name == "check_binary_name":
            prototypes.append("void check_binary_name(const char *path);")
        elif name == "xor_decode":
            prototypes.append("void xor_decode(char *out, const unsigned char *input, unsigned char key);")
        elif name == "check_magic_and_print_flag":
            prototypes.append("void check_magic_and_print_flag(int input);")
        elif "question" in name.lower():
            prototypes.append(f"int {sanitize_identifier(name)}(char *op, unsigned int *left, unsigned int *right);")
        elif "encode" in name.lower() or "multiplier" in name.lower():
            prototypes.append(f"void {sanitize_identifier(name)}(const char *text, int key);")
        elif "read_file" in name.lower() or "read_flag" in name.lower():
            prototypes.append(f"char *{sanitize_identifier(name)}(const char *path);")
        elif name.startswith("is_valid_"):
            prototypes.append(f"int {sanitize_identifier(name)}(const char *s);")
        elif "reveal" in name.lower() or "file_transform" in name.lower():
            prototypes.append(f"void {sanitize_identifier(name)}(void);")
        elif "hash_bytes" in name or name == "hash":
            prototypes.append(f"unsigned long {sanitize_identifier(name)}(const unsigned char *data);")
        elif "secret" in name.lower():
            prototypes.append(f"unsigned long {sanitize_identifier(name)}(unsigned char *out);")
        elif name in {"numeric_gate", "auth_or_compare_flow", "hash_auth_flow", "math_challenge_flow"}:
            prototypes.append(f"int {sanitize_identifier(name)}(void);")
        elif name == "print_fake_flag":
            prototypes.append("void print_fake_flag(void);")
        elif name == "print_debug_info":
            prototypes.append("void print_debug_info(void);")
        elif name == "decode_password":
            prototypes.append("void decode_password(char *out);")
        elif "decode" in name.lower() or "secret" in name.lower():
            prototypes.append(f"void {sanitize_identifier(name)}(char *out);")
        elif name == "sanitize_input":
            prototypes.append("void sanitize_input(const char *input, char *out);")
        elif "sanitize" in name.lower() or "filter" in name.lower():
            prototypes.append(f"void {sanitize_identifier(name)}(const char *input, char *out);")
        elif name == "type_out":
            prototypes.append("void type_out(const char *msg, unsigned int delay);")
        elif "print" in name.lower() or "type" in name.lower():
            prototypes.append(f"void {sanitize_identifier(name)}(const char *msg, unsigned int delay);")
        elif name in {"auth_sequence", "intro_sequence", "display_ui"}:
            prototypes.append(f"void {sanitize_identifier(name)}(void);")
    return unique(prototypes)


def obfuscated_externs(functions: dict[str, FunctionInfo], logic: dict[str, Any]) -> list[str]:
    names: set[str] = set()
    for item in selected_logic_functions(logic):
        info = functions.get(str(item.get("original_name")))
        if not info:
            continue
        names.update(re.findall(r"\bobf_[A-Za-z0-9_]*\b", info.body))
    return [f"extern const unsigned char {name}[];" for name in sorted(names)]


def selected_logic_functions(logic: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key in ("support_functions", "core_functions"):
        for item in logic.get(key, []):
            if isinstance(item, dict):
                items.append(item)
    return sorted(items, key=lambda item: int(str(item.get("address", "0x0")), 16))


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
    keys.append("utf8")
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


def first_call(info: FunctionInfo, names: list[str]) -> str:
    calls = set(info.calls)
    return next((name for name in names if name in calls), "")


def first_named_call(info: FunctionInfo, tokens: tuple[str, ...]) -> str:
    for call in info.calls:
        lowered = call.lower()
        if any(token in lowered for token in tokens):
            return call
    return ""


def first_success_call(info: FunctionInfo, logic: dict[str, Any]) -> str:
    known = {str(item.get("original_name")): str(item.get("suggested_name")) for item in selected_logic_functions(logic)}
    skip = RUNTIME_NAMES | {"if", "for", "while", info.name}
    for call in info.calls:
        lowered = call.lower()
        if call in skip:
            continue
        if any(token in lowered for token in ("valid", "scanf", "printf", "strlen", "atoi", "strtol")):
            continue
        if call in known:
            return known[call]
        if meaningful_symbol_name(FunctionInfo(name=call, address="0", body="")):
            return call
    return ""


def first_string_containing(strings: list[str], tokens: list[str]) -> str:
    for text in strings:
        lowered = text.lower()
        if any(token in lowered for token in tokens):
            return text
    return ""


def parse_first_char_buffer_size(text: str) -> int | None:
    match = re.search(r"char\s+\w+\s*\[(\d+)\]", text)
    if not match:
        return None
    return int(match.group(1))


def detect_packed_stub(functions: dict[str, FunctionInfo], metadata: dict[str, Any]) -> dict[str, Any]:
    input_meta = metadata.get("input", {}) if isinstance(metadata, dict) else {}
    strings_meta = metadata.get("strings", {}) if isinstance(metadata, dict) else {}
    strings = strings_meta.get("items", []) if isinstance(strings_meta, dict) else []
    entropy = input_meta.get("entropy") if isinstance(input_meta, dict) else None
    file_type = metadata.get("architecture", {}).get("file", "") if isinstance(metadata.get("architecture"), dict) else ""
    thunk_count = sum(1 for info in functions.values() if is_indirect_jump_thunk(info))
    decompressor_count = sum(1 for info in functions.values() if looks_like_decompressor_stub(info))
    indicators: list[str] = []
    if any("UPX" in str(item) for item in strings):
        indicators.append("UPX strings present")
    if isinstance(entropy, (int, float)) and entropy >= 7.0:
        indicators.append(f"high entropy {entropy}")
    if "no section header" in file_type.lower():
        indicators.append("ELF has no section headers")
    if thunk_count >= 5:
        indicators.append(f"{thunk_count} indirect resolver thunks")
    if decompressor_count:
        indicators.append(f"{decompressor_count} decompressor/unpacker-like function(s)")
    return {
        "likely_packed_stub": bool(indicators),
        "indicators": indicators,
        "thunk_count": thunk_count,
        "decompressor_count": decompressor_count,
    }


def is_indirect_jump_thunk(info: FunctionInfo) -> bool:
    return "Could not recover jumptable" in info.body and "Treating indirect jump as call" in info.body


def looks_like_decompressor_stub(info: FunctionInfo) -> bool:
    body = info.body
    return (
        "CARRY4" in body
        and "0xffffffff" in body
        and "FUN_" in body
        and len(body.splitlines()) > 60
    )


def decoded_strings_for_refs(refs: list[str], data_values: dict[str, dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for ref in refs:
        text = best_decoded_value(data_values.get(ref, {}))
        if text:
            out.append(text)
    return out


def first_path_like(strings: list[str]) -> str:
    for text in strings:
        if "/" in text or "." in text:
            return text
    return ""


def recover_global_byte_string(info: FunctionInfo) -> str:
    assignments = re.findall(r"DAT_[0-9A-Fa-f]+\s*=\s*(0x[0-9A-Fa-f]{1,2}|\d+)\s*;", info.body)
    if not assignments:
        return ""
    raw = bytes(int(value, 0) & 0xFF for value in assignments)
    text = raw.rstrip(b"\x00").decode("ascii", errors="replace")
    return text if is_readable(text) else ""


def first_store_offset(text: str) -> str:
    match = re.search(r"\+\s*(0x[0-9A-Fa-f]+|\d+)\)\s*=\s*0", text)
    return str(int(match.group(1), 0)) if match else ""


def first_required_length(text: str) -> str:
    for value in re.findall(r"==\s*(\d+)", text):
        number = int(value)
        if 0 < number <= 256:
            return value
    return ""


def interesting_strings(strings: list[str], limit: int) -> list[str]:
    out: list[str] = []
    for text in strings:
        if not text:
            continue
        if len(text.strip()) == 0:
            continue
        if len(text) > 260:
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_identifier(name: str) -> str:
    cleaned = re.sub(r"\W+", "_", name).strip("_")
    if not cleaned:
        return "recovered_function"
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned


def c_comment(text: str) -> str:
    return text.replace("*/", "* /").replace("\n", "\\n")[:240]


def c_string(text: str) -> str:
    out = ['"']
    for char in text:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif code == 0x1B:
            out.append("\\x1b")
        elif code < 32 or code == 127:
            out.append(f"\\x{code:02x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


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
    support_count = len(logic.get("support_functions", []))
    noise_count = len(logic["noise_functions"])
    lines.append(f"- Core functions identified: {core_count}")
    lines.append(f"- Support/helper functions identified: {support_count}")
    lines.append(f"- Noise/runtime functions filtered: {noise_count}")
    disassembly_features = logic.get("disassembly_features", [])
    if disassembly_features:
        lines.append(f"- Disassembly-only features recovered: {len(disassembly_features)}")
    packer_notes = logic.get("packer_notes", {})
    if isinstance(packer_notes, dict) and packer_notes.get("likely_packed_stub"):
        lines.append("- Packed/stub-like binary detected: heuristic output may describe the packer stub unless unpacking succeeds.")
        for indicator in packer_notes.get("indicators", [])[:5]:
            lines.append(f"  - {indicator}")
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
    if logic.get("support_functions"):
        lines.extend(["", "## Support Functions"])
        for item in logic["support_functions"]:
            lines.append(f"- `{item['original_name']}` -> `{item['suggested_name']}` at `{item['address']}`")
            for reason in item["reasons"][:2]:
                lines.append(f"  - {reason}")
    if disassembly_features:
        lines.extend(["", "## Disassembly Features"])
        for feature in disassembly_features:
            if isinstance(feature, dict) and feature.get("kind") == "syscall_write_immediate_string":
                lines.append("- syscall write of inline immediate string")
                lines.append(f"  - string: {feature.get('string')!r}")
                lines.append(f"  - length: {feature.get('length')}")
    lines.extend(["", "## Resolved Data"])
    if data_values:
        shown = False
        for ref, value in data_values.items():
            decoded = best_decoded_value(value)
            if decoded:
                shown = True
                lines.append(f"- `{ref}`: {decoded!r}")
        if not shown:
            lines.append("- No readable `DAT_*` references resolved from objdump bytes.")
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


def strip_string_literals(text: str) -> str:
    return STRING_RE.sub('""', text)


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
