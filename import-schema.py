#!/usr/bin/env python3
"""
import-schema.py — Import dezlock-dump JSON export into s2-framework generated SDK

Reads dezlock-dump's all-modules.json and generates:
  games/{game}/sdk/generated/
    _all-offsets.hpp     — Master offset constants for every class
    _all-enums.hpp       — All enums as enum class
    {module}/
      {ClassName}.hpp    — Padded struct with static_asserts

Usage:
  python tools/import-schema.py --game deadlock --json path/to/dezlock-export.json
  python tools/import-schema.py --game deadlock --dir path/to/schema-dump/
  python tools/import-schema.py --game deadlock  # auto-detect from %TEMP%
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# ============================================================================
# Type mapping (schema type -> C++ type)
# ============================================================================

PRIMITIVE_MAP = {
    "bool": ("bool", 1),
    "int8": ("int8_t", 1),
    "uint8": ("uint8_t", 1),
    "int16": ("int16_t", 2),
    "uint16": ("uint16_t", 2),
    "int32": ("int32_t", 4),
    "uint32": ("uint32_t", 4),
    "int64": ("int64_t", 8),
    "uint64": ("uint64_t", 8),
    "float32": ("float", 4),
    "float": ("float", 4),
    "float64": ("double", 8),
}

KNOWN_TYPES = {
    "CUtlString": ("void*", 8),
    "CUtlSymbolLarge": ("void*", 8),
    "Color": ("uint32_t", 4),
    "GameTime_t": ("float", 4),
    "GameTick_t": ("int32_t", 4),
    "QAngle": ("float[3]", 12),
    "Vector": ("float[3]", 12),
    "Vector2D": ("float[2]", 8),
    "Vector4D": ("float[4]", 16),
}


def schema_to_cpp_type(schema_type: str, size: int) -> tuple[str, bool]:
    """Returns (cpp_type, is_known). Empty string means use byte array."""
    if schema_type in PRIMITIVE_MAP:
        return PRIMITIVE_MAP[schema_type][0], True
    if schema_type in KNOWN_TYPES:
        return KNOWN_TYPES[schema_type][0], True

    # CHandle<T>, CEntityHandle<T>
    if "CHandle" in schema_type or "CEntityHandle" in schema_type:
        return "uint32_t", True

    # Pointers
    if "*" in schema_type:
        return "void*", True

    # char[N] arrays
    m = re.match(r"char\[(\d+)\]", schema_type)
    if m:
        return f"char[{m.group(1)}]", True

    # Fixed-size arrays of known types (e.g. int32[6])
    m = re.match(r"(\w+)\[(\d+)\]", schema_type)
    if m:
        base_type = m.group(1)
        count = m.group(2)
        if base_type in PRIMITIVE_MAP:
            return f"{PRIMITIVE_MAP[base_type][0]}[{count}]", True
        if base_type == "GameTime_t":
            return f"float[{count}]", True
        if base_type == "GameTick_t":
            return f"int32_t[{count}]", True

    return "", False


# ============================================================================
# JSON loading (handles dezlock-dump's sometimes-broken escapes)
# ============================================================================

def _strip_static_fields(raw: bytes) -> bytes:
    """Remove all "static_fields": [...] sections from raw JSON bytes.

    This operates on raw bytes before text decoding because the static_fields
    arrays contain binary garbage (raw memory pointers with 0x22/quote bytes
    embedded mid-string) that break both text decoders and regex parsers.

    Strategy: find each `"static_fields"` key, then scan forward for the
    closing `]` that sits at the correct indentation level (the line pattern
    `\\n          ]` — newline + 10 spaces + bracket). Simple bracket-depth
    counting won't work because the binary garbage contains literal [ and ] bytes.
    """
    marker = b'"static_fields"'
    # The closing bracket pattern: \r\n + 10 spaces + ]
    close_pattern = b"\n          ]"
    result = bytearray()
    pos = 0

    while pos < len(raw):
        idx = raw.find(marker, pos)
        if idx == -1:
            result.extend(raw[pos:])
            break

        # Find the comma before "static_fields" (skip whitespace)
        comma_pos = idx - 1
        while comma_pos > pos and raw[comma_pos] in (0x20, 0x09, 0x0A, 0x0D):
            comma_pos -= 1

        # Write everything up to (but not including) the comma
        if raw[comma_pos] == ord(","):
            result.extend(raw[pos:comma_pos])
        else:
            result.extend(raw[pos:idx])

        # Find the closing bracket by searching for the indentation pattern
        bracket_start = raw.find(b"[", idx + len(marker))
        if bracket_start == -1:
            pos = idx + len(marker)
            continue

        close_idx = raw.find(close_pattern, bracket_start)
        if close_idx == -1:
            # Couldn't find close — skip to next class boundary
            # Look for the next `\n        {` or `\n      ]` (class/module end)
            fallback = raw.find(b"\n        }", bracket_start)
            if fallback == -1:
                fallback = raw.find(b"\n      ]", bracket_start)
            if fallback == -1:
                pos = bracket_start  # give up, include remaining
                continue
            pos = fallback
            continue

        # Skip past the closing bracket + ]
        pos = close_idx + len(close_pattern)

    return bytes(result)


def load_json(path: str) -> dict:
    """Load dezlock-dump JSON export.

    Tries clean UTF-8 parse first (works if dezlock-dump was built with the
    seh_read_string + is_json_safe fixes). Falls back to byte-level sanitization
    for older exports that have binary garbage in static_fields.
    """
    # Fast path: try clean parse
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("  (clean parse failed, applying byte-level sanitization...)")

    # Slow path: strip static_fields + sanitize
    with open(path, "rb") as f:
        raw = f.read()

    raw = _strip_static_fields(raw)
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', text)
    text = re.sub(r'\\([^"\\/bfnrtu])', r'\1', text)

    return json.loads(text, strict=False)


# ============================================================================
# Code generation
# ============================================================================

def make_guard(name: str) -> str:
    guard = "SDK_GEN_" + name.upper()
    guard = re.sub(r"[^A-Z0-9_]", "_", guard)
    return guard + "_HPP"


def emit_field(f: dict, cursor: int, lines: list[str]) -> int:
    """Emit a single field with padding. Returns new cursor position."""
    offset = f["offset"]
    size = f["size"]
    name = f["name"]
    schema_type = f["type"]

    # Padding gap
    if offset > cursor:
        gap = offset - cursor
        lines.append(f"    uint8_t _pad{cursor:04X}[0x{gap:X}];")

    cpp_type, known = schema_to_cpp_type(schema_type, size)
    meta = f.get("metadata", [])
    meta_str = " ".join(f"[{m}]" for m in meta) if meta else ""
    comment = f"// 0x{offset:X} ({schema_type}, {size})"
    if meta_str:
        comment += f" {meta_str}"

    if known and cpp_type:
        bracket = cpp_type.find("[")
        if bracket != -1:
            base = cpp_type[:bracket]
            arr = cpp_type[bracket:]
            lines.append(f"    {base} {name}{arr}; {comment}")
        else:
            lines.append(f"    {cpp_type} {name}; {comment}")
    elif size > 0:
        lines.append(f"    uint8_t {name}[0x{size:X}]; {comment}")
    else:
        lines.append(f"    // 0x{offset:X} {name} ({schema_type}) — unknown size")
        return cursor  # don't advance

    return offset + size if size > 0 else offset


def generate_struct_header(cls: dict, module_name: str, class_lookup: dict,
                           timestamp: str) -> str:
    """Generate a complete .hpp file for one class."""
    name = cls["name"]
    size = cls["size"]
    parent = cls.get("parent")
    fields = sorted(cls.get("fields", []), key=lambda f: f["offset"])

    has_parent = parent and parent in class_lookup
    parent_size = class_lookup[parent]["size"] if has_parent else 0

    guard = make_guard(name)
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// Class: {name}")
    lines.append(f"// Module: {module_name}")
    lines.append(f"// Size: 0x{size:X} ({size} bytes)")
    if parent:
        lines.append(f"// Parent: {parent}")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"#include <cstddef>")
    if has_parent:
        safe_parent = parent.replace("::", "__")
        lines.append(f'#include "{safe_parent}.hpp"')
    lines.append(f"")

    # Struct definition
    if has_parent:
        lines.append(f"#pragma pack(push, 1)")
        lines.append(f"struct {name} : {parent} {{")
    else:
        lines.append(f"#pragma pack(push, 1)")
        lines.append(f"struct {name} {{")

    cursor = parent_size if has_parent else 0
    emitted_fields = []

    for f in fields:
        if f["offset"] < cursor:
            continue  # skip inherited fields
        cursor = emit_field(f, cursor, lines)
        emitted_fields.append(f)

    # Pad to class size
    if cursor < size:
        lines.append(f"    uint8_t _padEnd[0x{size - cursor:X}];")

    lines.append(f"}};")
    lines.append(f"#pragma pack(pop)")
    lines.append(f"")

    # static_asserts
    lines.append(f"static_assert(sizeof({name}) == 0x{size:X}, \"{name} size\");")
    for f in emitted_fields:
        fname = f["name"]
        foff = f["offset"]
        lines.append(f"static_assert(offsetof({name}, {fname}) == 0x{foff:X}, \"{fname}\");")

    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


def generate_all_offsets(modules: list[dict], game: str, timestamp: str) -> str:
    """Generate _all-offsets.hpp with every class from every module."""
    guard = make_guard(f"{game}_all_offsets")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// All class field offsets from runtime schema dump")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"")
    lines.append(f"namespace {game}::generated::offsets {{")
    lines.append(f"")

    total_classes = 0
    total_fields = 0

    for mod in modules:
        mod_name = mod["name"].replace(".dll", "")
        classes = sorted(mod.get("classes", []), key=lambda c: c["name"])

        for cls in classes:
            fields = cls.get("fields", [])
            if not fields:
                continue

            total_classes += 1
            lines.append(f"namespace {cls['name']} {{")

            sorted_fields = sorted(fields, key=lambda f: f["offset"])
            for f in sorted_fields:
                total_fields += 1
                comment = f"// {f['type']} ({f['size']}b)"
                lines.append(
                    f"    constexpr uint32_t {f['name']} = 0x{f['offset']:X}; {comment}"
                )

            lines.append(f"}} // {cls['name']}")
            lines.append(f"")

    lines.append(f"}} // namespace {game}::generated::offsets")
    lines.append(f"")
    lines.append(f"// Total: {total_classes} classes, {total_fields} fields")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


def sanitize_cpp_identifier(name: str) -> str | None:
    """Sanitize a class name into a valid C++ identifier.

    Returns None if the name is too mangled to be useful (template
    instantiations with ?$ prefix, names with only special chars, etc.)
    """
    # Skip MSVC mangled template names (still have ?$ prefix)
    if name.startswith("?$") or name.startswith("?"):
        return None

    # Replace common invalid chars
    s = name.replace("::", "__").replace("<", "_").replace(">", "_")
    s = s.replace(",", "_").replace(" ", "_").replace("&", "_").replace("*", "_")

    # Strip any remaining non-identifier chars
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)

    # Collapse multiple underscores and strip trailing
    s = re.sub(r"_+", "_", s).strip("_")

    if not s or not s[0].isalpha() and s[0] != "_":
        s = "_" + s

    return s if s else None


def generate_all_vtables(modules: list[dict], game: str, timestamp: str) -> str:
    """Generate _all-vtables.hpp with vtable RVAs and function indices."""
    guard = make_guard(f"{game}_all_vtables")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// All vtable RVAs and virtual function indices from RTTI scan")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"")
    lines.append(f"namespace {game}::generated::vtables {{")
    lines.append(f"")

    total_classes = 0
    total_funcs = 0
    skipped = 0

    for mod in modules:
        vtables = mod.get("vtables", [])
        if not vtables:
            continue

        for vt in sorted(vtables, key=lambda v: v["class"]):
            class_name = vt["class"]
            vtable_rva = vt["vtable_rva"]
            funcs = vt.get("functions", [])

            if not funcs:
                continue

            safe_name = sanitize_cpp_identifier(class_name)
            if not safe_name:
                skipped += 1
                continue

            total_classes += 1
            comment = f" // {class_name}" if safe_name != class_name else ""
            lines.append(f"namespace {safe_name} {{{comment}")
            lines.append(f"    constexpr uint32_t vtable_rva = {vtable_rva};")
            lines.append(f"    constexpr int entry_count = {len(funcs)};")
            lines.append(f"    namespace fn {{")

            for func in funcs:
                idx = func["index"]
                rva = func["rva"]
                total_funcs += 1
                lines.append(f"        constexpr int idx_{idx} = {idx}; // rva={rva}")

            lines.append(f"    }}")
            lines.append(f"}} // {safe_name}")
            lines.append(f"")

    lines.append(f"}} // namespace {game}::generated::vtables")
    lines.append(f"")
    lines.append(f"// Total: {total_classes} vtables, {total_funcs} virtual functions")
    if skipped:
        lines.append(f"// Skipped: {skipped} classes with unrepresentable names (templates, mangled)")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


def generate_all_enums(modules: list[dict], game: str, timestamp: str) -> str:
    """Generate _all-enums.hpp with all enums from all modules."""
    guard = make_guard(f"{game}_all_enums")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// All enums from runtime schema dump")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"")
    lines.append(f"namespace {game}::generated::enums {{")
    lines.append(f"")

    total = 0
    for mod in modules:
        for en in sorted(mod.get("enums", []), key=lambda e: e["name"]):
            total += 1
            sz = en.get("size", 4)
            underlying = {1: "uint8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(
                sz, "int32_t"
            )
            lines.append(f"enum class {en['name']} : {underlying} {{")
            for v in en.get("values", []):
                lines.append(f"    {v['name']} = {v['value']},")
            lines.append(f"}};")
            lines.append(f"")

    lines.append(f"}} // namespace {game}::generated::enums")
    lines.append(f"")
    lines.append(f"// Total: {total} enums")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


# ============================================================================
# Main
# ============================================================================

def find_json_path(args) -> str:
    """Resolve JSON input path from args or auto-detect."""
    if args.json:
        return args.json

    if args.dir:
        candidate = os.path.join(args.dir, "all-modules.json")
        if os.path.exists(candidate):
            return candidate
        # Try dezlock-export.json in the dir
        candidate = os.path.join(args.dir, "dezlock-export.json")
        if os.path.exists(candidate):
            return candidate
        print(f"ERROR: No JSON found in {args.dir}")
        sys.exit(1)

    # Auto-detect from %TEMP%
    temp = os.environ.get("TEMP", os.environ.get("TMP", "/tmp"))
    candidate = os.path.join(temp, "dezlock-export.json")
    if os.path.exists(candidate):
        return candidate

    print("ERROR: No JSON path specified and no dezlock-export.json in %TEMP%")
    print("Usage: python tools/import-schema.py --game deadlock --json path/to/export.json")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Import dezlock-dump schema into s2-framework")
    parser.add_argument("--game", required=True, help="Game name (e.g. deadlock)")
    parser.add_argument("--json", help="Path to dezlock-export.json or all-modules.json")
    parser.add_argument("--dir", help="Path to schema-dump directory containing all-modules.json")
    parser.add_argument("--modules", help="Comma-separated module filter (e.g. client,server)")
    args = parser.parse_args()

    json_path = find_json_path(args)
    print(f"Loading {json_path}...")

    data = load_json(json_path)
    timestamp = data.get("timestamp", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))

    modules = data.get("modules", [])
    if not modules:
        print("ERROR: No modules found in JSON")
        sys.exit(1)

    # Optional module filter
    if args.modules:
        allowed = set(m.strip() for m in args.modules.split(","))
        # Match with or without .dll
        modules = [
            m for m in modules
            if m["name"] in allowed or m["name"].replace(".dll", "") in allowed
        ]

    # Resolve output directory relative to this script
    script_dir = Path(__file__).parent.parent  # internal-v2/
    out_dir = script_dir / "shared" / "sdk" / "generated"

    print(f"Output: {out_dir}")
    print(f"Modules: {len(modules)}")
    print(f"Total classes: {data.get('total_classes', '?')}")
    print(f"Total fields: {data.get('total_fields', '?')}")
    print(f"Total enums: {data.get('total_enums', '?')}")
    print()

    # Ensure output dirs exist
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build global class lookup (for parent resolution across modules)
    global_lookup = {}
    for mod in modules:
        for cls in mod.get("classes", []):
            global_lookup[cls["name"]] = cls

    # Generate per-module struct headers
    total_structs = 0
    for mod in modules:
        mod_name = mod["name"].replace(".dll", "")
        classes = mod.get("classes", [])
        if not classes:
            continue

        mod_dir = out_dir / mod_name
        mod_dir.mkdir(exist_ok=True)

        mod_count = 0
        for cls in sorted(classes, key=lambda c: c["name"]):
            if cls["size"] <= 0:
                continue
            if not cls.get("fields"):
                continue

            header = generate_struct_header(cls, mod["name"], global_lookup, timestamp)
            # Sanitize filename (:: is invalid on Windows)
            safe_name = cls["name"].replace("::", "__")
            filepath = mod_dir / f"{safe_name}.hpp"
            filepath.write_text(header, encoding="utf-8")
            mod_count += 1

        total_structs += mod_count
        print(f"  {mod['name']:30s}  {mod_count:4d} structs")

    # Generate _all-offsets.hpp
    offsets_content = generate_all_offsets(modules, args.game, timestamp)
    offsets_path = out_dir / "_all-offsets.hpp"
    offsets_path.write_text(offsets_content, encoding="utf-8")

    # Count for summary
    offset_lines = offsets_content.count("constexpr uint32_t")
    print(f"\n  _all-offsets.hpp: {offset_lines} offset constants")

    # Generate _all-enums.hpp
    enums_content = generate_all_enums(modules, args.game, timestamp)
    enums_path = out_dir / "_all-enums.hpp"
    enums_path.write_text(enums_content, encoding="utf-8")

    enum_count = enums_content.count("enum class ")
    print(f"  _all-enums.hpp: {enum_count} enums")

    # Generate _all-vtables.hpp
    vtables_content = generate_all_vtables(modules, args.game, timestamp)
    vtables_path = out_dir / "_all-vtables.hpp"
    vtables_path.write_text(vtables_content, encoding="utf-8")

    vtable_count = vtables_content.count("constexpr uint32_t vtable_rva")
    vtable_func_count = vtables_content.count("constexpr int idx_")
    print(f"  _all-vtables.hpp: {vtable_count} vtables, {vtable_func_count} functions")

    print(f"\nDone! {total_structs} struct headers generated.")
    print(f"Output: {out_dir}")


if __name__ == "__main__":
    main()
