#!/usr/bin/env python3
"""
generate-signatures.py — Generate byte pattern signatures from dezlock-dump JSON.

Reads the vtable function prologue bytes (128 bytes each) captured by
dezlock-dump across 58+ DLLs, masks relocatable bytes (relative calls,
jumps, RIP-relative addressing), and outputs IDA/x64dbg-style pattern
strings with variable-length uniqueness.

Features:
  - Stub detection: trivial stubs (xor+ret, ret, mov+ret, etc.) labeled [STUB:type]
  - RVA deduplication: COMDAT-folded functions sharing the same address grouped together
  - Per-class uniqueness: [CLASS_UNIQUE] for functions unique within their class vtable
  - Module-level uniqueness: trimmed to shortest unique prefix per module
  - Improved masking: E8/E9/Jcc/RIP-relative + FF 15/FF 25 indirect call/jmp

Usage:
    python generate-signatures.py --json bin/schema-dump/all-modules.json
    python generate-signatures.py --json bin/schema-dump/all-modules.json --class CCitadelInput
    python generate-signatures.py --json bin/schema-dump/all-modules.json --module panorama.dll
    python generate-signatures.py --json bin/schema-dump/all-modules.json --min-length 8
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


# =============================================================================
# Stub detection
# =============================================================================

# Stub patterns: (byte_sequence, label)
# Matched against raw (unmasked) bytes at function start
STUB_PATTERNS = [
    (bytes([0xC3]),                         "ret"),
    (bytes([0x33, 0xC0, 0xC3]),            "xor_eax_ret"),
    (bytes([0x32, 0xC0, 0xC3]),            "xor_al_ret"),
    (bytes([0x0F, 0x57, 0xC0, 0xC3]),      "xorps_ret"),
    (bytes([0xB0, 0x00, 0xC3]),            "mov_al_0_ret"),
    (bytes([0xB0, 0x01, 0xC3]),            "mov_al_1_ret"),
    (bytes([0xCC]),                         "int3"),
]


def detect_stub(raw_bytes: list[int]) -> str | None:
    """
    Detect trivial function stubs by matching raw bytes.
    Returns stub type string or None.
    """
    if not raw_bytes:
        return None

    raw = bytes(raw_bytes)

    # Check fixed patterns first
    for pattern, label in STUB_PATTERNS:
        if raw[:len(pattern)] == pattern:
            return label

    # B8 xx xx xx xx C3 — mov eax, imm32; ret
    if len(raw) >= 6 and raw[0] == 0xB8 and raw[5] == 0xC3:
        return "mov_eax_imm_ret"

    # 48 8D 05 xx xx xx xx C3 — lea rax, [rip+disp32]; ret
    if len(raw) >= 8 and raw[0] == 0x48 and raw[1] == 0x8D and raw[2] == 0x05 and raw[7] == 0xC3:
        return "lea_rax_ret"

    # All CC bytes (int3 padding / dead code)
    if all(b == 0xCC for b in raw_bytes[:8]):
        return "int3_pad"

    return None


# =============================================================================
# Byte masking
# =============================================================================

def mask_relocatable_bytes(raw_bytes: list[int]) -> list[str]:
    """
    Mask bytes that are likely to change between builds (relocations).

    Rules:
    - E8 xx xx xx xx  — relative CALL
    - E9 xx xx xx xx  — relative JMP
    - 0F 8x xx xx xx xx — conditional Jcc near (0F 80..0F 8F)
    - FF 15 xx xx xx xx — indirect CALL via [RIP+disp32]
    - FF 25 xx xx xx xx — indirect JMP via [RIP+disp32]
    - RIP-relative: ModRM with mod=00, r/m=101 -> mask next 4 disp bytes
      Covers LEA, MOV, CMP, MOVSS, etc. with RIP-relative addressing.
    """
    n = len(raw_bytes)
    result = [f"{b:02X}" for b in raw_bytes]
    i = 0

    while i < n:
        b = raw_bytes[i]

        # --- Relative CALL (E8) or JMP (E9) ---
        if b in (0xE8, 0xE9) and i + 4 < n:
            for j in range(1, 5):
                result[i + j] = "?"
            i += 5
            continue

        # --- Conditional Jcc near: 0F 80..0F 8F ---
        if b == 0x0F and i + 1 < n and 0x80 <= raw_bytes[i + 1] <= 0x8F:
            if i + 5 < n:
                for j in range(2, 6):
                    result[i + j] = "?"
                i += 6
                continue

        # --- FF 15 (indirect CALL [RIP+disp32]) / FF 25 (indirect JMP [RIP+disp32]) ---
        if b == 0xFF and i + 1 < n and raw_bytes[i + 1] in (0x15, 0x25):
            if i + 5 < n:
                for j in range(2, 6):
                    result[i + j] = "?"
                i += 6
                continue

        # --- REX prefix detection ---
        pos = i
        if 0x40 <= b <= 0x4F:
            pos += 1
            if pos >= n:
                i += 1
                continue

        opcode = raw_bytes[pos] if pos < n else 0

        # Check for two-byte opcode (0F xx)
        if opcode == 0x0F and pos + 1 < n:
            modrm_pos = pos + 2
        else:
            modrm_pos = pos + 1

        # --- RIP-relative addressing detection ---
        # ModRM byte: mod=00 (bits 7-6), r/m=101 (bits 2-0)
        # This encodes [RIP + disp32] in x64
        if modrm_pos < n:
            modrm = raw_bytes[modrm_pos]
            mod = (modrm >> 6) & 3
            rm = modrm & 7

            if mod == 0 and rm == 5:
                disp_start = modrm_pos + 1
                if disp_start + 3 < n:
                    for j in range(4):
                        result[disp_start + j] = "?"
                    i = disp_start + 4
                    continue

        i += 1

    return result


def pattern_to_string(tokens: list[str]) -> str:
    """Convert pattern token list to space-separated string."""
    return " ".join(tokens)


def trim_trailing_wildcards(pattern: list[str]) -> list[str]:
    """Remove trailing wildcard bytes that add no matching value."""
    while pattern and pattern[-1] == "?":
        pattern.pop()
    return pattern


def parse_hex_bytes(hex_str: str) -> list[int]:
    """Parse a hex string like '4889742408...' into byte list."""
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]


# =============================================================================
# Uniqueness computation
# =============================================================================

def find_divergence(a: list[str], b: list[str]) -> int:
    """
    Find the index where two token lists first differ.
    Returns len if they're identical up to the shorter one's length.
    """
    limit = min(len(a), len(b))
    for i in range(limit):
        if a[i] != b[i]:
            return i
    return limit


def compute_unique_prefixes(entries: list[dict], min_length: int) -> None:
    """
    For each entry, compute the shortest prefix of its masked pattern
    that is unique among all entries. Uses sorted-neighbor comparison.

    Modifies entries in-place: sets 'unique_length' and 'unique' fields.
    """
    if not entries:
        return

    indexed = []
    for i, e in enumerate(entries):
        tokens = e["_tokens"]
        indexed.append((tokens, i))

    indexed.sort(key=lambda x: x[0])

    unique_lengths = [0] * len(entries)

    for si in range(len(indexed)):
        tokens, orig_idx = indexed[si]
        needed = min_length

        if si > 0:
            prev_tokens = indexed[si - 1][0]
            div = find_divergence(tokens, prev_tokens)
            needed = max(needed, div + 1)

        if si < len(indexed) - 1:
            next_tokens = indexed[si + 1][0]
            div = find_divergence(tokens, next_tokens)
            needed = max(needed, div + 1)

        unique_lengths[orig_idx] = needed

    for i, e in enumerate(entries):
        tokens = e["_tokens"]
        ul = unique_lengths[i]

        if ul <= len(tokens):
            e["unique"] = True
            e["unique_length"] = ul
            e["pattern"] = pattern_to_string(tokens[:ul])
        else:
            e["unique"] = False
            e["unique_length"] = len(tokens)
            e["pattern"] = pattern_to_string(tokens)


def compute_class_uniqueness(class_entries: list[dict], min_length: int) -> None:
    """
    Compute per-class uniqueness: is each function's pattern unique within
    its own class's vtable? A class-unique function is perfectly hookable
    even if another class happens to share the same pattern.

    Modifies entries in-place: sets 'class_unique' field.
    """
    # Filter to non-stub entries that have tokens
    candidates = [e for e in class_entries if not e.get("stub") and "_tokens" in e]

    if len(candidates) <= 1:
        for e in candidates:
            e["class_unique"] = True
        return

    indexed = [(e["_tokens"], i) for i, e in enumerate(candidates)]
    indexed.sort(key=lambda x: x[0])

    class_unique_flags = [True] * len(candidates)

    for si in range(len(indexed)):
        tokens, orig_idx = indexed[si]

        if si > 0:
            prev_tokens = indexed[si - 1][0]
            if tokens == prev_tokens:
                class_unique_flags[orig_idx] = False
                class_unique_flags[indexed[si - 1][1]] = False

        if si < len(indexed) - 1:
            next_tokens = indexed[si + 1][0]
            if tokens == next_tokens:
                class_unique_flags[orig_idx] = False
                class_unique_flags[indexed[si + 1][1]] = False

    for i, e in enumerate(candidates):
        e["class_unique"] = class_unique_flags[i]


# =============================================================================
# Module processing
# =============================================================================

def process_module(module_data: dict, args) -> dict:
    """
    Process a single module's vtables into signatures with:
    - Stub detection
    - RVA deduplication (COMDAT folding)
    - Module-level unique prefixes
    - Per-class uniqueness

    Returns dict: {class_name: [entry, ...]}
    """
    vtables = module_data.get("vtables", [])
    if not vtables:
        return {}

    # First pass: generate all masked patterns, detect stubs, track RVAs
    all_entries = []
    rva_to_entries: dict[str, list[dict]] = {}  # RVA -> list of entries sharing it

    for vt in vtables:
        class_name = vt.get("class", "")
        if args.class_filter and class_name != args.class_filter:
            continue

        for func in vt.get("functions", []):
            hex_bytes = func.get("bytes")
            if not hex_bytes:
                continue

            raw = parse_hex_bytes(hex_bytes)
            if len(raw) < args.min_length:
                continue

            # Skip all-zero bytes (failed reads)
            if all(b == 0 for b in raw):
                continue

            rva = func.get("rva", "0x0")

            entry = {
                "class": class_name,
                "index": func["index"],
                "rva": rva,
                "byte_count": len(raw),
            }

            # Stub detection (on raw bytes, before masking)
            stub_type = detect_stub(raw)
            if stub_type:
                entry["stub"] = True
                entry["stub_type"] = stub_type
                entry["unique"] = False
                entry["class_unique"] = False
                entry["unique_length"] = 0
                entry["pattern"] = pattern_to_string([f"{b:02X}" for b in raw[:8]])
                entry["shared_with"] = []
                all_entries.append(entry)

                # Track RVA for sharing info
                rva_key = rva
                if rva_key not in rva_to_entries:
                    rva_to_entries[rva_key] = []
                rva_to_entries[rva_key].append(entry)
                continue

            masked = mask_relocatable_bytes(raw)
            masked = trim_trailing_wildcards(masked)

            if len(masked) < args.min_length:
                continue

            entry["_tokens"] = masked
            entry["stub"] = False
            entry["stub_type"] = None
            entry["shared_with"] = []
            entry["class_unique"] = False

            all_entries.append(entry)

            # Track RVA for COMDAT dedup
            rva_key = rva
            if rva_key not in rva_to_entries:
                rva_to_entries[rva_key] = []
            rva_to_entries[rva_key].append(entry)

    if not all_entries:
        return {}

    # RVA deduplication: populate shared_with lists
    for rva_key, entries_for_rva in rva_to_entries.items():
        if len(entries_for_rva) <= 1:
            continue
        for entry in entries_for_rva:
            others = [
                f"{e['class']}::idx_{e['index']}"
                for e in entries_for_rva
                if e is not entry
            ]
            entry["shared_with"] = others[:5]  # cap at 5 to keep output manageable

    # For module-level uniqueness, deduplicate by RVA:
    # pick one representative per RVA for the uniqueness computation
    seen_rvas = set()
    deduped_entries = []
    rva_to_representative: dict[str, dict] = {}

    for e in all_entries:
        if e.get("stub"):
            continue
        rva_key = e["rva"]
        if rva_key not in seen_rvas:
            seen_rvas.add(rva_key)
            deduped_entries.append(e)
            rva_to_representative[rva_key] = e

    # Compute module-level uniqueness on deduplicated set
    compute_unique_prefixes(deduped_entries, args.min_length)

    # Propagate uniqueness from representative to all entries sharing that RVA
    for e in all_entries:
        if e.get("stub"):
            continue
        rva_key = e["rva"]
        rep = rva_to_representative.get(rva_key)
        if rep and rep is not e:
            e["unique"] = rep["unique"]
            e["unique_length"] = rep["unique_length"]
            e["pattern"] = rep["pattern"]

    # Group by class for per-class uniqueness
    by_class: dict[str, list[dict]] = {}
    for e in all_entries:
        cls = e["class"]
        if cls not in by_class:
            by_class[cls] = []
        by_class[cls].append(e)

    # Compute per-class uniqueness
    for class_entries in by_class.values():
        compute_class_uniqueness(class_entries, args.min_length)

    # Sort each class's entries by index
    for entries in by_class.values():
        entries.sort(key=lambda e: e["index"])

    # Clean up internal field
    for e in all_entries:
        e.pop("_tokens", None)

    return by_class


# =============================================================================
# Output
# =============================================================================

def write_text_output(module_name: str, signatures: dict, output_dir: str):
    """Write greppable text file for a module."""
    clean_name = module_name.replace(".dll", "")
    path = os.path.join(output_dir, f"{clean_name}.txt")

    total = 0
    unique = 0
    class_unique_count = 0
    stub_count = 0
    dup = 0

    with open(path, "w") as f:
        f.write(f"# {module_name} — Virtual function signatures\n")
        f.write(f"# Generated by generate-signatures.py\n")
        f.write(f"# Format: ClassName::idx_N  <pattern>  [markers]\n")
        f.write(f"#   ? = masked byte (relocation)\n")
        f.write(f"#   [DUP] = not uniquely signable at module or class level\n")
        f.write(f"#   [CLASS_UNIQUE] = unique within class vtable (hookable)\n")
        f.write(f"#   [STUB:type] = trivial stub function\n")
        f.write(f"#   # shared: ... = COMDAT-folded, same RVA as listed functions\n")
        f.write(f"#   Signatures are trimmed to shortest unique prefix\n\n")

        for class_name in sorted(signatures.keys()):
            entries = signatures[class_name]
            n_unique = sum(1 for e in entries if e.get("unique"))
            n_class_unique = sum(
                1 for e in entries
                if e.get("class_unique") and not e.get("unique") and not e.get("stub")
            )
            n_stubs = sum(1 for e in entries if e.get("stub"))

            header_parts = [f"{len(entries)} functions", f"{n_unique} unique"]
            if n_class_unique:
                header_parts.append(f"{n_class_unique} class-unique")
            if n_stubs:
                header_parts.append(f"{n_stubs} stubs")

            f.write(f"# --- {class_name} ({', '.join(header_parts)}) ---\n")

            for e in entries:
                total += 1

                if e.get("stub"):
                    stub_count += 1
                    f.write(f"{class_name}::idx_{e['index']}  {e['pattern']}  "
                            f"[STUB:{e['stub_type']}]\n")
                    continue

                marker = ""
                shared_comment = ""

                if e.get("unique"):
                    unique += 1
                elif e.get("class_unique"):
                    marker = "  [CLASS_UNIQUE]"
                    class_unique_count += 1
                else:
                    marker = "  [DUP]"
                    dup += 1

                if e.get("shared_with"):
                    shared_comment = f"  # shared: {', '.join(e['shared_with'])}"

                f.write(f"{class_name}::idx_{e['index']}  {e['pattern']}"
                        f"{marker}{shared_comment}\n")

            f.write("\n")

    return total, unique, class_unique_count, stub_count, dup


def write_json_output(all_modules: dict, output_dir: str):
    """Write structured JSON with all signatures."""
    path = os.path.join(output_dir, "_all-signatures.json")

    output = {"modules": {}}

    for mod_name, signatures in all_modules.items():
        mod_out = {}
        for class_name, entries in signatures.items():
            mod_out[class_name] = [
                {
                    "index": e["index"],
                    "rva": e["rva"],
                    "pattern": e["pattern"],
                    "unique": e.get("unique", False),
                    "length": e.get("unique_length", 0),
                    "stub": e.get("stub", False),
                    "stub_type": e.get("stub_type"),
                    "class_unique": e.get("class_unique", False),
                    "shared_with": e.get("shared_with", []),
                }
                for e in entries
            ]
        output["modules"][mod_name] = mod_out

    with open(path, "w") as f:
        json.dump(output, f, indent=2)


def _process_module_task(module, class_filter, min_length, output_dir):
    """Process a single module's signatures in a worker thread."""
    mod_name = module.get("name", "unknown")
    vtables = module.get("vtables", [])
    if not vtables:
        return None

    has_bytes = any(
        func.get("bytes")
        for vt in vtables
        for func in vt.get("functions", [])
    )
    if not has_bytes:
        print(f"  {mod_name}: no bytes data (run updated dezlock-dump first)")
        return None

    print(f"  Processing {mod_name}...")

    class _Args:
        pass
    fake_args = _Args()
    fake_args.class_filter = class_filter
    fake_args.min_length = min_length

    signatures = process_module(module, fake_args)
    if not signatures:
        print(f"    {mod_name}: no signatures generated")
        return None

    total, unique, class_unique, stubs, dup = write_text_output(
        mod_name, signatures, output_dir
    )

    parts = [f"{unique} unique"]
    if class_unique:
        parts.append(f"{class_unique} class-unique")
    if stubs:
        parts.append(f"{stubs} stubs")
    parts.append(f"{dup} dup")
    print(f"    {mod_name}: {total} signatures ({', '.join(parts)})")

    return {
        "mod_name": mod_name,
        "signatures": signatures,
        "total": total,
        "unique": unique,
        "class_unique": class_unique,
        "stubs": stubs,
        "dup": dup,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate byte pattern signatures from dezlock-dump JSON"
    )
    parser.add_argument(
        "--json", required=True,
        help="Path to dezlock-dump JSON (e.g. bin/schema-dump/all-modules.json)"
    )
    parser.add_argument(
        "--output", default="bin/schema-dump/signatures",
        help="Output directory (default: bin/schema-dump/signatures/)"
    )
    parser.add_argument(
        "--module", default=None,
        help="Filter to a specific module (e.g. client.dll)"
    )
    parser.add_argument(
        "--class", dest="class_filter", default=None,
        help="Filter to a specific class (e.g. CCitadelInput)"
    )
    parser.add_argument(
        "--min-length", type=int, default=6,
        help="Minimum pattern length in bytes (default: 6)"
    )
    args = parser.parse_args()

    # Load JSON
    print(f"Loading {args.json}...")
    with open(args.json, "r") as f:
        data = json.load(f)

    modules = data.get("modules", [])
    if not modules:
        print("ERROR: No modules found in JSON", file=sys.stderr)
        sys.exit(1)

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    all_module_sigs = {}
    grand_total = 0
    grand_unique = 0
    grand_class_unique = 0
    grand_stubs = 0
    grand_dup = 0

    # Filter modules
    work_modules = [
        m for m in modules
        if not args.module or m.get("name", "unknown") == args.module
    ]

    workers = min(os.cpu_count() or 4, max(len(work_modules), 1))
    print(f"Processing {len(work_modules)} modules with {workers} threads...")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(
                _process_module_task, mod,
                args.class_filter, args.min_length, args.output
            )
            for mod in work_modules
        ]

        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            all_module_sigs[result["mod_name"]] = result["signatures"]
            grand_total += result["total"]
            grand_unique += result["unique"]
            grand_class_unique += result["class_unique"]
            grand_stubs += result["stubs"]
            grand_dup += result["dup"]

    if all_module_sigs:
        write_json_output(all_module_sigs, args.output)
        pct_unique = (grand_unique / grand_total * 100) if grand_total else 0
        pct_class = (grand_class_unique / grand_total * 100) if grand_total else 0
        pct_hookable = ((grand_unique + grand_class_unique) / grand_total * 100) if grand_total else 0
        print(f"\nTotal: {grand_total} signatures")
        print(f"  Module-unique: {grand_unique} ({pct_unique:.1f}%)")
        print(f"  Class-unique:  {grand_class_unique} ({pct_class:.1f}%)")
        print(f"  Hookable:      {grand_unique + grand_class_unique} ({pct_hookable:.1f}%)")
        print(f"  Stubs:         {grand_stubs}")
        print(f"  Duplicates:    {grand_dup}")
        print(f"Output: {args.output}/")
    else:
        print("\nNo signatures generated. Make sure the JSON contains 'bytes' fields.")
        print("Re-run dezlock-dump.exe with the updated build to capture function bytes.")


if __name__ == "__main__":
    main()
