#!/usr/bin/env python3
"""
generate-signatures.py — Generate byte pattern signatures from dezlock-dump JSON.

Reads the vtable function prologue bytes (64 bytes each) captured by
dezlock-dump across 58+ DLLs, masks relocatable bytes (relative calls,
jumps, RIP-relative addressing), and outputs IDA/x64dbg-style pattern
strings with variable-length uniqueness.

Each signature is trimmed to the shortest prefix that's unique within its
module — a function unique at 12 bytes doesn't need all 64.

Covers ~839K functions across ~23K vtables. Produces ~52K unique signatures
including key hookable classes like CSource2Client, CPanoramaUIEngine,
CSchemaSystem, CInputSystem, CNetworkSystem, CCitadelInput, etc.

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


def mask_relocatable_bytes(raw_bytes: list[int]) -> list[str]:
    """
    Mask bytes that are likely to change between builds (relocations).

    Rules:
    - E8 xx xx xx xx  — relative CALL
    - E9 xx xx xx xx  — relative JMP
    - 0F 8x xx xx xx xx — conditional Jcc near (0F 80..0F 8F)
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
    that is unique among all entries. Uses sorted-neighbor comparison:
    sort all patterns lexicographically, then each entry only needs to
    diverge from its immediate neighbors to be unique.

    Modifies entries in-place: sets 'unique_length' and 'unique' fields.
    """
    if not entries:
        return

    # Build (tokens_tuple, original_index) for sorting
    indexed = []
    for i, e in enumerate(entries):
        tokens = e["_tokens"]
        indexed.append((tokens, i))

    # Sort by token list (lexicographic)
    indexed.sort(key=lambda x: x[0])

    # For each entry in sorted order, find how many tokens needed to
    # distinguish from both neighbors
    unique_lengths = [0] * len(entries)

    for si in range(len(indexed)):
        tokens, orig_idx = indexed[si]
        needed = min_length  # always need at least min_length

        # Compare with previous neighbor
        if si > 0:
            prev_tokens = indexed[si - 1][0]
            div = find_divergence(tokens, prev_tokens)
            # Need div+1 tokens to include the diverging byte
            needed = max(needed, div + 1)

        # Compare with next neighbor
        if si < len(indexed) - 1:
            next_tokens = indexed[si + 1][0]
            div = find_divergence(tokens, next_tokens)
            needed = max(needed, div + 1)

        unique_lengths[orig_idx] = needed

    # Apply results
    for i, e in enumerate(entries):
        tokens = e["_tokens"]
        ul = unique_lengths[i]

        if ul <= len(tokens):
            # Unique at this prefix length
            e["unique"] = True
            e["unique_length"] = ul
            e["pattern"] = pattern_to_string(tokens[:ul])
        else:
            # Full pattern isn't unique (identical functions)
            e["unique"] = False
            e["unique_length"] = len(tokens)
            e["pattern"] = pattern_to_string(tokens)


def process_module(module_data: dict, args) -> dict:
    """
    Process a single module's vtables into signatures with variable-length
    unique prefixes.

    Returns dict: {class_name: [{index, rva, pattern, unique, unique_length}, ...]}
    """
    vtables = module_data.get("vtables", [])
    if not vtables:
        return {}

    # First pass: generate all masked patterns
    all_entries = []

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

            masked = mask_relocatable_bytes(raw)
            masked = trim_trailing_wildcards(masked)

            if len(masked) < args.min_length:
                continue

            all_entries.append({
                "class": class_name,
                "index": func["index"],
                "rva": func.get("rva", "0x0"),
                "_tokens": masked,  # full masked pattern as token list
                "byte_count": len(masked),
            })

    if not all_entries:
        return {}

    # Second pass: compute shortest unique prefix for each function
    compute_unique_prefixes(all_entries, args.min_length)

    # Group by class
    results = {}
    for e in all_entries:
        del e["_tokens"]  # cleanup internal field
        cls = e["class"]
        if cls not in results:
            results[cls] = []
        results[cls].append(e)

    # Sort each class's entries by index
    for entries in results.values():
        entries.sort(key=lambda e: e["index"])

    return results


def write_text_output(module_name: str, signatures: dict, output_dir: str):
    """Write greppable text file for a module."""
    clean_name = module_name.replace(".dll", "")
    path = os.path.join(output_dir, f"{clean_name}.txt")

    total = 0
    unique = 0
    dup = 0

    with open(path, "w") as f:
        f.write(f"# {module_name} — Virtual function signatures\n")
        f.write(f"# Generated by generate-signatures.py\n")
        f.write(f"# Format: ClassName::idx_N  <pattern>\n")
        f.write(f"#   ? = masked byte (relocation)\n")
        f.write(f"#   [DUP] = identical function body, not uniquely signable\n")
        f.write(f"#   Signatures are trimmed to shortest unique prefix\n\n")

        for class_name in sorted(signatures.keys()):
            entries = signatures[class_name]
            n_unique = sum(1 for e in entries if e["unique"])
            f.write(f"# --- {class_name} ({len(entries)} functions, {n_unique} unique) ---\n")
            for e in entries:
                total += 1
                marker = ""
                if not e["unique"]:
                    marker = " [DUP]"
                    dup += 1
                else:
                    unique += 1
                f.write(f"{class_name}::idx_{e['index']}  {e['pattern']}{marker}\n")
            f.write("\n")

    return total, unique, dup


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
                    "unique": e["unique"],
                    "length": e["unique_length"],
                }
                for e in entries
            ]
        output["modules"][mod_name] = mod_out

    with open(path, "w") as f:
        json.dump(output, f, indent=2)


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
    grand_dup = 0

    for module in modules:
        mod_name = module.get("name", "unknown")
        if args.module and mod_name != args.module:
            continue

        vtables = module.get("vtables", [])
        if not vtables:
            continue

        # Check if any function has bytes data
        has_bytes = any(
            func.get("bytes")
            for vt in vtables
            for func in vt.get("functions", [])
        )
        if not has_bytes:
            print(f"  {mod_name}: no bytes data (run updated dezlock-dump first)")
            continue

        print(f"  Processing {mod_name}...")
        signatures = process_module(module, args)

        if not signatures:
            print(f"    No signatures generated")
            continue

        total, unique, dup = write_text_output(mod_name, signatures, args.output)
        all_module_sigs[mod_name] = signatures

        grand_total += total
        grand_unique += unique
        grand_dup += dup

        print(f"    {total} signatures ({unique} unique, {dup} duplicates)")

    if all_module_sigs:
        write_json_output(all_module_sigs, args.output)
        pct = (grand_unique / grand_total * 100) if grand_total else 0
        print(f"\nTotal: {grand_total} signatures ({grand_unique} unique [{pct:.1f}%], {grand_dup} duplicates)")
        print(f"Output: {args.output}/")
    else:
        print("\nNo signatures generated. Make sure the JSON contains 'bytes' fields.")
        print("Re-run dezlock-dump.exe with the updated build to capture function bytes.")


if __name__ == "__main__":
    main()
