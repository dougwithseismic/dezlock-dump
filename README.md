# dezlock-dump

[![Discord](https://img.shields.io/discord/1469694564683088168?color=5865F2&logo=discord&logoColor=white&label=Discord)](https://discord.gg/sjcsVkE8ur)

> **Join the community!** Got questions, want to share your setups, or just hang out? Jump into our Discord:
>
> **[discord.gg/sjcsVkE8ur](https://discord.gg/sjcsVkE8ur)**

---

Runtime schema + RTTI + vtable + signature extraction tool for Source 2 games (Deadlock, CS2, Dota 2). Injects a minimal worker DLL into a running game process and dumps the complete class hierarchy, field offsets, metadata annotations, static fields, enums, inheritance chains, **every virtual function table**, and **pattern signatures** for all virtual functions.

No source2gen required — reads directly from the game's `SchemaSystem` and MSVC x64 RTTI at runtime.

**Scans every loaded DLL** — walks all modules for schema data (client.dll, server.dll, engine2.dll, etc.) and RTTI vtables (panorama.dll, tier0.dll, inputsystem.dll, networksystem.dll, schemasystem.dll, and 50+ more).

## Output

For each module with schema data (e.g. `client.dll` → `client`), output is organized per-game:

| File | Format | Description |
|------|--------|-------------|
| `schema-dump/<game>/<module>.txt` | Greppable text | Every class + field with offsets and metadata |
| `schema-dump/<game>/<module>-flat.txt` | Flattened text | Inherited fields resolved per entity class |
| `schema-dump/<game>/<module>-enums.txt` | Greppable text | Every enum + enumerator values |
| `schema-dump/<game>/<module>/hierarchy/` | Tree | Per-class files organized by inheritance |
| `schema-dump/<game>/all-modules.json` | JSON | Full structured export for tooling (all modules) |

For signature generation (all modules with vtables):

| File | Format | Description |
|------|--------|-------------|
| `bin/schema-dump/signatures/<module>.txt` | Greppable text | Pattern signatures per function |
| `bin/schema-dump/signatures/_all-signatures.json` | JSON | Structured signatures for tooling |

Additionally, `%TEMP%\dezlock-export.json` contains the complete JSON export with vtable data and function bytes.

## Quick Start

### Pre-built (Releases)

1. Download `dezlock-dump.zip` from [Releases](../../releases)
2. Launch your Source 2 game and enter a match or lobby
3. Run as administrator:

```bash
# Deadlock (default)
dezlock-dump.exe --all

# CS2
dezlock-dump.exe --process cs2.exe --all

# Dota 2
dezlock-dump.exe --process dota2.exe --all
```

This dumps schema + generates SDK headers + pattern signatures in one shot. Output lands in `schema-dump/<game>/` next to the exe (e.g. `schema-dump/deadlock/`, `schema-dump/cs2/`).

> **Note:** The schema dump itself finishes in seconds, but SDK header generation (`--headers`) and especially signature generation (`--signatures` / `--all`) can take **several minutes** — the signature pass processes 800k+ virtual functions (128 bytes each) across 58+ DLLs. Let it run, don't close the window early.

### Build from Source

Requires Visual Studio 2022 (any edition with C++ desktop workload).

```bat
build.bat
```

Produces `bin/dezlock-dump.exe` and `bin/dezlock-worker.dll`.

## Usage

```
dezlock-dump.exe [--process <name>] [--output <dir>] [--wait <seconds>] [--headers] [--signatures] [--all]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--process <name>` | `deadlock.exe` | Target process (e.g. `cs2.exe`, `dota2.exe`) |
| `--output <dir>` | `schema-dump/<game>/` next to exe | Output directory (auto per-game) |
| `--wait <seconds>` | `30` | Max time to wait for worker DLL |
| `--headers` | off | Generate C++ SDK headers (structs, enums, offsets) |
| `--signatures` | off | Generate byte pattern signatures (requires Python 3) |
| `--all` | off | Enable all generators (headers + signatures) |

### Requirements

- Windows 10/11 (x64)
- Target Source 2 game must be running (with `client.dll` loaded)
- Run as **administrator** (required for process injection)

### Example Workflow

```bash
# Dump schema (all modules auto-discovered)
dezlock-dump.exe

# Find a field offset
grep m_iHealth schema-dump/client.txt

# Find all fields on a class (including inherited)
grep "C_CitadelPlayerPawn\." schema-dump/client-flat.txt

# Find an enum and its values
grep EAbilitySlots schema-dump/client-enums.txt

# Find networked fields
grep MNetworkEnable schema-dump/client.txt

# Find static fields
grep "= static" schema-dump/client.txt

# Search across all modules
grep -r m_iHealth schema-dump/*.txt

# Get the full class layout
cat schema-dump/hierarchy/C_BaseEntity/C_CitadelPlayerPawn.txt

# Generate pattern signatures
python generate-signatures.py --json bin/schema-dump/all-modules.json

# Find a signature for a specific class
grep CCitadelInput bin/schema-dump/signatures/client.txt
```

## Signature Generation

`generate-signatures.py` converts vtable function bytes into masked pattern signatures suitable for runtime pattern scanning. Signatures survive game patches where RVAs shift but instruction sequences stay the same.

### How It Works

Each vtable function's first **128 bytes** are captured at dump time (SEH-protected for safety). The script then:

1. **Detects trivial stubs** — `ret`, `xor eax,eax; ret`, `xorps; ret`, `mov al,0/1; ret`, `lea rax,[rip+x]; ret`, `int3` padding, etc. These are labeled `[STUB:type]` and excluded from uniqueness computation.

2. **Deduplicates by RVA** — COMDAT folding causes many vtable entries across different classes to point to the same function address. Entries sharing an RVA are grouped, with `shared_with` annotations showing which classes share the same function body.

3. **Masks relocatable bytes** that change between builds:
   - `E8/E9 xx xx xx xx` — relative CALL/JMP targets
   - `0F 8x xx xx xx xx` — conditional jumps (near)
   - `FF 15/FF 25 xx xx xx xx` — indirect CALL/JMP via `[RIP+disp32]`
   - RIP-relative addressing (`[RIP+disp32]`) — LEA, MOV, CMP, MOVSS, etc.

4. **Finds the shortest unique prefix** for each function within its module. A function unique at 12 bytes doesn't need all 128 — signatures are trimmed to the minimum length that uniquely identifies them.

5. **Computes per-class uniqueness** — functions that are unique within their class vtable (but not module-wide) are marked `[CLASS_UNIQUE]`. These are perfectly hookable since you typically know which vtable you're scanning.

### Usage

```bash
# Generate signatures for all modules (58+ DLLs)
python generate-signatures.py --json bin/schema-dump/all-modules.json

# Filter to a specific class
python generate-signatures.py --json bin/schema-dump/all-modules.json --class CCitadelInput

# Filter to a specific module
python generate-signatures.py --json bin/schema-dump/all-modules.json --module client.dll

# Require longer patterns (default: 6 bytes minimum)
python generate-signatures.py --json bin/schema-dump/all-modules.json --min-length 8
```

### Output

| File | Format | Description |
|------|--------|-------------|
| `bin/schema-dump/signatures/<module>.txt` | Greppable text | `ClassName::idx_N  48 89 5C 24 ? ...` |
| `bin/schema-dump/signatures/_all-signatures.json` | JSON | Structured with pattern, uniqueness, and length |

Signatures are trimmed to the shortest unique prefix. Markers: `[STUB:type]` = trivial stub function, `[CLASS_UNIQUE]` = unique within class vtable (hookable), `[DUP]` = not uniquely signable anywhere. COMDAT-shared functions show `# shared: OtherClass::idx_N`.

### Key Hookable Classes with Signatures

| Class | Module | Functions | Unique | Notes |
|-------|--------|-----------|--------|-------|
| `CSource2Client` | client.dll | 202 | **197** | FrameStageNotify, LevelInit, etc. |
| `CInputSystem` | inputsystem.dll | 107 | **97** | Input processing, key events |
| `CNetworkSystem` | networksystem.dll | 55 | **48** | Network layer |
| `CCitadelGameRules` | server.dll | 128 | **41** | Game rules |
| `CSchemaSystem` | schemasystem.dll | 40 | **31** | Schema type scopes, class lookup |
| `CGameEntitySystem` | server.dll | 24 | **20** | Entity add/remove |
| `CPanoramaUIEngine` | panorama.dll | 18 | **15** | RunScript, panel management |
| `ClientModeCitadelNormal` | client.dll | 40 | **10** | Client mode hooks |
| `CCitadelInput` | client.dll | 30 | **5** | CreateMove (idx_5), input processing |

### Example

```
# --- CSource2Client (202 functions, 197 unique) ---
CSource2Client::idx_0  40 53 56 57 48 81
CSource2Client::idx_14  48 89 5C 24 18 56 48 83 EC 70 8B

# --- CPanoramaUIEngine (18 functions, 15 unique) ---
CPanoramaUIEngine::idx_0  48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 48
CPanoramaUIEngine::idx_11  40 53 48 83 EC 20 48 8B D9 E8

# --- CSchemaSystem (40 functions, 31 unique) ---
CSchemaSystem::idx_0  40 53 48 83 EC 20 48 8B D9 C6
CSchemaSystem::idx_12  48 89 5C 24 10 55 56 57 48
```

Use in your pattern scanner:
```cpp
// Find CSource2Client vtable function by signature
auto addr = pattern_scan(client_dll, "40 53 56 57 48 81");

// Find CPanoramaUIEngine function in panorama.dll
auto addr = pattern_scan(panorama_dll, "48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 48");
```

## SDK Header Generation

`import-schema.py` converts the JSON export into ready-to-include C++ headers:

```bash
# After running dezlock-dump.exe
python import-schema.py --game deadlock
python import-schema.py --game cs2 --json path/to/all-modules.json
python import-schema.py --game dota2 --json path/to/all-modules.json
```

Output goes to `generated/<game>/` by default (e.g. `generated/deadlock/`, `generated/cs2/`).

### Generated Files

| File | Contents |
|------|----------|
| `_all-vtables.hpp` | Per-class vtable RVAs and function indices |
| `_all-offsets.hpp` | All field offsets as `constexpr uint32_t` |
| `_all-enums.hpp` | All enums as `enum class` |
| `<module>/<ClassName>.hpp` | Padded struct with `static_assert` validation |

### Vtable Header

```cpp
namespace deadlock::generated::vtables {
namespace CCitadelInput {
    constexpr uint32_t vtable_rva = 0x22A4A58;
    constexpr int entry_count = 30;
    namespace fn {
        constexpr int idx_0 = 0;  // rva=0x508F10
        constexpr int idx_5 = 5;  // rva=0x15AF360 (CreateMove)
        // ...
    }
}
}
```

Vtable indices are ABI-stable — they don't change across patches. Only the RVAs shift. Hook by index, resolve the vtable at runtime with `module_base + vtable_rva`.

### Offset Header

```cpp
namespace deadlock::generated::offsets {
namespace C_BaseEntity {
    constexpr uint32_t m_iHealth = 0x354;
    constexpr uint32_t m_iMaxHealth = 0x350;
    constexpr uint32_t m_pGameSceneNode = 0x330;
    // ...
}
}
```

### Struct Headers

Per-class headers with full padding and compile-time offset verification — if an offset is wrong after a patch, the build fails immediately:

```cpp
#pragma pack(push, 1)
struct C_BaseEntity {
    uint8_t _pad0000[0x330];
    void* m_pGameSceneNode;         // 0x330
    uint8_t _pad0338[0x18];
    int32_t m_iMaxHealth;           // 0x350
    int32_t m_iHealth;              // 0x354
    // ...
};
#pragma pack(pop)
static_assert(sizeof(C_BaseEntity) == 0xF60, "C_BaseEntity size");
static_assert(offsetof(C_BaseEntity, m_iHealth) == 0x354, "m_iHealth");
```

### Type Resolution (~96%)

The type resolver maps schema types to proper C++ types across 10 categories:

| Category | Description | Example |
|----------|-------------|---------|
| primitive | Built-in types | `int32` → `int32_t` |
| alias | Known Source 2 types (~100) | `Vector` → `float[3]`, `GameTime_t` → `float` |
| template | Container types (~25) | `CUtlVector<T>` → sized blob with type comment |
| embedded | Nested schema classes | Sized blob, class name in comment |
| handle | Entity handles | `CHandle<T>` → `uint32_t` |
| enum | Enum-typed fields | Resolved to sized integer from JSON |
| pointer | Pointer types | `T*` → `void*` |
| array | Fixed-size arrays | `int32[6]` → `int32_t[6]` |
| bitfield | Bit fields (size=0) | Emitted as comments |
| unresolved | Remaining (~3%) | Sized blob fallback (sizes always correct) |

## What Gets Captured

| Data | Source | Example Count |
|------|--------|---------------|
| Classes | SchemaSystem CUtlTSHash | ~5,000 |
| Fields | SchemaClassFieldData_t | ~21,000 |
| Enums | SchemaEnumInfoData_t | ~24 |
| RTTI classes | MSVC x64 TypeDescriptor (all DLLs) | ~23,000 |
| Vtables | RTTI COL → .rdata scan (58 DLLs) | ~23,000 |
| Virtual functions | .text pointer entries | ~839,000 |
| Function bytes | 128 bytes per function prologue | ~839,000 |
| Hookable signatures | Module-unique + class-unique | ~359,000 (76%) |

### Vtable Counts by Module (Top 20)

| Module | Vtables | Functions | Unique Sigs |
|--------|---------|-----------|-------------|
| server.dll | 7,323 | 515,909 | 18,410 |
| client.dll | 2,459 | 128,443 | 6,474 |
| steamclient64.dll | 5,182 | 85,325 | 8,334 |
| animationsystem.dll | 1,102 | 16,211 | 2,193 |
| particles.dll | 793 | 16,496 | 1,908 |
| v8.dll | 1,861 | 15,640 | 1,070 |
| soundsystem.dll | 736 | 15,060 | 1,685 |
| engine2.dll | 876 | 10,525 | 2,505 |
| nvcuda64.dll | 91 | 5,231 | 275 |
| vphysics2.dll | 179 | 3,297 | 1,449 |
| scenesystem.dll | 175 | 3,257 | 1,209 |
| steamnetworkingsockets.dll | 157 | 2,544 | 500 |
| panorama.dll | 81 | 1,677 | 766 |
| rendersystemdx11.dll | 73 | 1,703 | 399 |
| tier0.dll | 84 | 951 | 331 |
| inputsystem.dll | 2 | 137 | 118 |
| networksystem.dll | 39 | 484 | 290 |
| schemasystem.dll | 17 | 282 | 105 |
| materialsystem2.dll | 40 | 462 | 274 |
| panoramauiclient.dll | 9 | 218 | 45 |

This includes **RTTI-only classes** that have no schema entry — things like `CCitadelInput`, `CPanoramaUIEngine`, `CInputSystem`, `CNetworkSystem`, `CSchemaSystem`. These are often the most important for hooking.

## How It Works

1. Finds target process (default: `deadlock.exe`, configurable via `--process`)
2. Manual-maps `dezlock-worker.dll` into the target process (PE mapping, relocations, import resolution, SEH registration — no `LoadLibraryA` call)
3. Worker auto-discovers all loaded modules with schema data via `EnumProcessModules`
4. For each schema module, walks `SchemaSystem_001` — enumerates classes (CUtlTSHash at +0x0560) and enums (+0x0BE8)
5. Reads field metadata, class metadata, and static fields from each class
6. Walks RTTI (`_TypeDescriptor` + `_RTTICompleteObjectLocator`) in schema modules
7. **Full DLL scan**: enumerates ALL loaded DLLs and RTTI-scans any not already covered (catches panorama.dll, tier0.dll, inputsystem.dll, networksystem.dll, schemasystem.dll, etc. — skips Windows system DLLs)
8. **Pass 4 — Vtable discovery**: scans `.rdata` for pointers to COL structures (vtable[-1]), reads consecutive `.text`-pointing entries as virtual function addresses
9. **Function bytes**: reads 128 bytes from each function's prologue (SEH-protected) for signature generation
10. Exports JSON to `%TEMP%`, signals completion via marker file
11. Main exe reads JSON and generates all output formats per module
12. **Optional**: `--signatures` invokes `generate-signatures.py` to produce pattern signatures
13. **Optional**: `--headers` generates C++ SDK headers with padded structs
14. Worker auto-unloads via `FreeLibraryAndExitThread`

### Vtable Discovery Detail

```
For each CompleteObjectLocator found via RTTI:
  → Compute absolute address of COL in memory
  → Build hashset of all COL addresses

Single linear scan of .rdata section:
  → Check each 8-byte value against COL hashset
  → Match = vtable[-1], so vtable[0] starts at match + 8
  → Read entries while they point into .text section (max 512)
  → Store RVAs + first 128 bytes of each function
```

## Output Format

### Greppable text (`client.txt`)

```
# --- C_BaseEntity (size=0x560, parent=CEntityInstance)
#     metadata: [MNetworkVarNames]
#     chain: C_BaseEntity -> CEntityInstance -> CEntityComponent
C_BaseEntity.m_iHealth = 0x354 (int32, 4) [MNetworkEnable] [MNetworkChangeCallback]
C_BaseEntity.m_iMaxHealth = 0x350 (int32, 4) [MNetworkEnable]
C_BaseEntity.m_iTeamNum = 0x3F3 (uint8, 1) [MNetworkEnable]
C_BaseEntity.s_bDebugPrint = static (bool, 1)
```

### Flattened (`client-flat.txt`)

Shows all fields on entity classes with their defining parent class:

```
# === C_CitadelPlayerPawn (size=0x1800, 156 total fields) ===
C_CitadelPlayerPawn.m_iHealth = 0x354 (int32, 4, C_BaseEntity)
C_CitadelPlayerPawn.m_hPawn = 0x6BC (CHandle, 4, CBasePlayerController)
```

### Enums (`client-enums.txt`)

```
# --- EAbilitySlots_t (size=4 bytes, 23 values)
EAbilitySlots_t::ESlot_Signature_1 = 0
EAbilitySlots_t::ESlot_Signature_2 = 1
EAbilitySlots_t::ESlot_Signature_3 = 2
EAbilitySlots_t::ESlot_Signature_4 = 3
```

### Hierarchy tree (`hierarchy/_index.txt`)

```
CEntityComponent (0x8, 0 fields)
`-- CEntityInstance (0x38, 4 fields)
    `-- C_BaseEntity (0x560, 42 fields)
        `-- C_BasePlayerPawn (0x1100, 18 fields)
            `-- C_CitadelPlayerPawn (0x1800, 31 fields)
```

### JSON (`all-modules.json`)

```json
{
  "modules": [{
    "name": "client.dll",
    "vtables": [{
      "class": "CCitadelInput",
      "vtable_rva": "0x22A4A58",
      "functions": [
        {"index": 0, "rva": "0x508F10", "bytes": "48895C240857484883EC20488BD9E8..."},
        {"index": 5, "rva": "0x15AF360", "bytes": "85D20F85..."}
      ]
    }]
  }]
}
```

The `bytes` field contains 128 hex-encoded bytes from each function's prologue — used by `generate-signatures.py` to produce masked pattern signatures.

### Signature text (`signatures/client.txt`)

```
# --- CSource2Client (202 functions, 197 unique, 3 class-unique, 2 stubs) ---
CSource2Client::idx_0  40 53 56 57 48 81
CSource2Client::idx_14  48 89 5C 24 18 56 48 83 EC 70 8B
CSource2Client::idx_42  33 C0 C3  [STUB:xor_eax_ret]

# --- CCitadelInput (30 functions, 5 unique, 18 class-unique, 4 stubs) ---
CCitadelInput::idx_4  E9 ? ? ? ? CC CC CC CC CC CC CC CC CC CC CC 40 55 53 57 48
CCitadelInput::idx_17  40 55 53 57 48 8D 6C 24 B9 48 81 EC C0
CCitadelInput::idx_5  48 83 EC 28 ...  [CLASS_UNIQUE]
CCitadelInput::idx_8  48 89 5C 24 08 ...  [DUP]  # shared: CInput::idx_8
```

`?` = masked byte (relocation). `[STUB:type]` = trivial stub. `[CLASS_UNIQUE]` = unique within class. `[DUP]` = not uniquely signable. `# shared:` = COMDAT-folded. Signatures trimmed to shortest unique prefix.

## Why Not source2gen?

source2gen works great but requires building and injecting a separate loader, generates thousands of SDK header files you then have to parse, and doesn't give you vtables or RTTI inheritance. dezlock-dump gives you one JSON file with everything — schema + RTTI + vtables + signatures — in ~2 seconds. Use whatever fits your workflow.

## Contributing

Contributions are welcome! Feel free to:

- Open an [issue](../../issues) for bugs, feature requests, or offset discrepancies
- Submit a [pull request](../../pulls) with improvements

## License

[MIT](LICENSE)

---

If you find this tool useful, consider giving it a star — it helps others discover it.
