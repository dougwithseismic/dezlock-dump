# dezlock-dump

Runtime schema + RTTI + vtable extraction tool for Deadlock (Source 2). Injects a minimal worker DLL into a running Deadlock process and dumps the complete class hierarchy, field offsets, metadata annotations, static fields, enums, inheritance chains, and **every virtual function table**.

No source2gen required — reads directly from the game's `SchemaSystem` and MSVC x64 RTTI at runtime.

**Auto-discovers all modules** — walks every loaded DLL for schema data (client.dll, server.dll, engine2.dll, animationsystem.dll, etc).

## Output

For each module with schema data (e.g. `client.dll` → `client`):

| File | Format | Description |
|------|--------|-------------|
| `schema-dump/<module>.txt` | Greppable text | Every class + field with offsets and metadata |
| `schema-dump/<module>-flat.txt` | Flattened text | Inherited fields resolved per entity class |
| `schema-dump/<module>-enums.txt` | Greppable text | Every enum + enumerator values |
| `schema-dump/<module>/hierarchy/` | Tree | Per-class files organized by inheritance |
| `schema-dump/all-modules.json` | JSON | Full structured export for tooling (all modules) |

Additionally, `%TEMP%\dezlock-export.json` contains the complete JSON export with vtable data.

## Quick Start

### Pre-built (Releases)

1. Download `dezlock-dump.zip` from [Releases](../../releases)
2. Launch Deadlock and enter a match or lobby
3. Run as administrator:

```
dezlock-dump.exe
```

Output lands in `schema-dump/` next to the exe.

### Build from Source

Requires Visual Studio 2022 (any edition with C++ desktop workload).

```bat
build.bat
```

Produces `bin/dezlock-dump.exe` and `bin/dezlock-worker.dll`.

## Usage

```
dezlock-dump.exe [--output <dir>] [--wait <seconds>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output <dir>` | `schema-dump/` next to exe | Output directory |
| `--wait <seconds>` | `30` | Max time to wait for worker DLL |

### Requirements

- Windows 10/11 (x64)
- Deadlock must be running (with `client.dll` loaded)
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
```

## SDK Header Generation

`import-schema.py` converts the JSON export into ready-to-include C++ headers:

```bash
# After running dezlock-dump.exe
python import-schema.py --game deadlock
```

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

## What Gets Captured

| Data | Source | Example Count |
|------|--------|---------------|
| Classes | SchemaSystem CUtlTSHash | ~5,000 |
| Fields | SchemaClassFieldData_t | ~21,000 |
| Enums | SchemaEnumInfoData_t | ~24 |
| RTTI classes | MSVC x64 TypeDescriptor | ~8,500 |
| Vtables | RTTI COL → .rdata scan | ~12,500 |
| Virtual functions | .text pointer entries | ~688,000 |

### Vtable Counts by Module

| Module | Vtables | Functions |
|--------|---------|-----------|
| client.dll | 2,459 | 128,443 |
| server.dll | 7,323 | 515,909 |
| engine2.dll | 876 | 10,525 |
| animationsystem.dll | 1,102 | 16,211 |
| particles.dll | 793 | 16,496 |
| worldrenderer.dll | 26 | 341 |

This includes **RTTI-only classes** that have no schema entry — things like `CCitadelInput`, `CInput`, `CGameTraceManager`. These are often the most important for hooking.

## How It Works

1. Finds `deadlock.exe` process
2. Injects `dezlock-worker.dll` via `CreateRemoteThread` + `LoadLibraryA`
3. Worker auto-discovers all loaded modules with schema data via `EnumProcessModules`
4. For each module, walks `SchemaSystem_001` — enumerates classes (CUtlTSHash at +0x0560) and enums (+0x0BE8)
5. Reads field metadata, class metadata, and static fields from each class
6. Walks RTTI (`_TypeDescriptor` + `_RTTICompleteObjectLocator`) in each module
7. **Pass 4 — Vtable discovery**: scans `.rdata` for pointers to COL structures (vtable[-1]), reads consecutive `.text`-pointing entries as virtual function addresses
8. Exports JSON to `%TEMP%`, signals completion via marker file
9. Main exe reads JSON and generates all output formats per module
10. Worker auto-unloads via `FreeLibraryAndExitThread`

### Vtable Discovery Detail

```
For each CompleteObjectLocator found via RTTI:
  → Compute absolute address of COL in memory
  → Build hashset of all COL addresses

Single linear scan of .rdata section:
  → Check each 8-byte value against COL hashset
  → Match = vtable[-1], so vtable[0] starts at match + 8
  → Read entries while they point into .text section (max 512)
  → Store as RVAs (module_base subtracted, portable across sessions)
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

### JSON vtables (`dezlock-export.json`)

```json
{
  "modules": [{
    "name": "client.dll",
    "vtables": [{
      "class": "CCitadelInput",
      "vtable_rva": "0x22A4A58",
      "functions": [
        {"index": 0, "rva": "0x508F10"},
        {"index": 5, "rva": "0x15AF360"}
      ]
    }]
  }]
}
```

## Why Not source2gen?

source2gen works great but requires building and injecting a separate loader, generates thousands of SDK header files you then have to parse, and doesn't give you vtables or RTTI inheritance. dezlock-dump gives you one JSON file with everything — schema + RTTI + vtables — in ~2 seconds. Use whatever fits your workflow.

## Contributing

Contributions are welcome! Feel free to:

- Open an [issue](../../issues) for bugs, feature requests, or offset discrepancies
- Submit a [pull request](../../pulls) with improvements

## License

[MIT](LICENSE)

---

If you find this tool useful, consider giving it a star — it helps others discover it.
