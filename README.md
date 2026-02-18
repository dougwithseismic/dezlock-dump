# dezlock-dump

Runtime schema + RTTI extraction tool for Deadlock (Source 2). Injects a minimal worker DLL into a running Deadlock process and dumps the complete class hierarchy, field offsets, metadata annotations, static fields, enums, and inheritance chains.

No source2gen required — reads directly from the game's `SchemaSystem` at runtime.

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

## What Gets Captured

| Data | Source | Notes |
|------|--------|-------|
| Classes | SchemaSystem CUtlTSHash | All registered classes per module |
| Fields | SchemaClassFieldData_t | Name, type, offset, size |
| Field metadata | SchemaMetadataEntryData_t | `[MNetworkEnable]`, `[MNetworkChangeCallback]`, etc. |
| Static fields | SchemaClassFieldData_t | Class-level (non-instance) members |
| Class metadata | SchemaMetadataEntryData_t | Class-level annotations |
| Base classes | SchemaBaseClassInfoData_t | Multiple inheritance with offsets |
| Enums | SchemaEnumInfoData_t | All enumerators with values |
| RTTI hierarchy | MSVC x64 RTTI | Full inheritance chains via TypeDescriptor |

## How It Works

1. Finds `deadlock.exe` process
2. Injects `dezlock-worker.dll` via `CreateRemoteThread` + `LoadLibraryA`
3. Worker auto-discovers all loaded modules with schema data via `EnumProcessModules`
4. For each module, walks `SchemaSystem_001` — enumerates classes (CUtlTSHash at +0x0560) and enums (+0x0BE8)
5. Reads field metadata, class metadata, and static fields from each class
6. Walks RTTI (`_TypeDescriptor` + `_RTTICompleteObjectLocator`) in each module
7. Exports JSON to `%TEMP%`, signals completion via marker file
8. Main exe reads JSON and generates all output formats per module
9. Worker auto-unloads via `FreeLibraryAndExitThread`

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

## Contributing

Contributions are welcome! Feel free to:

- Open an [issue](../../issues) for bugs, feature requests, or offset discrepancies
- Submit a [pull request](../../pulls) with improvements

## License

[MIT](LICENSE)

---

If you find this tool useful, consider giving it a star — it helps others discover it.
