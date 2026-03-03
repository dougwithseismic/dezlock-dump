# dezlock-dump

[![GitHub Release](https://img.shields.io/github/v/release/dougwithseismic/dezlock-dump?label=Version)](../../releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/dougwithseismic/dezlock-dump/build.yml?label=Build)](../../actions/workflows/build.yml)
[![Discord](https://img.shields.io/discord/1469694564683088168?color=5865F2&logo=discord&logoColor=white&label=Discord)](https://discord.gg/sjcsVkE8ur)
[![Hire Me](https://img.shields.io/badge/Hire%20Me-hello%40withseismic.com-blue?style=flat&logo=gmail&logoColor=white)](mailto:hello@withseismic.com)

Runtime schema + RTTI extraction tool for Source 2 games (Deadlock, CS2, Dota 2).

![dezlock-dump viewer](assets/viewer-preview.png)

[![Watch the demo](https://img.youtube.com/vi/fz-JlwcnIfY/maxresdefault.jpg)](https://www.youtube.com/watch?v=fz-JlwcnIfY)

**[Watch the demo on YouTube](https://www.youtube.com/watch?v=fz-JlwcnIfY)**

## What's New

**Viewer rewrite** — The interactive viewer has been rebuilt from scratch with React 19 + TypeScript + Vite + Tailwind CSS v4. The 3,453-line monolithic HTML file is now 67 typed source files with virtualized lists, proper state management, and zero XSS vulnerabilities. All existing features preserved — same hash routing, same live entity inspector.

**v1.6.0** — Protobuf descriptor scanner. Decodes embedded `.proto` definitions from game binaries — extracts named fields, types, and message hierarchies for protobuf-only classes like `CBaseUserCmdPB` that have no Source 2 schema registration.

See the full [Changelog](CHANGELOG.md) for all releases.

## What

A single exe that injects a read-only worker DLL into a running Source 2 game and extracts the complete schema, RTTI, and runtime layout data — in seconds, with zero configuration. Built for educational purposes and reverse engineering research.

**One command, full extraction:**

```bash
dezlock-dump.exe --all
```

## How

1. Download from [Releases](../../releases) (or [build from source](#build-from-source))
2. Launch your game and load into a match or lobby
3. Run as administrator:

```bash
# Deadlock (default)
dezlock-dump.exe --all

# CS2
dezlock-dump.exe --process cs2.exe --all

# Dota 2
dezlock-dump.exe --process dota2.exe --all
```

Output lands in `schema-dump/<game>/` next to the exe.

| Flag | Default | Description |
|------|---------|-------------|
| `--process <name>` | `deadlock.exe` | Target process |
| `--output <dir>` | `schema-dump/<game>/` | Output directory |
| `--signatures` | off | Generate byte pattern signatures |
| `--sdk` | off | Generate cherry-pickable C++ SDK headers |
| `--layouts` | off | Analyze vtable functions for inferred member field offsets |
| `--all` | off | Enable all generators (sdk + signatures + layouts) |

> **Note:** Schema dump finishes in seconds. Signature generation (`--signatures` / `--all`) processes 800k+ functions and can take several minutes.

## Benefits

### Full SDK generation
Cherry-pickable C++ headers with v2-style types (`Vec3`, `QAngle`, `CHandle`), `constexpr` offsets, scoped enums, and `static_assert` validation on every field. Include only what you need — each class gets its own `.hpp`.

```cpp
#include "sdk/client/C_BaseEntity.hpp"
```

### Complete field offsets
Every class with every field — own and inherited — greppable in one file per module.

```
C_CitadelPlayerPawn.m_iHealth = 0x354 (int32, 4) [MNetworkEnable]
C_CitadelPlayerPawn.m_angEyeAngles = 0x11B0 (QAngle, 12)
```

### Entity access paths
Full recursive field trees with pointer chains resolved — grep any class and see the complete offset path to any nested field.

```
# C_CitadelPlayerPawn (size=0x1990)
  +0x10   m_pEntity                -> CEntityIdentity*
            +0x18   m_name                   (CUtlSymbolLarge)
  +0x354  m_iHealth                (int32, C_BaseEntity)
  +0x11B0 m_angEyeAngles           (QAngle)
```

### 10,000+ global singletons auto-discovered
Scans `.data` sections of every loaded module and cross-references against the RTTI vtable catalog. No hardcoded patterns needed.

```
client.dll::CCitadelCameraManager = 0x31F05F0 (static)
engine2.dll::CGameEntitySystem = 0x623AA8 (pointer)
```

### Pattern signatures for every virtual function
IDA-style byte patterns across 58+ DLLs — survive game patches where RVAs shift. Stubs detected, COMDAT deduplication handled, signatures trimmed to shortest unique prefix.

```
CCitadelInput::CreateMove = 48 89 5C 24 ? 55 48 8D AC 24
CSource2Client::idx_0 = 40 53 56 57 48 81
```

### RTTI layout headers
9,000+ non-schema classes get generated struct headers with inferred field offsets from vtable function analysis — no PDB required. Each field has type inference (`float`, `void*`, `uint32_t`, etc.) and access pattern annotations.

```cpp
#include "sdk/client/_rtti/CTraceFilter.hpp"
// namespace sdk::rtti — separate from schema structs
```

### Protobuf message definitions
Decodes serialized `.proto` descriptors embedded in game binaries. Extracts full message definitions with named fields, types, nesting, and oneofs — no PDB or protobuf library required.

```
message CBaseUserCmdPB {
  optional int32 legacy_command_number = 1;
  optional int32 client_tick = 2;
  optional CInButtonStatePB buttons_pb = 3;
  optional CMsgQAngle viewangles = 4;
  optional float forwardmove = 5;
  optional float leftmove = 6;
  optional float upmove = 7;
  repeated CSubtickMoveStep subtick_moves = 18;
  ...
}

message CCitadelUserCmdPB {
  optional CBaseUserCmdPB base = 1;
  optional CMsgVector vec_camera_position = 2;
  optional CMsgQAngle ang_camera_angles = 3;
  optional int32 enemy_hero_aimed_at = 10;
  ...
}
```

### Full RTTI inheritance
23,000+ classes with complete parent chains and vtable RVAs from MSVC x64 RTTI — including internal engine classes with no schema entry (CCitadelInput, CPanoramaUIEngine, CInputSystem, etc.).

### Runtime-scannable patterns in SDK
Global pointer patterns from `patterns.json` are exported as `_patterns.hpp` — drop them into your project and scan at runtime without hardcoded offsets. RIP-relative and derived patterns both supported.

```cpp
#include "sdk/_patterns.hpp"

// Scan at runtime — survives game patches
auto match = find_pattern(client_base, client_size, patterns::client::dwEntityList::sig);
auto addr = resolve_rip(match, patterns::client::dwEntityList::rip_offset);
```

### Supplementary pattern scanning
Optional `patterns.json` for untyped globals that vtable scanning can't find (`dwViewMatrix`, `dwEntityList`, etc.).

## Output Files

| File | Description |
|------|-------------|
| `<module>.txt` | Classes + flattened inherited fields + enums |
| `_globals.txt` | All global singletons with recursive field trees |
| `_access-paths.txt` | Schema globals only — fast offset grep |
| `_entity-paths.txt` | Every entity class with full field trees |
| `_protobuf-messages.txt` | Decoded protobuf message definitions from all modules |
| `_all-modules.json` | Complete structured JSON export |
| `signatures/<module>.txt` | Pattern signatures per module |
| `sdk/<Class>.hpp` | Per-class C++ SDK headers |
| `sdk/_all-offsets.hpp` | All offset constants |
| `sdk/_all-enums.hpp` | All scoped enums |
| `sdk/_all-vtables.hpp` | VTable RVAs + function indices |
| `sdk/_globals.hpp` | Resolved global pointer RVAs |
| `sdk/_patterns.hpp` | Runtime-scannable byte patterns for globals |
| `sdk/_rtti-layouts.hpp` | Master include for all RTTI layout headers |
| `sdk/<module>/_rtti/<Class>.hpp` | Per-class RTTI-inferred struct headers |
| `viewer/dist/index.html` | Interactive browser-based viewer for `_all-modules.json` |

## Interactive Viewer

A React + TypeScript viewer for exploring dump output interactively. Built with Vite and Tailwind CSS v4.

**Quick start (development):**

```bash
cd viewer
pnpm install
pnpm dev        # http://localhost:5173
```

**Production build:**

```bash
cd viewer
pnpm build      # outputs to viewer/dist/
```

Then open `viewer/dist/index.html` in any browser, or use `pnpm dev` during development.

1. Drop your `_all-modules.json` onto the landing page (or use the file picker)
2. Browse classes, fields, enums, globals, protobuf messages, and inheritance trees
3. Connect live to inspect entities in real time

**Features:**
- Searchable class/field/enum browser with module filtering (Ctrl+K to focus)
- Sortable field offset tables with own/flattened inherited field toggle
- Clickable inheritance chains — click any parent class to navigate
- Global singletons browser with module grouping and pattern globals
- Full inheritance tree with lazy-loaded collapsible nodes
- Protobuf message browser with nested message/enum support
- Dark/light theme toggle (persisted)
- Virtualized sidebar for smooth scrolling with 5,000+ items
- Works offline with 150MB+ JSON files (parses in a Web Worker)

> **Note:** When both `client.dll` and `server.dll` are present (common in Deadlock/CS2), the exported `_all-modules.json` can reach **500MB+** since many classes are duplicated across both modules. The viewer handles this fine but loading may take a moment. `server.dll` is excluded from the module filter by default — enable it manually if you need server-side class data.

### Live Server

The `--live` flag keeps the exe running after dump and starts a WebSocket server on `ws://127.0.0.1:9100`. The viewer can connect to it for real-time entity inspection — browse live entities, expand nested structs, follow handle references, and watch field values update in real time.

```bash
# Dump + stay live
dezlock-dump.exe --all --live

# Or skip injection entirely — load an existing dump and serve it
dezlock-dump.exe --schema schema-dump/deadlock/_all-modules.json
```

Then open the viewer (`pnpm dev` or `viewer/dist/index.html`) and hit **Connect Live** (or paste `ws://127.0.0.1:9100` into the header bar). The Entities tab appears once connected.

## Build from Source

Requires Visual Studio 2022 with C++ desktop workload and CMake 3.20+ (ships with VS2022).

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Or just run `build.bat`. Output lands in `build/bin/Release/`.

## Requirements

- Windows 10/11 (x64)
- Target Source 2 game running with `client.dll` loaded
- Run as **administrator**

## Technical Deep-Dives

Articles explaining the engineering behind each major subsystem:

- [How Source 2's SchemaSystem Works Internally](docs/how-source2-schema-system-works.md) — CUtlTSHash walking, RuntimeClass/Field structures, flat layout resolution
- [Building an MSVC x64 RTTI Scanner from Scratch](docs/building-msvc-x64-rtti-scanner.md) — TypeDescriptor chains, vtable discovery, inheritance reconstruction across 23,000+ classes
- [Manual DLL Mapping: How and Why We Skip LoadLibrary](docs/manual-dll-mapping-explained.md) — PE section copying, relocations, import resolution, SEH registration
- [Auto-Discovering 10,000+ Global Singletons](docs/auto-discovering-global-singletons.md) — .data section scanning, vtable cross-referencing, pattern-based supplementary resolution
- [Building an Interactive Binary Analysis Viewer](docs/building-a-binary-analysis-viewer.md) — React + TypeScript architecture, Web Worker parsing, live WebSocket entity inspector

## Disclaimer

This project is provided strictly for **educational and research purposes**. It is intended to help developers, researchers, and students understand game engine architecture, runtime type systems, and binary analysis techniques.

- **No game modification.** The tool performs read-only memory inspection. It does not patch, hook, or alter game code or data at runtime.
- **No competitive advantage.** This tool is not designed for use during online gameplay and provides no gameplay automation, aiming assistance, or any other form of unfair advantage.
- **Use at your own risk.** Using this software may violate the Terms of Service of the target application. The author(s) accept no responsibility for account bans, suspensions, or other consequences resulting from its use.
- **No warranty.** This software is provided "as is", without warranty of any kind, express or implied.
- **Respect intellectual property.** The extracted schemas, class names, and type information remain the intellectual property of their respective owners. Do not redistribute extracted game data in ways that infringe on those rights.

By using this software you acknowledge that you have read and understood this disclaimer and accept full responsibility for how you use it.

## Contributing

Open an [issue](../../issues) or submit a [pull request](../../pulls). Join the [Discord](https://discord.gg/sjcsVkE8ur) for questions and discussion.

---

If you find this tool useful, consider giving it a star.
