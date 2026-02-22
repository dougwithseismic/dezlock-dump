# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

Requires Visual Studio 2022 with C++ desktop workload (MSVC x64) and CMake 3.20+ (ships with VS2022).

```bat
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Or simply run `build.bat` which wraps the above commands.

Produces `dezlock-dump.exe` and `dezlock-worker.dll` in `build/bin/Release/`. No package manager, no dependencies beyond MSVC and the vendored `vendor/json.hpp` (nlohmann/json). Config files (`patterns.json`, `sdk-cherry-pick.json`) are copied to the output directory automatically.

Compiler flags (set in `CMakeLists.txt`): `/std:c++17 /O2 /MT /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS`. Worker DLL links `user32.lib psapi.lib` with `/GUARD:NO`; main exe links `user32.lib advapi32.lib`.

CI: `.github/workflows/build.yml` (push/PR), `.github/workflows/release.yml` (version tags `v*`).

## Architecture

**Two-binary system** — an exe orchestrator and an injected DLL worker that communicate via temp files:

```
dezlock-dump.exe                          dezlock-worker.dll (injected into game)
  ├─ Find game process (PID)                ├─ Find SchemaSystem_001 interface
  ├─ Manual-map worker DLL into game        ├─ Walk CUtlTSHash for classes/fields/enums
  ├─ Wait for %TEMP%/dezlock-done           ├─ Build RTTI hierarchy (all loaded DLLs)
  ├─ Read %TEMP%/dezlock-export.json        ├─ Scan .rdata for vtables, capture function bytes
  ├─ Generate text output files             ├─ Scan .data for global singletons
  ├─ [Optional] invoke Python scripts       ├─ Resolve pattern-based globals
  └─ Cleanup                                └─ Write JSON + marker file, auto-unload
```

### main.cpp (~2300 lines)
CLI entry point. Handles PE manual-mapping (section copy, relocations, imports, SEH registration), DLL injection via `VirtualAllocEx`/`WriteProcessMemory`, output file generation (text dumps, hierarchy trees, globals, entity paths), and Python script orchestration. Uses colored console output with progress steps.

### worker.cpp (~600 lines)
The injected DLL. Runs `worker_thread` on `DLL_PROCESS_ATTACH`. Orchestrates all data collection phases in sequence, writes the complete JSON export to `%TEMP%/dezlock-export.json`, then signals via `%TEMP%/dezlock-done` and auto-unloads with `FreeLibraryAndExitThread`.

### src/schema-manager.{hpp,cpp}
Core schema walker. Reads `SchemaSystem_001` interface (CUtlTSHash at +0x0560 for classes, +0x0BE8 for enums). Key types: `RuntimeClass`, `RuntimeField`, `RuntimeEnum`, `FlatLayout`. Provides `dump_all_modules()`, `find_class()`, `get_offset()`, `get_flat_layout()`.

### src/rtti-hierarchy.{hpp,cpp}
MSVC x64 RTTI scanner. Finds TypeDescriptors (`?AV` mangled names), resolves CompleteObjectLocator chains, builds inheritance maps. Also discovers vtables by scanning .rdata for COL pointers and captures 128-byte function prologues. Key type: `InheritanceInfo` (parent, chain, vtable_rva, func_rvas, func_bytes).

### src/global-scanner.{hpp,cpp}
Auto-discovers global singletons by scanning .data sections 8-byte-aligned and cross-referencing against known vtable RVAs. Direct match = static object in .data; indirect dereference = pointer to heap singleton. Key type: `DiscoveredGlobal`.

### src/pattern-scanner.{hpp,cpp}
Supplementary pattern-based global resolution from `patterns.json`. Two modes: RipRelative (IDA-style pattern + RIP offset) and Derived (field offset extracted from another global's code).

### src/log.{hpp,cpp}
Thread-safe file logger for the worker DLL. Writes to `%TEMP%/dezlock-worker.txt`. Macros: `LOG_D/I/W/E`.

### Python scripts (optional, require Python 3)
- **generate-signatures.py** — Converts vtable function bytes into masked IDA-style pattern signatures with stub detection, COMDAT deduplication, and shortest-unique-prefix trimming.
- **import-schema.py** — Generates cherry-pickable C++ SDK headers with v2-style types (Vec3, QAngle, CHandle), constexpr offsets, scoped enums, and static_asserts. Type mappings and helper methods configured via `sdk-cherry-pick.json`.

## Key Conventions

- **SEH protection** — All memory reads in the worker DLL use `__try/__except` blocks since we're reading arbitrary game memory.
- **JSON as IPC** — Worker-to-exe communication is via `%TEMP%/dezlock-export.json` + a marker file. No TCP/pipes.
- **No hooks/patches** — The tool is read-only; it never modifies game memory.
- **Auto-unload** — Worker DLL cleans up and unloads itself after dump completes.
- **Schema offsets are hardcoded** — CUtlTSHash at +0x0560, enums at +0x0BE8, field struct size 0x20, etc. These come from reverse engineering SchemaSystem and may need updating between major engine versions.

## Config Files

- **patterns.json** — IDA-style byte patterns for supplementary global pointer discovery (dwViewMatrix, dwEntityList, etc.).
- **sdk-cherry-pick.json** — Inline helper methods injected into generated SDK structs (e.g., `is_alive()`, `team()`).
