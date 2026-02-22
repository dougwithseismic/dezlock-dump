# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.5.0] - 2026-02-22

### Added
- Interface scanner — enumerates `CreateInterface` registrations across all loaded modules, exports factory/instance/vtable RVAs
- String reference scanner — finds `.rdata` strings with code xrefs, categorizes as convar, class_name, lifecycle, or debug
- Vtable member offset analyzer — decodes x86-64 function prologues to infer `this`-pointer field offsets from member access patterns (no PDB needed)
- RTTI-only SDK struct headers — generates `_rtti/` per-class `.hpp` files for 9,000+ classes that lack schema registration, using inferred field layouts with type inference and access flag annotations
- `_rtti-layouts.hpp` master include for all RTTI layout headers
- `--layouts` CLI flag and interactive menu option `[4]` for member layout analysis
- Interfaces and string references sections in `_all-modules.json` export
- Summary stats for interfaces, string refs, and member layouts in console output

### Changed
- `--all` now enables layouts in addition to sdk + signatures
- Enriched JSON output writes via nlohmann serialization when layout analysis is active (instead of raw file copy)

## [1.4.0] - 2025-06-22

### Changed
- Port `generate-signatures.py` and `import-schema.py` to C++ — signature and SDK generation are now built into the exe
- Python 3 is no longer required for `--signatures` or `--sdk`
- Shared data structures (`Field`, `ClassInfo`, `ModuleData`, etc.) moved to `src/import-schema.hpp`
- Python scripts remain in the repo as standalone tools for processing JSON independently

### Removed
- `find_python()` / `run_python_script()` subprocess infrastructure in `main.cpp`
- Python scripts no longer copied to output directory at build time

## [1.3.0] - 2025-06-15

### Added
- `--depth <N>` CLI flag to configure field expansion depth for globals and entity trees (default: 3, max: 32)
- Parallel per-module processing in `generate-signatures.py` and `import-schema.py` using ThreadPoolExecutor

## [1.2.0] - 2025-06-14

### Fixed
- Add missing source files and error handling to CI build commands

### Added
- Export runtime-scannable byte patterns to SDK (`_patterns.hpp`)

## [1.1.0] - 2025-06-13

### Added
- Interactive output selection menu after schema extraction
- Pattern-scanned globals to SDK output (`_globals.hpp`)

## [1.0.0] - 2025-06-12

### Added
- Runtime schema + RTTI dump tool for Deadlock (Source 2)
- Multi-game support + manual-map DLL injection
- Interactive game selector when `--process` not provided
- Auto-discover global singletons via .data vtable cross-reference
- Recursive field trees, entity paths, and consolidated output
- Entity field trees with showcase README
- Vtable function dumping + `import-schema.py` SDK generator
- Signature generation + one-shot `--all` pipeline
- `--sdk` flag for cherry-pickable C++ SDK generation
- `--headers` flag for C++ SDK header generation
- CI build and release pipelines

### Fixed
- Correct `SchemaBaseClassInfoData_t` layout + cross-module inheritance
- Filter cross-module schema entries from TypeScope hash tables
- Rewrite `CUtlTSHash` enumeration for V2 bucket-walking
- Enum offset auto-detection, module filtering, console UX
- Use cmd shell for build steps in CI

### Changed
- Improve vtable signature generation (5% -> 76% hookable)
- `import-schema` type resolver upgrade (60% -> 96.6%)
- SDK bundle: remove legacy `--headers`, add entity-aware generation
- Skip modules with no useful content in SDK generation
- Remove MIT license
