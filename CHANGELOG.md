# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
