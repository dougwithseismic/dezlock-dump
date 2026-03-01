# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Entity inspector: live values in inline drill-down** — expanding a type (e.g. `CBodyComponent*`) in the entity inspector now shows a 5th "Live" column with real-time values from the parent entity subscription; nested struct data is extracted and passed recursively; pointer fields gracefully fall back to dashes
- **Entity sidebar list** — extracted `EntitySidebarList` component for cleaner entity tab architecture
- **Entity context** — new `EntityContext` provider to share entity state across components

### Fixed
- **Diff flash animation not restarting on rapid changes** — when the same field changed again before the 400ms clear timer fired, the CSS animation never replayed; added a `flashTick` counter with `useLayoutEffect` to force animation restart via DOM reflow
- **Hook ordering crash in SidebarList** — early return before `useMemo`/`useCallback` caused "Rendered fewer hooks" React crash when toggling tabs

### Changed
- **InlineClassExpander** accepts optional `liveValues`, `enumMap`, `classMap`, `selectedEntityAddr` props; conditionally renders a "Live" column when values are provided; class view remains unchanged
- **EntityInspectorPane** passes live values and schema maps through to `InlineClassExpander` for inline-expand virtual items; `parentFieldName` added to inline-expand VirtualItem type
- **EntityInspectorField** gains `flashTick` prop for reliable diff flash restart
- Entity view refactored — simplified by extracting sidebar and context logic

## [1.7.0] - 2026-03-01

### Changed
- **Viewer rewritten in React + TypeScript + Vite + Tailwind CSS v4** — the 3,453-line monolithic `index.html` has been decomposed into 67 typed source files across a proper component architecture
- Virtualized sidebar list via `react-window` (previously rendered up to 5,000 raw DOM nodes)
- XSS vulnerabilities eliminated — React JSX auto-escapes all text content (previously 5 innerHTML injection points)
- Per-instance debounced search (fixes global timer collision bug)
- 11 duplicate table builders replaced with reusable `<DataTable>` and `<FieldTable>` components
- 3 duplicate drilldown toggles replaced with reusable `<Drilldown>` component
- 25+ global variables replaced with React state/context, properly scoped
- 50+ inline style assignments replaced with Tailwind utility classes
- Hash routing preserved (`#class/mod/name` format unchanged)
- All live/entity features preserved: WebSocket connection, entity browser, field subscription, pointer drill-down, snapshot diff

### Added
- `viewer/` is now a standalone Vite project — `pnpm dev` for HMR development, `pnpm build` for static output
- TypeScript type definitions for all schema, live, and entity data structures
- React context providers for schema data, live client state, and theme
- **Inline type expansion** — click the chevron next to any type reference to drill down into that class's fields without leaving the current view (recursive up to 3 levels deep)
- **Per-row copy button** — hover any field row (top-level or nested) to reveal a "C" button that copies `[module]+offset name // type` to clipboard, with tick feedback
- **Copy Pointer List button** — bulk-copy all pointer (`*`) fields in the current class's field section
- "Go to full page" link in inline expansions opens in a new tab

## [1.6.0] - 2026-02-23

### Added
- Protobuf descriptor scanner — decodes serialized `FileDescriptorProto` blobs embedded in `.rdata` sections of all loaded game DLLs
- Full protobuf wire format parser (varint, length-delimited, nested messages) with zero external dependencies
- `_protobuf-messages.txt` output — human-readable `.proto` definitions with messages, fields, enums, oneofs, and nesting
- `"protobuf_messages"` section in `_all-modules.json` export with structured message/field/enum data per module
- Protobuf summary stats in console output
- Extracts named fields for protobuf-only classes like `CBaseUserCmdPB` (viewangles, forwardmove, buttons, etc.) that have no Source 2 schema registration

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
