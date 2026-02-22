# Contributing to dezlock-dump

Thanks for your interest in contributing! This guide will get you from clone to working build and help you submit a clean PR.

## Prerequisites

- **Windows 10/11 x64**
- **Visual Studio 2022** with the **C++ desktop development** workload (MSVC x64 compiler)
- **Python 3** (optional — only needed for signature generation and SDK output)
- **Git**

No package manager or external dependencies beyond what's vendored (`vendor/json.hpp`).

## Building

```bat
git clone https://github.com/dougwithseismic/dezlock-dump.git
cd dezlock-dump
build.bat
```

This produces two binaries in `bin/`:

| Binary | Role |
|--------|------|
| `dezlock-dump.exe` | CLI orchestrator — finds the game, injects the worker, generates output |
| `dezlock-worker.dll` | Injected into the game process — extracts schema, RTTI, globals |

Config files (`patterns.json`, `sdk-cherry-pick.json`) are copied to `bin/` automatically.

### Build flags

The build uses `/std:c++17 /O2 /MT /EHsc /W3`. The worker DLL additionally uses `/GUARD:NO` to disable control flow guard (required for injection). You don't need to configure anything — `build.bat` handles it all.

## Architecture overview

Understanding the two-binary split is important before contributing:

```
dezlock-dump.exe                          dezlock-worker.dll (injected into game)
  ├─ Find game process (PID)                ├─ Find SchemaSystem_001 interface
  ├─ Manual-map worker DLL into game        ├─ Walk CUtlTSHash for classes/fields/enums
  ├─ Wait for %TEMP%/dezlock-done           ├─ Build RTTI hierarchy (all loaded DLLs)
  ├─ Read %TEMP%/dezlock-export.json        ├─ Scan .rdata for vtables
  ├─ Generate text output files             ├─ Scan .data for global singletons
  └─ Cleanup                                └─ Write JSON + marker file, auto-unload
```

**IPC is via temp files** — the worker writes `%TEMP%/dezlock-export.json` and signals completion with `%TEMP%/dezlock-done`. No TCP, no pipes.

### Key source files

| File | What it does |
|------|-------------|
| `main.cpp` | CLI entry, PE manual-mapping, DLL injection, output generation |
| `worker.cpp` | Injected DLL entry, orchestrates all data collection |
| `src/schema-manager.{hpp,cpp}` | Walks SchemaSystem CUtlTSHash for classes/enums/fields |
| `src/rtti-hierarchy.{hpp,cpp}` | MSVC x64 RTTI scanning, inheritance chains, vtables |
| `src/global-scanner.{hpp,cpp}` | Auto-discovers global singletons from .data sections |
| `src/pattern-scanner.{hpp,cpp}` | Pattern-based global resolution from `patterns.json` |
| `src/log.{hpp,cpp}` | Thread-safe file logger for the worker DLL |
| `generate-signatures.py` | Converts vtable function bytes into IDA-style signatures |
| `import-schema.py` | Generates cherry-pickable C++ SDK headers |

## Testing changes

There's no automated test suite — the tool requires a running game process. To test:

1. Build with `build.bat`
2. Launch a supported game (Deadlock, CS2, or Dota 2)
3. Run `bin\dezlock-dump.exe` (requires admin elevation)
4. Verify output in `schema-dump/<game>/`

If you're working on output formatting or Python scripts, you can test against a previously captured `_all-modules.json` without needing a running game.

## Code conventions

### C++

- **C++17** standard, MSVC-only (no GCC/Clang compat needed)
- **SEH protection** — all memory reads in the worker DLL must use `__try/__except` since we're reading arbitrary game memory
- **No hooks or patches** — the tool is strictly read-only, it never modifies game memory
- **Hardcoded offsets** — schema struct offsets (CUtlTSHash at +0x0560, etc.) come from reverse engineering and are intentionally hardcoded
- No external dependencies beyond `vendor/json.hpp`

### Python

- Python 3 compatible
- No pip dependencies — stdlib only
- Use `ThreadPoolExecutor` for parallel processing (see existing scripts)

### General

- Keep changes focused — one feature or fix per PR
- Don't add unrelated cleanups, reformatting, or documentation changes alongside feature work
- File names use kebab-case (e.g., `schema-manager.cpp`, not `schemaManager.cpp`)
- No barrel files

## Submitting a pull request

1. **Fork** the repo and create a branch from `main`
2. **Make your changes** — keep them focused on a single issue or feature
3. **Build** with `build.bat` and verify it compiles cleanly
4. **Test** if you have access to a supported game, otherwise note this in the PR
5. **Push** your branch and open a PR against `main`

### PR checklist

Your PR description should cover:

- **What** changed and **why**
- Which issue it addresses (if any) — use `Closes #N`
- Whether it's been tested against a running game
- Any breaking changes or new dependencies

### What makes a good PR

- Solves one problem well
- Doesn't break existing functionality
- Includes clear commit messages
- Code matches existing patterns and style

## Reporting bugs

Open an [issue](https://github.com/dougwithseismic/dezlock-dump/issues/new?template=bug_report.md) with:

- The game and version you're targeting
- Your Windows version
- Steps to reproduce
- Expected vs. actual behavior
- Worker log (`%TEMP%/dezlock-worker.txt`) if relevant

## Suggesting features

Open an [issue](https://github.com/dougwithseismic/dezlock-dump/issues/new?template=feature_request.md) describing the use case and proposed solution. Check [existing issues](https://github.com/dougwithseismic/dezlock-dump/issues) first to avoid duplicates.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
