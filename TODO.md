# dezlock-dump -- Phase 2: Virtual Function Call Wrappers with Auto-Naming

**Date:** 2026-03-06
**Status:** Planning
**Branch:** `feat/vfunc-wrappers`

---

## Goal

Add auto-named virtual function call wrappers to the internal SDK so that injected DLL consumers can call game virtual functions through type-safe, macro-generated methods -- without manually looking up vtable indices or writing casts. Functions are automatically named from debug strings, protobuf descriptors, and member-access heuristics; unnamed functions get fallback `VFUNC_RAW` wrappers with signature comments for manual identification.

### Success Criteria

- [ ] All non-stub vtable functions appear as `VFUNC`, `VFUNC_ARGS`, or `VFUNC_RAW` in generated class headers
- [ ] Debug string xrefs (`"ClassName::MethodName"`) produce correctly named `VFUNC` entries
- [ ] Member access inference produces `Get`/`Set`/`Is`-prefixed named `VFUNC` entries for single-field accessors
- [ ] Stub functions (`ret`, `xor_eax_ret`, `int3`, etc.) are excluded from output
- [ ] Inherited vfuncs (index < parent_vfunc_count) are not re-emitted in child class headers
- [ ] `schema_runtime.hpp` with new VFUNC macros compiles standalone under MSVC `/std:c++17`
- [ ] Existing FIELD macro output in all class headers is unchanged (no regressions)
- [ ] Full project builds with zero warnings under `/W3`

---

## What's Already Done

### RTTI Hierarchy Scanner -- Complete
- [x] `src/rtti-hierarchy.hpp` / `src/rtti-hierarchy.cpp`
- [x] Discovers vtables per class, captures function RVAs and 128-byte prologues
- [x] Data type: `schema::InheritanceInfo` with `vtable_rva`, `vtable_func_rvas`, `vtable_func_bytes`
- [x] JSON output: `modules[].vtables[]` with `{ "class", "vtable_rva", "functions": [{ "index", "rva", "bytes" }] }`

### Signature Generator -- Complete
- [x] `src/generate-signatures.hpp` / `src/generate-signatures.cpp`
- [x] `detect_stub()` function at line 72 with `STUB_PATTERNS[]` array at line 61
- [x] 7 fixed patterns (`ret`, `xor_eax_ret`, `xor_al_ret`, `xorps_ret`, `mov_al_0_ret`, `mov_al_1_ret`, `int3`) plus dynamic checks (`mov_eax_imm_ret`, `lea_rax_ret`, all-CC padding)
- [x] IDA-style masked pattern generation, COMDAT dedup, shortest-unique-prefix trimming

### String Scanner -- Complete
- [x] `src/string-scanner.hpp` / `src/string-scanner.cpp`
- [x] Finds `"ClassName::MethodName"` debug strings in .rdata
- [x] Traces code xrefs via RIP-relative addressing
- [x] JSON output: `string_refs[module_name].strings[]` with `{ "value", "rva", "category", "associated_class", "xrefs": [{ "code_rva", "func_rva", "type" }] }`
- [x] Categories: `"convar"`, `"class_name"`, `"lifecycle"`, `"debug"`

### Member Access Analyzer -- Complete
- [x] `src/analyze-members.hpp` / `src/analyze-members.cpp`
- [x] Decodes x86-64 vtable function prologues, tracks schema field offsets each function reads/writes
- [x] JSON output: `member_layouts[module_name][class_name]` with `{ "vtable_size", "analyzed", "fields": [{ "offset", "size", "access", "funcs": [indices] }] }`
- [x] Access mask distinguishes read vs write operations

### Protobuf Scanner -- Complete
- [x] `src/protobuf-scanner.hpp` / `src/protobuf-scanner.cpp`
- [x] Decodes embedded FileDescriptorProto blobs from .rdata
- [x] Provides `MethodDescriptorProto`-level method names per service
- [x] JSON output: `protobuf[module_name][]` with nested messages, fields, enums

### Internal SDK Generator -- Complete (Phase 1)
- [x] `src/generate-internal-sdk.hpp` / `src/generate-internal-sdk.cpp`
- [x] `SCHEMA_RUNTIME_HPP` raw string literal (lines 552-739) containing full runtime resolver
- [x] Macros: `SCHEMA_CLASS`, `FIELD`, `FIELD_ARRAY`, `FIELD_PTR`, `FIELD_BLOB`
- [x] `generate_internal_class_header()` at line 860 -- emits per-class .hpp files
- [x] `process_module()` at line 1071 -- parallel per-module processing
- [x] `generate_internal_sdk()` at line 1123 -- entry point, builds `ISDKState`, dispatches threads
- [x] Cherry-pick helpers from `sdk-cherry-pick.json` emitted after FIELD section
- [x] Struct types: `ISDKState` (line 246), `ClassGenResult` (line 854), `ModuleResult` (line 1064), `InternalSdkStats` (line 9 in .hpp)

### Build System -- Complete
- [x] `CMakeLists.txt` with exe sources listed at lines 40-53
- [x] Worker DLL sources at lines 19-29
- [x] MSVC flags: `/O2 /MP /MT /EHsc /W3 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS`

---

## What We're Building Now

### Step 1: Create `src/vfunc-namer.hpp` -- Type Definitions
**Priority:** HIGH -- all other steps depend on these types
**File:** `E:\WEB_PROJECTS\ARCRAIDERS\dezlock-dump\src\vfunc-namer.hpp`

- [ ] Define `VFuncInfo` struct
  ```cpp
  struct VFuncInfo {
      int index;                    // vtable slot index
      std::string name;             // auto-discovered name (empty if unnamed)
      std::string source;           // "debug_string", "protobuf", "member_infer", ""
      std::string signature;        // IDA-style masked pattern (e.g. "48 89 5C 24 ? 57")
      bool is_stub = false;         // true if detected as stub (excluded from output)
      std::string stub_type;        // "ret", "xor_eax_ret", etc.
      std::string return_hint;      // "void*" default, "bool" for Is* inferred, etc.
      std::vector<std::string> accessed_fields; // field names this func touches (from member_layouts)
  };
  ```

- [ ] Define `ClassVFuncTable` struct
  ```cpp
  struct ClassVFuncTable {
      std::string class_name;
      std::string module_name;
      uint32_t vtable_rva = 0;
      std::vector<VFuncInfo> functions;
      int parent_vfunc_count = 0;   // functions[0..parent_vfunc_count-1] are inherited
  };
  ```

- [ ] Define `VFuncMap` type alias
  ```cpp
  // module_name -> class_name -> ClassVFuncTable
  using VFuncMap = std::unordered_map<std::string, std::unordered_map<std::string, ClassVFuncTable>>;
  ```

- [ ] Declare `build_vfunc_map()` function
  ```cpp
  VFuncMap build_vfunc_map(
      const nlohmann::json& data,
      const std::unordered_map<std::string, const ClassInfo*>& class_lookup);
  ```

- [ ] Include guards, required headers: `<string>`, `<vector>`, `<unordered_map>`, `<cstdint>`, `"vendor/json.hpp"`, `"src/import-schema.hpp"`

**Example output for a ClassVFuncTable:**
```
ClassVFuncTable {
    class_name: "C_BaseEntity",
    module_name: "client.dll",
    vtable_rva: 0x1A2B3C,
    parent_vfunc_count: 12,
    functions: [
        { index: 12, name: "GetAbsOrigin", source: "debug_string", ... },
        { index: 13, name: "GetHealth",    source: "member_infer", ... },
        { index: 14, name: "",             source: "",             ... },  // unnamed -> VFUNC_RAW
    ]
}
```

---

### Step 2: Create `src/vfunc-namer.cpp` -- Three-Pass Naming Engine
**Priority:** HIGH -- core logic for the entire feature
**File:** `E:\WEB_PROJECTS\ARCRAIDERS\dezlock-dump\src\vfunc-namer.cpp`

- [ ] Implement `extract_class_method()` helper
  - Input: `"CBaseEntity::GetAbsOrigin"` or `"C_BaseEntity::SetHealth"`
  - Output: `std::pair<std::string, std::string>{"CBaseEntity", "GetAbsOrigin"}`
  - Handle edge cases: no `::` separator returns empty pair; nested `::` (e.g. `"ns::Class::Method"`) takes last `::` as delimiter
  - Strip `C_` prefix variant for matching: both `"C_BaseEntity"` and `"CBaseEntity"` should match RTTI class `"C_BaseEntity"`

- [ ] Implement `infer_getter_name()` helper
  - Input: field name string from schema (e.g. `"m_iHealth"`, `"m_bAlive"`, `"m_flSpeed"`)
  - Output: PascalCase method name with appropriate prefix
  - Rules:
    - Strip `m_` prefix
    - Strip Hungarian notation prefix: `i`, `fl`, `n`, `sz`, `str`, `h`, `vec`, `ang`, `clr`, `ul`, `us`, `uch` (single lowercase letter or known prefix before uppercase)
    - `m_b*` fields (bool) -> `Is*` prefix (e.g. `m_bAlive` -> `IsAlive`)
    - All other fields -> `Get*` prefix (e.g. `m_iHealth` -> `GetHealth`, `m_flSpeed` -> `GetSpeed`)
    - Write accessor -> `Set*` prefix (e.g. `m_iHealth` write -> `SetHealth`)
  - Ensure first letter after prefix is uppercase

- [ ] Implement `build_func_rva_index()` internal helper
  - Build a map of `func_rva (uint32_t) -> { module_name, class_name, vtable_index }` from `data["modules"][].vtables[].functions[]`
  - This enables O(1) lookup when matching string xref `func_rva` values to vtable entries

- [ ] Implement stub detection (reuse from generate-signatures.cpp)
  - Either `#include "src/generate-signatures.cpp"` is not viable (static functions), so replicate the ~30-line `detect_stub()` logic or extract it to a shared header
  - **Preferred approach:** Extract `detect_stub()` and `STUB_PATTERNS` into a new shared header `src/stub-detect.hpp` as inline functions, then include from both `generate-signatures.cpp` and `vfunc-namer.cpp`
  - Alternatively, duplicate the stub detection locally (simpler, fewer file changes)

- [ ] Implement `build_vfunc_map()` -- main entry point

  **Phase 1 -- Populate base data:**
  - Iterate `data["modules"]` array
  - For each module with `"vtables"` array, iterate vtable entries
  - For each `vtable.functions[]`, create a `VFuncInfo` with index, parse hex bytes, run stub detection
  - Generate IDA-style masked signature string (reuse `mask_relocations()` logic from generate-signatures.cpp or simplified version)
  - Store in `VFuncMap[module_name][class_name]`

  **Phase 2 -- Resolve inheritance:**
  - For each `ClassVFuncTable`, look up parent class via `class_lookup`
  - Walk parent chain to find parent's vtable function count
  - Set `parent_vfunc_count` = number of functions in direct parent's vtable (from the parent's `ClassVFuncTable` if available, else 0)
  - If parent class exists in same module's VFuncMap, use its function count directly
  - If parent is in a different module, search across all modules

  **Pass 1 -- Debug String Xrefs (highest confidence):**
  - Iterate `data["string_refs"][module_name]["strings"]`
  - For each string where `category == "debug"` and value matches `ClassName::MethodName` pattern (contains exactly one `::` with non-empty parts)
  - Call `extract_class_method()` to get class + method name
  - For each xref in the string entry, check if `xref.func_rva` (parsed from hex string) matches any vtable function RVA in the func_rva_index
  - If match found: set `VFuncInfo.name = method_name`, `VFuncInfo.source = "debug_string"`
  - Handle RVA format: values in JSON are hex strings like `"0x1A2B3C"`, parse with `std::strtoul(str.c_str(), nullptr, 16)`

  **Pass 2 -- Protobuf Method Names (medium confidence):**
  - Iterate `data["protobuf"][module_name][]` proto files
  - For each message that has a name matching an RTTI class (check `class_lookup`), and the message has methods/services
  - This pass is lower yield since protobuf methods rarely map directly to vtable functions
  - Only apply if the function has no name from Pass 1
  - Set `VFuncInfo.source = "protobuf"` when applied

  **Pass 3 -- Member Access Inference (heuristic):**
  - Iterate `data["member_layouts"][module_name][class_name]["fields"]`
  - Each field entry has `"funcs": [vtable_indices]` and `"access": "read"/"write"/"read_write"`
  - For each field accessed by exactly ONE vtable function:
    - Look up the vtable function in our `ClassVFuncTable`
    - If function already has a name from Pass 1/2, skip
    - Cross-reference `field.offset` against the schema `class_lookup` to find the field name (match by offset value against `ClassInfo.fields[].offset`)
    - If matched and access is read-only: `VFuncInfo.name = infer_getter_name(field_name)`, source = `"member_infer"`, return_hint based on field type
    - If matched and access is write-only: name = `"Set" + PascalCaseName`, source = `"member_infer"`
    - If read_write: skip (ambiguous)
  - Populate `VFuncInfo.accessed_fields` for all functions regardless of naming (useful as comments)

**Example use cases:**
1. `C_BaseEntity::GetAbsOrigin` debug string xref matches vtable index 15 -> `VFUNC(15, void*, GetAbsOrigin)`
2. Vtable function at index 22 reads only `m_iHealth` (offset 0x100) -> `VFUNC(22, int32_t, GetHealth)`
3. Vtable function at index 7 is `0xC3` (ret stub) -> excluded entirely
4. Vtable function at index 30 has no name match, accesses `m_flSpeed` and `m_vecVelocity` -> `VFUNC_RAW(30)` with comment listing accessed fields

---

### Step 3: Extract Shared Stub Detection (Optional Refactor)
**Priority:** MEDIUM -- reduces code duplication, but can be deferred
**File:** `E:\WEB_PROJECTS\ARCRAIDERS\dezlock-dump\src\stub-detect.hpp`

- [ ] Create header-only `src/stub-detect.hpp` with `inline` functions
  - Move `StubPattern` struct, `STUB_PATTERNS[]` array, and `detect_stub()` function
  - Mark as `inline` to avoid ODR violations
  - Keep the dynamic checks (mov_eax_imm_ret, lea_rax_ret, all-CC padding)
- [ ] Update `src/generate-signatures.cpp` to `#include "src/stub-detect.hpp"` and remove local copies
- [ ] Include from `src/vfunc-namer.cpp`

**Decision point:** If this refactor is too risky (touching working code), simply duplicate the ~40 lines of stub detection in `vfunc-namer.cpp` with a `// Duplicated from generate-signatures.cpp` comment. Both approaches are acceptable.

---

### Step 4: Extend `schema_runtime.hpp` with VFUNC Macros
**Priority:** HIGH -- the macros are what end users consume
**File:** `E:\WEB_PROJECTS\ARCRAIDERS\dezlock-dump\src\generate-internal-sdk.cpp` (modify `SCHEMA_RUNTIME_HPP` raw string literal)

- [ ] Add `sdk::vfunc` namespace with `get_vtable()` helper after the existing `FIELD_BLOB` macro (before the closing `)";` at line 739)
  ```cpp
  // ---- Virtual function call wrappers ----

  namespace sdk::vfunc {

  inline uintptr_t* get_vtable(void* obj) {
      uintptr_t* vt = nullptr;
      __try { vt = *reinterpret_cast<uintptr_t**>(obj); }
      __except(EXCEPTION_EXECUTE_HANDLER) { vt = nullptr; }
      return vt;
  }

  } // namespace sdk::vfunc
  ```

- [ ] Add `VFUNC` macro -- zero-argument virtual function call
  ```cpp
  #define VFUNC(idx, ret, name)                                          \
      ret name() {                                                       \
          auto _vt = ::sdk::vfunc::get_vtable(this);                     \
          if (!_vt) return ret{};                                        \
          return reinterpret_cast<ret(__fastcall*)(void*)>(_vt[idx])(this); \
      }
  ```

- [ ] Add `VFUNC_ARGS` macro -- variadic-argument virtual function call
  ```cpp
  #define VFUNC_ARGS(idx, ret, name, ...)                                \
      template<typename... _VArgs>                                       \
      ret name(_VArgs&&... args) {                                       \
          auto _vt = ::sdk::vfunc::get_vtable(this);                     \
          if (!_vt) return ret{};                                        \
          using _Fn = ret(__fastcall*)(void*, _VArgs...);                \
          return reinterpret_cast<_Fn>(_vt[idx])(this, std::forward<_VArgs>(args)...); \
      }
  ```

- [ ] Add `VFUNC_RAW` macro -- unnamed fallback returning `void*`
  ```cpp
  #define VFUNC_RAW(idx)                                                 \
      void* vfunc_##idx() {                                              \
          auto _vt = ::sdk::vfunc::get_vtable(this);                     \
          if (!_vt) return nullptr;                                      \
          return reinterpret_cast<void*(__fastcall*)(void*)>(_vt[idx])(this); \
      }
  ```

- [ ] Verify the raw string literal remains valid C++ (no unescaped `)"` sequences)
- [ ] Ensure `<utility>` is included in the runtime header for `std::forward` (add `#include <utility>` near the top of the raw string)

---

### Step 5: Modify `generate_internal_class_header()` to Emit VFUNCs
**Priority:** HIGH -- this is where vfunc data enters the generated headers
**File:** `E:\WEB_PROJECTS\ARCRAIDERS\dezlock-dump\src\generate-internal-sdk.cpp`

- [ ] Add `#include "src/vfunc-namer.hpp"` at the top of the file (after line 8)

- [ ] Add `const ClassVFuncTable*` parameter to `generate_internal_class_header()`
  - Current signature (line 860):
    ```cpp
    static ClassGenResult generate_internal_class_header(
        const ClassInfo& cls, const std::string& module_name,
        const ISDKState& state, const std::string& timestamp)
    ```
  - New signature:
    ```cpp
    static ClassGenResult generate_internal_class_header(
        const ClassInfo& cls, const std::string& module_name,
        const ISDKState& state, const std::string& timestamp,
        const ClassVFuncTable* vftable)  // nullptr if no vtable data
    ```

- [ ] Add `int vfunc_count = 0;` to `ClassGenResult` struct (line 854)

- [ ] Implement `emit_vfunc_section()` static function
  ```cpp
  static void emit_vfunc_section(
      std::vector<std::string>& lines,
      const ClassVFuncTable& vft,
      int& vfunc_count)
  ```
  - Emit section header comment: `// --- Virtual functions (vtable RVA: 0xXXXXXX) ---`
  - Iterate `vft.functions` from index `vft.parent_vfunc_count` to end (skip inherited)
  - Skip entries where `is_stub == true`
  - For named functions: emit `VFUNC(idx, return_hint, name);` with trailing comment showing source
    - Example: `    VFUNC(15, void*, GetAbsOrigin);  // source: debug_string`
  - For unnamed functions: emit `VFUNC_RAW(idx);` with trailing comment showing signature + accessed fields
    - Example: `    VFUNC_RAW(30);  // sig: 48 89 5C 24 08, reads: m_flSpeed`
  - Increment `vfunc_count` for each emitted entry

- [ ] Call `emit_vfunc_section()` in `generate_internal_class_header()` after cherry-pick helpers (after line 971, before the closing `};`)
  ```cpp
  // Emit virtual functions
  if (vftable && !vftable->functions.empty()) {
      lines.push_back("");
      emit_vfunc_section(lines, *vftable, result.vfunc_count);
  }
  ```

---

### Step 6: Thread VFuncMap Through `process_module()` and `generate_internal_sdk()`
**Priority:** HIGH -- wiring everything together
**File:** `E:\WEB_PROJECTS\ARCRAIDERS\dezlock-dump\src\generate-internal-sdk.cpp`

- [ ] Add `int vfuncs = 0;` to `ModuleResult` struct (line 1064)

- [ ] Add `const VFuncMap*` parameter to `process_module()`
  - Current signature (line 1071):
    ```cpp
    static ModuleResult process_module(const ModuleData& mod,
        const ISDKState& state, const std::string& output_dir,
        const std::string& timestamp)
    ```
  - New signature:
    ```cpp
    static ModuleResult process_module(const ModuleData& mod,
        const ISDKState& state, const std::string& output_dir,
        const std::string& timestamp, const VFuncMap* vfunc_map)
    ```

- [ ] Inside `process_module()`, look up the module's vfunc data:
  ```cpp
  const std::unordered_map<std::string, ClassVFuncTable>* mod_vfuncs = nullptr;
  if (vfunc_map) {
      auto it = vfunc_map->find(mod.name);
      if (it != vfunc_map->end()) mod_vfuncs = &it->second;
  }
  ```

- [ ] Pass per-class `ClassVFuncTable*` to `generate_internal_class_header()`:
  ```cpp
  const ClassVFuncTable* vft = nullptr;
  if (mod_vfuncs) {
      auto vit = mod_vfuncs->find(cls.name);
      if (vit != mod_vfuncs->end()) vft = &vit->second;
  }
  ClassGenResult gen = generate_internal_class_header(cls, mod.name, state, timestamp, vft);
  ```

- [ ] Accumulate vfunc stats: `result.vfuncs += gen.vfunc_count;`

- [ ] In `generate_internal_sdk()` (line 1123):
  - Call `build_vfunc_map(data, class_lookup)` early, before module processing
  - Pass `&vfunc_map` to each `process_module()` call
  - Aggregate `stats.vfuncs` from all `ModuleResult` values

---

### Step 7: Update `InternalSdkStats` and Summary Output
**Priority:** MEDIUM -- user-facing reporting
**Files:**
- `E:\WEB_PROJECTS\ARCRAIDERS\dezlock-dump\src\generate-internal-sdk.hpp`
- `E:\WEB_PROJECTS\ARCRAIDERS\dezlock-dump\main.cpp`

- [ ] Add `int vfuncs = 0;` to `InternalSdkStats` struct in `generate-internal-sdk.hpp` (after line 14)

- [ ] Update `main.cpp` summary output where `InternalSdkStats` is printed
  - Line ~255 (schema path mode):
    ```cpp
    con_ok("Internal SDK: %d classes, %d fields, %d vfuncs, %d enums -> %s\\",
           isdk_stats.classes, isdk_stats.fields, isdk_stats.vfuncs, isdk_stats.enums, isdk_output.c_str());
    ```
  - Line ~622 (live dump mode): same update pattern

---

### Step 8: Update `CMakeLists.txt`
**Priority:** HIGH -- build will fail without this
**File:** `E:\WEB_PROJECTS\ARCRAIDERS\dezlock-dump\CMakeLists.txt`

- [ ] Add `src/vfunc-namer.cpp` to the exe source list (after line 49, near `src/analyze-members.cpp`)
  ```cmake
  add_executable(dezlock-dump
      main.cpp
      src/console.cpp
      src/injector.cpp
      src/cli.cpp
      src/output-generator.cpp
      src/generate-signatures.cpp
      src/import-schema.cpp
      src/generate-internal-sdk.cpp
      src/analyze-members.cpp
      src/vfunc-namer.cpp          # <-- NEW
      src/ws-server.cpp
      src/live-bridge.cpp
      src/version-check.cpp
  )
  ```

- [ ] If `src/stub-detect.hpp` was created (Step 3), no CMake change needed (header-only)

---

### Step 9: Build and Validate
**Priority:** HIGH -- verification gate
**Commands:**
```bat
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

- [ ] Build succeeds with zero errors
- [ ] Build succeeds with zero warnings under `/W3`
- [ ] Run with existing JSON data:
  ```bat
  build\bin\Release\dezlock-dump.exe --schema path\to\_all-modules.json --internal-sdk
  ```
- [ ] Verify `internal-sdk/schema_runtime.hpp` contains VFUNC, VFUNC_ARGS, VFUNC_RAW macros and `sdk::vfunc::get_vtable()`
- [ ] Verify `internal-sdk/client/entities/C_BaseEntity.hpp` (or equivalent) contains VFUNC entries after FIELD entries
- [ ] Verify stubs are excluded (no `VFUNC` for index 0 if it's a `ret` stub)
- [ ] Verify inherited vfuncs are not re-emitted (child class with parent_vfunc_count=12 starts at index 12)
- [ ] Verify auto-named functions have correct names and source comments
- [ ] Verify unnamed functions have `VFUNC_RAW(idx)` with signature and field-access comments
- [ ] Verify FIELD macros are unchanged in all headers (diff against previous output)
- [ ] Test `schema_runtime.hpp` compiles standalone:
  ```cpp
  // test_compile.cpp
  #include "schema_runtime.hpp"
  struct TestEntity {
      SCHEMA_CLASS("client.dll", "C_BaseEntity");
      FIELD(m_iHealth, int32_t);
      VFUNC(5, void*, GetAbsOrigin);
      VFUNC_RAW(10);
  };
  int main() { return 0; }
  ```

---

## Not In Scope

### Argument Type Inference for VFUNC_ARGS
- The auto-naming system does NOT attempt to infer function argument types from prologue disassembly
- **Why:** Reliably deducing parameter types from x86-64 machine code without PDB symbols is an unsolved problem. Users must manually specify argument types via `VFUNC_ARGS` when they know the signature. The default `VFUNC` and `VFUNC_RAW` macros use `void*` return and zero extra args.

### Return Type Inference Beyond Heuristics
- We provide `return_hint` based on field type for `Get*` inferences (e.g. bool field -> `bool` return) but do NOT analyze register usage in epilogues
- **Why:** Epilogue analysis for return types requires full-function disassembly far beyond the captured 128-byte prologues. Phase 3 could add this with a longer capture window.

### Cross-Module Vtable Inheritance Resolution
- Parent vfunc count resolution only works when both parent and child have vtable data in the JSON
- **Why:** Some parent classes may be in modules that weren't dumped. We default `parent_vfunc_count = 0` in these cases, which means some inherited entries may appear in child classes. This is a conservative choice -- better to emit duplicates than miss entries.

### SDK Cherry-Pick Integration for VFUNCs
- VFUNC entries are NOT configurable via `sdk-cherry-pick.json`
- **Why:** Cherry-pick is designed for hand-written helper methods. VFUNCs are auto-generated from data. Phase 3 could add a `vfunc-overrides.json` for manual name corrections.

### Signature Deduplication (COMDAT-Folded VFUNCs)
- Two different classes may have vtable entries pointing to the same function RVA (COMDAT folding). We do NOT deduplicate these in the VFUNC output -- each class gets its own entry.
- **Why:** From the user's perspective, each class should have its own callable wrapper regardless of whether the underlying implementation is shared. Dedup is only relevant for pattern scanning, which is handled by `generate-signatures.cpp`.

---

## Implementation Plan

### Phase A: Foundation (2-3 hours)
1. **(30 min)** Create `src/vfunc-namer.hpp` with all type definitions (Step 1)
2. **(15 min)** Decide on stub detection approach: shared header vs. duplication. Create `src/stub-detect.hpp` if going shared route (Step 3)
3. **(90 min)** Implement `src/vfunc-namer.cpp` with all three naming passes (Step 2)
   - Start with `build_func_rva_index()` and basic population
   - Add Pass 1 (debug strings) -- test with known `ClassName::MethodName` patterns
   - Add Pass 2 (protobuf) -- likely low yield, keep simple
   - Add Pass 3 (member inference) -- test with single-field-access functions
4. **(15 min)** Add to `CMakeLists.txt` and verify it compiles in isolation (Step 8)

### Phase B: Integration (1-2 hours)
5. **(30 min)** Extend `SCHEMA_RUNTIME_HPP` with VFUNC macros (Step 4)
6. **(45 min)** Modify `generate_internal_class_header()`, `process_module()`, `generate_internal_sdk()` (Steps 5-6)
7. **(15 min)** Update `InternalSdkStats` and main.cpp summary output (Step 7)

### Phase C: Validation (1 hour)
8. **(30 min)** Full build, fix any compile errors/warnings (Step 9)
9. **(30 min)** Run against real JSON data, inspect generated headers, verify all criteria

**Total estimated time: 4-6 hours**

---

## Definition of Done

- [ ] `src/vfunc-namer.hpp` and `src/vfunc-namer.cpp` exist and compile cleanly
- [ ] `schema_runtime.hpp` output contains `VFUNC`, `VFUNC_ARGS`, `VFUNC_RAW` macros and `sdk::vfunc::get_vtable()`
- [ ] Generated class headers contain a `// --- Virtual functions ---` section after fields/helpers
- [ ] Named vfuncs use `VFUNC(idx, type, Name)` format with `// source:` comments
- [ ] Unnamed vfuncs use `VFUNC_RAW(idx)` format with `// sig:` and field-access comments
- [ ] Stubs are excluded from all generated output
- [ ] Child classes do not re-emit parent vtable indices
- [ ] Console summary reports vfunc count: `"Internal SDK: X classes, Y fields, Z vfuncs, W enums"`
- [ ] Full project builds with zero warnings under MSVC `/W3 /std:c++17`
- [ ] Existing FIELD macro output is byte-identical to pre-change output (no regressions)

---

## Notes

### Tech Stack
- **C++17 / MSVC x64** -- matches existing codebase, no new dependencies
- **nlohmann/json** (`vendor/json.hpp`) -- all JSON parsing uses this, no alternatives
- **No disassembly library** -- prologue analysis uses hand-written byte pattern matching (consistent with existing `analyze-members.cpp` approach)

### Design Principles
- **Data-driven naming** -- all function names come from existing JSON data (debug strings, protobuf, member layouts). No new data collection in the worker DLL is required.
- **Conservative naming** -- if a naming heuristic has any ambiguity (multiple field accesses, read_write access), we fall back to `VFUNC_RAW` rather than risk a wrong name.
- **SEH everywhere** -- `get_vtable()` uses `__try/__except` consistent with all other runtime memory reads in schema_runtime.hpp.
- **Backward compatible** -- the new feature is purely additive. All existing FIELD output, file structure, and API signatures (with default nullptr) remain unchanged.

### Best Practices
- **Parse hex RVA strings safely** -- JSON stores RVAs as `"0x1A2B3C"` strings. Always use `std::strtoul(s.c_str() + 2, nullptr, 16)` or handle both `0x`-prefixed and bare hex.
- **Thread safety** -- `build_vfunc_map()` runs single-threaded before the parallel module processing. The resulting `VFuncMap` is read-only during header generation, so no mutex needed.
- **Inline stub detect** -- if using shared header approach, all functions must be `inline` or `static` to avoid multiple-definition linker errors.

---

## Next Steps (Future Phases)

### Phase 3: Extended Prologue Capture + Return Type Inference
- Increase function byte capture from 128 to 512 bytes in `rtti-hierarchy.cpp`
- Analyze epilogue patterns (`mov eax, ...` vs `xorps xmm0, ...`) to infer return types beyond heuristics
- Rough timeline: 1-2 sprints after Phase 2 ships

### Phase 4: VFUNC Override Configuration
- Add `vfunc-overrides.json` for manual name corrections, argument types, and exclusions
- Allow users to pin names for functions where auto-detection fails
- Rough timeline: 1 sprint after Phase 3

### Phase 5: Dynamic VFUNC Resolution (Runtime Vtable Index Lookup)
- Instead of hardcoded vtable indices, resolve at runtime by pattern-matching function prologues
- Makes the internal SDK resilient to vtable reordering across game patches
- Rough timeline: 2-3 sprints (research-heavy)
