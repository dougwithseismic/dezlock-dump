/**
 * dezlock-dump -- Virtual Function Naming Engine
 *
 * Three-pass auto-naming system for vtable functions:
 *   Pass 1: Debug string xrefs ("ClassName::MethodName") -- highest confidence
 *   Pass 2: Protobuf descriptor method names -- medium confidence
 *   Pass 3: Member access inference (single-field getters/setters) -- heuristic
 *
 * Consumes JSON data from the worker DLL (vtables, string_refs, member_layouts,
 * protobuf_messages) and produces a VFuncMap used by the internal SDK generator
 * to emit VFUNC/VFUNC_RAW macros in class headers.
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include "vendor/json.hpp"

// Forward declare ClassInfo from import-schema.hpp
struct ClassInfo;

// Information about a single virtual function in a class vtable
struct VFuncInfo {
    int index = 0;                          // vtable slot index
    std::string name;                       // auto-discovered name (empty if unnamed)
    std::string source;                     // "debug_string", "protobuf", "member_infer", ""
    std::string signature;                  // IDA-style masked pattern (e.g. "48 89 5C 24 ? 57")
    bool is_stub = false;                   // true if detected as stub (excluded from output)
    std::string stub_type;                  // "ret", "xor_eax_ret", etc.
    std::string return_hint;                // "void*" default, "bool" for Is* inferred, etc.
    std::vector<std::string> accessed_fields; // field names this func touches (from member_layouts)
};

// All virtual functions for a single class
struct ClassVFuncTable {
    std::string class_name;
    std::string module_name;
    uint32_t vtable_rva = 0;
    std::vector<VFuncInfo> functions;
    int parent_vfunc_count = 0;             // functions[0..parent_vfunc_count-1] are inherited
};

// module_name -> class_name -> ClassVFuncTable
using VFuncMap = std::unordered_map<std::string, std::unordered_map<std::string, ClassVFuncTable>>;

// Build the complete VFuncMap from JSON data and schema class lookup.
// Runs three naming passes in sequence: debug strings, protobuf, member inference.
// Thread-safe: the returned map is read-only after construction.
VFuncMap build_vfunc_map(
    const nlohmann::json& data,
    const std::unordered_map<std::string, const ClassInfo*>& class_lookup);
