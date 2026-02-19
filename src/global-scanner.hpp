#pragma once
#ifndef DEZLOCK_GLOBAL_SCANNER_HPP
#define DEZLOCK_GLOBAL_SCANNER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "rtti-hierarchy.hpp"

namespace globals {

// ============================================================================
// Types
// ============================================================================

struct DiscoveredGlobal {
    std::string class_name;      // RTTI class name (e.g. "CGameEntitySystem")
    std::string module;          // module containing the global (e.g. "client.dll")
    uint32_t    global_rva;      // RVA of the global variable in .data
    uint32_t    vtable_rva;      // RVA of the matched vtable
    bool        is_pointer;      // true = .data has pointer to heap object
                                 // false = .data IS the object (vtable at start)
    bool        has_schema;      // true = class exists in SchemaSystem (known fields)
};

// module name -> list of discovered globals
using GlobalMap = std::unordered_map<std::string, std::vector<DiscoveredGlobal>>;

// ============================================================================
// API
// ============================================================================

// Scan writable (.data) sections of all modules that have RTTI classes.
// Cross-references 8-byte values against known vtable addresses.
//
// Two-pass per module:
//   1. Direct: value at .data addr matches a vtable RVA (object lives in .data)
//   2. Indirect: value is a pointer to memory whose first 8 bytes match a vtable
//      (object on heap, .data has a pointer to it)
//
// rtti_map:      class_name -> InheritanceInfo (with vtable_rva + source_module)
// schema_classes: set of class names that have SchemaSystem entries (for tagging)
GlobalMap scan(const std::unordered_map<std::string, schema::InheritanceInfo>& rtti_map,
               const std::unordered_set<std::string>& schema_classes);

} // namespace globals

#endif // DEZLOCK_GLOBAL_SCANNER_HPP
