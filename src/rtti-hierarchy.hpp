/**
 * dezlock-dump — RTTI Inheritance Hierarchy Walker
 *
 * Scans a loaded module (client.dll) for MSVC x64 RTTI data to build
 * the complete C++ inheritance map for every virtual class.
 *
 * This is the missing piece for full schema resolution: the Source 2
 * SchemaSystem stores class fields but NOT the C++ parent chain.
 * RTTI always has it.
 */

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace schema {

struct InheritanceInfo {
    std::string parent;                  // direct parent class name (empty if root)
    std::vector<std::string> chain;      // full chain: [self, parent, grandparent, ...]
};

// Build inheritance map from RTTI data in a loaded module.
// Scans for TypeDescriptors and CompleteObjectLocators.
// Returns map of class_name -> InheritanceInfo.
std::unordered_map<std::string, InheritanceInfo>
build_rtti_hierarchy(uintptr_t module_base, size_t module_size);

} // namespace schema
