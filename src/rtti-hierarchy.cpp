/**
 * dezlock-dump — RTTI Inheritance Hierarchy Walker
 *
 * Walks MSVC x64 RTTI structures in a loaded module to discover
 * the complete C++ class hierarchy. Three passes:
 *
 *   1. Scan for TypeDescriptor names (".?AV" prefix) -> RVA-to-name map
 *   2. Scan for CompleteObjectLocators (signature=1, selfRVA valid) -> COL list
 *   3. For each COL, walk ClassHierarchyDescriptor -> BaseClassArray -> parent chain
 *
 * Total time: ~30-60ms for a 60MB module (client.dll). Runs once at init.
 */

#define LOG_TAG "rtti"

#include "rtti-hierarchy.hpp"
#include "log.hpp"

#include <Windows.h>
#include <cstring>

namespace schema {

// ============================================================================
// MSVC x64 RTTI structures (in-memory layout)
// ============================================================================

#pragma pack(push, 1)
struct RTTICompleteObjectLocator {
    uint32_t signature;            // 1 for x64
    uint32_t offset;               // offset of this vtable in class
    uint32_t cd_offset;
    int32_t  type_desc_rva;        // RVA to TypeDescriptor
    int32_t  class_hierarchy_rva;  // RVA to ClassHierarchyDescriptor
    int32_t  self_rva;             // RVA of this COL (self-validation)
};
#pragma pack(pop)

struct RTTIClassHierarchyDescriptor {
    uint32_t signature;            // 0
    uint32_t attributes;
    uint32_t num_base_classes;
    int32_t  base_class_array_rva; // RVA to array of RVAs
};

struct RTTIBaseClassDescriptor {
    int32_t  type_desc_rva;
    uint32_t num_contained_bases;
    int32_t  mdisp;
    int32_t  pdisp;
    int32_t  vdisp;
    uint32_t attributes;
    int32_t  class_hierarchy_rva;
};

// ============================================================================
// Helpers
// ============================================================================

// Extract clean class name from mangled RTTI name.
// ".?AVC_BaseEntity@@" -> "C_BaseEntity"
// ".?AVCEntityInstance@@" -> "CEntityInstance"
static std::string demangle(const char* mangled) {
    if (!mangled || strncmp(mangled, ".?AV", 4) != 0) return {};
    const char* start = mangled + 4;
    const char* end = strstr(start, "@@");
    if (!end || (end - start) > 256 || (end - start) <= 0) return {};
    return std::string(start, end - start);
}

// ============================================================================
// Main scanner
// ============================================================================

std::unordered_map<std::string, InheritanceInfo>
build_rtti_hierarchy(uintptr_t base, size_t size) {
    std::unordered_map<std::string, InheritanceInfo> result;

    if (!base || size < 0x1000) return result;

    const uint8_t* mem = reinterpret_cast<const uint8_t*>(base);

    // ========================================================================
    // Pass 1: Find all TypeDescriptors by scanning for ".?AV" name strings.
    // TypeDescriptor layout (x64):
    //   +0x00  vtable_ptr (8 bytes)
    //   +0x08  spare      (8 bytes)
    //   +0x10  name[]     (mangled C string, starts with ".?AV")
    // ========================================================================

    std::unordered_map<int32_t, std::string> rva_to_name;  // TD RVA -> clean name

    for (size_t i = 0; i + 20 < size; i++) {
        if (mem[i] != '.' || mem[i+1] != '?' || mem[i+2] != 'A' || mem[i+3] != 'V')
            continue;

        // Candidate TypeDescriptor.name at offset i
        // TypeDescriptor starts at i - 0x10
        if (i < 0x10) continue;

        const char* name_start = reinterpret_cast<const char*>(mem + i);

        // Quick validation: must end with "@@" within 256 chars
        const char* at_at = strstr(name_start, "@@");
        if (!at_at || (at_at - name_start) > 256) continue;

        // Ensure no weird characters in the name
        bool valid = true;
        for (const char* p = name_start + 4; p < at_at; p++) {
            if (*p < 0x20 || *p > 0x7E) { valid = false; break; }
        }
        if (!valid) continue;

        std::string clean = demangle(name_start);
        if (clean.empty()) continue;

        int32_t td_rva = static_cast<int32_t>(i - 0x10);
        rva_to_name[td_rva] = std::move(clean);
    }

    LOG_I("pass 1: found %d type descriptors", (int)rva_to_name.size());

    // ========================================================================
    // Pass 2: Find all CompleteObjectLocators.
    // COL is 24 bytes, aligned to 4. Validated by:
    //   signature == 1 (x64)
    //   self_rva == offset of this COL within the module
    //   type_desc_rva points to a known TypeDescriptor
    // ========================================================================

    struct COLEntry {
        std::string class_name;
        int32_t hierarchy_rva;
    };
    std::vector<COLEntry> cols;

    for (size_t i = 0; i + sizeof(RTTICompleteObjectLocator) <= size; i += 4) {
        auto* col = reinterpret_cast<const RTTICompleteObjectLocator*>(mem + i);

        if (col->signature != 1) continue;
        if (col->self_rva != static_cast<int32_t>(i)) continue;

        // Must reference a known TypeDescriptor
        auto it = rva_to_name.find(col->type_desc_rva);
        if (it == rva_to_name.end()) continue;

        cols.push_back({it->second, col->class_hierarchy_rva});
    }

    LOG_I("pass 2: found %d complete object locators", (int)cols.size());

    // ========================================================================
    // Pass 3: For each COL, walk the hierarchy to build parent chain.
    //
    // ClassHierarchyDescriptor -> base_class_array (array of RVAs)
    // Each RVA -> BaseClassDescriptor -> type_desc_rva -> class name
    //
    // Array order is DFS of the hierarchy:
    //   [0] = self
    //   [1] = direct parent
    //   [2] = direct parent's parent
    //   ... etc
    // ========================================================================

    for (const auto& col : cols) {
        // Skip if already processed (first COL for a class = primary vtable)
        if (result.count(col.class_name)) continue;

        // Validate hierarchy RVA
        if (col.hierarchy_rva < 0 ||
            static_cast<size_t>(col.hierarchy_rva) + sizeof(RTTIClassHierarchyDescriptor) > size)
            continue;

        auto* hierarchy = reinterpret_cast<const RTTIClassHierarchyDescriptor*>(
            mem + col.hierarchy_rva);

        if (hierarchy->num_base_classes == 0 || hierarchy->num_base_classes > 64)
            continue;

        // Read base class array
        int32_t bca_rva = hierarchy->base_class_array_rva;
        if (bca_rva < 0 ||
            static_cast<size_t>(bca_rva) + hierarchy->num_base_classes * 4 > size)
            continue;

        const int32_t* bca = reinterpret_cast<const int32_t*>(mem + bca_rva);

        InheritanceInfo info;

        for (uint32_t j = 0; j < hierarchy->num_base_classes; j++) {
            int32_t bcd_rva = bca[j];
            if (bcd_rva < 0 ||
                static_cast<size_t>(bcd_rva) + sizeof(RTTIBaseClassDescriptor) > size)
                continue;

            auto* bcd = reinterpret_cast<const RTTIBaseClassDescriptor*>(mem + bcd_rva);

            auto name_it = rva_to_name.find(bcd->type_desc_rva);
            if (name_it == rva_to_name.end()) continue;

            info.chain.push_back(name_it->second);

            // [1] = direct parent
            if (j == 1) {
                info.parent = name_it->second;
            }
        }

        result[col.class_name] = std::move(info);
    }

    LOG_I("pass 3: built inheritance map for %d classes", (int)result.size());

    return result;
}

} // namespace schema
