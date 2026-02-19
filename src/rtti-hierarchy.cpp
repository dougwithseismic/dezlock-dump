/**
 * dezlock-dump — RTTI Inheritance Hierarchy Walker
 *
 * Walks MSVC x64 RTTI structures in a loaded module to discover
 * the complete C++ class hierarchy. Three passes:
 *
 *   1. Scan for TypeDescriptor names (".?AV"/".?AU" prefixes) -> RVA-to-name map
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
#include <unordered_set>

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

// SEH-safe memcpy for reading function bytes at potentially-invalid addresses.
// Isolated in its own function because __try cannot coexist with C++ destructors.
static size_t safe_memcpy(void* dst, const void* src, size_t len) {
    __try {
        memcpy(dst, src, len);
        return len;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// Extract clean class name from mangled RTTI name.
// ".?AVC_BaseEntity@@" -> "C_BaseEntity"       (class)
// ".?AUCEntityInstance@@" -> "CEntityInstance"  (struct)
static std::string demangle(const char* mangled) {
    if (!mangled || (strncmp(mangled, ".?AV", 4) != 0 && strncmp(mangled, ".?AU", 4) != 0)) return {};
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
    // Pass 1: Find all TypeDescriptors by scanning for ".?AV"/".?AU" name strings.
    // TypeDescriptor layout (x64):
    //   +0x00  vtable_ptr (8 bytes)
    //   +0x08  spare      (8 bytes)
    //   +0x10  name[]     (mangled C string, starts with ".?AV" or ".?AU")
    // ========================================================================

    std::unordered_map<int32_t, std::string> rva_to_name;  // TD RVA -> clean name

    for (size_t i = 0; i + 20 < size; i++) {
        if (mem[i] != '.' || mem[i+1] != '?' || mem[i+2] != 'A' || (mem[i+3] != 'V' && mem[i+3] != 'U'))
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

    // ========================================================================
    // Pass 4: Discover vtables by scanning .rdata for COL pointers.
    //
    // MSVC x64: vtable[-1] = pointer to CompleteObjectLocator.
    //           vtable[0]  = first virtual function pointer.
    //
    // Strategy: Build set of all COL absolute addresses, then do one linear
    // scan of .rdata checking each 8-byte value against the set. O(rdata/8).
    // ========================================================================

    // Parse PE section table to find .text and .rdata boundaries
    uintptr_t text_start = 0, text_end = 0;
    uintptr_t rdata_start = 0, rdata_end = 0;

    {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                auto* sec = IMAGE_FIRST_SECTION(nt);
                for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                    uintptr_t sec_start = base + sec[i].VirtualAddress;
                    uintptr_t sec_size = sec[i].Misc.VirtualSize;
                    if (memcmp(sec[i].Name, ".text", 5) == 0) {
                        text_start = sec_start;
                        text_end = sec_start + sec_size;
                    } else if (memcmp(sec[i].Name, ".rdata", 6) == 0) {
                        rdata_start = sec_start;
                        rdata_end = sec_start + sec_size;
                    }
                }
            }
        }
    }

    if (!text_start || !rdata_start) {
        LOG_W("pass 4: could not find .text/.rdata sections, skipping vtable scan");
        return result;
    }

    LOG_I("pass 4: .text [%p - %p], .rdata [%p - %p]",
          (void*)text_start, (void*)text_end,
          (void*)rdata_start, (void*)rdata_end);

    // Build COL absolute address set. We re-scan Pass 2 COLs because we need
    // the COL's own offset (self_rva) which wasn't stored in the COLEntry struct.
    struct COLVtableEntry {
        std::string class_name;
        uintptr_t col_abs;     // absolute address of COL in memory
    };
    std::vector<COLVtableEntry> col_vtable_entries;
    std::unordered_set<uintptr_t> col_abs_set;

    for (size_t i = 0; i + sizeof(RTTICompleteObjectLocator) <= size; i += 4) {
        auto* col = reinterpret_cast<const RTTICompleteObjectLocator*>(mem + i);

        if (col->signature != 1) continue;
        if (col->self_rva != static_cast<int32_t>(i)) continue;

        auto it = rva_to_name.find(col->type_desc_rva);
        if (it == rva_to_name.end()) continue;

        // Only process primary vtable (offset == 0, first COL for this class)
        if (col->offset != 0) continue;

        uintptr_t abs_addr = base + i;
        col_abs_set.insert(abs_addr);
        col_vtable_entries.push_back({it->second, abs_addr});
    }

    // Reverse map: COL absolute addr -> index into col_vtable_entries
    std::unordered_map<uintptr_t, size_t> col_abs_to_idx;
    for (size_t i = 0; i < col_vtable_entries.size(); i++) {
        col_abs_to_idx[col_vtable_entries[i].col_abs] = i;
    }

    // Single linear scan of .rdata: find 8-byte pointers that match a COL address
    // These are vtable[-1] entries, so vtable[0] starts at found + 8
    int vtable_count = 0;

    for (uintptr_t addr = rdata_start; addr + 8 <= rdata_end; addr += 8) {
        uintptr_t val = *reinterpret_cast<const uintptr_t*>(addr);

        auto it = col_abs_to_idx.find(val);
        if (it == col_abs_to_idx.end()) continue;

        auto& entry = col_vtable_entries[it->second];
        const std::string& class_name = entry.class_name;

        // vtable[0] starts at addr + 8
        uintptr_t vtable_start = addr + 8;
        uint32_t vtable_rva = static_cast<uint32_t>(vtable_start - base);

        // Read consecutive entries that point into .text
        std::vector<uint32_t> func_rvas;
        std::vector<std::vector<uint8_t>> func_bytes;
        constexpr int MAX_VTABLE_ENTRIES = 512;
        constexpr int FUNC_BYTES_SIZE = 128;

        for (int idx = 0; idx < MAX_VTABLE_ENTRIES; idx++) {
            uintptr_t slot_addr = vtable_start + idx * 8;
            if (slot_addr + 8 > rdata_end) break;

            uintptr_t fn_ptr = *reinterpret_cast<const uintptr_t*>(slot_addr);

            // Must point into .text section
            if (fn_ptr < text_start || fn_ptr >= text_end) break;

            func_rvas.push_back(static_cast<uint32_t>(fn_ptr - base));

            // Read first N bytes of the function for signature generation.
            // safe_memcpy uses SEH in case function is at edge of a mapped page.
            std::vector<uint8_t> bytes(FUNC_BYTES_SIZE, 0);
            size_t avail = text_end - fn_ptr;
            size_t to_read = (avail < FUNC_BYTES_SIZE) ? avail : FUNC_BYTES_SIZE;
            safe_memcpy(bytes.data(), reinterpret_cast<const void*>(fn_ptr), to_read);
            func_bytes.push_back(std::move(bytes));
        }

        if (func_rvas.empty()) continue;

        // Store in the InheritanceInfo for this class (if it exists in result)
        auto res_it = result.find(class_name);
        if (res_it != result.end() && res_it->second.vtable_rva == 0) {
            res_it->second.vtable_rva = vtable_rva;
            res_it->second.vtable_func_rvas = std::move(func_rvas);
            res_it->second.vtable_func_bytes = std::move(func_bytes);
            vtable_count++;
        }
    }

    LOG_I("pass 4: discovered %d vtables", vtable_count);

    return result;
}

} // namespace schema
