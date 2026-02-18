/**
 * dezlock-dump — Runtime Schema Walker Implementation
 *
 * Uses vtable virtual calls on SchemaSystem + TypeScope for safe lookups.
 * CUtlTSHash iteration for full module dumps is SEH-wrapped.
 *
 * Struct layouts from source2gen:
 *
 * SchemaClassInfoData_t:
 *   +0x08  m_pszName (const char*)
 *   +0x10  m_pszModule (const char*)
 *   +0x18  m_nSizeOf (int32)
 *   +0x1C  m_nFieldSize (int16)
 *   +0x21  m_nBaseClassSize (int8)  [confirmed via raw dump, NOT +0x23]
 *   +0x28  m_pFields (SchemaClassFieldData_t*)
 *   +0x38  m_pBaseClasses (SchemaBaseClassInfoData_t*)
 *
 * SchemaClassFieldData_t (0x20 bytes each):
 *   +0x00  m_pszName (const char*)
 *   +0x08  m_pSchemaType (CSchemaType*)
 *   +0x10  m_nSingleInheritanceOffset (int32)
 *   +0x14  m_nMetadataSize (int16)
 *   +0x18  m_pMetadata (SchemaMetadataEntryData_t*)
 *
 * SchemaMetadataEntryData_t (0x10 bytes each):
 *   +0x00  m_pszName (const char*)
 *   +0x08  m_pValue (void*)
 *
 * SchemaBaseClassInfoData_t (0x10 bytes each):
 *   +0x00  m_unOffset (uint32)
 *   +0x08  m_pClass (CSchemaClassInfo*)
 *
 * CSchemaType:
 *   +0x08  m_pszName (const char*)
 *   vtable[3] = GetSizes(this, &size1, &size2)
 *
 * CSchemaSystemTypeScope:
 *   +0x08   m_szName[256]
 *   +0x0560 m_ClassBindings (CUtlTSHash)
 */

#define LOG_TAG "schema"

#include "schema-manager.hpp"
#include "log.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <algorithm>
#include <cstring>

namespace schema {

// ============================================================================
// SEH helpers (isolated, no C++ objects)
// ============================================================================

static bool seh_read_ptr(uintptr_t addr, uintptr_t* out) {
    __try {
        *out = *reinterpret_cast<uintptr_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool seh_read_i32(uintptr_t addr, int32_t* out) {
    __try {
        *out = *reinterpret_cast<int32_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool seh_read_i16(uintptr_t addr, int16_t* out) {
    __try {
        *out = *reinterpret_cast<int16_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool seh_read_i8(uintptr_t addr, int8_t* out) {
    __try {
        *out = *reinterpret_cast<int8_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool seh_read_u32(uintptr_t addr, uint32_t* out) {
    __try {
        *out = *reinterpret_cast<uint32_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool seh_read_i64(uintptr_t addr, int64_t* out) {
    __try {
        *out = *reinterpret_cast<int64_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool seh_read_string(uintptr_t addr, const char** out) {
    __try {
        const char* s = reinterpret_cast<const char*>(addr);
        // Quick sanity: check first byte is printable or null
        if (s && (s[0] == '\0' || (s[0] >= 0x20 && s[0] < 0x7F))) {
            *out = s;
            return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ============================================================================
// Vtable call wrappers (SEH-isolated)
// ============================================================================

// SchemaSystem vtable[13]: FindTypeScopeForModule
// void* __fastcall(void* this, const char* module, void* null)
static void* seh_find_type_scope(void* schema_system, const char* module) {
    void* result = nullptr;
    __try {
        auto vtable = *reinterpret_cast<uintptr_t**>(schema_system);
        auto fn = reinterpret_cast<void*(__fastcall*)(void*, const char*, void*)>(vtable[13]);
        result = fn(schema_system, module, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = nullptr;
    }
    return result;
}

// TypeScope vtable[2]: FindDeclaredClass (out-param calling convention)
// void __fastcall(void* this, CSchemaClassInfo** out, const char* name)
static void* seh_find_declared_class(void* type_scope, const char* name) {
    void* result = nullptr;
    __try {
        auto vtable = *reinterpret_cast<uintptr_t**>(type_scope);
        auto fn = reinterpret_cast<void(__fastcall*)(void*, void**, const char*)>(vtable[2]);
        fn(type_scope, &result, name);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = nullptr;
    }
    return result;
}

// CSchemaType vtable[3]: GetSizes
// bool __fastcall(void* this, int* outSize, uint8_t* outUnk)
static int seh_get_type_size(void* schema_type) {
    int size = 0;
    __try {
        auto vtable = *reinterpret_cast<uintptr_t**>(schema_type);
        auto fn = reinterpret_cast<bool(__fastcall*)(void*, int*, uint8_t*)>(vtable[3]);
        uint8_t unk = 0;
        fn(schema_type, &size, &unk);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        size = 0;
    }
    return size;
}

// ============================================================================
// SchemaManager implementation
// ============================================================================

SchemaManager& instance() {
    static SchemaManager s_instance;
    return s_instance;
}

bool SchemaManager::init(void* schema_system_ptr) {
    if (!schema_system_ptr) {
        LOG_W("init failed: null schema system pointer");
        return false;
    }
    m_schema_system = schema_system_ptr;
    LOG_I("initialized (SchemaSystem=%p)", schema_system_ptr);
    return true;
}

void* SchemaManager::find_type_scope(const char* module) {
    if (!m_schema_system || !module) return nullptr;
    return seh_find_type_scope(m_schema_system, module);
}

void* SchemaManager::find_declared_class(void* type_scope, const char* class_name) {
    if (!type_scope || !class_name) return nullptr;
    return seh_find_declared_class(type_scope, class_name);
}

bool SchemaManager::resolve_class(void* class_info, const char* module_name, RuntimeClass& out) {
    if (!class_info) return false;

    uintptr_t ci = reinterpret_cast<uintptr_t>(class_info);

    // Read class name
    uintptr_t name_ptr = 0;
    if (!seh_read_ptr(ci + 0x08, &name_ptr) || !name_ptr) return false;

    const char* name = nullptr;
    if (!seh_read_string(name_ptr, &name) || !name || !name[0]) return false;

    out.name = name;
    out.module = module_name;

    // Read sizeof
    seh_read_i32(ci + 0x18, &out.size);

    // Read field count
    int16_t field_count = 0;
    seh_read_i16(ci + 0x1C, &field_count);

    // Read fields pointer
    uintptr_t fields_ptr = 0;
    seh_read_ptr(ci + 0x28, &fields_ptr);

    // Walk fields
    if (fields_ptr && field_count > 0 && field_count < 4096) {
        out.fields.reserve(field_count);

        for (int16_t i = 0; i < field_count; ++i) {
            uintptr_t field_addr = fields_ptr + i * 0x20;

            RuntimeField field = {};

            // Field name (ptr at +0x00 -> const char*)
            uintptr_t fname_ptr = 0;
            if (!seh_read_ptr(field_addr + 0x00, &fname_ptr) || !fname_ptr) continue;
            if (!seh_read_string(fname_ptr, &field.name) || !field.name) continue;

            // Schema type (ptr at +0x08)
            uintptr_t type_ptr = 0;
            if (seh_read_ptr(field_addr + 0x08, &type_ptr) && type_ptr) {
                // Type name at CSchemaType+0x08 -> const char*
                uintptr_t tname_ptr = 0;
                if (seh_read_ptr(type_ptr + 0x08, &tname_ptr) && tname_ptr) {
                    seh_read_string(tname_ptr, &field.type_name);
                }
                // Get type size via vtable call
                field.size = seh_get_type_size(reinterpret_cast<void*>(type_ptr));
            }

            // Field offset at +0x10
            seh_read_i32(field_addr + 0x10, &field.offset);

            // Field metadata at +0x14 (count) and +0x18 (ptr)
            int16_t meta_count = 0;
            seh_read_i16(field_addr + 0x14, &meta_count);
            uintptr_t meta_ptr = 0;
            seh_read_ptr(field_addr + 0x18, &meta_ptr);
            if (meta_ptr && meta_count > 0 && meta_count < 64) {
                for (int16_t m = 0; m < meta_count; ++m) {
                    uintptr_t meta_entry = meta_ptr + m * 0x10;
                    uintptr_t mname_ptr = 0;
                    if (seh_read_ptr(meta_entry + 0x00, &mname_ptr) && mname_ptr) {
                        const char* mname = nullptr;
                        if (seh_read_string(mname_ptr, &mname) && mname && mname[0]) {
                            field.metadata.push_back(mname);
                        }
                    }
                }
            }

            out.fields.push_back(field);
        }
    }

    // Read base classes
    // Raw dump of ClassInfo+0x20: 08 01 03 00 02 00 00 00
    //   +0x20=0x08, +0x21=0x01(base_count), +0x22=0x03(flags?), +0x23=0x00
    // SchemaBaseClassInfoData_t layout (confirmed via memory dump):
    //   +0x00  m_pClass (CSchemaClassInfo*)  -- pointer FIRST
    //   +0x08  m_nOffset (int32)             -- offset SECOND
    //   Total: 0x10 bytes per entry
    int8_t base_count = 0;
    seh_read_i8(ci + 0x21, &base_count);

    uintptr_t bases_ptr = 0;
    seh_read_ptr(ci + 0x38, &bases_ptr);

    out.base_classes.clear();

    if (bases_ptr && base_count > 0 && base_count < 32) {
        for (int8_t i = 0; i < base_count; ++i) {
            uintptr_t entry_addr = bases_ptr + i * 0x10;

            uintptr_t parent_ci = 0;
            seh_read_ptr(entry_addr + 0x00, &parent_ci);

            int32_t parent_offset = 0;
            seh_read_i32(entry_addr + 0x08, &parent_offset);

            if (parent_ci) {
                uintptr_t parent_name_ptr = 0;
                if (seh_read_ptr(parent_ci + 0x08, &parent_name_ptr) && parent_name_ptr) {
                    const char* pname = nullptr;
                    if (seh_read_string(parent_name_ptr, &pname) && pname && pname[0]) {
                        out.base_classes.push_back({pname, parent_offset});
                    }
                }
            }
        }
    }

    // ---- Static fields ----
    // classinfo+0x1E = m_nStaticFieldCount (int16)
    // classinfo+0x30 = m_pStaticFields (SchemaClassFieldData_t*)
    int16_t static_count = 0;
    seh_read_i16(ci + 0x1E, &static_count);

    uintptr_t static_fields_ptr = 0;
    seh_read_ptr(ci + 0x30, &static_fields_ptr);

    if (static_fields_ptr && static_count > 0 && static_count < 1024) {
        out.static_fields.reserve(static_count);

        for (int16_t i = 0; i < static_count; ++i) {
            uintptr_t sf_addr = static_fields_ptr + i * 0x20;

            RuntimeField sf = {};

            uintptr_t sfname_ptr = 0;
            if (!seh_read_ptr(sf_addr + 0x00, &sfname_ptr) || !sfname_ptr) continue;
            if (!seh_read_string(sfname_ptr, &sf.name) || !sf.name) continue;

            uintptr_t sf_type_ptr = 0;
            if (seh_read_ptr(sf_addr + 0x08, &sf_type_ptr) && sf_type_ptr) {
                uintptr_t sf_tname_ptr = 0;
                if (seh_read_ptr(sf_type_ptr + 0x08, &sf_tname_ptr) && sf_tname_ptr) {
                    seh_read_string(sf_tname_ptr, &sf.type_name);
                }
                sf.size = seh_get_type_size(reinterpret_cast<void*>(sf_type_ptr));
            }

            seh_read_i32(sf_addr + 0x10, &sf.offset);

            // Static field metadata
            int16_t sf_meta_count = 0;
            seh_read_i16(sf_addr + 0x14, &sf_meta_count);
            uintptr_t sf_meta_ptr = 0;
            seh_read_ptr(sf_addr + 0x18, &sf_meta_ptr);
            if (sf_meta_ptr && sf_meta_count > 0 && sf_meta_count < 64) {
                for (int16_t m = 0; m < sf_meta_count; ++m) {
                    uintptr_t meta_entry = sf_meta_ptr + m * 0x10;
                    uintptr_t mname_ptr = 0;
                    if (seh_read_ptr(meta_entry + 0x00, &mname_ptr) && mname_ptr) {
                        const char* mname = nullptr;
                        if (seh_read_string(mname_ptr, &mname) && mname && mname[0]) {
                            sf.metadata.push_back(mname);
                        }
                    }
                }
            }

            out.static_fields.push_back(sf);
        }
    }

    // ---- Class metadata ----
    // classinfo+0x20 has packed fields: +0x20=align(int8), +0x21=base_count(int8)
    // classinfo+0x22 = m_nMetadataCount (int16) — right after base_count byte + alignment
    // classinfo+0x48 = m_pMetadata (SchemaMetadataEntryData_t*)
    //
    // Note: +0x20 is a packed area. We already read base_count from +0x21.
    // Metadata count is at +0x22 (2 bytes).
    int16_t class_meta_count = 0;
    seh_read_i16(ci + 0x22, &class_meta_count);

    uintptr_t class_meta_ptr = 0;
    seh_read_ptr(ci + 0x48, &class_meta_ptr);

    if (class_meta_ptr && class_meta_count > 0 && class_meta_count < 64) {
        for (int16_t m = 0; m < class_meta_count; ++m) {
            uintptr_t meta_entry = class_meta_ptr + m * 0x10;
            uintptr_t mname_ptr = 0;
            if (seh_read_ptr(meta_entry + 0x00, &mname_ptr) && mname_ptr) {
                const char* mname = nullptr;
                if (seh_read_string(mname_ptr, &mname) && mname && mname[0]) {
                    out.metadata.push_back(mname);
                }
            }
        }
    }

    return true;
}

// ============================================================================
// SEH-isolated enum resolver
//
// SchemaEnumInfoData_t layout (from source2gen):
//   +0x08  m_pszName (const char*)
//   +0x10  m_pszModule (const char*)
//   +0x18  m_nSize (int8)
//   +0x1C  m_nEnumeratorCount (int16)
//   +0x20  m_pEnumerators (SchemaEnumeratorInfoData_t*)
//
// SchemaEnumeratorInfoData_t (0x20 bytes each):
//   +0x00  m_nValue (union, 64-bit)
//   +0x08  m_pszName (const char*)
// ============================================================================

static bool resolve_enum(void* enum_info, const char* module_name, RuntimeEnum& out) {
    if (!enum_info) return false;

    uintptr_t ei = reinterpret_cast<uintptr_t>(enum_info);

    // Read enum name
    uintptr_t name_ptr = 0;
    if (!seh_read_ptr(ei + 0x08, &name_ptr) || !name_ptr) return false;

    const char* name = nullptr;
    if (!seh_read_string(name_ptr, &name) || !name || !name[0]) return false;

    out.name = name;
    out.module = module_name;

    // Read size (byte width of enum type)
    seh_read_i8(ei + 0x18, &out.size);

    // Read enumerator count
    int16_t enumerator_count = 0;
    seh_read_i16(ei + 0x1C, &enumerator_count);

    // Read enumerators pointer
    uintptr_t enumerators_ptr = 0;
    seh_read_ptr(ei + 0x20, &enumerators_ptr);

    // Walk enumerators
    if (enumerators_ptr && enumerator_count > 0 && enumerator_count < 4096) {
        out.values.reserve(enumerator_count);

        for (int16_t i = 0; i < enumerator_count; ++i) {
            uintptr_t entry_addr = enumerators_ptr + i * 0x20;

            RuntimeEnumerator enumerator = {};

            // Value at +0x00 (int64)
            if (!seh_read_i64(entry_addr + 0x00, &enumerator.value)) continue;

            // Name at +0x08 -> const char*
            uintptr_t ename_ptr = 0;
            if (!seh_read_ptr(entry_addr + 0x08, &ename_ptr) || !ename_ptr) continue;
            if (!seh_read_string(ename_ptr, &enumerator.name) || !enumerator.name) continue;

            out.values.push_back(enumerator);
        }
    }

    return true;
}

const RuntimeClass* SchemaManager::find_class(const char* module, const char* class_name) {
    if (!m_schema_system || !module || !class_name) return nullptr;

    // Check cache first
    std::string key = std::string(module) + "::" + class_name;
    auto it = m_cache.find(key);
    if (it != m_cache.end()) return &it->second;

    // Look up via vtable calls
    void* scope = find_type_scope(module);
    if (!scope) {
        LOG_D("type scope not found for module: %s", module);
        return nullptr;
    }

    void* class_info = find_declared_class(scope, class_name);
    if (!class_info) {
        LOG_D("class not found: %s::%s", module, class_name);
        return nullptr;
    }

    RuntimeClass cls = {};
    if (!resolve_class(class_info, module, cls)) {
        LOG_W("failed to resolve class: %s::%s", module, class_name);
        return nullptr;
    }

    auto [inserted, _] = m_cache.emplace(key, std::move(cls));
    return &inserted->second;
}

void* SchemaManager::get_class_info(const char* module, const char* class_name) {
    if (!m_schema_system || !module || !class_name) return nullptr;
    void* scope = find_type_scope(module);
    if (!scope) return nullptr;
    return find_declared_class(scope, class_name);
}

void SchemaManager::load_rtti(uintptr_t module_base, size_t module_size) {
    m_rtti_map = build_rtti_hierarchy(module_base, module_size);
    LOG_I("RTTI hierarchy loaded: %d classes", (int)m_rtti_map.size());
}

const InheritanceInfo* SchemaManager::get_inheritance(const char* class_name) const {
    if (!class_name) return nullptr;
    auto it = m_rtti_map.find(class_name);
    return (it != m_rtti_map.end()) ? &it->second : nullptr;
}

int32_t SchemaManager::get_offset(const char* module, const char* class_name, const char* field_name) {
    const auto* cls = find_class(module, class_name);
    if (!cls) return -1;

    // Search this class's own fields
    for (const auto& f : cls->fields) {
        if (f.name && strcmp(f.name, field_name) == 0) {
            return f.offset;
        }
    }

    // Walk RTTI parent chain (primary inheritance = offset 0)
    auto* info = get_inheritance(class_name);
    if (info && !info->parent.empty()) {
        int32_t parent_off = get_offset(module, info->parent.c_str(), field_name);
        if (parent_off >= 0) return parent_off;
    }

    // Fallback: search schema base_classes (embedded components)
    for (const auto& base : cls->base_classes) {
        if (!base.name) continue;
        int32_t off = get_offset(module, base.name, field_name);
        if (off >= 0) {
            return base.offset + off;
        }
    }

    return -1;
}

// ============================================================================
// Flattened layout resolution
// ============================================================================

bool SchemaManager::get_flat_layout(const char* module, const char* class_name, FlatLayout& out) {
    const auto* cls = find_class(module, class_name);
    if (!cls) return false;

    out.name = cls->name;
    out.total_size = cls->size;
    out.fields.clear();
    out.inheritance_chain.clear();

    // Walk RTTI parent chain to collect fields from entire hierarchy.
    // Primary inheritance = offset 0 (single inheritance for all Source 2 entity classes).
    // We walk: self -> parent -> grandparent -> ... -> root
    const RuntimeClass* current = cls;
    int depth = 0;

    while (current && depth < 32) {
        depth++;
        out.inheritance_chain.push_back(current->name ? current->name : "?");

        // Add this class's own fields
        for (const auto& f : current->fields) {
            FlatField ff;
            ff.name = f.name;
            ff.type_name = f.type_name;
            ff.offset = f.offset;  // primary inheritance: parent at offset 0
            ff.size = f.size;
            ff.defined_in = current->name;
            out.fields.push_back(ff);
        }

        // Follow RTTI parent
        auto* info = get_inheritance(current->name);
        if (!info || info->parent.empty()) break;
        current = find_class(module, info->parent.c_str());
    }

    // Sort by absolute offset
    std::sort(out.fields.begin(), out.fields.end(),
        [](const FlatField& a, const FlatField& b) { return a.offset < b.offset; });

    return true;
}

// ============================================================================
// CUtlTSHash enumeration (SEH-protected)
//
// TypeScope+0x0560 = CUtlTSHash<CSchemaClassBinding*>
//
// The CUtlTSHash starts with a CUtlMemoryPool for entry allocation:
//   +0x00  m_nBlockSize (int32)        = 32 (bytes per hash entry)
//   +0x04  m_nBlocksPerBlob (int32)    = 256 (entries per allocation blob)
//   +0x08  m_nGrowMode (int32)         = 2
//   +0x0C  m_nBlocksAllocated (int32)  = total entry count (our class count!)
//   +0x10  m_nPeakAlloc (int32)        = peak allocation
//   +0x14  (alignment/flags)
//   +0x18  m_pFreeListHead (ptr)       = free list (usually null when full)
//   +0x20  m_pBlobHead (ptr)           = head of blob linked list
//
// Each CBlob:
//   +0x00  m_pNext (CBlob*)
//   +0x08  m_nBlobSize (int32)         = data size in bytes
//   +0x10  data[] starts here          = blocksPerBlob * blockSize bytes
//
// Each 32-byte hash entry (HashFixedData_t):
//   We probe for the CSchemaClassInfo* pointer at offsets 0, 8, 16, 24
//   by checking if candidate+0x08 is a valid class name string.
//
// Confirmed via `schema raw` + `schema scope` debug commands (2026-02-17).
// ============================================================================

// SEH-isolated: probe a 32-byte hash entry for a CSchemaClassInfo* pointer
// Returns the valid class_info pointer, or 0 if none found.
static uintptr_t seh_probe_hash_entry(uintptr_t entry_addr) {
    __try {
        // Try each 8-byte slot in the 32-byte entry
        for (int off = 0; off < 32; off += 8) {
            uintptr_t candidate = *reinterpret_cast<uintptr_t*>(entry_addr + off);
            if (!candidate || candidate < 0x10000) continue;

            // Check if candidate+0x08 is a valid class name string pointer
            uintptr_t name_ptr = *reinterpret_cast<uintptr_t*>(candidate + 0x08);
            if (!name_ptr || name_ptr < 0x10000) continue;

            const char* name = reinterpret_cast<const char*>(name_ptr);
            // Validate: first char is uppercase letter or underscore (class name convention)
            if ((name[0] >= 'A' && name[0] <= 'Z') || name[0] == '_' || name[0] == 'C') {
                // Extra validation: check a few more chars are printable
                bool valid = true;
                for (int i = 1; i < 4 && name[i]; ++i) {
                    char c = name[i];
                    if (c < 0x20 || c > 0x7E) { valid = false; break; }
                }
                if (valid) return candidate;
            }
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// SEH-isolated: read a pointer at an offset within a blob
static bool seh_read_blob_ptr(uintptr_t blob_addr, int offset, uintptr_t* out) {
    __try {
        *out = *reinterpret_cast<uintptr_t*>(blob_addr + offset);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool SchemaManager::enumerate_scope(void* type_scope, const char* module_name) {
    if (!type_scope || !module_name) return false;

    uintptr_t scope = reinterpret_cast<uintptr_t>(type_scope);

    // CUtlTSHash is at TypeScope + 0x0560
    // It starts with a CUtlMemoryPool that allocates hash entries in blobs.
    uintptr_t pool_base = scope + 0x0560;

    // Read CUtlMemoryPool header
    int32_t block_size = 0, blocks_per_blob = 0, blocks_allocated = 0;
    seh_read_i32(pool_base + 0x00, &block_size);
    seh_read_i32(pool_base + 0x04, &blocks_per_blob);
    seh_read_i32(pool_base + 0x0C, &blocks_allocated);

    LOG_I("CUtlMemoryPool: block_size=%d, blocks_per_blob=%d, allocated=%d",
          block_size, blocks_per_blob, blocks_allocated);

    // Validate pool parameters
    if (block_size < 16 || block_size > 256 || blocks_per_blob <= 0 ||
        blocks_per_blob > 4096 || blocks_allocated <= 0 || blocks_allocated > 100000) {
        LOG_W("pool parameters look invalid, falling back to vtable lookups only");
        return false;
    }

    // Read blob head pointer at pool+0x20
    uintptr_t first_blob = 0;
    if (!seh_read_ptr(pool_base + 0x20, &first_blob) || !first_blob) {
        LOG_W("blob head pointer is null");
        return false;
    }

    int classes_found = 0;
    int max_blobs = (blocks_allocated / blocks_per_blob) + 2;

    // ---- Probe blob layout ----
    // CBlob may be: { next(8), size(4), pad(4), data... }    → next at +0x00, data at +0x10
    //           or: { prev(8), next(8), data... }              → next at +0x08, data at +0x10
    //           or: { prev(8), next(8), size(4), pad(4), data } → next at +0x08, data at +0x18
    // We probe by:
    //   1. Find which data offset has valid hash entries
    //   2. Find which "next" offset leads to another blob with valid entries at same data offset

    int blob_data_offset = -1;
    int blob_next_offset = -1;

    // Try data offsets
    static const int data_offsets[] = { 0x10, 0x18, 0x20 };
    for (int d : data_offsets) {
        if (seh_probe_hash_entry(first_blob + d)) {
            blob_data_offset = d;
            break;
        }
    }

    if (blob_data_offset < 0) {
        LOG_W("could not find valid data offset in first blob at %p", (void*)first_blob);
        return false;
    }

    // Try next-pointer offsets (0x00 and 0x08)
    // A valid "next" pointer should lead to another blob with valid entries
    for (int n : { 0x00, 0x08 }) {
        uintptr_t candidate_next = 0;
        if (!seh_read_blob_ptr(first_blob, n, &candidate_next)) continue;
        if (!candidate_next || candidate_next == first_blob) continue;
        if (candidate_next < 0x10000) continue;

        // Check if candidate_next + blob_data_offset has a valid hash entry
        if (seh_probe_hash_entry(candidate_next + blob_data_offset)) {
            blob_next_offset = n;
            break;
        }
    }

    if (blob_next_offset < 0) {
        // Only one blob accessible — walk just the first one
        LOG_I("single blob mode (next probe failed), data at +0x%X", blob_data_offset);
        blob_next_offset = 0x00; // won't matter, we'll stop after first blob
    } else {
        LOG_I("blob layout: next at +0x%X, data at +0x%X", blob_next_offset, blob_data_offset);
    }

    // ---- Walk all blobs ----
    uintptr_t blob_ptr = first_blob;
    int blobs_walked = 0;
    int entries_total = 0;

    while (blob_ptr && blobs_walked < max_blobs) {
        blobs_walked++;

        // Walk entries in this blob
        int entries_in_blob = blocks_per_blob;
        int remaining = blocks_allocated - entries_total;
        if (remaining <= 0) break;
        if (entries_in_blob > remaining) entries_in_blob = remaining;

        uintptr_t data_start = blob_ptr + blob_data_offset;
        for (int i = 0; i < entries_in_blob; ++i) {
            uintptr_t entry_addr = data_start + i * block_size;

            uintptr_t class_info = seh_probe_hash_entry(entry_addr);
            if (!class_info) continue;

            RuntimeClass cls = {};
            if (resolve_class(reinterpret_cast<void*>(class_info), module_name, cls)) {
                std::string key = std::string(module_name) + "::" + cls.name;
                if (m_cache.find(key) == m_cache.end()) {
                    m_cache.emplace(key, std::move(cls));
                    classes_found++;
                }
            }
        }

        entries_total += entries_in_blob;

        // Follow next blob
        uintptr_t next_blob = 0;
        if (!seh_read_blob_ptr(blob_ptr, blob_next_offset, &next_blob)) break;
        if (!next_blob || next_blob == blob_ptr || next_blob == first_blob) break;
        blob_ptr = next_blob;
    }

    LOG_I("blob walk: %d blobs, %d entries scanned, %d classes resolved from %s",
          blobs_walked, entries_total, classes_found, module_name);

    return classes_found > 0;
}

// ============================================================================
// CUtlTSHash enumeration for enums (SEH-protected)
//
// TypeScope+0x0BE8 = CUtlTSHash<CSchemaEnumBinding*>
//
// Same CUtlMemoryPool + blob structure as class bindings at +0x0560.
// Each hash entry contains a SchemaEnumInfoData_t* pointer.
// We probe candidate+0x08 for a valid enum name string.
// ============================================================================

// SEH-isolated: probe a hash entry for a SchemaEnumInfoData_t* pointer
// Enum names can start with uppercase, lowercase, or underscore.
static uintptr_t seh_probe_enum_hash_entry(uintptr_t entry_addr) {
    __try {
        for (int off = 0; off < 32; off += 8) {
            uintptr_t candidate = *reinterpret_cast<uintptr_t*>(entry_addr + off);
            if (!candidate || candidate < 0x10000) continue;

            // Check if candidate+0x08 is a valid enum name string pointer
            uintptr_t name_ptr = *reinterpret_cast<uintptr_t*>(candidate + 0x08);
            if (!name_ptr || name_ptr < 0x10000) continue;

            const char* name = reinterpret_cast<const char*>(name_ptr);
            // Validate: first char is letter or underscore (enum names are less restrictive)
            char c0 = name[0];
            if ((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || c0 == '_') {
                bool valid = true;
                for (int i = 1; i < 4 && name[i]; ++i) {
                    char c = name[i];
                    if (c < 0x20 || c > 0x7E) { valid = false; break; }
                }
                if (valid) return candidate;
            }
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

bool SchemaManager::enumerate_enums(void* type_scope, const char* module_name) {
    if (!type_scope || !module_name) return false;

    uintptr_t scope = reinterpret_cast<uintptr_t>(type_scope);

    // The enum CUtlTSHash location varies between builds.
    // Known offsets: 0x0BE8 (older), but can shift.
    // Strategy: try known offsets, then probe around the class hash (+0x0560)
    // looking for a valid CUtlMemoryPool with enum-like entries.
    static const int enum_offsets[] = { 0x0BE8, 0x0C00, 0x0C08, 0x0C10, 0x0C18, 0x0C20,
                                        0x0BD0, 0x0BD8, 0x0BE0, 0x0BF0, 0x0BF8 };

    uintptr_t pool_base = 0;
    int32_t block_size = 0, blocks_per_blob = 0, blocks_allocated = 0;

    for (int candidate_offset : enum_offsets) {
        uintptr_t candidate = scope + candidate_offset;

        int32_t bs = 0, bpb = 0, ba = 0;
        if (!seh_read_i32(candidate + 0x00, &bs)) continue;
        if (!seh_read_i32(candidate + 0x04, &bpb)) continue;
        if (!seh_read_i32(candidate + 0x0C, &ba)) continue;

        // Valid pool: block_size 16-256, blocks_per_blob 1-4096, allocated > 0
        if (bs >= 16 && bs <= 256 && bpb > 0 && bpb <= 4096 && ba > 0 && ba <= 100000) {
            // Extra validation: check blob head pointer exists
            uintptr_t blob_head = 0;
            if (!seh_read_ptr(candidate + 0x20, &blob_head) || !blob_head) continue;

            // Try to probe for an enum entry in the first blob
            for (int d : { 0x10, 0x18, 0x20 }) {
                if (seh_probe_enum_hash_entry(blob_head + d)) {
                    pool_base = candidate;
                    block_size = bs;
                    blocks_per_blob = bpb;
                    blocks_allocated = ba;
                    LOG_I("enum CUtlTSHash found at scope+0x%X (block_size=%d, per_blob=%d, allocated=%d)",
                          candidate_offset, bs, bpb, ba);
                    goto found_enum_pool;
                }
            }
        }
    }

    // Not found via known offsets — do a broader scan
    // Scan from +0x0580 to +0x0D00 in 8-byte steps (after class hash at +0x0560)
    for (int off = 0x0580; off <= 0x0D00; off += 8) {
        uintptr_t candidate = scope + off;

        int32_t bs = 0, bpb = 0, ba = 0;
        if (!seh_read_i32(candidate + 0x00, &bs)) continue;
        if (!seh_read_i32(candidate + 0x04, &bpb)) continue;
        if (!seh_read_i32(candidate + 0x0C, &ba)) continue;

        if (bs >= 16 && bs <= 256 && bpb > 0 && bpb <= 4096 && ba > 0 && ba <= 100000) {
            uintptr_t blob_head = 0;
            if (!seh_read_ptr(candidate + 0x20, &blob_head) || !blob_head) continue;

            for (int d : { 0x10, 0x18, 0x20 }) {
                if (seh_probe_enum_hash_entry(blob_head + d)) {
                    pool_base = candidate;
                    block_size = bs;
                    blocks_per_blob = bpb;
                    blocks_allocated = ba;
                    LOG_I("enum CUtlTSHash discovered at scope+0x%X (block_size=%d, per_blob=%d, allocated=%d)",
                          off, bs, bpb, ba);
                    goto found_enum_pool;
                }
            }
        }
    }

    LOG_W("enum CUtlTSHash not found for %s (probed offsets 0x0580-0x0D00)", module_name);
    return false;

found_enum_pool:
    if (!pool_base) return false;

    // Read blob head pointer at pool+0x20
    uintptr_t first_blob = 0;
    if (!seh_read_ptr(pool_base + 0x20, &first_blob) || !first_blob) {
        LOG_W("enum blob head pointer is null");
        return false;
    }

    int enums_found = 0;
    int max_blobs = (blocks_allocated / blocks_per_blob) + 2;

    // Probe blob layout (same approach as enumerate_scope)
    int blob_data_offset = -1;
    int blob_next_offset = -1;

    static const int data_offsets[] = { 0x10, 0x18, 0x20 };
    for (int d : data_offsets) {
        if (seh_probe_enum_hash_entry(first_blob + d)) {
            blob_data_offset = d;
            break;
        }
    }

    if (blob_data_offset < 0) {
        LOG_W("could not find valid data offset in first enum blob at %p", (void*)first_blob);
        return false;
    }

    for (int n : { 0x00, 0x08 }) {
        uintptr_t candidate_next = 0;
        if (!seh_read_blob_ptr(first_blob, n, &candidate_next)) continue;
        if (!candidate_next || candidate_next == first_blob) continue;
        if (candidate_next < 0x10000) continue;

        if (seh_probe_enum_hash_entry(candidate_next + blob_data_offset)) {
            blob_next_offset = n;
            break;
        }
    }

    if (blob_next_offset < 0) {
        LOG_I("enum: single blob mode, data at +0x%X", blob_data_offset);
        blob_next_offset = 0x00;
    } else {
        LOG_I("enum blob layout: next at +0x%X, data at +0x%X", blob_next_offset, blob_data_offset);
    }

    // Walk all blobs
    uintptr_t blob_ptr = first_blob;
    int blobs_walked = 0;
    int entries_total = 0;

    while (blob_ptr && blobs_walked < max_blobs) {
        blobs_walked++;

        int entries_in_blob = blocks_per_blob;
        int remaining = blocks_allocated - entries_total;
        if (remaining <= 0) break;
        if (entries_in_blob > remaining) entries_in_blob = remaining;

        uintptr_t data_start = blob_ptr + blob_data_offset;
        for (int i = 0; i < entries_in_blob; ++i) {
            uintptr_t entry_addr = data_start + i * block_size;

            uintptr_t enum_info = seh_probe_enum_hash_entry(entry_addr);
            if (!enum_info) continue;

            RuntimeEnum enm = {};
            if (resolve_enum(reinterpret_cast<void*>(enum_info), module_name, enm)) {
                std::string key = std::string(module_name) + "::" + enm.name;
                if (m_enum_cache.find(key) == m_enum_cache.end()) {
                    m_enum_cache.emplace(key, std::move(enm));
                    enums_found++;
                }
            }
        }

        entries_total += entries_in_blob;

        uintptr_t next_blob = 0;
        if (!seh_read_blob_ptr(blob_ptr, blob_next_offset, &next_blob)) break;
        if (!next_blob || next_blob == blob_ptr || next_blob == first_blob) break;
        blob_ptr = next_blob;
    }

    LOG_I("enum blob walk: %d blobs, %d entries scanned, %d enums resolved from %s",
          blobs_walked, entries_total, enums_found, module_name);

    return enums_found > 0;
}

bool SchemaManager::dump_module(const char* module) {
    if (!m_schema_system || !module) return false;

    void* scope = find_type_scope(module);
    if (!scope) {
        LOG_W("type scope not found for: %s", module);
        return false;
    }

    LOG_I("dumping module: %s (scope=%p)", module, scope);
    bool classes_ok = enumerate_scope(scope, module);
    bool enums_ok = enumerate_enums(scope, module);
    return classes_ok || enums_ok;
}

int SchemaManager::class_count() const {
    return static_cast<int>(m_cache.size());
}

int SchemaManager::total_field_count() const {
    int total = 0;
    for (const auto& [_, cls] : m_cache) {
        total += static_cast<int>(cls.fields.size());
    }
    return total;
}

int SchemaManager::enum_count() const {
    return static_cast<int>(m_enum_cache.size());
}

int SchemaManager::total_static_field_count() const {
    int total = 0;
    for (const auto& [_, cls] : m_cache) {
        total += static_cast<int>(cls.static_fields.size());
    }
    return total;
}

int SchemaManager::total_enumerator_count() const {
    int total = 0;
    for (const auto& [_, enm] : m_enum_cache) {
        total += static_cast<int>(enm.values.size());
    }
    return total;
}

// ============================================================================
// Auto-discover all modules with schema data
// ============================================================================

int SchemaManager::dump_all_modules() {
    if (!m_schema_system) return 0;

    // Enumerate all loaded modules in this process
    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        LOG_W("EnumProcessModules failed (err=%lu)", GetLastError());
        return 0;
    }

    int module_count = needed / sizeof(HMODULE);
    int dumped = 0;

    LOG_I("scanning %d loaded modules for schema data...", module_count);

    for (int i = 0; i < module_count; i++) {
        char mod_name[MAX_PATH];
        if (!GetModuleBaseNameA(GetCurrentProcess(), modules[i], mod_name, MAX_PATH))
            continue;

        // Try to find a type scope for this module
        void* scope = find_type_scope(mod_name);
        if (!scope) continue;

        // Validate: the scope at +0x08 has a 256-byte name buffer.
        // If it doesn't contain our module name, FindTypeScopeForModule
        // returned a default/shared scope — skip it.
        uintptr_t scope_addr = reinterpret_cast<uintptr_t>(scope);
        const char* scope_name = nullptr;
        if (!seh_read_string(scope_addr + 0x08, &scope_name) || !scope_name || !scope_name[0])
            continue;
        // Check the scope name contains our module name (case-insensitive)
        if (_stricmp(scope_name, mod_name) != 0)
            continue;

        LOG_I("found schema scope for: %s", mod_name);

        bool classes_ok = enumerate_scope(scope, mod_name);
        bool enums_ok = enumerate_enums(scope, mod_name);

        if (classes_ok || enums_ok) {
            m_dumped_modules.push_back(mod_name);
            dumped++;
        }
    }

    LOG_I("dumped %d modules with schema data", dumped);
    return dumped;
}

} // namespace schema
