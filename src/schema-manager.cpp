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
#include <unordered_set>

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
        if (!s) return false;
        // Validate: at least 1 char, all printable ASCII up to first null or 128 chars
        // This catches raw memory pointers that happen to start with a printable byte
        int len = 0;
        for (int i = 0; i < 128 && s[i]; ++i) {
            char c = s[i];
            if (c < 0x20 || c > 0x7E) return false;  // non-printable = garbage
            len++;
        }
        if (len == 0) return false;  // empty string
        *out = s;
        return true;
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
    // classinfo+0x30 = m_pStaticFields (SchemaStaticFieldData_t*)
    //
    // SchemaStaticFieldData_t has SAME layout as SchemaClassFieldData_t (0x20 bytes):
    //   +0x00  m_pszName (const char*)
    //   +0x08  m_pSchemaType (CSchemaType*)
    //   +0x10  m_pInstance (void*) — pointer to static data, NOT an int32 offset
    //   +0x14  (upper 32 bits of pointer)
    //   +0x18  m_pMetadata (SchemaMetadataEntryData_t*)
    //
    // We store the instance pointer as-is in the offset field (truncated to int32
    // for the RuntimeField struct). Static field offsets aren't meaningful for struct
    // generation; they represent global addresses.
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

            // +0x10 is m_pInstance (void*), not an offset. Store 0 for static fields
            // since the address is process-specific and not useful for SDK generation.
            sf.offset = 0;

            // Static field metadata at +0x14 (count) and +0x18 (ptr)
            // Note: +0x14 overlaps with upper bytes of m_pInstance on 64-bit.
            // Metadata for static fields is uncommon; skip to avoid reading garbage.

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
//   +0x00  m_pszName (const char*) — name FIRST
//   +0x08  m_nValue (union { int64, uint64 }) — value SECOND
//   +0x10  m_pMetadata (SchemaMetadataEntryData_t*)
//   +0x18  (padding/reserved)
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

            // Name at +0x00 -> const char*
            uintptr_t ename_ptr = 0;
            if (!seh_read_ptr(entry_addr + 0x00, &ename_ptr) || !ename_ptr) continue;
            if (!seh_read_string(ename_ptr, &enumerator.name) || !enumerator.name) continue;

            // Value at +0x08 (int64)
            if (!seh_read_i64(entry_addr + 0x08, &enumerator.value)) continue;

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

void SchemaManager::load_rtti(uintptr_t module_base, size_t module_size, const char* module_name) {
    auto map = build_rtti_hierarchy(module_base, module_size);

    // Tag each entry with source module and merge into global map
    std::string mod_str = module_name ? module_name : "";
    int added = 0;
    for (auto& [name, info] : map) {
        info.source_module = mod_str;
        // Only insert if not already present (first module wins for duplicates)
        if (m_rtti_map.find(name) == m_rtti_map.end()) {
            m_rtti_map[name] = std::move(info);
            added++;
        }
    }
    LOG_I("RTTI hierarchy: +%d from %s (%d total)", added, mod_str.c_str(), (int)m_rtti_map.size());
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
// CUtlTSHash enumeration (V2 bucket-walking, SEH-protected)
//
// TypeScope+0x0560 = CUtlTSHash<CSchemaClassBinding*, uint64, 256>
//
// CUtlTSHash V2 layout (Win x64):
//   +0x00  CUtlMemoryPoolBase (0x80 bytes)
//     +0x0C  m_BlocksAllocated (int32) — committed entry count
//     +0x10  m_PeakAlloc (int32) — total ever allocated
//     +0x20  m_FreeBlocks.m_Head.Next (ptr) — unallocated chain head
//   +0x80  HashBucket_t[256] (0x18 each = 0x1800 total)
//     +0x00  m_AddLock* (ptr)
//     +0x08  m_pFirst (HashFixedData_t*)
//     +0x10  m_pFirstUncommitted (HashFixedData_t*) — walk THIS
//
// HashFixedData_t (linked list node):
//   +0x00  m_uiKey (uint64)
//   +0x08  m_pNext (HashFixedData_t*)
//   +0x10  m_Data  (CSchemaClassInfo* / CSchemaEnumBinding*)
//
// Enumeration (matching cs2-dumper + source2gen):
//   Phase 1: Walk all 256 bucket chains via m_pFirstUncommitted
//   Phase 2: Walk m_FreeBlocks chain for unallocated-but-valid entries
//   Deduplicate by pointer address
//
// Reference: a2x/cs2-dumper utl_ts_hash.rs, neverlosecc/source2gen CUtlTSHash.h
// ============================================================================

static constexpr int UTLTSHASH_BUCKET_COUNT = 256;
static constexpr uintptr_t UTLTSHASH_BUCKET_STRIDE = 0x18; // sizeof(HashBucket_t) on Win64

// SEH-isolated: read the data pointer from a HashFixedData_t node
// Returns the m_Data pointer (e.g. CSchemaClassInfo*), or 0 on failure
static uintptr_t seh_read_hash_node_data(uintptr_t node_addr) {
    __try {
        return *reinterpret_cast<uintptr_t*>(node_addr + 0x10); // m_Data at +0x10
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// SEH-isolated: read the next pointer from a HashFixedData_t node
static uintptr_t seh_read_hash_node_next(uintptr_t node_addr) {
    __try {
        return *reinterpret_cast<uintptr_t*>(node_addr + 0x08); // m_pNext at +0x08
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// SEH-isolated: validate that a pointer looks like a CSchemaClassInfo*
// (has a valid class name string at +0x08)
static bool seh_validate_class_info(uintptr_t candidate) {
    __try {
        if (!candidate || candidate < 0x10000) return false;
        uintptr_t name_ptr = *reinterpret_cast<uintptr_t*>(candidate + 0x08);
        if (!name_ptr || name_ptr < 0x10000) return false;
        const char* name = reinterpret_cast<const char*>(name_ptr);
        // Class names start with uppercase letter or underscore
        char c0 = name[0];
        if (c0 < 0x20 || c0 > 0x7E) return false;
        if (!((c0 >= 'A' && c0 <= 'Z') || c0 == '_')) return false;
        // Check a few more chars are printable
        for (int i = 1; i < 4 && name[i]; ++i) {
            char c = name[i];
            if (c < 0x20 || c > 0x7E) return false;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH-isolated: validate that a pointer looks like a SchemaEnumInfoData_t*
// (has a valid enum name string at +0x08, less restrictive than class names)
static bool seh_validate_enum_info(uintptr_t candidate) {
    __try {
        if (!candidate || candidate < 0x10000) return false;
        uintptr_t name_ptr = *reinterpret_cast<uintptr_t*>(candidate + 0x08);
        if (!name_ptr || name_ptr < 0x10000) return false;
        const char* name = reinterpret_cast<const char*>(name_ptr);
        char c0 = name[0];
        if (c0 < 0x20 || c0 > 0x7E) return false;
        if (!((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || c0 == '_')) return false;
        for (int i = 1; i < 4 && name[i]; ++i) {
            char c = name[i];
            if (c < 0x20 || c > 0x7E) return false;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH-isolated: check if a given offset into the hash looks like a valid bucket
// by trying to follow the m_pFirstUncommitted chain and validating data pointers.
static int seh_probe_bucket_at(uintptr_t candidate_bucket, bool (*validator)(uintptr_t)) {
    __try {
        // Try m_pFirstUncommitted at +0x10 within the bucket
        uintptr_t node = *reinterpret_cast<uintptr_t*>(candidate_bucket + 0x10);
        if (!node || node < 0x10000) {
            // Also try m_pFirst at +0x08
            node = *reinterpret_cast<uintptr_t*>(candidate_bucket + 0x08);
            if (!node || node < 0x10000) return 0;
        }

        // Check if node looks like a HashFixedData_t: data at +0x10
        uintptr_t data = *reinterpret_cast<uintptr_t*>(node + 0x10);
        if (data && data > 0x10000 && validator(data)) return 1;

        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// Auto-detect where hash buckets start by probing candidate offsets.
// The CUtlMemoryPoolBase size varies between builds (0x28 on V1, 0x80 on V2, etc.)
// We try candidate pool sizes and check if buckets contain valid entries.
static uintptr_t find_bucket_base(uintptr_t hash_base, bool (*validator)(uintptr_t)) {
    // Known pool sizes: V1=0x28, V2=0x80, but can vary. Probe a range.
    static const int pool_sizes[] = { 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xA0 };

    for (int ps : pool_sizes) {
        uintptr_t candidate = hash_base + ps;
        // Check several buckets for valid entries (most buckets may be empty,
        // so scan a good sample)
        int hits = 0;
        for (int i = 0; i < UTLTSHASH_BUCKET_COUNT; ++i) {
            if (seh_probe_bucket_at(candidate + i * UTLTSHASH_BUCKET_STRIDE, validator)) {
                hits++;
                if (hits >= 3) {
                    LOG_I("bucket base found at hash+0x%X (pool_size=0x%X, %d bucket hits in scan)",
                          ps, ps, hits);
                    return candidate;
                }
            }
        }
    }
    return 0;
}

// Collect all data pointers from a CUtlTSHash by walking hash buckets + free list.
// validator: function to check if a data pointer is valid (class or enum)
// Returns vector of unique data pointers.
static std::vector<uintptr_t> collect_utltshash_entries(
    uintptr_t hash_base,
    bool (*validator)(uintptr_t),
    const char* label)
{
    std::vector<uintptr_t> results;
    std::unordered_set<uintptr_t> seen;

    // Read pool header
    int32_t blocks_allocated = 0, peak_alloc = 0;
    seh_read_i32(hash_base + 0x0C, &blocks_allocated);
    seh_read_i32(hash_base + 0x10, &peak_alloc);

    LOG_I("%s: blocks_allocated=%d, peak_alloc=%d", label, blocks_allocated, peak_alloc);

    if (blocks_allocated <= 0 && peak_alloc <= 0) {
        LOG_W("%s: empty hash table", label);
        return results;
    }

    // Phase 1: Walk all 256 hash bucket chains
    // Auto-detect bucket base (pool size varies between builds)
    uintptr_t buckets_base = find_bucket_base(hash_base, validator);
    int bucket_entries = 0;

    if (buckets_base) {
        for (int i = 0; i < UTLTSHASH_BUCKET_COUNT; ++i) {
            uintptr_t bucket_addr = buckets_base + i * UTLTSHASH_BUCKET_STRIDE;

            // Try m_pFirstUncommitted at +0x10, then m_pFirst at +0x08
            for (int chain_off : { 0x10, 0x08 }) {
                uintptr_t node = 0;
                if (!seh_read_ptr(bucket_addr + chain_off, &node)) continue;

                int chain_len = 0;
                while (node && node > 0x10000 && chain_len < 4096) {
                    chain_len++;
                    uintptr_t data = seh_read_hash_node_data(node);
                    if (data && data > 0x10000 && validator(data)) {
                        if (seen.insert(data).second) {
                            results.push_back(data);
                            bucket_entries++;
                        }
                    }
                    node = seh_read_hash_node_next(node);
                }

                // If this chain had entries, don't try the other offset
                if (chain_len > 0) break;
            }
        }
    }

    LOG_I("%s: phase 1 (buckets) found %d entries", label, bucket_entries);

    // Phase 2: Walk free-blocks chain for unallocated entries
    // Try multiple candidate offsets for the free list head pointer
    // V1: m_pFreeListHead at +0x18, V2: m_FreeBlocks.m_Head.Next at +0x20
    int free_entries = 0;
    for (int free_off : { 0x18, 0x20, 0x28 }) {
        uintptr_t free_node = 0;
        if (!seh_read_ptr(hash_base + free_off, &free_node)) continue;
        if (!free_node || free_node < 0x10000) continue;

        // Validate: first node should have valid data at +0x10
        uintptr_t first_data = 0;
        if (!seh_read_ptr(free_node + 0x10, &first_data)) continue;
        if (!first_data || !validator(first_data)) continue;

        LOG_I("%s: free list head at pool+0x%X", label, free_off);

        int chain_len = 0;
        uintptr_t node = free_node;
        while (node && node > 0x10000 && chain_len < 100000) {
            chain_len++;
            uintptr_t data = 0;
            if (seh_read_ptr(node + 0x10, &data) && data && data > 0x10000 && validator(data)) {
                if (seen.insert(data).second) {
                    results.push_back(data);
                    free_entries++;
                }
            }
            uintptr_t next = 0;
            if (!seh_read_ptr(node + 0x00, &next)) break;
            if (next == node) break;
            node = next;
        }
        break; // Found a valid free list, stop trying offsets
    }

    if (free_entries > 0) {
        LOG_I("%s: phase 2 (free list) found %d additional entries", label, free_entries);
    }

    LOG_I("%s: total %d unique entries", label, (int)results.size());
    return results;
}

bool SchemaManager::enumerate_scope(void* type_scope, const char* module_name) {
    if (!type_scope || !module_name) return false;

    uintptr_t scope = reinterpret_cast<uintptr_t>(type_scope);
    uintptr_t hash_base = scope + 0x0560;

    auto entries = collect_utltshash_entries(hash_base, seh_validate_class_info, module_name);

    int classes_found = 0;
    for (uintptr_t class_info : entries) {
        RuntimeClass cls = {};
        if (resolve_class(reinterpret_cast<void*>(class_info), module_name, cls)) {
            std::string key = std::string(module_name) + "::" + cls.name;
            if (m_cache.find(key) == m_cache.end()) {
                m_cache.emplace(key, std::move(cls));
                classes_found++;
            }
        }
    }

    LOG_I("enumerate_scope: %d classes resolved from %s", classes_found, module_name);
    return classes_found > 0;
}

// ============================================================================
// CUtlTSHash enumeration for enums (V2 bucket-walking)
//
// The enum hash table is a second CUtlTSHash inside the TypeScope.
// Its offset varies between builds. We scan for it by probing known offsets
// and validating the pool header + bucket entries.
//
// The class hash is at TypeScope+0x0560, size 0x80 (pool) + 256*0x18 (buckets)
// = 0x1880 bytes. So the class hash occupies 0x0560..0x1DE0.
// The enum hash should be after that, typically around 0x1DE0 or later.
// But some builds put it at 0x0BE8 (overlapping with class bucket area??)
// — in V2 that can't be right since the class buckets extend to 0x1DE0.
//
// Strategy: try the area after the class hash (0x1DE0+), then fall back to
// a broader scan looking for valid CUtlTSHash headers with enum-like entries.
// ============================================================================

bool SchemaManager::enumerate_enums(void* type_scope, const char* module_name) {
    if (!type_scope || !module_name) return false;

    uintptr_t scope = reinterpret_cast<uintptr_t>(type_scope);

    // Class CUtlTSHash ends at 0x0560 + 0x80 (pool) + 256*0x18 (buckets) = 0x1DE0
    // The enum hash should be somewhere after that.
    // Also try legacy offset 0x0BE8 in case V1 layout is in use.
    // Additionally try offsets that source2gen uses.
    static const int enum_offsets[] = {
        // V2: after the class hash buckets
        0x1DE0, 0x1DE8, 0x1DF0, 0x1DF8, 0x1E00, 0x1E08, 0x1E10, 0x1E18,
        0x1E20, 0x1E28, 0x1E30, 0x1E38, 0x1E40, 0x1E48, 0x1E50,
        // V1 legacy
        0x0BE8, 0x0BF0, 0x0BF8, 0x0C00, 0x0C08, 0x0C10,
    };

    // Try each candidate: look for a valid CUtlTSHash header that has
    // bucket entries validating as enum info pointers
    for (int candidate_offset : enum_offsets) {
        uintptr_t hash_base = scope + candidate_offset;

        int32_t blocks_allocated = 0, peak_alloc = 0;
        if (!seh_read_i32(hash_base + 0x0C, &blocks_allocated)) continue;
        if (!seh_read_i32(hash_base + 0x10, &peak_alloc)) continue;

        if (blocks_allocated <= 0 || blocks_allocated > 100000) continue;

        // Auto-detect bucket base for this candidate hash
        uintptr_t buckets_base = find_bucket_base(hash_base, seh_validate_enum_info);
        if (!buckets_base) continue;

        LOG_I("enum CUtlTSHash found at scope+0x%X (allocated=%d, peak=%d)",
              candidate_offset, blocks_allocated, peak_alloc);

        // Found it — collect entries using the standard bucket walker
        std::string label = std::string(module_name) + " enums";
        auto entries = collect_utltshash_entries(hash_base, seh_validate_enum_info, label.c_str());

        int enums_found = 0;
        for (uintptr_t enum_info : entries) {
            RuntimeEnum enm = {};
            if (resolve_enum(reinterpret_cast<void*>(enum_info), module_name, enm)) {
                std::string key = std::string(module_name) + "::" + enm.name;
                if (m_enum_cache.find(key) == m_enum_cache.end()) {
                    m_enum_cache.emplace(key, std::move(enm));
                    enums_found++;
                }
            }
        }

        LOG_I("enumerate_enums: %d enums resolved from %s", enums_found, module_name);
        return enums_found > 0;
    }

    // Broader scan if known offsets didn't work
    LOG_I("enum hash not at known offsets for %s, scanning 0x1D00..0x2800...", module_name);
    for (int off = 0x1D00; off <= 0x2800; off += 8) {
        uintptr_t hash_base = scope + off;

        int32_t blocks_allocated = 0;
        if (!seh_read_i32(hash_base + 0x0C, &blocks_allocated)) continue;
        if (blocks_allocated <= 0 || blocks_allocated > 100000) continue;

        uintptr_t buckets_base = find_bucket_base(hash_base, seh_validate_enum_info);
        if (!buckets_base) continue;

        LOG_I("enum CUtlTSHash discovered at scope+0x%X (allocated=%d)", off, blocks_allocated);

        std::string label = std::string(module_name) + " enums";
        auto entries = collect_utltshash_entries(hash_base, seh_validate_enum_info, label.c_str());

        int enums_found = 0;
        for (uintptr_t enum_info : entries) {
            RuntimeEnum enm = {};
            if (resolve_enum(reinterpret_cast<void*>(enum_info), module_name, enm)) {
                std::string key = std::string(module_name) + "::" + enm.name;
                if (m_enum_cache.find(key) == m_enum_cache.end()) {
                    m_enum_cache.emplace(key, std::move(enm));
                    enums_found++;
                }
            }
        }

        LOG_I("enumerate_enums: %d enums resolved from %s", enums_found, module_name);
        return enums_found > 0;
    }

    LOG_W("enum CUtlTSHash not found for %s", module_name);
    return false;
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
