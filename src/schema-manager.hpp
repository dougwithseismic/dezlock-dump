/**
 * dezlock-dump — Runtime Schema Walker
 *
 * Walks the Source 2 SchemaSystem at runtime to resolve class layouts
 * and field offsets dynamically. Patch-proof alternative to offline
 * source2gen + manual offset maintenance.
 *
 * Phase 1: Safe vtable-based lookups + CUtlTSHash enumeration (SEH protected).
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

#include "rtti-hierarchy.hpp"

namespace schema {

struct RuntimeField {
    const char* name;           // field name (engine-owned string, do not free)
    const char* type_name;      // type name from CSchemaType (engine-owned)
    int32_t offset;             // field offset in class
    int32_t size;               // field size (from CSchemaType::GetSizes, 0 if unavailable)
    std::vector<std::string> metadata;  // annotation names (MNetworkEnable, etc.)
};

struct BaseClassRef {
    const char* name;           // base class name (engine-owned string)
    int32_t offset;             // offset of base within derived class
};

struct RuntimeClass {
    const char* name;           // class name (engine-owned)
    const char* module;         // module name
    int32_t size;               // class sizeof
    std::vector<RuntimeField> fields;
    std::vector<RuntimeField> static_fields;  // static members (class-level, not per-instance)
    std::vector<BaseClassRef> base_classes;    // all base classes (primary + secondary)
    std::vector<std::string> metadata;         // class-level annotations

    // Convenience: primary parent (first base class, or nullptr/0)
    const char* parent_name() const { return base_classes.empty() ? nullptr : base_classes[0].name; }
    int32_t parent_offset() const { return base_classes.empty() ? 0 : base_classes[0].offset; }
};

// Flattened field with absolute offset and source class annotation
struct FlatField {
    const char* name;           // field name (engine-owned)
    const char* type_name;      // type name (engine-owned)
    int32_t offset;             // absolute offset from top-level class start
    int32_t size;               // field size
    const char* defined_in;     // class that declared this field
};

// Complete flattened layout of a class including all inherited fields
struct FlatLayout {
    const char* name;           // top-level class name
    int32_t total_size;         // sizeof top-level class
    std::vector<FlatField> fields;              // all fields sorted by offset
    std::vector<std::string> inheritance_chain;  // top-down: [self, parent, grandparent, ...]
};

struct RuntimeEnumerator {
    const char* name;           // enumerator name (engine-owned string)
    int64_t value;              // enumerator value
};

struct RuntimeEnum {
    const char* name;           // enum name (engine-owned)
    const char* module;         // module name
    int8_t size;                // byte size of enum type (1, 2, 4)
    std::vector<RuntimeEnumerator> values;
};

class SchemaManager {
public:
    bool init(void* schema_system_ptr);

    // Single class lookup (vtable-based, always safe)
    const RuntimeClass* find_class(const char* module, const char* class_name);

    // Field offset lookup (walks class + all base classes)
    int32_t get_offset(const char* module, const char* class_name, const char* field_name);

    // Flattened layout: all inherited fields at absolute offsets, sorted
    bool get_flat_layout(const char* module, const char* class_name, FlatLayout& out);

    // Full module dump (CUtlTSHash iteration, SEH protected)
    bool dump_module(const char* module);

    // Auto-discover and dump ALL modules with schema data
    int dump_all_modules();

    // List of modules that were successfully dumped
    const std::vector<std::string>& dumped_modules() const { return m_dumped_modules; }

    // Stats
    int class_count() const;
    int total_field_count() const;
    int total_static_field_count() const;

    // Is initialized?
    bool is_ready() const { return m_schema_system != nullptr; }

    // Get raw schema system pointer
    void* schema_system() const { return m_schema_system; }

    // Access cached classes (for iteration)
    const std::unordered_map<std::string, RuntimeClass>& cache() const { return m_cache; }

    // RTTI-backed inheritance (call after init, before any lookups)
    // module_name is the DLL name (e.g. "client.dll") — stored in each InheritanceInfo
    void load_rtti(uintptr_t module_base, size_t module_size, const char* module_name = nullptr);
    const InheritanceInfo* get_inheritance(const char* class_name) const;
    int rtti_class_count() const { return static_cast<int>(m_rtti_map.size()); }
    const std::unordered_map<std::string, InheritanceInfo>& rtti_map() const { return m_rtti_map; }

    // Enum enumeration
    int enum_count() const;
    int total_enumerator_count() const;
    const std::unordered_map<std::string, RuntimeEnum>& enum_cache() const { return m_enum_cache; }

    // Raw pointer access for debugging
    void* get_type_scope(const char* module) { return find_type_scope(module); }
    void* get_class_info(const char* module, const char* class_name);

private:
    void* m_schema_system = nullptr;
    std::unordered_map<std::string, RuntimeClass> m_cache;
    std::unordered_map<std::string, InheritanceInfo> m_rtti_map;
    std::unordered_map<std::string, RuntimeEnum> m_enum_cache;
    std::vector<std::string> m_dumped_modules;

    // Internal: find type scope for a module via vtable call
    void* find_type_scope(const char* module);

    // Internal: find declared class via vtable call on type scope
    void* find_declared_class(void* type_scope, const char* class_name);

    // Internal: walk a single class info into RuntimeClass
    bool resolve_class(void* class_info, const char* module_name, RuntimeClass& out);

    // Internal: enumerate all classes from CUtlTSHash in a type scope
    bool enumerate_scope(void* type_scope, const char* module_name);

    // Internal: enumerate all enums from CUtlTSHash in a type scope
    bool enumerate_enums(void* type_scope, const char* module_name);
};

SchemaManager& instance();

} // namespace schema
