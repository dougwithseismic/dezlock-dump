/**
 * dezlock-dump -- C++ port of import-schema.py
 *
 * Generates cherry-pickable C++ SDK headers from dezlock-dump's JSON export.
 * Produces per-class padded structs with static_asserts, per-module offset
 * constants and scoped enums, vtable RVAs, global pointer offsets, and
 * runtime-scannable byte patterns.
 *
 * Called directly from the main exe with already-parsed data structures.
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include "vendor/json.hpp"

// Shared data structures used by both main.cpp and import-schema.cpp.
// Defined here so both translation units share the same types.

struct Field {
    std::string name;
    std::string type;
    int offset = 0;
    int size = 0;
    std::string defined_in;
    std::vector<std::string> metadata;
};

struct EnumValue {
    std::string name;
    long long value = 0;
};

struct EnumInfo {
    std::string name;
    int size = 0;
    std::vector<EnumValue> values;
};

struct ClassInfo {
    std::string name;
    int size = 0;
    std::string parent;
    std::vector<std::string> inheritance;
    std::vector<std::string> metadata;
    std::vector<Field> fields;
    std::vector<Field> static_fields;
    std::vector<std::pair<std::string, int>> components;
};

struct ModuleData {
    std::string name;
    std::vector<ClassInfo> classes;
    std::vector<EnumInfo> enums;
};

struct SdkStats {
    int structs = 0;
    int enums = 0;
    int vtables = 0;
    int globals = 0;
    int patterns = 0;
    int resolved = 0;
    int unresolved = 0;
    int total_fields = 0;
};

SdkStats generate_sdk(const nlohmann::json& data,
                       const std::vector<ModuleData>& modules,
                       const std::unordered_map<std::string, const ClassInfo*>& class_lookup,
                       const std::string& output_dir,
                       const std::string& game_name,
                       const std::string& exe_dir);
