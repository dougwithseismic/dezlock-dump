#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include "vendor/json.hpp"
#include "src/import-schema.hpp"

// Parse field arrays from JSON
std::vector<Field> parse_fields(const nlohmann::json& arr);

// Parse all modules from the JSON export (supports both multi-module and legacy formats)
std::vector<ModuleData> parse_modules(const nlohmann::json& data);

// Generate consolidated module text output: classes + flattened + enums in one file
void generate_module_txt(const std::vector<ClassInfo>& classes,
                         const std::vector<EnumInfo>& enums,
                         const nlohmann::json& data,
                         const std::string& output_dir, const std::string& module_name,
                         const std::unordered_map<std::string, const ClassInfo*>& global_lookup);

// Generate hierarchy files: per-class files in category folders + _index.txt tree
void generate_hierarchy(const std::vector<ClassInfo>& classes,
                        const std::string& output_dir, const std::string& module_name,
                        const std::unordered_map<std::string, const ClassInfo*>& global_lookup);

// Generate _globals.txt with recursive field expansion
void generate_globals_txt(const nlohmann::json& data,
                          const std::vector<ModuleData>& modules,
                          const std::string& output_dir,
                          int field_depth);

// Generate _access-paths.txt (schema globals only, quick-reference)
void generate_access_paths(const nlohmann::json& data,
                           const std::vector<ModuleData>& modules,
                           const std::string& output_dir);

// Generate _entity-paths.txt (full field trees for all entity classes)
void generate_entity_paths(const nlohmann::json& data,
                           const std::vector<ModuleData>& modules,
                           const std::string& output_dir,
                           int field_depth);

// Generate _protobuf-messages.txt from decoded protobuf descriptors
void generate_protobuf_output(const nlohmann::json& data,
                              const std::string& output_dir);
