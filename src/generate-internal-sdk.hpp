#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include "vendor/json.hpp"
#include "src/import-schema.hpp"

struct InternalSdkStats {
    int classes = 0;
    int enums = 0;
    int fields = 0;
    int helpers = 0;
    int vfuncs = 0;
    int modules = 0;
};

InternalSdkStats generate_internal_sdk(
    const nlohmann::json& data,
    const std::vector<ModuleData>& modules,
    const std::unordered_map<std::string, const ClassInfo*>& class_lookup,
    const std::string& output_dir,
    const std::string& game_name,
    const std::string& exe_dir);
