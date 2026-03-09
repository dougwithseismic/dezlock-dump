/**
 * dezlock-dump -- Internal SDK generator
 *
 * Generates runtime-resolved C++ SDK headers that query SchemaSystem_001
 * at runtime for field offsets. Patch-proof as long as field names are stable.
 */

#include "src/generate-internal-sdk.hpp"
#include "src/vfunc-namer.hpp"

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>
#include <optional>
#include <regex>
#include <cctype>

using json = nlohmann::json;

// ============================================================================
// Type resolution tables (copied from import-schema.cpp)
// ============================================================================

struct TypeEntry {
    std::string cpp_type;
    int size;
};

struct ContainerEntry {
    std::optional<int> size;
};

static const std::unordered_map<std::string, TypeEntry> RICH_TYPES = {
    {"Vector",    {"Vec3",   12}},
    {"VectorWS",  {"Vec3",   12}},
    {"QAngle",    {"QAngle", 12}},
    {"Color",     {"Color",   4}},
    {"Vector2D",  {"Vec2",    8}},
    {"Vector4D",  {"Vec4",   16}},
};

static const std::unordered_map<std::string, TypeEntry> PRIMITIVE_MAP = {
    {"bool",    {"bool",     1}},
    {"int8",    {"int8_t",   1}},
    {"uint8",   {"uint8_t",  1}},
    {"int16",   {"int16_t",  2}},
    {"uint16",  {"uint16_t", 2}},
    {"int32",   {"int32_t",  4}},
    {"uint32",  {"uint32_t", 4}},
    {"int64",   {"int64_t",  8}},
    {"uint64",  {"uint64_t", 8}},
    {"float32", {"float",    4}},
    {"float",   {"float",    4}},
    {"float64", {"double",   8}},
};

static const std::unordered_map<std::string, TypeEntry> ALIAS_TABLE = {
    {"CUtlString",                  {"void*",    8}},
    {"CUtlSymbolLarge",             {"void*",    8}},
    {"CGlobalSymbol",               {"",         8}},
    {"CUtlStringToken",             {"uint32_t", 4}},
    {"CKV3MemberNameWithStorage",   {"",        24}},
    {"VectorAligned",               {"float[4]",  16}},
    {"Quaternion",                  {"float[4]",  16}},
    {"QuaternionStorage",           {"float[4]",  16}},
    {"RotationVector",              {"float[3]",  12}},
    {"matrix3x4_t",                 {"float[12]", 48}},
    {"matrix3x4a_t",                {"float[12]", 48}},
    {"CTransform",                  {"",          32}},
    {"GameTime_t",                  {"float",    4}},
    {"GameTick_t",                  {"int32_t",  4}},
    {"AnimationTimeFloat",          {"float",    4}},
    {"AttachmentHandle_t",          {"uint8_t",  1}},
    {"CAnimParamHandle",            {"uint16_t", 2}},
    {"CAnimParamHandleMap",         {"",         2}},
    {"ModelConfigHandle_t",         {"uint16_t", 2}},
    {"HitGroup_t",                  {"int32_t",  4}},
    {"RenderPrimitiveType_t",       {"int32_t",  4}},
    {"MoveType_t",                  {"uint8_t",  1}},
    {"MoveCollide_t",               {"uint8_t",  1}},
    {"SolidType_t",                 {"uint8_t",  1}},
    {"SurroundingBoundsType_t",     {"uint8_t",  1}},
    {"RenderMode_t",                {"uint8_t",  1}},
    {"RenderFx_t",                  {"uint8_t",  1}},
    {"EntityDisolveType_t",         {"int32_t",  4}},
    {"NPC_STATE",                   {"int32_t",  4}},
    {"Hull_t",                      {"int32_t",  4}},
    {"Activity",                    {"int32_t",  4}},
    {"CSoundEventName",             {"",        16}},
    {"CFootstepTableHandle",        {"",         8}},
    {"CBodyComponent",              {"",         8}},
    {"AnimValueSource",             {"int32_t",  4}},
    {"AnimParamID",                 {"uint32_t", 4}},
    {"AnimScriptHandle",            {"uint16_t", 2}},
    {"AnimNodeID",                  {"uint32_t", 4}},
    {"AnimNodeOutputID",            {"uint32_t", 4}},
    {"AnimStateID",                 {"uint32_t", 4}},
    {"AnimComponentID",             {"uint32_t", 4}},
    {"AnimTagID",                   {"uint32_t", 4}},
    {"BlendKeyType",                {"int32_t",  4}},
    {"BinaryNodeTiming",            {"int32_t",  4}},
    {"BinaryNodeChildOption",       {"int32_t",  4}},
    {"DampingSpeedFunction",        {"int32_t",  4}},
    {"CPhysicsComponent",           {"",         8}},
    {"CRenderComponent",            {"",         8}},
    {"CPiecewiseCurve",                      {"",  64}},
    {"CAnimGraphTagOptionalRef",             {"",  32}},
    {"CAnimGraphTagRef",                     {"",  32}},
    {"CitadelCameraOperationsSequence_t",    {"", 136}},
    {"PulseSymbol_t",                        {"",  16}},
    {"CNetworkVarChainer",                   {"",  40}},
    {"CPanoramaImageName",                   {"",  16}},
    {"CBufferString",                        {"",  16}},
    {"KeyValues3",                           {"",  16}},
    {"CPulseValueFullType",                  {"",  24}},
    {"PulseRegisterMap_t",                   {"",  48}},
    {"HeroID_t",                             {"int32_t", 4}},
    {"HSequence",                            {"int32_t", 4}},
    {"CPlayerSlot",                          {"int32_t", 4}},
    {"WorldGroupId_t",                       {"int32_t", 4}},
    {"PulseDocNodeID_t",                     {"int32_t", 4}},
    {"PulseRuntimeChunkIndex_t",             {"int32_t", 4}},
    {"ParticleTraceSet_t",                   {"int32_t", 4}},
    {"ParticleColorBlendType_t",             {"int32_t", 4}},
    {"EventTypeSelection_t",                 {"int32_t", 4}},
    {"ThreeState_t",                         {"int32_t", 4}},
    {"ParticleAttachment_t",                 {"int32_t", 4}},
    {"EModifierValue",                       {"int32_t", 4}},
    {"ParticleOutputBlendMode_t",            {"int32_t", 4}},
    {"Detail2Combo_t",                       {"int32_t", 4}},
    {"ParticleFalloffFunction_t",            {"int32_t", 4}},
    {"ParticleHitboxBiasType_t",             {"int32_t", 4}},
    {"ParticleEndcapMode_t",                 {"int32_t", 4}},
    {"ParticleLightingQuality_t",            {"int32_t", 4}},
    {"ParticleSelection_t",                  {"int32_t", 4}},
    {"SpriteCardPerParticleScale_t",         {"int32_t", 4}},
    {"ParticleAlphaReferenceType_t",         {"int32_t", 4}},
    {"ParticleSequenceCropOverride_t",       {"int32_t", 4}},
    {"ParticleLightTypeChoiceList_t",        {"int32_t", 4}},
    {"ParticleDepthFeatheringMode_t",        {"int32_t", 4}},
    {"ParticleFogType_t",                    {"int32_t", 4}},
    {"ParticleOmni2LightTypeChoiceList_t",   {"int32_t", 4}},
    {"ParticleSortingChoiceList_t",          {"int32_t", 4}},
    {"ParticleOrientationChoiceList_t",      {"int32_t", 4}},
    {"TextureRepetitionMode_t",              {"int32_t", 4}},
    {"SpriteCardShaderType_t",               {"int32_t", 4}},
    {"ParticleDirectionNoiseType_t",         {"int32_t", 4}},
    {"ParticleRotationLockType_t",           {"int32_t", 4}},
    {"ParticlePostProcessPriorityGroup_t",   {"int32_t", 4}},
    {"InheritableBoolType_t",                {"int32_t", 4}},
    {"ClosestPointTestType_t",               {"int32_t", 4}},
    {"ParticleColorBlendMode_t",             {"int32_t", 4}},
    {"ParticleTopology_t",                   {"int32_t", 4}},
    {"PFuncVisualizationType_t",             {"int32_t", 4}},
    {"ParticleVRHandChoiceList_t",           {"int32_t", 4}},
    {"StandardLightingAttenuationStyle_t",   {"int32_t", 4}},
    {"SnapshotIndexType_t",                  {"int32_t", 4}},
    {"PFNoiseType_t",                        {"int32_t", 4}},
    {"PFNoiseTurbulence_t",                  {"int32_t", 4}},
    {"PFNoiseModifier_t",                    {"int32_t", 4}},
    {"AnimVRHandMotionRange_t",              {"int32_t", 4}},
    {"AnimVRFinger_t",                       {"int32_t", 4}},
    {"IKSolverType",                         {"int32_t", 4}},
    {"IKTargetSource",                       {"int32_t", 4}},
    {"JiggleBoneSimSpace",                   {"int32_t", 4}},
    {"AnimPoseControl",                      {"int32_t", 4}},
    {"FacingMode",                           {"int32_t", 4}},
    {"FieldNetworkOption",                   {"int32_t", 4}},
    {"StanceOverrideMode",                   {"int32_t", 4}},
    {"AimMatrixBlendMode",                   {"int32_t", 4}},
    {"SolveIKChainAnimNodeDebugSetting",     {"int32_t", 4}},
    {"AnimNodeNetworkMode",                  {"int32_t", 4}},
    {"ChoiceMethod",                         {"int32_t", 4}},
    {"ChoiceBlendMethod",                    {"int32_t", 4}},
    {"ChoiceChangeMethod",                   {"int32_t", 4}},
    {"FootFallTagFoot_t",                    {"int32_t", 4}},
    {"MatterialAttributeTagType_t",          {"int32_t", 4}},
    {"FootPinningTimingSource",              {"int32_t", 4}},
    {"StepPhase",                            {"int32_t", 4}},
    {"FootLockSubVisualization",             {"int32_t", 4}},
    {"ResetCycleOption",                     {"int32_t", 4}},
    {"IkEndEffectorType",                    {"int32_t", 4}},
    {"IkTargetType",                         {"int32_t", 4}},
    {"Comparison_t",                         {"int32_t", 4}},
    {"ComparisonValueType",                  {"int32_t", 4}},
    {"ConditionLogicOp",                     {"int32_t", 4}},
    {"EDemoBoneSelectionMode",               {"int32_t", 4}},
    {"StateActionBehavior",                  {"int32_t", 4}},
    {"SeqPoseSetting_t",                     {"int32_t", 4}},
    {"StateComparisonValueType",             {"int32_t", 4}},
    {"SelectionSource_t",                    {"int32_t", 4}},
    {"MoodType_t",                           {"int32_t", 4}},
    {"AnimParamButton_t",                    {"int32_t", 4}},
    {"AnimParamNetworkSetting",              {"int32_t", 4}},
    {"CGroundIKSolverSettings",              {"",       48}},
};

static const std::unordered_map<std::string, ContainerEntry> CONTAINER_SIZES = {
    {"CUtlVector",                          {24}},
    {"CNetworkUtlVectorBase",               {24}},
    {"C_NetworkUtlVectorBase",              {24}},
    {"CUtlVectorEmbeddedNetworkVar",        {24}},
    {"CUtlLeanVector",                      {16}},
    {"CUtlOrderedMap",                      {40}},
    {"CUtlHashtable",                       {40}},
    {"CResourceNameTyped",                  {std::nullopt}},
    {"CEmbeddedSubclass",                   {16}},
    {"CStrongHandle",                       {8}},
    {"CWeakHandle",                         {8}},
    {"CStrongHandleCopyable",               {8}},
    {"CSmartPtr",                           {8}},
    {"CSmartPropPtr",                       {8}},
    {"CAnimGraphParamRef",                  {std::nullopt}},
    {"CEntityOutputTemplate",               {std::nullopt}},
    {"CEntityIOOutput",                     {std::nullopt}},
    {"CAnimInputDamping",                   {std::nullopt}},
    {"CRemapFloat",                         {std::nullopt}},
    {"CPerParticleFloatInput",              {std::nullopt}},
    {"CPerParticleVecInput",                {std::nullopt}},
    {"CParticleCollectionFloatInput",       {std::nullopt}},
    {"CParticleCollectionVecInput",         {std::nullopt}},
    {"CParticleTransformInput",             {std::nullopt}},
    {"CParticleModelInput",                 {std::nullopt}},
    {"CParticleRemapFloatInput",            {std::nullopt}},
    {"CRandomNumberGeneratorParameters",    {std::nullopt}},
    {"CAnimGraph2ParamOptionalRef",         {std::nullopt}},
    {"CAnimGraph2ParamRef",                 {std::nullopt}},
    {"CModifierHandleTyped",                {std::nullopt}},
    {"CSubclassName",                       {std::nullopt}},
    {"CSubclassNameBase",                   {16}},
};

// ============================================================================
// Shared state
// ============================================================================

struct ISDKState {
    std::unordered_map<std::string, int> all_enums;
    std::unordered_set<std::string> all_classes;
    std::unordered_map<std::string, std::string> class_to_module;
    std::unordered_map<std::string, std::string> class_subfolder;
    json cherry_pick;
    const std::unordered_map<std::string, const ClassInfo*>* class_lookup = nullptr;
};

// ============================================================================
// Helpers
// ============================================================================

static const char* enum_int_type(int sz) {
    switch (sz) {
        case 1: return "uint8_t";
        case 2: return "int16_t";
        case 4: return "int32_t";
        case 8: return "int64_t";
        default: return "int32_t";
    }
}

static void create_dirs(const std::string& path) {
    for (size_t i = 0; i < path.size(); i++) {
        if (path[i] == '\\' || path[i] == '/') {
            CreateDirectoryA(path.substr(0, i).c_str(), nullptr);
        }
    }
    CreateDirectoryA(path.c_str(), nullptr);
}

static bool write_file(const std::string& path, const std::string& content) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    fwrite(content.data(), 1, content.size(), f);
    fclose(f);
    return true;
}

static std::string strip_dll(const std::string& name) {
    if (name.size() > 4 && name.substr(name.size() - 4) == ".dll") {
        return name.substr(0, name.size() - 4);
    }
    return name;
}

static std::string safe_class_name(const std::string& name) {
    std::string result = name;
    size_t pos = 0;
    while ((pos = result.find("::", pos)) != std::string::npos) {
        result.replace(pos, 2, "__");
        pos += 2;
    }
    return result;
}

static std::string make_guard(const std::string& name) {
    std::string guard = "ISDK_";
    for (char c : name) {
        if (std::isalnum(static_cast<unsigned char>(c)))
            guard += (char)std::toupper(static_cast<unsigned char>(c));
        else
            guard += '_';
    }
    guard += "_HPP";
    return guard;
}

static bool is_entity_class(const std::string& cls_name,
                             const std::unordered_map<std::string, const ClassInfo*>& lookup) {
    std::string current = cls_name;
    std::unordered_set<std::string> seen;
    while (!current.empty() && lookup.count(current) && !seen.count(current)) {
        if (current == "CEntityInstance") return true;
        seen.insert(current);
        current = lookup.at(current)->parent;
    }
    return false;
}

static bool needs_types_include(const std::vector<Field>& fields) {
    for (const auto& f : fields) {
        if (RICH_TYPES.count(f.type)) return true;
        if (f.type.substr(0, 8) == "CHandle<" || f.type.substr(0, 13) == "CEntityHandle") return true;
        // Check array of rich types
        static const std::regex rx_arr(R"(([\w:]+)\[(\d+)\])");
        std::smatch m;
        if (std::regex_match(f.type, m, rx_arr)) {
            if (RICH_TYPES.count(m[1].str())) return true;
        }
    }
    return false;
}

// ============================================================================
// Type resolution (same logic as import-schema.cpp)
// ============================================================================

struct FieldMacro {
    std::string macro;      // "FIELD", "FIELD_ARRAY", "FIELD_PTR", "FIELD_BLOB"
    std::string cpp_type;   // resolved type or "" for blob
    std::string elem_type;  // for FIELD_ARRAY
    int count = 0;          // for FIELD_ARRAY
    int blob_size = 0;      // for FIELD_BLOB
    std::string comment;    // original schema type + size
};

static FieldMacro resolve_field(const Field& field, const ISDKState& state) {
    FieldMacro result;
    const std::string& st = field.type;
    result.comment = st + " (" + std::to_string(field.size) + ")";

    // Bitfields -> comment only
    if (st.substr(0, 9) == "bitfield:") {
        result.macro = ""; // skip
        return result;
    }

    // Rich types
    {
        auto it = RICH_TYPES.find(st);
        if (it != RICH_TYPES.end()) {
            result.macro = "FIELD";
            result.cpp_type = it->second.cpp_type;
            return result;
        }
    }

    // Primitives
    {
        auto it = PRIMITIVE_MAP.find(st);
        if (it != PRIMITIVE_MAP.end()) {
            result.macro = "FIELD";
            result.cpp_type = it->second.cpp_type;
            return result;
        }
    }

    // Alias table
    {
        auto it = ALIAS_TABLE.find(st);
        if (it != ALIAS_TABLE.end()) {
            if (!it->second.cpp_type.empty()) {
                // Check if it's an array-like alias (e.g. float[4])
                if (it->second.cpp_type.find('[') != std::string::npos) {
                    result.macro = "FIELD_BLOB";
                    result.blob_size = field.size;
                    return result;
                }
                result.macro = "FIELD";
                result.cpp_type = it->second.cpp_type;
                return result;
            }
            // Opaque blob
            result.macro = "FIELD_BLOB";
            result.blob_size = field.size;
            return result;
        }
    }

    // CHandle<T>
    if (st.substr(0, 8) == "CHandle<" || st.substr(0, 13) == "CEntityHandle") {
        result.macro = "FIELD";
        result.cpp_type = "CHandle";
        return result;
    }

    // Pointers
    if (!st.empty() && st.back() == '*') {
        result.macro = "FIELD_PTR";
        result.cpp_type = "void*";
        return result;
    }

    // char[N]
    {
        static const std::regex rx_char(R"(char\[(\d+)\])");
        std::smatch m;
        if (std::regex_match(st, m, rx_char)) {
            result.macro = "FIELD_ARRAY";
            result.elem_type = "char";
            result.count = std::stoi(m[1].str());
            return result;
        }
    }

    // Fixed-size arrays: BaseType[Count]
    {
        static const std::regex rx_array(R"(([\w:]+)\[(\d+)\])");
        std::smatch m;
        if (std::regex_match(st, m, rx_array)) {
            std::string base_type = m[1].str();
            int count = std::stoi(m[2].str());

            auto rit = RICH_TYPES.find(base_type);
            if (rit != RICH_TYPES.end()) {
                result.macro = "FIELD_ARRAY";
                result.elem_type = rit->second.cpp_type;
                result.count = count;
                return result;
            }

            auto pit = PRIMITIVE_MAP.find(base_type);
            if (pit != PRIMITIVE_MAP.end()) {
                result.macro = "FIELD_ARRAY";
                result.elem_type = pit->second.cpp_type;
                result.count = count;
                return result;
            }

            auto ait = ALIAS_TABLE.find(base_type);
            if (ait != ALIAS_TABLE.end() && !ait->second.cpp_type.empty() &&
                ait->second.cpp_type.find('[') == std::string::npos) {
                result.macro = "FIELD_ARRAY";
                result.elem_type = ait->second.cpp_type;
                result.count = count;
                return result;
            }

            if (base_type.substr(0, 7) == "CHandle") {
                result.macro = "FIELD_ARRAY";
                result.elem_type = "CHandle";
                result.count = count;
                return result;
            }

            auto eit = state.all_enums.find(base_type);
            if (eit != state.all_enums.end()) {
                result.macro = "FIELD_ARRAY";
                result.elem_type = enum_int_type(eit->second);
                result.count = count;
                return result;
            }

            // Unknown array base -> blob
            result.macro = "FIELD_BLOB";
            result.blob_size = field.size;
            return result;
        }
    }

    // Template containers
    {
        size_t lt = st.find('<');
        if (lt != std::string::npos) {
            std::string outer = st.substr(0, lt);

            if (outer == "CHandle") {
                result.macro = "FIELD";
                result.cpp_type = "CHandle";
                return result;
            }

            // All containers -> blob (can't resolve inner template at runtime)
            if (CONTAINER_SIZES.count(outer)) {
                result.macro = "FIELD_BLOB";
                auto it = CONTAINER_SIZES.find(outer);
                result.blob_size = it->second.size.value_or(field.size);
                return result;
            }

            // Unknown template -> blob
            result.macro = "FIELD_BLOB";
            result.blob_size = field.size;
            return result;
        }
    }

    // Enum-typed fields
    {
        auto it = state.all_enums.find(st);
        if (it != state.all_enums.end()) {
            result.macro = "FIELD";
            result.cpp_type = enum_int_type(it->second);
            return result;
        }
    }

    // Embedded schema classes -> blob
    if (state.all_classes.count(st)) {
        result.macro = "FIELD_BLOB";
        result.blob_size = field.size;
        return result;
    }

    // Unresolved -> blob
    result.macro = "FIELD_BLOB";
    result.blob_size = field.size;
    return result;
}

// ============================================================================
// Cherry-pick helper transformation: m_fieldName -> m_fieldName()
// ============================================================================

static std::string transform_helper(const std::string& method) {
    // Match m_xxx identifiers not already followed by (
    static const std::regex rx(R"(\b(m_\w+)\b(?!\())");
    return std::regex_replace(method, rx, "$1()");
}

// ============================================================================
// schema_runtime.hpp content
// ============================================================================

static const char* SCHEMA_RUNTIME_HPP = R"(// schema_runtime.hpp -- Runtime schema offset resolver for Source 2
// Auto-generated by dezlock-dump. Copy this file into your injected DLL project.
// Zero dependencies beyond <Windows.h> and C++17 stdlib.
#pragma once

#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <string>
#include <mutex>
#include <utility>

namespace sdk::schema {

// ---- SchemaSystem interface discovery (singleton) ----

inline void* get_schema_system() {
    static void* s_system = nullptr;
    if (s_system) return s_system;

    HMODULE hmod = GetModuleHandleA("schemasystem.dll");
    if (!hmod) return nullptr;

    using CreateInterfaceFn = void*(*)(const char*, int*);
    auto fn = reinterpret_cast<CreateInterfaceFn>(
        GetProcAddress(hmod, "CreateInterface"));
    if (!fn) return nullptr;

    int ret = 0;
    s_system = fn("SchemaSystem_001", &ret);
    return s_system;
}

// ---- SEH-isolated vtable calls ----

inline void* find_type_scope(void* schema_system, const char* module_name) {
    void* result = nullptr;
    __try {
        auto vtable = *reinterpret_cast<uintptr_t**>(schema_system);
        auto fn = reinterpret_cast<void*(__fastcall*)(void*, const char*, void*)>(vtable[13]);
        result = fn(schema_system, module_name, nullptr);
    } __except(EXCEPTION_EXECUTE_HANDLER) { result = nullptr; }
    return result;
}

inline void* find_declared_class(void* type_scope, const char* class_name) {
    void* result = nullptr;
    __try {
        auto vtable = *reinterpret_cast<uintptr_t**>(type_scope);
        auto fn = reinterpret_cast<void(__fastcall*)(void*, void**, const char*)>(vtable[2]);
        fn(type_scope, &result, class_name);
    } __except(EXCEPTION_EXECUTE_HANDLER) { result = nullptr; }
    return result;
}

// ---- Safe memory reader (SEH-isolated, no C++ unwinding) ----

template<typename T>
inline bool safe_read(uintptr_t addr, T* out) {
    __try {
        *out = *reinterpret_cast<const T*>(addr);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        *out = T{};
        return false;
    }
}

// ---- Offset resolution with caching ----

inline int32_t resolve_offset(const char* module_name, const char* class_name, const char* field_name) {
    struct FieldCache {
        std::unordered_map<std::string, int32_t> fields;
    };
    struct ClassCache {
        std::unordered_map<std::string, FieldCache> classes;
    };
    struct ModuleCache {
        void* type_scope = nullptr;
        ClassCache cache;
    };

    static std::unordered_map<std::string, ModuleCache> s_modules;
    static std::mutex s_mutex;

    std::lock_guard<std::mutex> lock(s_mutex);

    // Check cache
    auto& mod = s_modules[module_name];
    auto& cls = mod.cache.classes[class_name];
    auto it = cls.fields.find(field_name);
    if (it != cls.fields.end()) return it->second;

    // Resolve from SchemaSystem
    void* sys = get_schema_system();
    if (!sys) return -1;

    if (!mod.type_scope) {
        mod.type_scope = find_type_scope(sys, module_name);
    }
    if (!mod.type_scope) return -1;

    void* class_info = find_declared_class(mod.type_scope, class_name);
    if (!class_info) return -1;

    // CSchemaClassInfo: field_count at +0x1C (int16), fields_ptr at +0x28
    // SchemaClassFieldData_t: 0x20 bytes each, name at +0x00, offset at +0x10
    uintptr_t ci = reinterpret_cast<uintptr_t>(class_info);
    int16_t field_count = 0;
    uintptr_t fields_ptr = 0;

    if (!safe_read<int16_t>(ci + 0x1C, &field_count)) return -1;
    if (!safe_read<uintptr_t>(ci + 0x28, &fields_ptr)) return -1;
    if (!fields_ptr || field_count <= 0) return -1;

    // Walk all fields and cache them (avoids repeated walks for the same class)
    for (int i = 0; i < field_count; i++) {
        uintptr_t entry = fields_ptr + i * 0x20;
        const char* fname = nullptr;
        int32_t foffset = 0;
        if (!safe_read<const char*>(entry + 0x00, &fname) || !fname) continue;
        if (!safe_read<int32_t>(entry + 0x10, &foffset)) continue;
        cls.fields[fname] = foffset;
    }

    // Return the requested field
    it = cls.fields.find(field_name);
    if (it != cls.fields.end()) return it->second;
    return -1;
}

} // namespace sdk::schema

// ============================================================================
// Macros -- the public API
// ============================================================================

// Declare once per struct: binds module + class name for all FIELD macros below
#define SCHEMA_CLASS(mod, cls)                                              \
    static constexpr const char* _schema_module = mod;                      \
    static constexpr const char* _schema_class  = cls;

// Standard field accessor: returns type&
#define FIELD(name, type)                                                   \
    type& name() {                                                          \
        static int32_t off = ::sdk::schema::resolve_offset(                 \
            _schema_module, _schema_class, #name);                          \
        if (off == -1) { static type _z{}; _z = {}; return _z; }             \
        return *reinterpret_cast<type*>(                                    \
            reinterpret_cast<uintptr_t>(this) + off);                       \
    }                                                                       \
    const type& name() const {                                              \
        static int32_t off = ::sdk::schema::resolve_offset(                 \
            _schema_module, _schema_class, #name);                          \
        if (off == -1) { static const type _z{}; return _z; }               \
        return *reinterpret_cast<const type*>(                              \
            reinterpret_cast<uintptr_t>(this) + off);                       \
    }

// Array field: returns pointer to first element (nullptr on failure)
#define FIELD_ARRAY(name, elem_type, count)                                 \
    elem_type* name() {                                                     \
        static int32_t off = ::sdk::schema::resolve_offset(                 \
            _schema_module, _schema_class, #name);                          \
        if (off == -1) return nullptr;                                      \
        return reinterpret_cast<elem_type*>(                                \
            reinterpret_cast<uintptr_t>(this) + off);                       \
    }                                                                       \
    const elem_type* name() const {                                         \
        static int32_t off = ::sdk::schema::resolve_offset(                 \
            _schema_module, _schema_class, #name);                          \
        if (off == -1) return nullptr;                                      \
        return reinterpret_cast<const elem_type*>(                          \
            reinterpret_cast<uintptr_t>(this) + off);                       \
    }

// Pointer field: reads and returns the pointer value (default-constructed on failure)
#define FIELD_PTR(name, type)                                               \
    type name() {                                                           \
        static int32_t off = ::sdk::schema::resolve_offset(                 \
            _schema_module, _schema_class, #name);                          \
        if (off == -1) { type _z = {}; return _z; }                         \
        return *reinterpret_cast<type*>(                                    \
            reinterpret_cast<uintptr_t>(this) + off);                       \
    }

// Opaque/embedded type: returns void* to the field's raw memory (nullptr on failure)
#define FIELD_BLOB(name, sz)                                                \
    void* name() {                                                          \
        static int32_t off = ::sdk::schema::resolve_offset(                 \
            _schema_module, _schema_class, #name);                          \
        if (off == -1) return nullptr;                                      \
        return reinterpret_cast<void*>(                                     \
            reinterpret_cast<uintptr_t>(this) + off);                       \
    }                                                                       \
    const void* name() const {                                              \
        static int32_t off = ::sdk::schema::resolve_offset(                 \
            _schema_module, _schema_class, #name);                          \
        if (off == -1) return nullptr;                                      \
        return reinterpret_cast<const void*>(                               \
            reinterpret_cast<uintptr_t>(this) + off);                       \
    }

// ============================================================================
// Virtual function call wrappers
// ============================================================================

namespace sdk::vfunc {

inline uintptr_t* get_vtable(void* obj) {
    uintptr_t* vt = nullptr;
    __try { vt = *reinterpret_cast<uintptr_t**>(obj); }
    __except(EXCEPTION_EXECUTE_HANDLER) { vt = nullptr; }
    return vt;
}

} // namespace sdk::vfunc

// Zero-argument virtual function call (most common, used for getters)
#define VFUNC(idx, ret, name)                                              \
    ret name() {                                                           \
        auto _vt = ::sdk::vfunc::get_vtable(this);                         \
        if (!_vt) return ret{};                                            \
        return reinterpret_cast<ret(__fastcall*)(void*)>(_vt[idx])(this);   \
    }

// Variadic-argument virtual function call (manual use)
#define VFUNC_ARGS(idx, ret, name, ...)                                    \
    template<typename... _VArgs>                                           \
    ret name(_VArgs&&... args) {                                           \
        auto _vt = ::sdk::vfunc::get_vtable(this);                         \
        if (!_vt) return ret{};                                            \
        using _Fn = ret(__fastcall*)(void*, _VArgs...);                    \
        return reinterpret_cast<_Fn>(_vt[idx])(this, std::forward<_VArgs>(args)...); \
    }

// Unnamed fallback returning void*
#define VFUNC_RAW(idx)                                                     \
    void* vfunc_##idx() {                                                  \
        auto _vt = ::sdk::vfunc::get_vtable(this);                         \
        if (!_vt) return nullptr;                                          \
        return reinterpret_cast<void*(__fastcall*)(void*)>(_vt[idx])(this); \
    }
)";

// ============================================================================
// types.hpp content (same layout types as static SDK, no pack pragmas)
// ============================================================================

static std::string generate_types_hpp() {
    return R"(// Auto-generated by dezlock-dump (internal SDK) -- DO NOT EDIT
// Base SDK types for runtime-resolved headers
#pragma once

#include <cstdint>
#include <cstddef>

// If the consumer project already defines SDK types (e.g., shared/sdk/types.hpp),
// skip all definitions here. The consumer's types.hpp must define SDK_TYPES_DEFINED.
#ifndef SDK_TYPES_DEFINED
#define SDK_TYPES_DEFINED

namespace sdk {

struct Vec2 {
    float x, y;
    Vec2() : x(0), y(0) {}
    Vec2(float x, float y) : x(x), y(y) {}
    Vec2 operator+(const Vec2& o) const { return {x + o.x, y + o.y}; }
    Vec2 operator-(const Vec2& o) const { return {x - o.x, y - o.y}; }
    Vec2 operator*(float s) const { return {x * s, y * s}; }
};

struct Vec3 {
    float x, y, z;
    Vec3() : x(0), y(0), z(0) {}
    Vec3(float x, float y, float z) : x(x), y(y), z(z) {}
    Vec3 operator+(const Vec3& o) const { return {x + o.x, y + o.y, z + o.z}; }
    Vec3 operator-(const Vec3& o) const { return {x - o.x, y - o.y, z - o.z}; }
    Vec3 operator*(float s) const { return {x * s, y * s, z * s}; }
    float length_sqr() const { return x * x + y * y + z * z; }
    float length_2d_sqr() const { return x * x + y * y; }
};

struct Vec4 { float x, y, z, w; };

struct QAngle {
    float pitch, yaw, roll;
    QAngle() : pitch(0), yaw(0), roll(0) {}
    QAngle(float p, float y, float r) : pitch(p), yaw(y), roll(r) {}
};

struct Color { uint8_t r, g, b, a; };

struct CHandle {
    uint32_t value;
    bool is_valid() const { return value != 0xFFFFFFFF; }
    uint32_t index() const { return value & 0x7FFF; }
    uint32_t serial() const { return value >> 15; }
};

struct ViewMatrix { float m[4][4]; };

} // namespace sdk

#endif // SDK_TYPES_DEFINED
)";
}

// ============================================================================
// Per-class header generation
// ============================================================================

static std::string get_class_subfolder(const std::string& cls_name, const ISDKState& state) {
    auto it = state.class_subfolder.find(cls_name);
    return (it != state.class_subfolder.end()) ? it->second : "";
}

static std::string compute_types_include(const std::string& cls_name, const ISDKState& state) {
    std::string sub = get_class_subfolder(cls_name, state);
    return !sub.empty() ? "\"../../types.hpp\"" : "\"../types.hpp\"";
}

static std::string compute_runtime_include(const std::string& cls_name, const ISDKState& state) {
    std::string sub = get_class_subfolder(cls_name, state);
    return !sub.empty() ? "\"../../schema_runtime.hpp\"" : "\"../schema_runtime.hpp\"";
}

static std::string compute_include_path(const std::string& from_class,
                                         const std::string& to_class,
                                         const ISDKState& state) {
    std::string from_module = state.class_to_module.count(from_class)
        ? state.class_to_module.at(from_class) : "";
    std::string to_module = state.class_to_module.count(to_class)
        ? state.class_to_module.at(to_class) : "";
    std::string from_sub = get_class_subfolder(from_class, state);
    std::string to_sub = get_class_subfolder(to_class, state);
    std::string to_safe = safe_class_name(to_class);

    bool same_module = (from_module == to_module);

    if (same_module && from_sub == to_sub) {
        return "\"" + to_safe + ".hpp\"";
    }
    if (same_module) {
        if (!from_sub.empty() && !to_sub.empty()) {
            return "\"../" + to_sub + "/" + to_safe + ".hpp\"";
        } else if (!from_sub.empty()) {
            return "\"../" + to_safe + ".hpp\"";
        } else {
            return "\"" + to_sub + "/" + to_safe + ".hpp\"";
        }
    }
    std::string prefix;
    if (!from_sub.empty()) {
        prefix = "\"../../" + to_module;
    } else {
        prefix = "\"../" + to_module;
    }
    if (!to_sub.empty()) {
        return prefix + "/" + to_sub + "/" + to_safe + ".hpp\"";
    }
    return prefix + "/" + to_safe + ".hpp\"";
}

struct ClassGenResult {
    std::string content;
    int field_count = 0;
    int helper_count = 0;
    int vfunc_count = 0;
};

static void emit_vfunc_section(
    std::vector<std::string>& lines,
    const ClassVFuncTable& vft,
    int& vfunc_count)
{
    char vtable_comment[128];
    snprintf(vtable_comment, sizeof(vtable_comment),
             "    // --- Virtual functions (vtable RVA: 0x%X, %d total) ---",
             vft.vtable_rva, (int)vft.functions.size());
    lines.push_back("");
    lines.push_back(vtable_comment);

    for (const auto& func : vft.functions) {
        // Skip inherited entries
        if (func.index < vft.parent_vfunc_count) continue;
        // Skip stubs
        if (func.is_stub) continue;

        std::string line = "    ";

        if (!func.name.empty()) {
            // Named function
            line += "VFUNC(" + std::to_string(func.index) + ", " + func.return_hint + ", " + func.name + ");";
            // Pad and add source comment
            while (line.size() < 60) line += ' ';
            line += "// source: " + func.source;
        } else {
            // Unnamed fallback
            line += "VFUNC_RAW(" + std::to_string(func.index) + ");";
            // Pad and add signature/field comment
            while (line.size() < 60) line += ' ';
            std::string comment = "//";
            if (!func.signature.empty()) {
                // Show first ~40 chars of signature
                std::string short_sig = func.signature.substr(0, 40);
                if (func.signature.size() > 40) short_sig += "...";
                comment += " sig: " + short_sig;
            }
            if (!func.accessed_fields.empty()) {
                comment += " reads:";
                for (size_t i = 0; i < func.accessed_fields.size() && i < 3; i++) {
                    comment += " " + func.accessed_fields[i];
                    if (i + 1 < func.accessed_fields.size() && i + 1 < 3) comment += ",";
                }
                if (func.accessed_fields.size() > 3) comment += "...";
            }
            line += comment;
        }

        lines.push_back(line);
        vfunc_count++;
    }
}

static ClassGenResult generate_internal_class_header(
    const ClassInfo& cls,
    const std::string& module_name,
    const ISDKState& state,
    const std::string& timestamp,
    const ClassVFuncTable* vftable = nullptr)
{
    ClassGenResult result;
    std::string safe_name = safe_class_name(cls.name);
    std::string guard = make_guard(safe_name);
    std::string mod_clean = strip_dll(module_name);

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by dezlock-dump (internal SDK) \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Class: " + cls.name + " (runtime-resolved offsets)");
    lines.push_back("// Module: " + module_name);
    if (!cls.parent.empty())
        lines.push_back("// Parent: " + cls.parent);
    lines.push_back("// Generated: " + timestamp);
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    lines.push_back("#include " + compute_runtime_include(cls.name, state));

    if (needs_types_include(cls.fields))
        lines.push_back("#include " + compute_types_include(cls.name, state));

    // Include parent class
    if (!cls.parent.empty() && state.all_classes.count(cls.parent)) {
        lines.push_back("#include " + compute_include_path(cls.name, cls.parent, state));
    }

    lines.push_back("");
    lines.push_back("namespace sdk {");
    lines.push_back("");

    // Struct declaration
    if (!cls.parent.empty() && state.all_classes.count(cls.parent)) {
        lines.push_back("struct " + safe_name + " : " + safe_class_name(cls.parent) + " {");
    } else {
        lines.push_back("struct " + safe_name + " {");
    }

    // SCHEMA_CLASS binding
    lines.push_back("    SCHEMA_CLASS(\"" + module_name + "\", \"" + cls.name + "\");");
    lines.push_back("");

    // Collect parent field names to skip inherited fields
    std::unordered_set<std::string> parent_fields;
    if (!cls.parent.empty() && state.class_lookup) {
        std::string walk = cls.parent;
        std::unordered_set<std::string> seen;
        while (!walk.empty() && state.class_lookup->count(walk) && !seen.count(walk)) {
            seen.insert(walk);
            const ClassInfo* parent_cls = state.class_lookup->at(walk);
            for (const auto& f : parent_cls->fields)
                parent_fields.insert(f.name);
            walk = parent_cls->parent;
        }
    }

    // Emit fields
    std::vector<Field> sorted_fields = cls.fields;
    std::sort(sorted_fields.begin(), sorted_fields.end(),
              [](const Field& a, const Field& b) { return a.offset < b.offset; });

    for (const auto& field : sorted_fields) {
        if (parent_fields.count(field.name)) continue;

        FieldMacro fm = resolve_field(field, state);

        if (fm.macro.empty()) {
            // Bitfield or skip
            if (field.type.substr(0, 9) == "bitfield:") {
                lines.push_back("    // " + field.name + " : " + field.type.substr(9) + " bits");
            }
            continue;
        }

        std::string line = "    ";
        if (fm.macro == "FIELD") {
            line += "FIELD(" + field.name + ", " + fm.cpp_type + ");";
        } else if (fm.macro == "FIELD_ARRAY") {
            line += "FIELD_ARRAY(" + field.name + ", " + fm.elem_type + ", " + std::to_string(fm.count) + ");";
        } else if (fm.macro == "FIELD_PTR") {
            line += "FIELD_PTR(" + field.name + ", " + fm.cpp_type + ");";
        } else if (fm.macro == "FIELD_BLOB") {
            line += "FIELD_BLOB(" + field.name + ", " + std::to_string(fm.blob_size) + ");";
        }

        // Pad to alignment for comment
        while (line.size() < 60) line += ' ';
        line += "// " + fm.comment;

        lines.push_back(line);
        result.field_count++;
    }

    // Cherry-pick helpers
    if (state.cherry_pick.contains("helpers") &&
        state.cherry_pick["helpers"].contains(cls.name)) {
        const auto& helpers = state.cherry_pick["helpers"][cls.name]["methods"];
        if (!helpers.empty()) {
            lines.push_back("");
            lines.push_back("    // --- Helper methods ---");
            for (const auto& method : helpers) {
                std::string transformed = transform_helper(method.get<std::string>());
                lines.push_back("    " + transformed);
                result.helper_count++;
            }
        }
    }

    // Emit virtual functions
    if (vftable && !vftable->functions.empty()) {
        emit_vfunc_section(lines, *vftable, result.vfunc_count);
    }

    lines.push_back("};");
    lines.push_back("");
    lines.push_back("} // namespace sdk");
    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    for (const auto& l : lines) { result.content += l; result.content += '\n'; }
    return result;
}

// ============================================================================
// Enum generation (identical to static SDK -- enums are compile-time constants)
// ============================================================================

static std::string generate_module_enums(const std::vector<EnumInfo>& enums,
                                          const std::string& module_name,
                                          const std::string& timestamp) {
    std::string mod_clean = strip_dll(module_name);
    std::string guard = make_guard(mod_clean + "_enums");

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by dezlock-dump (internal SDK) \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Enums for module: " + module_name);
    lines.push_back("// Generated: " + timestamp);
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    lines.push_back("#include <cstdint>");
    lines.push_back("");
    lines.push_back("namespace sdk::enums::" + mod_clean + " {");
    lines.push_back("");

    std::vector<const EnumInfo*> sorted_enums;
    for (const auto& e : enums) sorted_enums.push_back(&e);
    std::sort(sorted_enums.begin(), sorted_enums.end(),
              [](const EnumInfo* a, const EnumInfo* b) { return a->name < b->name; });

    for (const auto* en : sorted_enums) {
        std::string underlying = enum_int_type(en->size);
        lines.push_back("enum class " + en->name + " : " + underlying + " {");
        for (const auto& v : en->values) {
            char buf[256];
            snprintf(buf, sizeof(buf), "    %s = %lld,", v.name.c_str(), v.value);
            lines.push_back(buf);
        }
        lines.push_back("};");
        lines.push_back("");
    }

    lines.push_back("} // namespace sdk::enums::" + mod_clean);
    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return result;
}

static std::string generate_all_enums(const std::vector<std::string>& module_names,
                                       const std::string& timestamp) {
    std::string guard = make_guard("all_enums");
    std::vector<std::string> sorted_names = module_names;
    std::sort(sorted_names.begin(), sorted_names.end());

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by dezlock-dump (internal SDK) \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Master include for all enums");
    lines.push_back("// Generated: " + timestamp);
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    for (const auto& mod : sorted_names) {
        lines.push_back("#include \"" + mod + "/_enums.hpp\"");
    }
    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return result;
}

// ============================================================================
// Per-module processing
// ============================================================================

struct ModuleResult {
    int classes = 0;
    int enums = 0;
    int fields = 0;
    int helpers = 0;
    int vfuncs = 0;
};

static ModuleResult process_module(const ModuleData& mod,
                                    const ISDKState& state,
                                    const std::string& output_dir,
                                    const std::string& timestamp,
                                    const VFuncMap* vfunc_map = nullptr) {
    ModuleResult result;
    std::string mod_clean = strip_dll(mod.name);
    std::string mod_dir = output_dir + "\\" + mod_clean;
    create_dirs(mod_dir);

    // Determine which classes are entities vs structs
    bool has_entities = false, has_structs = false;
    for (const auto& cls : mod.classes) {
        if (state.class_subfolder.count(cls.name)) {
            std::string sub = state.class_subfolder.at(cls.name);
            if (sub == "entities") has_entities = true;
            else if (sub == "structs") has_structs = true;
        }
    }

    if (has_entities) create_dirs(mod_dir + "\\entities");
    if (has_structs) create_dirs(mod_dir + "\\structs");

    // Look up this module's vfunc data
    const std::unordered_map<std::string, ClassVFuncTable>* mod_vfuncs = nullptr;
    if (vfunc_map) {
        auto vit = vfunc_map->find(mod.name);
        if (vit != vfunc_map->end()) mod_vfuncs = &vit->second;
    }

    // Generate per-class headers
    for (const auto& cls : mod.classes) {
        const ClassVFuncTable* vft = nullptr;
        if (mod_vfuncs) {
            auto vit = mod_vfuncs->find(cls.name);
            if (vit != mod_vfuncs->end()) vft = &vit->second;
        }
        ClassGenResult gen = generate_internal_class_header(cls, mod.name, state, timestamp, vft);

        std::string sub = get_class_subfolder(cls.name, state);
        std::string cls_dir = mod_dir;
        if (!sub.empty()) cls_dir += "\\" + sub;

        std::string safe_name = safe_class_name(cls.name);
        write_file(cls_dir + "\\" + safe_name + ".hpp", gen.content);

        result.classes++;
        result.fields += gen.field_count;
        result.helpers += gen.helper_count;
        result.vfuncs += gen.vfunc_count;
    }

    // Generate enums
    if (!mod.enums.empty()) {
        std::string enums_content = generate_module_enums(mod.enums, mod.name, timestamp);
        write_file(mod_dir + "\\_enums.hpp", enums_content);
        result.enums += (int)mod.enums.size();
    }

    return result;
}

// ============================================================================
// Entry point
// ============================================================================

InternalSdkStats generate_internal_sdk(
    const nlohmann::json& data,
    const std::vector<ModuleData>& modules,
    const std::unordered_map<std::string, const ClassInfo*>& class_lookup,
    const std::string& output_dir,
    const std::string& game_name,
    const std::string& exe_dir)
{
    InternalSdkStats stats;

    // Timestamp
    std::string timestamp;
    {
        time_t now = time(nullptr);
        struct tm t;
        localtime_s(&t, &now);
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &t);
        timestamp = buf;
    }

    // Build shared state
    ISDKState state;
    state.class_lookup = &class_lookup;

    for (const auto& mod : modules) {
        std::string mod_clean = strip_dll(mod.name);
        for (const auto& cls : mod.classes) {
            state.all_classes.insert(cls.name);
            state.class_to_module[cls.name] = mod_clean;
        }
        for (const auto& en : mod.enums) {
            state.all_enums[en.name] = en.size;
        }
    }

    // Determine entity/struct subfolder for each class
    // (matches import-schema.cpp logic: filter useful classes, three-way split)
    for (const auto& mod : modules) {
        std::vector<const ClassInfo*> useful;
        for (const auto& c : mod.classes) {
            if (c.size > 0 && !c.fields.empty()) useful.push_back(&c);
        }

        std::vector<const ClassInfo*> entities;
        std::vector<const ClassInfo*> non_entities;
        for (const auto* c : useful) {
            if (is_entity_class(c->name, class_lookup))
                entities.push_back(c);
            else
                non_entities.push_back(c);
        }

        if (!entities.empty() && !non_entities.empty()) {
            // Mixed module -- split into entities/ and structs/
            for (const auto* c : entities)
                state.class_subfolder[c->name] = "entities";
            for (const auto* c : non_entities)
                state.class_subfolder[c->name] = "structs";
        } else if (!entities.empty()) {
            // All entities -- put in entities/ for clarity
            for (const auto* c : entities)
                state.class_subfolder[c->name] = "entities";
        }
        // else: all structs or empty -- no subfolder (stay at module root)
    }

    // Load cherry-pick config
    {
        std::string cherry_path = exe_dir + "\\sdk-cherry-pick.json";
        FILE* f = fopen(cherry_path.c_str(), "rb");
        if (!f) {
            cherry_path = exe_dir + "\\bin\\sdk-cherry-pick.json";
            f = fopen(cherry_path.c_str(), "rb");
        }
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            std::string content(sz, '\0');
            fread(&content[0], 1, sz, f);
            fclose(f);
            try { state.cherry_pick = json::parse(content); }
            catch (...) {}
        }
    }

    // Create output directory
    create_dirs(output_dir);

    // Build VFunc naming map (single-threaded, read-only during generation)
    VFuncMap vfunc_map = build_vfunc_map(data, class_lookup);

    // Write schema_runtime.hpp
    write_file(output_dir + "\\schema_runtime.hpp", std::string(SCHEMA_RUNTIME_HPP));

    // Write types.hpp
    write_file(output_dir + "\\types.hpp", generate_types_hpp());

    // Process modules in parallel
    std::vector<ModuleResult> module_results(modules.size());
    std::vector<std::thread> threads;
    std::atomic<int> next_module{0};
    int num_threads = (int)modules.size() < (int)std::thread::hardware_concurrency()
        ? (int)modules.size() : (int)std::thread::hardware_concurrency();
    if (num_threads < 1) num_threads = 1;

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([&]() {
            while (true) {
                int idx = next_module.fetch_add(1);
                if (idx >= (int)modules.size()) break;
                module_results[idx] = process_module(modules[idx], state, output_dir, timestamp, &vfunc_map);
            }
        });
    }
    for (auto& t : threads) t.join();

    // Aggregate stats
    std::vector<std::string> module_names;
    for (size_t i = 0; i < modules.size(); i++) {
        const auto& r = module_results[i];
        stats.classes += r.classes;
        stats.enums += r.enums;
        stats.fields += r.fields;
        stats.helpers += r.helpers;
        stats.vfuncs += r.vfuncs;
        if (!modules[i].enums.empty()) {
            module_names.push_back(strip_dll(modules[i].name));
        }
    }
    stats.modules = (int)modules.size();

    // Write _all-enums.hpp
    if (!module_names.empty()) {
        write_file(output_dir + "\\_all-enums.hpp", generate_all_enums(module_names, timestamp));
    }

    return stats;
}
