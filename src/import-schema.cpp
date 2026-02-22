/**
 * dezlock-dump -- C++ port of import-schema.py (1481 lines)
 *
 * Generates cherry-pickable C++ SDK headers from dezlock-dump's JSON export.
 * All logic ported from the Python version with identical output.
 */

#include "src/import-schema.hpp"

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>
#include <optional>
#include <sstream>
#include <regex>
#include <cctype>
#include <functional>

using json = nlohmann::json;

// ============================================================================
// Type resolution tables
// ============================================================================

struct TypeEntry {
    std::string cpp_type; // empty string means emit as blob
    int size;
};

struct ContainerEntry {
    std::optional<int> size; // nullopt means use field's own size
};

// Rich types: schema type -> {cpp_type, size}
static const std::unordered_map<std::string, TypeEntry>& rich_types() {
    static const std::unordered_map<std::string, TypeEntry> tbl = {
        {"Vector",    {"Vec3",   12}},
        {"VectorWS",  {"Vec3",   12}},
        {"QAngle",    {"QAngle", 12}},
        {"Color",     {"Color",   4}},
        {"Vector2D",  {"Vec2",    8}},
        {"Vector4D",  {"Vec4",   16}},
    };
    return tbl;
}

// Primitive types: schema type -> {cpp_type, size}
static const std::unordered_map<std::string, TypeEntry>& primitive_map() {
    static const std::unordered_map<std::string, TypeEntry> tbl = {
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
    return tbl;
}

// Alias table: schema type -> {cpp_type (empty = blob), size}
// ALL ~180 entries from the Python source
static const std::unordered_map<std::string, TypeEntry>& alias_table() {
    static const std::unordered_map<std::string, TypeEntry> tbl = {
        // String / symbol types (opaque blobs)
        {"CUtlString",                  {"void*",    8}},
        {"CUtlSymbolLarge",             {"void*",    8}},
        {"CGlobalSymbol",               {"",         8}},
        {"CUtlStringToken",             {"uint32_t", 4}},
        {"CKV3MemberNameWithStorage",   {"",        24}},

        // Math types (non-rich -- raw array fallback)
        {"VectorAligned",               {"float[4]",  16}},
        {"Quaternion",                  {"float[4]",  16}},
        {"QuaternionStorage",           {"float[4]",  16}},
        {"RotationVector",              {"float[3]",  12}},
        {"matrix3x4_t",                 {"float[12]", 48}},
        {"matrix3x4a_t",                {"float[12]", 48}},
        {"CTransform",                  {"",          32}},

        // Game time / tick types
        {"GameTime_t",                  {"float",    4}},
        {"GameTick_t",                  {"int32_t",  4}},
        {"AnimationTimeFloat",          {"float",    4}},

        // Handle types
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

        // Resource / sound types (opaque blobs)
        {"CSoundEventName",             {"",        16}},
        {"CFootstepTableHandle",        {"",         8}},
        {"CBodyComponent",              {"",         8}},

        // Anim types
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

        // Physics
        {"CPhysicsComponent",           {"",         8}},
        {"CRenderComponent",            {"",         8}},

        // Commonly-seen opaque structs
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

        // Small integer-like types
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
    return tbl;
}

// Container sizes: outer template name -> fixed size (nullopt = use field's size)
static const std::unordered_map<std::string, ContainerEntry>& container_sizes() {
    static const std::unordered_map<std::string, ContainerEntry> tbl = {
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
    return tbl;
}

// ============================================================================
// Resolution statistics tracker (thread-safe)
// ============================================================================

struct ResolveStats {
    std::atomic<int> primitive{0};
    std::atomic<int> alias{0};
    std::atomic<int> rich_type{0};
    std::atomic<int> tmpl{0};      // "template" is a keyword
    std::atomic<int> embedded{0};
    std::atomic<int> handle{0};
    std::atomic<int> enum_type{0}; // "enum" is a keyword
    std::atomic<int> pointer{0};
    std::atomic<int> array{0};
    std::atomic<int> bitfield{0};
    std::atomic<int> unresolved{0};
    std::atomic<int> total{0};

    void record(const std::string& category) {
        total++;
        if (category == "primitive")       primitive++;
        else if (category == "alias")      alias++;
        else if (category == "rich_type")  rich_type++;
        else if (category == "template")   tmpl++;
        else if (category == "embedded")   embedded++;
        else if (category == "handle")     handle++;
        else if (category == "enum")       enum_type++;
        else if (category == "pointer")    pointer++;
        else if (category == "array")      array++;
        else if (category == "bitfield")   bitfield++;
        else if (category == "unresolved") unresolved++;
    }

    void print_summary() const {
        int t = total.load();
        int u = unresolved.load();
        int r = t - u;
        double pct = t > 0 ? (r * 100.0 / t) : 0.0;
        printf("\nType resolution: %d / %d (%.1f%%)\n", r, t, pct);

        auto print_cat = [](const char* name, int count, const char* suffix = "") {
            if (count > 0)
                printf("  %-14s%5d%s\n", name, count, suffix);
        };

        print_cat("primitive:", primitive.load());
        print_cat("alias:", alias.load());
        print_cat("rich_type:", rich_type.load());
        print_cat("template:", tmpl.load());
        print_cat("embedded:", embedded.load());
        print_cat("handle:", handle.load());
        print_cat("enum:", enum_type.load());
        print_cat("pointer:", pointer.load());
        print_cat("array:", array.load());
        print_cat("bitfield:", bitfield.load());
        print_cat("unresolved:", u, "  (blob fallback, sizes correct)");
    }
};

// ============================================================================
// Shared read-only state (set before generation, never mutated during)
// ============================================================================

struct SharedState {
    std::unordered_map<std::string, int> all_enums;               // enum name -> size
    std::unordered_set<std::string> all_classes;                   // set of all class names
    std::unordered_map<std::string, std::string> class_to_module;  // class -> module (no .dll)
    std::unordered_map<std::string, std::string> class_subfolder;  // class -> "entities"/"structs"/""
    json cherry_pick;                                               // from sdk-cherry-pick.json

    // Class lookup provided by caller
    const std::unordered_map<std::string, const ClassInfo*>* class_lookup = nullptr;
};

// ============================================================================
// Helper: enum size to int type
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

// ============================================================================
// Helper: hex formatting
// ============================================================================

static std::string hex_upper(int val) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%X", val);
    return buf;
}

static std::string hex04(int val) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%04X", val);
    return buf;
}

// ============================================================================
// Helper: create directories recursively
// ============================================================================

static void create_dirs(const std::string& path) {
    for (size_t i = 0; i < path.size(); i++) {
        if (path[i] == '\\' || path[i] == '/') {
            CreateDirectoryA(path.substr(0, i).c_str(), nullptr);
        }
    }
    CreateDirectoryA(path.c_str(), nullptr);
}

// ============================================================================
// Helper: write string to file
// ============================================================================

static bool write_file(const std::string& path, const std::string& content) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    fwrite(content.data(), 1, content.size(), f);
    fclose(f);
    return true;
}

// ============================================================================
// Helper: strip .dll from module name
// ============================================================================

static std::string strip_dll(const std::string& name) {
    if (name.size() > 4 && name.substr(name.size() - 4) == ".dll") {
        return name.substr(0, name.size() - 4);
    }
    return name;
}

// ============================================================================
// schema_to_cpp_type -- Core type resolution
// ============================================================================

// Returns {cpp_type, category}. Empty cpp_type means emit as sized blob.
static std::pair<std::string, std::string> schema_to_cpp_type(
    const std::string& schema_type,
    int field_size,
    const SharedState& state)
{
    // 1. Rich types (Vector -> Vec3, QAngle -> QAngle, etc.)
    {
        auto it = rich_types().find(schema_type);
        if (it != rich_types().end()) {
            return {it->second.cpp_type, "rich_type"};
        }
    }

    // 2. Primitives
    {
        auto it = primitive_map().find(schema_type);
        if (it != primitive_map().end()) {
            return {it->second.cpp_type, "primitive"};
        }
    }

    // 3. Alias table
    {
        auto it = alias_table().find(schema_type);
        if (it != alias_table().end()) {
            return {it->second.cpp_type, "alias"};
        }
    }

    // 4. CHandle<T> / CEntityHandle (always CHandle)
    if (schema_type.substr(0, 8) == "CHandle<" ||
        schema_type.substr(0, 13) == "CEntityHandle") {
        return {"CHandle", "handle"};
    }

    // 5. Pointers
    if (!schema_type.empty() && schema_type.back() == '*') {
        return {"void*", "pointer"};
    }

    // 6. Bitfields (type like "bitfield:3")
    if (schema_type.substr(0, 9) == "bitfield:") {
        return {"", "bitfield"};
    }

    // 7. char[N] arrays
    {
        static const std::regex rx_char(R"(char\[(\d+)\])");
        std::smatch m;
        if (std::regex_match(schema_type, m, rx_char)) {
            return {"char[" + m[1].str() + "]", "array"};
        }
    }

    // 8. Fixed-size arrays of known types: BaseType[Count]
    {
        static const std::regex rx_array(R"(([\w:]+)\[(\d+)\])");
        std::smatch m;
        if (std::regex_match(schema_type, m, rx_array)) {
            std::string base_type = m[1].str();
            std::string count = m[2].str();

            // Rich type arrays
            auto rit = rich_types().find(base_type);
            if (rit != rich_types().end()) {
                return {rit->second.cpp_type + "[" + count + "]", "array"};
            }

            auto pit = primitive_map().find(base_type);
            if (pit != primitive_map().end()) {
                return {pit->second.cpp_type + "[" + count + "]", "array"};
            }

            auto ait = alias_table().find(base_type);
            if (ait != alias_table().end()) {
                const std::string& alias_cpp = ait->second.cpp_type;
                if (!alias_cpp.empty()) {
                    size_t bracket = alias_cpp.find('[');
                    if (bracket == std::string::npos) {
                        return {alias_cpp + "[" + count + "]", "array"};
                    }
                    // Already has brackets (e.g. float[4]) -- can't nest
                    return {"", "array"};
                }
                // Blob alias
                return {"", "array"};
            }

            if (base_type.substr(0, 7) == "CHandle") {
                return {"CHandle[" + count + "]", "array"};
            }

            auto eit = state.all_enums.find(base_type);
            if (eit != state.all_enums.end()) {
                return {std::string(enum_int_type(eit->second)) + "[" + count + "]", "array"};
            }

            // Unknown base type in array
            return {"", "array"};
        }
    }

    // 9. Template containers
    {
        size_t lt = schema_type.find('<');
        if (lt != std::string::npos) {
            std::string outer = schema_type.substr(0, lt);

            // CNetworkUtlVectorBase<CHandle<T>> -> CHandleVector
            if (outer == "CNetworkUtlVectorBase" || outer == "C_NetworkUtlVectorBase") {
                std::string inner;
                if (schema_type.back() == '>') {
                    inner = schema_type.substr(lt + 1, schema_type.size() - lt - 2);
                }
                if (inner.substr(0, 8) == "CHandle<") {
                    return {"CHandleVector", "template"};
                }
            }

            if (container_sizes().count(outer)) {
                return {"", "template"};
            }

            if (outer == "CHandle") {
                return {"CHandle", "handle"};
            }
        }
    }

    // 10. Enum-typed fields
    {
        auto it = state.all_enums.find(schema_type);
        if (it != state.all_enums.end()) {
            return {enum_int_type(it->second), "enum"};
        }
    }

    // 11. Embedded schema classes (blob)
    if (state.all_classes.count(schema_type)) {
        return {"", "embedded"};
    }

    // 12. Unresolved -- fallback to blob
    return {"", "unresolved"};
}

// ============================================================================
// make_guard / safe_class_name / sanitize_cpp_identifier
// ============================================================================

static std::string make_guard(const std::string& name) {
    std::string guard = "SDK_GEN_";
    for (char c : name) {
        if (std::isalnum(static_cast<unsigned char>(c))) {
            guard += (char)std::toupper(static_cast<unsigned char>(c));
        } else {
            guard += '_';
        }
    }
    guard += "_HPP";
    return guard;
}

static std::string safe_class_name(const std::string& name) {
    std::string result = name;
    // Replace :: with __
    size_t pos = 0;
    while ((pos = result.find("::", pos)) != std::string::npos) {
        result.replace(pos, 2, "__");
        pos += 2;
    }
    return result;
}

static std::string sanitize_cpp_identifier(const std::string& name) {
    if (name.size() >= 2 && name[0] == '?' && name[1] == '$') return "";
    if (!name.empty() && name[0] == '?') return "";

    std::string s = name;
    // Replace special characters
    auto replace_all = [&](const std::string& from, const std::string& to) {
        size_t pos = 0;
        while ((pos = s.find(from, pos)) != std::string::npos) {
            s.replace(pos, from.size(), to);
            pos += to.size();
        }
    };
    replace_all("::", "__");
    replace_all("<", "_");
    replace_all(">", "_");
    replace_all(",", "_");
    replace_all(" ", "_");
    replace_all("&", "_");
    replace_all("*", "_");

    // Replace any remaining non-alnum/non-underscore
    for (char& c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
            c = '_';
        }
    }

    // Collapse multiple underscores
    std::string collapsed;
    bool prev_under = false;
    for (char c : s) {
        if (c == '_') {
            if (!prev_under) collapsed += c;
            prev_under = true;
        } else {
            collapsed += c;
            prev_under = false;
        }
    }

    // Strip leading/trailing underscores
    size_t start = 0, end = collapsed.size();
    while (start < end && collapsed[start] == '_') start++;
    while (end > start && collapsed[end - 1] == '_') end--;
    s = collapsed.substr(start, end - start);

    if (s.empty()) return "";

    // Ensure starts with alpha or underscore
    if (!std::isalpha(static_cast<unsigned char>(s[0])) && s[0] != '_') {
        s = "_" + s;
    }

    return s;
}

// ============================================================================
// is_entity_class
// ============================================================================

static bool is_entity_class(const std::string& cls_name,
                             const std::unordered_map<std::string, const ClassInfo*>& lookup);

// Forward-declare ClassInfo members we need
// (these are defined in main.cpp, we access them via the pointer)
// struct ClassInfo has: name, size, parent, fields, metadata, etc.

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

// ============================================================================
// needs_types_include
// ============================================================================

static bool needs_types_include(const std::vector<Field>& fields) {
    for (const auto& f : fields) {
        const std::string& st = f.type;

        if (rich_types().count(st)) return true;

        // Check array of rich types
        static const std::regex rx_arr(R"(([\w:]+)\[(\d+)\])");
        std::smatch m;
        if (std::regex_match(st, m, rx_arr)) {
            if (rich_types().count(m[1].str())) return true;
        }

        // CHandle fields
        if (st.substr(0, 8) == "CHandle<" || st.substr(0, 13) == "CEntityHandle") {
            return true;
        }

        // CHandleVector
        size_t lt = st.find('<');
        if (lt != std::string::npos) {
            std::string outer = st.substr(0, lt);
            if (outer == "CNetworkUtlVectorBase" || outer == "C_NetworkUtlVectorBase") {
                std::string inner;
                if (st.back() == '>') {
                    inner = st.substr(lt + 1, st.size() - lt - 2);
                }
                if (inner.substr(0, 8) == "CHandle<") return true;
            }
        }
    }
    return false;
}

// ============================================================================
// get_class_subfolder / compute_types_include / compute_include_path
// ============================================================================

static std::string get_class_subfolder(const std::string& cls_name,
                                        const SharedState& state) {
    auto it = state.class_subfolder.find(cls_name);
    return (it != state.class_subfolder.end()) ? it->second : "";
}

static std::string compute_types_include(const std::string& cls_name,
                                          const SharedState& state) {
    std::string sub = get_class_subfolder(cls_name, state);
    if (!sub.empty()) {
        return "\"../../types.hpp\"";
    }
    return "\"../types.hpp\"";
}

static std::string compute_include_path(const std::string& from_class,
                                         const std::string& to_class,
                                         const SharedState& state) {
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

    // Different module
    std::string prefix;
    if (!from_sub.empty()) {
        prefix = "\"../../" + to_module;
    } else {
        prefix = "\"../" + to_module;
    }

    if (!to_sub.empty()) {
        return prefix + "/" + to_sub + "/" + to_safe + ".hpp\"";
    } else {
        return prefix + "/" + to_safe + ".hpp\"";
    }
}

// ============================================================================
// generate_types_hpp
// ============================================================================

static std::string generate_types_hpp(const std::string& timestamp) {
    std::string s;
    s += "// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT\n";
    s += "// Base SDK types matching v2 hand-written quality\n";
    s += "// Generated: " + timestamp + "\n";
    s += "#pragma once\n";
    s += "\n";
    s += "#include <cstdint>\n";
    s += "#include <cstddef>\n";
    s += "\n";
    s += "namespace sdk {\n";
    s += "\n";
    s += "// ---- Math types ----\n";
    s += "\n";
    s += "struct Vec2 {\n";
    s += "    float x, y;\n";
    s += "\n";
    s += "    Vec2() : x(0), y(0) {}\n";
    s += "    Vec2(float x, float y) : x(x), y(y) {}\n";
    s += "\n";
    s += "    Vec2 operator+(const Vec2& o) const { return {x + o.x, y + o.y}; }\n";
    s += "    Vec2 operator-(const Vec2& o) const { return {x - o.x, y - o.y}; }\n";
    s += "    Vec2 operator*(float s) const { return {x * s, y * s}; }\n";
    s += "};\n";
    s += "\n";
    s += "struct Vec3 {\n";
    s += "    float x, y, z;\n";
    s += "\n";
    s += "    Vec3() : x(0), y(0), z(0) {}\n";
    s += "    Vec3(float x, float y, float z) : x(x), y(y), z(z) {}\n";
    s += "\n";
    s += "    Vec3 operator+(const Vec3& o) const { return {x + o.x, y + o.y, z + o.z}; }\n";
    s += "    Vec3 operator-(const Vec3& o) const { return {x - o.x, y - o.y, z - o.z}; }\n";
    s += "    Vec3 operator*(float s) const { return {x * s, y * s, z * s}; }\n";
    s += "\n";
    s += "    float length_sqr() const { return x * x + y * y + z * z; }\n";
    s += "    float length_2d_sqr() const { return x * x + y * y; }\n";
    s += "};\n";
    s += "\n";
    s += "struct Vec4 {\n";
    s += "    float x, y, z, w;\n";
    s += "};\n";
    s += "\n";
    s += "struct QAngle {\n";
    s += "    float pitch, yaw, roll;\n";
    s += "\n";
    s += "    QAngle() : pitch(0), yaw(0), roll(0) {}\n";
    s += "    QAngle(float p, float y, float r) : pitch(p), yaw(y), roll(r) {}\n";
    s += "};\n";
    s += "\n";
    s += "// ---- Color ----\n";
    s += "\n";
    s += "struct Color {\n";
    s += "    uint8_t r, g, b, a;\n";
    s += "};\n";
    s += "\n";
    s += "// ---- Handles ----\n";
    s += "\n";
    s += "struct CHandle {\n";
    s += "    uint32_t value;\n";
    s += "\n";
    s += "    bool is_valid() const { return value != 0xFFFFFFFF; }\n";
    s += "    uint32_t index() const { return value & 0x7FFF; }\n";
    s += "    uint32_t serial() const { return value >> 15; }\n";
    s += "};\n";
    s += "\n";
    s += "// CNetworkUtlVectorBase<CHandle<T>> — vector of entity handles\n";
    s += "struct CHandleVector {\n";
    s += "    uint8_t _data[24]; // CNetworkUtlVectorBase internal layout\n";
    s += "\n";
    s += "    // Access as raw CHandle array (count at offset 0x0, data ptr at 0x8)\n";
    s += "    int32_t count() const { return *reinterpret_cast<const int32_t*>(_data); }\n";
    s += "    const CHandle* data() const { return *reinterpret_cast<const CHandle* const*>(_data + 8); }\n";
    s += "};\n";
    s += "\n";
    s += "// ---- View matrix ----\n";
    s += "\n";
    s += "struct ViewMatrix {\n";
    s += "    float m[4][4];\n";
    s += "};\n";
    s += "\n";
    s += "// ---- Static asserts ----\n";
    s += "static_assert(sizeof(Vec2) == 8);\n";
    s += "static_assert(sizeof(Vec3) == 12);\n";
    s += "static_assert(sizeof(Vec4) == 16);\n";
    s += "static_assert(sizeof(QAngle) == 12);\n";
    s += "static_assert(sizeof(Color) == 4);\n";
    s += "static_assert(sizeof(CHandle) == 4);\n";
    s += "static_assert(sizeof(CHandleVector) == 24);\n";
    s += "static_assert(sizeof(ViewMatrix) == 64);\n";
    s += "\n";
    s += "} // namespace sdk\n";
    return s;
}

// ============================================================================
// emit_field -- Emit a single field with padding, returns new cursor
// ============================================================================

static int emit_field(const Field& f, int cursor, std::vector<std::string>& lines,
                       const SharedState& state, ResolveStats& stats) {
    int offset = f.offset;
    int size = f.size;
    const std::string& name = f.name;
    const std::string& schema_type = f.type;

    // Padding gap
    if (offset > cursor) {
        int gap = offset - cursor;
        char buf[128];
        snprintf(buf, sizeof(buf), "    uint8_t _pad%s[0x%s];",
                 hex04(cursor).c_str(), hex_upper(gap).c_str());
        lines.push_back(buf);
    }

    auto [cpp_type, category] = schema_to_cpp_type(schema_type, size, state);
    stats.record(category);

    // Build metadata string
    std::string meta_str;
    for (const auto& m : f.metadata) {
        if (!meta_str.empty()) meta_str += " ";
        meta_str += "[" + m + "]";
    }

    // Build comment
    char comment_buf[512];
    if (!meta_str.empty()) {
        snprintf(comment_buf, sizeof(comment_buf), "// 0x%s (%s, %d) %s",
                 hex_upper(offset).c_str(), schema_type.c_str(), size, meta_str.c_str());
    } else {
        snprintf(comment_buf, sizeof(comment_buf), "// 0x%s (%s, %d)",
                 hex_upper(offset).c_str(), schema_type.c_str(), size);
    }

    // Bitfields (size=0): emit as comment only
    if (category == "bitfield") {
        std::string bits = "?";
        if (schema_type.size() > 9) {
            bits = schema_type.substr(9);
        }
        lines.push_back("    // bitfield " + name + " : " + bits + "; " + comment_buf);
        return cursor;
    }

    if (!cpp_type.empty()) {
        size_t bracket = cpp_type.find('[');
        if (bracket != std::string::npos) {
            std::string base = cpp_type.substr(0, bracket);
            std::string arr = cpp_type.substr(bracket);
            lines.push_back("    " + base + " " + name + arr + "; " + comment_buf);
        } else {
            lines.push_back("    " + cpp_type + " " + name + "; " + comment_buf);
        }
    } else if (size > 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "    uint8_t %s[0x%s]; %s",
                 name.c_str(), hex_upper(size).c_str(), comment_buf);
        lines.push_back(buf);
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf), "    // 0x%s %s (%s) — zero size",
                 hex_upper(offset).c_str(), name.c_str(), schema_type.c_str());
        lines.push_back(buf);
        return cursor;
    }

    return (size > 0) ? (offset + size) : offset;
}

// ============================================================================
// generate_struct_header -- Per-class .hpp
// ============================================================================

static std::string generate_struct_header(const ClassInfo& cls,
                                           const std::string& module_name,
                                           const SharedState& state,
                                           const std::string& timestamp,
                                           ResolveStats& stats) {
    const std::string& name = cls.name;
    int size = cls.size;
    const std::string& parent = cls.parent;

    // Sort fields by offset
    std::vector<Field> fields = cls.fields;
    std::sort(fields.begin(), fields.end(),
              [](const Field& a, const Field& b) { return a.offset < b.offset; });

    bool has_parent = !parent.empty() && state.class_lookup->count(parent);
    int parent_size = 0;
    if (has_parent) {
        parent_size = state.class_lookup->at(parent)->size;
    }

    std::string guard = make_guard(name);

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by import-schema.py from dezlock-dump \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Class: " + name);
    lines.push_back("// Module: " + module_name);

    {
        char buf[128];
        snprintf(buf, sizeof(buf), "// Size: 0x%s (%d bytes)", hex_upper(size).c_str(), size);
        lines.push_back(buf);
    }

    if (!parent.empty()) {
        lines.push_back("// Parent: " + parent);
    }

    lines.push_back("// Generated: " + timestamp);
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    lines.push_back("#include <cstdint>");
    lines.push_back("#include <cstddef>");

    // Include types.hpp if any field uses rich types
    bool use_types = needs_types_include(fields);
    if (use_types) {
        lines.push_back("#include " + compute_types_include(name, state));
    }

    if (has_parent) {
        lines.push_back("#include " + compute_include_path(name, parent, state));
    }

    lines.push_back("");
    lines.push_back("namespace sdk {");
    lines.push_back("");

    // Struct definition
    lines.push_back("#pragma pack(push, 1)");
    if (has_parent) {
        lines.push_back("struct " + name + " : " + parent + " {");
    } else {
        lines.push_back("struct " + name + " {");
    }

    int cursor = has_parent ? parent_size : 0;
    std::vector<const Field*> emitted_fields;

    for (const auto& f : fields) {
        if (f.offset < cursor) continue; // skip inherited fields
        cursor = emit_field(f, cursor, lines, state, stats);
        emitted_fields.push_back(&f);
    }

    // Cherry-pick helper methods
    if (state.cherry_pick.contains("helpers") &&
        state.cherry_pick["helpers"].contains(name)) {
        const auto& helpers = state.cherry_pick["helpers"][name];
        if (helpers.contains("methods") && helpers["methods"].is_array()) {
            lines.push_back("");
            lines.push_back("    // --- Helper methods (from sdk-cherry-pick.json) ---");
            for (const auto& method : helpers["methods"]) {
                lines.push_back("    " + method.get<std::string>());
            }
        }
    }

    // Pad to class size
    if (cursor < size) {
        char buf[128];
        snprintf(buf, sizeof(buf), "    uint8_t _padEnd[0x%s];", hex_upper(size - cursor).c_str());
        lines.push_back(buf);
    }

    lines.push_back("};");
    lines.push_back("#pragma pack(pop)");
    lines.push_back("");

    // static_asserts
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "static_assert(sizeof(%s) == 0x%s, \"%s size\");",
                 name.c_str(), hex_upper(size).c_str(), name.c_str());
        lines.push_back(buf);
    }

    for (const auto* f : emitted_fields) {
        if (f->type.substr(0, 9) == "bitfield:" || f->size == 0) continue;
        char buf[256];
        snprintf(buf, sizeof(buf), "static_assert(offsetof(%s, %s) == 0x%s, \"%s\");",
                 name.c_str(), f->name.c_str(), hex_upper(f->offset).c_str(), f->name.c_str());
        lines.push_back(buf);
    }

    lines.push_back("");
    lines.push_back("} // namespace sdk");
    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    // Join all lines
    std::string result;
    for (size_t i = 0; i < lines.size(); i++) {
        result += lines[i];
        result += '\n';
    }
    return result;
}

// ============================================================================
// generate_module_offsets
// ============================================================================

static std::string generate_module_offsets(const std::vector<const ClassInfo*>& classes,
                                            const std::string& module_name,
                                            const std::string& game,
                                            const std::string& timestamp) {
    std::string mod_clean = strip_dll(module_name);
    std::string guard = make_guard(game + "_" + mod_clean + "_offsets");

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by import-schema.py from dezlock-dump \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Offset constants for module: " + module_name);
    lines.push_back("// Generated: " + timestamp);
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    lines.push_back("#include <cstdint>");
    lines.push_back("");
    lines.push_back("namespace sdk::offsets::" + mod_clean + " {");
    lines.push_back("");

    int total_fields = 0;

    // Sort classes by name
    std::vector<const ClassInfo*> sorted_classes = classes;
    std::sort(sorted_classes.begin(), sorted_classes.end(),
              [](const ClassInfo* a, const ClassInfo* b) { return a->name < b->name; });

    for (const auto* cls : sorted_classes) {
        if (cls->fields.empty()) continue;

        lines.push_back("namespace " + cls->name + " {");

        // Sort fields by offset
        std::vector<const Field*> sorted_fields;
        for (const auto& f : cls->fields) sorted_fields.push_back(&f);
        std::sort(sorted_fields.begin(), sorted_fields.end(),
                  [](const Field* a, const Field* b) { return a->offset < b->offset; });

        for (const auto* f : sorted_fields) {
            total_fields++;
            char buf[256];
            snprintf(buf, sizeof(buf), "    constexpr uint32_t %s = 0x%s; // %s (%db)",
                     f->name.c_str(), hex_upper(f->offset).c_str(),
                     f->type.c_str(), f->size);
            lines.push_back(buf);
        }

        lines.push_back("} // " + cls->name);
        lines.push_back("");
    }

    lines.push_back("} // namespace sdk::offsets::" + mod_clean);
    lines.push_back("");

    {
        char buf[128];
        snprintf(buf, sizeof(buf), "// Total: %d fields", total_fields);
        lines.push_back(buf);
    }

    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return result;
}

// ============================================================================
// generate_module_enums
// ============================================================================

static std::string generate_module_enums(const std::vector<EnumInfo>& enums,
                                          const std::string& module_name,
                                          const std::string& game,
                                          const std::string& timestamp) {
    std::string mod_clean = strip_dll(module_name);
    std::string guard = make_guard(game + "_" + mod_clean + "_enums");

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by import-schema.py from dezlock-dump \xe2\x80\x94 DO NOT EDIT");
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

    // Sort enums by name
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

    {
        char buf[128];
        snprintf(buf, sizeof(buf), "// Total: %d enums", (int)enums.size());
        lines.push_back(buf);
    }

    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return result;
}

// ============================================================================
// generate_all_offsets / generate_all_enums
// ============================================================================

static std::string generate_all_offsets(const std::vector<std::string>& module_names,
                                         const std::string& game,
                                         const std::string& timestamp) {
    std::string guard = make_guard(game + "_all_offsets");
    std::vector<std::string> sorted_names = module_names;
    std::sort(sorted_names.begin(), sorted_names.end());

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by import-schema.py from dezlock-dump \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Master include for all offset constants");
    lines.push_back("// Generated: " + timestamp);
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    for (const auto& mod : sorted_names) {
        lines.push_back("#include \"" + mod + "/_offsets.hpp\"");
    }
    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return result;
}

static std::string generate_all_enums(const std::vector<std::string>& module_names,
                                       const std::string& game,
                                       const std::string& timestamp) {
    std::string guard = make_guard(game + "_all_enums");
    std::vector<std::string> sorted_names = module_names;
    std::sort(sorted_names.begin(), sorted_names.end());

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by import-schema.py from dezlock-dump \xe2\x80\x94 DO NOT EDIT");
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
// generate_all_vtables
// ============================================================================

static std::string generate_all_vtables(const json& data,
                                          const std::string& game,
                                          const std::string& timestamp) {
    std::string guard = make_guard(game + "_all_vtables");

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by import-schema.py from dezlock-dump \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// All vtable RVAs and virtual function indices from RTTI scan");
    lines.push_back("// Generated: " + timestamp);
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    lines.push_back("#include <cstdint>");
    lines.push_back("");
    lines.push_back("namespace sdk::vtables {");
    lines.push_back("");

    int total_classes = 0;
    int total_funcs = 0;
    int skipped = 0;

    if (data.contains("modules") && data["modules"].is_array()) {
        for (const auto& mod : data["modules"]) {
            if (!mod.contains("vtables") || !mod["vtables"].is_array()) continue;

            // Sort vtables by class name
            std::vector<const json*> sorted_vts;
            for (const auto& vt : mod["vtables"]) {
                sorted_vts.push_back(&vt);
            }
            std::sort(sorted_vts.begin(), sorted_vts.end(),
                      [](const json* a, const json* b) {
                          return a->value("class", "") < b->value("class", "");
                      });

            for (const auto* vtp : sorted_vts) {
                const auto& vt = *vtp;
                std::string class_name = vt.value("class", "");
                std::string vtable_rva = vt.contains("vtable_rva")
                    ? (vt["vtable_rva"].is_string()
                        ? vt["vtable_rva"].get<std::string>()
                        : std::to_string(vt["vtable_rva"].get<uint64_t>()))
                    : "0";

                if (!vt.contains("functions") || !vt["functions"].is_array() ||
                    vt["functions"].empty()) continue;

                std::string safe_name = sanitize_cpp_identifier(class_name);
                if (safe_name.empty()) {
                    skipped++;
                    continue;
                }

                total_classes++;
                std::string comment = (safe_name != class_name)
                    ? " // " + class_name : "";

                lines.push_back("namespace " + safe_name + " {" + comment);
                lines.push_back("    constexpr uint32_t vtable_rva = " + vtable_rva + ";");

                {
                    char buf[128];
                    snprintf(buf, sizeof(buf), "    constexpr int entry_count = %d;",
                             (int)vt["functions"].size());
                    lines.push_back(buf);
                }

                lines.push_back("    namespace fn {");

                for (const auto& func : vt["functions"]) {
                    int idx = func.value("index", 0);
                    std::string rva = func.contains("rva")
                        ? (func["rva"].is_string()
                            ? func["rva"].get<std::string>()
                            : std::to_string(func["rva"].get<uint64_t>()))
                        : "0";
                    total_funcs++;
                    char buf[128];
                    snprintf(buf, sizeof(buf), "        constexpr int idx_%d = %d; // rva=%s",
                             idx, idx, rva.c_str());
                    lines.push_back(buf);
                }

                lines.push_back("    }");
                lines.push_back("} // " + safe_name);
                lines.push_back("");
            }
        }
    }

    lines.push_back("} // namespace sdk::vtables");
    lines.push_back("");

    {
        char buf[128];
        snprintf(buf, sizeof(buf), "// Total: %d vtables, %d virtual functions",
                 total_classes, total_funcs);
        lines.push_back(buf);
    }

    if (skipped > 0) {
        char buf[128];
        snprintf(buf, sizeof(buf),
                 "// Skipped: %d classes with unrepresentable names (templates, mangled)",
                 skipped);
        lines.push_back(buf);
    }

    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return result;
}

// ============================================================================
// generate_globals_hpp
// ============================================================================

struct GlobalsResult {
    std::string content;
    int count;
};

static GlobalsResult generate_globals_hpp(const json& pattern_globals,
                                            const std::string& game,
                                            const std::string& timestamp) {
    std::string guard = make_guard(game + "_globals");

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by import-schema.py from dezlock-dump \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Pattern-scanned global pointer offsets (from patterns.json)");
    lines.push_back("// Generated: " + timestamp);
    lines.push_back("//");
    lines.push_back("// These are RVA offsets from the module base address.");
    lines.push_back("// Usage: uintptr_t entity_list = module_base + globals::client::dwEntityList;");
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    lines.push_back("#include <cstdint>");
    lines.push_back("");
    lines.push_back("namespace globals {");

    int total = 0;

    // Sort module names
    std::vector<std::string> mod_keys;
    for (auto it = pattern_globals.begin(); it != pattern_globals.end(); ++it) {
        mod_keys.push_back(it.key());
    }
    std::sort(mod_keys.begin(), mod_keys.end());

    for (const auto& mod_name : mod_keys) {
        const auto& entries = pattern_globals[mod_name];
        if (!entries.is_object() || entries.empty()) continue;

        std::string ns = strip_dll(mod_name);
        // Replace dots with underscores
        for (char& c : ns) { if (c == '.') c = '_'; }

        lines.push_back("");
        lines.push_back("namespace " + ns + " {");

        // Sort entry names
        std::vector<std::string> entry_keys;
        for (auto it = entries.begin(); it != entries.end(); ++it) {
            entry_keys.push_back(it.key());
        }
        std::sort(entry_keys.begin(), entry_keys.end());

        for (const auto& name : entry_keys) {
            const auto& entry = entries[name];
            std::string rva;
            if (entry.is_object()) {
                rva = entry.value("rva", "0x0");
            } else if (entry.is_string()) {
                rva = entry.get<std::string>();
            } else {
                rva = "0x0";
            }
            lines.push_back("    constexpr uint64_t " + name + " = " + rva + ";");
            total++;
        }

        lines.push_back("} // namespace " + ns);
    }

    lines.push_back("");
    lines.push_back("} // namespace globals");
    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return {result, total};
}

// ============================================================================
// generate_patterns_hpp
// ============================================================================

static GlobalsResult generate_patterns_hpp(const json& pattern_globals,
                                             const std::string& game,
                                             const std::string& timestamp) {
    std::string guard = make_guard(game + "_patterns");

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated by import-schema.py from dezlock-dump \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Runtime-scannable patterns for global pointers (from patterns.json)");
    lines.push_back("// Generated: " + timestamp);
    lines.push_back("//");
    lines.push_back("// These patterns can be used with any IDA-style pattern scanner to resolve");
    lines.push_back("// global pointers at runtime \xe2\x80\x94 no hardcoded offsets needed.");
    lines.push_back("//");
    lines.push_back("// RipRelative: sig points to a MOV/LEA with RIP-relative displacement.");
    lines.push_back("//   addr = (match + rip_offset + 4) + *(int32_t*)(match + rip_offset)");
    lines.push_back("//");
    lines.push_back("// Derived: resolve the base pattern first, then scan for chain_pattern");
    lines.push_back("//   in the resolved function to extract a uint32 field offset.");
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    lines.push_back("namespace patterns {");

    int total = 0;

    std::vector<std::string> mod_keys;
    for (auto it = pattern_globals.begin(); it != pattern_globals.end(); ++it) {
        mod_keys.push_back(it.key());
    }
    std::sort(mod_keys.begin(), mod_keys.end());

    for (const auto& mod_name : mod_keys) {
        const auto& entries = pattern_globals[mod_name];
        if (!entries.is_object() || entries.empty()) continue;

        std::string ns = strip_dll(mod_name);
        for (char& c : ns) { if (c == '.') c = '_'; }

        lines.push_back("");
        lines.push_back("namespace " + ns + " {");

        std::vector<std::string> entry_keys;
        for (auto it = entries.begin(); it != entries.end(); ++it) {
            entry_keys.push_back(it.key());
        }
        std::sort(entry_keys.begin(), entry_keys.end());

        for (const auto& name : entry_keys) {
            const auto& entry = entries[name];
            if (!entry.is_object()) continue;

            std::string mode = entry.value("mode", "rip_relative");

            if (mode == "derived") {
                std::string derived_from = entry.value("derived_from", "");
                std::string chain_pattern = entry.value("chain_pattern", "");
                int chain_offset = entry.value("chain_extract_offset", 0);

                lines.push_back("");
                lines.push_back("namespace " + name + " { // derived from " + derived_from);
                lines.push_back("    constexpr const char* derived_from = \"" + derived_from + "\";");
                lines.push_back("    constexpr const char* chain_pattern = \"" + chain_pattern + "\";");

                char buf[128];
                snprintf(buf, sizeof(buf), "    constexpr int chain_extract_offset = %d;", chain_offset);
                lines.push_back(buf);

                lines.push_back("} // namespace " + name);
                total++;
            } else if (entry.contains("pattern")) {
                std::string sig = entry.value("pattern", "");
                int rip_offset = entry.value("rip_offset", 0);

                lines.push_back("");
                lines.push_back("namespace " + name + " {");
                lines.push_back("    constexpr const char* sig = \"" + sig + "\";");

                char buf[128];
                snprintf(buf, sizeof(buf), "    constexpr int rip_offset = %d;", rip_offset);
                lines.push_back(buf);

                lines.push_back("} // namespace " + name);
                total++;
            }
        }

        lines.push_back("");
        lines.push_back("} // namespace " + ns);
    }

    lines.push_back("");
    lines.push_back("} // namespace patterns");
    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return {result, total};
}

// ============================================================================
// Per-module processing worker
// ============================================================================

struct ModuleResult {
    std::string mod_name;
    int struct_count;
    int entity_count;
    int non_entity_count;
    int enum_count;
    bool valid;
};

static ModuleResult process_sdk_module(const ModuleData& mod,
                                        const std::string& game,
                                        const SharedState& state,
                                        const std::string& out_dir,
                                        const std::string& timestamp,
                                        ResolveStats& stats) {
    ModuleResult result = {};
    result.valid = false;

    std::string mod_name = strip_dll(mod.name);

    // Filter useful classes
    std::vector<const ClassInfo*> useful_classes;
    for (const auto& cls : mod.classes) {
        if (cls.size > 0 && !cls.fields.empty()) {
            useful_classes.push_back(&cls);
        }
    }

    bool has_content = !useful_classes.empty() || !mod.enums.empty();
    if (!has_content) return result;

    // Create module directory
    std::string mod_dir = out_dir + "\\" + mod_name;
    create_dirs(mod_dir);

    // Create subdirectories
    std::unordered_set<std::string> subfolders_used;
    for (const auto* cls : useful_classes) {
        std::string sub = get_class_subfolder(cls->name, state);
        if (!sub.empty()) subfolders_used.insert(sub);
    }
    for (const auto& sub : subfolders_used) {
        create_dirs(mod_dir + "\\" + sub);
    }

    // Generate _offsets.hpp
    if (!useful_classes.empty()) {
        std::string offsets_content = generate_module_offsets(useful_classes, mod.name, game, timestamp);
        write_file(mod_dir + "\\_offsets.hpp", offsets_content);
    }

    // Generate _enums.hpp
    if (!mod.enums.empty()) {
        std::string enums_content = generate_module_enums(mod.enums, mod.name, game, timestamp);
        write_file(mod_dir + "\\_enums.hpp", enums_content);
    }

    // Sort classes by name and generate per-class headers
    std::vector<const ClassInfo*> sorted_classes = useful_classes;
    std::sort(sorted_classes.begin(), sorted_classes.end(),
              [](const ClassInfo* a, const ClassInfo* b) { return a->name < b->name; });

    int mod_count = 0;
    int entity_count = 0;
    int struct_count = 0;

    for (const auto* cls : sorted_classes) {
        std::string header = generate_struct_header(*cls, mod.name, state, timestamp, stats);
        std::string safe_name = safe_class_name(cls->name);
        std::string sub = get_class_subfolder(cls->name, state);

        std::string filepath;
        if (!sub.empty()) {
            filepath = mod_dir + "\\" + sub + "\\" + safe_name + ".hpp";
            if (sub == "entities") {
                entity_count++;
            } else {
                struct_count++;
            }
        } else {
            filepath = mod_dir + "\\" + safe_name + ".hpp";
            struct_count++;
        }

        write_file(filepath, header);
        mod_count++;
    }

    // Print progress
    std::string parts;
    if (entity_count > 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%d entities", entity_count);
        parts += buf;
    }
    if (struct_count > 0) {
        if (!parts.empty()) parts += ", ";
        char buf[64];
        snprintf(buf, sizeof(buf), "%d structs", struct_count);
        parts += buf;
    }
    if (!mod.enums.empty()) {
        if (!parts.empty()) parts += ", ";
        char buf[64];
        snprintf(buf, sizeof(buf), "%d enums", (int)mod.enums.size());
        parts += buf;
    }
    printf("  %-30s  %s\n", mod.name.c_str(), parts.c_str());

    result.mod_name = mod_name;
    result.struct_count = mod_count;
    result.entity_count = entity_count;
    result.non_entity_count = struct_count;
    result.enum_count = (int)mod.enums.size();
    result.valid = true;
    return result;
}

// ============================================================================
// RTTI layout generation — struct headers from inferred member access patterns
// ============================================================================

// Infer C++ type from field size and access flags
static std::string infer_type_name(int size, const std::vector<std::string>& access_flags) {
    bool is_float = false;
    bool is_ref = false;
    for (const auto& flag : access_flags) {
        if (flag == "float") is_float = true;
        if (flag == "ref") is_ref = true;
    }

    switch (size) {
        case 1:  return "uint8_t";
        case 2:  return "uint16_t";
        case 4:  return is_float ? "float" : "uint32_t";
        case 8:  return is_ref ? "void*" : "uint64_t";
        case 16: return is_float ? "float[4]" : "uint8_t[16]";
        default: {
            char buf[32];
            snprintf(buf, sizeof(buf), "uint8_t[%d]", size);
            return buf;
        }
    }
}

// Build access flags comment string like "[read, write, float]"
static std::string format_access_flags(const std::vector<std::string>& access_flags) {
    if (access_flags.empty()) return "";
    std::string s = "[";
    for (size_t i = 0; i < access_flags.size(); i++) {
        if (i > 0) s += ", ";
        s += access_flags[i];
    }
    s += "]";
    return s;
}

// Generate a single RTTI class .hpp content string
static std::string generate_rtti_struct_header(
    const std::string& class_name,
    const std::string& module_name,
    const json& fields_json,
    int vtable_size,
    int analyzed_count,
    const std::string& parent_name,
    const std::string& timestamp)
{
    std::string safe_name = sanitize_cpp_identifier(class_name);
    if (safe_name.empty()) safe_name = class_name;

    std::string guard = "SDK_RTTI_" + safe_name + "_HPP";
    for (char& c : guard) {
        c = (char)std::toupper(static_cast<unsigned char>(c));
    }

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated from RTTI vtable analysis \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Class: " + class_name);
    lines.push_back("// Module: " + module_name);

    {
        char buf[128];
        snprintf(buf, sizeof(buf), "// Vtable functions: %d total, %d analyzed",
                 vtable_size, analyzed_count);
        lines.push_back(buf);
    }

    lines.push_back("// Fields are inferred from member access patterns (no PDB)");

    if (!parent_name.empty()) {
        lines.push_back("// Parent: " + parent_name);
    }

    lines.push_back("// Generated: " + timestamp);
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");
    lines.push_back("#include <cstdint>");
    lines.push_back("#include <cstddef>");
    lines.push_back("");
    lines.push_back("namespace sdk::rtti {");
    lines.push_back("");
    lines.push_back("#pragma pack(push, 1)");

    std::string struct_line = "struct " + safe_name + " {";
    if (!parent_name.empty()) {
        struct_line = "struct " + safe_name + " {    // parent: " + parent_name;
    }
    lines.push_back(struct_line);

    // vtable pointer at offset 0
    lines.push_back("    void* vtable;                               // 0x0000 (8 bytes)");

    int cursor = 8; // after vtable pointer

    // Sort fields by offset
    struct FieldEntry {
        uint32_t offset;
        int size;
        std::vector<std::string> access;
        std::vector<int> funcs;
    };
    std::vector<FieldEntry> fields;

    for (const auto& fobj : fields_json) {
        FieldEntry fe;
        fe.offset = fobj.value("offset", 0u);
        fe.size = fobj.value("size", 0);

        if (fobj.contains("access") && fobj["access"].is_array()) {
            for (const auto& a : fobj["access"]) {
                if (a.is_string()) fe.access.push_back(a.get<std::string>());
            }
        }
        if (fobj.contains("funcs") && fobj["funcs"].is_array()) {
            for (const auto& f : fobj["funcs"]) {
                if (f.is_number_integer()) fe.funcs.push_back(f.get<int>());
            }
        }

        // Skip offset 0 — that's the vtable pointer we already emitted
        if (fe.offset == 0) continue;
        // Skip fields with invalid size
        if (fe.size <= 0) continue;

        fields.push_back(std::move(fe));
    }

    std::sort(fields.begin(), fields.end(),
              [](const FieldEntry& a, const FieldEntry& b) { return a.offset < b.offset; });

    for (const auto& fe : fields) {
        int offset = static_cast<int>(fe.offset);

        // Emit padding if needed
        if (offset > cursor) {
            int gap = offset - cursor;
            char buf[128];
            snprintf(buf, sizeof(buf), "    uint8_t _pad%s[0x%s];",
                     hex04(cursor).c_str(), hex_upper(gap).c_str());
            lines.push_back(buf);
        }

        // Determine type
        std::string cpp_type = infer_type_name(fe.size, fe.access);

        // Build access comment
        std::string access_str = format_access_flags(fe.access);

        // Build func indices comment
        std::string funcs_str;
        if (!fe.funcs.empty()) {
            funcs_str = " funcs: ";
            for (size_t i = 0; i < fe.funcs.size(); i++) {
                if (i > 0) funcs_str += ", ";
                funcs_str += std::to_string(fe.funcs[i]);
            }
        }

        // Format the field line
        char offset_hex[16];
        snprintf(offset_hex, sizeof(offset_hex), "0x%04X", offset);

        char size_comment[64];
        snprintf(size_comment, sizeof(size_comment), "(%d bytes)", fe.size);

        // Check if type has array brackets
        size_t bracket = cpp_type.find('[');
        std::string field_name;
        {
            char buf[32];
            snprintf(buf, sizeof(buf), "field_0x%04X", offset);
            field_name = buf;
        }

        std::string decl;
        if (bracket != std::string::npos) {
            std::string base = cpp_type.substr(0, bracket);
            std::string arr = cpp_type.substr(bracket);
            decl = "    " + base + " " + field_name + arr + ";";
        } else {
            decl = "    " + cpp_type + " " + field_name + ";";
        }

        // Pad declaration to align comments
        while (decl.size() < 48) decl += ' ';

        std::string comment = "// " + std::string(offset_hex) + " " + size_comment;
        if (!access_str.empty()) comment += " " + access_str;
        if (!funcs_str.empty()) comment += funcs_str;

        lines.push_back(decl + comment);

        cursor = offset + fe.size;
    }

    lines.push_back("};");
    lines.push_back("#pragma pack(pop)");
    lines.push_back("");
    lines.push_back("} // namespace sdk::rtti");
    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return result;
}

// Process all RTTI classes in one module, write .hpp files to _rtti/ subdir
static int generate_rtti_module(
    const std::string& module_name,
    const json& layouts_json,
    const json& vtables_json,
    const std::unordered_set<std::string>& schema_classes,
    const std::string& output_dir,
    const std::string& timestamp)
{
    if (!layouts_json.is_object() || layouts_json.empty()) return 0;

    std::string mod_clean = strip_dll(module_name);

    // Build vtable info lookup: class_name -> {parent, vtable_rva}
    struct VtableInfo {
        std::string parent;
        std::string vtable_rva;
    };
    std::unordered_map<std::string, VtableInfo> vtable_lookup;

    if (vtables_json.is_array()) {
        for (const auto& vt : vtables_json) {
            if (!vt.contains("class") || !vt["class"].is_string()) continue;
            VtableInfo vi;
            vi.parent = vt.value("parent", "");
            if (vt.contains("vtable_rva")) {
                if (vt["vtable_rva"].is_string())
                    vi.vtable_rva = vt["vtable_rva"].get<std::string>();
                else
                    vi.vtable_rva = std::to_string(vt["vtable_rva"].get<uint64_t>());
            }
            vtable_lookup[vt["class"].get<std::string>()] = std::move(vi);
        }
    }

    // Create _rtti directory
    std::string rtti_dir = output_dir + "\\" + mod_clean + "\\_rtti";
    create_dirs(rtti_dir);

    int count = 0;

    // Sort class names for deterministic output
    std::vector<std::string> class_names;
    for (auto it = layouts_json.begin(); it != layouts_json.end(); ++it) {
        class_names.push_back(it.key());
    }
    std::sort(class_names.begin(), class_names.end());

    for (const auto& class_name : class_names) {
        // Skip classes that already have schema headers
        if (schema_classes.count(class_name)) continue;

        const auto& cls_data = layouts_json[class_name];
        if (!cls_data.contains("fields") || !cls_data["fields"].is_array()) continue;
        if (cls_data["fields"].empty()) continue;

        // Get vtable metadata
        int vtable_size = cls_data.value("vtable_size", 0);
        int analyzed = cls_data.value("analyzed", 0);

        // Get parent from RTTI data
        std::string parent_name;
        auto vit = vtable_lookup.find(class_name);
        if (vit != vtable_lookup.end()) {
            parent_name = vit->second.parent;
        }

        // Sanitize class name for file
        std::string safe_name = sanitize_cpp_identifier(class_name);
        if (safe_name.empty()) continue;

        std::string header = generate_rtti_struct_header(
            class_name, module_name, cls_data["fields"],
            vtable_size, analyzed, parent_name, timestamp);

        write_file(rtti_dir + "\\" + safe_name + ".hpp", header);
        count++;
    }

    return count;
}

// Generate _rtti-layouts.hpp master include
static std::string generate_rtti_master_include(
    const std::vector<std::pair<std::string, std::vector<std::string>>>& module_classes,
    const std::string& game,
    const std::string& timestamp)
{
    std::string guard = make_guard(game + "_rtti_layouts");

    std::vector<std::string> lines;
    lines.push_back("// Auto-generated from RTTI vtable analysis \xe2\x80\x94 DO NOT EDIT");
    lines.push_back("// Master include for all RTTI-inferred struct layouts");
    lines.push_back("// Generated: " + timestamp);
    lines.push_back("#pragma once");
    lines.push_back("#ifndef " + guard);
    lines.push_back("#define " + guard);
    lines.push_back("");

    int total = 0;
    for (const auto& [mod_name, class_names] : module_classes) {
        if (class_names.empty()) continue;
        lines.push_back("// " + mod_name + " (" + std::to_string(class_names.size()) + " classes)");
        for (const auto& cls : class_names) {
            lines.push_back("#include \"" + mod_name + "/_rtti/" + cls + ".hpp\"");
            total++;
        }
        lines.push_back("");
    }

    {
        char buf[128];
        snprintf(buf, sizeof(buf), "// Total: %d RTTI layout headers", total);
        lines.push_back(buf);
    }

    lines.push_back("");
    lines.push_back("#endif // " + guard);
    lines.push_back("");

    std::string result;
    for (const auto& l : lines) { result += l; result += '\n'; }
    return result;
}

// Top-level RTTI layout generation entry point
static int generate_rtti_layouts(
    const json& data,
    const std::string& output_dir,
    const std::string& game_name,
    const std::string& timestamp,
    const std::unordered_set<std::string>& schema_classes)
{
    if (!data.contains("member_layouts") || !data["member_layouts"].is_object())
        return 0;

    const auto& member_layouts = data["member_layouts"];

    // Build a lookup from module name -> vtables array
    std::unordered_map<std::string, const json*> module_vtables;
    if (data.contains("modules") && data["modules"].is_array()) {
        for (const auto& mod : data["modules"]) {
            if (mod.contains("name") && mod["name"].is_string() &&
                mod.contains("vtables") && mod["vtables"].is_array()) {
                module_vtables[mod["name"].get<std::string>()] = &mod["vtables"];
            }
        }
    }

    int total_count = 0;
    // Track generated classes per module for master include
    std::vector<std::pair<std::string, std::vector<std::string>>> module_classes;

    // Sort module names
    std::vector<std::string> mod_names;
    for (auto it = member_layouts.begin(); it != member_layouts.end(); ++it) {
        mod_names.push_back(it.key());
    }
    std::sort(mod_names.begin(), mod_names.end());

    for (const auto& mod_name : mod_names) {
        const json* vtables_ptr = nullptr;
        auto vit = module_vtables.find(mod_name);
        if (vit != module_vtables.end()) vtables_ptr = vit->second;

        json empty_arr = json::array();
        const json& vtables_ref = vtables_ptr ? *vtables_ptr : empty_arr;

        int mod_count = generate_rtti_module(
            mod_name, member_layouts[mod_name], vtables_ref,
            schema_classes, output_dir, timestamp);

        if (mod_count > 0) {
            // Collect generated class names for master include
            std::string mod_clean = strip_dll(mod_name);
            std::vector<std::string> class_names;
            const auto& layouts = member_layouts[mod_name];

            std::vector<std::string> sorted_names;
            for (auto it = layouts.begin(); it != layouts.end(); ++it) {
                sorted_names.push_back(it.key());
            }
            std::sort(sorted_names.begin(), sorted_names.end());

            for (const auto& cls_name : sorted_names) {
                if (schema_classes.count(cls_name)) continue;
                std::string safe = sanitize_cpp_identifier(cls_name);
                if (safe.empty()) continue;
                const auto& cls_data = layouts[cls_name];
                if (!cls_data.contains("fields") || !cls_data["fields"].is_array() ||
                    cls_data["fields"].empty()) continue;
                class_names.push_back(safe);
            }

            module_classes.push_back({mod_clean, std::move(class_names)});
            total_count += mod_count;

            printf("  %-30s  %d RTTI layouts\n", mod_name.c_str(), mod_count);
        }
    }

    // Generate master include
    if (total_count > 0) {
        std::string master = generate_rtti_master_include(module_classes, game_name, timestamp);
        write_file(output_dir + "\\_rtti-layouts.hpp", master);
    }

    return total_count;
}

// ============================================================================
// generate_sdk -- Main entry point
// ============================================================================

SdkStats generate_sdk(const json& data,
                       const std::vector<ModuleData>& modules,
                       const std::unordered_map<std::string, const ClassInfo*>& class_lookup,
                       const std::string& output_dir,
                       const std::string& game_name,
                       const std::string& exe_dir) {
    SdkStats sdk_stats = {};

    // Get timestamp
    std::string timestamp = data.value("timestamp", "");
    if (timestamp.empty()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buf[64];
        snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond);
        timestamp = buf;
    }

    // Build shared state
    SharedState state;
    state.class_lookup = &class_lookup;

    // Build class -> module mapping
    for (const auto& mod : modules) {
        std::string mod_clean = strip_dll(mod.name);
        for (const auto& cls : mod.classes) {
            state.class_to_module[cls.name] = mod_clean;
        }
    }

    // Build enum lookup
    for (const auto& mod : modules) {
        for (const auto& en : mod.enums) {
            state.all_enums[en.name] = en.size > 0 ? en.size : 4;
        }
    }

    // Build class name set
    for (const auto& kv : class_lookup) {
        state.all_classes.insert(kv.first);
    }

    // Load cherry-pick config
    state.cherry_pick = json::object();
    {
        std::string candidates[] = {
            exe_dir + "\\sdk-cherry-pick.json",
            exe_dir + "\\bin\\sdk-cherry-pick.json",
        };
        for (const auto& candidate : candidates) {
            FILE* f = fopen(candidate.c_str(), "rb");
            if (f) {
                fseek(f, 0, SEEK_END);
                long len = ftell(f);
                fseek(f, 0, SEEK_SET);
                std::string content(len, '\0');
                fread(&content[0], 1, len, f);
                fclose(f);
                try {
                    state.cherry_pick = json::parse(content);
                    int helper_count = 0;
                    if (state.cherry_pick.contains("helpers")) {
                        helper_count = (int)state.cherry_pick["helpers"].size();
                    }
                    printf("Cherry-pick config loaded: %d classes with helpers\n", helper_count);
                } catch (...) {
                    printf("  Warning: Failed to parse %s\n", candidate.c_str());
                    state.cherry_pick = json::object();
                }
                break;
            }
        }
        if (state.cherry_pick.empty() || !state.cherry_pick.contains("helpers")) {
            printf("No sdk-cherry-pick.json found \xe2\x80\x94 generating plain structs for all classes\n");
        }
    }
    printf("\n");

    // Reset stats tracker
    ResolveStats resolve_stats;

    // Pre-compute subfolder assignments
    for (const auto& mod : modules) {
        std::vector<const ClassInfo*> useful;
        for (const auto& c : mod.classes) {
            if (c.size > 0 && !c.fields.empty()) useful.push_back(&c);
        }

        std::vector<const ClassInfo*> entities;
        std::vector<const ClassInfo*> non_entities;
        for (const auto* c : useful) {
            if (is_entity_class(c->name, class_lookup)) {
                entities.push_back(c);
            } else {
                non_entities.push_back(c);
            }
        }

        if (!entities.empty() && !non_entities.empty()) {
            // Mixed module -- split into entities/ and structs/
            for (const auto* c : entities) {
                state.class_subfolder[c->name] = "entities";
            }
            for (const auto* c : non_entities) {
                state.class_subfolder[c->name] = "structs";
            }
        } else if (!entities.empty()) {
            // All entities -- put in entities/ for clarity
            for (const auto* c : entities) {
                state.class_subfolder[c->name] = "entities";
            }
        }
        // else: all structs or empty -- no subfolder (stay at module root)
    }

    // Create output directory
    create_dirs(output_dir);

    // 1. Generate types.hpp
    std::string types_content = generate_types_hpp(timestamp);
    write_file(output_dir + "\\types.hpp", types_content);
    printf("  types.hpp (Vec3, QAngle, CHandle, Color, ViewMatrix, CHandleVector)\n");

    // 2. Generate per-module struct headers + offset/enum files (parallel)
    int total_structs = 0;
    std::vector<std::string> module_names;
    std::mutex results_mutex;

    int num_workers = (std::min)((int)std::thread::hardware_concurrency(),
                                (std::max)((int)modules.size(), 1));
    if (num_workers < 1) num_workers = 4;
    printf("Processing %d modules with %d threads...\n", (int)modules.size(), num_workers);

    // Process modules in parallel
    std::vector<ModuleResult> mod_results(modules.size());
    std::atomic<size_t> next_module{0};

    auto worker_fn = [&]() {
        while (true) {
            size_t idx = next_module.fetch_add(1);
            if (idx >= modules.size()) break;
            mod_results[idx] = process_sdk_module(
                modules[idx], game_name, state, output_dir, timestamp, resolve_stats);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < num_workers; i++) {
        threads.emplace_back(worker_fn);
    }
    for (auto& t : threads) {
        t.join();
    }

    // Collect results
    for (const auto& r : mod_results) {
        if (!r.valid) continue;
        module_names.push_back(r.mod_name);
        total_structs += r.struct_count;
    }

    // 3. Consolidated includes
    if (!module_names.empty()) {
        std::string all_offsets = generate_all_offsets(module_names, game_name, timestamp);
        write_file(output_dir + "\\_all-offsets.hpp", all_offsets);

        std::string all_enums = generate_all_enums(module_names, game_name, timestamp);
        write_file(output_dir + "\\_all-enums.hpp", all_enums);
    }

    // 4. _all-vtables.hpp
    std::string vtables_content = generate_all_vtables(data, game_name, timestamp);
    write_file(output_dir + "\\_all-vtables.hpp", vtables_content);

    // Count vtables and functions from generated content
    int vtable_count = 0;
    int vtable_func_count = 0;
    {
        size_t pos = 0;
        while ((pos = vtables_content.find("constexpr uint32_t vtable_rva", pos)) != std::string::npos) {
            vtable_count++;
            pos++;
        }
        pos = 0;
        while ((pos = vtables_content.find("constexpr int idx_", pos)) != std::string::npos) {
            vtable_func_count++;
            pos++;
        }
    }

    // 5. _globals.hpp
    int globals_count = 0;
    if (data.contains("pattern_globals") && data["pattern_globals"].is_object() &&
        !data["pattern_globals"].empty()) {
        auto gr = generate_globals_hpp(data["pattern_globals"], game_name, timestamp);
        write_file(output_dir + "\\_globals.hpp", gr.content);
        globals_count = gr.count;
    }

    // 6. _patterns.hpp
    int patterns_count = 0;
    if (data.contains("pattern_globals") && data["pattern_globals"].is_object()) {
        const auto& pg = data["pattern_globals"];
        bool has_patterns = false;
        for (auto it = pg.begin(); it != pg.end() && !has_patterns; ++it) {
            if (!it.value().is_object()) continue;
            for (auto jt = it.value().begin(); jt != it.value().end(); ++jt) {
                if (jt.value().is_object()) {
                    if (jt.value().contains("pattern") ||
                        jt.value().value("mode", "") == "derived") {
                        has_patterns = true;
                        break;
                    }
                }
            }
        }

        if (has_patterns) {
            auto pr = generate_patterns_hpp(pg, game_name, timestamp);
            write_file(output_dir + "\\_patterns.hpp", pr.content);
            patterns_count = pr.count;
        }
    }

    // 7. RTTI layout headers
    int rtti_count = 0;
    if (data.contains("member_layouts")) {
        // Build set of schema class names to skip
        std::unordered_set<std::string> schema_classes;
        for (const auto& mod : modules) {
            for (const auto& cls : mod.classes) {
                if (cls.size > 0 && !cls.fields.empty())
                    schema_classes.insert(cls.name);
            }
        }
        printf("\nGenerating RTTI layout headers...\n");
        rtti_count = generate_rtti_layouts(data, output_dir, game_name, timestamp, schema_classes);
    }
    sdk_stats.rtti_layouts = rtti_count;

    printf("\n  _all-offsets.hpp: includes %d modules\n", (int)module_names.size());
    printf("  _all-enums.hpp: includes %d modules\n", (int)module_names.size());
    printf("  _all-vtables.hpp: %d vtables, %d functions\n", vtable_count, vtable_func_count);
    if (globals_count > 0) {
        printf("  _globals.hpp: %d global pointers\n", globals_count);
    }
    if (patterns_count > 0) {
        printf("  _patterns.hpp: %d scannable patterns\n", patterns_count);
    }
    if (rtti_count > 0) {
        printf("  _rtti-layouts.hpp: %d RTTI struct headers\n", rtti_count);
    }

    // Print type resolution statistics
    resolve_stats.print_summary();

    printf("\nDone! %d struct headers generated", total_structs);
    if (rtti_count > 0) printf(" + %d RTTI layouts", rtti_count);
    printf(".\n");
    printf("Output: %s\n", output_dir.c_str());

    // Populate return stats
    sdk_stats.structs = total_structs;
    sdk_stats.vtables = vtable_count;
    sdk_stats.globals = globals_count;
    sdk_stats.patterns = patterns_count;
    sdk_stats.resolved = resolve_stats.total.load() - resolve_stats.unresolved.load();
    sdk_stats.unresolved = resolve_stats.unresolved.load();
    sdk_stats.total_fields = resolve_stats.total.load();

    // Count total enums
    for (const auto& r : mod_results) {
        if (r.valid) sdk_stats.enums += r.enum_count;
    }

    return sdk_stats;
}
