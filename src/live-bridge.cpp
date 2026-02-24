#include "live-bridge.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <cctype>
#include <cstdarg>

namespace live {

// ============================================================================
// Logging implementation
// ============================================================================

static LogFn g_logger;

void set_logger(LogFn fn) { g_logger = std::move(fn); }

void log_error(const char* tag, const char* fmt, ...) {
    if (!g_logger) return;
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    g_logger(tag, buf);
}

void log_info(const char* tag, const char* fmt, ...) {
    if (!g_logger) return;
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    g_logger(tag, buf);
}

// ============================================================================
// Pipe protocol constants (must match worker.cpp)
// ============================================================================

static const uint8_t PIPE_OP_READ     = 0x01;
// PIPE_OP_WRITE (0x02) removed — this tool is read-only
static const uint8_t PIPE_OP_MODULE_BASE = 0x03;
static const uint8_t PIPE_OP_SHUTDOWN = 0xFF;

static const uint8_t PIPE_STATUS_OK       = 0x00;

#pragma pack(push, 1)
struct PipeRequest {
    uint8_t  op;
    uint8_t  pad[3];
    uint32_t size;
    uint64_t addr;
};

struct PipeResponse {
    uint8_t  status;
    uint8_t  pad[3];
    uint32_t size;
};
#pragma pack(pop)

// ============================================================================
// PipeClient
// ============================================================================

static bool pipe_read_exact(HANDLE pipe, void* buf, DWORD len) {
    DWORD total = 0;
    while (total < len) {
        DWORD bytesRead = 0;
        if (!ReadFile(pipe, (uint8_t*)buf + total, len - total, &bytesRead, NULL) || bytesRead == 0)
            return false;
        total += bytesRead;
    }
    return true;
}

static bool pipe_write_exact(HANDLE pipe, const void* buf, DWORD len) {
    DWORD total = 0;
    while (total < len) {
        DWORD written = 0;
        if (!WriteFile(pipe, (const uint8_t*)buf + total, len - total, &written, NULL) || written == 0)
            return false;
        total += written;
    }
    return true;
}

PipeClient::PipeClient() : m_pipe(INVALID_HANDLE_VALUE) {}

PipeClient::~PipeClient() { disconnect(); }

bool PipeClient::connect(const char* pipe_name) {
    // Wait up to 5 seconds for the pipe to become available
    if (!WaitNamedPipeA(pipe_name, 5000)) {
        log_error("PIPE", "WaitNamedPipe failed for %s (err=%lu)", pipe_name, GetLastError());
        return false;
    }

    HANDLE h = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        log_error("PIPE", "CreateFile failed for %s (err=%lu)", pipe_name, GetLastError());
        return false;
    }

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(h, &mode, NULL, NULL);

    m_pipe = h;
    log_info("PIPE", "Connected to %s", pipe_name);
    return true;
}

void PipeClient::disconnect() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle((HANDLE)m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
}

bool PipeClient::connected() const {
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_pipe != INVALID_HANDLE_VALUE;
}

std::vector<uint8_t> PipeClient::read(uint64_t addr, uint32_t size) {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_pipe == INVALID_HANDLE_VALUE || size == 0 || size > 65536) return {};

    PipeRequest req = {};
    req.op = PIPE_OP_READ;
    req.size = size;
    req.addr = addr;

    HANDLE h = (HANDLE)m_pipe;
    if (!pipe_write_exact(h, &req, sizeof(req))) {
        log_error("PIPE", "write request failed for read(0x%llX, %u) err=%lu",
                  (unsigned long long)addr, size, GetLastError());
        return {};
    }

    PipeResponse resp = {};
    if (!pipe_read_exact(h, &resp, sizeof(resp))) {
        log_error("PIPE", "read response header failed for read(0x%llX) err=%lu",
                  (unsigned long long)addr, GetLastError());
        return {};
    }
    if (resp.status != PIPE_STATUS_OK) {
        log_error("PIPE", "read(0x%llX) returned status=%d", (unsigned long long)addr, resp.status);
        return {};
    }

    std::vector<uint8_t> buf(resp.size);
    if (resp.size > 0 && !pipe_read_exact(h, buf.data(), resp.size)) {
        log_error("PIPE", "read payload failed for read(0x%llX) err=%lu",
                  (unsigned long long)addr, GetLastError());
        return {};
    }
    return buf;
}

// PipeClient::write() removed — this tool is read-only.

bool PipeClient::shutdown() {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_pipe == INVALID_HANDLE_VALUE) return false;

    PipeRequest req = {};
    req.op = PIPE_OP_SHUTDOWN;

    HANDLE h = (HANDLE)m_pipe;
    if (!pipe_write_exact(h, &req, sizeof(req))) {
        log_error("PIPE", "shutdown request failed err=%lu", GetLastError());
        CloseHandle(h);
        m_pipe = INVALID_HANDLE_VALUE;
        return false;
    }

    PipeResponse resp = {};
    pipe_read_exact(h, &resp, sizeof(resp)); // best effort

    CloseHandle(h);
    m_pipe = INVALID_HANDLE_VALUE;
    log_info("PIPE", "Shutdown sent, pipe closed");
    return true;
}

uint64_t PipeClient::module_base(const std::string& name) {
    std::lock_guard<std::mutex> lk(m_mtx);
    if (m_pipe == INVALID_HANDLE_VALUE || name.empty() || name.size() > 260) return 0;

    PipeRequest req = {};
    req.op = PIPE_OP_MODULE_BASE;
    req.size = static_cast<uint32_t>(name.size());
    req.addr = 0;

    HANDLE h = (HANDLE)m_pipe;
    if (!pipe_write_exact(h, &req, sizeof(req))) {
        log_error("PIPE", "module_base request failed for '%s' err=%lu", name.c_str(), GetLastError());
        return 0;
    }
    if (!pipe_write_exact(h, name.data(), req.size)) {
        log_error("PIPE", "module_base payload failed for '%s' err=%lu", name.c_str(), GetLastError());
        return 0;
    }

    PipeResponse resp = {};
    if (!pipe_read_exact(h, &resp, sizeof(resp))) {
        log_error("PIPE", "module_base response failed for '%s' err=%lu", name.c_str(), GetLastError());
        return 0;
    }
    if (resp.status != PIPE_STATUS_OK || resp.size != 8) {
        log_error("PIPE", "module_base '%s' returned status=%d size=%u", name.c_str(), resp.status, resp.size);
        return 0;
    }

    uint64_t base = 0;
    if (!pipe_read_exact(h, &base, 8)) return 0;
    return base;
}

// ============================================================================
// SchemaCache
// ============================================================================

// Safe string extraction — returns "" for null or missing values
static std::string jstr(const nlohmann::json& j, const char* key) {
    if (!j.contains(key)) return {};
    const auto& v = j[key];
    if (v.is_null()) return {};
    if (v.is_string()) return v.get<std::string>();
    return {};
}

bool SchemaCache::load(const nlohmann::json& data) {
    m_modules.clear();
    m_classes.clear();
    m_enums.clear();
    m_globals.clear();
    m_pattern_globals.clear();
    m_rtti_vtables.clear();

    if (!data.contains("modules") || !data["modules"].is_array())
        return false;

    for (const auto& mod : data["modules"]) {
        std::string mod_name = jstr(mod, "name");
        if (mod_name.empty()) continue;
        m_modules.push_back(mod_name);

        // Classes
        if (mod.contains("classes") && mod["classes"].is_array()) {
            for (const auto& cls : mod["classes"]) {
                CachedClass cc;
                cc.name = jstr(cls, "name");
                cc.module = mod_name;
                cc.size = cls.value("size", 0);
                cc.parent = jstr(cls, "parent");

                if (cls.contains("inheritance") && cls["inheritance"].is_array()) {
                    for (const auto& inh : cls["inheritance"]) {
                        if (inh.is_string()) cc.inheritance.push_back(inh.get<std::string>());
                    }
                }
                if (cls.contains("metadata") && cls["metadata"].is_array()) {
                    for (const auto& m : cls["metadata"]) {
                        if (m.is_string()) cc.metadata.push_back(m.get<std::string>());
                    }
                }

                auto parse_fields = [](const nlohmann::json& arr) {
                    std::vector<CachedField> fields;
                    for (const auto& f : arr) {
                        CachedField cf;
                        cf.name = f.value("name", "");
                        cf.type = f.value("type", "");
                        cf.offset = f.value("offset", 0);
                        cf.size = f.value("size", 0);
                        fields.push_back(std::move(cf));
                    }
                    return fields;
                };

                if (cls.contains("fields") && cls["fields"].is_array())
                    cc.fields = parse_fields(cls["fields"]);
                if (cls.contains("static_fields") && cls["static_fields"].is_array())
                    cc.static_fields = parse_fields(cls["static_fields"]);

                std::string key = mod_name + "::" + cc.name;
                m_classes[key] = std::move(cc);
            }
        }

        // Enums
        if (mod.contains("enums") && mod["enums"].is_array()) {
            for (const auto& en : mod["enums"]) {
                CachedEnum ce;
                ce.name = en.value("name", "");
                ce.module = mod_name;
                ce.size = en.value("size", 0);
                if (en.contains("values") && en["values"].is_array()) {
                    for (const auto& v : en["values"]) {
                        ce.values.emplace_back(
                            v.value("name", ""),
                            v.value("value", (int64_t)0));
                    }
                }
                std::string key = mod_name + "::" + ce.name;
                m_enums[key] = std::move(ce);
            }
        }

        // RTTI vtables
        if (mod.contains("vtables") && mod["vtables"].is_array()) {
            for (const auto& vt : mod["vtables"]) {
                RttiVtable rv;
                rv.class_name = jstr(vt, "class");
                rv.module = mod_name;
                auto rva_str = jstr(vt, "vtable_rva");
                if (!rva_str.empty())
                    rv.vtable_rva = static_cast<uint32_t>(std::stoul(rva_str, nullptr, 16));
                if (rv.vtable_rva != 0 && !rv.class_name.empty())
                    m_rtti_vtables.push_back(std::move(rv));
            }
        }
    }

    // Globals
    if (data.contains("globals") && data["globals"].is_object()) {
        for (const auto& [mod_name, entries] : data["globals"].items()) {
            if (!entries.is_array()) continue;
            for (const auto& g : entries) {
                CachedGlobal cg;
                cg.class_name = jstr(g, "class");
                cg.module = mod_name;

                auto rva_str = jstr(g, "rva");
                if (!rva_str.empty())
                    cg.global_rva = static_cast<uint32_t>(std::stoul(rva_str, nullptr, 16));

                auto vt_str = jstr(g, "vtable_rva");
                if (!vt_str.empty())
                    cg.vtable_rva = static_cast<uint32_t>(std::stoul(vt_str, nullptr, 16));

                cg.is_pointer = jstr(g, "type") == "pointer";
                cg.has_schema = g.value("has_schema", false);
                m_globals.push_back(std::move(cg));
            }
        }
    }

    // Pattern globals (dwEntityList, dwViewMatrix, etc.)
    if (data.contains("pattern_globals") && data["pattern_globals"].is_object()) {
        for (const auto& [mod_name, patterns] : data["pattern_globals"].items()) {
            if (!patterns.is_object()) continue;
            for (const auto& [pat_name, pat_data] : patterns.items()) {
                PatternGlobal pg;
                pg.name = pat_name;
                pg.module = mod_name;
                auto rva_str = jstr(pat_data, "rva");
                if (!rva_str.empty())
                    pg.rva = static_cast<uint32_t>(std::stoul(rva_str, nullptr, 16));
                m_pattern_globals.push_back(std::move(pg));
            }
        }
    }

    return true;
}

std::vector<std::string> SchemaCache::modules() const {
    return m_modules;
}

std::vector<const CachedClass*> SchemaCache::classes_in_module(const std::string& mod) const {
    std::vector<const CachedClass*> result;
    std::string prefix = mod + "::";
    for (const auto& [key, cls] : m_classes) {
        if (key.rfind(prefix, 0) == 0)
            result.push_back(&cls);
    }
    return result;
}

const CachedClass* SchemaCache::find_class(const std::string& mod, const std::string& name) const {
    auto it = m_classes.find(mod + "::" + name);
    return (it != m_classes.end()) ? &it->second : nullptr;
}

std::vector<const CachedEnum*> SchemaCache::enums_in_module(const std::string& mod) const {
    std::vector<const CachedEnum*> result;
    std::string prefix = mod + "::";
    for (const auto& [key, en] : m_enums) {
        if (key.rfind(prefix, 0) == 0)
            result.push_back(&en);
    }
    return result;
}

const CachedEnum* SchemaCache::find_enum(const std::string& mod, const std::string& name) const {
    auto it = m_enums.find(mod + "::" + name);
    return (it != m_enums.end()) ? &it->second : nullptr;
}

bool SchemaCache::is_enum_type(const std::string& name) const {
    for (const auto& [key, en] : m_enums) {
        if (en.name == name) return true;
    }
    return false;
}

std::string SchemaCache::resolve_wrapper(const std::string& name) const {
    // Build cache on first call
    if (!m_wrapper_cache_built) {
        for (const auto& [key, cls] : m_classes) {
            if (cls.fields.size() == 1 && cls.parent.empty() &&
                cls.fields[0].size == cls.size && cls.size > 0) {
                m_wrapper_cache[cls.name] = cls.fields[0].type;
            }
        }
        m_wrapper_cache_built = true;
    }
    auto it = m_wrapper_cache.find(name);
    return (it != m_wrapper_cache.end()) ? it->second : "";
}

std::vector<CachedGlobal> SchemaCache::all_globals() const {
    return m_globals;
}

std::vector<PatternGlobal> SchemaCache::pattern_globals() const {
    return m_pattern_globals;
}

const std::vector<RttiVtable>& SchemaCache::rtti_vtables() const {
    return m_rtti_vtables;
}

const CachedClass* SchemaCache::find_class_any(const std::string& name) const {
    for (const auto& mod : m_modules) {
        auto it = m_classes.find(mod + "::" + name);
        if (it != m_classes.end()) return &it->second;
    }
    return nullptr;
}

const CachedEnum* SchemaCache::find_enum_any(const std::string& name) const {
    for (const auto& [key, en] : m_enums) {
        if (en.name == name) return &en;
    }
    return nullptr;
}

std::vector<CachedField> SchemaCache::flat_fields(const std::string& mod, const std::string& name) const {
    std::vector<CachedField> result;
    const CachedClass* cls = find_class(mod, name);
    if (!cls) return result;

    // Collect fields from parent chain first
    if (!cls->parent.empty()) {
        // Try same module first, then search all modules
        auto parent_fields = flat_fields(mod, cls->parent);
        if (parent_fields.empty()) {
            for (const auto& m : m_modules) {
                parent_fields = flat_fields(m, cls->parent);
                if (!parent_fields.empty()) break;
            }
        }
        result = std::move(parent_fields);
    }

    // Add own fields
    for (const auto& f : cls->fields)
        result.push_back(f);

    // Sort by offset
    std::sort(result.begin(), result.end(),
              [](const CachedField& a, const CachedField& b) { return a.offset < b.offset; });

    return result;
}

std::vector<std::pair<std::string, std::string>> SchemaCache::search(const std::string& query) const {
    std::vector<std::pair<std::string, std::string>> result;
    std::string lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    for (const auto& [key, cls] : m_classes) {
        std::string lower_name = cls.name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                       [](unsigned char c) { return (char)std::tolower(c); });
        if (lower_name.find(lower_query) != std::string::npos)
            result.emplace_back(cls.module, cls.name);
    }
    for (const auto& [key, en] : m_enums) {
        std::string lower_name = en.name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                       [](unsigned char c) { return (char)std::tolower(c); });
        if (lower_name.find(lower_query) != std::string::npos)
            result.emplace_back(en.module, en.name);
    }

    return result;
}

// ============================================================================
// Field type interpretation
// ============================================================================

static bool starts_with(const std::string& s, const char* prefix) {
    return s.rfind(prefix, 0) == 0;
}

nlohmann::json interpret_field(const std::string& type, const uint8_t* data, int size) {
    using json = nlohmann::json;

    // Integer types
    if (type == "int8" || type == "char")
        return (size >= 1) ? json((int)(int8_t)data[0]) : json(nullptr);
    if (type == "uint8" || type == "byte")
        return (size >= 1) ? json(data[0]) : json(nullptr);
    if (type == "int16")
        return (size >= 2) ? json(*(const int16_t*)data) : json(nullptr);
    if (type == "uint16")
        return (size >= 2) ? json(*(const uint16_t*)data) : json(nullptr);
    if (type == "int32")
        return (size >= 4) ? json(*(const int32_t*)data) : json(nullptr);
    if (type == "uint32")
        return (size >= 4) ? json(*(const uint32_t*)data) : json(nullptr);
    if (type == "int64")
        return (size >= 8) ? json(*(const int64_t*)data) : json(nullptr);
    if (type == "uint64")
        return (size >= 8) ? json(*(const uint64_t*)data) : json(nullptr);

    // Float types
    if (type == "float32" || type == "float")
        return (size >= 4) ? json(*(const float*)data) : json(nullptr);
    if (type == "float64" || type == "double")
        return (size >= 8) ? json(*(const double*)data) : json(nullptr);

    // Bool
    if (type == "bool")
        return (size >= 1) ? json(data[0] != 0) : json(nullptr);

    // Vector types (3 floats)
    if (type == "Vector" || type == "QAngle") {
        if (size >= 12) {
            const float* f = (const float*)data;
            return json::array({f[0], f[1], f[2]});
        }
        return json(nullptr);
    }

    // Vector2D
    if (type == "Vector2D") {
        if (size >= 8) {
            const float* f = (const float*)data;
            return json::array({f[0], f[1]});
        }
        return json(nullptr);
    }

    // Vector4D / Quaternion
    if (type == "Vector4D" || type == "Quaternion") {
        if (size >= 16) {
            const float* f = (const float*)data;
            return json::array({f[0], f[1], f[2], f[3]});
        }
        return json(nullptr);
    }

    // Color (4 bytes RGBA)
    if (type == "Color") {
        if (size >= 4) {
            return json::array({data[0], data[1], data[2], data[3]});
        }
        return json(nullptr);
    }

    // CHandle<*> — uint32 entity handle
    if (starts_with(type, "CHandle<") || starts_with(type, "CHandle<")) {
        if (size >= 4)
            return json(*(const uint32_t*)data);
        return json(nullptr);
    }

    // CUtlString / CUtlSymbolLarge — pointer to string (just show the pointer)
    if (type == "CUtlString" || type == "CUtlSymbolLarge") {
        if (size >= 8) {
            char hex[32];
            snprintf(hex, sizeof(hex), "0x%llX", (unsigned long long)(*(const uint64_t*)data));
            return json(hex);
        }
        return json(nullptr);
    }

    // Fallback: show as hex bytes
    if (size <= 8) {
        // Small values — show as hex integer
        uint64_t val = 0;
        memcpy(&val, data, std::min(size, 8));
        char hex[32];
        snprintf(hex, sizeof(hex), "0x%llX", (unsigned long long)val);
        return json(hex);
    }

    // Large: show first 16 bytes as hex string
    std::string hex;
    int show = std::min(size, 16);
    for (int i = 0; i < show; i++) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%02X", data[i]);
        hex += buf;
        if (i + 1 < show) hex += ' ';
    }
    if (size > 16) hex += "...";
    return json(hex);
}

// ============================================================================
// Forward declarations for helpers used by both SubManager and CommandDispatcher
// ============================================================================

static bool is_valid_ptr(uint64_t p) {
    return p > 0x10000 && p < 0x7FFFFFFFFFFF;
}

static std::string resolve_type(const std::string& type, int size, const SchemaCache& cache) {
    // Enums → sized integer
    if (cache.is_enum_type(type)) {
        switch (size) {
            case 1: return "int8";
            case 2: return "int16";
            case 4: return "int32";
            case 8: return "int64";
            default: break;
        }
    }
    // Single-field wrapper structs → inner type (e.g. GameTime_t → float32)
    std::string inner = cache.resolve_wrapper(type);
    if (!inner.empty()) return inner;
    return type;
}

// ============================================================================
// Template / array type parsers
// ============================================================================

// Parse "CUtlVector< int32 >" → outer="CUtlVector", inner="int32"
static bool parse_template(const std::string& type, std::string& outer, std::string& inner) {
    auto lt = type.find('<');
    if (lt == std::string::npos) return false;
    auto gt = type.rfind('>');
    if (gt == std::string::npos || gt <= lt) return false;
    outer = type.substr(0, lt);
    inner = type.substr(lt + 1, gt - lt - 1);
    // Trim spaces
    while (!inner.empty() && inner.back() == ' ') inner.pop_back();
    while (!inner.empty() && inner.front() == ' ') inner.erase(inner.begin());
    return true;
}

// Parse "float32[4]" → elem_type="float32", count=4
static bool parse_fixed_array(const std::string& type, std::string& elem_type, int& count) {
    auto bracket = type.find('[');
    if (bracket == std::string::npos) return false;
    auto end = type.find(']', bracket);
    if (end == std::string::npos) return false;
    elem_type = type.substr(0, bracket);
    try {
        count = std::stoi(type.substr(bracket + 1, end - bracket - 1));
    } catch (...) {
        return false;
    }
    return count > 0;
}

// Return size in bytes for primitive type names, 0 if unknown
static int primitive_size(const std::string& type) {
    if (type == "bool" || type == "int8" || type == "uint8" || type == "char" || type == "byte") return 1;
    if (type == "int16" || type == "uint16") return 2;
    if (type == "int32" || type == "uint32" || type == "float32" || type == "float") return 4;
    if (type == "int64" || type == "uint64" || type == "float64" || type == "double") return 8;
    if (type == "Vector" || type == "QAngle") return 12;
    if (type == "Vector2D") return 8;
    if (type == "Vector4D" || type == "Quaternion") return 16;
    if (type == "Color") return 4;
    return 0;
}

// ============================================================================
// Enum value name resolution
// ============================================================================

static nlohmann::json resolve_enum_value(const std::string& enum_type, int64_t raw_val,
                                          const SchemaCache& cache) {
    using json = nlohmann::json;
    const CachedEnum* en = cache.find_enum_any(enum_type);
    if (!en) return json(raw_val); // fallback

    for (const auto& [name, val] : en->values) {
        if (val == raw_val) {
            return json::object({{"_t", "enum"}, {"v", raw_val}, {"name", name}, {"enum", enum_type}});
        }
    }
    // Not found in values — still tag it
    return json::object({{"_t", "enum"}, {"v", raw_val}, {"name", nullptr}, {"enum", enum_type}});
}

// ============================================================================
// CUtlVector reader
// ============================================================================

static nlohmann::json read_utlvector(const uint8_t* field_data, int field_size,
                                      const std::string& elem_type, PipeClient& pipe,
                                      const SchemaCache& cache) {
    using json = nlohmann::json;
    if (field_size < 16) return json(nullptr);

    int32_t count = *(const int32_t*)(field_data);
    uint64_t data_ptr = *(const uint64_t*)(field_data + 8);

    json result = json::object({{"_t", "vector"}, {"count", count}, {"type", elem_type}});

    if (count <= 0 || count > 4096 || !is_valid_ptr(data_ptr)) {
        result["items"] = json::array();
        return result;
    }

    int elem_size = primitive_size(elem_type);
    if (elem_size == 0) {
        auto* cls = cache.find_class_any(elem_type);
        if (cls) elem_size = cls->size;
    }
    if (elem_size == 0) elem_size = 8; // fallback

    int read_count = std::min(count, 64);
    auto elem_data = pipe.read(data_ptr, static_cast<uint32_t>(read_count * elem_size));
    if (elem_data.empty()) return result;

    json items = json::array();
    for (int i = 0; i < read_count && (i * elem_size + elem_size) <= (int)elem_data.size(); i++) {
        std::string eff = resolve_type(elem_type, elem_size, cache);
        items.push_back(interpret_field(eff, elem_data.data() + i * elem_size, elem_size));
    }
    result["items"] = std::move(items);
    if (count > 64) result["truncated"] = true;
    return result;
}

// ============================================================================
// Unified field processor — used by mem.read_object, SubManager, entity.find
// ============================================================================

static nlohmann::json process_field(const CachedField& f, const uint8_t* data, int data_size,
                                     PipeClient& pipe, const SchemaCache& cache, int depth = 0) {
    using json = nlohmann::json;
    if (f.offset + f.size > data_size) return json(nullptr);

    const uint8_t* field_data = data + f.offset;

    // 1. Fixed array: "float32[4]"
    {
        std::string arr_elem; int arr_count;
        if (parse_fixed_array(f.type, arr_elem, arr_count) && arr_count > 0) {
            int elem_size = f.size / arr_count;
            if (elem_size > 0) {
                json items = json::array();
                for (int i = 0; i < arr_count && (f.offset + i * elem_size + elem_size) <= data_size; i++) {
                    std::string eff = resolve_type(arr_elem, elem_size, cache);
                    json item = interpret_field(eff, data + f.offset + i * elem_size, elem_size);
                    // Resolve enum items
                    if (cache.is_enum_type(arr_elem) && item.is_number_integer()) {
                        item = resolve_enum_value(arr_elem, item.get<int64_t>(), cache);
                    }
                    items.push_back(std::move(item));
                }
                return json::object({{"_t", "array"}, {"count", arr_count}, {"type", arr_elem}, {"items", items}});
            }
        }
    }

    // 2. Template types: CUtlVector, CHandle, CNetworkUtlVectorBase, etc.
    {
        std::string tmpl_outer, tmpl_inner;
        if (parse_template(f.type, tmpl_outer, tmpl_inner)) {
            // CUtlVector / CNetworkUtlVectorBase / CUtlVectorEmbeddedNetworkVar
            if (tmpl_outer == "CUtlVector" || tmpl_outer == "CNetworkUtlVectorBase" ||
                tmpl_outer == "CUtlVectorEmbeddedNetworkVar") {
                return read_utlvector(field_data, f.size, tmpl_inner, pipe, cache);
            }
            // CHandle<T>
            if (tmpl_outer == "CHandle") {
                if (f.size >= 4) {
                    uint32_t handle = *(const uint32_t*)field_data;
                    uint32_t index = handle & 0x7FFF;
                    uint32_t serial = handle >> 15;
                    return json::object({{"_t", "handle"}, {"raw", handle}, {"index", index},
                                         {"serial", serial}, {"type", tmpl_inner}});
                }
                return json(nullptr);
            }
        }
    }

    // 3. Pointer fields: "CBaseEntity*"
    if (!f.type.empty() && f.type.back() == '*' && f.size == 8) {
        uint64_t ptr = *(const uint64_t*)field_data;
        std::string pointed_type = f.type.substr(0, f.type.size() - 1);
        while (!pointed_type.empty() && pointed_type.back() == ' ') pointed_type.pop_back();
        char hex[32];
        snprintf(hex, sizeof(hex), "0x%llX", (unsigned long long)ptr);
        return json::object({{"_t", "ptr"}, {"addr", std::string(hex)}, {"type", pointed_type},
                             {"valid", is_valid_ptr(ptr)}});
    }

    // 4. String types: CUtlString / CUtlSymbolLarge — deref pointer to show string
    if ((f.type == "CUtlString" || f.type == "CUtlSymbolLarge") && f.size >= 8) {
        uint64_t str_ptr = *(const uint64_t*)field_data;
        char hex[32];
        snprintf(hex, sizeof(hex), "0x%llX", (unsigned long long)str_ptr);
        json val = json::object({{"_t", "string"}, {"ptr", std::string(hex)}});
        if (is_valid_ptr(str_ptr)) {
            auto str_bytes = pipe.read(str_ptr, 256);
            size_t len = 0;
            for (; len < str_bytes.size() && str_bytes[len] != 0; len++) {
                if (str_bytes[len] < 0x20 || str_bytes[len] > 0x7E) { len = 0; break; }
            }
            if (len > 0)
                val["str"] = std::string((const char*)str_bytes.data(), len);
        }
        return val;
    }

    // 5. Enum types — resolve to int, then look up name
    if (cache.is_enum_type(f.type)) {
        std::string effective_type = resolve_type(f.type, f.size, cache);
        json val = interpret_field(effective_type, field_data, f.size);
        if (val.is_number_integer()) {
            return resolve_enum_value(f.type, val.get<int64_t>(), cache);
        }
        return val;
    }

    // 6. Wrapper structs (e.g. GameTime_t → float32)
    {
        std::string wrapper_inner = cache.resolve_wrapper(f.type);
        if (!wrapper_inner.empty()) {
            return interpret_field(wrapper_inner, field_data, f.size);
        }
    }

    // 7. Embedded struct — known class with fields, inline expansion
    if (depth < 3 && f.size > 0) {
        const CachedClass* embedded = cache.find_class_any(f.type);
        if (embedded && !embedded->fields.empty()) {
            // Get flat fields for the embedded class
            std::vector<CachedField> sub_fields;
            // Try to get flat fields (with inheritance)
            sub_fields = cache.flat_fields(embedded->module, embedded->name);
            if (sub_fields.empty()) sub_fields = embedded->fields;

            json sub = json::object();
            for (const auto& sf : sub_fields) {
                int abs_off = f.offset + sf.offset;
                if (abs_off + sf.size > data_size) continue;
                sub[sf.name] = process_field(sf, data + f.offset, f.size, pipe, cache, depth + 1);
            }
            return json::object({{"_t", "struct"}, {"class", f.type}, {"module", embedded->module},
                                 {"fields", sub}});
        }
    }

    // 8. Fallback: resolve type + interpret_field
    std::string effective_type = resolve_type(f.type, f.size, cache);
    return interpret_field(effective_type, field_data, f.size);
}

// ============================================================================
// SubManager
// ============================================================================

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

SubManager::SubManager(PipeClient& pipe, SchemaCache& cache, BroadcastFn broadcast)
    : m_pipe(pipe), m_cache(cache), m_broadcast(std::move(broadcast))
{
    m_running.store(true);
    m_thread = std::thread(&SubManager::loop, this);
}

SubManager::~SubManager() { stop(); }

uint32_t SubManager::subscribe(uint64_t addr, const std::string& module,
                                const std::string& class_name, int interval_ms) {
    std::lock_guard<std::mutex> lk(m_mtx);
    uint32_t id = m_next_id++;

    Subscription sub;
    sub.id = id;
    sub.addr = addr;
    sub.module = module;
    sub.class_name = class_name;
    sub.interval_ms = std::max(interval_ms, 16); // minimum 16ms
    sub.last_tick = 0;

    m_subs[id] = std::move(sub);
    return id;
}

void SubManager::unsubscribe(uint32_t sub_id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    m_subs.erase(sub_id);
}

void SubManager::stop() {
    m_running.store(false);
    if (m_thread.joinable()) m_thread.join();
}

void SubManager::loop() {
    using json = nlohmann::json;
    log_info("SUB", "subscription thread started");

  try {
    while (m_running.load()) {
        Sleep(10); // 10ms tick

        if (!m_pipe.connected()) continue;

        int64_t now = now_ms();
        std::vector<Subscription*> due;

        {
            std::lock_guard<std::mutex> lk(m_mtx);
            for (auto& [id, sub] : m_subs) {
                if (now - sub.last_tick >= sub.interval_ms)
                    due.push_back(&sub);
            }
        }

        for (auto* sub : due) {
            // Find the class to know total size
            auto fields = m_cache.flat_fields(sub->module, sub->class_name);
            if (fields.empty()) continue;

            // Determine read size from last field
            int read_size = 0;
            for (const auto& f : fields) {
                int end = f.offset + f.size;
                if (end > read_size) read_size = end;
            }
            if (read_size == 0) continue;

            auto data = m_pipe.read(sub->addr, static_cast<uint32_t>(read_size));
            if (data.empty()) {
                // Pipe broken — notify and skip
                log_error("SUB", "pipe read failed for sub %u (addr=0x%llX, class=%s) — stopping subscriptions",
                          sub->id, (unsigned long long)sub->addr, sub->class_name.c_str());
                if (m_broadcast) {
                    json push;
                    push["cmd"] = "live.disconnected";
                    m_broadcast(push.dump());
                }
                m_running.store(false);
                break;
            }

            // Compare with last snapshot, build diff
            json changes = json::object();
            bool has_changes = false;

            for (const auto& f : fields) {
                if (f.offset + f.size > (int)data.size()) continue;

                const uint8_t* new_bytes = data.data() + f.offset;

                // Check if changed vs last snapshot
                bool changed = sub->last_snapshot.empty();
                if (!changed && f.offset + f.size <= (int)sub->last_snapshot.size()) {
                    changed = (memcmp(new_bytes, sub->last_snapshot.data() + f.offset, f.size) != 0);
                }

                if (changed) {
                    json change;
                    change["new"] = process_field(f, data.data(), (int)data.size(), m_pipe, m_cache);

                    if (!sub->last_snapshot.empty() && f.offset + f.size <= (int)sub->last_snapshot.size()) {
                        change["old"] = process_field(f, sub->last_snapshot.data(), (int)sub->last_snapshot.size(), m_pipe, m_cache);
                    }

                    changes[f.name] = std::move(change);
                    has_changes = true;
                }
            }

            sub->last_snapshot = data;
            sub->last_tick = now;

            if (has_changes && m_broadcast) {
                json push;
                push["cmd"] = "mem.diff";
                push["data"]["sub_id"] = sub->id;
                push["data"]["addr"] = (std::to_string(sub->addr));
                push["data"]["class"] = sub->class_name;
                push["data"]["changes"] = std::move(changes);
                m_broadcast(push.dump());
            }
        }
    }
  } catch (const std::exception& e) {
    log_error("SUB", "thread crashed: %s", e.what());
  } catch (...) {
    log_error("SUB", "thread crashed: unknown exception");
  }
  log_info("SUB", "subscription thread exiting");
}

// ============================================================================
// CommandDispatcher
// ============================================================================

CommandDispatcher::CommandDispatcher(SchemaCache& cache, PipeClient& pipe, SubManager& subs)
    : m_cache(cache), m_pipe(pipe), m_subs(subs) {}

// ----------------------------------------------------------------------------
// probe_entity_config — resolve CGameEntitySystem address and auto-probe
// identity stride, chunk offset, and designer name offset at runtime.
// Called once on first entity.list; results cached in m_ent_config.
// ----------------------------------------------------------------------------
void CommandDispatcher::probe_entity_config() {
    if (m_ent_config.probed) return;

    // ------------------------------------------------------------------
    // Step 1: Resolve CGameEntitySystem address (3-tier fallback)
    // ------------------------------------------------------------------
    uint64_t ges_ptr = 0;

    // Tier 1: Pattern globals — dwGameEntitySystem or dwEntityList
    {
        uint32_t ges_rva = 0;
        std::string ges_module;
        for (const auto& pg : m_cache.pattern_globals()) {
            if (pg.name == "dwGameEntitySystem") {
                ges_rva = pg.rva; ges_module = pg.module; break;
            }
        }
        if (ges_rva == 0) {
            for (const auto& pg : m_cache.pattern_globals()) {
                if (pg.name == "dwEntityList") {
                    ges_rva = pg.rva; ges_module = pg.module; break;
                }
            }
        }
        if (ges_rva != 0) {
            uint64_t mod_base = m_pipe.module_base(ges_module);
            if (mod_base != 0) {
                auto ptr_data = m_pipe.read(mod_base + ges_rva, 8);
                if (ptr_data.size() == 8)
                    ges_ptr = *(const uint64_t*)ptr_data.data();
            }
        }
    }

    // Tier 2: Discovered globals — any global with class_name == "CGameEntitySystem"
    if (!is_valid_ptr(ges_ptr)) {
        for (const auto& g : m_cache.all_globals()) {
            if (g.class_name == "CGameEntitySystem" && g.is_pointer && g.global_rva != 0) {
                uint64_t mod_base = m_pipe.module_base(g.module);
                if (mod_base == 0) continue;
                auto ptr_data = m_pipe.read(mod_base + g.global_rva, 8);
                if (ptr_data.size() == 8) {
                    uint64_t candidate = *(const uint64_t*)ptr_data.data();
                    if (is_valid_ptr(candidate)) {
                        ges_ptr = candidate;
                        log_info("ENT", "resolved CGameEntitySystem from discovered global (RVA 0x%X in %s)",
                                 g.global_rva, g.module.c_str());
                        break;
                    }
                }
            }
        }
    }

    if (!is_valid_ptr(ges_ptr))
        throw std::runtime_error("CGameEntitySystem not found via pattern or discovered globals");

    m_ent_config.ges_addr = ges_ptr;

    // ------------------------------------------------------------------
    // Step 2: Schema-resolve CEntityIdentity size + designer name offset
    // ------------------------------------------------------------------
    int schema_stride = 0;
    int schema_designer_offset = 0;
    for (const auto& mod_name : m_cache.modules()) {
        const CachedClass* id_cls = m_cache.find_class(mod_name, "CEntityIdentity");
        if (id_cls && id_cls->size > 0) {
            schema_stride = id_cls->size;
            auto flat = m_cache.flat_fields(mod_name, "CEntityIdentity");
            for (const auto& f : flat) {
                if (f.name == "m_designerName") {
                    schema_designer_offset = f.offset;
                    break;
                }
            }
            break;
        }
    }

    // ------------------------------------------------------------------
    // Step 3: Probe chunk table offset in CGameEntitySystem
    //   Scan qwords at offsets 0x08..0x80, dereference as chunk pointer,
    //   check if first identity slot has a valid entity pointer with a vtable.
    // ------------------------------------------------------------------
    auto probe_chunk_offset = [&](int stride) -> int {
        for (int off = 0x08; off <= 0x80; off += 8) {
            auto qw = m_pipe.read(ges_ptr + off, 8);
            if (qw.size() != 8) continue;
            uint64_t chunk_ptr = *(const uint64_t*)qw.data();
            if (!is_valid_ptr(chunk_ptr)) continue;

            // Read first identity slot
            auto id_data = m_pipe.read(chunk_ptr, std::max(stride, 8));
            if ((int)id_data.size() < 8) continue;
            uint64_t ent_ptr = *(const uint64_t*)id_data.data();
            if (!is_valid_ptr(ent_ptr)) continue;

            // Check if entity has a valid vtable
            auto vt = m_pipe.read(ent_ptr, 8);
            if (vt.size() != 8) continue;
            uint64_t vtable = *(const uint64_t*)vt.data();
            if (is_valid_ptr(vtable)) {
                log_info("ENT", "probed chunk_offset = 0x%X", off);
                return off;
            }
        }
        return 0x10; // fallback
    };

    // ------------------------------------------------------------------
    // Step 4: Probe identity stride
    //   Try candidates and score by counting valid entity pointers in first chunk.
    // ------------------------------------------------------------------
    auto probe_stride = [&](uint64_t chunk_ptr) -> int {
        const int candidates[] = { 0x70, 0x78, 0x80 };
        int best_stride = 0x70;
        int best_score = -1;

        for (int stride : candidates) {
            int score = 0;
            // Check slots 0..7
            for (int s = 0; s < 8; s++) {
                auto slot_data = m_pipe.read(chunk_ptr + (uint64_t)s * stride, 8);
                if (slot_data.size() != 8) continue;
                uint64_t ent_ptr = *(const uint64_t*)slot_data.data();
                if (!is_valid_ptr(ent_ptr)) continue;
                auto vt = m_pipe.read(ent_ptr, 8);
                if (vt.size() != 8) continue;
                uint64_t vtable = *(const uint64_t*)vt.data();
                if (is_valid_ptr(vtable)) score++;
            }
            if (score > best_score) {
                best_score = score;
                best_stride = stride;
            }
        }
        log_info("ENT", "probed identity_stride = 0x%X (score=%d)", best_stride, best_score);
        return best_stride;
    };

    // ------------------------------------------------------------------
    // Step 5: Probe designer name offset in CEntityIdentity
    //   Read full identity struct, check qwords for valid string pointers.
    // ------------------------------------------------------------------
    auto probe_designer_name = [&](uint64_t chunk_ptr, int stride) -> int {
        // Read first non-null identity
        uint64_t identity_addr = 0;
        for (int s = 0; s < 16; s++) {
            auto slot_data = m_pipe.read(chunk_ptr + (uint64_t)s * stride, 8);
            if (slot_data.size() != 8) continue;
            uint64_t ent_ptr = *(const uint64_t*)slot_data.data();
            if (is_valid_ptr(ent_ptr)) {
                identity_addr = chunk_ptr + (uint64_t)s * stride;
                break;
            }
        }
        if (identity_addr == 0) return 0x20; // fallback

        auto id_bytes = m_pipe.read(identity_addr, stride);
        if ((int)id_bytes.size() < stride) return 0x20;

        // Check each qword offset for a pointer to a printable ASCII string
        // that looks like a Source 2 designer name (lowercase, underscores)
        for (int off = 0x08; off <= stride - 8; off += 8) {
            uint64_t str_ptr = *(const uint64_t*)(id_bytes.data() + off);
            if (!is_valid_ptr(str_ptr)) continue;

            auto str_data = m_pipe.read(str_ptr, 64);
            if (str_data.empty()) continue;

            // Check if it looks like a designer name
            size_t len = 0;
            bool has_underscore = false;
            bool all_valid = true;
            for (; len < str_data.size(); len++) {
                uint8_t ch = str_data[len];
                if (ch == 0) break;
                if (ch >= 0x80 || (ch < 0x20 && ch != 0)) { all_valid = false; break; }
                if (ch == '_') has_underscore = true;
            }
            if (!all_valid || len < 3) continue;

            // Designer names typically: lowercase + underscores, no spaces
            // e.g. "citadel_hero_*", "npc_*", "prop_*", "trigger_*"
            std::string candidate((const char*)str_data.data(), len);
            bool looks_like_name = has_underscore && len < 128;
            if (looks_like_name) {
                // Extra check: mostly lowercase/digits/underscores
                int lower_count = 0;
                for (char c : candidate) {
                    if ((c >= 'a' && c <= 'z') || c == '_' || (c >= '0' && c <= '9')) lower_count++;
                }
                if (lower_count > (int)(len * 0.6)) {
                    log_info("ENT", "probed designer_name_offset = 0x%X (sample: %.32s)",
                             off, candidate.c_str());
                    return off;
                }
            }
        }
        return 0x20; // fallback
    };

    // ------------------------------------------------------------------
    // Run probes in order
    // ------------------------------------------------------------------

    // Use schema stride if available, otherwise probe
    int stride_hint = schema_stride > 0 ? schema_stride : 0x70;
    int chunk_offset = probe_chunk_offset(stride_hint);
    m_ent_config.chunk_offset = chunk_offset;

    // Get first chunk pointer for further probing
    auto chunk0_data = m_pipe.read(ges_ptr + chunk_offset, 8);
    if (chunk0_data.size() == 8) {
        uint64_t chunk0 = *(const uint64_t*)chunk0_data.data();
        if (is_valid_ptr(chunk0)) {
            if (schema_stride > 0) {
                m_ent_config.identity_stride = schema_stride;
                log_info("ENT", "using schema identity_stride = 0x%X", schema_stride);
            } else {
                m_ent_config.identity_stride = probe_stride(chunk0);
            }

            if (schema_designer_offset > 0) {
                m_ent_config.designer_name_offset = schema_designer_offset;
                log_info("ENT", "using schema designer_name_offset = 0x%X", schema_designer_offset);
            } else {
                m_ent_config.designer_name_offset = probe_designer_name(chunk0, m_ent_config.identity_stride);
            }
        }
    }

    m_ent_config.probed = true;
    log_info("ENT", "entity config probed: ges=0x%llX chunk_off=0x%X stride=0x%X designer=0x%X",
             (unsigned long long)m_ent_config.ges_addr,
             m_ent_config.chunk_offset,
             m_ent_config.identity_stride,
             m_ent_config.designer_name_offset);
}

std::string CommandDispatcher::dispatch(const std::string& message) {
    using json = nlohmann::json;

    json req;
    try {
        req = json::parse(message);
    } catch (...) {
        log_error("CMD", "invalid JSON received: %.100s", message.c_str());
        json resp;
        resp["ok"] = false;
        resp["error"] = "invalid JSON";
        return resp.dump();
    }

    int id = req.value("id", 0);
    std::string cmd = req.value("cmd", "");
    json args = req.value("args", json::object());

    json result;
    try {
        log_info("CMD", ">> %s (id=%d)", cmd.c_str(), id);
        result = handle(cmd, args);
        log_info("CMD", "<< %s (id=%d) OK", cmd.c_str(), id);
    } catch (const std::exception& e) {
        log_error("CMD", "cmd '%s' (id=%d) failed: %s", cmd.c_str(), id, e.what());
        json resp;
        resp["id"] = id;
        resp["ok"] = false;
        resp["error"] = e.what();
        return resp.dump();
    } catch (...) {
        log_error("CMD", "cmd '%s' (id=%d) unknown exception!", cmd.c_str(), id);
        json resp;
        resp["id"] = id;
        resp["ok"] = false;
        resp["error"] = "unknown exception in " + cmd;
        return resp.dump();
    }

    json resp;
    resp["id"] = id;
    resp["ok"] = true;
    resp["data"] = std::move(result);
    return resp.dump();
}

static uint64_t parse_addr(const std::string& s) {
    if (s.empty()) return 0;
    return std::stoull(s, nullptr, 0); // handles 0x prefix
}

nlohmann::json CommandDispatcher::handle(const std::string& cmd, const nlohmann::json& args) {
    using json = nlohmann::json;

    // ---- ping ----
    if (cmd == "ping") {
        return json("pong");
    }

    // ---- schema.modules ----
    if (cmd == "schema.modules") {
        return json(m_cache.modules());
    }

    // ---- schema.classes ----
    if (cmd == "schema.classes") {
        std::string mod = args.value("module", "");
        auto classes = m_cache.classes_in_module(mod);
        json arr = json::array();
        for (auto* cls : classes) {
            json c;
            c["name"] = cls->name;
            c["size"] = cls->size;
            c["parent"] = cls->parent.empty() ? json(nullptr) : json(cls->parent);
            c["field_count"] = (int)cls->fields.size();
            arr.push_back(std::move(c));
        }
        return arr;
    }

    // ---- schema.class ----
    if (cmd == "schema.class") {
        std::string mod = args.value("module", "");
        std::string name = args.value("name", "");
        auto* cls = m_cache.find_class(mod, name);
        if (!cls) throw std::runtime_error("class not found: " + mod + "::" + name);

        json c;
        c["name"] = cls->name;
        c["module"] = cls->module;
        c["size"] = cls->size;
        c["parent"] = cls->parent.empty() ? json(nullptr) : json(cls->parent);
        c["inheritance_chain"] = json(cls->inheritance);
        c["metadata"] = json(cls->metadata);

        json fields = json::array();
        for (const auto& f : cls->fields) {
            json fj;
            fj["name"] = f.name;
            fj["type"] = f.type;
            fj["offset"] = f.offset;
            fj["size"] = f.size;
            fields.push_back(std::move(fj));
        }
        c["fields"] = std::move(fields);

        json sfields = json::array();
        for (const auto& f : cls->static_fields) {
            json fj;
            fj["name"] = f.name;
            fj["type"] = f.type;
            fj["offset"] = f.offset;
            fj["size"] = f.size;
            sfields.push_back(std::move(fj));
        }
        c["static_fields"] = std::move(sfields);

        return c;
    }

    // ---- schema.enums ----
    if (cmd == "schema.enums") {
        std::string mod = args.value("module", "");
        auto enums = m_cache.enums_in_module(mod);
        json arr = json::array();
        for (auto* en : enums) {
            json e;
            e["name"] = en->name;
            e["size"] = en->size;
            e["value_count"] = (int)en->values.size();
            arr.push_back(std::move(e));
        }
        return arr;
    }

    // ---- schema.enum ----
    if (cmd == "schema.enum") {
        std::string mod = args.value("module", "");
        std::string name = args.value("name", "");
        auto* en = m_cache.find_enum(mod, name);
        if (!en) throw std::runtime_error("enum not found: " + mod + "::" + name);

        json e;
        e["name"] = en->name;
        e["module"] = en->module;
        e["size"] = en->size;

        json vals = json::array();
        for (const auto& [vname, vval] : en->values) {
            json v;
            v["name"] = vname;
            v["value"] = vval;
            vals.push_back(std::move(v));
        }
        e["values"] = std::move(vals);
        return e;
    }

    // ---- schema.search ----
    if (cmd == "schema.search") {
        std::string query = args.value("query", "");
        if (query.empty()) throw std::runtime_error("query required");
        auto results = m_cache.search(query);
        json arr = json::array();
        for (const auto& [mod, name] : results) {
            json r;
            r["module"] = mod;
            r["name"] = name;
            arr.push_back(std::move(r));
        }
        return arr;
    }

    // ---- global.list ----
    if (cmd == "global.list") {
        auto globals = m_cache.all_globals();
        json arr = json::array();
        for (const auto& g : globals) {
            json gj;
            gj["class_name"] = g.class_name;
            gj["module"] = g.module;

            char rva_buf[32];
            snprintf(rva_buf, sizeof(rva_buf), "0x%X", g.global_rva);
            gj["global_rva"] = rva_buf;

            snprintf(rva_buf, sizeof(rva_buf), "0x%X", g.vtable_rva);
            gj["vtable_rva"] = rva_buf;

            gj["is_pointer"] = g.is_pointer;
            gj["has_schema"] = g.has_schema;
            arr.push_back(std::move(gj));
        }
        return arr;
    }

    // ---- Commands below require a live pipe connection ----
    if ((cmd.rfind("mem.", 0) == 0 || cmd.rfind("module.", 0) == 0 || cmd.rfind("entity.", 0) == 0)
        && !m_pipe.connected()) {
        throw std::runtime_error("not connected to game (no pipe) — " + cmd + " requires a live connection");
    }

    // ---- mem.read ----
    if (cmd == "mem.read") {
        std::string addr_str = args.value("addr", "");
        uint64_t addr = parse_addr(addr_str);
        int size = args.value("size", 64);
        if (addr == 0) throw std::runtime_error("invalid address");
        if (size <= 0 || size > 65536) throw std::runtime_error("invalid size");

        auto data = m_pipe.read(addr, static_cast<uint32_t>(size));
        if (data.empty()) throw std::runtime_error("read failed (SEH or pipe error)");

        // Return as hex string
        std::string hex;
        for (size_t i = 0; i < data.size(); i++) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02X", data[i]);
            hex += buf;
            if (i + 1 < data.size()) hex += ' ';
        }

        json result;
        result["addr"] = addr_str;
        result["size"] = (int)data.size();
        result["hex"] = hex;
        return result;
    }

    // ---- mem.read_object ----
    if (cmd == "mem.read_object") {
        std::string addr_str = args.value("addr", "");
        uint64_t addr = parse_addr(addr_str);
        std::string mod = args.value("module", "");
        std::string cls_name = args.value("class", "");

        if (addr == 0) throw std::runtime_error("invalid address");

        auto fields = m_cache.flat_fields(mod, cls_name);
        if (fields.empty()) throw std::runtime_error("class not found or has no fields");

        // Determine read size
        int read_size = 0;
        for (const auto& f : fields) {
            int end = f.offset + f.size;
            if (end > read_size) read_size = end;
        }

        auto data = m_pipe.read(addr, static_cast<uint32_t>(read_size));
        if (data.empty()) throw std::runtime_error("read failed");

        json result = json::object();
        for (const auto& f : fields) {
            if (f.offset + f.size > (int)data.size()) continue;
            result[f.name] = process_field(f, data.data(), (int)data.size(), m_pipe, m_cache);
        }
        return result;
    }

    // mem.write_field removed — this tool is read-only.

    // ---- mem.subscribe ----
    if (cmd == "mem.subscribe") {
        std::string addr_str = args.value("addr", "");
        uint64_t addr = parse_addr(addr_str);
        std::string mod = args.value("module", "");
        std::string cls_name = args.value("class", "");
        int interval_ms = args.value("interval_ms", 100);

        if (addr == 0) throw std::runtime_error("invalid address");

        uint32_t sub_id = m_subs.subscribe(addr, mod, cls_name, interval_ms);
        json result;
        result["sub_id"] = sub_id;
        return result;
    }

    // ---- mem.unsubscribe ----
    if (cmd == "mem.unsubscribe") {
        uint32_t sub_id = args.value("sub_id", (uint32_t)0);
        m_subs.unsubscribe(sub_id);
        return json(true);
    }

    // ---- module.base ----
    if (cmd == "module.base") {
        std::string mod = args.value("module", "");
        if (mod.empty()) throw std::runtime_error("module name required");
        uint64_t base = m_pipe.module_base(mod);
        if (base == 0) throw std::runtime_error("module not found: " + mod);
        char hex[32];
        snprintf(hex, sizeof(hex), "0x%llX", (unsigned long long)base);
        json result;
        result["module"] = mod;
        result["base"] = std::string(hex);
        return result;
    }

    // ---- entity.config ----
    if (cmd == "entity.config") {
        probe_entity_config();
        char hex[32];
        snprintf(hex, sizeof(hex), "0x%llX", (unsigned long long)m_ent_config.ges_addr);
        json result;
        result["ges_addr"] = std::string(hex);
        result["chunk_offset"] = m_ent_config.chunk_offset;
        result["max_chunks"] = m_ent_config.max_chunks;
        result["chunk_size"] = m_ent_config.chunk_size;
        result["identity_stride"] = m_ent_config.identity_stride;
        result["designer_name_offset"] = m_ent_config.designer_name_offset;
        result["probed"] = m_ent_config.probed;
        return result;
    }

    // ---- entity.list ----
    if (cmd == "entity.list") {
        // Ensure entity system config is probed (cached after first call)
        probe_entity_config();

        const int IDENTITY_SIZE = m_ent_config.identity_stride;
        const int DESIGNER_NAME_OFFSET = m_ent_config.designer_name_offset;
        const int CHUNK_OFFSET = m_ent_config.chunk_offset;
        const int CHUNK_SIZE = m_ent_config.chunk_size;
        const uint64_t ges_ptr = m_ent_config.ges_addr;

        int max_chunks = args.value("max_chunks", m_ent_config.max_chunks);
        if (max_chunks > m_ent_config.max_chunks) max_chunks = m_ent_config.max_chunks;

        // Read the inline chunk pointer array
        auto chunk_table = m_pipe.read(ges_ptr + CHUNK_OFFSET, max_chunks * 8);
        if (chunk_table.size() < (size_t)(max_chunks * 8))
            throw std::runtime_error("failed to read chunk pointer table");

        // Build vtable->class name lookup from RTTI vtables + globals
        std::unordered_map<uint64_t, std::string> vtable_lookup;
        log_info("ENT", "building vtable lookup from %zu rtti vtables...",
                 m_cache.rtti_vtables().size());

        // Cache module bases to avoid repeated pipe calls
        std::unordered_map<std::string, uint64_t> mod_base_cache;
        auto get_mod_base = [&](const std::string& mod) -> uint64_t {
            auto it = mod_base_cache.find(mod);
            if (it != mod_base_cache.end()) return it->second;
            uint64_t base = m_pipe.module_base(mod);
            mod_base_cache[mod] = base;
            return base;
        };

        for (const auto& rv : m_cache.rtti_vtables()) {
            uint64_t vt_base = get_mod_base(rv.module);
            if (vt_base != 0)
                vtable_lookup[vt_base + rv.vtable_rva] = rv.class_name;
        }
        for (const auto& g : m_cache.all_globals()) {
            if (g.vtable_rva != 0 && !g.class_name.empty()) {
                uint64_t vt_base = get_mod_base(g.module);
                if (vt_base != 0)
                    vtable_lookup[vt_base + g.vtable_rva] = g.class_name;
            }
        }
        log_info("ENT", "vtable lookup built: %zu entries from %zu module bases",
                 vtable_lookup.size(), mod_base_cache.size());

        // RTTI chain walk: entity vtable -> vtable[-1] (COL) -> COL+0xC (TD RVA)
        // -> module_base + TD_RVA + 0x10 (mangled name)
        auto resolve_rtti = [&](uint64_t vtable) -> std::string {
            if (!is_valid_ptr(vtable)) return "";
            auto col_data = m_pipe.read(vtable - 8, 8);
            if (col_data.size() != 8) return "";
            uint64_t col_ptr = *(const uint64_t*)col_data.data();
            if (!is_valid_ptr(col_ptr)) return "";

            auto col_fields = m_pipe.read(col_ptr + 0x0C, 12);
            if (col_fields.size() != 12) return "";
            uint32_t td_rva   = *(const uint32_t*)(col_fields.data() + 0);
            uint32_t self_rva = *(const uint32_t*)(col_fields.data() + 8);
            if (td_rva == 0 || self_rva == 0) return "";

            uint64_t owning_base = col_ptr - (uint64_t)self_rva;
            uint64_t td_addr = owning_base + td_rva;
            auto name_data = m_pipe.read(td_addr + 0x10, 128);
            if (name_data.empty()) return "";

            name_data.push_back(0);
            size_t len = 0;
            for (; len < name_data.size() - 1; len++) {
                uint8_t ch = name_data[len];
                if (ch == 0 || ch >= 0x80 || (ch < 0x20 && ch != 0)) break;
            }
            if (len == 0) return "";
            std::string mangled((const char*)name_data.data(), len);
            if (mangled.size() >= 4 && (mangled.substr(0, 4) == ".?AV" || mangled.substr(0, 4) == ".?AU"))
                mangled = mangled.substr(4);
            auto at_pos = mangled.find("@@");
            if (at_pos != std::string::npos)
                mangled = mangled.substr(0, at_pos);
            return mangled;
        };

        json entities = json::array();
        log_info("ENT", "enumerating %d chunks...", max_chunks);

        for (int ci = 0; ci < max_chunks; ci++) {
            uint64_t chunk_ptr = *(const uint64_t*)(chunk_table.data() + ci * 8);
            if (!is_valid_ptr(chunk_ptr)) continue;

            constexpr int BATCH = 64;
            const int BATCH_BYTES = BATCH * IDENTITY_SIZE;

            for (int batch_start = 0; batch_start < CHUNK_SIZE; batch_start += BATCH) {
                uint64_t read_addr = chunk_ptr + (uint64_t)batch_start * IDENTITY_SIZE;
                auto batch_data = m_pipe.read(read_addr, BATCH_BYTES);
                if (batch_data.size() < (size_t)BATCH_BYTES) break;

                for (int slot = 0; slot < BATCH; slot++) {
                    const uint8_t* identity = batch_data.data() + slot * IDENTITY_SIZE;

                    uint64_t ent_ptr = *(const uint64_t*)(identity + 0x00);
                    if (!is_valid_ptr(ent_ptr)) continue;

                    int index = ci * CHUNK_SIZE + batch_start + slot;

                    auto vt_data = m_pipe.read(ent_ptr, 8);
                    std::string class_name = "Unknown";
                    if (vt_data.size() == 8) {
                        uint64_t vtable = *(const uint64_t*)vt_data.data();
                        auto it = vtable_lookup.find(vtable);
                        if (it != vtable_lookup.end()) {
                            class_name = it->second;
                        } else {
                            std::string rtti_name = resolve_rtti(vtable);
                            if (!rtti_name.empty()) {
                                class_name = rtti_name;
                                vtable_lookup[vtable] = rtti_name;
                            }
                        }
                    }

                    std::string designer_name;
                    uint64_t name_sym = 0;
                    if (DESIGNER_NAME_OFFSET + 8 <= IDENTITY_SIZE)
                        name_sym = *(const uint64_t*)(identity + DESIGNER_NAME_OFFSET);
                    if (is_valid_ptr(name_sym)) {
                        auto name_bytes = m_pipe.read(name_sym, 128);
                        if (!name_bytes.empty()) {
                            size_t nlen = 0;
                            for (; nlen < name_bytes.size(); nlen++) {
                                uint8_t ch = name_bytes[nlen];
                                if (ch == 0 || ch >= 0x80 || (ch < 0x20 && ch != 0)) break;
                            }
                            if (nlen > 0)
                                designer_name.assign((const char*)name_bytes.data(), nlen);
                        }
                    }

                    char addr_hex[32];
                    snprintf(addr_hex, sizeof(addr_hex), "0x%llX", (unsigned long long)ent_ptr);

                    json ent;
                    ent["index"] = index;
                    ent["addr"] = std::string(addr_hex);
                    ent["class"] = class_name;
                    if (!designer_name.empty())
                        ent["designer_name"] = designer_name;
                    entities.push_back(std::move(ent));
                }
            }
        }

        log_info("ENT", "enumeration done: %d entities found", (int)entities.size());

        json result;
        result["count"] = (int)entities.size();
        result["entities"] = std::move(entities);
        return result;
    }

    // ---- mem.deref ----
    if (cmd == "mem.deref") {
        std::string addr_str = args.value("addr", "");
        uint64_t addr = parse_addr(addr_str);
        std::string field_type = args.value("type", "");
        std::string mod = args.value("module", "");
        int fallback_size = args.value("size", 64);

        if (addr == 0) throw std::runtime_error("invalid address");

        // First dereference the pointer
        auto ptr_data = m_pipe.read(addr, 8);
        if (ptr_data.size() < 8) throw std::runtime_error("read failed");
        uint64_t target = *(const uint64_t*)ptr_data.data();

        // If it's a string type, read and return the string
        if (field_type == "CUtlSymbolLarge" || field_type == "CUtlString") {
            if (!is_valid_ptr(target)) {
                json r; r["kind"] = "raw"; r["hex"] = "NULL"; return r;
            }
            auto str_bytes = m_pipe.read(target, 256);
            size_t len = 0;
            for (; len < str_bytes.size() && str_bytes[len] != 0; len++) {
                if (str_bytes[len] < 0x20 || str_bytes[len] > 0x7E) { len = 0; break; }
            }
            json r;
            r["kind"] = "string";
            r["value"] = len > 0 ? std::string((const char*)str_bytes.data(), len) : "";
            char hex[32]; snprintf(hex, sizeof(hex), "0x%llX", (unsigned long long)target);
            r["ptr"] = std::string(hex);
            return r;
        }

        // If the type is a known schema class, read its fields
        if (!field_type.empty() && !mod.empty()) {
            // Strip pointer suffix if present (e.g. "CBaseEntity*" -> "CBaseEntity")
            std::string cls = field_type;
            if (!cls.empty() && cls.back() == '*') cls.pop_back();

            auto fields = m_cache.flat_fields(mod, cls);
            if (!fields.empty() && is_valid_ptr(target)) {
                int read_size = 0;
                for (const auto& f : fields) {
                    int end = f.offset + f.size;
                    if (end > read_size) read_size = end;
                }
                auto obj_data = m_pipe.read(target, static_cast<uint32_t>(read_size));
                if (!obj_data.empty()) {
                    json obj_fields = json::object();
                    for (const auto& f : fields) {
                        if (f.offset + f.size > (int)obj_data.size()) continue;
                        obj_fields[f.name] = process_field(f, obj_data.data(), (int)obj_data.size(), m_pipe, m_cache);
                    }
                    json r;
                    r["kind"] = "object";
                    r["class"] = cls;
                    r["fields"] = std::move(obj_fields);
                    char hex[32]; snprintf(hex, sizeof(hex), "0x%llX", (unsigned long long)target);
                    r["addr"] = std::string(hex);
                    return r;
                }
            }
        }

        // Fallback: read raw bytes
        if (!is_valid_ptr(target)) {
            json r; r["kind"] = "raw"; r["hex"] = "NULL"; return r;
        }
        auto raw = m_pipe.read(target, static_cast<uint32_t>(std::min(fallback_size, 256)));
        std::string hex;
        for (size_t i = 0; i < raw.size(); i++) {
            char buf[4]; snprintf(buf, sizeof(buf), "%02X", raw[i]);
            hex += buf;
            if (i + 1 < raw.size()) hex += ' ';
        }
        json r;
        r["kind"] = "raw";
        r["hex"] = hex;
        char ahex[32]; snprintf(ahex, sizeof(ahex), "0x%llX", (unsigned long long)target);
        r["addr"] = std::string(ahex);
        return r;
    }

    // ---- entity.search ----
    if (cmd == "entity.search") {
        probe_entity_config();

        std::string field_filter = args.value("field", "");
        std::string value_filter = args.value("value", "");
        std::string class_filter = args.value("class_filter", "");
        int max_results = args.value("max_results", 50);

        if (field_filter.empty() && value_filter.empty())
            throw std::runtime_error("at least one of 'field' or 'value' must be specified");

        // Convert filters to lowercase for case-insensitive match
        std::string lf_field = field_filter, lf_value = value_filter, lf_class = class_filter;
        for (auto& c : lf_field) c = (char)tolower((unsigned char)c);
        for (auto& c : lf_value) c = (char)tolower((unsigned char)c);
        for (auto& c : lf_class) c = (char)tolower((unsigned char)c);

        const int IDENTITY_SIZE = m_ent_config.identity_stride;
        const int CHUNK_OFFSET = m_ent_config.chunk_offset;
        const int CHUNK_SIZE = m_ent_config.chunk_size;
        const uint64_t ges_ptr = m_ent_config.ges_addr;

        auto chunk_table = m_pipe.read(ges_ptr + CHUNK_OFFSET, m_ent_config.max_chunks * 8);
        if (chunk_table.size() < (size_t)(m_ent_config.max_chunks * 8))
            throw std::runtime_error("failed to read chunk table");

        // Build vtable lookup (reuse entity.list logic)
        std::unordered_map<uint64_t, std::string> vtable_lookup;
        for (const auto& rv : m_cache.rtti_vtables()) {
            uint64_t vt_base = m_pipe.module_base(rv.module);
            if (vt_base != 0) vtable_lookup[vt_base + rv.vtable_rva] = rv.class_name;
        }

        json matches = json::array();
        int found = 0;

        for (int ci = 0; ci < m_ent_config.max_chunks && found < max_results; ci++) {
            uint64_t chunk_ptr = *(const uint64_t*)(chunk_table.data() + ci * 8);
            if (!is_valid_ptr(chunk_ptr)) continue;

            constexpr int BATCH = 64;
            for (int batch_start = 0; batch_start < CHUNK_SIZE && found < max_results; batch_start += BATCH) {
                auto batch_data = m_pipe.read(chunk_ptr + (uint64_t)batch_start * IDENTITY_SIZE, BATCH * IDENTITY_SIZE);
                if ((int)batch_data.size() < BATCH * IDENTITY_SIZE) break;

                for (int slot = 0; slot < BATCH && found < max_results; slot++) {
                    uint64_t ent_ptr = *(const uint64_t*)(batch_data.data() + slot * IDENTITY_SIZE);
                    if (!is_valid_ptr(ent_ptr)) continue;

                    // Resolve class name via vtable
                    auto vt_data = m_pipe.read(ent_ptr, 8);
                    if (vt_data.size() != 8) continue;
                    uint64_t vtable = *(const uint64_t*)vt_data.data();
                    auto it = vtable_lookup.find(vtable);
                    if (it == vtable_lookup.end()) continue;
                    std::string cls_name = it->second;

                    // Class filter
                    if (!lf_class.empty()) {
                        std::string lcls = cls_name;
                        for (auto& c : lcls) c = (char)tolower((unsigned char)c);
                        if (lcls.find(lf_class) == std::string::npos) continue;
                    }

                    // Find the class module and fields
                    std::string cls_mod;
                    std::vector<CachedField> fields;
                    for (const auto& mod_name : m_cache.modules()) {
                        fields = m_cache.flat_fields(mod_name, cls_name);
                        if (!fields.empty()) { cls_mod = mod_name; break; }
                    }
                    if (fields.empty()) continue;

                    // Read entity memory
                    int read_size = 0;
                    for (const auto& f : fields) {
                        int end = f.offset + f.size;
                        if (end > read_size) read_size = end;
                    }
                    auto ent_data = m_pipe.read(ent_ptr, static_cast<uint32_t>(read_size));
                    if (ent_data.empty()) continue;

                    // Search fields
                    for (const auto& f : fields) {
                        if (f.offset + f.size > (int)ent_data.size()) continue;

                        // Field name filter
                        if (!lf_field.empty()) {
                            std::string lname = f.name;
                            for (auto& c : lname) c = (char)tolower((unsigned char)c);
                            if (lname.find(lf_field) == std::string::npos) continue;
                        }

                        json val = process_field(f, ent_data.data(), (int)ent_data.size(), m_pipe, m_cache);
                        std::string val_str = val.is_string() ? val.get<std::string>() : val.dump();

                        // Value filter
                        if (!lf_value.empty()) {
                            std::string lval = val_str;
                            for (auto& c : lval) c = (char)tolower((unsigned char)c);
                            if (lval.find(lf_value) == std::string::npos) continue;
                        }

                        int index = ci * CHUNK_SIZE + batch_start + slot;
                        char addr_hex[32];
                        snprintf(addr_hex, sizeof(addr_hex), "0x%llX", (unsigned long long)ent_ptr);

                        json match;
                        match["entity_index"] = index;
                        match["addr"] = std::string(addr_hex);
                        match["class"] = cls_name;
                        match["module"] = cls_mod;
                        match["field_name"] = f.name;
                        match["field_value"] = val;
                        matches.push_back(std::move(match));
                        found++;
                        if (found >= max_results) break;
                    }
                }
            }
        }

        json result;
        result["count"] = found;
        result["matches"] = std::move(matches);
        return result;
    }

    throw std::runtime_error("unknown command: " + cmd);
}

} // namespace live
