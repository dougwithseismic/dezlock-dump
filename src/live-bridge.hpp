#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include "vendor/json.hpp"

namespace live {

// ============================================================================
// Logging — set from main.cpp to route errors to console + log file
// ============================================================================

// Callback signature: (tag, formatted message)
using LogFn = std::function<void(const char* tag, const char* msg)>;
void set_logger(LogFn fn);

// Internal use — call from live-bridge.cpp / ws-server.cpp
void log_error(const char* tag, const char* fmt, ...);
void log_info(const char* tag, const char* fmt, ...);

// ============================================================================
// PipeClient — connects to the DLL's named pipe for memory reads
// ============================================================================

class PipeClient {
public:
    PipeClient();
    ~PipeClient();

    bool connect(const char* pipe_name = "\\\\.\\pipe\\dezlock-live");
    void disconnect();
    bool connected() const;

    // Read `size` bytes from `addr` in the game process. Empty on failure.
    std::vector<uint8_t> read(uint64_t addr, uint32_t size);

    // Send shutdown command to DLL
    bool shutdown();

    // Get base address of a loaded module by name
    uint64_t module_base(const std::string& name);

private:
    void* m_pipe; // HANDLE
    mutable std::mutex m_mtx; // serialize all pipe I/O
};

// ============================================================================
// SchemaCache — indexed in-memory copy of the JSON export
// ============================================================================

struct CachedField {
    std::string name;
    std::string type;
    int offset = 0;
    int size = 0;
};

struct CachedClass {
    std::string name;
    std::string module;
    int size = 0;
    std::string parent;
    std::vector<std::string> inheritance;
    std::vector<std::string> metadata;
    std::vector<CachedField> fields;
    std::vector<CachedField> static_fields;
};

struct CachedEnum {
    std::string name;
    std::string module;
    int size = 0;
    std::vector<std::pair<std::string, int64_t>> values;
};

struct PatternGlobal {
    std::string name;
    std::string module;
    uint32_t rva = 0;
};

struct CachedGlobal {
    std::string class_name;
    std::string module;
    uint32_t global_rva = 0;
    uint32_t vtable_rva = 0;
    bool is_pointer = false;
    bool has_schema = false;
};

struct RttiVtable {
    std::string class_name;
    std::string module;
    uint32_t vtable_rva = 0;
};

class SchemaCache {
public:
    bool load(const nlohmann::json& data);

    // Module listing
    std::vector<std::string> modules() const;

    // Class queries
    std::vector<const CachedClass*> classes_in_module(const std::string& mod) const;
    const CachedClass* find_class(const std::string& mod, const std::string& name) const;

    // Enum queries
    std::vector<const CachedEnum*> enums_in_module(const std::string& mod) const;
    const CachedEnum* find_enum(const std::string& mod, const std::string& name) const;

    // Globals
    std::vector<CachedGlobal> all_globals() const;

    // Pattern globals (dwEntityList, dwViewMatrix, etc.)
    std::vector<PatternGlobal> pattern_globals() const;

    // RTTI vtables (all classes with vtable RVAs from modules)
    const std::vector<RttiVtable>& rtti_vtables() const;

    // Flat field layout (own + inherited)
    std::vector<CachedField> flat_fields(const std::string& mod, const std::string& name) const;

    // Check if a type name is a known enum (across all modules)
    bool is_enum_type(const std::string& name) const;

    // Resolve single-field wrapper structs (e.g. GameTime_t -> float32)
    // Returns the inner primitive type, or empty string if not a wrapper.
    std::string resolve_wrapper(const std::string& name) const;

    // Find a class by name across all modules (returns first match)
    const CachedClass* find_class_any(const std::string& name) const;

    // Find an enum by name across all modules (returns first match)
    const CachedEnum* find_enum_any(const std::string& name) const;

    // Search
    std::vector<std::pair<std::string, std::string>> search(const std::string& query) const; // returns (module, name) pairs

private:
    std::vector<std::string> m_modules;
    // Key: "module::class"
    std::unordered_map<std::string, CachedClass> m_classes;
    std::unordered_map<std::string, CachedEnum> m_enums;
    std::vector<CachedGlobal> m_globals;
    std::vector<PatternGlobal> m_pattern_globals;
    std::vector<RttiVtable> m_rtti_vtables;
    mutable std::unordered_map<std::string, std::string> m_wrapper_cache; // name -> inner type (or "")
    mutable bool m_wrapper_cache_built = false;
};

// ============================================================================
// Field type interpretation for live memory reads
// ============================================================================

// Given a type string from the schema and raw bytes, return a JSON value
nlohmann::json interpret_field(const std::string& type, const uint8_t* data, int size);

// ============================================================================
// SubManager — subscription loop with field-level diffing
// ============================================================================

struct Subscription {
    uint32_t id;
    uint64_t addr;
    std::string module;
    std::string class_name;
    int interval_ms;
    int64_t last_tick; // ms timestamp of last read
    std::vector<uint8_t> last_snapshot;
};

class SubManager {
public:
    using BroadcastFn = std::function<void(const std::string& json)>;

    SubManager(PipeClient& pipe, SchemaCache& cache, BroadcastFn broadcast);
    ~SubManager();

    uint32_t subscribe(uint64_t addr, const std::string& module,
                       const std::string& class_name, int interval_ms);
    void unsubscribe(uint32_t sub_id);
    void stop();

private:
    void loop();

    PipeClient& m_pipe;
    SchemaCache& m_cache;
    BroadcastFn m_broadcast;

    std::mutex m_mtx;
    std::unordered_map<uint32_t, Subscription> m_subs;
    uint32_t m_next_id = 1;
    std::atomic<bool> m_running{false};
    std::thread m_thread;
};

// ============================================================================
// EntitySystemConfig — probed at runtime, cached for session
// ============================================================================

struct EntitySystemConfig {
    uint64_t ges_addr = 0;             // CGameEntitySystem address
    int chunk_offset = 0x10;            // offset to chunk ptr array in GES
    int max_chunks = 32;                // chunk count
    int chunk_size = 512;               // identities per chunk
    int identity_stride = 0x70;         // sizeof(CEntityIdentity)
    int designer_name_offset = 0x20;    // offset to m_designerName in CEntityIdentity
    bool probed = false;                // true after successful probe
};

// ============================================================================
// CommandDispatcher — routes WebSocket JSON-RPC to handlers
// ============================================================================

class CommandDispatcher {
public:
    CommandDispatcher(SchemaCache& cache, PipeClient& pipe, SubManager& subs);

    // Process an incoming JSON-RPC message, return the response JSON string
    std::string dispatch(const std::string& message);

private:
    nlohmann::json handle(const std::string& cmd, const nlohmann::json& args);

    // Probe entity system layout on first entity.list call
    void probe_entity_config();

    SchemaCache& m_cache;
    PipeClient& m_pipe;
    SubManager& m_subs;
    EntitySystemConfig m_ent_config;
};

} // namespace live
