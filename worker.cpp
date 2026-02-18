/**
 * Dezlock Dump Worker DLL
 *
 * Minimal DLL injected into Deadlock to walk the SchemaSystem + RTTI.
 * Writes complete JSON export to %TEMP%\dezlock-export.json and
 * signals completion via %TEMP%\dezlock-done marker file.
 *
 * Auto-unloads after dump completes. No hooks, no overlay, no debug server.
 */

#define LOG_TAG "schema-worker"

#include "src/log.hpp"
#include "src/schema-manager.hpp"
#include "src/rtti-hierarchy.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <ctime>
#include <thread>

namespace {

// ============================================================================
// Minimal interface discovery (no full interface walker needed)
// ============================================================================

void* find_schema_system() {
    HMODULE hmod = GetModuleHandleA("schemasystem.dll");
    if (!hmod) {
        LOG_E("schemasystem.dll not found");
        return nullptr;
    }

    using CreateInterfaceFn = void*(*)(const char*, int*);
    auto fn = reinterpret_cast<CreateInterfaceFn>(
        GetProcAddress(hmod, "CreateInterface"));
    if (!fn) {
        LOG_E("CreateInterface export not found in schemasystem.dll");
        return nullptr;
    }

    int ret = 0;
    void* iface = fn("SchemaSystem_001", &ret);
    if (!iface) {
        LOG_E("SchemaSystem_001 interface not found");
    }
    return iface;
}

// ============================================================================
// JSON export (writes directly to file, no TCP)
// ============================================================================

// Helper: escape a string for JSON output
static std::string json_escape(const char* s) {
    std::string out;
    if (!s) return out;
    for (const char* p = s; *p; p++) {
        if (*p == '"') out += "\\\"";
        else if (*p == '\\') out += "\\\\";
        else if (*p == '\n') out += "\\n";
        else if (*p == '\r') out += "\\r";
        else if (*p == '\t') out += "\\t";
        else out += *p;
    }
    return out;
}

// Write a single field (instance or static) as JSON
static void write_field_json(FILE* fp, const schema::RuntimeField& f, bool first) {
    if (!first) fprintf(fp, ",");
    fprintf(fp, "\n        {\"name\": \"%s\", \"type\": \"%s\", \"offset\": %d, \"size\": %d",
            f.name ? f.name : "",
            json_escape(f.type_name).c_str(),
            f.offset, f.size);
    if (!f.metadata.empty()) {
        fprintf(fp, ", \"metadata\": [");
        for (size_t m = 0; m < f.metadata.size(); m++) {
            if (m > 0) fprintf(fp, ", ");
            fprintf(fp, "\"%s\"", json_escape(f.metadata[m].c_str()).c_str());
        }
        fprintf(fp, "]");
    }
    fprintf(fp, "}");
}

bool write_export(schema::SchemaManager& mgr, const char* path) {
    FILE* fp = fopen(path, "w");
    if (!fp) {
        LOG_E("Failed to open %s for writing", path);
        return false;
    }

    time_t now = time(nullptr);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", localtime(&now));

    fprintf(fp, "{\n");
    fprintf(fp, "  \"timestamp\": \"%s\",\n", timebuf);
    fprintf(fp, "  \"rtti_classes\": %d,\n", mgr.rtti_class_count());
    fprintf(fp, "  \"total_classes\": %d,\n", mgr.class_count());
    fprintf(fp, "  \"total_fields\": %d,\n", mgr.total_field_count());
    fprintf(fp, "  \"total_static_fields\": %d,\n", mgr.total_static_field_count());
    fprintf(fp, "  \"total_enums\": %d,\n", mgr.enum_count());
    fprintf(fp, "  \"total_enumerators\": %d,\n", mgr.total_enumerator_count());

    const auto& modules = mgr.dumped_modules();
    const auto& cache = mgr.cache();
    const auto& ecache = mgr.enum_cache();

    fprintf(fp, "  \"modules\": [\n");

    for (size_t mi = 0; mi < modules.size(); mi++) {
        const std::string& mod = modules[mi];
        std::string prefix = mod + "::";

        if (mi > 0) fprintf(fp, ",\n");
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"name\": \"%s\",\n", mod.c_str());

        // Count classes and enums for this module
        int class_count = 0, enum_count = 0;
        for (const auto& [key, _] : cache) {
            if (key.rfind(prefix, 0) == 0) class_count++;
        }
        for (const auto& [key, _] : ecache) {
            if (key.rfind(prefix, 0) == 0) enum_count++;
        }
        fprintf(fp, "      \"class_count\": %d,\n", class_count);
        fprintf(fp, "      \"enum_count\": %d,\n", enum_count);

        // ---- Classes ----
        fprintf(fp, "      \"classes\": [\n");
        int idx = 0;
        for (const auto& [key, cls] : cache) {
            if (key.rfind(prefix, 0) != 0) continue;
            if (idx > 0) fprintf(fp, ",\n");

            fprintf(fp, "        {\n");
            fprintf(fp, "          \"name\": \"%s\",\n", cls.name ? cls.name : "");
            fprintf(fp, "          \"size\": %d,\n", cls.size);

            // Class metadata
            if (!cls.metadata.empty()) {
                fprintf(fp, "          \"metadata\": [");
                for (size_t m = 0; m < cls.metadata.size(); m++) {
                    if (m > 0) fprintf(fp, ", ");
                    fprintf(fp, "\"%s\"", json_escape(cls.metadata[m].c_str()).c_str());
                }
                fprintf(fp, "],\n");
            }

            auto* rtti = mgr.get_inheritance(cls.name);
            if (rtti && !rtti->parent.empty()) {
                fprintf(fp, "          \"parent\": \"%s\",\n", rtti->parent.c_str());
                fprintf(fp, "          \"inheritance\": [");
                for (size_t i = 0; i < rtti->chain.size(); i++) {
                    if (i > 0) fprintf(fp, ", ");
                    fprintf(fp, "\"%s\"", rtti->chain[i].c_str());
                }
                fprintf(fp, "],\n");
            } else {
                fprintf(fp, "          \"parent\": null,\n");
                fprintf(fp, "          \"inheritance\": [],\n");
            }

            if (!cls.base_classes.empty()) {
                fprintf(fp, "          \"components\": [");
                for (size_t i = 0; i < cls.base_classes.size(); i++) {
                    if (i > 0) fprintf(fp, ", ");
                    fprintf(fp, "{\"name\": \"%s\", \"offset\": %d}",
                            cls.base_classes[i].name ? cls.base_classes[i].name : "",
                            cls.base_classes[i].offset);
                }
                fprintf(fp, "],\n");
            }

            // Instance fields
            fprintf(fp, "          \"fields\": [");
            for (size_t i = 0; i < cls.fields.size(); i++) {
                write_field_json(fp, cls.fields[i], i == 0);
            }
            if (!cls.fields.empty()) fprintf(fp, "\n          ");
            fprintf(fp, "]");

            // Static fields
            if (!cls.static_fields.empty()) {
                fprintf(fp, ",\n          \"static_fields\": [");
                for (size_t i = 0; i < cls.static_fields.size(); i++) {
                    write_field_json(fp, cls.static_fields[i], i == 0);
                }
                fprintf(fp, "\n          ]");
            }

            fprintf(fp, "\n        }");
            idx++;
        }
        fprintf(fp, "\n      ],\n");

        // ---- Enums ----
        fprintf(fp, "      \"enums\": [\n");
        idx = 0;
        for (const auto& [key, en] : ecache) {
            if (key.rfind(prefix, 0) != 0) continue;
            if (idx > 0) fprintf(fp, ",\n");

            fprintf(fp, "        {\n");
            fprintf(fp, "          \"name\": \"%s\",\n", en.name ? en.name : "");
            fprintf(fp, "          \"size\": %d,\n", (int)en.size);
            fprintf(fp, "          \"values\": [");
            for (size_t i = 0; i < en.values.size(); i++) {
                const auto& v = en.values[i];
                if (i > 0) fprintf(fp, ",");
                fprintf(fp, "\n            {\"name\": \"%s\", \"value\": %lld}",
                        v.name ? v.name : "", (long long)v.value);
            }
            if (!en.values.empty()) fprintf(fp, "\n          ");
            fprintf(fp, "]\n");
            fprintf(fp, "        }");
            idx++;
        }
        fprintf(fp, "\n      ]\n");

        fprintf(fp, "    }");
    }

    fprintf(fp, "\n  ]\n}\n");
    fclose(fp);

    LOG_I("Exported %d modules (%d classes, %d enums) to %s",
          (int)modules.size(), mgr.class_count(), mgr.enum_count(), path);
    return true;
}

// ============================================================================
// Main worker thread
// ============================================================================

void worker_thread(HMODULE hModule) {
    core::log::init("dezlock-worker", true);
    LOG_I("=== Dezlock Dump Worker starting ===");

    // Build output paths
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);

    char json_path[MAX_PATH];
    snprintf(json_path, MAX_PATH, "%sdezlock-export.json", temp_dir);

    char done_path[MAX_PATH];
    snprintf(done_path, MAX_PATH, "%sdezlock-done", temp_dir);

    // Clean up any stale signal file
    DeleteFileA(done_path);

    // Wait for client.dll if not loaded yet
    int wait = 0;
    while (!GetModuleHandleA("client.dll") && wait < 100) {
        Sleep(100);
        wait++;
    }
    if (!GetModuleHandleA("client.dll")) {
        LOG_E("client.dll not loaded after 10s, aborting");
        goto done;
    }

    {
        // Find SchemaSystem
        void* schema_sys = find_schema_system();
        if (!schema_sys) {
            LOG_E("SchemaSystem not found, aborting");
            goto done;
        }
        LOG_I("SchemaSystem: %p", schema_sys);

        // Init schema manager
        auto& mgr = schema::instance();
        if (!mgr.init(schema_sys)) {
            LOG_E("Schema manager init failed");
            goto done;
        }

        // Auto-discover and dump ALL modules with schema data
        LOG_I("Auto-discovering all modules with schema data...");
        {
            int module_count = mgr.dump_all_modules();
            if (module_count == 0) {
                LOG_E("No modules with schema data found");
                goto done;
            }
            LOG_I("Schema: %d modules, %d classes, %d fields, %d static fields, %d enums, %d enumerators",
                  module_count, mgr.class_count(), mgr.total_field_count(),
                  mgr.total_static_field_count(), mgr.enum_count(), mgr.total_enumerator_count());

            // Log discovered modules
            for (const auto& mod : mgr.dumped_modules()) {
                LOG_I("  module: %s", mod.c_str());
            }
        }

        // Walk RTTI hierarchy from all modules that have schema data
        LOG_I("Walking RTTI hierarchies...");
        for (const auto& mod_name : mgr.dumped_modules()) {
            HMODULE hmod = GetModuleHandleA(mod_name.c_str());
            if (!hmod) continue;

            MODULEINFO mi = {};
            if (GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi))) {
                mgr.load_rtti(reinterpret_cast<uintptr_t>(mi.lpBaseOfDll), mi.SizeOfImage);
                LOG_I("  RTTI %s: %d classes total", mod_name.c_str(), mgr.rtti_class_count());
            }
        }

        // Resolve RTTI class names through SchemaSystem for all dumped modules
        LOG_I("Resolving RTTI classes through SchemaSystem...");
        {
            int resolved = 0;
            const auto& rtti_map = mgr.rtti_map();
            for (const auto& [name, info] : rtti_map) {
                // Try each dumped module
                for (const auto& mod_name : mgr.dumped_modules()) {
                    auto* cls = mgr.find_class(mod_name.c_str(), name.c_str());
                    if (cls) { resolved++; break; }
                }
            }
            LOG_I("Resolved %d/%d RTTI classes with schema data", resolved, mgr.rtti_class_count());
        }

        LOG_I("Total: %d classes, %d fields, %d static, %d enums",
              mgr.class_count(), mgr.total_field_count(),
              mgr.total_static_field_count(), mgr.enum_count());

        // Export to JSON (all modules)
        LOG_I("Writing JSON export...");
        write_export(mgr, json_path);
    }

done:
    // Signal completion
    FILE* sig = fopen(done_path, "w");
    if (sig) {
        fprintf(sig, "done\n");
        fclose(sig);
    }

    LOG_I("=== Worker complete, unloading ===");
    core::log::shutdown();

    // Give the exe a moment to notice the signal before we unload
    Sleep(200);

    FreeLibraryAndExitThread(hModule, 0);
}

} // anonymous namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        std::thread(worker_thread, hModule).detach();
    }
    return TRUE;
}
