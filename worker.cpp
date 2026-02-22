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
#include "src/global-scanner.hpp"
#include "src/pattern-scanner.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <ctime>
#include <thread>
#include <unordered_set>

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

// Helper: check if a string is safe for JSON (all printable ASCII)
static bool is_json_safe(const char* s) {
    if (!s || !s[0]) return false;
    for (const char* p = s; *p; p++) {
        if (*p < 0x20 || *p > 0x7E) return false;
    }
    return true;
}

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
// Returns true if written, false if skipped (invalid data)
static bool write_field_json(FILE* fp, const schema::RuntimeField& f, bool first) {
    // Belt-and-suspenders: skip fields with non-ASCII names or types
    if (!is_json_safe(f.name)) return false;
    if (f.type_name && !is_json_safe(f.type_name)) return false;

    if (!first) fprintf(fp, ",");
    fprintf(fp, "\n        {\"name\": \"%s\", \"type\": \"%s\", \"offset\": %d, \"size\": %d",
            json_escape(f.name).c_str(),
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
    return true;
}

bool write_export(schema::SchemaManager& mgr, const char* path,
                  const globals::GlobalMap& discovered,
                  const pattern::ResultMap& pattern_globals,
                  const pattern::PatternConfig& pattern_config) {
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

    // Build complete module list: schema modules + RTTI-only modules
    std::vector<std::string> modules = mgr.dumped_modules();
    {
        std::unordered_set<std::string> known(modules.begin(), modules.end());
        for (const auto& [name, info] : mgr.rtti_map()) {
            if (!info.source_module.empty() && !known.count(info.source_module)) {
                known.insert(info.source_module);
                modules.push_back(info.source_module);
            }
        }
    }

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
            if (!is_json_safe(cls.name)) continue;  // skip classes with garbage names
            if (idx > 0) fprintf(fp, ",\n");

            fprintf(fp, "        {\n");
            fprintf(fp, "          \"name\": \"%s\",\n", json_escape(cls.name).c_str());
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
                fprintf(fp, "          \"parent\": \"%s\",\n", json_escape(rtti->parent.c_str()).c_str());
                fprintf(fp, "          \"inheritance\": [");
                for (size_t i = 0; i < rtti->chain.size(); i++) {
                    if (i > 0) fprintf(fp, ", ");
                    fprintf(fp, "\"%s\"", json_escape(rtti->chain[i].c_str()).c_str());
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
                            json_escape(cls.base_classes[i].name ? cls.base_classes[i].name : "").c_str(),
                            cls.base_classes[i].offset);
                }
                fprintf(fp, "],\n");
            }

            // Instance fields
            fprintf(fp, "          \"fields\": [");
            {
                bool first_f = true;
                for (size_t i = 0; i < cls.fields.size(); i++) {
                    if (write_field_json(fp, cls.fields[i], first_f))
                        first_f = false;
                }
                if (!first_f) fprintf(fp, "\n          ");
            }
            fprintf(fp, "]");

            // Static fields
            if (!cls.static_fields.empty()) {
                fprintf(fp, ",\n          \"static_fields\": [");
                bool first_sf = true;
                for (size_t i = 0; i < cls.static_fields.size(); i++) {
                    if (write_field_json(fp, cls.static_fields[i], first_sf))
                        first_sf = false;
                }
                if (!first_sf) fprintf(fp, "\n          ");
                fprintf(fp, "]");
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
            // Skip enums with invalid names
            if (!is_json_safe(en.name)) { idx++; continue; }
            fprintf(fp, "          \"name\": \"%s\",\n", en.name);
            fprintf(fp, "          \"size\": %d,\n", (int)en.size);
            fprintf(fp, "          \"values\": [");
            bool first_val = true;
            for (size_t i = 0; i < en.values.size(); i++) {
                const auto& v = en.values[i];
                if (!is_json_safe(v.name)) continue;
                if (!first_val) fprintf(fp, ",");
                first_val = false;
                fprintf(fp, "\n            {\"name\": \"%s\", \"value\": %lld}",
                        v.name, (long long)v.value);
            }
            if (!en.values.empty()) fprintf(fp, "\n          ");
            fprintf(fp, "]\n");
            fprintf(fp, "        }");
            idx++;
        }
        fprintf(fp, "\n      ],\n");

        // ---- Vtables ----
        // Vtables come from RTTI, matched to module via source_module field.
        // Includes ALL RTTI classes (even those without schema entries, like
        // CCitadelInput) — these are the most important for hooking.
        fprintf(fp, "      \"vtables\": [\n");
        {
            const auto& rtti_map = mgr.rtti_map();
            int vt_idx = 0;
            for (const auto& [name, info] : rtti_map) {
                if (info.vtable_rva == 0 || info.vtable_func_rvas.empty())
                    continue;
                if (!is_json_safe(name.c_str())) continue;

                // Match by source_module (set during load_rtti)
                if (info.source_module != mod) continue;

                if (vt_idx > 0) fprintf(fp, ",\n");
                fprintf(fp, "        {\n");
                fprintf(fp, "          \"class\": \"%s\",\n", json_escape(name.c_str()).c_str());
                fprintf(fp, "          \"vtable_rva\": \"0x%X\",\n", info.vtable_rva);
                fprintf(fp, "          \"functions\": [");
                for (size_t fi = 0; fi < info.vtable_func_rvas.size(); fi++) {
                    if (fi > 0) fprintf(fp, ",");
                    fprintf(fp, "\n            {\"index\": %d, \"rva\": \"0x%X\"",
                            (int)fi, info.vtable_func_rvas[fi]);
                    // Emit prologue bytes for signature generation
                    if (fi < info.vtable_func_bytes.size() && !info.vtable_func_bytes[fi].empty()) {
                        fprintf(fp, ", \"bytes\": \"");
                        for (uint8_t b : info.vtable_func_bytes[fi]) {
                            fprintf(fp, "%02X", b);
                        }
                        fprintf(fp, "\"");
                    }
                    fprintf(fp, "}");
                }
                fprintf(fp, "\n          ]\n");
                fprintf(fp, "        }");
                vt_idx++;
            }
            fprintf(fp, "\n      ]\n");
        }

        fprintf(fp, "    }");
    }

    fprintf(fp, "\n  ]");

    // ---- Globals section (auto-discovered via vtable scan) ----
    if (!discovered.empty()) {
        fprintf(fp, ",\n  \"globals\": {\n");
        int mod_idx = 0;
        for (const auto& [mod_name, entries] : discovered) {
            if (entries.empty()) continue;

            if (mod_idx > 0) fprintf(fp, ",\n");
            fprintf(fp, "    \"%s\": [\n", mod_name.c_str());
            for (size_t i = 0; i < entries.size(); i++) {
                const auto& g = entries[i];
                if (i > 0) fprintf(fp, ",\n");
                fprintf(fp, "      {\"class\": \"%s\", \"rva\": \"0x%X\", \"vtable_rva\": \"0x%X\", \"type\": \"%s\", \"has_schema\": %s}",
                        g.class_name.c_str(), g.global_rva, g.vtable_rva,
                        g.is_pointer ? "pointer" : "static",
                        g.has_schema ? "true" : "false");
            }
            fprintf(fp, "\n    ]");
            mod_idx++;
        }
        fprintf(fp, "\n  }");
    }

    // ---- Pattern globals (supplementary, from patterns.json) ----
    if (!pattern_globals.empty()) {
        bool has_any = false;
        for (const auto& [mod, results] : pattern_globals) {
            for (const auto& r : results) {
                if (r.found) { has_any = true; break; }
            }
            if (has_any) break;
        }

        // Build lookup from pattern name -> PatternEntry for metadata
        std::unordered_map<std::string, const pattern::PatternEntry*> entry_lookup;
        for (const auto& e : pattern_config.entries) {
            entry_lookup[e.name] = &e;
        }

        if (has_any) {
            fprintf(fp, ",\n  \"pattern_globals\": {\n");
            int mod_idx = 0;
            for (const auto& [mod_name, results] : pattern_globals) {
                bool mod_has_any = false;
                for (const auto& r : results) {
                    if (r.found) { mod_has_any = true; break; }
                }
                if (!mod_has_any) continue;

                if (mod_idx > 0) fprintf(fp, ",\n");
                fprintf(fp, "    \"%s\": {\n", mod_name.c_str());
                int entry_idx = 0;
                for (const auto& r : results) {
                    if (!r.found) continue;
                    if (entry_idx > 0) fprintf(fp, ",\n");

                    auto it = entry_lookup.find(r.name);
                    if (it != entry_lookup.end()) {
                        const auto* pe = it->second;
                        fprintf(fp, "      \"%s\": {\n", r.name.c_str());
                        fprintf(fp, "        \"rva\": \"0x%X\"", r.rva);
                        if (pe->mode == pattern::ResolveMode::Derived) {
                            fprintf(fp, ",\n        \"mode\": \"derived\"");
                            fprintf(fp, ",\n        \"derived_from\": \"%s\"",
                                    json_escape(pe->derived_from.c_str()).c_str());
                            fprintf(fp, ",\n        \"chain_pattern\": \"%s\"",
                                    json_escape(pe->chain_pattern.c_str()).c_str());
                            fprintf(fp, ",\n        \"chain_extract_offset\": %d",
                                    pe->chain_extract_offset);
                        } else {
                            fprintf(fp, ",\n        \"pattern\": \"%s\"",
                                    json_escape(pe->signature.c_str()).c_str());
                            fprintf(fp, ",\n        \"rip_offset\": %d", pe->rip_offset);
                        }
                        fprintf(fp, "\n      }");
                    } else {
                        // Fallback: no config entry found, emit RVA only
                        fprintf(fp, "      \"%s\": {\"rva\": \"0x%X\"}",
                                r.name.c_str(), r.rva);
                    }
                    entry_idx++;
                }
                fprintf(fp, "\n    }");
                mod_idx++;
            }
            fprintf(fp, "\n  }");
        }
    }

    fprintf(fp, "\n}\n");
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
        LOG_I("Walking RTTI hierarchies (schema modules)...");
        std::unordered_set<HMODULE> scanned_modules;
        for (const auto& mod_name : mgr.dumped_modules()) {
            HMODULE hmod = GetModuleHandleA(mod_name.c_str());
            if (!hmod) continue;

            MODULEINFO mi = {};
            if (GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi))) {
                mgr.load_rtti(reinterpret_cast<uintptr_t>(mi.lpBaseOfDll), mi.SizeOfImage, mod_name.c_str());
                scanned_modules.insert(hmod);
                LOG_I("  RTTI %s: %d classes total", mod_name.c_str(), mgr.rtti_class_count());
            }
        }

        // Walk RTTI from ALL loaded DLLs (catches panorama.dll, tier0.dll, etc.)
        // These have vtables but no SchemaSystem type scopes.
        LOG_I("Walking RTTI hierarchies (all loaded DLLs)...");
        {
            HMODULE modules_arr[512];
            DWORD needed = 0;
            if (EnumProcessModules(GetCurrentProcess(), modules_arr, sizeof(modules_arr), &needed)) {
                int extra_count = 0;
                int mod_count = needed / sizeof(HMODULE);
                for (int i = 0; i < mod_count; i++) {
                    if (scanned_modules.count(modules_arr[i])) continue;

                    char mod_path[MAX_PATH];
                    if (!GetModuleFileNameA(modules_arr[i], mod_path, MAX_PATH)) continue;

                    // Extract just the filename
                    const char* slash = strrchr(mod_path, '\\');
                    const char* mod_name = slash ? slash + 1 : mod_path;

                    // Skip system DLLs (ntdll, kernel32, etc.) — only scan .dll in game dirs
                    // Quick heuristic: skip anything in Windows\System32 or WinSxS
                    if (strstr(mod_path, "\\Windows\\") || strstr(mod_path, "\\windows\\"))
                        continue;

                    MODULEINFO mi = {};
                    if (!GetModuleInformation(GetCurrentProcess(), modules_arr[i], &mi, sizeof(mi)))
                        continue;

                    // Skip tiny modules (unlikely to have meaningful RTTI)
                    if (mi.SizeOfImage < 0x10000) continue;

                    int before = mgr.rtti_class_count();
                    mgr.load_rtti(reinterpret_cast<uintptr_t>(mi.lpBaseOfDll), mi.SizeOfImage, mod_name);
                    int found = mgr.rtti_class_count() - before;
                    if (found > 0) {
                        LOG_I("  RTTI %s: +%d classes (%d total)", mod_name, found, mgr.rtti_class_count());
                        extra_count += found;
                    }
                }
                LOG_I("Extra RTTI scan: +%d classes from non-schema DLLs", extra_count);
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

        // ---- Auto-discover globals via .data vtable scan ----
        LOG_I("Scanning .data sections for global singletons...");

        // Build set of class names that have schema data (for tagging)
        std::unordered_set<std::string> schema_classes;
        for (const auto& [key, cls] : mgr.cache()) {
            // Cache key is "module::ClassName", extract just the class name
            auto sep = key.find("::");
            if (sep != std::string::npos)
                schema_classes.insert(key.substr(sep + 2));
            else
                schema_classes.insert(key);
        }
        LOG_I("Schema class set: %d classes for tagging", (int)schema_classes.size());

        globals::GlobalMap discovered = globals::scan(mgr.rtti_map(), schema_classes);
        {
            int total = 0;
            for (const auto& [mod, entries] : discovered) total += (int)entries.size();
            LOG_I("Auto-discovered %d globals", total);
        }

        // ---- Optional: pattern-based globals (supplementary) ----
        pattern::ResultMap pattern_globals;
        pattern::PatternConfig pattern_config;
        {
            char patterns_path[MAX_PATH];
            snprintf(patterns_path, MAX_PATH, "%sdezlock-patterns.json", temp_dir);

            if (pattern::load_config(patterns_path, pattern_config)) {
                LOG_I("Running supplementary pattern scan (%d patterns)...", (int)pattern_config.entries.size());
                pattern_globals = pattern::resolve_all(pattern_config);

                int found = 0, total = 0;
                for (const auto& [mod, results] : pattern_globals) {
                    for (const auto& r : results) {
                        total++;
                        if (r.found) found++;
                    }
                }
                LOG_I("Patterns: %d/%d resolved", found, total);
            } else {
                LOG_I("No patterns.json — pattern globals skipped (auto-discovery is primary)");
            }
        }

        // Export to JSON (all modules)
        LOG_I("Writing JSON export...");
        write_export(mgr, json_path, discovered, pattern_globals, pattern_config);
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
