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
#include "src/interface-scanner.hpp"
#include "src/string-scanner.hpp"
#include "src/protobuf-scanner.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <ctime>
#include <thread>
#include <unordered_set>

namespace {

// ============================================================================
// JSON utility functions
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

// Helper: write a JSON string array inline
static void write_json_string_array(FILE* fp, const std::vector<std::string>& arr) {
    fprintf(fp, "[");
    for (size_t i = 0; i < arr.size(); i++) {
        if (i > 0) fprintf(fp, ", ");
        fprintf(fp, "\"%s\"", json_escape(arr[i].c_str()).c_str());
    }
    fprintf(fp, "]");
}

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

bool write_export(schema::SchemaManager& mgr, const char* path,
                  const globals::GlobalMap& discovered,
                  const pattern::ResultMap& pattern_globals,
                  const pattern::PatternConfig& pattern_config,
                  const interfaces::InterfaceMap& iface_map,
                  const strings::StringMap& string_map,
                  const protobuf_scan::ProtoMap& proto_map) {
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
        for (const auto& [key, info] : mgr.rtti_map()) {
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
                fprintf(fp, "          \"metadata\": ");
                write_json_string_array(fp, cls.metadata);
                fprintf(fp, ",\n");
            }

            auto* rtti = mgr.get_inheritance(cls.name, mod.c_str());
            if (rtti && !rtti->parent.empty()) {
                fprintf(fp, "          \"parent\": \"%s\",\n", json_escape(rtti->parent.c_str()).c_str());
                fprintf(fp, "          \"inheritance\": ");
                write_json_string_array(fp, rtti->chain);
                fprintf(fp, ",\n");
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
            for (const auto& [key, info] : rtti_map) {
                if (info.vtable_rva == 0 || info.vtable_func_rvas.empty())
                    continue;

                // key is now "module::ClassName" — extract bare class name
                std::string bare_name = schema::rtti_class_name(key);
                if (!is_json_safe(bare_name.c_str())) continue;

                // Match by source_module (set during load_rtti)
                if (info.source_module != mod) continue;

                if (vt_idx > 0) fprintf(fp, ",\n");
                fprintf(fp, "        {\n");
                fprintf(fp, "          \"class\": \"%s\",\n", json_escape(bare_name.c_str()).c_str());
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
        const auto& rtti = mgr.rtti_map();
        fprintf(fp, ",\n  \"globals\": {\n");
        int mod_idx = 0;
        for (const auto& [mod_name, entries] : discovered) {
            if (entries.empty()) continue;

            if (mod_idx > 0) fprintf(fp, ",\n");
            fprintf(fp, "    \"%s\": [\n", mod_name.c_str());
            for (size_t i = 0; i < entries.size(); i++) {
                const auto& g = entries[i];
                if (i > 0) fprintf(fp, ",\n");
                fprintf(fp, "      {\"class\": \"%s\", \"rva\": \"0x%X\", \"vtable_rva\": \"0x%X\", \"type\": \"%s\", \"has_schema\": %s",
                        g.class_name.c_str(), g.global_rva, g.vtable_rva,
                        g.is_pointer ? "pointer" : "static",
                        g.has_schema ? "true" : "false");

                // Enrich with RTTI data if available
                std::string composite_key = mod_name + "::" + g.class_name;
                auto it = rtti.find(composite_key);
                if (it != rtti.end()) {
                    const auto& info = it->second;
                    if (!info.parent.empty())
                        fprintf(fp, ", \"parent\": \"%s\"", info.parent.c_str());
                    fprintf(fp, ", \"function_count\": %d", (int)info.vtable_func_rvas.size());
                    if (!info.chain.empty()) {
                        fprintf(fp, ", \"inheritance\": ");
                        write_json_string_array(fp, info.chain);
                    }
                }

                fprintf(fp, "}");
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

    // ---- Interfaces section (CreateInterface registrations) ----
    if (!iface_map.empty()) {
        fprintf(fp, ",\n  \"interfaces\": {\n");
        int mod_idx = 0;
        for (const auto& [mod_name, entries] : iface_map) {
            if (entries.empty()) continue;

            if (mod_idx > 0) fprintf(fp, ",\n");
            fprintf(fp, "    \"%s\": [\n", json_escape(mod_name.c_str()).c_str());
            for (size_t i = 0; i < entries.size(); i++) {
                const auto& e = entries[i];
                if (i > 0) fprintf(fp, ",\n");
                fprintf(fp, "      {\"name\": \"%s\", \"base_name\": \"%s\", \"version\": %d",
                        json_escape(e.name.c_str()).c_str(),
                        json_escape(e.base_name.c_str()).c_str(),
                        e.version);
                if (e.factory_rva)
                    fprintf(fp, ", \"factory_rva\": \"0x%X\"", e.factory_rva);
                if (e.instance_rva)
                    fprintf(fp, ", \"instance_rva\": \"0x%X\"", e.instance_rva);
                if (e.vtable_rva)
                    fprintf(fp, ", \"vtable_rva\": \"0x%X\"", e.vtable_rva);
                fprintf(fp, "}");
            }
            fprintf(fp, "\n    ]");
            mod_idx++;
        }
        fprintf(fp, "\n  }");
    }

    // ---- String references section ----
    if (!string_map.empty()) {
        fprintf(fp, ",\n  \"string_refs\": {\n");
        int mod_idx = 0;
        for (const auto& [mod_name, mod_data] : string_map) {
            if (mod_data.strings.empty()) continue;

            if (mod_idx > 0) fprintf(fp, ",\n");
            fprintf(fp, "    \"%s\": {\n", json_escape(mod_name.c_str()).c_str());

            // Summary
            fprintf(fp, "      \"summary\": {\"total_strings\": %d, \"total_xrefs\": %d, "
                        "\"categories\": {\"convar\": %d, \"class_name\": %d, \"lifecycle\": %d, \"debug\": %d}},\n",
                    mod_data.summary.total_strings, mod_data.summary.total_xrefs,
                    mod_data.summary.convar, mod_data.summary.class_name,
                    mod_data.summary.lifecycle, mod_data.summary.debug);

            // Strings array
            fprintf(fp, "      \"strings\": [\n");
            for (size_t i = 0; i < mod_data.strings.size(); i++) {
                const auto& s = mod_data.strings[i];
                if (i > 0) fprintf(fp, ",\n");
                fprintf(fp, "        {\"value\": \"%s\", \"rva\": \"0x%X\", \"category\": \"%s\"",
                        json_escape(s.value.c_str()).c_str(), s.rva,
                        json_escape(s.category.c_str()).c_str());
                if (!s.associated_class.empty())
                    fprintf(fp, ", \"associated_class\": \"%s\"",
                            json_escape(s.associated_class.c_str()).c_str());
                if (!s.xrefs.empty()) {
                    fprintf(fp, ", \"xrefs\": [");
                    for (size_t x = 0; x < s.xrefs.size(); x++) {
                        if (x > 0) fprintf(fp, ", ");
                        fprintf(fp, "{\"code_rva\": \"0x%X\", \"func_rva\": \"0x%X\", \"type\": \"%s\"}",
                                s.xrefs[x].code_rva, s.xrefs[x].func_rva,
                                s.xrefs[x].type.c_str());
                    }
                    fprintf(fp, "]");
                }
                fprintf(fp, "}");
            }
            fprintf(fp, "\n      ]\n");
            fprintf(fp, "    }");
            mod_idx++;
        }
        fprintf(fp, "\n  }");
    }

    // ---- Protobuf messages section (decoded from embedded descriptors) ----
    if (!proto_map.empty()) {
        fprintf(fp, ",\n  \"protobuf_messages\": {\n");
        int mod_idx = 0;
        for (const auto& [mod_name, proto_files] : proto_map) {
            if (proto_files.empty()) continue;

            if (mod_idx > 0) fprintf(fp, ",\n");
            fprintf(fp, "    \"%s\": {\n", json_escape(mod_name.c_str()).c_str());
            fprintf(fp, "      \"files\": [\n");

            for (size_t fi = 0; fi < proto_files.size(); fi++) {
                const auto& pf = proto_files[fi];
                if (fi > 0) fprintf(fp, ",\n");
                fprintf(fp, "        {\n");
                fprintf(fp, "          \"name\": \"%s\",\n", json_escape(pf.name.c_str()).c_str());
                fprintf(fp, "          \"package\": \"%s\",\n", json_escape(pf.package.c_str()).c_str());
                if (!pf.syntax.empty())
                    fprintf(fp, "          \"syntax\": \"%s\",\n", json_escape(pf.syntax.c_str()).c_str());

                // Dependencies
                if (!pf.dependencies.empty()) {
                    fprintf(fp, "          \"dependencies\": ");
                    write_json_string_array(fp, pf.dependencies);
                    fprintf(fp, ",\n");
                }

                // Messages (recursive helper via lambda)
                struct JsonWriter {
                    FILE* fp;
                    const char* (*escape)(const char*);

                    void write_message(const protobuf_scan::ProtoMessage& msg, int indent) {
                        std::string pad(indent, ' ');
                        fprintf(fp, "%s{\n", pad.c_str());
                        fprintf(fp, "%s  \"name\": \"%s\",\n", pad.c_str(), json_escape(msg.name.c_str()).c_str());

                        // Fields
                        fprintf(fp, "%s  \"fields\": [", pad.c_str());
                        for (size_t i = 0; i < msg.fields.size(); i++) {
                            const auto& f = msg.fields[i];
                            if (i > 0) fprintf(fp, ",");
                            fprintf(fp, "\n%s    {\"name\": \"%s\", \"number\": %d, \"type\": \"%s\", \"label\": \"%s\"",
                                    pad.c_str(),
                                    json_escape(f.name.c_str()).c_str(),
                                    f.number,
                                    protobuf_scan::field_type_name(f.type),
                                    f.label == 1 ? "optional" : f.label == 2 ? "required" : f.label == 3 ? "repeated" : "unknown");
                            if (!f.type_name.empty())
                                fprintf(fp, ", \"type_name\": \"%s\"", json_escape(f.type_name.c_str()).c_str());
                            if (!f.default_value.empty())
                                fprintf(fp, ", \"default_value\": \"%s\"", json_escape(f.default_value.c_str()).c_str());
                            if (f.oneof_index >= 0)
                                fprintf(fp, ", \"oneof_index\": %d", f.oneof_index);
                            if (!f.json_name.empty())
                                fprintf(fp, ", \"json_name\": \"%s\"", json_escape(f.json_name.c_str()).c_str());
                            fprintf(fp, "}");
                        }
                        if (!msg.fields.empty()) fprintf(fp, "\n%s  ", pad.c_str());
                        fprintf(fp, "]");

                        // Nested messages
                        if (!msg.nested_messages.empty()) {
                            fprintf(fp, ",\n%s  \"nested_messages\": [\n", pad.c_str());
                            for (size_t i = 0; i < msg.nested_messages.size(); i++) {
                                if (i > 0) fprintf(fp, ",\n");
                                write_message(msg.nested_messages[i], indent + 4);
                            }
                            fprintf(fp, "\n%s  ]", pad.c_str());
                        }

                        // Nested enums
                        if (!msg.nested_enums.empty()) {
                            fprintf(fp, ",\n%s  \"nested_enums\": [", pad.c_str());
                            for (size_t i = 0; i < msg.nested_enums.size(); i++) {
                                const auto& e = msg.nested_enums[i];
                                if (i > 0) fprintf(fp, ",");
                                fprintf(fp, "\n%s    {\"name\": \"%s\", \"values\": [",
                                        pad.c_str(), json_escape(e.name.c_str()).c_str());
                                for (size_t v = 0; v < e.values.size(); v++) {
                                    if (v > 0) fprintf(fp, ", ");
                                    fprintf(fp, "{\"name\": \"%s\", \"number\": %d}",
                                            json_escape(e.values[v].name.c_str()).c_str(),
                                            e.values[v].number);
                                }
                                fprintf(fp, "]}");
                            }
                            if (!msg.nested_enums.empty()) fprintf(fp, "\n%s  ", pad.c_str());
                            fprintf(fp, "]");
                        }

                        // Oneof declarations
                        if (!msg.oneof_decls.empty()) {
                            fprintf(fp, ",\n%s  \"oneof_decls\": [", pad.c_str());
                            for (size_t i = 0; i < msg.oneof_decls.size(); i++) {
                                if (i > 0) fprintf(fp, ", ");
                                fprintf(fp, "\"%s\"", json_escape(msg.oneof_decls[i].c_str()).c_str());
                            }
                            fprintf(fp, "]");
                        }

                        fprintf(fp, "\n%s}", pad.c_str());
                    }
                };

                JsonWriter jw{fp, nullptr};

                fprintf(fp, "          \"messages\": [\n");
                for (size_t mi2 = 0; mi2 < pf.messages.size(); mi2++) {
                    if (mi2 > 0) fprintf(fp, ",\n");
                    jw.write_message(pf.messages[mi2], 12);
                }
                if (!pf.messages.empty()) fprintf(fp, "\n          ");
                fprintf(fp, "],\n");

                // Top-level enums
                fprintf(fp, "          \"enums\": [");
                for (size_t ei = 0; ei < pf.enums.size(); ei++) {
                    const auto& e = pf.enums[ei];
                    if (ei > 0) fprintf(fp, ",");
                    fprintf(fp, "\n            {\"name\": \"%s\", \"values\": [",
                            json_escape(e.name.c_str()).c_str());
                    for (size_t v = 0; v < e.values.size(); v++) {
                        if (v > 0) fprintf(fp, ", ");
                        fprintf(fp, "{\"name\": \"%s\", \"number\": %d}",
                                json_escape(e.values[v].name.c_str()).c_str(),
                                e.values[v].number);
                    }
                    fprintf(fp, "]}");
                }
                if (!pf.enums.empty()) fprintf(fp, "\n          ");
                fprintf(fp, "]\n");

                fprintf(fp, "        }");
            }
            fprintf(fp, "\n      ]\n");
            fprintf(fp, "    }");
            mod_idx++;
        }
        fprintf(fp, "\n  }");
    }

    fprintf(fp, "\n}\n");
    fclose(fp);

    LOG_I("Exported %d modules (%d classes, %d enums) to %s",
          (int)modules.size(), mgr.class_count(), mgr.enum_count(), path);
    return true;
}

// ============================================================================
// Live Pipe Server — binary read/write proxy for dezlock-dump.exe live mode
// ============================================================================

static const uint8_t PIPE_OP_READ        = 0x01;
static const uint8_t PIPE_OP_WRITE       = 0x02;
static const uint8_t PIPE_OP_MODULE_BASE = 0x03;
static const uint8_t PIPE_OP_SHUTDOWN    = 0xFF;

static const uint8_t PIPE_STATUS_OK       = 0x00;
static const uint8_t PIPE_STATUS_SEH      = 0x01;
static const uint8_t PIPE_STATUS_BAD_ARGS = 0x02;

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

// SEH wrappers — must be in separate functions (no C++ objects with destructors)
static bool seh_memcpy_read(void* dst, const void* src, size_t len) {
    __try {
        memcpy(dst, src, len);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void run_pipe_server(HMODULE hModule) {
    LOG_I("Starting named pipe server...");

    HANDLE hPipe = CreateNamedPipeA(
        "\\\\.\\pipe\\dezlock-live",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 65536, 65536, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_E("CreateNamedPipe failed (err %lu)", GetLastError());
        core::log::shutdown();
        Sleep(200);
        FreeLibraryAndExitThread(hModule, 1);
        return;
    }

    LOG_I("Pipe created, waiting for exe to connect...");
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        LOG_E("ConnectNamedPipe failed (err %lu)", GetLastError());
        CloseHandle(hPipe);
        core::log::shutdown();
        Sleep(200);
        FreeLibraryAndExitThread(hModule, 1);
        return;
    }
    LOG_I("Pipe client connected — serving memory requests");

    bool running = true;
    while (running) {
        PipeRequest req = {};
        if (!pipe_read_exact(hPipe, &req, sizeof(req))) {
            LOG_W("Pipe read failed — client disconnected");
            break;
        }

        switch (req.op) {
        case PIPE_OP_READ: {
            if (req.size == 0 || req.size > 65536) {
                PipeResponse resp = { PIPE_STATUS_BAD_ARGS, {}, 0 };
                pipe_write_exact(hPipe, &resp, sizeof(resp));
                break;
            }
            std::vector<uint8_t> buf(req.size);
            bool ok = seh_memcpy_read(buf.data(), reinterpret_cast<const void*>(req.addr), req.size);
            if (ok) {
                PipeResponse resp = { PIPE_STATUS_OK, {}, req.size };
                pipe_write_exact(hPipe, &resp, sizeof(resp));
                pipe_write_exact(hPipe, buf.data(), req.size);
            } else {
                PipeResponse resp = { PIPE_STATUS_SEH, {}, 0 };
                pipe_write_exact(hPipe, &resp, sizeof(resp));
            }
            break;
        }
        case PIPE_OP_WRITE: {
            // Write capability removed — this tool is read-only.
            // Drain any payload the client may have sent, then return error.
            if (req.size > 0 && req.size <= 65536) {
                std::vector<uint8_t> drain(req.size);
                pipe_read_exact(hPipe, drain.data(), req.size);
            }
            PipeResponse resp = { PIPE_STATUS_BAD_ARGS, {}, 0 };
            pipe_write_exact(hPipe, &resp, sizeof(resp));
            break;
        }
        case PIPE_OP_MODULE_BASE: {
            // size = length of module name string that follows header
            if (req.size == 0 || req.size > 260) {
                PipeResponse resp = { PIPE_STATUS_BAD_ARGS, {}, 0 };
                pipe_write_exact(hPipe, &resp, sizeof(resp));
                break;
            }
            std::vector<char> name_buf(req.size + 1, 0);
            if (!pipe_read_exact(hPipe, name_buf.data(), req.size)) {
                LOG_W("Failed to read module name");
                break;
            }
            name_buf[req.size] = '\0';

            HMODULE hmod = GetModuleHandleA(name_buf.data());
            if (hmod) {
                uint64_t base = reinterpret_cast<uint64_t>(hmod);
                PipeResponse resp = { PIPE_STATUS_OK, {}, 8 };
                pipe_write_exact(hPipe, &resp, sizeof(resp));
                pipe_write_exact(hPipe, &base, 8);
            } else {
                PipeResponse resp = { PIPE_STATUS_BAD_ARGS, {}, 0 };
                pipe_write_exact(hPipe, &resp, sizeof(resp));
            }
            break;
        }
        case PIPE_OP_SHUTDOWN:
            LOG_I("Received shutdown command");
            running = false;
            {
                PipeResponse resp = { PIPE_STATUS_OK, {}, 0 };
                pipe_write_exact(hPipe, &resp, sizeof(resp));
            }
            break;
        default:
            LOG_W("Unknown pipe op 0x%02X", req.op);
            {
                PipeResponse resp = { PIPE_STATUS_BAD_ARGS, {}, 0 };
                pipe_write_exact(hPipe, &resp, sizeof(resp));
            }
            break;
        }
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    LOG_I("Pipe server shut down, unloading DLL...");
    core::log::shutdown();
    Sleep(200);
    FreeLibraryAndExitThread(hModule, 0);
}

// ============================================================================
// Phase functions — each phase handles one scanning stage
// ============================================================================

// Phase 1: Schema system walking
// Discovers all modules with schema data and dumps classes, fields, enums.
// Returns the module count (0 on failure).
static int phase_schema(schema::SchemaManager& mgr, void* schema_sys) {
    if (!mgr.init(schema_sys)) {
        LOG_E("Schema manager init failed");
        return 0;
    }

    LOG_I("Auto-discovering all modules with schema data...");
    int module_count = mgr.dump_all_modules();
    if (module_count == 0) {
        LOG_E("No modules with schema data found");
        return 0;
    }

    LOG_I("Schema: %d modules, %d classes, %d fields, %d static fields, %d enums, %d enumerators",
          module_count, mgr.class_count(), mgr.total_field_count(),
          mgr.total_static_field_count(), mgr.enum_count(), mgr.total_enumerator_count());

    for (const auto& mod : mgr.dumped_modules()) {
        LOG_I("  module: %s", mod.c_str());
    }

    return module_count;
}

// Phase 2: RTTI hierarchy building
// Walks RTTI from schema modules first, then all loaded DLLs.
// Resolves RTTI class names through SchemaSystem.
static void phase_rtti(schema::SchemaManager& mgr) {
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
        for (const auto& [key, info] : rtti_map) {
            std::string bare = schema::rtti_class_name(key);
            // Try each dumped module
            for (const auto& mod_name : mgr.dumped_modules()) {
                auto* cls = mgr.find_class(mod_name.c_str(), bare.c_str());
                if (cls) { resolved++; break; }
            }
        }
        LOG_I("Resolved %d/%d RTTI classes with schema data", resolved, mgr.rtti_class_count());
    }

    LOG_I("Total: %d classes, %d fields, %d static, %d enums",
          mgr.class_count(), mgr.total_field_count(),
          mgr.total_static_field_count(), mgr.enum_count());
}

// Phase 3: Global singleton scanning
// Scans .data sections for objects whose vtables match known RTTI classes.
static globals::GlobalMap phase_globals(schema::SchemaManager& mgr) {
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

    return discovered;
}

// Phase 4: Pattern-based global resolution (supplementary)
// Reads patterns.json from temp dir and resolves IDA-style patterns.
// active_game is the host process exe stem (e.g. "cs2", "deadlock"), used to filter
// entries that carry a "game" tag.
struct PatternResult {
    pattern::ResultMap results;
    pattern::PatternConfig config;
};

static PatternResult phase_patterns(const char* temp_dir, const std::string& active_game) {
    PatternResult out;

    char patterns_path[MAX_PATH];
    snprintf(patterns_path, MAX_PATH, "%sdezlock-patterns.json", temp_dir);

    if (pattern::load_config(patterns_path, out.config)) {
        LOG_I("Running supplementary pattern scan (%d patterns, game=%s)...",
              (int)out.config.entries.size(), active_game.c_str());
        out.results = pattern::resolve_all(out.config, active_game);

        int found = 0, total = 0;
        for (const auto& [mod, results] : out.results) {
            for (const auto& r : results) {
                total++;
                if (r.found) found++;
            }
        }
        LOG_I("Patterns: %d/%d resolved", found, total);
    } else {
        LOG_I("No patterns.json — pattern globals skipped (auto-discovery is primary)");
    }

    return out;
}

// Phase 5: Interface scanning
// Enumerates CreateInterface registrations across all loaded DLLs.
static interfaces::InterfaceMap phase_interfaces() {
    LOG_I("Scanning CreateInterface registrations...");
    interfaces::InterfaceMap iface_map = interfaces::scan();
    {
        int total = 0;
        for (const auto& [mod, entries] : iface_map) total += (int)entries.size();
        LOG_I("Discovered %d interfaces across %d modules", total, (int)iface_map.size());
    }
    return iface_map;
}

// Phase 6: String scanning
// Scans for string references and code cross-references.
static strings::StringMap phase_strings(schema::SchemaManager& mgr) {
    LOG_I("Scanning string references...");
    std::unordered_set<std::string> rtti_class_names;
    for (const auto& [key, info] : mgr.rtti_map()) {
        rtti_class_names.insert(schema::rtti_class_name(key));
    }
    strings::StringMap string_map = strings::scan(rtti_class_names);
    {
        int total_str = 0, total_xref = 0;
        for (const auto& [mod, data] : string_map) {
            total_str += data.summary.total_strings;
            total_xref += data.summary.total_xrefs;
        }
        LOG_I("Found %d strings with %d xrefs across %d modules",
              total_str, total_xref, (int)string_map.size());
    }
    return string_map;
}

// Phase 7: Protobuf extraction
// Scans for embedded protobuf descriptors in loaded modules.
static protobuf_scan::ProtoMap phase_protobuf() {
    LOG_I("Scanning for protobuf descriptors...");
    return protobuf_scan::scan();
}

// ============================================================================
// Main worker thread
// ============================================================================

// Derive the host game name from the process exe (e.g. "C:\...\cs2.exe" -> "cs2").
// Returns lowercase stem with no path or extension.
static std::string detect_game_name() {
    char exe_path[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    // Strip directory
    const char* stem = exe_path;
    for (const char* p = exe_path; *p; ++p) {
        if (*p == '\\' || *p == '/') stem = p + 1;
    }

    std::string name(stem);

    // Strip .exe extension (case-insensitive)
    if (name.size() > 4) {
        std::string ext = name.substr(name.size() - 4);
        for (auto& c : ext) c = (char)tolower((unsigned char)c);
        if (ext == ".exe") name.resize(name.size() - 4);
    }

    for (auto& c : name) c = (char)tolower((unsigned char)c);
    return name;
}

void worker_thread(HMODULE hModule) {
    core::log::init("dezlock-worker", true);
    LOG_I("=== Dezlock Dump Worker starting ===");

    // Detect host game from process exe name (e.g. "cs2", "deadlock")
    std::string active_game = detect_game_name();
    LOG_I("Detected game: %s", active_game.c_str());

    // Build output paths
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);

    char json_path[MAX_PATH];
    snprintf(json_path, MAX_PATH, "%sdezlock-export.json", temp_dir);

    char done_path[MAX_PATH];
    snprintf(done_path, MAX_PATH, "%sdezlock-done", temp_dir);

    // Check for live mode
    char live_cfg_path[MAX_PATH];
    snprintf(live_cfg_path, MAX_PATH, "%sdezlock-live.cfg", temp_dir);
    bool live_mode = false;
    {
        FILE* lcfg = fopen(live_cfg_path, "rb");
        if (lcfg) {
            uint32_t magic = 0, flag = 0;
            if (fread(&magic, 4, 1, lcfg) == 1 && fread(&flag, 4, 1, lcfg) == 1) {
                if (magic == 0xDEADDEAD && flag == 1) live_mode = true;
            }
            fclose(lcfg);
            DeleteFileA(live_cfg_path);
        }
    }
    if (live_mode) LOG_I("Live mode enabled — will start pipe server after dump");

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

        auto& mgr = schema::instance();

        // Phase 1: Schema system walking
        if (phase_schema(mgr, schema_sys) == 0)
            goto done;

        // Phase 2: RTTI hierarchy building
        phase_rtti(mgr);

        // Phase 3: Global singleton scanning
        globals::GlobalMap discovered = phase_globals(mgr);

        // Phase 4: Pattern-based global resolution
        PatternResult pat = phase_patterns(temp_dir, active_game);

        // Phase 5: Interface scanning
        interfaces::InterfaceMap iface_map = phase_interfaces();

        // Phase 6: String scanning
        strings::StringMap string_map = phase_strings(mgr);

        // Phase 7: Protobuf extraction
        protobuf_scan::ProtoMap proto_map = phase_protobuf();

        // Export to JSON (all modules)
        LOG_I("Writing JSON export...");
        write_export(mgr, json_path, discovered, pat.results, pat.config,
                     iface_map, string_map, proto_map);

    }

done:
    // Signal completion
    FILE* sig = fopen(done_path, "w");
    if (sig) {
        fprintf(sig, "done\n");
        fclose(sig);
    }

    if (live_mode) {
        LOG_I("=== Dump complete, entering live pipe server mode ===");
        run_pipe_server(hModule);
        // run_pipe_server calls FreeLibraryAndExitThread, never returns
        return;
    }

    LOG_I("=== Worker complete, unloading ===");
    core::log::shutdown();
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
