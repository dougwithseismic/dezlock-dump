/**
 * Dezlock Dump — Standalone Schema Extraction Tool
 *
 * Usage: dezlock-dump.exe [--process <name>] [--output <dir>] [--wait <seconds>] [--live]
 *
 * 1. Interactive game selection (or --process to skip menu)
 * 2. Injects dezlock-worker.dll via manual-map (PE mapping + shellcode)
 * 3. Waits for the worker to finish (writes JSON to %TEMP%)
 * 4. Reads JSON and generates output files:
 *    - schema-dump/client.txt       (classes + flattened + enums in one file)
 *    - schema-dump/_globals.txt     (global singletons with recursive field trees)
 *    - schema-dump/_access-paths.txt (schema globals only — full offset access guide)
 *    - schema-dump/_entity-paths.txt (every entity class with full field trees)
 *    - schema-dump/_all-modules.json (full JSON)
 *
 * Requires: admin elevation (for process injection)
 * Requires: Target Source 2 game must be running
 */

#include <Windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>

#include "vendor/json.hpp"
#include "src/console.hpp"
#include "src/injector.hpp"
#include "src/cli.hpp"
#include "src/output-generator.hpp"
#include "src/generate-signatures.hpp"
#include "src/import-schema.hpp"
#include "src/analyze-members.hpp"
#include "src/ws-server.hpp"
#include "src/live-bridge.hpp"
#include "src/version-check.hpp"
#include "version.h"
using json = nlohmann::json;

// ============================================================================
// Live Server — shared by --live (after dump) and --schema (standalone)
// ============================================================================

static int run_live_server(const json& data, bool pipe_required) {
    con_print("\n");
    con_step("LIVE", "Starting live memory bridge...");

    // Wire up live bridge logging to console + log file
    live::set_logger([](const char* tag, const char* msg) {
        con_print("  [%s] %s\n", tag, msg);
    });

    try {
        // Connect to DLL's named pipe
        live::PipeClient pipe;
        bool pipe_ok = pipe.connect();
        if (pipe_ok) {
            con_ok("Connected to worker pipe");
        } else if (pipe_required) {
            con_fail("Could not connect to worker pipe. DLL may have unloaded.");
            con_info("Make sure the game is still running and --live was used.");
            wait_for_keypress();
            return 1;
        } else {
            con_info("No pipe connection — schema-only mode (mem.* commands disabled)");
        }

        // Load schema into cache
        con_info("Loading schema into cache...");
        live::SchemaCache cache;
        if (!cache.load(data)) {
            con_fail("Failed to load schema into cache.");
            if (pipe_ok) pipe.shutdown();
            wait_for_keypress();
            return 1;
        }
        con_ok("Schema cached (%d modules)", (int)cache.modules().size());

        // Start WebSocket server
        ws::WsServer ws_server;

        // SubManager for push-based subscriptions
        live::SubManager subs(pipe, cache, [&ws_server](const std::string& msg) {
            ws_server.broadcast(msg);
        });

        // Command dispatcher
        live::CommandDispatcher dispatcher(cache, pipe, subs);

        // Wire up WS message handling
        bool ws_ok = ws_server.start(9100, [&](ws::ClientId client, const std::string& msg) {
            try {
                std::string response = dispatcher.dispatch(msg);
                ws_server.send(client, response);
            } catch (const std::exception& e) {
                live::log_error("WS", "Message handler exception: %s", e.what());
            } catch (...) {
                live::log_error("WS", "Message handler unknown exception!");
            }
        });

        if (!ws_ok) {
            con_fail("Could not start WebSocket server on port 9100.");
            con_info("Port may be in use. Check for another instance.");
            if (pipe_ok) pipe.shutdown();
            wait_for_keypress();
            return 1;
        }

        ws_server.set_on_connect([](ws::ClientId) {});
        ws_server.set_on_disconnect([](ws::ClientId) {});

        con_ok("WebSocket server listening on ws://127.0.0.1:9100");
        con_print("\n");
        con_color(CLR_TITLE);
        con_print("  LIVE MODE ACTIVE");
        if (!pipe_ok) con_print(" (schema-only)");
        con_print("\n");
        con_color(CLR_DEFAULT);
        con_print("  Open viewer/index.html and click 'Connect Live'\n");
        con_print("  Press Ctrl+C to stop.\n\n");

        // Ctrl+C handler
        static std::atomic<bool> g_shutdown{false};
        g_shutdown.store(false);
        SetConsoleCtrlHandler([](DWORD type) -> BOOL {
            if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT) {
                g_shutdown.store(true);
                return TRUE;
            }
            return FALSE;
        }, TRUE);

        // Block until shutdown
        while (!g_shutdown.load()) {
            Sleep(100);
            // Check if pipe is still alive (only when we had one)
            if (pipe_ok && !pipe.connected()) {
                con_print("\n");
                con_fail("Game disconnected (pipe broken).");
                con_info("WS server still running for schema queries. Ctrl+C to stop.");
                pipe_ok = false;
            }
        }

        con_print("\n");
        con_step("---", "Shutting down...");

        subs.stop();
        ws_server.stop();
        if (pipe_ok) pipe.shutdown();

        con_ok("Live bridge stopped.");

    } catch (const std::exception& e) {
        con_fail("Live bridge crashed: %s", e.what());
        wait_for_keypress();
        return 1;
    } catch (...) {
        con_fail("Live bridge crashed with unknown exception.");
        wait_for_keypress();
        return 1;
    }

    con_print("\n");
    if (g_log_fp) fclose(g_log_fp);
    return 0;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    ensure_console();

    // Parse args
    CliOptions opts = parse_args(argc, argv);
    if (opts.show_help) {
        wait_for_keypress();
        return 0;
    }

    // Banner
    SetConsoleTitleA("dezlock-dump - Source 2 Schema Extractor");
    print_banner();

    // Version check (non-blocking, silent on failure)
    if (!opts.no_update_check) {
        auto update = check_for_update();
        if (update.has_update) {
            con_color(CLR_WARN);
            con_print("  UPDATE  ");
            con_color(CLR_DEFAULT);
            con_print("New version available: %s (you have %s)\n",
                      update.latest_version.c_str(), DEZLOCK_VERSION_STR);
            con_color(CLR_DIM);
            con_print("          %s\n", update.release_url.c_str());
            con_color(CLR_DEFAULT);
            con_print("\n");
        }
    }

    // --schema fast path: load JSON and jump straight to live mode
    if (!opts.schema_path.empty()) {
        con_step("1/2", "Loading schema from file...");

        FILE* sfp = fopen(opts.schema_path.c_str(), "rb");
        if (!sfp) {
            con_fail("Cannot open schema file: %s", opts.schema_path.c_str());
            wait_for_keypress();
            return 1;
        }
        fseek(sfp, 0, SEEK_END);
        long ssize = ftell(sfp);
        fseek(sfp, 0, SEEK_SET);
        std::string schema_json(ssize, '\0');
        fread(&schema_json[0], 1, ssize, sfp);
        fclose(sfp);

        json data;
        try {
            data = json::parse(schema_json);
        } catch (const std::exception& e) {
            con_fail("Failed to parse schema: %s", e.what());
            wait_for_keypress();
            return 1;
        }

        con_ok("Loaded %s (%.1f MB)", opts.schema_path.c_str(), ssize / (1024.0 * 1024.0));
        return run_live_server(data, false);
    }

    // Interactive game selection (when --process not provided)
    if (opts.target_process.empty()) {
        if (!select_game(opts)) {
            wait_for_keypress();
            return 1;
        }
    }

    // Derive game display name, game name, and default output dir
    derive_game_info(opts);

    // ---- Pre-flight checks ----
    con_step("1/5", "Checking prerequisites...");

    if (!is_elevated()) {
        con_fail("Not running as administrator.");
        con_print("\n");
        con_color(CLR_WARN);
        con_print("  This tool needs admin privileges to read %s's memory.\n", opts.game_display.c_str());
        con_print("  Right-click dezlock-dump.exe -> Run as administrator\n");
        con_color(CLR_DEFAULT);
        wait_for_keypress();
        return 1;
    }
    con_ok("Running as administrator");

    // Check: Target game is running
    wchar_t target_wide[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, opts.target_process.c_str(), -1, target_wide, MAX_PATH);

    DWORD pid = find_process(target_wide);
    if (!pid) {
        con_fail("%s is not running.", opts.game_display.c_str());
        con_print("\n");
        con_color(CLR_WARN);
        con_print("  Please launch %s first, then run this tool.\n", opts.game_display.c_str());
        con_print("  The game needs to be fully loaded (main menu or in a match).\n");
        con_color(CLR_DEFAULT);
        con_print("\n");
        con_info("Waiting for %s to start...", opts.game_display.c_str());

        const char* spinner = "|/-\\";
        int spin = 0;
        int wait_count = 0;
        while (!pid) {
            Sleep(500);
            pid = find_process(target_wide);
            wait_count++;

            char spin_buf[64];
            snprintf(spin_buf, sizeof(spin_buf), "  %c Waiting... (%ds)\r",
                     spinner[spin % 4], wait_count / 2);
            con_print("%s", spin_buf);
            spin++;

            if (wait_count > 600) {
                con_print("\n");
                con_fail("Timed out waiting for %s (5 min). Exiting.", opts.game_display.c_str());
                wait_for_keypress();
                return 1;
            }
        }
        con_print("\n");
    }
    con_ok("%s found (PID: %lu)", opts.game_display.c_str(), pid);

    // Check: Worker DLL exists
    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    char* slash = strrchr(exe_path, '\\');
    if (slash) *(slash + 1) = '\0';

    char dll_path[MAX_PATH];
    snprintf(dll_path, MAX_PATH, "%sdezlock-worker.dll", exe_path);

    if (GetFileAttributesA(dll_path) == INVALID_FILE_ATTRIBUTES) {
        con_fail("dezlock-worker.dll not found next to this exe.");
        con_info("Make sure both files are in the same folder:");
        con_info("  dezlock-dump.exe");
        con_info("  dezlock-worker.dll");
        wait_for_keypress();
        return 1;
    }
    con_ok("Worker DLL found");

    // ---- Injection ----
    con_step("2/5", "Preparing worker...");

    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);

    char json_path[MAX_PATH], done_path[MAX_PATH], patterns_temp[MAX_PATH];
    snprintf(json_path, MAX_PATH, "%sdezlock-export.json", temp_dir);
    snprintf(done_path, MAX_PATH, "%sdezlock-done", temp_dir);
    snprintf(patterns_temp, MAX_PATH, "%sdezlock-patterns.json", temp_dir);
    DeleteFileA(done_path);
    DeleteFileA(json_path);

    // Copy patterns.json to %TEMP% for supplementary pattern scan (optional)
    {
        char patterns_src[MAX_PATH];
        snprintf(patterns_src, MAX_PATH, "%spatterns.json", exe_path);
        if (GetFileAttributesA(patterns_src) != INVALID_FILE_ATTRIBUTES) {
            CopyFileA(patterns_src, patterns_temp, FALSE);
        }
    }

    // Write live config file before injection (tells DLL to stay loaded)
    {
        char live_cfg_path[MAX_PATH];
        snprintf(live_cfg_path, MAX_PATH, "%sdezlock-live.cfg", temp_dir);
        if (opts.live_mode) {
            FILE* lcfg = fopen(live_cfg_path, "wb");
            if (lcfg) {
                uint32_t magic = 0xDEADDEAD;
                uint32_t flag = 1;
                fwrite(&magic, 4, 1, lcfg);
                fwrite(&flag, 4, 1, lcfg);
                fclose(lcfg);
            }
        } else {
            DeleteFileA(live_cfg_path); // clean up stale config
        }
    }

    {
        std::string step_msg = "Extracting schema from " + opts.game_display + "...";
        con_step(opts.live_mode ? "3/6" : "3/5", step_msg.c_str());
    }
    con_info("This reads class layouts and field offsets from the game's memory.");
    if (opts.live_mode) {
        con_info("%s will not be modified in read-only mode. Write requires --live.", opts.game_display.c_str());
    } else {
        con_info("%s will not be modified. This is read-only.", opts.game_display.c_str());
    }

    if (!inject_dll(pid, dll_path)) {
        con_fail("Could not connect to %s process.", opts.game_display.c_str());
        con_info("Make sure the game is fully loaded (not still on splash screen).");
        con_info("If the problem persists, try restarting %s.", opts.game_display.c_str());
        wait_for_keypress();
        return 1;
    }
    con_ok("Connected to %s", opts.game_display.c_str());

    // ---- Wait for completion ----
    con_step("4/5", "Dumping schema data...");

    const char* spinner = "|/-\\";
    int waited = 0;
    int spin = 0;
    while (waited < opts.timeout_sec * 10) {
        if (GetFileAttributesA(done_path) != INVALID_FILE_ATTRIBUTES)
            break;
        Sleep(100);
        waited++;

        if (waited % 2 == 0) {
            int secs = waited / 10;
            char spin_buf[128];
            if (secs < 30) {
                snprintf(spin_buf, sizeof(spin_buf), "  %c Working... (%ds)\r",
                         spinner[spin % 4], secs);
            } else if (secs < 60) {
                snprintf(spin_buf, sizeof(spin_buf), "  %c Working... (%ds) — scanning modules + globals\r",
                         spinner[spin % 4], secs);
            } else {
                snprintf(spin_buf, sizeof(spin_buf), "  %c Working... (%ds) — writing export (large JSON)\r",
                         spinner[spin % 4], secs);
            }
            con_print("%s", spin_buf);
            spin++;
        }
    }
    con_print("                              \r"); // clear spinner line

    if (GetFileAttributesA(done_path) == INVALID_FILE_ATTRIBUTES) {
        con_fail("Schema dump timed out after %ds.", opts.timeout_sec);
        con_info("The game might not be fully loaded yet. Try again in a match.");

        char worker_log[MAX_PATH];
        snprintf(worker_log, MAX_PATH, "%sdezlock-worker.txt", temp_dir);
        con_info("Worker log: %s", worker_log);

        wait_for_keypress();
        return 1;
    }
    con_ok("Schema extracted (%.1fs)", waited / 10.0f);

    // ---- Interactive output selection (when no CLI flags were passed) ----
    if (!opts.gen_signatures && !opts.gen_sdk && !opts.gen_layouts) {
        select_outputs(opts);
    }

    // ---- Generate output ----
    con_step("5/5", "Generating output files...");

    FILE* fp = fopen(json_path, "rb");
    if (!fp) {
        con_fail("Cannot read export data.");
        wait_for_keypress();
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    std::string json_str(fsize, '\0');
    size_t bytes_read = fread(&json_str[0], 1, fsize, fp);
    fclose(fp);
    json_str.resize(bytes_read);

    // Trim trailing garbage after the last '}'
    auto last_brace = json_str.rfind('}');
    if (last_brace != std::string::npos && last_brace + 1 < json_str.size())
        json_str.resize(last_brace + 1);

    json data;
    try {
        data = json::parse(json_str);
    } catch (const std::exception& e) {
        con_fail("Failed to parse export data: %s", e.what());
        wait_for_keypress();
        return 1;
    }

    int total_classes = data.value("total_classes", data.value("class_count", 0));
    int total_enums = data.value("total_enums", data.value("enum_count", 0));
    int rtti_count = data.value("rtti_classes", 0);
    int total_static = data.value("total_static_fields", 0);

    auto modules = parse_modules(data);

    if (!create_directory_recursive(opts.output_dir.c_str())) {
        con_fail("Cannot create output directory: %s", opts.output_dir.c_str());
        wait_for_keypress();
        return 1;
    }

    // Build cross-module class lookup for flattening inherited fields
    std::unordered_map<std::string, const ClassInfo*> global_class_lookup;
    for (const auto& mod : modules) {
        for (const auto& cls : mod.classes) {
            if (global_class_lookup.find(cls.name) == global_class_lookup.end())
                global_class_lookup[cls.name] = &cls;
        }
    }

    for (auto& mod : modules) {
        std::string module_name = mod.name;
        {
            auto pos = module_name.rfind(".dll");
            if (pos != std::string::npos) module_name = module_name.substr(0, pos);
        }

        std::sort(mod.classes.begin(), mod.classes.end(),
                  [](const ClassInfo& a, const ClassInfo& b) { return a.name < b.name; });
        std::sort(mod.enums.begin(), mod.enums.end(),
                  [](const EnumInfo& a, const EnumInfo& b) { return a.name < b.name; });

        generate_module_txt(mod.classes, mod.enums, data, opts.output_dir, module_name, global_class_lookup);
        generate_hierarchy(mod.classes, opts.output_dir, module_name, global_class_lookup);

        con_ok("%-20s  %4d classes, %4d enums", mod.name.c_str(),
               (int)mod.classes.size(), (int)mod.enums.size());
    }

    // ---- Member layout analysis (optional) ----
    MemberAnalysisStats layout_stats = {};
    if (opts.gen_layouts) {
        con_print("\n");
        con_step("LAY", "Analyzing vtable functions for member offsets...");
        layout_stats = analyze_members(data);
        con_ok("Layouts: %d classes, %d inferred fields", layout_stats.classes_analyzed, layout_stats.total_fields);
    }

    // Write enriched JSON
    {
        std::string json_out = opts.output_dir + "\\_all-modules.json";
        if (opts.gen_layouts && data.contains("member_layouts")) {
            FILE* jfp = fopen(json_out.c_str(), "wb");
            if (jfp) {
                std::string dumped = data.dump();
                fwrite(dumped.data(), 1, dumped.size(), jfp);
                fclose(jfp);
            }
        } else {
            CopyFileA(json_path, json_out.c_str(), FALSE);
        }
    }

    // ---- Globals, access-paths, entity-paths, protobuf ----
    generate_globals_txt(data, modules, opts.output_dir, opts.field_depth);
    generate_entity_paths(data, modules, opts.output_dir, opts.field_depth);
    generate_protobuf_output(data, opts.output_dir);

    // ---- Signature generation (optional) ----
    SignatureStats sig_stats = {};
    if (opts.gen_signatures) {
        con_print("\n");
        con_step("SIG", "Generating byte pattern signatures...");

        std::string sig_output = opts.output_dir + "\\signatures";
        sig_stats = generate_signatures(data, sig_output);
        con_ok("Signatures generated -> %s\\", sig_output.c_str());
    }

    // ---- SDK generation (optional) ----
    SdkStats sdk_stats = {};
    bool sdk_ok = false;
    if (opts.gen_sdk) {
        con_print("\n");
        con_step("SDK", "Generating cherry-pickable C++ SDK...");

        std::string sdk_output = opts.output_dir + "\\sdk";
        sdk_stats = generate_sdk(data, modules, global_class_lookup, sdk_output,
                                  opts.game_name, std::string(exe_path));
        sdk_ok = true;
        con_ok("SDK generated -> %s\\", sdk_output.c_str());
    }

    // Clean up temp files
    DeleteFileA(done_path);
    DeleteFileA(patterns_temp);

    // ---- Summary ----
    con_print("\n");
    con_color(CLR_TITLE);
    con_print("  Done!\n\n");
    con_color(CLR_DEFAULT);

    con_print("  %-20s %d\n", "Modules:", (int)modules.size());
    con_print("  %-20s %d\n", "Classes:", total_classes);
    con_print("  %-20s %d\n", "Enums:", total_enums);
    con_print("  %-20s %d\n", "RTTI hierarchies:", rtti_count);
    con_print("  %-20s %d\n", "Static fields:", total_static);
    if (data.contains("globals")) {
        int glob_total = 0, glob_schema = 0;
        for (const auto& [mod_name, mod_globals] : data["globals"].items()) {
            if (!mod_globals.is_array()) continue;
            glob_total += (int)mod_globals.size();
            for (const auto& g : mod_globals) {
                if (g.value("has_schema", false)) glob_schema++;
            }
        }
        con_print("  %-20s %d with schema, %d total\n", "Global singletons:", glob_schema, glob_total);
    }
    if (data.contains("pattern_globals")) {
        int pat_count = 0;
        for (const auto& [mod_name, mod_pats] : data["pattern_globals"].items()) {
            if (mod_pats.is_object())
                pat_count += (int)mod_pats.size();
        }
        if (pat_count > 0)
            con_print("  %-20s %d (from patterns.json)\n", "Pattern globals:", pat_count);
    }
    if (data.contains("interfaces")) {
        int iface_total = 0;
        for (const auto& [mod_name, mod_ifaces] : data["interfaces"].items()) {
            if (mod_ifaces.is_array())
                iface_total += (int)mod_ifaces.size();
        }
        if (iface_total > 0)
            con_print("  %-20s %d\n", "Interfaces:", iface_total);
    }
    if (data.contains("string_refs")) {
        int str_total = 0, xref_total = 0;
        for (const auto& [mod_name, mod_strs] : data["string_refs"].items()) {
            if (mod_strs.contains("summary") && mod_strs["summary"].is_object()) {
                str_total += mod_strs["summary"].value("total_strings", 0);
                xref_total += mod_strs["summary"].value("total_xrefs", 0);
            }
        }
        if (str_total > 0)
            con_print("  %-20s %d strings, %d xrefs\n", "String refs:", str_total, xref_total);
    }
    if (data.contains("protobuf_messages")) {
        int pb_files = 0, pb_msgs = 0;
        for (const auto& [mod_name, mod_data] : data["protobuf_messages"].items()) {
            if (mod_data.contains("files")) {
                pb_files += (int)mod_data["files"].size();
                for (const auto& f : mod_data["files"]) {
                    if (f.contains("messages"))
                        pb_msgs += (int)f["messages"].size();
                }
            }
        }
        if (pb_files > 0)
            con_print("  %-20s %d files, %d messages\n", "Protobuf:", pb_files, pb_msgs);
    }
    if (layout_stats.classes_analyzed > 0) {
        con_print("  %-20s %d classes, %d inferred fields\n",
                  "Member layouts:", layout_stats.classes_analyzed, layout_stats.total_fields);
    }
    if (sig_stats.total > 0) {
        con_print("  %-20s %d (%d unique, %d class-unique, %d stubs)\n",
                  "Signatures:", sig_stats.total, sig_stats.unique,
                  sig_stats.class_unique, sig_stats.stubs);
    }
    if (sdk_ok) {
        con_print("  %-20s %d structs, %d enums, %d vtables\n",
                  "SDK:", sdk_stats.structs, sdk_stats.enums, sdk_stats.vtables);
        if (sdk_stats.globals > 0)
            con_print("  %-20s %d globals, %d patterns\n", "", sdk_stats.globals, sdk_stats.patterns);
        if (sdk_stats.rtti_layouts > 0)
            con_print("  %-20s %d RTTI layout headers\n", "", sdk_stats.rtti_layouts);
        if (sdk_stats.total_fields > 0)
            con_print("  %-20s %d/%d fields resolved\n", "Type resolution:",
                      sdk_stats.resolved, sdk_stats.total_fields);
    }
    con_print("\n");

    con_color(CLR_OK);
    con_print("  Output: ");
    con_color(CLR_DEFAULT);
    con_print("%s\\\n\n", opts.output_dir.c_str());

    con_color(CLR_DIM);
    con_print("  Quick start:\n");
    con_print("    grep m_iHealth %s\\client.txt\n", opts.output_dir.c_str());
    con_print("    grep FLATTENED %s\\client.txt\n", opts.output_dir.c_str());
    con_print("    grep EAbilitySlots %s\\client.txt\n", opts.output_dir.c_str());
    if (opts.gen_signatures && sig_stats.total > 0) {
        con_print("    grep CCitadelInput %s\\signatures\\client.txt\n", opts.output_dir.c_str());
    }
    if (sdk_ok) {
        con_print("    #include \"sdk/client/C_BaseEntity.hpp\"\n");
    }

    con_color(CLR_DEFAULT);

    // ---- Live mode: start WebSocket server for real-time memory inspection ----
    if (opts.live_mode) {
        return run_live_server(data, true /* pipe required */);
    }

    if (g_log_fp) fclose(g_log_fp);

    wait_for_keypress();
    return 0;
}
