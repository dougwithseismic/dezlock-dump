#include "src/cli.hpp"
#include "src/console.hpp"
#include "src/injector.hpp"

#include <Windows.h>
#include <cstdlib>
#include <cstring>
#include <cctype>

// ============================================================================
// Argument parsing
// ============================================================================

CliOptions parse_args(int argc, char* argv[]) {
    CliOptions opts;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            opts.output_dir = argv[++i];
        } else if (strcmp(argv[i], "--process") == 0 && i + 1 < argc) {
            opts.target_process = argv[++i];
        } else if (strcmp(argv[i], "--wait") == 0 && i + 1 < argc) {
            opts.timeout_sec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--depth") == 0 && i + 1 < argc) {
            opts.field_depth = atoi(argv[++i]);
            if (opts.field_depth < 1) opts.field_depth = 1;
            if (opts.field_depth > 32) opts.field_depth = 32;
        } else if (strcmp(argv[i], "--headers") == 0) {
            // Legacy alias — now handled by --sdk
            opts.gen_sdk = true;
        } else if (strcmp(argv[i], "--signatures") == 0) {
            opts.gen_signatures = true;
        } else if (strcmp(argv[i], "--sdk") == 0) {
            opts.gen_sdk = true;
        } else if (strcmp(argv[i], "--layouts") == 0) {
            opts.gen_layouts = true;
        } else if (strcmp(argv[i], "--all") == 0) {
            opts.gen_all = true;
        } else if (strcmp(argv[i], "--live") == 0) {
            opts.live_mode = true;
        } else if (strcmp(argv[i], "--no-update-check") == 0) {
            opts.no_update_check = true;
        } else if (strcmp(argv[i], "--schema") == 0 && i + 1 < argc) {
            opts.schema_path = argv[++i];
            opts.live_mode = true; // --schema implies live mode
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            con_print("Usage: dezlock-dump.exe [--process <name>] [--output <dir>] [--wait <seconds>] [--depth <N>] [--sdk] [--signatures] [--layouts] [--all] [--live] [--schema <path>]\n\n");
            con_print("  --process     Target process name (skips game selection menu)\n");
            con_print("                Examples: --process cs2.exe, --process dota2.exe\n");
            con_print("  --output      Output directory (default: schema-dump/<game>/ next to exe)\n");
            con_print("  --wait        Max wait time for worker DLL (default: 30s)\n");
            con_print("  --live        Stay running after dump — start WebSocket server on :9100\n");
            con_print("                for real-time memory inspection from the viewer\n");
            con_print("  --schema      Load existing _all-modules.json and start WS server directly\n");
            con_print("                Skips injection/dump. Use with --process to also connect pipe.\n");
            con_print("                Example: --schema schema-dump/deadlock/_all-modules.json\n");
            con_print("  --depth       Field expansion depth for globals/entity trees (default: 3, max: 32)\n");
            con_print("  --sdk         Generate cherry-pickable C++ SDK headers\n");
            con_print("  --signatures  Generate byte pattern signatures\n");
            con_print("  --layouts     Analyze vtable functions for member field offsets\n");
            con_print("  --all         Enable all generators (sdk + signatures + layouts)\n");
            con_print("  --no-update-check  Skip the GitHub update check on startup\n");
            opts.show_help = true;
        }
    }

    return opts;
}

// ============================================================================
// Game selection menu
// ============================================================================

bool select_game(CliOptions& opts) {
    struct GameOption {
        const char* label;
        const char* process;
        const wchar_t* process_w;
    };
    GameOption known_games[] = {
        {"Deadlock",  "deadlock.exe", L"deadlock.exe"},
        {"CS2",       "cs2.exe",      L"cs2.exe"},
        {"Dota 2",    "dota2.exe",    L"dota2.exe"},
    };
    constexpr int NUM_KNOWN = 3;

    // Auto-detect which games are running
    bool running[NUM_KNOWN] = {};
    int auto_pick = -1;
    int running_count = 0;
    for (int i = 0; i < NUM_KNOWN; i++) {
        if (find_process(known_games[i].process_w)) {
            running[i] = true;
            auto_pick = i;
            running_count++;
        }
    }

    // If exactly one game is running, auto-select it
    if (running_count == 1) {
        opts.target_process = known_games[auto_pick].process;
        con_color(CLR_OK);
        con_print("  AUTO ");
        con_color(CLR_DEFAULT);
        con_print("Detected %s running — auto-selecting.\n\n", known_games[auto_pick].label);
        return true;
    }

    // Show menu
    con_print("  Select a game to dump:\n\n");

    for (int i = 0; i < NUM_KNOWN; i++) {
        con_color(CLR_TITLE);
        con_print("    [%d] ", i + 1);
        con_color(CLR_DEFAULT);
        con_print("%-12s", known_games[i].label);
        if (running[i]) {
            con_color(CLR_OK);
            con_print("  (running)");
            con_color(CLR_DEFAULT);
        }
        con_print("\n");
    }

    con_color(CLR_TITLE);
    con_print("    [%d] ", NUM_KNOWN + 1);
    con_color(CLR_DEFAULT);
    con_print("Other (enter process name)\n");

    con_print("\n  > ");

    // Read input
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    char input_buf[256] = {};
    DWORD chars_read = 0;
    ReadConsoleA(hInput, input_buf, sizeof(input_buf) - 1, &chars_read, nullptr);

    // Trim newline
    for (DWORD i = 0; i < chars_read; i++) {
        if (input_buf[i] == '\r' || input_buf[i] == '\n') {
            input_buf[i] = '\0';
            break;
        }
    }

    int choice = atoi(input_buf);
    if (choice >= 1 && choice <= NUM_KNOWN) {
        opts.target_process = known_games[choice - 1].process;
    } else if (choice == NUM_KNOWN + 1) {
        // Custom process name
        con_print("  Enter process name (e.g. game.exe): ");
        char custom_buf[256] = {};
        DWORD custom_read = 0;
        ReadConsoleA(hInput, custom_buf, sizeof(custom_buf) - 1, &custom_read, nullptr);
        for (DWORD i = 0; i < custom_read; i++) {
            if (custom_buf[i] == '\r' || custom_buf[i] == '\n') {
                custom_buf[i] = '\0';
                break;
            }
        }
        opts.target_process = custom_buf;
        if (opts.target_process.empty()) {
            con_fail("No process name entered.");
            return false;
        }
        // Append .exe if not present
        if (opts.target_process.find('.') == std::string::npos) {
            opts.target_process += ".exe";
        }
    } else {
        con_fail("Invalid selection.");
        return false;
    }

    con_print("\n");
    return true;
}

// ============================================================================
// Output selection menu
// ============================================================================

void select_outputs(CliOptions& opts) {
    con_print("\n");
    con_print("  Select outputs to generate:\n\n");

    con_color(CLR_TITLE);
    con_print("    [1] ");
    con_color(CLR_DEFAULT);
    con_print("Schema dump (txt)");
    con_color(CLR_DIM);
    con_print("       always on\n");
    con_color(CLR_DEFAULT);

    con_color(CLR_TITLE);
    con_print("    [2] ");
    con_color(CLR_DEFAULT);
    con_print("C++ SDK\n");

    con_color(CLR_TITLE);
    con_print("    [3] ");
    con_color(CLR_DEFAULT);
    con_print("Byte signatures\n");

    con_color(CLR_TITLE);
    con_print("    [4] ");
    con_color(CLR_DEFAULT);
    con_print("Class layouts (inferred member offsets)\n");

    con_color(CLR_TITLE);
    con_print("    [5] ");
    con_color(CLR_DEFAULT);
    con_print("All of the above\n");

    con_print("\n  Enter choices (e.g. 2 3 4), or press Enter for schema only: ");

    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    char input_buf[256] = {};
    DWORD chars_read = 0;
    ReadConsoleA(hInput, input_buf, sizeof(input_buf) - 1, &chars_read, nullptr);

    for (DWORD ci = 0; ci < chars_read; ci++) {
        if (input_buf[ci] == '5') { opts.gen_sdk = true; opts.gen_signatures = true; opts.gen_layouts = true; }
        if (input_buf[ci] == '2') { opts.gen_sdk = true; }
        if (input_buf[ci] == '3') { opts.gen_signatures = true; }
        if (input_buf[ci] == '4') { opts.gen_layouts = true; }
    }

    con_print("\n");
}

// ============================================================================
// Derive game info from target process
// ============================================================================

void derive_game_info(CliOptions& opts) {
    // Derive display name from process (e.g. "deadlock.exe" -> "Deadlock")
    opts.game_display = opts.target_process;
    {
        auto dot = opts.game_display.rfind('.');
        if (dot != std::string::npos) opts.game_display = opts.game_display.substr(0, dot);
        if (!opts.game_display.empty()) opts.game_display[0] = toupper(opts.game_display[0]);
    }

    // Update console title with selected game
    {
        std::string title = "dezlock-dump - " + opts.game_display + " Schema Extractor";
        SetConsoleTitleA(title.c_str());
    }

    // --all enables everything
    if (opts.gen_all) {
        opts.gen_signatures = true;
        opts.gen_sdk = true;
        opts.gen_layouts = true;
    }

    // Game name (lowercase) for --sdk and folder naming
    opts.game_name = opts.game_display;
    for (auto& c : opts.game_name) c = tolower(c);

    // Default output dir: schema-dump/ next to the exe
    if (opts.output_dir.empty()) {
        char exe_dir[MAX_PATH];
        GetModuleFileNameA(GetModuleHandleA(nullptr), exe_dir, MAX_PATH);
        char full_path[MAX_PATH];
        GetFullPathNameA(exe_dir, MAX_PATH, full_path, nullptr);
        char* last_slash = strrchr(full_path, '\\');
        if (last_slash) *(last_slash + 1) = '\0';
        opts.output_dir = std::string(full_path) + "schema-dump\\" + opts.game_name;
    }
}
