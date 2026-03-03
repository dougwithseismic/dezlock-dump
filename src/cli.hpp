#pragma once

#include <string>

struct CliOptions {
    std::string output_dir;
    std::string target_process;   // empty = interactive selection
    std::string schema_path;      // --schema <path> — skip injection, load JSON directly
    std::string game_display;     // derived display name (e.g. "Deadlock")
    std::string game_name;        // lowercase game name (e.g. "deadlock")
    int timeout_sec = 180;
    int field_depth = 3;
    bool gen_signatures = false;
    bool gen_sdk = false;
    bool gen_layouts = false;
    bool gen_all = false;
    bool live_mode = false;
    bool no_update_check = false;
    bool show_help = false;
};

// Parse command-line arguments. Returns filled CliOptions.
// If --help is requested, prints help and sets show_help = true.
CliOptions parse_args(int argc, char* argv[]);

// Interactive game selection menu. Returns false if user input was invalid.
// On success, sets opts.target_process.
bool select_game(CliOptions& opts);

// Interactive output selection menu (shown when no CLI output flags were passed).
// Modifies opts.gen_sdk, opts.gen_signatures, opts.gen_layouts.
void select_outputs(CliOptions& opts);

// Derive game display name and game name from target_process.
// Also sets default output_dir if not already set.
void derive_game_info(CliOptions& opts);
