#pragma once

#include <Windows.h>
#include <cstdio>

// Console handle and log file (global state)
extern HANDLE g_console;
extern FILE* g_log_fp;

// Color constants
static constexpr WORD CLR_DEFAULT = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static constexpr WORD CLR_TITLE   = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
static constexpr WORD CLR_OK      = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD CLR_WARN    = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD CLR_ERR     = FOREGROUND_RED | FOREGROUND_INTENSITY;
static constexpr WORD CLR_DIM     = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static constexpr WORD CLR_STEP    = FOREGROUND_GREEN | FOREGROUND_BLUE;

// Console initialization
void ensure_console();

// Formatted print to both console and log file
void con_print(const char* fmt, ...);

// Set console text color
void con_color(WORD attr);

// Styled output helpers
void con_step(const char* step, const char* msg);
void con_ok(const char* fmt, ...);
void con_fail(const char* fmt, ...);
void con_info(const char* fmt, ...);

// Block until any key is pressed
void wait_for_keypress();

// Check if running with admin privileges
bool is_elevated();

// Create directory and all intermediate parents
bool create_directory_recursive(const char* path);

// Print the startup banner
void print_banner();
