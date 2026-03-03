#include "src/console.hpp"
#include "version.h"
#include <cstdarg>
#include <string>

HANDLE g_console = INVALID_HANDLE_VALUE;
FILE* g_log_fp = nullptr;

void ensure_console() {
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_console == INVALID_HANDLE_VALUE || g_console == nullptr) {
        AllocConsole();
        g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    // Also open a log file for diagnostics
    char log_path[MAX_PATH];
    GetTempPathA(MAX_PATH, log_path);
    strcat_s(log_path, "dezlock-dump.log");
    g_log_fp = fopen(log_path, "w");
}

void con_print(const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len <= 0) return;

    // Write to console
    DWORD written = 0;
    if (g_console != INVALID_HANDLE_VALUE)
        WriteConsoleA(g_console, buf, (DWORD)len, &written, nullptr);

    // Write to log
    if (g_log_fp) { fwrite(buf, 1, len, g_log_fp); fflush(g_log_fp); }
}

void con_color(WORD attr) {
    if (g_console != INVALID_HANDLE_VALUE)
        SetConsoleTextAttribute(g_console, attr);
}

void con_step(const char* step, const char* msg) {
    con_color(CLR_STEP);
    con_print("[%s] ", step);
    con_color(CLR_DEFAULT);
    con_print("%s\n", msg);
}

void con_ok(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    con_color(CLR_OK);
    con_print("  OK  ");
    con_color(CLR_DEFAULT);
    con_print("%s\n", buf);
}

void con_fail(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    con_color(CLR_ERR);
    con_print("  ERR ");
    con_color(CLR_DEFAULT);
    con_print("%s\n", buf);
}

void con_info(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    con_color(CLR_DIM);
    con_print("      %s\n", buf);
    con_color(CLR_DEFAULT);
}

void wait_for_keypress() {
    con_print("\nPress any key to exit...\n");
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    if (hInput != INVALID_HANDLE_VALUE) {
        FlushConsoleInputBuffer(hInput);
        INPUT_RECORD ir;
        DWORD read;
        while (ReadConsoleInputA(hInput, &ir, 1, &read)) {
            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown)
                break;
        }
    }
}

bool is_elevated() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev = {};
        DWORD size = 0;
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
            elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

bool create_directory_recursive(const char* path) {
    // Try creating directly first (fast path for existing or single-level)
    if (CreateDirectoryA(path, nullptr))
        return true;
    if (GetLastError() == ERROR_ALREADY_EXISTS)
        return true;

    // Walk the path and create each component
    std::string dir(path);
    for (size_t i = 0; i < dir.size(); i++) {
        if (dir[i] == '\\' || dir[i] == '/') {
            std::string partial = dir.substr(0, i);
            if (partial.empty() || partial.back() == ':')
                continue; // skip drive letter (e.g. "C:")
            CreateDirectoryA(partial.c_str(), nullptr);
        }
    }
    // Create the final directory
    if (CreateDirectoryA(path, nullptr))
        return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

void print_banner() {
    con_print("\n");
    con_color(CLR_TITLE);
    con_print("  dezlock-dump");
    con_color(CLR_DIM);
    con_print("  v1.8.0\n");
    con_color(CLR_DEFAULT);
    con_print("  Runtime schema + RTTI extraction for Source 2 games\n");
    con_color(CLR_DIM);
    con_print("  https://github.com/dougwithseismic/dezlock-dump\n");
    con_color(CLR_DEFAULT);
    con_print("\n");
}
