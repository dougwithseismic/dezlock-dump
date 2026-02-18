/**
 * dezlock-dump — Logging System Implementation
 */

#include "log.hpp"

#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <share.h>

namespace core::log {

namespace {

// State
FILE* g_file = nullptr;
char g_path[MAX_PATH] = {};
CRITICAL_SECTION g_cs;
bool g_cs_initialized = false;

#ifdef _DEBUG
Level g_min_level = Level::Debug;
#else
Level g_min_level = Level::Info;
#endif

// Level strings (fixed width for alignment)
const char* level_str(Level lvl) {
    switch (lvl) {
        case Level::Debug: return "DEBUG";
        case Level::Info:  return "INFO ";
        case Level::Warn:  return "WARN ";
        case Level::Error: return "ERROR";
        default:           return "?????";
    }
}

// Get current timestamp as string: HH:MM:SS.mmm
void get_timestamp(char* buf, size_t buf_size) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, buf_size, "%02d:%02d:%02d.%03d",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// Build log file path
bool build_path(const char* log_name, bool use_temp) {
    g_path[0] = '\0';

    // Try temp directory
    if (use_temp) {
        char temp_dir[MAX_PATH] = {};
        DWORD len = GetTempPathA(MAX_PATH, temp_dir);
        if (len > 0 && len < MAX_PATH) {
            snprintf(g_path, MAX_PATH, "%s%s.txt", temp_dir, log_name);
            return true;
        }
    }

    // Fallback to current directory
    snprintf(g_path, MAX_PATH, "%s.txt", log_name);
    return true;
}

} // anonymous namespace

bool init(const char* log_name, bool use_temp) {
    if (g_file) return true; // Already initialized

    // Initialize critical section
    if (!g_cs_initialized) {
        InitializeCriticalSection(&g_cs);
        g_cs_initialized = true;
    }

    // Build path
    if (!build_path(log_name, use_temp)) {
        return false;
    }

    // Open file with shared read access (allows tail -f while running)
    g_file = _fsopen(g_path, "a", _SH_DENYNO);
    if (!g_file) {
        // Try without shared access
        g_file = fopen(g_path, "a");
    }

    if (!g_file) {
        return false;
    }

    // Write session header
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(g_file, "\n");
    fprintf(g_file, "================================================================================\n");
    fprintf(g_file, "[%s] dezlock-dump — Session Start\n", timestamp);
    fprintf(g_file, "================================================================================\n");
    fflush(g_file);

    return true;
}

void shutdown() {
    if (!g_file) return;

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(g_file, "[%s] [INFO ] [log] Session end\n", timestamp);
    fprintf(g_file, "================================================================================\n\n");
    fflush(g_file);
    fclose(g_file);
    g_file = nullptr;

    if (g_cs_initialized) {
        DeleteCriticalSection(&g_cs);
        g_cs_initialized = false;
    }
}

bool is_initialized() {
    return g_file != nullptr;
}

const char* get_log_path() {
    return g_path;
}

void write_v(Level level, const char* tag, const char* fmt, va_list args) {
    if (!g_file) return;
    if (level < g_min_level) return;

    EnterCriticalSection(&g_cs);

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    // Format: [HH:MM:SS.mmm] [LEVEL] [tag] message
    fprintf(g_file, "[%s] [%s] [%s] ", timestamp, level_str(level), tag);
    vfprintf(g_file, fmt, args);
    fprintf(g_file, "\n");
    fflush(g_file);

    LeaveCriticalSection(&g_cs);
}

void write(Level level, const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_v(level, tag, fmt, args);
    va_end(args);
}

void debug(const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_v(Level::Debug, tag, fmt, args);
    va_end(args);
}

void info(const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_v(Level::Info, tag, fmt, args);
    va_end(args);
}

void warn(const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_v(Level::Warn, tag, fmt, args);
    va_end(args);
}

void error(const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_v(Level::Error, tag, fmt, args);
    va_end(args);
}

void set_min_level(Level level) {
    g_min_level = level;
}

Level get_min_level() {
    return g_min_level;
}

void flush() {
    if (g_file) {
        EnterCriticalSection(&g_cs);
        fflush(g_file);
        LeaveCriticalSection(&g_cs);
    }
}

} // namespace core::log
