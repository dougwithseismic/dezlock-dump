/**
 * dezlock-dump — Logging System
 *
 * Timestamped logging to file with severity levels.
 * Thread-safe, usable from shell and logic DLLs.
 */

#pragma once

#include <cstdarg>

namespace core::log {

// Log levels
enum class Level {
    Debug,
    Info,
    Warn,
    Error
};

// Initialize logging - call once at startup
// log_name: base name like "deadlock-arc" (will create deadlock-arc.txt)
// use_temp: if true, writes to %TEMP%/log_name.txt, else current directory
bool init(const char* log_name = "dezlock-dump", bool use_temp = true);

// Shutdown logging - flushes and closes file
void shutdown();

// Check if logging is initialized
bool is_initialized();

// Get log file path (for debug info display)
const char* get_log_path();

// Log with level
void write(Level level, const char* tag, const char* fmt, ...);
void write_v(Level level, const char* tag, const char* fmt, va_list args);

// Convenience functions with automatic tag
void debug(const char* tag, const char* fmt, ...);
void info(const char* tag, const char* fmt, ...);
void warn(const char* tag, const char* fmt, ...);
void error(const char* tag, const char* fmt, ...);

// Set minimum log level (default: Debug in debug builds, Info in release)
void set_min_level(Level level);
Level get_min_level();

// Flush the log file immediately
void flush();

} // namespace core::log

// ============================================================================
// Convenience Macros
// ============================================================================
// Usage: LOG_INFO("shell", "loaded module at 0x%p", addr);

#define LOG_DEBUG(tag, fmt, ...) ::core::log::debug(tag, fmt, ##__VA_ARGS__)
#define LOG_INFO(tag, fmt, ...)  ::core::log::info(tag, fmt, ##__VA_ARGS__)
#define LOG_WARN(tag, fmt, ...)  ::core::log::warn(tag, fmt, ##__VA_ARGS__)
#define LOG_ERROR(tag, fmt, ...) ::core::log::error(tag, fmt, ##__VA_ARGS__)

// Scoped tag macros - define LOG_TAG in your cpp file, then use these
// Example:
//   #define LOG_TAG "aimbot"
//   LOG_D("target acquired at %f", dist);
//
#ifdef LOG_TAG
    #define LOG_D(fmt, ...) LOG_DEBUG(LOG_TAG, fmt, ##__VA_ARGS__)
    #define LOG_I(fmt, ...) LOG_INFO(LOG_TAG, fmt, ##__VA_ARGS__)
    #define LOG_W(fmt, ...) LOG_WARN(LOG_TAG, fmt, ##__VA_ARGS__)
    #define LOG_E(fmt, ...) LOG_ERROR(LOG_TAG, fmt, ##__VA_ARGS__)
#endif
