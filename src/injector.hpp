#pragma once

#include <Windows.h>
#include <cstdint>

// Find a running process by name. Returns PID or 0 if not found.
DWORD find_process(const wchar_t* name);

// Parse a PE DLL from disk and manual-map inject it into the target process.
// Returns true on success.
bool inject_dll(DWORD pid, const char* dll_path);
