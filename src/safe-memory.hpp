#pragma once

/**
 * dezlock-dump — SEH-protected memory read utilities
 *
 * Header-only inline functions for safely reading arbitrary game memory.
 * All reads are wrapped in MSVC __try/__except to handle access violations
 * gracefully, since we're dereferencing pointers from game .data/.rdata sections.
 */

#include <Windows.h>
#include <cstdint>
#include <cstring>

namespace safe_mem {

inline bool read_u64(uintptr_t addr, uint64_t& out) {
    __try {
        out = *reinterpret_cast<const uint64_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

inline bool read_bytes(const void* src, void* dst, size_t len) {
    __try {
        memcpy(dst, src, len);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

inline bool read_string(const char* src, char* dst, size_t max_len) {
    __try {
        size_t i = 0;
        for (; i < max_len - 1; i++) {
            dst[i] = src[i];
            if (src[i] == '\0') return true;
        }
        dst[i] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = '\0';
        return false;
    }
}

} // namespace safe_mem
