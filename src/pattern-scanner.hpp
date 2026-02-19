#pragma once
#ifndef DEZLOCK_PATTERN_SCANNER_HPP
#define DEZLOCK_PATTERN_SCANNER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace pattern {

// ============================================================================
// Types
// ============================================================================

enum class ResolveMode {
    RipRelative,  // Standard RIP-relative (MOV/LEA): rva = match + rip_offset + 4 + int32
    Derived       // Resolved from another global + extracted uint32 field offset
};

struct PatternEntry {
    std::string name;
    std::string module;
    ResolveMode mode = ResolveMode::RipRelative;

    // RipRelative fields
    std::string signature;   // IDA-style: "48 8B 0D ?? ?? ?? ??"
    int         rip_offset = 0;

    // Derived fields
    std::string derived_from;       // name of base global (must be RipRelative)
    std::string chain_pattern;      // pattern to extract field offset from
    int         chain_extract_offset = 0; // byte offset within match to read uint32
};

struct PatternConfig {
    int                       version = 1;
    std::vector<PatternEntry> entries;
};

struct GlobalResult {
    std::string name;
    uint32_t    rva = 0;
    bool        found = false;
};

// module name -> vector of results
using ResultMap = std::unordered_map<std::string, std::vector<GlobalResult>>;

// ============================================================================
// API
// ============================================================================

// Parse patterns.json into config struct. Returns false on error.
bool load_config(const char* path, PatternConfig& out);

// Resolve all patterns against loaded modules (in-process).
// Two-pass: RipRelative first, then Derived.
ResultMap resolve_all(const PatternConfig& cfg);

// Low-level: scan memory for IDA-style pattern, resolve RIP-relative.
// Returns RVA from module base, or 0 on failure.
uint32_t scan_rip_relative(const uint8_t* mem, size_t size, uintptr_t base,
                           const char* pattern, int rip_offset);

// Low-level: scan memory for pattern, extract uint32 at extract_offset within match.
// Returns extracted value, or 0 on failure.
uint32_t scan_extract_u32(const uint8_t* mem, size_t size,
                          const char* pattern, int extract_offset);

} // namespace pattern

#endif // DEZLOCK_PATTERN_SCANNER_HPP
