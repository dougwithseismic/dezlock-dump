/**
 * dezlock-dump — String Reference Scanner
 *
 * Finds debug strings, ConVar names, and class name references in .rdata,
 * then traces code cross-references in .text via RIP-relative addressing.
 *
 * Discovers classes without RTTI, finds ConVar registrations revealing
 * manager singletons, and provides code xrefs for reverse engineering.
 */

#pragma once
#ifndef DEZLOCK_STRING_SCANNER_HPP
#define DEZLOCK_STRING_SCANNER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace strings {

// ============================================================================
// Types
// ============================================================================

struct CodeXref {
    uint32_t    code_rva = 0;   // RVA of the referencing instruction
    uint32_t    func_rva = 0;   // Heuristic function start RVA
    std::string type;           // "LEA" or "MOV"
};

struct StringEntry {
    std::string value;              // The string content
    uint32_t    rva = 0;           // RVA of the string in the module
    std::string category;          // "convar", "class_name", "lifecycle", "debug"
    std::string associated_class;  // Matched RTTI class name (if any)
    std::vector<CodeXref> xrefs;   // Code references to this string
};

struct ModuleSummary {
    int total_strings = 0;
    int total_xrefs = 0;
    int convar = 0;
    int class_name = 0;
    int lifecycle = 0;
    int debug = 0;
};

struct ModuleStrings {
    ModuleSummary summary;
    std::vector<StringEntry> strings;
};

// module name -> string scan results
using StringMap = std::unordered_map<std::string, ModuleStrings>;

// ============================================================================
// API
// ============================================================================

// Scan all loaded game DLLs for categorized strings and code cross-references.
// rtti_class_names: set of known RTTI class names for cross-referencing.
// Skips Windows system DLLs. All memory reads are SEH-protected.
StringMap scan(const std::unordered_set<std::string>& rtti_class_names);

} // namespace strings

#endif // DEZLOCK_STRING_SCANNER_HPP
