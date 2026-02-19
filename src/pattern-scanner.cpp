#define LOG_TAG "pattern-scanner"

#include "pattern-scanner.hpp"
#include "log.hpp"
#include "../vendor/json.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <fstream>
#include <sstream>

using json = nlohmann::json;

namespace pattern {

// ============================================================================
// IDA-style pattern parsing
// ============================================================================

struct ParsedPattern {
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;  // true = must match, false = wildcard
};

static ParsedPattern parse_ida_pattern(const char* sig) {
    ParsedPattern p;
    const char* s = sig;
    while (*s) {
        while (*s == ' ') s++;
        if (!*s) break;

        if (*s == '?') {
            p.bytes.push_back(0);
            p.mask.push_back(false);
            while (*s == '?') s++;
        } else {
            char hex[3] = {s[0], s[1] ? s[1] : '\0', '\0'};
            p.bytes.push_back((uint8_t)strtoul(hex, nullptr, 16));
            p.mask.push_back(true);
            s += (s[1] ? 2 : 1);
        }
    }
    return p;
}

// Find first occurrence of pattern in memory. Returns offset from mem, or -1.
static int64_t find_pattern(const uint8_t* mem, size_t size, const ParsedPattern& pat) {
    if (pat.bytes.empty() || pat.bytes.size() > size) return -1;

    size_t scan_end = size - pat.bytes.size();
    for (size_t i = 0; i <= scan_end; i++) {
        bool match = true;
        for (size_t j = 0; j < pat.bytes.size(); j++) {
            if (pat.mask[j] && mem[i + j] != pat.bytes[j]) {
                match = false;
                break;
            }
        }
        if (match) return (int64_t)i;
    }
    return -1;
}

// ============================================================================
// Config loading
// ============================================================================

bool load_config(const char* path, PatternConfig& out) {
    std::ifstream f(path);
    if (!f.is_open()) {
        LOG_E("Cannot open pattern config: %s", path);
        return false;
    }

    json data;
    try {
        data = json::parse(f);
    } catch (const std::exception& e) {
        LOG_E("Failed to parse pattern config: %s", e.what());
        return false;
    }

    out.version = data.value("version", 1);
    out.entries.clear();

    for (const auto& entry : data.value("entries", json::array())) {
        PatternEntry pe;
        pe.name   = entry.value("name", "");
        pe.module = entry.value("module", "");

        std::string mode_str = entry.value("mode", "rip_relative");
        if (mode_str == "derived") {
            pe.mode = ResolveMode::Derived;
            pe.derived_from        = entry.value("derived_from", "");
            pe.chain_pattern       = entry.value("chain_pattern", "");
            pe.chain_extract_offset = entry.value("chain_extract_offset", 0);
        } else {
            pe.mode       = ResolveMode::RipRelative;
            pe.signature  = entry.value("pattern", "");
            pe.rip_offset = entry.value("rip_offset", 0);
        }

        if (!pe.name.empty() && !pe.module.empty()) {
            out.entries.push_back(std::move(pe));
        }
    }

    LOG_I("Loaded %d pattern entries from config", (int)out.entries.size());
    return true;
}

// ============================================================================
// Scanning
// ============================================================================

uint32_t scan_rip_relative(const uint8_t* mem, size_t size, uintptr_t base,
                           const char* sig, int rip_offset) {
    ParsedPattern pat = parse_ida_pattern(sig);
    int64_t match = find_pattern(mem, size, pat);
    if (match < 0) return 0;

    // RIP-relative: addr = (base + match + rip_offset + 4) + int32_at(match + rip_offset)
    int32_t disp = *(const int32_t*)(mem + match + rip_offset);
    uintptr_t abs_addr = (base + (uintptr_t)match + rip_offset + 4) + disp;
    uint32_t rva = (uint32_t)(abs_addr - base);

    return rva;
}

uint32_t scan_extract_u32(const uint8_t* mem, size_t size,
                          const char* sig, int extract_offset) {
    ParsedPattern pat = parse_ida_pattern(sig);
    int64_t match = find_pattern(mem, size, pat);
    if (match < 0) return 0;

    return *(const uint32_t*)(mem + match + extract_offset);
}

// ============================================================================
// resolve_all — two-pass resolution
// ============================================================================

ResultMap resolve_all(const PatternConfig& cfg) {
    // Group entries by module
    std::unordered_map<std::string, std::vector<const PatternEntry*>> by_module;
    for (const auto& e : cfg.entries) {
        by_module[e.module].push_back(&e);
    }

    // Cache module info
    struct ModuleInfo {
        uintptr_t base = 0;
        size_t    size = 0;
    };
    std::unordered_map<std::string, ModuleInfo> modules;

    for (const auto& [mod_name, _] : by_module) {
        HMODULE hmod = GetModuleHandleA(mod_name.c_str());
        if (!hmod) {
            LOG_W("Module not loaded: %s", mod_name.c_str());
            continue;
        }
        MODULEINFO mi = {};
        if (GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi))) {
            modules[mod_name] = {reinterpret_cast<uintptr_t>(mi.lpBaseOfDll), mi.SizeOfImage};
            LOG_I("Module %s: base=0x%llX size=0x%X",
                  mod_name.c_str(), (unsigned long long)modules[mod_name].base,
                  (unsigned)modules[mod_name].size);
        }
    }

    // Pass 1: RipRelative entries
    // name -> rva (for derived lookups)
    std::unordered_map<std::string, uint32_t> resolved_rvas;
    ResultMap results;

    for (const auto& e : cfg.entries) {
        if (e.mode != ResolveMode::RipRelative) continue;

        auto mit = modules.find(e.module);
        if (mit == modules.end()) {
            results[e.module].push_back({e.name, 0, false});
            continue;
        }

        const auto& mod = mit->second;
        uint32_t rva = scan_rip_relative(
            reinterpret_cast<const uint8_t*>(mod.base), mod.size,
            mod.base, e.signature.c_str(), e.rip_offset);

        if (rva) {
            LOG_I("  %-30s = 0x%X", e.name.c_str(), rva);
            resolved_rvas[e.name] = rva;
            results[e.module].push_back({e.name, rva, true});
        } else {
            LOG_W("  %-30s = NOT FOUND", e.name.c_str());
            results[e.module].push_back({e.name, 0, false});
        }
    }

    // Pass 2: Derived entries
    for (const auto& e : cfg.entries) {
        if (e.mode != ResolveMode::Derived) continue;

        // Look up base RVA
        auto base_it = resolved_rvas.find(e.derived_from);
        if (base_it == resolved_rvas.end()) {
            LOG_W("  %-30s = SKIPPED (base '%s' not found)", e.name.c_str(), e.derived_from.c_str());
            results[e.module].push_back({e.name, 0, false});
            continue;
        }

        // Find module for chain pattern scan (same module as this entry)
        auto mit = modules.find(e.module);
        if (mit == modules.end()) {
            results[e.module].push_back({e.name, 0, false});
            continue;
        }

        const auto& mod = mit->second;
        uint32_t field_offset = scan_extract_u32(
            reinterpret_cast<const uint8_t*>(mod.base), mod.size,
            e.chain_pattern.c_str(), e.chain_extract_offset);

        if (field_offset) {
            uint32_t rva = base_it->second + field_offset;
            LOG_I("  %-30s = 0x%X (derived: %s + 0x%X)",
                  e.name.c_str(), rva, e.derived_from.c_str(), field_offset);
            resolved_rvas[e.name] = rva;
            results[e.module].push_back({e.name, rva, true});
        } else {
            LOG_W("  %-30s = NOT FOUND (chain pattern failed)", e.name.c_str());
            results[e.module].push_back({e.name, 0, false});
        }
    }

    return results;
}

} // namespace pattern
