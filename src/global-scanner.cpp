#define LOG_TAG "global-scanner"

#include "global-scanner.hpp"
#include "log.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <unordered_set>

namespace globals {

// ============================================================================
// Safe memory read (SEH protected — we're dereferencing arbitrary .data values)
// ============================================================================

static bool safe_read_u64(uintptr_t addr, uint64_t& out) {
    __try {
        out = *reinterpret_cast<const uint64_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ============================================================================
// PE section walking
// ============================================================================

struct SectionRange {
    uintptr_t start;
    size_t    size;
};

// Find all writable sections (.data, .bss, etc.) in a loaded module
static std::vector<SectionRange> find_writable_sections(uintptr_t base) {
    std::vector<SectionRange> result;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            uintptr_t sec_start = base + sec[i].VirtualAddress;
            size_t sec_size = sec[i].Misc.VirtualSize;
            if (sec_size >= 8) {
                result.push_back({sec_start, sec_size});
            }
        }
    }

    return result;
}

// Quick check: is this value plausibly a user-mode pointer?
static bool is_plausible_pointer(uint64_t val) {
    // x64 user-mode: 0x10000 .. 0x7FFFFFFFFFFF (typical range)
    return val >= 0x10000 && val < 0x800000000000ULL;
}

// ============================================================================
// Core scan
// ============================================================================

GlobalMap scan(const std::unordered_map<std::string, schema::InheritanceInfo>& rtti_map,
               const std::unordered_set<std::string>& schema_classes) {
    GlobalMap results;

    // ---- Build lookup tables ----

    // Collect unique modules that have vtable data
    struct ModuleCtx {
        uintptr_t base = 0;
        size_t    size = 0;
        std::vector<SectionRange> writable;
    };
    std::unordered_map<std::string, ModuleCtx> modules;

    for (const auto& [class_name, info] : rtti_map) {
        if (info.vtable_rva == 0 || info.source_module.empty()) continue;
        if (modules.count(info.source_module)) continue;

        HMODULE hmod = GetModuleHandleA(info.source_module.c_str());
        if (!hmod) continue;

        MODULEINFO mi = {};
        if (!GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi))) continue;

        ModuleCtx ctx;
        ctx.base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        ctx.size = mi.SizeOfImage;
        ctx.writable = find_writable_sections(ctx.base);
        modules[info.source_module] = ctx;
    }

    // Build absolute-vtable-addr -> class name map (across all modules)
    // vtable_abs_addr = module_base + vtable_rva
    std::unordered_map<uint64_t, std::string> vtable_to_class;
    std::unordered_map<std::string, uint32_t> class_to_vtable_rva;

    for (const auto& [class_name, info] : rtti_map) {
        if (info.vtable_rva == 0 || info.source_module.empty()) continue;

        auto mit = modules.find(info.source_module);
        if (mit == modules.end()) continue;

        uint64_t vtable_abs = mit->second.base + info.vtable_rva;
        vtable_to_class[vtable_abs] = class_name;
        class_to_vtable_rva[class_name] = info.vtable_rva;
    }

    LOG_I("Vtable catalog: %d entries across %d modules",
          (int)vtable_to_class.size(), (int)modules.size());

    // ---- Scan each module's writable sections ----

    for (auto& [mod_name, mod] : modules) {
        size_t writable_total = 0;
        for (const auto& sec : mod.writable) writable_total += sec.size;

        LOG_I("Scanning %s .data: %d sections, %zu KB total",
              mod_name.c_str(), (int)mod.writable.size(), writable_total / 1024);

        // Track which classes we've already found (prefer first occurrence)
        std::unordered_set<std::string> found_classes;
        auto& mod_results = results[mod_name];

        for (const auto& sec : mod.writable) {
            size_t scan_end = sec.size - 8;

            for (size_t off = 0; off <= scan_end; off += 8) {
                uintptr_t addr = sec.start + off;
                uint64_t val = *reinterpret_cast<const uint64_t*>(addr);

                if (val == 0) continue;

                // ---- Pass 1: Direct vtable match ----
                // Is this value itself a known vtable address?
                // Means the object lives right here in .data.
                {
                    auto it = vtable_to_class.find(val);
                    if (it != vtable_to_class.end()) {
                        const std::string& cls = it->second;
                        std::string key = cls + ":direct";
                        if (!found_classes.count(key)) {
                            found_classes.insert(key);
                            uint32_t global_rva = (uint32_t)(addr - mod.base);
                            mod_results.push_back({
                                cls, mod_name, global_rva,
                                class_to_vtable_rva[cls], false,
                                schema_classes.count(cls) > 0
                            });
                        }
                        continue; // Don't also check indirect for same address
                    }
                }

                // ---- Pass 2: Indirect (pointer to object) ----
                // Value looks like a pointer -> dereference -> check vtable
                if (!is_plausible_pointer(val)) continue;

                uint64_t vtable_ptr = 0;
                if (!safe_read_u64(val, vtable_ptr)) continue;
                if (vtable_ptr == 0) continue;

                auto it = vtable_to_class.find(vtable_ptr);
                if (it != vtable_to_class.end()) {
                    const std::string& cls = it->second;
                    std::string key = cls + ":pointer";
                    if (!found_classes.count(key)) {
                        found_classes.insert(key);
                        uint32_t global_rva = (uint32_t)(addr - mod.base);
                        mod_results.push_back({
                            cls, mod_name, global_rva,
                            class_to_vtable_rva[cls], true,
                            schema_classes.count(cls) > 0
                        });
                    }
                }
            }
        }

        LOG_I("  %s: found %d globals", mod_name.c_str(), (int)mod_results.size());
    }

    return results;
}

} // namespace globals
