#define LOG_TAG "global-scanner"

#include "global-scanner.hpp"
#include "schema-manager.hpp"
#include "safe-memory.hpp"
#include "log.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <unordered_set>

namespace globals {

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
               const std::unordered_set<std::string>& schema_classes,
               const std::unordered_set<std::string>& scan_modules) {
    GlobalMap results;

    // ---- Build lookup tables ----

    // Resolve module base addresses for all modules that have vtable data.
    // We need these to compute absolute vtable addresses for the lookup table.
    struct ModuleCtx {
        uintptr_t base = 0;
        size_t    size = 0;
        std::vector<SectionRange> writable;  // only populated for scan targets
    };
    std::unordered_map<std::string, ModuleCtx> modules;

    for (const auto& [key, info] : rtti_map) {
        if (info.vtable_rva == 0 || info.source_module.empty()) continue;
        if (modules.count(info.source_module)) continue;

        HMODULE hmod = GetModuleHandleA(info.source_module.c_str());
        if (!hmod) continue;

        MODULEINFO mi = {};
        if (!GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi))) continue;

        ModuleCtx ctx;
        ctx.base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        ctx.size = mi.SizeOfImage;

        // Only discover writable sections for modules we'll actually scan
        if (scan_modules.count(info.source_module))
            ctx.writable = find_writable_sections(ctx.base);

        modules[info.source_module] = ctx;
    }

    // Build absolute-vtable-addr -> bare class name map (across ALL modules).
    // This ensures we can match vtable pointers even if the class was defined
    // in a non-scanned module (e.g. steamclient64.dll vtable referenced by client.dll).
    std::unordered_map<uint64_t, std::string> vtable_to_class;
    std::unordered_map<std::string, uint32_t> class_to_vtable_rva;

    for (const auto& [key, info] : rtti_map) {
        if (info.vtable_rva == 0 || info.source_module.empty()) continue;

        auto mit = modules.find(info.source_module);
        if (mit == modules.end()) continue;

        std::string bare_name = schema::rtti_class_name(key);
        uint64_t vtable_abs = mit->second.base + info.vtable_rva;
        vtable_to_class[vtable_abs] = bare_name;
        class_to_vtable_rva[key] = info.vtable_rva;  // composite key
    }

    LOG_I("Vtable catalog: %d entries across %d modules",
          (int)vtable_to_class.size(), (int)modules.size());

    // Pre-build a sorted list of readable memory regions for fast pointer validation.
    // This avoids calling VirtualQuery (syscall) or triggering SEH for every pointer.
    struct MemRegion { uintptr_t start; uintptr_t end; };
    std::vector<MemRegion> readable_regions;
    {
        uintptr_t addr = 0x10000;  // skip null page
        MEMORY_BASIC_INFORMATION mbi;
        while (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                !(mbi.Protect & PAGE_GUARD)) {
                uintptr_t rstart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                uintptr_t rend = rstart + mbi.RegionSize;
                // Merge with previous region if contiguous
                if (!readable_regions.empty() && readable_regions.back().end == rstart)
                    readable_regions.back().end = rend;
                else
                    readable_regions.push_back({rstart, rend});
            }
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (addr == 0) break;  // overflow
        }
        LOG_I("Memory map: %d readable regions", (int)readable_regions.size());
    }

    // Lambda: binary search to check if an address falls in a readable region
    auto is_readable = [&readable_regions](uintptr_t addr) -> bool {
        size_t lo = 0, hi = readable_regions.size();
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (addr < readable_regions[mid].start)
                hi = mid;
            else if (addr >= readable_regions[mid].end)
                lo = mid + 1;
            else
                return true;
        }
        return false;
    };

    // ---- Scan each module's writable sections ----

    // Only scan .data of whitelisted modules (game DLLs with schema data).
    // The vtable catalog above includes ALL modules for cross-referencing.
    for (auto& [mod_name, mod] : modules) {
        if (mod.writable.empty()) continue;  // not a scan target

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
                        std::string dedup_key = cls + ":direct";
                        if (!found_classes.count(dedup_key)) {
                            found_classes.insert(dedup_key);
                            uint32_t global_rva = (uint32_t)(addr - mod.base);
                            std::string composite = mod_name + "::" + cls;
                            auto rva_it = class_to_vtable_rva.find(composite);
                            uint32_t vt_rva = (rva_it != class_to_vtable_rva.end()) ? rva_it->second : 0;
                            mod_results.push_back({
                                cls, mod_name, global_rva,
                                vt_rva, false,
                                schema_classes.count(cls) > 0
                            });
                        }
                        continue; // Don't also check indirect for same address
                    }
                }

                // ---- Pass 2: Indirect (pointer to object) ----
                // Value looks like a pointer -> dereference -> check vtable.
                // Use pre-built memory map (binary search) instead of SEH per pointer.
                if (!is_plausible_pointer(val)) continue;
                if (!is_readable(val)) continue;

                uint64_t vtable_ptr = *reinterpret_cast<const uint64_t*>(val);
                if (vtable_ptr == 0) continue;

                auto it = vtable_to_class.find(vtable_ptr);
                if (it != vtable_to_class.end()) {
                    const std::string& cls = it->second;
                    std::string dedup_key = cls + ":pointer";
                    if (!found_classes.count(dedup_key)) {
                        found_classes.insert(dedup_key);
                        uint32_t global_rva = (uint32_t)(addr - mod.base);
                        std::string composite = mod_name + "::" + cls;
                        auto rva_it = class_to_vtable_rva.find(composite);
                        uint32_t vt_rva = (rva_it != class_to_vtable_rva.end()) ? rva_it->second : 0;
                        mod_results.push_back({
                            cls, mod_name, global_rva,
                            vt_rva, true,
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
