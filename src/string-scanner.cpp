/**
 * dezlock-dump — String Reference Scanner
 *
 * Three-pass scanner per module:
 *   Pass 1: Collect candidate strings from .rdata (categorize as convar/class_name/lifecycle/debug)
 *   Pass 2: Scan .text for RIP-relative references to those strings
 *   Pass 3: Cross-reference with RTTI class names
 */

#define LOG_TAG "string-scanner"

#include "string-scanner.hpp"
#include "log.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <cstring>
#include <algorithm>

namespace strings {

// ============================================================================
// SEH-safe memory reads
// ============================================================================

static bool safe_read_bytes(const void* src, void* dst, size_t len) {
    __try {
        memcpy(dst, src, len);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ============================================================================
// PE section discovery
// ============================================================================

struct SectionRange {
    uintptr_t start;
    size_t    size;
};

// SEH-isolated PE section enumeration (no C++ objects)
static int find_sections_raw(uintptr_t base, uint32_t characteristics,
                             SectionRange* out, int max_out) {
    int count = 0;
    __try {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections && count < max_out; i++) {
            if ((sec[i].Characteristics & characteristics) == characteristics) {
                uintptr_t sec_start = base + sec[i].VirtualAddress;
                size_t sec_size = sec[i].Misc.VirtualSize;
                if (sec_size >= 16) {
                    out[count].start = sec_start;
                    out[count].size = sec_size;
                    count++;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // PE parsing failed
    }
    return count;
}

static std::vector<SectionRange> find_sections(uintptr_t base, uint32_t characteristics) {
    SectionRange buf[64];
    int n = find_sections_raw(base, characteristics, buf, 64);
    return std::vector<SectionRange>(buf, buf + n);
}

// ============================================================================
// String categorization
// ============================================================================

// Check if character is valid printable ASCII (for string scanning)
static bool is_printable(char c) {
    return c >= 0x20 && c <= 0x7E;
}

// Categorize a string. Returns empty string if not interesting.
static std::string categorize_string(const char* str, size_t len) {
    if (len < 3 || len > 512) return "";

    // ConVar: starts with common prefixes
    if ((len >= 3 && strncmp(str, "sv_", 3) == 0) ||
        (len >= 3 && strncmp(str, "mp_", 3) == 0) ||
        (len >= 3 && strncmp(str, "cl_", 3) == 0) ||
        (len >= 2 && strncmp(str, "r_", 2) == 0)  ||
        (len >= 4 && strncmp(str, "net_", 4) == 0) ||
        (len >= 3 && strncmp(str, "cv_", 3) == 0)  ||
        (len >= 5 && strncmp(str, "host_", 5) == 0) ||
        (len >= 4 && strncmp(str, "mat_", 4) == 0) ||
        (len >= 5 && strncmp(str, "snd_", 5) == 0)) {
        // Verify it looks like a convar name (alphanumeric + underscores only)
        bool valid = true;
        for (size_t i = 0; i < len; i++) {
            char c = str[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_')) {
                valid = false;
                break;
            }
        }
        if (valid) return "convar";
    }

    // Class name: starts with C + uppercase (e.g. CGameTraceManager, CTraceFilter)
    if (len >= 3 && str[0] == 'C' && str[1] >= 'A' && str[1] <= 'Z') {
        bool valid = true;
        for (size_t i = 0; i < len; i++) {
            char c = str[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_')) {
                valid = false;
                break;
            }
        }
        if (valid) return "class_name";
    }

    // Lifecycle: contains ::Initialize, ::Shutdown, ::PostInit, etc.
    if (strstr(str, "::Initialize") || strstr(str, "::Shutdown") ||
        strstr(str, "::PostInit") || strstr(str, "::PreShutdown") ||
        strstr(str, "::Start") || strstr(str, "::Stop") ||
        strstr(str, "::OnCreate") || strstr(str, "::OnDestroy")) {
        return "lifecycle";
    }

    // Debug: format strings with %s:: pattern (class method debug prints)
    if (strstr(str, "%s::") || strstr(str, "%s:") ||
        (strstr(str, "::") && strchr(str, '%'))) {
        return "debug";
    }

    return "";
}

// Extract class name from a string (before :: if present)
static std::string extract_class_name(const std::string& str) {
    auto pos = str.find("::");
    if (pos != std::string::npos && pos > 0) {
        // Verify what's before :: looks like a class name
        std::string candidate = str.substr(0, pos);
        // Handle %s prefix for format strings
        if (candidate.size() > 2 && candidate[0] == '%' && candidate[1] == 's')
            return "";
        if (candidate.size() >= 2 && candidate[0] == 'C' && candidate[1] >= 'A' && candidate[1] <= 'Z')
            return candidate;
    }
    return "";
}

// ============================================================================
// Heuristic function start finder
// ============================================================================

// Walk backward from code_addr to find approximate function start
// Looks for common function prologue patterns or CC/INT3 padding
static uint32_t find_func_start(uintptr_t code_addr, uintptr_t text_start, uintptr_t mod_base) {
    // Search backward up to 256 bytes for a prologue or padding
    uintptr_t search_start = (code_addr > text_start + 256) ? code_addr - 256 : text_start;

    for (uintptr_t addr = code_addr - 1; addr >= search_start; addr--) {
        uint8_t byte = 0;
        __try {
            byte = *reinterpret_cast<const uint8_t*>(addr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        // INT3 padding between functions
        if (byte == 0xCC) {
            return static_cast<uint32_t>((addr + 1) - mod_base);
        }
    }

    // Fallback: return the code address itself as approximate
    return static_cast<uint32_t>(code_addr - mod_base);
}

// ============================================================================
// Pass 1: Collect candidate strings from .rdata sections
// ============================================================================

struct CandidateString {
    uintptr_t   addr;
    std::string  value;
    std::string  category;
    std::vector<CodeXref> xrefs; // populated in pass 2
};

// SEH-isolated writable section check (no C++ objects)
static bool is_section_writable(uintptr_t mod_base, uintptr_t sec_start) {
    __try {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod_base);
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(mod_base + dos->e_lfanew);
        auto* sec_hdr = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            uintptr_t s_start = mod_base + sec_hdr[i].VirtualAddress;
            if (s_start == sec_start) {
                return (sec_hdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true; // assume writable on error (skip)
    }
    return false;
}

static std::vector<CandidateString> collect_strings(uintptr_t mod_base) {
    std::vector<CandidateString> candidates;

    // .rdata is read-only initialized data
    auto rdata_sections = find_sections(mod_base,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);

    for (const auto& sec : rdata_sections) {
        // Skip writable sections (those are .data, not .rdata)
        if (is_section_writable(mod_base, sec.start)) continue;

        // Linear scan for null-terminated ASCII strings
        uintptr_t pos = sec.start;
        uintptr_t end = sec.start + sec.size;

        while (pos < end) {
            // Try to read a string starting at pos
            char buf[520] = {};
            size_t max_read = (std::min)((size_t)(end - pos), sizeof(buf) - 1);
            if (!safe_read_bytes(reinterpret_cast<const void*>(pos), buf, max_read)) {
                pos += 16;
                continue;
            }

            // Check if this looks like a string start
            if (!is_printable(buf[0]) || buf[0] == '\0') {
                pos++;
                continue;
            }

            // Find string length
            size_t str_len = 0;
            while (str_len < max_read && buf[str_len] != '\0' && is_printable(buf[str_len])) {
                str_len++;
            }

            // Must be null-terminated and within bounds
            if (str_len < 3 || str_len >= max_read || buf[str_len] != '\0') {
                pos++;
                continue;
            }

            std::string cat = categorize_string(buf, str_len);
            if (!cat.empty()) {
                CandidateString cs;
                cs.addr = pos;
                cs.value = std::string(buf, str_len);
                cs.category = std::move(cat);
                candidates.push_back(std::move(cs));
            }

            // Skip past the string + null terminator
            pos += str_len + 1;
        }
    }

    return candidates;
}

// ============================================================================
// Pass 2: Scan .text for RIP-relative references to candidate strings
// ============================================================================

static void scan_xrefs(std::vector<CandidateString>& candidates,
                       uintptr_t mod_base,
                       std::unordered_map<uintptr_t, size_t>& addr_to_idx) {
    // Build hash set for fast lookup
    addr_to_idx.clear();
    for (size_t i = 0; i < candidates.size(); i++) {
        addr_to_idx[candidates[i].addr] = i;
    }

    // Find .text (executable) sections
    auto text_sections = find_sections(mod_base, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE);

    constexpr int MAX_XREFS_PER_STRING = 100;

    for (const auto& sec : text_sections) {
        // Read entire section for fast scanning
        std::vector<uint8_t> code(sec.size);
        if (!safe_read_bytes(reinterpret_cast<const void*>(sec.start), code.data(), sec.size))
            continue;

        // Scan for LEA reg, [rip+disp32] and MOV reg, [rip+disp32]
        for (size_t i = 0; i + 7 <= code.size(); i++) {
            uint8_t b0 = code[i];

            // Must have REX.W prefix (0x48 or 0x4C)
            if (b0 != 0x48 && b0 != 0x4C) continue;

            uint8_t opcode = code[i + 1];
            // LEA = 0x8D, MOV = 0x8B
            if (opcode != 0x8D && opcode != 0x8B) continue;

            uint8_t modrm = code[i + 2];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            // [rip+disp32] encoding: mod=00, rm=5
            if (mod != 0 || rm != 5) continue;

            // Read disp32
            int32_t disp = 0;
            memcpy(&disp, &code[i + 3], 4);

            // Calculate target address
            uintptr_t insn_addr = sec.start + i;
            uintptr_t insn_end = insn_addr + 7;
            uintptr_t target = insn_end + disp;

            // Check if target matches a candidate string
            auto it = addr_to_idx.find(target);
            if (it == addr_to_idx.end()) continue;

            size_t idx = it->second;
            if ((int)candidates[idx].xrefs.size() >= MAX_XREFS_PER_STRING) continue;

            // Don't store xrefs inline on CandidateString — we'll build StringEntry later
            // For now, tag the xref data onto the candidate
            CodeXref xref;
            xref.code_rva = static_cast<uint32_t>(insn_addr - mod_base);
            xref.func_rva = find_func_start(insn_addr, sec.start, mod_base);
            xref.type = (opcode == 0x8D) ? "LEA" : "MOV";

            candidates[idx].xrefs.push_back(std::move(xref));
        }
    }
}

// ============================================================================
// Pass 3: Cross-reference with RTTI, build final results
// ============================================================================

static ModuleStrings build_results(std::vector<CandidateString>& candidates,
                                   uintptr_t mod_base,
                                   const std::unordered_set<std::string>& rtti_class_names) {
    ModuleStrings result;

    for (auto& cs : candidates) {
        // Skip strings with no xrefs (unreferenced)
        if (cs.xrefs.empty()) continue;

        StringEntry entry;
        entry.value = std::move(cs.value);
        entry.rva = static_cast<uint32_t>(cs.addr - mod_base);
        entry.category = std::move(cs.category);
        entry.xrefs = std::move(cs.xrefs);

        // Cross-reference with RTTI
        if (entry.category == "class_name") {
            if (rtti_class_names.count(entry.value)) {
                entry.associated_class = entry.value;
            }
        } else if (entry.category == "lifecycle" || entry.category == "debug") {
            std::string cls = extract_class_name(entry.value);
            if (!cls.empty() && rtti_class_names.count(cls)) {
                entry.associated_class = cls;
            }
        }

        // Update summary
        result.summary.total_xrefs += (int)entry.xrefs.size();
        if (entry.category == "convar") result.summary.convar++;
        else if (entry.category == "class_name") result.summary.class_name++;
        else if (entry.category == "lifecycle") result.summary.lifecycle++;
        else if (entry.category == "debug") result.summary.debug++;

        result.strings.push_back(std::move(entry));
    }

    result.summary.total_strings = (int)result.strings.size();
    return result;
}

// ============================================================================
// Main scan
// ============================================================================

StringMap scan(const std::unordered_set<std::string>& rtti_class_names) {
    StringMap results;

    HMODULE modules_arr[512];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), modules_arr, sizeof(modules_arr), &needed)) {
        LOG_E("EnumProcessModules failed");
        return results;
    }

    int mod_count = needed / sizeof(HMODULE);
    int total_strings = 0;
    int total_xrefs = 0;

    for (int i = 0; i < mod_count; i++) {
        char mod_path[MAX_PATH];
        if (!GetModuleFileNameA(modules_arr[i], mod_path, MAX_PATH)) continue;

        // Skip Windows system DLLs
        if (strstr(mod_path, "\\Windows\\") || strstr(mod_path, "\\windows\\"))
            continue;

        MODULEINFO mi = {};
        if (!GetModuleInformation(GetCurrentProcess(), modules_arr[i], &mi, sizeof(mi)))
            continue;

        // Skip tiny modules
        if (mi.SizeOfImage < 0x10000) continue;

        // Extract filename
        const char* slash = strrchr(mod_path, '\\');
        const char* mod_name = slash ? slash + 1 : mod_path;

        uintptr_t mod_base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);

        // Pass 1: Collect candidate strings
        auto candidates = collect_strings(mod_base);
        if (candidates.empty()) continue;

        std::unordered_map<uintptr_t, size_t> addr_to_idx;

        // Pass 2: Scan for xrefs
        scan_xrefs(candidates, mod_base, addr_to_idx);

        // Pass 3: Build results with RTTI cross-referencing
        auto mod_result = build_results(candidates, mod_base, rtti_class_names);

        if (mod_result.summary.total_strings > 0) {
            LOG_I("  %s: %d strings, %d xrefs (convar:%d class:%d lifecycle:%d debug:%d)",
                  mod_name,
                  mod_result.summary.total_strings, mod_result.summary.total_xrefs,
                  mod_result.summary.convar, mod_result.summary.class_name,
                  mod_result.summary.lifecycle, mod_result.summary.debug);

            total_strings += mod_result.summary.total_strings;
            total_xrefs += mod_result.summary.total_xrefs;
            results[mod_name] = std::move(mod_result);
        }
    }

    LOG_I("String scan complete: %d strings, %d xrefs across %d modules",
          total_strings, total_xrefs, (int)results.size());
    return results;
}

} // namespace strings
