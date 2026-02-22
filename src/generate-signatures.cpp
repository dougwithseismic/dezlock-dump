/**
 * dezlock-dump -- C++ port of generate-signatures.py
 *
 * Full port of the Python signature generation logic including:
 *   - Stub detection (ret, xor+ret, mov+ret, lea+ret, int3 padding)
 *   - Byte masking for relocatable addresses (E8/E9, Jcc, FF15/FF25, RIP-relative)
 *   - COMDAT/RVA deduplication with shared_with tracking
 *   - Module-level shortest unique prefix computation (sorted-neighbor)
 *   - Per-class uniqueness computation
 *   - Multi-threaded per-module processing
 *   - Text and JSON output generation
 */

#include "generate-signatures.hpp"

#include <atomic>
#include <cstdio>
#include <cstdint>
#include <algorithm>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <Windows.h>

using json = nlohmann::json;

// ============================================================================
// Internal types
// ============================================================================

namespace {

struct SigEntry {
    std::string class_name;
    int index = 0;
    std::string rva;
    int byte_count = 0;
    bool stub = false;
    std::string stub_type;
    bool unique = false;
    bool class_unique = false;
    int unique_length = 0;
    std::string pattern;
    std::vector<std::string> shared_with;
    std::vector<std::string> _tokens; // internal, cleared after processing
};

// ============================================================================
// Stub detection
// ============================================================================

struct StubPattern {
    std::vector<uint8_t> bytes;
    const char* label;
};

static const StubPattern STUB_PATTERNS[] = {
    { {0xC3},                         "ret" },
    { {0x33, 0xC0, 0xC3},            "xor_eax_ret" },
    { {0x32, 0xC0, 0xC3},            "xor_al_ret" },
    { {0x0F, 0x57, 0xC0, 0xC3},      "xorps_ret" },
    { {0xB0, 0x00, 0xC3},            "mov_al_0_ret" },
    { {0xB0, 0x01, 0xC3},            "mov_al_1_ret" },
    { {0xCC},                         "int3" },
};

// Returns stub type string, or empty string if not a stub
std::string detect_stub(const std::vector<uint8_t>& raw) {
    if (raw.empty()) return "";

    // Check fixed patterns first
    for (const auto& sp : STUB_PATTERNS) {
        if (raw.size() >= sp.bytes.size()) {
            bool match = true;
            for (size_t i = 0; i < sp.bytes.size(); i++) {
                if (raw[i] != sp.bytes[i]) { match = false; break; }
            }
            if (match) return sp.label;
        }
    }

    // B8 xx xx xx xx C3 -- mov eax, imm32; ret
    if (raw.size() >= 6 && raw[0] == 0xB8 && raw[5] == 0xC3) {
        return "mov_eax_imm_ret";
    }

    // 48 8D 05 xx xx xx xx C3 -- lea rax, [rip+disp32]; ret
    if (raw.size() >= 8 && raw[0] == 0x48 && raw[1] == 0x8D && raw[2] == 0x05 && raw[7] == 0xC3) {
        return "lea_rax_ret";
    }

    // All CC bytes in first 8 (int3 padding / dead code)
    {
        size_t check_len = (std::min)(raw.size(), (size_t)8);
        bool all_cc = true;
        for (size_t i = 0; i < check_len; i++) {
            if (raw[i] != 0xCC) { all_cc = false; break; }
        }
        if (all_cc) return "int3_pad";
    }

    return "";
}

// ============================================================================
// Hex parsing
// ============================================================================

static int hex_char_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return -1;
}

std::vector<uint8_t> parse_hex_bytes(const std::string& hex_str) {
    std::vector<uint8_t> result;
    result.reserve(hex_str.size() / 2);
    for (size_t i = 0; i + 1 < hex_str.size(); i += 2) {
        int hi = hex_char_val(hex_str[i]);
        int lo = hex_char_val(hex_str[i + 1]);
        if (hi < 0 || lo < 0) break;
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return result;
}

// ============================================================================
// Byte masking
// ============================================================================

std::vector<std::string> mask_relocatable_bytes(const std::vector<uint8_t>& raw) {
    int n = static_cast<int>(raw.size());
    std::vector<std::string> result(n);

    // Pre-fill with hex representations
    for (int i = 0; i < n; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", raw[i]);
        result[i] = buf;
    }

    int i = 0;
    while (i < n) {
        uint8_t b = raw[i];

        // --- Relative CALL (E8) or JMP (E9) ---
        if ((b == 0xE8 || b == 0xE9) && i + 4 < n) {
            for (int j = 1; j <= 4; j++) result[i + j] = "?";
            i += 5;
            continue;
        }

        // --- Conditional Jcc near: 0F 80..0F 8F ---
        if (b == 0x0F && i + 1 < n && raw[i + 1] >= 0x80 && raw[i + 1] <= 0x8F) {
            if (i + 5 < n) {
                for (int j = 2; j <= 5; j++) result[i + j] = "?";
                i += 6;
                continue;
            }
        }

        // --- FF 15 (indirect CALL [RIP+disp32]) / FF 25 (indirect JMP [RIP+disp32]) ---
        if (b == 0xFF && i + 1 < n && (raw[i + 1] == 0x15 || raw[i + 1] == 0x25)) {
            if (i + 5 < n) {
                for (int j = 2; j <= 5; j++) result[i + j] = "?";
                i += 6;
                continue;
            }
        }

        // --- REX prefix detection ---
        int pos = i;
        if (b >= 0x40 && b <= 0x4F) {
            pos += 1;
            if (pos >= n) {
                i += 1;
                continue;
            }
        }

        uint8_t opcode = (pos < n) ? raw[pos] : 0;

        // Check for two-byte opcode (0F xx)
        int modrm_pos;
        if (opcode == 0x0F && pos + 1 < n) {
            modrm_pos = pos + 2;
        } else {
            modrm_pos = pos + 1;
        }

        // --- RIP-relative addressing detection ---
        // ModRM byte: mod=00 (bits 7-6), r/m=101 (bits 2-0)
        // This encodes [RIP + disp32] in x64
        if (modrm_pos < n) {
            uint8_t modrm = raw[modrm_pos];
            int mod = (modrm >> 6) & 3;
            int rm = modrm & 7;

            if (mod == 0 && rm == 5) {
                int disp_start = modrm_pos + 1;
                if (disp_start + 3 < n) {
                    for (int j = 0; j < 4; j++) {
                        result[disp_start + j] = "?";
                    }
                    i = disp_start + 4;
                    continue;
                }
            }
        }

        i += 1;
    }

    return result;
}

// ============================================================================
// Pattern helpers
// ============================================================================

std::string pattern_to_string(const std::vector<std::string>& tokens) {
    std::string out;
    for (size_t i = 0; i < tokens.size(); i++) {
        if (i > 0) out += ' ';
        out += tokens[i];
    }
    return out;
}

std::string pattern_to_string(const std::vector<std::string>& tokens, size_t count) {
    std::string out;
    size_t limit = (std::min)(count, tokens.size());
    for (size_t i = 0; i < limit; i++) {
        if (i > 0) out += ' ';
        out += tokens[i];
    }
    return out;
}

void trim_trailing_wildcards(std::vector<std::string>& tokens) {
    while (!tokens.empty() && tokens.back() == "?") {
        tokens.pop_back();
    }
}

// ============================================================================
// Uniqueness computation
// ============================================================================

int find_divergence(const std::vector<std::string>& a, const std::vector<std::string>& b) {
    int limit = static_cast<int>((std::min)(a.size(), b.size()));
    for (int i = 0; i < limit; i++) {
        if (a[i] != b[i]) return i;
    }
    return limit;
}

void compute_unique_prefixes(std::vector<SigEntry*>& entries, int min_length) {
    if (entries.empty()) return;

    // Build indexed list: (tokens_ptr, original_index)
    struct IndexedEntry {
        const std::vector<std::string>* tokens;
        size_t orig_idx;
    };

    std::vector<IndexedEntry> indexed;
    indexed.reserve(entries.size());
    for (size_t i = 0; i < entries.size(); i++) {
        indexed.push_back({ &entries[i]->_tokens, i });
    }

    // Sort by token list (lexicographic)
    std::sort(indexed.begin(), indexed.end(),
        [](const IndexedEntry& a, const IndexedEntry& b) {
            return *a.tokens < *b.tokens;
        });

    std::vector<int> unique_lengths(entries.size(), 0);

    for (size_t si = 0; si < indexed.size(); si++) {
        const auto* tokens = indexed[si].tokens;
        size_t orig_idx = indexed[si].orig_idx;
        int needed = min_length;

        if (si > 0) {
            const auto* prev_tokens = indexed[si - 1].tokens;
            int div = find_divergence(*tokens, *prev_tokens);
            needed = (std::max)(needed, div + 1);
        }

        if (si < indexed.size() - 1) {
            const auto* next_tokens = indexed[si + 1].tokens;
            int div = find_divergence(*tokens, *next_tokens);
            needed = (std::max)(needed, div + 1);
        }

        unique_lengths[orig_idx] = needed;
    }

    for (size_t i = 0; i < entries.size(); i++) {
        auto* e = entries[i];
        int ul = unique_lengths[i];
        int token_count = static_cast<int>(e->_tokens.size());

        if (ul <= token_count) {
            e->unique = true;
            e->unique_length = ul;
            e->pattern = pattern_to_string(e->_tokens, static_cast<size_t>(ul));
        } else {
            e->unique = false;
            e->unique_length = token_count;
            e->pattern = pattern_to_string(e->_tokens);
        }
    }
}

void compute_class_uniqueness(std::vector<SigEntry*>& class_entries, int min_length) {
    // Filter to non-stub entries that have tokens
    std::vector<SigEntry*> candidates;
    for (auto* e : class_entries) {
        if (!e->stub && !e->_tokens.empty()) {
            candidates.push_back(e);
        }
    }

    if (candidates.size() <= 1) {
        for (auto* e : candidates) {
            e->class_unique = true;
        }
        return;
    }

    struct IndexedEntry {
        const std::vector<std::string>* tokens;
        size_t orig_idx;
    };

    std::vector<IndexedEntry> indexed;
    indexed.reserve(candidates.size());
    for (size_t i = 0; i < candidates.size(); i++) {
        indexed.push_back({ &candidates[i]->_tokens, i });
    }

    std::sort(indexed.begin(), indexed.end(),
        [](const IndexedEntry& a, const IndexedEntry& b) {
            return *a.tokens < *b.tokens;
        });

    std::vector<bool> class_unique_flags(candidates.size(), true);

    for (size_t si = 0; si < indexed.size(); si++) {
        const auto* tokens = indexed[si].tokens;
        size_t orig_idx = indexed[si].orig_idx;

        if (si > 0) {
            const auto* prev_tokens = indexed[si - 1].tokens;
            if (*tokens == *prev_tokens) {
                class_unique_flags[orig_idx] = false;
                class_unique_flags[indexed[si - 1].orig_idx] = false;
            }
        }

        if (si < indexed.size() - 1) {
            const auto* next_tokens = indexed[si + 1].tokens;
            if (*tokens == *next_tokens) {
                class_unique_flags[orig_idx] = false;
                class_unique_flags[indexed[si + 1].orig_idx] = false;
            }
        }
    }

    for (size_t i = 0; i < candidates.size(); i++) {
        candidates[i]->class_unique = class_unique_flags[i];
    }
}

// (min_length unused for compute_class_uniqueness in practice, kept for interface parity)

// ============================================================================
// Module processing
// ============================================================================

// Returns map of class_name -> vector of SigEntry
using ClassSigMap = std::map<std::string, std::vector<SigEntry>>;

ClassSigMap process_module(const json& module_data, int min_length) {
    ClassSigMap result;

    if (!module_data.contains("vtables") || !module_data["vtables"].is_array())
        return result;

    const auto& vtables = module_data["vtables"];
    if (vtables.empty()) return result;

    // First pass: generate all masked patterns, detect stubs, track RVAs
    std::vector<SigEntry> all_entries;
    std::unordered_map<std::string, std::vector<size_t>> rva_to_indices;

    for (const auto& vt : vtables) {
        std::string class_name = vt.value("class", "");

        if (!vt.contains("functions") || !vt["functions"].is_array())
            continue;

        for (const auto& func : vt["functions"]) {
            if (!func.contains("bytes") || !func["bytes"].is_string())
                continue;

            std::string hex_bytes = func["bytes"].get<std::string>();
            if (hex_bytes.empty()) continue;

            auto raw = parse_hex_bytes(hex_bytes);
            if (static_cast<int>(raw.size()) < min_length) continue;

            // Skip all-zero bytes (failed reads)
            {
                bool all_zero = true;
                for (uint8_t b : raw) {
                    if (b != 0) { all_zero = false; break; }
                }
                if (all_zero) continue;
            }

            std::string rva = func.value("rva", "0x0");
            int func_index = func.value("index", 0);

            SigEntry entry;
            entry.class_name = class_name;
            entry.index = func_index;
            entry.rva = rva;
            entry.byte_count = static_cast<int>(raw.size());

            // Stub detection (on raw bytes, before masking)
            std::string stub_type = detect_stub(raw);
            if (!stub_type.empty()) {
                entry.stub = true;
                entry.stub_type = stub_type;
                entry.unique = false;
                entry.class_unique = false;
                entry.unique_length = 0;

                // Pattern for stubs: first 8 raw bytes as hex
                std::vector<std::string> stub_tokens;
                size_t stub_len = (std::min)(raw.size(), (size_t)8);
                for (size_t i = 0; i < stub_len; i++) {
                    char buf[3];
                    snprintf(buf, sizeof(buf), "%02X", raw[i]);
                    stub_tokens.emplace_back(buf);
                }
                entry.pattern = pattern_to_string(stub_tokens);

                size_t idx = all_entries.size();
                all_entries.push_back(std::move(entry));
                rva_to_indices[rva].push_back(idx);
                continue;
            }

            auto masked = mask_relocatable_bytes(raw);
            trim_trailing_wildcards(masked);

            if (static_cast<int>(masked.size()) < min_length) continue;

            entry._tokens = std::move(masked);
            entry.stub = false;
            entry.class_unique = false;

            size_t idx = all_entries.size();
            all_entries.push_back(std::move(entry));
            rva_to_indices[rva].push_back(idx);
        }
    }

    if (all_entries.empty()) return result;

    // RVA deduplication: populate shared_with lists
    for (auto& [rva_key, indices] : rva_to_indices) {
        if (indices.size() <= 1) continue;
        for (size_t idx : indices) {
            std::vector<std::string> others;
            for (size_t other_idx : indices) {
                if (other_idx == idx) continue;
                auto& other = all_entries[other_idx];
                std::string label = other.class_name + "::idx_" + std::to_string(other.index);
                others.push_back(std::move(label));
                if (others.size() >= 5) break; // cap at 5
            }
            all_entries[idx].shared_with = std::move(others);
        }
    }

    // For module-level uniqueness, deduplicate by RVA:
    // pick one representative per RVA for the uniqueness computation
    std::unordered_set<std::string> seen_rvas;
    std::vector<SigEntry*> deduped_entries;
    std::unordered_map<std::string, SigEntry*> rva_to_representative;

    for (auto& e : all_entries) {
        if (e.stub) continue;
        if (seen_rvas.find(e.rva) == seen_rvas.end()) {
            seen_rvas.insert(e.rva);
            deduped_entries.push_back(&e);
            rva_to_representative[e.rva] = &e;
        }
    }

    // Compute module-level uniqueness on deduplicated set
    compute_unique_prefixes(deduped_entries, min_length);

    // Propagate uniqueness from representative to all entries sharing that RVA
    for (auto& e : all_entries) {
        if (e.stub) continue;
        auto it = rva_to_representative.find(e.rva);
        if (it != rva_to_representative.end() && it->second != &e) {
            e.unique = it->second->unique;
            e.unique_length = it->second->unique_length;
            e.pattern = it->second->pattern;
        }
    }

    // Group by class for per-class uniqueness
    std::unordered_map<std::string, std::vector<SigEntry*>> by_class;
    for (auto& e : all_entries) {
        by_class[e.class_name].push_back(&e);
    }

    // Compute per-class uniqueness
    for (auto& [cls, class_entries] : by_class) {
        compute_class_uniqueness(class_entries, min_length);
    }

    // Sort each class's entries by index
    for (auto& [cls, class_entries] : by_class) {
        std::sort(class_entries.begin(), class_entries.end(),
            [](const SigEntry* a, const SigEntry* b) {
                return a->index < b->index;
            });
    }

    // Clean up internal _tokens field
    for (auto& e : all_entries) {
        e._tokens.clear();
        e._tokens.shrink_to_fit();
    }

    // Build result map (ordered by class name)
    for (auto& [cls, ptrs] : by_class) {
        auto& vec = result[cls];
        vec.reserve(ptrs.size());
        for (auto* p : ptrs) {
            vec.push_back(std::move(*p));
        }
    }

    return result;
}

// ============================================================================
// Output: text file per module
// ============================================================================

struct ModuleStats {
    int total = 0;
    int unique = 0;
    int class_unique = 0;
    int stubs = 0;
    int dup = 0;
};

ModuleStats write_text_output(const std::string& module_name, const ClassSigMap& signatures,
                              const std::string& output_dir) {
    ModuleStats stats = {};

    // Build output path: strip .dll extension for filename
    std::string clean_name = module_name;
    {
        size_t pos = clean_name.rfind(".dll");
        if (pos != std::string::npos && pos == clean_name.size() - 4) {
            clean_name = clean_name.substr(0, pos);
        }
    }

    std::string path = output_dir + "\\" + clean_name + ".txt";

    FILE* f = fopen(path.c_str(), "w");
    if (!f) return stats;

    fprintf(f, "# %s — Virtual function signatures\n", module_name.c_str());
    fprintf(f, "# Generated by dezlock-dump\n");
    fprintf(f, "# Format: ClassName::idx_N  <pattern>  [markers]\n");
    fprintf(f, "#   ? = masked byte (relocation)\n");
    fprintf(f, "#   [DUP] = not uniquely signable at module or class level\n");
    fprintf(f, "#   [CLASS_UNIQUE] = unique within class vtable (hookable)\n");
    fprintf(f, "#   [STUB:type] = trivial stub function\n");
    fprintf(f, "#   # shared: ... = COMDAT-folded, same RVA as listed functions\n");
    fprintf(f, "#   Signatures are trimmed to shortest unique prefix\n\n");

    for (const auto& [class_name, entries] : signatures) {
        int n_unique = 0;
        int n_class_unique = 0;
        int n_stubs = 0;

        for (const auto& e : entries) {
            if (e.unique) n_unique++;
            if (e.class_unique && !e.unique && !e.stub) n_class_unique++;
            if (e.stub) n_stubs++;
        }

        // Build header parts
        fprintf(f, "# --- %s (%d functions, %d unique", class_name.c_str(),
                static_cast<int>(entries.size()), n_unique);
        if (n_class_unique > 0) fprintf(f, ", %d class-unique", n_class_unique);
        if (n_stubs > 0) fprintf(f, ", %d stubs", n_stubs);
        fprintf(f, ") ---\n");

        for (const auto& e : entries) {
            stats.total++;

            if (e.stub) {
                stats.stubs++;
                fprintf(f, "%s::idx_%d  %s  [STUB:%s]\n",
                        class_name.c_str(), e.index,
                        e.pattern.c_str(), e.stub_type.c_str());
                continue;
            }

            std::string marker;
            std::string shared_comment;

            if (e.unique) {
                stats.unique++;
            } else if (e.class_unique) {
                marker = "  [CLASS_UNIQUE]";
                stats.class_unique++;
            } else {
                marker = "  [DUP]";
                stats.dup++;
            }

            if (!e.shared_with.empty()) {
                shared_comment = "  # shared: ";
                for (size_t i = 0; i < e.shared_with.size(); i++) {
                    if (i > 0) shared_comment += ", ";
                    shared_comment += e.shared_with[i];
                }
            }

            fprintf(f, "%s::idx_%d  %s%s%s\n",
                    class_name.c_str(), e.index,
                    e.pattern.c_str(), marker.c_str(), shared_comment.c_str());
        }

        fprintf(f, "\n");
    }

    fclose(f);
    return stats;
}

// ============================================================================
// Output: consolidated JSON
// ============================================================================

void write_json_output(const std::map<std::string, ClassSigMap>& all_module_sigs,
                       const std::string& output_dir) {
    std::string path = output_dir + "\\_all-signatures.json";

    json output;
    json& modules = output["modules"];
    modules = json::object();

    for (const auto& [mod_name, signatures] : all_module_sigs) {
        json mod_out = json::object();
        for (const auto& [class_name, entries] : signatures) {
            json arr = json::array();
            for (const auto& e : entries) {
                json entry;
                entry["index"] = e.index;
                entry["rva"] = e.rva;
                entry["pattern"] = e.pattern;
                entry["unique"] = e.unique;
                entry["length"] = e.unique_length;
                entry["stub"] = e.stub;
                if (!e.stub_type.empty()) {
                    entry["stub_type"] = e.stub_type;
                } else {
                    entry["stub_type"] = nullptr;
                }
                entry["class_unique"] = e.class_unique;
                entry["shared_with"] = e.shared_with;
                arr.push_back(std::move(entry));
            }
            mod_out[class_name] = std::move(arr);
        }
        modules[mod_name] = std::move(mod_out);
    }

    FILE* f = fopen(path.c_str(), "w");
    if (!f) return;

    std::string dumped = output.dump(2);
    fwrite(dumped.c_str(), 1, dumped.size(), f);
    fclose(f);
}

// ============================================================================
// Per-module task (called from threads)
// ============================================================================

struct ModuleResult {
    std::string mod_name;
    ClassSigMap signatures;
    ModuleStats stats;
    bool valid = false;
};

ModuleResult process_module_task(const json& module, int min_length,
                                 const std::string& output_dir) {
    ModuleResult res;
    res.mod_name = module.value("name", "unknown");

    if (!module.contains("vtables") || !module["vtables"].is_array() || module["vtables"].empty()) {
        return res;
    }

    // Check if any function has bytes data
    bool has_bytes = false;
    for (const auto& vt : module["vtables"]) {
        if (!vt.contains("functions") || !vt["functions"].is_array()) continue;
        for (const auto& func : vt["functions"]) {
            if (func.contains("bytes") && func["bytes"].is_string() &&
                !func["bytes"].get<std::string>().empty()) {
                has_bytes = true;
                break;
            }
        }
        if (has_bytes) break;
    }

    if (!has_bytes) {
        printf("  %s: no bytes data (run updated dezlock-dump first)\n", res.mod_name.c_str());
        return res;
    }

    printf("  Processing %s...\n", res.mod_name.c_str());

    res.signatures = process_module(module, min_length);
    if (res.signatures.empty()) {
        printf("    %s: no signatures generated\n", res.mod_name.c_str());
        return res;
    }

    res.stats = write_text_output(res.mod_name, res.signatures, output_dir);

    // Print summary
    printf("    %s: %d signatures (%d unique",
           res.mod_name.c_str(), res.stats.total, res.stats.unique);
    if (res.stats.class_unique > 0) printf(", %d class-unique", res.stats.class_unique);
    if (res.stats.stubs > 0) printf(", %d stubs", res.stats.stubs);
    printf(", %d dup)\n", res.stats.dup);

    res.valid = true;
    return res;
}

// ============================================================================
// Directory creation helper
// ============================================================================

static void ensure_directory(const std::string& path) {
    // Walk the path and create each component
    for (size_t i = 0; i < path.size(); i++) {
        if (path[i] == '\\' || path[i] == '/') {
            std::string sub = path.substr(0, i);
            if (!sub.empty()) {
                CreateDirectoryA(sub.c_str(), nullptr);
            }
        }
    }
    CreateDirectoryA(path.c_str(), nullptr);
}

} // anonymous namespace

// ============================================================================
// Public entry point
// ============================================================================

SignatureStats generate_signatures(const json& data, const std::string& output_dir, int min_length) {
    SignatureStats stats;

    if (!data.contains("modules") || !data["modules"].is_array()) {
        printf("ERROR: No modules found in JSON data\n");
        return stats;
    }

    const auto& modules = data["modules"];
    if (modules.empty()) {
        printf("ERROR: No modules found in JSON data\n");
        return stats;
    }

    // Create output directory
    ensure_directory(output_dir);

    // Collect modules that have vtable data
    std::vector<size_t> work_indices;
    for (size_t i = 0; i < modules.size(); i++) {
        const auto& mod = modules[i];
        if (mod.contains("vtables") && mod["vtables"].is_array() && !mod["vtables"].empty()) {
            work_indices.push_back(i);
        }
    }

    if (work_indices.empty()) {
        printf("No modules with vtable data found.\n");
        return stats;
    }

    unsigned int hw_threads = std::thread::hardware_concurrency();
    if (hw_threads == 0) hw_threads = 4;
    unsigned int num_workers = (std::min)(hw_threads, static_cast<unsigned int>(work_indices.size()));

    printf("Processing %d modules with %u threads...\n",
           static_cast<int>(work_indices.size()), num_workers);

    // Collect results (thread-safe)
    std::mutex results_mutex;
    std::map<std::string, ClassSigMap> all_module_sigs;
    int grand_total = 0, grand_unique = 0, grand_class_unique = 0;
    int grand_stubs = 0, grand_dup = 0;

    // Thread pool: divide work among threads
    std::vector<std::thread> threads;
    std::atomic<size_t> next_work_idx{0};

    auto worker_fn = [&]() {
        while (true) {
            size_t wi = next_work_idx.fetch_add(1);
            if (wi >= work_indices.size()) break;

            size_t mod_idx = work_indices[wi];
            ModuleResult res = process_module_task(modules[mod_idx], min_length, output_dir);

            if (res.valid) {
                std::lock_guard<std::mutex> lock(results_mutex);
                all_module_sigs[res.mod_name] = std::move(res.signatures);
                grand_total += res.stats.total;
                grand_unique += res.stats.unique;
                grand_class_unique += res.stats.class_unique;
                grand_stubs += res.stats.stubs;
                grand_dup += res.stats.dup;
            }
        }
    };

    for (unsigned int t = 0; t < num_workers; t++) {
        threads.emplace_back(worker_fn);
    }
    for (auto& t : threads) {
        t.join();
    }

    if (!all_module_sigs.empty()) {
        write_json_output(all_module_sigs, output_dir);

        double pct_unique = grand_total > 0 ? (grand_unique * 100.0 / grand_total) : 0.0;
        double pct_class = grand_total > 0 ? (grand_class_unique * 100.0 / grand_total) : 0.0;
        double pct_hookable = grand_total > 0
            ? ((grand_unique + grand_class_unique) * 100.0 / grand_total) : 0.0;

        printf("\nTotal: %d signatures\n", grand_total);
        printf("  Module-unique: %d (%.1f%%)\n", grand_unique, pct_unique);
        printf("  Class-unique:  %d (%.1f%%)\n", grand_class_unique, pct_class);
        printf("  Hookable:      %d (%.1f%%)\n", grand_unique + grand_class_unique, pct_hookable);
        printf("  Stubs:         %d\n", grand_stubs);
        printf("  Duplicates:    %d\n", grand_dup);
        printf("Output: %s\\\n", output_dir.c_str());
    } else {
        printf("\nNo signatures generated. Make sure the JSON contains 'bytes' fields.\n");
        printf("Re-run dezlock-dump.exe with the updated build to capture function bytes.\n");
    }

    stats.total = grand_total;
    stats.unique = grand_unique;
    stats.class_unique = grand_class_unique;
    stats.stubs = grand_stubs;
    stats.duplicates = grand_dup;

    return stats;
}
