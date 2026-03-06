/**
 * dezlock-dump -- Virtual Function Naming Engine
 *
 * Three-pass naming system that correlates vtable function RVAs with:
 *   1. Debug string cross-references ("ClassName::MethodName")
 *   2. Protobuf descriptor method names
 *   3. Member access patterns (single-field getter/setter inference)
 *
 * Stub detection is duplicated from generate-signatures.cpp (~40 lines)
 * to avoid touching that working code. See TODO.md Step 3 for the
 * optional shared-header refactor.
 */

#include "src/vfunc-namer.hpp"
#include "src/import-schema.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using json = nlohmann::json;

// ============================================================================
// Internal helpers
// ============================================================================

namespace {

// --- Hex parsing (duplicated from generate-signatures.cpp) ---

static int hex_char_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return -1;
}

static std::vector<uint8_t> parse_hex_bytes(const std::string& hex_str) {
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

// Parse a hex RVA string like "0x1A2B3C" or "1A2B3C"
static uint32_t parse_rva(const std::string& s) {
    if (s.empty()) return 0;
    return static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 16));
}

// --- Stub detection (duplicated from generate-signatures.cpp) ---

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

// Returns stub type string, or empty string if not a stub.
// Duplicated from generate-signatures.cpp to avoid coupling.
static std::string detect_stub(const std::vector<uint8_t>& raw) {
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

// --- Simplified IDA-style signature generation ---
// Masks relocatable bytes (CALL/JMP rel32, Jcc rel32, RIP-relative) with '?'

static std::string build_signature(const std::vector<uint8_t>& raw) {
    if (raw.empty()) return "";

    int n = static_cast<int>(raw.size());
    std::vector<std::string> tokens(n);

    // Pre-fill with hex representations
    for (int i = 0; i < n; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", raw[i]);
        tokens[i] = buf;
    }

    // Mask relocatable operands
    int i = 0;
    while (i < n) {
        uint8_t b = raw[i];

        // Relative CALL (E8) or JMP (E9)
        if ((b == 0xE8 || b == 0xE9) && i + 4 < n) {
            for (int j = 1; j <= 4; j++) tokens[i + j] = "?";
            i += 5;
            continue;
        }

        // Conditional Jcc near: 0F 80..0F 8F
        if (b == 0x0F && i + 1 < n && raw[i + 1] >= 0x80 && raw[i + 1] <= 0x8F) {
            if (i + 5 < n) {
                for (int j = 2; j <= 5; j++) tokens[i + j] = "?";
                i += 6;
                continue;
            }
        }

        // FF 15 / FF 25 (indirect CALL/JMP [RIP+disp32])
        if (b == 0xFF && i + 1 < n && (raw[i + 1] == 0x15 || raw[i + 1] == 0x25)) {
            if (i + 5 < n) {
                for (int j = 2; j <= 5; j++) tokens[i + j] = "?";
                i += 6;
                continue;
            }
        }

        // RIP-relative MOD=00 R/M=101 patterns (xx 05/0D/15/1D/25/2D/35/3D)
        if (i + 1 < n) {
            uint8_t modrm = raw[i + 1];
            if ((modrm & 0xC7) == 0x05 && i + 5 < n) {
                // Check if the opcode uses ModR/M (common patterns with REX prefix)
                bool is_rip = false;
                // REX.W + opcode with ModR/M
                if (b >= 0x48 && b <= 0x4F) is_rip = true;
                // Two-byte opcode 0F xx with ModR/M
                if (b == 0x0F) is_rip = true;
                // Single-byte with ModR/M: 8B, 89, 8D, 63, 39, 3B, etc.
                if (b == 0x8B || b == 0x89 || b == 0x8D || b == 0x63 ||
                    b == 0x39 || b == 0x3B || b == 0x31 || b == 0x33) is_rip = true;

                if (is_rip) {
                    for (int j = 2; j <= 5; j++) {
                        if (i + j < n) tokens[i + j] = "?";
                    }
                }
            }
        }

        i++;
    }

    // Build space-separated signature string
    std::string sig;
    for (int k = 0; k < n; k++) {
        if (k > 0) sig += ' ';
        sig += tokens[k];
    }
    return sig;
}

// --- Class::Method extraction ---

// Split "ClassName::MethodName" on the last "::" delimiter.
// Returns {class_name, method_name}. Returns {"", ""} if no "::" found.
static std::pair<std::string, std::string> extract_class_method(const std::string& str) {
    size_t pos = str.rfind("::");
    if (pos == std::string::npos || pos == 0 || pos + 2 >= str.size()) {
        return {"", ""};
    }
    return { str.substr(0, pos), str.substr(pos + 2) };
}

// Normalize a class name for matching: strip "C_" prefix if present.
// e.g. "C_BaseEntity" -> "BaseEntity", "CBaseEntity" -> "BaseEntity"
static std::string normalize_class_name(const std::string& name) {
    if (name.size() > 2 && name[0] == 'C' && name[1] == '_') {
        return name.substr(2);
    }
    if (name.size() > 1 && name[0] == 'C' && std::isupper(static_cast<unsigned char>(name[1]))) {
        return name.substr(1);
    }
    return name;
}

// --- Getter/Setter name inference ---

// Known Hungarian notation prefixes (ordered longest-first to avoid partial matches)
static const char* const HUNGARIAN_PREFIXES[] = {
    "str", "vec", "ang", "clr", "uch", "ul", "us",
    "fl", "sz", "n", "i", "h", "b", "e", "p",
    nullptr
};

// Infer a getter/setter method name from a schema field name.
// Examples:
//   "m_iHealth"  + read  -> "GetHealth"
//   "m_bAlive"   + read  -> "IsAlive"
//   "m_flSpeed"  + write -> "SetSpeed"
static std::string infer_getter_name(const std::string& field_name, bool is_write) {
    std::string name = field_name;

    // Strip m_ prefix
    if (name.size() > 2 && name[0] == 'm' && name[1] == '_') {
        name = name.substr(2);
    }

    // Detect bool prefix before stripping
    bool is_bool = (name.size() > 1 && name[0] == 'b' &&
                    std::isupper(static_cast<unsigned char>(name[1])));

    // Strip Hungarian notation prefix
    for (int i = 0; HUNGARIAN_PREFIXES[i] != nullptr; i++) {
        const char* prefix = HUNGARIAN_PREFIXES[i];
        size_t plen = strlen(prefix);
        if (name.size() > plen &&
            name.compare(0, plen, prefix) == 0 &&
            std::isupper(static_cast<unsigned char>(name[plen]))) {
            name = name.substr(plen);
            break;
        }
    }

    // Ensure first letter is uppercase
    if (!name.empty()) {
        name[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(name[0])));
    }

    // Apply prefix based on access type and field type
    if (is_write) {
        return "Set" + name;
    }
    if (is_bool) {
        return "Is" + name;
    }
    return "Get" + name;
}

// --- Reverse RVA index entry (used during Phase 0 / Pass 1) ---

struct RvaEntry {
    std::string module_name;
    std::string class_name;
    int vtable_index = 0;
};

} // anonymous namespace

// ============================================================================
// build_vfunc_map -- main entry point
// ============================================================================

VFuncMap build_vfunc_map(
    const nlohmann::json& data,
    const std::unordered_map<std::string, const ClassInfo*>& class_lookup)
{
    VFuncMap vmap;

    if (!data.contains("modules") || !data["modules"].is_array()) {
        return vmap;
    }

    // Reverse index: "module_name:0xRVA" -> RvaEntry for O(1) xref lookup
    std::unordered_map<std::string, RvaEntry> rva_index;

    // ========================================================================
    // Phase 0 -- Populate base data from vtables JSON
    // ========================================================================

    for (const auto& mod : data["modules"]) {
        if (!mod.contains("name") || !mod["name"].is_string()) continue;
        std::string mod_name = mod["name"].get<std::string>();

        if (!mod.contains("vtables") || !mod["vtables"].is_array()) continue;

        auto& mod_map = vmap[mod_name];

        for (const auto& vt : mod["vtables"]) {
            if (!vt.contains("class") || !vt["class"].is_string()) continue;
            std::string cls_name = vt["class"].get<std::string>();

            ClassVFuncTable cvft;
            cvft.class_name = cls_name;
            cvft.module_name = mod_name;

            if (vt.contains("vtable_rva") && vt["vtable_rva"].is_string()) {
                cvft.vtable_rva = parse_rva(vt["vtable_rva"].get<std::string>());
            }

            if (!vt.contains("functions") || !vt["functions"].is_array()) {
                mod_map[cls_name] = std::move(cvft);
                continue;
            }

            for (const auto& fn : vt["functions"]) {
                VFuncInfo vfi;
                vfi.return_hint = "void*";

                if (fn.contains("index") && fn["index"].is_number_integer()) {
                    vfi.index = fn["index"].get<int>();
                }

                uint32_t func_rva = 0;
                if (fn.contains("rva") && fn["rva"].is_string()) {
                    func_rva = parse_rva(fn["rva"].get<std::string>());
                }

                // Parse prologue bytes and run stub detection
                std::vector<uint8_t> raw_bytes;
                if (fn.contains("bytes") && fn["bytes"].is_string()) {
                    raw_bytes = parse_hex_bytes(fn["bytes"].get<std::string>());
                }

                std::string stub_type = detect_stub(raw_bytes);
                if (!stub_type.empty()) {
                    vfi.is_stub = true;
                    vfi.stub_type = stub_type;
                }

                // Build simplified IDA-style signature
                if (!raw_bytes.empty() && !vfi.is_stub) {
                    vfi.signature = build_signature(raw_bytes);
                }

                // Build reverse RVA index for xref matching (before move)
                if (func_rva != 0) {
                    char rva_key[128];
                    snprintf(rva_key, sizeof(rva_key), "%s:0x%X", mod_name.c_str(), func_rva);
                    RvaEntry entry;
                    entry.module_name = mod_name;
                    entry.class_name = cls_name;
                    entry.vtable_index = vfi.index;
                    rva_index[rva_key] = std::move(entry);
                }

                cvft.functions.push_back(std::move(vfi));
            }

            mod_map[cls_name] = std::move(cvft);
        }
    }

    // ========================================================================
    // Phase 1 -- Resolve inheritance (set parent_vfunc_count)
    // ========================================================================

    for (auto& [mod_name, class_map] : vmap) {
        for (auto& [cls_name, cvft] : class_map) {
            // Find parent class via class_lookup
            auto cls_it = class_lookup.find(cls_name);
            if (cls_it == class_lookup.end() || !cls_it->second) continue;

            const ClassInfo* cls_info = cls_it->second;
            if (cls_info->parent.empty()) continue;

            // Search for parent's vtable -- first in same module, then across all
            const ClassVFuncTable* parent_vft = nullptr;

            auto mod_it = class_map.find(cls_info->parent);
            if (mod_it != class_map.end()) {
                parent_vft = &mod_it->second;
            } else {
                // Search across all modules
                for (const auto& [other_mod, other_map] : vmap) {
                    auto pit = other_map.find(cls_info->parent);
                    if (pit != other_map.end()) {
                        parent_vft = &pit->second;
                        break;
                    }
                }
            }

            if (parent_vft) {
                cvft.parent_vfunc_count = static_cast<int>(parent_vft->functions.size());
            }
        }
    }

    // ========================================================================
    // Pass 1 -- Debug String Xrefs (highest confidence)
    // ========================================================================

    if (data.contains("string_refs") && data["string_refs"].is_object()) {
        // Build a normalized name -> actual class name lookup for flexible matching
        std::unordered_map<std::string, std::vector<std::string>> norm_to_classes;
        for (const auto& [cls_name, _] : class_lookup) {
            norm_to_classes[normalize_class_name(cls_name)].push_back(cls_name);
        }

        for (auto it = data["string_refs"].begin(); it != data["string_refs"].end(); ++it) {
            const std::string& mod_name = it.key();
            const auto& mod_data = it.value();

            if (!mod_data.contains("strings") || !mod_data["strings"].is_array()) continue;

            for (const auto& str_entry : mod_data["strings"]) {
                if (!str_entry.contains("value") || !str_entry["value"].is_string()) continue;
                if (!str_entry.contains("category") || !str_entry["category"].is_string()) continue;

                std::string category = str_entry["category"].get<std::string>();
                if (category != "debug" && category != "lifecycle") continue;

                std::string value = str_entry["value"].get<std::string>();

                // Must contain "::" to be a ClassName::MethodName pattern
                auto [class_part, method_part] = extract_class_method(value);
                if (class_part.empty() || method_part.empty()) continue;

                // Skip if method name contains spaces or non-identifier chars
                bool valid_method = true;
                for (char c : method_part) {
                    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
                        valid_method = false;
                        break;
                    }
                }
                if (!valid_method) continue;

                // Check xrefs for vtable function matches
                if (!str_entry.contains("xrefs") || !str_entry["xrefs"].is_array()) continue;

                for (const auto& xref : str_entry["xrefs"]) {
                    if (!xref.contains("func_rva") || !xref["func_rva"].is_string()) continue;

                    std::string func_rva_str = xref["func_rva"].get<std::string>();
                    uint32_t func_rva = parse_rva(func_rva_str);
                    if (func_rva == 0) continue;

                    // Build key for reverse index lookup
                    char rva_key[128];
                    snprintf(rva_key, sizeof(rva_key), "%s:0x%X", mod_name.c_str(), func_rva);

                    auto rva_it = rva_index.find(rva_key);
                    if (rva_it == rva_index.end()) continue;

                    const RvaEntry& entry = rva_it->second;

                    // Verify class name matches (with normalization)
                    std::string norm_entry = normalize_class_name(entry.class_name);
                    std::string norm_str = normalize_class_name(class_part);
                    if (norm_entry != norm_str) continue;

                    // Find the function in our vmap and set the name
                    auto vmod_it = vmap.find(entry.module_name);
                    if (vmod_it == vmap.end()) continue;
                    auto vcls_it = vmod_it->second.find(entry.class_name);
                    if (vcls_it == vmod_it->second.end()) continue;

                    for (auto& func : vcls_it->second.functions) {
                        if (func.index == entry.vtable_index && func.name.empty()) {
                            func.name = method_part;
                            func.source = "debug_string";
                            break;
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // Pass 2 -- Protobuf Method Names (medium confidence, low yield)
    // ========================================================================
    // Protobuf messages rarely map directly to vtable functions, but service
    // method names can occasionally match. Keep this pass simple.

    if (data.contains("protobuf_messages") && data["protobuf_messages"].is_object()) {
        // For each module's protobuf files, check if any message names match
        // RTTI classes and if any nested message names could be method hints.
        // This is intentionally minimal -- expand if real data shows matches.
        for (auto it = data["protobuf_messages"].begin();
             it != data["protobuf_messages"].end(); ++it) {
            const std::string& mod_name = it.key();
            const auto& mod_proto = it.value();

            if (!mod_proto.contains("files") || !mod_proto["files"].is_array()) continue;

            auto vmod_it = vmap.find(mod_name);
            if (vmod_it == vmap.end()) continue;

            for (const auto& proto_file : mod_proto["files"]) {
                if (!proto_file.contains("messages") || !proto_file["messages"].is_array()) continue;

                for (const auto& msg : proto_file["messages"]) {
                    if (!msg.contains("name") || !msg["name"].is_string()) continue;
                    std::string msg_name = msg["name"].get<std::string>();

                    // Check if this message name matches any vtable class
                    // (protobuf message names sometimes match game class names)
                    auto vcls_it = vmod_it->second.find(msg_name);
                    if (vcls_it == vmod_it->second.end()) continue;

                    // If the message has nested messages that look like method descriptors,
                    // try to match them. This is speculative and low-yield.
                    if (!msg.contains("fields") || !msg["fields"].is_array()) continue;

                    // Look for fields whose names suggest method names
                    // (e.g., a field named "get_health_request" might hint at a GetHealth method)
                    // For now, just log that we found a match but don't name anything
                    // unless we have strong evidence. Expand in future phases.
                }
            }
        }
    }

    // ========================================================================
    // Pass 3 -- Member Access Inference (heuristic)
    // ========================================================================

    if (data.contains("member_layouts") && data["member_layouts"].is_object()) {
        for (auto it = data["member_layouts"].begin();
             it != data["member_layouts"].end(); ++it) {
            const std::string& mod_name = it.key();
            const auto& mod_layouts = it.value();

            if (!mod_layouts.is_object()) continue;

            auto vmod_it = vmap.find(mod_name);
            if (vmod_it == vmap.end()) continue;

            for (auto cls_it = mod_layouts.begin(); cls_it != mod_layouts.end(); ++cls_it) {
                const std::string& cls_name = cls_it.key();
                const auto& cls_layout = cls_it.value();

                auto vcls_it = vmod_it->second.find(cls_name);
                if (vcls_it == vmod_it->second.end()) continue;

                ClassVFuncTable& cvft = vcls_it->second;

                if (!cls_layout.contains("fields") || !cls_layout["fields"].is_array()) continue;

                // Build offset-to-field-name map from schema ClassInfo
                std::unordered_map<int, const Field*> offset_to_field;
                auto schema_it = class_lookup.find(cls_name);
                if (schema_it != class_lookup.end() && schema_it->second) {
                    for (const auto& f : schema_it->second->fields) {
                        offset_to_field[f.offset] = &f;
                    }
                }

                for (const auto& field_entry : cls_layout["fields"]) {
                    if (!field_entry.contains("offset") || !field_entry["offset"].is_number_integer()) continue;
                    if (!field_entry.contains("funcs") || !field_entry["funcs"].is_array()) continue;

                    int field_offset = field_entry["offset"].get<int>();

                    // Parse access: can be a string ("read") or array (["read", "compare"])
                    bool has_read = false, has_write = false;
                    if (field_entry.contains("access")) {
                        const auto& acc = field_entry["access"];
                        if (acc.is_string()) {
                            std::string a = acc.get<std::string>();
                            has_read = (a == "read");
                            has_write = (a == "write");
                        } else if (acc.is_array()) {
                            for (const auto& a : acc) {
                                if (a.is_string()) {
                                    std::string s = a.get<std::string>();
                                    if (s == "read") has_read = true;
                                    if (s == "write") has_write = true;
                                }
                            }
                        }
                    }

                    const auto& funcs_arr = field_entry["funcs"];

                    // Look up the schema field name by offset
                    const Field* schema_field = nullptr;
                    auto off_it = offset_to_field.find(field_offset);
                    if (off_it != offset_to_field.end()) {
                        schema_field = off_it->second;
                    }

                    // Populate accessed_fields for ALL functions that touch this field
                    std::string field_label;
                    if (schema_field) {
                        field_label = schema_field->name;
                    } else {
                        char buf[32];
                        snprintf(buf, sizeof(buf), "0x%X", field_offset);
                        field_label = buf;
                    }

                    for (const auto& func_idx_val : funcs_arr) {
                        if (!func_idx_val.is_number_integer()) continue;
                        int func_idx = func_idx_val.get<int>();

                        // Find the matching VFuncInfo
                        for (auto& func : cvft.functions) {
                            if (func.index == func_idx) {
                                // Add to accessed_fields (avoid duplicates)
                                bool already = false;
                                for (const auto& af : func.accessed_fields) {
                                    if (af == field_label) { already = true; break; }
                                }
                                if (!already) {
                                    func.accessed_fields.push_back(field_label);
                                }
                                break;
                            }
                        }
                    }

                    // Naming: only if exactly ONE function accesses this field
                    // and that function has no name yet, and access is read-only or write-only
                    if (funcs_arr.size() != 1) continue;
                    if (!schema_field) continue;
                    if (has_read && has_write) continue;   // ambiguous read+write
                    if (!has_read && !has_write) continue;  // unknown access type

                    int target_idx = funcs_arr[0].get<int>();
                    for (auto& func : cvft.functions) {
                        if (func.index != target_idx) continue;
                        if (!func.name.empty()) break;  // already named by Pass 1/2
                        if (func.is_stub) break;        // don't name stubs

                        bool is_write = has_write && !has_read;
                        func.name = infer_getter_name(schema_field->name, is_write);
                        func.source = "member_infer";

                        // Set return_hint based on field type
                        if (!is_write && schema_field) {
                            const std::string& ftype = schema_field->type;
                            if (ftype == "bool" || ftype == "_Bool") {
                                func.return_hint = "bool";
                            } else if (ftype == "int32" || ftype == "int32_t") {
                                func.return_hint = "int32_t";
                            } else if (ftype == "uint32" || ftype == "uint32_t") {
                                func.return_hint = "uint32_t";
                            } else if (ftype == "float32" || ftype == "float") {
                                func.return_hint = "float";
                            } else if (ftype == "int64" || ftype == "int64_t") {
                                func.return_hint = "int64_t";
                            } else if (ftype == "uint64" || ftype == "uint64_t") {
                                func.return_hint = "uint64_t";
                            } else if (ftype == "int16" || ftype == "int16_t") {
                                func.return_hint = "int16_t";
                            } else if (ftype == "uint16" || ftype == "uint16_t") {
                                func.return_hint = "uint16_t";
                            } else if (ftype == "int8" || ftype == "int8_t") {
                                func.return_hint = "int8_t";
                            } else if (ftype == "uint8" || ftype == "uint8_t") {
                                func.return_hint = "uint8_t";
                            }
                            // Otherwise keep default "void*"
                        }
                        break;
                    }
                }
            }
        }
    }

    return vmap;
}
