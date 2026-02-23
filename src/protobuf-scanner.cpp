#define LOG_TAG "protobuf-scanner"

#include "protobuf-scanner.hpp"
#include "log.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <algorithm>
#include <unordered_set>

namespace protobuf_scan {

// ============================================================================
// Field type names (FieldDescriptorProto.Type enum values)
// ============================================================================

const char* field_type_name(int32_t type) {
    switch (type) {
        case 1:  return "double";
        case 2:  return "float";
        case 3:  return "int64";
        case 4:  return "uint64";
        case 5:  return "int32";
        case 6:  return "fixed64";
        case 7:  return "fixed32";
        case 8:  return "bool";
        case 9:  return "string";
        case 10: return "group";
        case 11: return "message";
        case 12: return "bytes";
        case 13: return "uint32";
        case 14: return "enum";
        case 15: return "sfixed32";
        case 16: return "sfixed64";
        case 17: return "sint32";
        case 18: return "sint64";
        default: return "unknown";
    }
}

// ============================================================================
// Minimal protobuf wire format decoder
// ============================================================================

namespace wire {

struct Reader {
    const uint8_t* data;
    size_t         size;
    size_t         pos = 0;

    bool has_more() const { return pos < size; }
    size_t remaining() const { return size - pos; }

    // Read a varint, return false on error/truncation
    bool read_varint(uint64_t& out) {
        out = 0;
        int shift = 0;
        while (pos < size && shift < 64) {
            uint8_t b = data[pos++];
            out |= (uint64_t)(b & 0x7F) << shift;
            if (!(b & 0x80)) return true;
            shift += 7;
        }
        return false;
    }

    bool read_tag(uint32_t& field_num, uint32_t& wire_type) {
        uint64_t v;
        if (!read_varint(v)) return false;
        wire_type = (uint32_t)(v & 0x07);
        field_num = (uint32_t)(v >> 3);
        return field_num != 0;  // field 0 is invalid
    }

    // Read length-delimited bytes, returns sub-reader
    bool read_bytes(const uint8_t*& out_data, size_t& out_len) {
        uint64_t len;
        if (!read_varint(len)) return false;
        if (len > remaining()) return false;
        out_data = data + pos;
        out_len = (size_t)len;
        pos += (size_t)len;
        return true;
    }

    bool read_string(std::string& out) {
        const uint8_t* d;
        size_t len;
        if (!read_bytes(d, len)) return false;
        out.assign(reinterpret_cast<const char*>(d), len);
        return true;
    }

    Reader sub_reader(const uint8_t* d, size_t len) {
        return Reader{d, len, 0};
    }

    // Skip a field value based on wire type
    bool skip_field(uint32_t wire_type) {
        switch (wire_type) {
            case 0: { // varint
                uint64_t dummy;
                return read_varint(dummy);
            }
            case 1: { // 64-bit
                if (remaining() < 8) return false;
                pos += 8;
                return true;
            }
            case 2: { // length-delimited
                const uint8_t* d;
                size_t len;
                return read_bytes(d, len);
            }
            case 5: { // 32-bit
                if (remaining() < 4) return false;
                pos += 4;
                return true;
            }
            default:
                return false; // groups (3,4) or unknown
        }
    }
};

} // namespace wire

// ============================================================================
// Protobuf descriptor decoders
// ============================================================================

static ProtoEnumValue decode_enum_value(wire::Reader& r) {
    ProtoEnumValue ev;
    while (r.has_more()) {
        uint32_t fnum, wtype;
        if (!r.read_tag(fnum, wtype)) break;
        switch (fnum) {
            case 1: // name
                if (wtype == 2) r.read_string(ev.name);
                else r.skip_field(wtype);
                break;
            case 2: { // number
                if (wtype == 0) {
                    uint64_t v;
                    r.read_varint(v);
                    ev.number = (int32_t)v;
                } else r.skip_field(wtype);
                break;
            }
            default:
                r.skip_field(wtype);
                break;
        }
    }
    return ev;
}

static ProtoEnum decode_enum(wire::Reader& r) {
    ProtoEnum en;
    while (r.has_more()) {
        uint32_t fnum, wtype;
        if (!r.read_tag(fnum, wtype)) break;
        switch (fnum) {
            case 1: // name
                if (wtype == 2) r.read_string(en.name);
                else r.skip_field(wtype);
                break;
            case 2: { // value (repeated EnumValueDescriptorProto)
                if (wtype == 2) {
                    const uint8_t* d; size_t len;
                    r.read_bytes(d, len);
                    wire::Reader sub{d, len, 0};
                    en.values.push_back(decode_enum_value(sub));
                } else r.skip_field(wtype);
                break;
            }
            default:
                r.skip_field(wtype);
                break;
        }
    }
    return en;
}

static ProtoField decode_field(wire::Reader& r) {
    ProtoField f;
    while (r.has_more()) {
        uint32_t fnum, wtype;
        if (!r.read_tag(fnum, wtype)) break;
        switch (fnum) {
            case 1: // name
                if (wtype == 2) r.read_string(f.name);
                else r.skip_field(wtype);
                break;
            case 2: // extendee (skip)
                r.skip_field(wtype);
                break;
            case 3: { // number
                if (wtype == 0) {
                    uint64_t v; r.read_varint(v);
                    f.number = (int32_t)v;
                } else r.skip_field(wtype);
                break;
            }
            case 4: { // label
                if (wtype == 0) {
                    uint64_t v; r.read_varint(v);
                    f.label = (int32_t)v;
                } else r.skip_field(wtype);
                break;
            }
            case 5: { // type
                if (wtype == 0) {
                    uint64_t v; r.read_varint(v);
                    f.type = (int32_t)v;
                } else r.skip_field(wtype);
                break;
            }
            case 6: // type_name
                if (wtype == 2) r.read_string(f.type_name);
                else r.skip_field(wtype);
                break;
            case 7: // default_value
                if (wtype == 2) r.read_string(f.default_value);
                else r.skip_field(wtype);
                break;
            case 9: { // oneof_index
                if (wtype == 0) {
                    uint64_t v; r.read_varint(v);
                    f.oneof_index = (int32_t)v;
                } else r.skip_field(wtype);
                break;
            }
            case 10: // json_name
                if (wtype == 2) r.read_string(f.json_name);
                else r.skip_field(wtype);
                break;
            default:
                r.skip_field(wtype);
                break;
        }
    }
    return f;
}

// Forward declaration for recursive nested_type parsing
static ProtoMessage decode_message(wire::Reader& r);

static ProtoMessage decode_message(wire::Reader& r) {
    ProtoMessage msg;
    while (r.has_more()) {
        uint32_t fnum, wtype;
        if (!r.read_tag(fnum, wtype)) break;
        switch (fnum) {
            case 1: // name
                if (wtype == 2) r.read_string(msg.name);
                else r.skip_field(wtype);
                break;
            case 2: { // field (repeated FieldDescriptorProto)
                if (wtype == 2) {
                    const uint8_t* d; size_t len;
                    r.read_bytes(d, len);
                    wire::Reader sub{d, len, 0};
                    msg.fields.push_back(decode_field(sub));
                } else r.skip_field(wtype);
                break;
            }
            case 3: { // nested_type (repeated DescriptorProto)
                if (wtype == 2) {
                    const uint8_t* d; size_t len;
                    r.read_bytes(d, len);
                    wire::Reader sub{d, len, 0};
                    msg.nested_messages.push_back(decode_message(sub));
                } else r.skip_field(wtype);
                break;
            }
            case 4: { // enum_type (repeated EnumDescriptorProto)
                if (wtype == 2) {
                    const uint8_t* d; size_t len;
                    r.read_bytes(d, len);
                    wire::Reader sub{d, len, 0};
                    msg.nested_enums.push_back(decode_enum(sub));
                } else r.skip_field(wtype);
                break;
            }
            case 8: { // oneof_decl (repeated OneofDescriptorProto)
                if (wtype == 2) {
                    const uint8_t* d; size_t len;
                    r.read_bytes(d, len);
                    // OneofDescriptorProto: field 1 = name (string)
                    wire::Reader sub{d, len, 0};
                    std::string oneof_name;
                    while (sub.has_more()) {
                        uint32_t fn2, wt2;
                        if (!sub.read_tag(fn2, wt2)) break;
                        if (fn2 == 1 && wt2 == 2)
                            sub.read_string(oneof_name);
                        else
                            sub.skip_field(wt2);
                    }
                    msg.oneof_decls.push_back(oneof_name);
                } else r.skip_field(wtype);
                break;
            }
            default:
                r.skip_field(wtype);
                break;
        }
    }
    return msg;
}

static ProtoFile decode_file_descriptor(wire::Reader& r) {
    ProtoFile file;
    while (r.has_more()) {
        uint32_t fnum, wtype;
        if (!r.read_tag(fnum, wtype)) break;
        switch (fnum) {
            case 1: // name
                if (wtype == 2) r.read_string(file.name);
                else r.skip_field(wtype);
                break;
            case 2: // package
                if (wtype == 2) r.read_string(file.package);
                else r.skip_field(wtype);
                break;
            case 3: // dependency (repeated string)
                if (wtype == 2) {
                    std::string dep;
                    r.read_string(dep);
                    file.dependencies.push_back(std::move(dep));
                } else r.skip_field(wtype);
                break;
            case 4: { // message_type (repeated DescriptorProto)
                if (wtype == 2) {
                    const uint8_t* d; size_t len;
                    r.read_bytes(d, len);
                    wire::Reader sub{d, len, 0};
                    file.messages.push_back(decode_message(sub));
                } else r.skip_field(wtype);
                break;
            }
            case 5: { // enum_type (repeated EnumDescriptorProto)
                if (wtype == 2) {
                    const uint8_t* d; size_t len;
                    r.read_bytes(d, len);
                    wire::Reader sub{d, len, 0};
                    file.enums.push_back(decode_enum(sub));
                } else r.skip_field(wtype);
                break;
            }
            case 12: // syntax
                if (wtype == 2) r.read_string(file.syntax);
                else r.skip_field(wtype);
                break;
            default:
                r.skip_field(wtype);
                break;
        }
    }
    return file;
}

// ============================================================================
// Serialized FileDescriptorProto blob detection in .rdata
// ============================================================================

// A valid FileDescriptorProto starts with field 1 (name) = tag 0x0A,
// followed by a varint length, followed by a string ending in ".proto".
// This is a strong heuristic for finding embedded descriptors.

struct BlobCandidate {
    const uint8_t* data;
    size_t         size;
};

// Try to determine the total size of a serialized protobuf message
// by walking its wire format. Returns 0 if parsing fails.
static size_t measure_proto_blob(const uint8_t* data, size_t max_size) {
    wire::Reader r{data, max_size, 0};
    while (r.has_more()) {
        uint32_t fnum, wtype;
        size_t before = r.pos;
        if (!r.read_tag(fnum, wtype)) {
            // If we consumed some valid fields before failing, that's our size
            return before;
        }
        // Sanity: field numbers in FileDescriptorProto are 1-15
        // (with some extensions up to ~1000). Reject clearly invalid ones.
        if (fnum > 100000) return before;
        if (!r.skip_field(wtype)) return before;
    }
    return r.pos;
}

// Check if a string looks like a valid .proto filename
static bool looks_like_proto_filename(const std::string& s) {
    if (s.size() < 7) return false;  // "x.proto" minimum
    if (s.size() > 512) return false;
    // Must end with .proto
    if (s.substr(s.size() - 6) != ".proto") return false;
    // Must be printable ASCII
    for (char c : s) {
        if (c < 0x20 || c > 0x7E) return false;
    }
    return true;
}

// ============================================================================
// PE section utilities
// ============================================================================

struct SectionRange {
    uintptr_t start;
    size_t    size;
};

// SEH wrapper — no C++ objects, just fills a pre-allocated array
static int find_rdata_sections_seh(uintptr_t base, SectionRange* out, int max_count) {
    int count = 0;
    __try {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections && count < max_count; i++) {
            bool is_rdata = (memcmp(sec[i].Name, ".rdata", 6) == 0);
            bool is_readonly = (sec[i].Characteristics & IMAGE_SCN_MEM_READ) &&
                              !(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
                              !(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
            if (is_rdata || is_readonly) {
                uintptr_t sec_start = base + sec[i].VirtualAddress;
                size_t sec_size = sec[i].Misc.VirtualSize;
                if (sec_size >= 16) {
                    out[count++] = {sec_start, sec_size};
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // PE parsing failed
    }
    return count;
}

static std::vector<SectionRange> find_rdata_sections(uintptr_t base) {
    SectionRange buf[64];
    int n = find_rdata_sections_seh(base, buf, 64);
    return std::vector<SectionRange>(buf, buf + n);
}

// ============================================================================
// Core scanner: find serialized FileDescriptorProto blobs
// ============================================================================

// SEH-safe probe: check if memory at p (up to max_len bytes) starts with
// a valid FileDescriptorProto header (field 1 = string ending in ".proto").
// Returns the proto filename length (including tag+varint) or 0 on failure.
// name_buf must be at least 512 bytes.
static size_t probe_proto_header(const uint8_t* p, size_t max_len,
                                  char* name_buf, size_t name_buf_size) {
    __try {
        if (max_len < 8) return 0;
        if (p[0] != 0x0A) return 0;  // field 1, LEN

        // Read varint length
        size_t pos = 1;
        uint64_t str_len = 0;
        int shift = 0;
        while (pos < max_len && shift < 64) {
            uint8_t b = p[pos++];
            str_len |= (uint64_t)(b & 0x7F) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }

        if (str_len < 7 || str_len >= name_buf_size || pos + str_len > max_len)
            return 0;

        // Copy string and null-terminate
        memcpy(name_buf, p + pos, (size_t)str_len);
        name_buf[str_len] = '\0';

        // Check ".proto" suffix
        if (str_len < 6) return 0;
        if (memcmp(name_buf + str_len - 6, ".proto", 6) != 0) return 0;

        // Validate printable ASCII
        for (size_t i = 0; i < str_len; i++) {
            if (name_buf[i] < 0x20 || name_buf[i] > 0x7E) return 0;
        }

        return pos + (size_t)str_len;  // bytes consumed
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// SEH-safe: copy blob data to a local buffer for safe parsing
static bool safe_copy_bytes(const uint8_t* src, uint8_t* dst, size_t len) {
    __try {
        memcpy(dst, src, len);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static std::vector<ProtoFile> scan_module(uintptr_t base, size_t image_size,
                                           const char* mod_name) {
    std::vector<ProtoFile> files;
    auto sections = find_rdata_sections(base);

    if (sections.empty()) {
        LOG_D("  %s: no .rdata sections found", mod_name);
        return files;
    }

    size_t total_rdata = 0;
    for (const auto& sec : sections) total_rdata += sec.size;
    LOG_D("  %s: scanning %zu KB of .rdata across %d sections",
          mod_name, total_rdata / 1024, (int)sections.size());

    // Track found .proto filenames to avoid duplicates
    std::unordered_set<std::string> found_names;

    for (const auto& sec : sections) {
        for (size_t off = 0; off + 16 < sec.size; off++) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(sec.start + off);

            // Quick check: first byte must be 0x0A (field 1, LEN)
            if (*p != 0x0A) continue;

            // SEH-safe header probe
            char name_buf[512];
            size_t header_len = probe_proto_header(p, sec.size - off, name_buf, sizeof(name_buf));
            if (header_len == 0) continue;

            std::string name(name_buf);
            if (found_names.count(name)) continue;

            // Measure and copy the blob to a local buffer for safe parsing
            size_t max_blob = sec.size - off;
            if (max_blob > 1024 * 1024) max_blob = 1024 * 1024;  // cap at 1MB

            // First pass: measure the blob size from the original memory
            // (measure_proto_blob only reads, doesn't allocate)
            size_t blob_size = 0;
            {
                // Copy a reasonable chunk to measure safely
                size_t probe_size = (max_blob < 256 * 1024) ? max_blob : 256 * 1024;
                std::vector<uint8_t> probe_buf(probe_size);
                if (!safe_copy_bytes(p, probe_buf.data(), probe_size)) continue;
                blob_size = measure_proto_blob(probe_buf.data(), probe_size);
            }

            if (blob_size < 10 || blob_size > max_blob) continue;

            // Copy the exact blob
            std::vector<uint8_t> blob(blob_size);
            if (!safe_copy_bytes(p, blob.data(), blob_size)) continue;

            wire::Reader full{blob.data(), blob_size, 0};
            ProtoFile file = decode_file_descriptor(full);

            if (file.name.empty()) continue;
            if (file.messages.empty() && file.enums.empty()) continue;

            found_names.insert(file.name);

            LOG_I("  %s: found %s (%d messages, %d enums)",
                  mod_name, file.name.c_str(),
                  (int)file.messages.size(), (int)file.enums.size());

            files.push_back(std::move(file));
        }
    }

    return files;
}

// ============================================================================
// Public API
// ============================================================================

ProtoMap scan() {
    ProtoMap results;

    LOG_I("Scanning for embedded protobuf descriptors...");

    // Enumerate all loaded modules
    HMODULE modules[512];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        LOG_E("EnumProcessModules failed");
        return results;
    }

    int mod_count = needed / sizeof(HMODULE);
    int total_files = 0;
    int total_messages = 0;

    for (int i = 0; i < mod_count; i++) {
        char mod_path[MAX_PATH];
        if (!GetModuleFileNameA(modules[i], mod_path, MAX_PATH)) continue;

        // Skip Windows system DLLs
        if (strstr(mod_path, "\\Windows\\") || strstr(mod_path, "\\windows\\"))
            continue;

        const char* slash = strrchr(mod_path, '\\');
        const char* mod_name = slash ? slash + 1 : mod_path;

        MODULEINFO mi = {};
        if (!GetModuleInformation(GetCurrentProcess(), modules[i], &mi, sizeof(mi)))
            continue;

        // Skip tiny modules
        if (mi.SizeOfImage < 0x10000) continue;

        auto files = scan_module(
            reinterpret_cast<uintptr_t>(mi.lpBaseOfDll),
            mi.SizeOfImage,
            mod_name
        );

        if (!files.empty()) {
            int msg_count = 0;
            for (const auto& f : files) msg_count += (int)f.messages.size();
            total_files += (int)files.size();
            total_messages += msg_count;
            results[mod_name] = std::move(files);
        }
    }

    LOG_I("Protobuf scan complete: %d .proto files, %d messages across %d modules",
          total_files, total_messages, (int)results.size());

    return results;
}

} // namespace protobuf_scan
