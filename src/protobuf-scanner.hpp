#pragma once
#ifndef DEZLOCK_PROTOBUF_SCANNER_HPP
#define DEZLOCK_PROTOBUF_SCANNER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace protobuf_scan {

// ============================================================================
// Types — mirrors the protobuf descriptor.proto schema
// ============================================================================

struct ProtoEnumValue {
    std::string name;
    int32_t     number = 0;
};

struct ProtoEnum {
    std::string                 name;
    std::vector<ProtoEnumValue> values;
};

struct ProtoField {
    std::string name;
    int32_t     number    = 0;
    int32_t     type      = 0;   // FieldDescriptorProto.Type enum
    int32_t     label     = 0;   // 1=optional, 2=required, 3=repeated
    std::string type_name;       // for message/enum references
    std::string default_value;
    int32_t     oneof_index = -1;
    std::string json_name;
};

struct ProtoMessage {
    std::string                  name;
    std::vector<ProtoField>      fields;
    std::vector<ProtoMessage>    nested_messages;
    std::vector<ProtoEnum>       nested_enums;
    std::vector<std::string>     oneof_decls;    // oneof names
};

struct ProtoFile {
    std::string                  name;           // e.g. "usercmd.proto"
    std::string                  package;        // e.g. "citadel"
    std::string                  syntax;         // e.g. "proto2", "proto3"
    std::vector<std::string>     dependencies;
    std::vector<ProtoMessage>    messages;
    std::vector<ProtoEnum>       enums;
};

// module name -> list of proto files found in that module
using ProtoMap = std::unordered_map<std::string, std::vector<ProtoFile>>;

// ============================================================================
// Field type name lookup
// ============================================================================

// Returns human-readable type name for FieldDescriptorProto.Type value
const char* field_type_name(int32_t type);

// ============================================================================
// API
// ============================================================================

// Scan all loaded game DLLs for serialized FileDescriptorProto blobs
// embedded in .rdata sections. Decodes them using raw protobuf wire format.
ProtoMap scan();

} // namespace protobuf_scan

#endif // DEZLOCK_PROTOBUF_SCANNER_HPP
