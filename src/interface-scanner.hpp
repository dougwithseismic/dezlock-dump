/**
 * dezlock-dump — CreateInterface Scanner
 *
 * Enumerates all CreateInterface exports across loaded DLLs, walks
 * InterfaceReg linked lists, and collects interface names + vtable pointers.
 *
 * Finds registered engine interfaces like EngineTraceServer_001,
 * GameTraceManager_001, etc. that are not discoverable through SchemaSystem.
 */

#pragma once
#ifndef DEZLOCK_INTERFACE_SCANNER_HPP
#define DEZLOCK_INTERFACE_SCANNER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace interfaces {

// ============================================================================
// Types
// ============================================================================

struct InterfaceEntry {
    std::string name;           // Full name e.g. "EngineTraceServer_001"
    std::string base_name;      // Without version e.g. "EngineTraceServer"
    int         version = 0;    // Parsed version number (001 -> 1)
    uint32_t    factory_rva = 0;// RVA of the CreateFn factory
    uint32_t    instance_rva = 0; // RVA of the instance pointer (from calling factory)
    uint32_t    vtable_rva = 0; // RVA of the vtable of the instance
};

// module name -> list of discovered interfaces
using InterfaceMap = std::unordered_map<std::string, std::vector<InterfaceEntry>>;

// ============================================================================
// API
// ============================================================================

// Scan all loaded DLLs for CreateInterface exports, walk InterfaceReg lists.
// Skips Windows system DLLs. All memory reads are SEH-protected.
InterfaceMap scan();

} // namespace interfaces

#endif // DEZLOCK_INTERFACE_SCANNER_HPP
