/**
 * dezlock-dump — CreateInterface Scanner
 *
 * Enumerates CreateInterface exports from all loaded game DLLs and walks
 * the InterfaceReg linked list to discover registered engine interfaces.
 *
 * InterfaceReg layout (Source 2, x64):
 *   +0x00: CreateFn m_CreateFn  (8 bytes, function pointer returning void*)
 *   +0x08: const char* m_pName  (8 bytes, interface name string)
 *   +0x10: InterfaceReg* m_pNext (8 bytes, next in linked list)
 *
 * CreateInterface export typically starts with:
 *   LEA reg, [rip+disp32]   ; load InterfaceReg* list head
 */

#define LOG_TAG "interface-scanner"

#include "interface-scanner.hpp"
#include "log.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <cstring>

namespace interfaces {

// ============================================================================
// SEH-safe memory reads
// ============================================================================

static bool safe_read_u64(uintptr_t addr, uint64_t& out) {
    __try {
        out = *reinterpret_cast<const uint64_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool safe_read_bytes(const void* src, void* dst, size_t len) {
    __try {
        memcpy(dst, src, len);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool safe_read_string(const char* src, char* dst, size_t max_len) {
    __try {
        size_t i = 0;
        for (; i < max_len - 1; i++) {
            dst[i] = src[i];
            if (src[i] == '\0') return true;
        }
        dst[i] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = '\0';
        return false;
    }
}

// ============================================================================
// Find InterfaceReg list head from CreateInterface function body
// ============================================================================

// Scan first N bytes of CreateInterface for LEA/MOV reg, [rip+disp32]
// that loads the InterfaceReg* linked list head.
static uintptr_t find_interface_list_head(uintptr_t func_addr) {
    uint8_t code[64];
    if (!safe_read_bytes(reinterpret_cast<const void*>(func_addr), code, sizeof(code)))
        return 0;

    for (size_t i = 0; i + 7 <= sizeof(code); i++) {
        // Look for LEA reg, [rip+disp32]:  48 8D xx yy yy yy yy
        // or MOV reg, [rip+disp32]:         48 8B xx yy yy yy yy
        // REX.W prefix = 0x48 or 0x4C (with REX.R)
        uint8_t rex = code[i];
        if (rex != 0x48 && rex != 0x4C) continue;

        uint8_t opcode = code[i + 1];
        if (opcode != 0x8D && opcode != 0x8B) continue;

        uint8_t modrm = code[i + 2];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm  = modrm & 7;

        // mod=00, rm=5 means [rip+disp32]
        if (mod != 0 || rm != 5) continue;

        int32_t disp = 0;
        memcpy(&disp, &code[i + 3], 4);

        // RIP-relative: target = instruction_end + disp
        uintptr_t insn_end = func_addr + i + 7;
        uintptr_t target = insn_end + disp;

        // For LEA, target IS the InterfaceReg*
        // For MOV, target is a pointer TO InterfaceReg*
        if (opcode == 0x8B) {
            // MOV — dereference to get the actual pointer
            uint64_t ptr_val = 0;
            if (!safe_read_u64(target, ptr_val)) continue;
            return static_cast<uintptr_t>(ptr_val);
        } else {
            // LEA — target is the static InterfaceReg* variable, dereference it
            uint64_t ptr_val = 0;
            if (!safe_read_u64(target, ptr_val)) continue;
            return static_cast<uintptr_t>(ptr_val);
        }
    }

    return 0;
}

// ============================================================================
// Parse interface name: extract base name and version
// ============================================================================

static void parse_interface_name(const std::string& name, std::string& base_name, int& version) {
    // Find trailing digits: "EngineTraceServer_001" -> base="EngineTraceServer", ver=1
    size_t i = name.size();
    while (i > 0 && name[i - 1] >= '0' && name[i - 1] <= '9') {
        i--;
    }

    if (i < name.size()) {
        // Remove trailing underscore or separator
        size_t base_end = i;
        if (base_end > 0 && name[base_end - 1] == '_') base_end--;

        base_name = name.substr(0, base_end);
        version = atoi(name.c_str() + i);
    } else {
        base_name = name;
        version = 0;
    }
}

// ============================================================================
// SEH-isolated factory call (no C++ objects in scope)
// ============================================================================

// Call a CreateInterface factory and extract instance/vtable RVAs.
// Isolated because __try cannot coexist with C++ destructors.
static bool safe_call_factory(uint64_t create_fn, uintptr_t mod_base,
                              uint32_t& out_instance_rva, uint32_t& out_vtable_rva) {
    out_instance_rva = 0;
    out_vtable_rva = 0;

    __try {
        using CreateFn = void*(*)();
        auto factory = reinterpret_cast<CreateFn>(create_fn);
        void* instance = factory();

        if (instance) {
            uintptr_t instance_addr = reinterpret_cast<uintptr_t>(instance);
            if (instance_addr > mod_base)
                out_instance_rva = static_cast<uint32_t>(instance_addr - mod_base);

            uint64_t vtable_ptr = 0;
            if (safe_read_u64(instance_addr, vtable_ptr)) {
                if (vtable_ptr > mod_base)
                    out_vtable_rva = static_cast<uint32_t>(vtable_ptr - mod_base);
            }
            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Factory call failed
    }
    return false;
}

// ============================================================================
// Walk InterfaceReg linked list
// ============================================================================

static std::vector<InterfaceEntry> walk_interface_list(uintptr_t head, uintptr_t mod_base) {
    std::vector<InterfaceEntry> entries;
    uintptr_t current = head;
    int count = 0;
    constexpr int MAX_ENTRIES = 4096;

    while (current != 0 && count < MAX_ENTRIES) {
        count++;

        // Read InterfaceReg fields:
        //   +0x00: CreateFn (8 bytes)
        //   +0x08: const char* m_pName (8 bytes)
        //   +0x10: InterfaceReg* m_pNext (8 bytes)

        uint64_t create_fn = 0, name_ptr = 0, next_ptr = 0;
        if (!safe_read_u64(current + 0x00, create_fn)) break;
        if (!safe_read_u64(current + 0x08, name_ptr)) break;
        if (!safe_read_u64(current + 0x10, next_ptr)) break;

        // Validate name pointer
        if (name_ptr == 0) {
            current = static_cast<uintptr_t>(next_ptr);
            continue;
        }

        char name_buf[256] = {};
        if (!safe_read_string(reinterpret_cast<const char*>(name_ptr), name_buf, sizeof(name_buf))) {
            current = static_cast<uintptr_t>(next_ptr);
            continue;
        }

        // Skip empty or garbage names
        if (name_buf[0] == '\0' || strlen(name_buf) < 3) {
            current = static_cast<uintptr_t>(next_ptr);
            continue;
        }

        // Validate name is printable ASCII
        bool valid = true;
        for (const char* p = name_buf; *p; p++) {
            if (*p < 0x20 || *p > 0x7E) { valid = false; break; }
        }
        if (!valid) {
            current = static_cast<uintptr_t>(next_ptr);
            continue;
        }

        InterfaceEntry entry;
        entry.name = name_buf;
        parse_interface_name(entry.name, entry.base_name, entry.version);

        // Factory RVA
        if (create_fn > mod_base)
            entry.factory_rva = static_cast<uint32_t>(create_fn - mod_base);

        // Call factory to get instance (Source 2 factories return pre-allocated singletons)
        safe_call_factory(create_fn, mod_base, entry.instance_rva, entry.vtable_rva);

        entries.push_back(std::move(entry));
        current = static_cast<uintptr_t>(next_ptr);
    }

    return entries;
}

// ============================================================================
// Main scan
// ============================================================================

InterfaceMap scan() {
    InterfaceMap results;

    HMODULE modules_arr[512];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), modules_arr, sizeof(modules_arr), &needed)) {
        LOG_E("EnumProcessModules failed");
        return results;
    }

    int mod_count = needed / sizeof(HMODULE);
    int total_interfaces = 0;

    for (int i = 0; i < mod_count; i++) {
        char mod_path[MAX_PATH];
        if (!GetModuleFileNameA(modules_arr[i], mod_path, MAX_PATH)) continue;

        // Skip Windows system DLLs
        if (strstr(mod_path, "\\Windows\\") || strstr(mod_path, "\\windows\\"))
            continue;

        // Extract filename
        const char* slash = strrchr(mod_path, '\\');
        const char* mod_name = slash ? slash + 1 : mod_path;

        // Check for CreateInterface export
        auto create_fn = reinterpret_cast<uintptr_t>(
            GetProcAddress(modules_arr[i], "CreateInterface"));
        if (!create_fn) continue;

        uintptr_t mod_base = reinterpret_cast<uintptr_t>(modules_arr[i]);

        // Find list head by scanning CreateInterface function body
        uintptr_t list_head = find_interface_list_head(create_fn);
        if (!list_head) {
            LOG_W("  %s: CreateInterface found but couldn't locate list head", mod_name);
            continue;
        }

        auto entries = walk_interface_list(list_head, mod_base);
        if (!entries.empty()) {
            LOG_I("  %s: %d interfaces", mod_name, (int)entries.size());
            total_interfaces += (int)entries.size();
            results[mod_name] = std::move(entries);
        }
    }

    LOG_I("Interface scan complete: %d interfaces across %d modules",
          total_interfaces, (int)results.size());
    return results;
}

} // namespace interfaces
