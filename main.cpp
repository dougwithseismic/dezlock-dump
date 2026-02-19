/**
 * Dezlock Dump — Standalone Schema Extraction Tool
 *
 * Usage: dezlock-dump.exe [--process <name>] [--output <dir>] [--wait <seconds>]
 *
 * 1. Finds target Source 2 process (default: deadlock.exe)
 * 2. Injects dezlock-worker.dll via manual-map (PE mapping + shellcode)
 * 3. Waits for the worker to finish (writes JSON to %TEMP%)
 * 4. Reads JSON and generates output files:
 *    - schema-dump/client.txt      (greppable text)
 *    - schema-dump/client-flat.txt (flattened with inherited fields)
 *    - schema-dump/client.json     (full JSON)
 *
 * Requires: admin elevation (for process injection)
 * Requires: Target Source 2 game must be running
 */

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

#include "vendor/json.hpp"
using json = nlohmann::json;

// ============================================================================
// Process finding
// ============================================================================

DWORD find_process(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

// Forward declarations for console helpers (defined below)
static void con_ok(const char* fmt, ...);
static void con_fail(const char* fmt, ...);
static void con_info(const char* fmt, ...);

// ============================================================================
// DLL Injection via Manual-Map (PE mapping + in-process shellcode)
// ============================================================================

// --- PE Parser ---

struct PeInfo {
    std::vector<uint8_t>   raw;
    IMAGE_DOS_HEADER*      dos;
    IMAGE_NT_HEADERS64*    nt;
    IMAGE_SECTION_HEADER*  sections;
    WORD                   num_sections;
    uint64_t               preferred_base;
    uint32_t               size_of_image;
    uint32_t               entry_point_rva;
    IMAGE_DATA_DIRECTORY   reloc_dir;
    IMAGE_DATA_DIRECTORY   import_dir;
    IMAGE_DATA_DIRECTORY   exc_dir;
    IMAGE_DATA_DIRECTORY   tls_dir;
};

static bool pe_parse(const char* path, PeInfo& pe) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        con_fail("Cannot open DLL: %s (err %lu)", path, GetLastError());
        return false;
    }

    DWORD file_size = GetFileSize(hFile, nullptr);
    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        con_fail("File too small");
        CloseHandle(hFile);
        return false;
    }

    pe.raw.resize(file_size);
    DWORD read;
    ReadFile(hFile, pe.raw.data(), file_size, &read, nullptr);
    CloseHandle(hFile);
    if (read != file_size) return false;

    pe.dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.raw.data());
    if (pe.dos->e_magic != IMAGE_DOS_SIGNATURE) {
        con_fail("Invalid DOS signature");
        return false;
    }

    pe.nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.raw.data() + pe.dos->e_lfanew);
    if (pe.nt->Signature != IMAGE_NT_SIGNATURE) {
        con_fail("Invalid NT signature");
        return false;
    }

    if (pe.nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        con_fail("Not a 64-bit DLL");
        return false;
    }

    if (!(pe.nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        con_fail("Not a DLL");
        return false;
    }

    auto& opt = pe.nt->OptionalHeader;
    pe.preferred_base  = opt.ImageBase;
    pe.size_of_image   = opt.SizeOfImage;
    pe.entry_point_rva = opt.AddressOfEntryPoint;
    pe.sections        = IMAGE_FIRST_SECTION(pe.nt);
    pe.num_sections    = pe.nt->FileHeader.NumberOfSections;

    pe.reloc_dir  = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pe.import_dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pe.exc_dir    = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    pe.tls_dir    = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    con_info("PE: ImageBase=0x%llX  SizeOfImage=0x%X  EntryRVA=0x%X",
             pe.preferred_base, pe.size_of_image, pe.entry_point_rva);
    con_info("PE: Sections=%u  Relocs=0x%X (%u bytes)  Imports=0x%X",
             pe.num_sections, pe.reloc_dir.VirtualAddress, pe.reloc_dir.Size,
             pe.import_dir.VirtualAddress);

    return true;
}

// --- Mapping Context & In-Process Shellcode ---

typedef struct _MAPPING_CTX {
    LPVOID    base_addr;
    HINSTANCE (WINAPI* fn_LoadLibrary)(LPCSTR);
    FARPROC   (WINAPI* fn_GetProcAddress)(HMODULE, LPCSTR);
    BOOL      (WINAPI* fn_RtlAddFunctionTable)(PVOID, DWORD, DWORD64);
    HINSTANCE mod_handle;
    DWORD     reason;
    LPVOID    reserved;
    BOOL      seh_enabled;
} MAPPING_CTX;

#define RELOC_FLAG64(info) (((info) >> 12) == IMAGE_REL_BASED_DIR64)
#define INJECT_INVALID_DATA ((HINSTANCE)0x404040)
#define INJECT_SEH_FAILED   ((HINSTANCE)0x505050)

static constexpr size_t CTX_OFFSET  = 0;
static constexpr size_t CODE_OFFSET = 0x100;
static constexpr size_t SHELL_PAGE  = 0x1000;

#pragma runtime_checks("", off)
#pragma optimize("", off)
#pragma strict_gs_check(push, off)
#pragma check_stack(off)
__declspec(safebuffers)
static DWORD WINAPI target_shellcode(LPVOID lpParam) {
    MAPPING_CTX* pData = reinterpret_cast<MAPPING_CTX*>(lpParam);
    if (!pData)
        return 1;

    BYTE* pBase = reinterpret_cast<BYTE*>(pData->base_addr);
    if (!pBase) {
        pData->mod_handle = INJECT_INVALID_DATA;
        return 2;
    }

    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(
        pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA   = pData->fn_LoadLibrary;
    auto _GetProcAddress = pData->fn_GetProcAddress;

    if (!_LoadLibraryA || !_GetProcAddress) {
        pData->mod_handle = INJECT_INVALID_DATA;
        return 3;
    }

    auto _DllMain = reinterpret_cast<BOOL(WINAPI*)(void*, DWORD, void*)>(
        pBase + pOpt->AddressOfEntryPoint);

    // Phase 1: Relocations
    BYTE* delta = pBase - pOpt->ImageBase;
    if (delta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        const auto* pRelocEnd = reinterpret_cast<BYTE*>(pReloc) +
            pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        while (reinterpret_cast<BYTE*>(pReloc) < pRelocEnd && pReloc->SizeOfBlock) {
            UINT count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = reinterpret_cast<WORD*>(pReloc + 1);

            for (UINT i = 0; i < count; ++i) {
                if (RELOC_FLAG64(entries[i])) {
                    UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(
                        pBase + pReloc->VirtualAddress + (entries[i] & 0xFFF));
                    *pPatch += reinterpret_cast<UINT_PTR>(delta);
                }
            }

            pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
        }
    }

    // Phase 2: Import Resolution
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImport = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (pImport->Name) {
            HMODULE hMod = _LoadLibraryA(reinterpret_cast<char*>(pBase + pImport->Name));
            if (!hMod) {
                pData->mod_handle = INJECT_INVALID_DATA;
                return 4;
            }

            ULONG_PTR* pThunk = reinterpret_cast<ULONG_PTR*>(
                pBase + pImport->OriginalFirstThunk);
            ULONG_PTR* pFunc = reinterpret_cast<ULONG_PTR*>(
                pBase + pImport->FirstThunk);
            if (!pThunk) pThunk = pFunc;

            for (; *pThunk; ++pThunk, ++pFunc) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunk)) {
                    *pFunc = reinterpret_cast<ULONG_PTR>(
                        _GetProcAddress(hMod, reinterpret_cast<char*>(*pThunk & 0xFFFF)));
                } else {
                    auto* pName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + *pThunk);
                    *pFunc = reinterpret_cast<ULONG_PTR>(
                        _GetProcAddress(hMod, pName->Name));
                }
            }

            ++pImport;
        }
    }

    // Phase 3: TLS Callbacks
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
            pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto** pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback) {
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    // Phase 4: SEH Exception Handlers (.pdata)
    bool seh_failed = false;
    if (pData->seh_enabled) {
        auto& excDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir.Size) {
            if (!pData->fn_RtlAddFunctionTable(
                    reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excDir.VirtualAddress),
                    excDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
                    reinterpret_cast<DWORD64>(pBase))) {
                seh_failed = true;
            }
        }
    }

    // Phase 5: DllMain
    _DllMain(pBase, pData->reason, pData->reserved);

    pData->mod_handle = seh_failed
        ? INJECT_SEH_FAILED
        : reinterpret_cast<HINSTANCE>(pBase);

    return 0;
}
#pragma strict_gs_check(pop)
#pragma runtime_checks("", restore)
#pragma optimize("", on)

// --- Manual-Map Inject ---

static bool mmap_inject(HANDLE hProc, const PeInfo& pe) {
    // Allocate image in target (RWX during setup)
    void* image_base = VirtualAllocEx(hProc, nullptr, pe.size_of_image,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!image_base) {
        con_fail("VirtualAllocEx failed for image (%u bytes, err %lu)",
                 pe.size_of_image, GetLastError());
        return false;
    }
    con_info("Image allocated at 0x%p (%u bytes)", image_base, pe.size_of_image);

    // Write PE headers
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, image_base, pe.raw.data(),
                            pe.nt->OptionalHeader.SizeOfHeaders, &written)) {
        con_fail("Failed to write PE headers (err %lu)", GetLastError());
        VirtualFreeEx(hProc, image_base, 0, MEM_RELEASE);
        return false;
    }

    // Write each section
    for (WORD i = 0; i < pe.num_sections; ++i) {
        auto& sec = pe.sections[i];
        if (sec.SizeOfRawData == 0) continue;

        void* dest = static_cast<BYTE*>(image_base) + sec.VirtualAddress;
        if (!WriteProcessMemory(hProc, dest,
                                pe.raw.data() + sec.PointerToRawData,
                                sec.SizeOfRawData, &written)) {
            con_fail("Failed to write section %.8s (err %lu)",
                     sec.Name, GetLastError());
            VirtualFreeEx(hProc, image_base, 0, MEM_RELEASE);
            return false;
        }
    }
    con_info("PE headers + %u sections written", pe.num_sections);

    // Allocate shellcode page
    void* shell_page = VirtualAllocEx(hProc, nullptr, SHELL_PAGE,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!shell_page) {
        con_fail("VirtualAllocEx failed for shellcode (err %lu)", GetLastError());
        VirtualFreeEx(hProc, image_base, 0, MEM_RELEASE);
        return false;
    }

    // Write MAPPING_CTX
    MAPPING_CTX ctx{};
    ctx.base_addr          = image_base;
    ctx.fn_LoadLibrary     = LoadLibraryA;
    ctx.fn_GetProcAddress  = GetProcAddress;
    ctx.fn_RtlAddFunctionTable = reinterpret_cast<decltype(ctx.fn_RtlAddFunctionTable)>(RtlAddFunctionTable);
    ctx.mod_handle         = nullptr;
    ctx.reason             = DLL_PROCESS_ATTACH;
    ctx.reserved           = nullptr;
    ctx.seh_enabled        = TRUE;

    if (!WriteProcessMemory(hProc, static_cast<BYTE*>(shell_page) + CTX_OFFSET,
                            &ctx, sizeof(ctx), &written)) {
        con_fail("Failed to write MAPPING_CTX (err %lu)", GetLastError());
        VirtualFreeEx(hProc, shell_page, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, image_base, 0, MEM_RELEASE);
        return false;
    }

    // Write shellcode function bytes
    if (!WriteProcessMemory(hProc, static_cast<BYTE*>(shell_page) + CODE_OFFSET,
                            reinterpret_cast<const void*>(&target_shellcode),
                            SHELL_PAGE - CODE_OFFSET, &written)) {
        con_fail("Failed to write shellcode (err %lu)", GetLastError());
        VirtualFreeEx(hProc, shell_page, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, image_base, 0, MEM_RELEASE);
        return false;
    }

    // Execute via CreateRemoteThread
    void* thread_entry = static_cast<BYTE*>(shell_page) + CODE_OFFSET;
    void* thread_param = static_cast<BYTE*>(shell_page) + CTX_OFFSET;

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
                                         reinterpret_cast<LPTHREAD_START_ROUTINE>(thread_entry),
                                         thread_param, 0, nullptr);
    if (!hThread) {
        con_fail("CreateRemoteThread failed (err %lu)", GetLastError());
        VirtualFreeEx(hProc, shell_page, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, image_base, 0, MEM_RELEASE);
        return false;
    }

    // Wait for completion
    DWORD wait = WaitForSingleObject(hThread, 15000);
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);

    if (wait == WAIT_TIMEOUT) {
        con_fail("Thread timed out (15s) — DLL may be stuck in DllMain");
        VirtualFreeEx(hProc, shell_page, 0, MEM_RELEASE);
        return false;
    }

    if (wait != WAIT_OBJECT_0) {
        con_fail("WaitForSingleObject failed (err %lu)", GetLastError());
        VirtualFreeEx(hProc, shell_page, 0, MEM_RELEASE);
        return false;
    }

    // Check for crash exceptions
    if (exit_code >= 0xC0000000) {
        con_fail("Thread crashed with exception 0x%08lX", exit_code);
        con_info("0xC0000005 = Access Violation, 0xC00000FD = Stack Overflow");
        VirtualFreeEx(hProc, shell_page, 0, MEM_RELEASE);
        return false;
    }

    if (exit_code != 0) {
        con_fail("Shellcode returned error %lu", exit_code);
        con_info("1=null param, 2=null base, 3=null functions, 4=import fail");
        VirtualFreeEx(hProc, shell_page, 0, MEM_RELEASE);
        return false;
    }

    // Read back MAPPING_CTX for result
    MAPPING_CTX result{};
    ReadProcessMemory(hProc, static_cast<BYTE*>(shell_page) + CTX_OFFSET,
                      &result, sizeof(result), nullptr);

    if (result.mod_handle == INJECT_INVALID_DATA) {
        con_fail("Shellcode reported failure (imports or bad data)");
        VirtualFreeEx(hProc, shell_page, 0, MEM_RELEASE);
        return false;
    }

    if (result.mod_handle == INJECT_SEH_FAILED) {
        con_info("Warning: SEH registration failed (non-fatal)");
    }

    return true;
}

// --- inject_dll: parse PE and manual-map into target process ---

bool inject_dll(DWORD pid, const char* dll_path) {
    PeInfo pe{};
    if (!pe_parse(dll_path, pe))
        return false;

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        FALSE, pid);

    if (!hProcess) {
        con_fail("OpenProcess failed (err=%lu). Run as admin?", GetLastError());
        return false;
    }

    bool ok = mmap_inject(hProcess, pe);
    CloseHandle(hProcess);
    return ok;
}

// ============================================================================
// Output generation
// ============================================================================

struct Field {
    std::string name;
    std::string type;
    int offset = 0;
    int size = 0;
    std::string defined_in;
    std::vector<std::string> metadata;
};

struct EnumValue {
    std::string name;
    long long value = 0;
};

struct EnumInfo {
    std::string name;
    int size = 0;
    std::vector<EnumValue> values;
};

struct ClassInfo {
    std::string name;
    int size = 0;
    std::string parent;
    std::vector<std::string> inheritance;
    std::vector<std::string> metadata;
    std::vector<Field> fields;
    std::vector<Field> static_fields;
    std::vector<std::pair<std::string, int>> components;
};

struct ModuleData {
    std::string name;
    std::vector<ClassInfo> classes;
    std::vector<EnumInfo> enums;
};

static std::vector<Field> parse_fields(const json& arr) {
    std::vector<Field> result;
    for (const auto& f : arr) {
        Field field;
        field.name = f.value("name", "");
        field.type = f.value("type", "");
        field.offset = f.value("offset", 0);
        field.size = f.value("size", 0);
        if (f.contains("metadata")) {
            for (const auto& m : f["metadata"]) {
                field.metadata.push_back(m.get<std::string>());
            }
        }
        result.push_back(std::move(field));
    }
    return result;
}

std::vector<ModuleData> parse_modules(const json& data) {
    std::vector<ModuleData> result;

    // New multi-module format
    if (data.contains("modules")) {
        for (const auto& mod : data["modules"]) {
            ModuleData md;
            md.name = mod.value("name", "");

            for (const auto& c : mod.value("classes", json::array())) {
                ClassInfo cls;
                cls.name = c.value("name", "");
                cls.size = c.value("size", 0);
                if (c.contains("parent") && c["parent"].is_string())
                    cls.parent = c["parent"].get<std::string>();
                for (const auto& inh : c.value("inheritance", json::array()))
                    cls.inheritance.push_back(inh.get<std::string>());
                if (c.contains("metadata")) {
                    for (const auto& m : c["metadata"])
                        cls.metadata.push_back(m.get<std::string>());
                }
                cls.fields = parse_fields(c.value("fields", json::array()));
                if (c.contains("static_fields"))
                    cls.static_fields = parse_fields(c["static_fields"]);
                for (const auto& comp : c.value("components", json::array()))
                    cls.components.emplace_back(comp.value("name", ""), comp.value("offset", 0));
                md.classes.push_back(std::move(cls));
            }

            for (const auto& e : mod.value("enums", json::array())) {
                EnumInfo en;
                en.name = e.value("name", "");
                en.size = e.value("size", 0);
                for (const auto& v : e.value("values", json::array())) {
                    EnumValue val;
                    val.name = v.value("name", "");
                    val.value = v.value("value", (long long)0);
                    en.values.push_back(val);
                }
                md.enums.push_back(std::move(en));
            }

            result.push_back(std::move(md));
        }
    }
    // Legacy single-module format (backward compat)
    else if (data.contains("classes")) {
        ModuleData md;
        md.name = data.value("module", "client.dll");
        for (const auto& c : data["classes"]) {
            ClassInfo cls;
            cls.name = c.value("name", "");
            cls.size = c.value("size", 0);
            if (c.contains("parent") && c["parent"].is_string())
                cls.parent = c["parent"].get<std::string>();
            for (const auto& inh : c.value("inheritance", json::array()))
                cls.inheritance.push_back(inh.get<std::string>());
            cls.fields = parse_fields(c.value("fields", json::array()));
            for (const auto& comp : c.value("components", json::array()))
                cls.components.emplace_back(comp.value("name", ""), comp.value("offset", 0));
            md.classes.push_back(std::move(cls));
        }
        if (data.contains("enums")) {
            for (const auto& e : data["enums"]) {
                EnumInfo en;
                en.name = e.value("name", "");
                en.size = e.value("size", 0);
                for (const auto& v : e.value("values", json::array())) {
                    EnumValue val;
                    val.name = v.value("name", "");
                    val.value = v.value("value", (long long)0);
                    en.values.push_back(val);
                }
                md.enums.push_back(std::move(en));
            }
        }
        result.push_back(std::move(md));
    }

    return result;
}

// (con_ok, con_fail, con_info forward-declared above inject code)

// ============================================================================
// C++ SDK header generation
// ============================================================================

// Map schema type name to C++ type
static std::string schema_to_cpp_type(const std::string& schema_type, int size) {
    // Primitives
    if (schema_type == "bool") return "bool";
    if (schema_type == "int8") return "int8_t";
    if (schema_type == "uint8") return "uint8_t";
    if (schema_type == "int16") return "int16_t";
    if (schema_type == "uint16") return "uint16_t";
    if (schema_type == "int32") return "int32_t";
    if (schema_type == "uint32") return "uint32_t";
    if (schema_type == "int64") return "int64_t";
    if (schema_type == "uint64") return "uint64_t";
    if (schema_type == "float32" || schema_type == "float") return "float";
    if (schema_type == "float64") return "double";

    // Common Source 2 types
    if (schema_type == "CUtlString" || schema_type == "CUtlSymbolLarge") return "void*"; // 8 bytes ptr
    if (schema_type == "Color") return "uint32_t";
    if (schema_type == "GameTime_t") return "float";
    if (schema_type == "GameTick_t") return "int32_t";
    if (schema_type == "QAngle") return "float[3]";
    if (schema_type == "Vector") return "float[3]";
    if (schema_type == "Vector2D") return "float[2]";
    if (schema_type == "Vector4D") return "float[4]";

    // Handles
    if (schema_type.find("CHandle") != std::string::npos) return "uint32_t";
    if (schema_type.find("CEntityHandle") != std::string::npos) return "uint32_t";

    // Pointers
    if (schema_type.find("*") != std::string::npos) return "void*";

    // For complex/unknown types, use sized byte array
    if (size > 0 && size <= 8) {
        // Small known-size types — use uint8_t array
        return ""; // signal: use raw padding
    }

    return ""; // unknown — will be padded
}

static std::string make_guard(const std::string& module_name) {
    std::string guard = "DEZLOCK_SDK_" + module_name;
    for (auto& c : guard) { c = toupper(c); if (c == '.' || c == '-') c = '_'; }
    guard += "_HPP";
    return guard;
}

void generate_headers(const std::vector<ClassInfo>& classes,
                      const std::vector<EnumInfo>& enums,
                      const std::string& output_dir,
                      const std::string& module_name) {
    // Build class lookup
    std::unordered_map<std::string, const ClassInfo*> by_name;
    for (const auto& c : classes) by_name[c.name] = &c;

    std::string sdk_dir = output_dir + "\\sdk";
    CreateDirectoryA(sdk_dir.c_str(), nullptr);

    // ---- Enums header ----
    if (!enums.empty()) {
        std::string enum_path = sdk_dir + "\\" + module_name + "-enums.hpp";
        FILE* fp = fopen(enum_path.c_str(), "w");
        if (fp) {
            std::string guard = make_guard(module_name + "_enums");
            fprintf(fp, "// Auto-generated by dezlock-dump — DO NOT EDIT\n");
            fprintf(fp, "#pragma once\n");
            fprintf(fp, "#ifndef %s\n#define %s\n\n", guard.c_str(), guard.c_str());
            fprintf(fp, "#include <cstdint>\n\n");

            for (const auto& en : enums) {
                const char* underlying = "int32_t";
                if (en.size == 1) underlying = "uint8_t";
                else if (en.size == 2) underlying = "int16_t";
                else if (en.size == 8) underlying = "int64_t";

                fprintf(fp, "enum class %s : %s {\n", en.name.c_str(), underlying);
                for (const auto& v : en.values) {
                    fprintf(fp, "    %s = %lld,\n", v.name.c_str(), v.value);
                }
                fprintf(fp, "};\n\n");
            }

            fprintf(fp, "#endif // %s\n", guard.c_str());
            fclose(fp);
            con_ok("  %s (%d enums)", enum_path.c_str(), (int)enums.size());
        }
    }

    // ---- Offsets namespace header ----
    {
        std::string off_path = sdk_dir + "\\" + module_name + "-offsets.hpp";
        FILE* fp = fopen(off_path.c_str(), "w");
        if (!fp) return;

        std::string guard = make_guard(module_name + "_offsets");
        fprintf(fp, "// Auto-generated by dezlock-dump — DO NOT EDIT\n");
        fprintf(fp, "#pragma once\n");
        fprintf(fp, "#ifndef %s\n#define %s\n\n", guard.c_str(), guard.c_str());
        fprintf(fp, "#include <cstdint>\n\n");
        fprintf(fp, "namespace offsets {\n\n");

        for (const auto& cls : classes) {
            if (cls.fields.empty()) continue;

            // Convert class name to snake_case namespace
            std::string ns = cls.name;
            // Just use the class name directly for clarity
            fprintf(fp, "namespace %s {\n", ns.c_str());

            auto sorted = cls.fields;
            std::sort(sorted.begin(), sorted.end(),
                      [](const Field& a, const Field& b) { return a.offset < b.offset; });

            for (const auto& f : sorted) {
                fprintf(fp, "    constexpr uint32_t %s = 0x%X; // %s (%d bytes)",
                        f.name.c_str(), f.offset, f.type.c_str(), f.size);
                for (const auto& m : f.metadata) fprintf(fp, " [%s]", m.c_str());
                fprintf(fp, "\n");
            }
            fprintf(fp, "} // %s\n\n", ns.c_str());
        }

        fprintf(fp, "} // namespace offsets\n\n");
        fprintf(fp, "#endif // %s\n", guard.c_str());
        fclose(fp);
        con_ok("  %s", off_path.c_str());
    }

    // ---- Padded struct headers ----
    // Generate one header per class with fields, padding, and static_asserts
    {
        std::string structs_dir = sdk_dir + "\\" + module_name;
        CreateDirectoryA(structs_dir.c_str(), nullptr);

        int struct_count = 0;

        for (const auto& cls : classes) {
            std::string file_path = structs_dir + "\\" + cls.name + ".hpp";
            FILE* fp = fopen(file_path.c_str(), "w");
            if (!fp) continue;

            std::string guard = make_guard(cls.name);
            fprintf(fp, "// Auto-generated by dezlock-dump — DO NOT EDIT\n");
            fprintf(fp, "// Class: %s\n", cls.name.c_str());
            fprintf(fp, "// Size: 0x%X (%d bytes)\n", cls.size, cls.size);
            if (!cls.parent.empty())
                fprintf(fp, "// Parent: %s\n", cls.parent.c_str());
            if (!cls.metadata.empty()) {
                fprintf(fp, "// Metadata:");
                for (const auto& m : cls.metadata) fprintf(fp, " [%s]", m.c_str());
                fprintf(fp, "\n");
            }
            fprintf(fp, "#pragma once\n");
            fprintf(fp, "#ifndef %s\n#define %s\n\n", guard.c_str(), guard.c_str());
            fprintf(fp, "#include <cstdint>\n");
            fprintf(fp, "#include <cstddef>\n");

            // Include parent header if it exists in this module
            if (!cls.parent.empty() && by_name.count(cls.parent)) {
                fprintf(fp, "#include \"%s.hpp\"\n", cls.parent.c_str());
            }
            fprintf(fp, "\n");

            // Determine base: if parent exists and is in this module, inherit from it
            bool has_known_parent = !cls.parent.empty() && by_name.count(cls.parent);
            int parent_size = 0;
            if (has_known_parent) {
                parent_size = by_name.at(cls.parent)->size;
            }

            if (has_known_parent) {
                fprintf(fp, "struct %s : %s {\n", cls.name.c_str(), cls.parent.c_str());
            } else {
                fprintf(fp, "struct %s {\n", cls.name.c_str());
            }

            // Sort own fields by offset
            auto sorted = cls.fields;
            std::sort(sorted.begin(), sorted.end(),
                      [](const Field& a, const Field& b) { return a.offset < b.offset; });

            // Filter to only fields that belong to THIS class (offset >= parent_size)
            // and generate padding between fields
            int cursor = has_known_parent ? parent_size : 0;
            int pad_idx = 0;

            for (const auto& f : sorted) {
                // Skip fields that belong to parent
                if (f.offset < cursor) continue;

                // Add padding if there's a gap
                if (f.offset > cursor) {
                    int gap = f.offset - cursor;
                    fprintf(fp, "    uint8_t _pad%X[0x%X];\n", cursor, gap);
                }

                // Map type
                std::string cpp_type = schema_to_cpp_type(f.type, f.size);

                // Metadata comment
                std::string meta_str;
                for (const auto& m : f.metadata) {
                    meta_str += " [";
                    meta_str += m;
                    meta_str += "]";
                }

                if (!cpp_type.empty()) {
                    // Check for array types like float[3]
                    auto bracket = cpp_type.find('[');
                    if (bracket != std::string::npos) {
                        std::string base = cpp_type.substr(0, bracket);
                        std::string arr = cpp_type.substr(bracket);
                        fprintf(fp, "    %s %s%s; // 0x%X (%s, %d)%s\n",
                                base.c_str(), f.name.c_str(), arr.c_str(),
                                f.offset, f.type.c_str(), f.size, meta_str.c_str());
                    } else {
                        fprintf(fp, "    %s %s; // 0x%X (%s, %d)%s\n",
                                cpp_type.c_str(), f.name.c_str(),
                                f.offset, f.type.c_str(), f.size, meta_str.c_str());
                    }
                } else {
                    // Unknown type — emit as byte array with comment
                    if (f.size > 0) {
                        fprintf(fp, "    uint8_t %s[0x%X]; // 0x%X (%s)%s\n",
                                f.name.c_str(), f.size,
                                f.offset, f.type.c_str(), meta_str.c_str());
                    } else {
                        fprintf(fp, "    // 0x%X  %s  %s  (unknown size)%s\n",
                                f.offset, f.name.c_str(), f.type.c_str(), meta_str.c_str());
                    }
                }

                cursor = f.offset + (f.size > 0 ? f.size : 0);
            }

            // Pad to class size
            int target_size = has_known_parent ? (cls.size - parent_size) : cls.size;
            int own_end = has_known_parent ? (cursor - parent_size) : cursor;
            // Actually we want total size padding
            if (cursor < cls.size) {
                fprintf(fp, "    uint8_t _padEnd[0x%X];\n", cls.size - cursor);
            }

            fprintf(fp, "};\n\n");

            // static_asserts
            fprintf(fp, "static_assert(sizeof(%s) == 0x%X);\n", cls.name.c_str(), cls.size);
            for (const auto& f : sorted) {
                if (f.offset < (has_known_parent ? parent_size : 0)) continue;
                std::string cpp_type = schema_to_cpp_type(f.type, f.size);
                // Only assert fields we actually emitted as named members
                fprintf(fp, "static_assert(offsetof(%s, %s) == 0x%X);\n",
                        cls.name.c_str(), f.name.c_str(), f.offset);
            }

            fprintf(fp, "\n#endif // %s\n", guard.c_str());
            fclose(fp);
            struct_count++;
        }

        con_ok("  %s\\ (%d struct headers)", structs_dir.c_str(), struct_count);
    }
}

void generate_enums(const std::vector<EnumInfo>& enums,
                    const std::string& output_dir, const std::string& module_name) {
    std::string path = output_dir + "\\" + module_name + "-enums.txt";
    FILE* fp = fopen(path.c_str(), "w");
    if (!fp) return;

    fprintf(fp, "# Dezlock Enum Dump - %s.dll\n", module_name.c_str());
    fprintf(fp, "# Format: enum_name::VALUE_NAME = value\n");
    fprintf(fp, "# %d enums\n\n", (int)enums.size());

    int total_values = 0;
    for (const auto& en : enums) {
        fprintf(fp, "# --- %s (size=%d byte%s, %d values)\n",
                en.name.c_str(), en.size, en.size != 1 ? "s" : "",
                (int)en.values.size());
        for (const auto& v : en.values) {
            fprintf(fp, "%s::%s = %lld\n", en.name.c_str(), v.name.c_str(), v.value);
            total_values++;
        }
        fprintf(fp, "\n");
    }
    fclose(fp);
    printf("  -> %s (%d enums, %d values)\n", path.c_str(), (int)enums.size(), total_values);
}

void generate_text(const std::vector<ClassInfo>& classes, const json& data,
                   const std::string& output_dir, const std::string& module_name) {
    std::string txt_path = output_dir + "\\" + module_name + ".txt";
    FILE* fp = fopen(txt_path.c_str(), "w");
    if (!fp) {
        printf("  ERROR: Cannot write %s\n", txt_path.c_str());
        return;
    }

    fprintf(fp, "# Dezlock Schema Dump - %s\n", module_name.c_str());
    fprintf(fp, "# Generated: %s\n", data.value("timestamp", "?").c_str());
    fprintf(fp, "# Format: class_name.field_name = 0xOFFSET (type, size) [metadata...]\n#\n\n");

    int total_fields = 0;
    for (const auto& cls : classes) {
        fprintf(fp, "# --- %s (size=0x%X", cls.name.c_str(), cls.size);
        if (!cls.parent.empty()) fprintf(fp, ", parent=%s", cls.parent.c_str());
        fprintf(fp, ")\n");

        // Class metadata
        if (!cls.metadata.empty()) {
            fprintf(fp, "#     metadata:");
            for (const auto& m : cls.metadata) fprintf(fp, " [%s]", m.c_str());
            fprintf(fp, "\n");
        }

        if (cls.inheritance.size() > 1) {
            fprintf(fp, "#     chain:");
            for (size_t i = 0; i < cls.inheritance.size(); i++) {
                fprintf(fp, "%s%s", i ? " -> " : " ", cls.inheritance[i].c_str());
            }
            fprintf(fp, "\n");
        }

        for (const auto& [cname, coffset] : cls.components) {
            fprintf(fp, "#     component: %s at +0x%X\n", cname.c_str(), coffset);
        }

        auto sorted_fields = cls.fields;
        std::sort(sorted_fields.begin(), sorted_fields.end(),
                  [](const Field& a, const Field& b) { return a.offset < b.offset; });

        for (const auto& f : sorted_fields) {
            fprintf(fp, "%s.%s = 0x%X (%s, %d)",
                    cls.name.c_str(), f.name.c_str(), f.offset,
                    f.type.c_str(), f.size);
            for (const auto& m : f.metadata) fprintf(fp, " [%s]", m.c_str());
            fprintf(fp, "\n");
            total_fields++;
        }

        // Static fields
        if (!cls.static_fields.empty()) {
            for (const auto& sf : cls.static_fields) {
                fprintf(fp, "%s.%s = static (%s, %d)",
                        cls.name.c_str(), sf.name.c_str(), sf.type.c_str(), sf.size);
                for (const auto& m : sf.metadata) fprintf(fp, " [%s]", m.c_str());
                fprintf(fp, "\n");
            }
        }

        fprintf(fp, "\n");
    }
    fclose(fp);
    printf("  -> %s (%d classes, %d fields)\n", txt_path.c_str(), (int)classes.size(), total_fields);
}

void generate_flat(const std::vector<ClassInfo>& classes,
                   const std::string& output_dir, const std::string& module_name) {
    // Build lookup
    std::unordered_map<std::string, const ClassInfo*> by_name;
    for (const auto& c : classes) by_name[c.name] = &c;

    // Recursive field collector
    struct Collector {
        const std::unordered_map<std::string, const ClassInfo*>& lookup;
        std::vector<Field> result;

        void collect(const std::string& name, std::unordered_set<std::string>& visited) {
            if (visited.count(name)) return;
            visited.insert(name);

            auto it = lookup.find(name);
            if (it == lookup.end()) return;

            const auto* cls = it->second;
            for (const auto& f : cls->fields) {
                Field ff = f;
                ff.defined_in = name;
                result.push_back(ff);
            }
            if (!cls->parent.empty()) {
                collect(cls->parent, visited);
            }
        }
    };

    std::string flat_path = output_dir + "\\" + module_name + "-flat.txt";
    FILE* fp = fopen(flat_path.c_str(), "w");
    if (!fp) return;

    fprintf(fp, "# Dezlock Flattened Offset Index - %s.dll\n", module_name.c_str());
    fprintf(fp, "# All fields including inherited, sorted by offset\n");
    fprintf(fp, "# Format: class_name.field_name = 0xOFFSET (type, size, defined_in)\n\n");

    // Only flatten entity classes with 3+ inheritance depth
    for (const auto& cls : classes) {
        if (cls.inheritance.size() < 3) continue;

        Collector col{by_name, {}};
        std::unordered_set<std::string> visited;
        col.collect(cls.name, visited);

        if (col.result.empty()) continue;

        std::sort(col.result.begin(), col.result.end(),
                  [](const Field& a, const Field& b) { return a.offset < b.offset; });

        fprintf(fp, "# === %s (size=0x%X, %d total fields) ===\n",
                cls.name.c_str(), cls.size, (int)col.result.size());
        if (!cls.inheritance.empty()) {
            fprintf(fp, "#    ");
            for (size_t i = 0; i < cls.inheritance.size(); i++) {
                fprintf(fp, "%s%s", i ? " -> " : " ", cls.inheritance[i].c_str());
            }
            fprintf(fp, "\n");
        }

        for (const auto& f : col.result) {
            fprintf(fp, "%s.%s = 0x%X (%s, %d, %s)\n",
                    cls.name.c_str(), f.name.c_str(), f.offset,
                    f.type.c_str(), f.size, f.defined_in.c_str());
        }
        fprintf(fp, "\n");
    }

    fclose(fp);
    printf("  -> %s\n", flat_path.c_str());
}

void generate_hierarchy(const std::vector<ClassInfo>& classes,
                        const std::string& output_dir, const std::string& module_name) {
    // Build lookup
    std::unordered_map<std::string, const ClassInfo*> by_name;
    for (const auto& c : classes) by_name[c.name] = &c;

    // Build children map (parent -> list of children)
    std::unordered_map<std::string, std::vector<std::string>> children_map;
    std::unordered_set<std::string> has_parent;
    for (const auto& c : classes) {
        if (!c.parent.empty()) {
            children_map[c.parent].push_back(c.name);
            has_parent.insert(c.name);
        }
    }

    std::string hier_dir = output_dir + "\\hierarchy";
    CreateDirectoryA(hier_dir.c_str(), nullptr);

    // Recursive field collector for flat layout
    struct Collector {
        const std::unordered_map<std::string, const ClassInfo*>& lookup;
        std::vector<Field> result;

        void collect(const std::string& name, std::unordered_set<std::string>& visited) {
            if (visited.count(name)) return;
            visited.insert(name);
            auto it = lookup.find(name);
            if (it == lookup.end()) return;
            const auto* cls = it->second;
            for (const auto& f : cls->fields) {
                Field ff = f;
                ff.defined_in = name;
                result.push_back(ff);
            }
            if (!cls->parent.empty())
                collect(cls->parent, visited);
        }
    };

    // Helper: find the topmost schema-known ancestor for categorization
    auto get_category = [&by_name](const std::vector<std::string>& chain,
                                    const std::string& self_name) -> std::string {
        // Walk chain from root (end) to self (start), find the topmost that has schema data
        // chain = [self, parent, grandparent, ..., root]
        for (int i = (int)chain.size() - 1; i >= 1; i--) {
            if (by_name.count(chain[i])) return chain[i];
        }
        // No schema-known ancestor; put in _root
        return "_root";
    };

    int file_count = 0;
    int dir_count = 0;
    std::unordered_set<std::string> created_dirs;

    for (const auto& cls : classes) {
        // Determine category folder from topmost schema-known ancestor
        std::string category = get_category(cls.inheritance, cls.name);
        std::string cat_dir = hier_dir + "\\" + category;
        if (!created_dirs.count(cat_dir)) {
            CreateDirectoryA(cat_dir.c_str(), nullptr);
            created_dirs.insert(cat_dir);
            dir_count++;
        }

        // Write class file
        std::string file_path = cat_dir + "\\" + cls.name + ".txt";
        FILE* fp = fopen(file_path.c_str(), "w");
        if (!fp) continue;

        fprintf(fp, "// %s\n", cls.name.c_str());
        fprintf(fp, "// Size: 0x%X (%d bytes)\n", cls.size, cls.size);
        if (!cls.parent.empty())
            fprintf(fp, "// Parent: %s\n", cls.parent.c_str());
        fprintf(fp, "// Module: %s.dll\n", module_name.c_str());

        // Inheritance chain
        if (!cls.inheritance.empty()) {
            fprintf(fp, "//\n// Inheritance:\n//   ");
            for (size_t i = 0; i < cls.inheritance.size(); i++) {
                if (i > 0) fprintf(fp, " -> ");
                fprintf(fp, "%s", cls.inheritance[i].c_str());
            }
            fprintf(fp, "\n");
        }

        // Components
        if (!cls.components.empty()) {
            fprintf(fp, "//\n// Components:\n");
            for (const auto& [comp_name, comp_off] : cls.components) {
                fprintf(fp, "//   +0x%04X  %s\n", comp_off, comp_name.c_str());
            }
        }

        // Children (direct subclasses)
        auto cit = children_map.find(cls.name);
        if (cit != children_map.end() && !cit->second.empty()) {
            auto sorted_children = cit->second;
            std::sort(sorted_children.begin(), sorted_children.end());
            fprintf(fp, "//\n// Direct subclasses (%d):\n", (int)sorted_children.size());
            for (const auto& child : sorted_children) {
                fprintf(fp, "//   %s\n", child.c_str());
            }
        }

        fprintf(fp, "//\n\n");

        // Own fields (sorted by offset)
        auto sorted_fields = cls.fields;
        std::sort(sorted_fields.begin(), sorted_fields.end(),
                  [](const Field& a, const Field& b) { return a.offset < b.offset; });

        if (sorted_fields.empty()) {
            fprintf(fp, "// (no own fields)\n");
        } else {
            fprintf(fp, "// Own fields (%d):\n", (int)sorted_fields.size());
            for (const auto& f : sorted_fields) {
                fprintf(fp, "  +0x%04X  %-40s  %s  (%d bytes)\n",
                        f.offset, f.name.c_str(), f.type.c_str(), f.size);
            }
        }

        // Full flattened layout (if has parents)
        if (!cls.parent.empty()) {
            Collector col{by_name, {}};
            std::unordered_set<std::string> visited;
            col.collect(cls.name, visited);

            if (!col.result.empty()) {
                std::sort(col.result.begin(), col.result.end(),
                          [](const Field& a, const Field& b) { return a.offset < b.offset; });

                fprintf(fp, "\n// ---- Full layout (all inherited fields) ---- %d fields\n",
                        (int)col.result.size());
                for (const auto& f : col.result) {
                    fprintf(fp, "  +0x%04X  %-40s  %-30s  %3d  [%s]\n",
                            f.offset, f.name.c_str(), f.type.c_str(), f.size,
                            f.defined_in.c_str());
                }
            }
        }

        fclose(fp);
        file_count++;
    }

    // Write _index.txt with full tree
    std::string index_path = hier_dir + "\\_index.txt";
    FILE* idx = fopen(index_path.c_str(), "w");
    if (idx) {
        fprintf(idx, "# Dezlock Schema Hierarchy Index - %s.dll\n", module_name.c_str());
        fprintf(idx, "# %d classes in %d categories\n\n", file_count, dir_count);

        // Print tree for each root class
        std::vector<std::string> roots;
        for (const auto& c : classes) {
            if (has_parent.find(c.name) == has_parent.end())
                roots.push_back(c.name);
        }
        std::sort(roots.begin(), roots.end());

        // Recursive tree printer
        struct TreePrinter {
            const std::unordered_map<std::string, std::vector<std::string>>& children;
            const std::unordered_map<std::string, const ClassInfo*>& lookup;
            FILE* out;
            int max_depth;

            void print(const std::string& name, int depth, const std::string& prefix) {
                if (depth > max_depth) return;
                auto it = lookup.find(name);
                int sz = it != lookup.end() ? it->second->size : 0;
                int fc = it != lookup.end() ? (int)it->second->fields.size() : 0;
                fprintf(out, "%s%s (0x%X, %d fields)\n",
                        prefix.c_str(), name.c_str(), sz, fc);

                auto cit = children.find(name);
                if (cit == children.end()) return;

                auto sorted = cit->second;
                std::sort(sorted.begin(), sorted.end());
                for (size_t i = 0; i < sorted.size(); i++) {
                    bool last = (i == sorted.size() - 1);
                    std::string connector = last ? "`-- " : "|-- ";
                    std::string next_prefix = prefix + (last ? "    " : "|   ");
                    print(sorted[i], depth + 1, prefix + connector);
                }
            }
        };

        TreePrinter printer{children_map, by_name, idx, 20};
        for (const auto& root : roots) {
            printer.print(root, 0, "");
            fprintf(idx, "\n");
        }
        fclose(idx);
    }

    printf("  -> %s\\ (%d classes in %d folders + _index.txt)\n",
           hier_dir.c_str(), file_count, dir_count);
}

// ============================================================================
// Main
// ============================================================================

// ============================================================================
// Console helpers
// ============================================================================

static HANDLE g_console = INVALID_HANDLE_VALUE;
static FILE* g_log_fp = nullptr;

// Ensure we have a visible console window (even when launched elevated via UAC)
static void ensure_console() {
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_console == INVALID_HANDLE_VALUE || g_console == nullptr) {
        AllocConsole();
        g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    // Also open a log file for diagnostics
    char log_path[MAX_PATH];
    GetTempPathA(MAX_PATH, log_path);
    strcat_s(log_path, "dezlock-dump.log");
    g_log_fp = fopen(log_path, "w");
}

// Print to both console and log file
static void con_print(const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len <= 0) return;

    // Write to console
    DWORD written = 0;
    if (g_console != INVALID_HANDLE_VALUE)
        WriteConsoleA(g_console, buf, (DWORD)len, &written, nullptr);

    // Write to log
    if (g_log_fp) { fwrite(buf, 1, len, g_log_fp); fflush(g_log_fp); }
}

// Set console text color
static void con_color(WORD attr) {
    if (g_console != INVALID_HANDLE_VALUE)
        SetConsoleTextAttribute(g_console, attr);
}

static constexpr WORD CLR_DEFAULT = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static constexpr WORD CLR_TITLE   = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
static constexpr WORD CLR_OK      = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD CLR_WARN    = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD CLR_ERR     = FOREGROUND_RED | FOREGROUND_INTENSITY;
static constexpr WORD CLR_DIM     = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static constexpr WORD CLR_STEP    = FOREGROUND_GREEN | FOREGROUND_BLUE;

static void con_step(const char* step, const char* msg) {
    con_color(CLR_STEP);
    con_print("[%s] ", step);
    con_color(CLR_DEFAULT);
    con_print("%s\n", msg);
}

static void con_ok(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    con_color(CLR_OK);
    con_print("  OK  ");
    con_color(CLR_DEFAULT);
    con_print("%s\n", buf);
}

static void con_fail(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    con_color(CLR_ERR);
    con_print("  ERR ");
    con_color(CLR_DEFAULT);
    con_print("%s\n", buf);
}

static void con_info(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    con_color(CLR_DIM);
    con_print("      %s\n", buf);
    con_color(CLR_DEFAULT);
}

static void wait_for_keypress() {
    con_print("\nPress any key to exit...\n");
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    if (hInput != INVALID_HANDLE_VALUE) {
        FlushConsoleInputBuffer(hInput);
        INPUT_RECORD ir;
        DWORD read;
        while (ReadConsoleInputA(hInput, &ir, 1, &read)) {
            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown)
                break;
        }
    }
}

// Check if running with admin privileges
static bool is_elevated() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev = {};
        DWORD size = 0;
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
            elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

// ============================================================================
// Python script runner
// ============================================================================

// Find Python executable (tries python, python3, py in PATH)
static bool find_python(char* out_path, size_t out_size) {
    const char* candidates[] = {"python", "python3", "py"};
    for (const char* name : candidates) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "where %s > nul 2>&1", name);
        if (system(cmd) == 0) {
            snprintf(out_path, out_size, "%s", name);
            return true;
        }
    }
    return false;
}

// Run a Python script with arguments. Returns true on success (exit code 0).
static bool run_python_script(const char* python, const char* script_path,
                               const char* args) {
    char cmdline[2048];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" \"%s\" %s", python, script_path, args);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    // Inherit our console so Python output is visible
    si.dwFlags = 0;

    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(nullptr, cmdline, nullptr, nullptr, TRUE,
                        0, nullptr, nullptr, &si, &pi)) {
        con_fail("CreateProcess failed (err=%lu): %s", GetLastError(), cmdline);
        return false;
    }

    WaitForSingleObject(pi.hProcess, 120000); // 2 min timeout

    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return exit_code == 0;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    ensure_console();

    // Parse args (early pass — need process name for banner)
    std::string output_dir;
    std::string target_process = "deadlock.exe";
    int timeout_sec = 30;
    bool gen_headers = false;
    bool gen_signatures = false;
    bool gen_all = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "--process") == 0 && i + 1 < argc) {
            target_process = argv[++i];
        } else if (strcmp(argv[i], "--wait") == 0 && i + 1 < argc) {
            timeout_sec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--headers") == 0) {
            gen_headers = true;
        } else if (strcmp(argv[i], "--signatures") == 0) {
            gen_signatures = true;
        } else if (strcmp(argv[i], "--all") == 0) {
            gen_all = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            con_print("Usage: dezlock-dump.exe [--process <name>] [--output <dir>] [--wait <seconds>] [--headers] [--signatures] [--all]\n\n");
            con_print("  --process     Target process name (default: deadlock.exe)\n");
            con_print("                Examples: --process cs2.exe, --process dota2.exe\n");
            con_print("  --output      Output directory (default: schema-dump/ next to exe)\n");
            con_print("  --wait        Max wait time for worker DLL (default: 30s)\n");
            con_print("  --headers     Generate C++ SDK headers (structs, enums, offsets)\n");
            con_print("  --signatures  Generate byte pattern signatures from vtable functions\n");
            con_print("  --all         Enable all generators (headers + signatures)\n");
            wait_for_keypress();
            return 0;
        }
    }

    // Derive display name from process (e.g. "deadlock.exe" -> "Deadlock")
    std::string game_display = target_process;
    {
        auto dot = game_display.rfind('.');
        if (dot != std::string::npos) game_display = game_display.substr(0, dot);
        if (!game_display.empty()) game_display[0] = toupper(game_display[0]);
    }

    // Set console title
    {
        std::string title = "dezlock-dump - " + game_display + " Schema Extractor";
        SetConsoleTitleA(title.c_str());
    }

    con_print("\n");
    con_color(CLR_TITLE);
    con_print("  dezlock-dump");
    con_color(CLR_DIM);
    con_print("  v1.1.0\n");
    con_color(CLR_DEFAULT);
    con_print("  Runtime schema + RTTI extraction for %s (Source 2)\n", game_display.c_str());
    con_color(CLR_DIM);
    con_print("  https://github.com/dougwithseismic/dezlock-dump\n");
    con_color(CLR_DEFAULT);
    con_print("\n");

    // --all enables everything
    if (gen_all) {
        gen_headers = true;
        gen_signatures = true;
    }

    // Default output dir: schema-dump/ next to the exe
    if (output_dir.empty()) {
        char exe_dir[MAX_PATH];
        GetModuleFileNameA(GetModuleHandleA(nullptr), exe_dir, MAX_PATH);
        char full_path[MAX_PATH];
        GetFullPathNameA(exe_dir, MAX_PATH, full_path, nullptr);
        char* last_slash = strrchr(full_path, '\\');
        if (last_slash) *(last_slash + 1) = '\0';
        // Per-game output dir (e.g. schema-dump/deadlock/, schema-dump/cs2/)
        std::string game_folder = game_display;
        for (auto& c : game_folder) c = tolower(c);
        output_dir = std::string(full_path) + "schema-dump\\" + game_folder;
    }

    // ---- Pre-flight checks ----

    // Check 1: Admin privileges
    con_step("1/5", "Checking prerequisites...");

    if (!is_elevated()) {
        con_fail("Not running as administrator.");
        con_print("\n");
        con_color(CLR_WARN);
        con_print("  This tool needs admin privileges to read %s's memory.\n", game_display.c_str());
        con_print("  Right-click dezlock-dump.exe -> Run as administrator\n");
        con_color(CLR_DEFAULT);
        wait_for_keypress();
        return 1;
    }
    con_ok("Running as administrator");

    // Check 2: Target game is running
    // Convert process name to wide string for find_process
    wchar_t target_wide[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, target_process.c_str(), -1, target_wide, MAX_PATH);

    DWORD pid = find_process(target_wide);
    if (!pid) {
        con_fail("%s is not running.", game_display.c_str());
        con_print("\n");
        con_color(CLR_WARN);
        con_print("  Please launch %s first, then run this tool.\n", game_display.c_str());
        con_print("  The game needs to be fully loaded (main menu or in a match).\n");
        con_color(CLR_DEFAULT);
        con_print("\n");
        con_info("Waiting for %s to start...", game_display.c_str());

        // Wait for game with a spinner
        const char* spinner = "|/-\\";
        int spin = 0;
        int wait_count = 0;
        while (!pid) {
            Sleep(500);
            pid = find_process(target_wide);
            wait_count++;

            // Update spinner
            char spin_buf[64];
            snprintf(spin_buf, sizeof(spin_buf), "  %c Waiting... (%ds)\r",
                     spinner[spin % 4], wait_count / 2);
            con_print("%s", spin_buf);
            spin++;

            // Give up after 5 minutes
            if (wait_count > 600) {
                con_print("\n");
                con_fail("Timed out waiting for %s (5 min). Exiting.", game_display.c_str());
                wait_for_keypress();
                return 1;
            }
        }
        con_print("\n");
    }
    con_ok("%s found (PID: %lu)", game_display.c_str(), pid);

    // Check 3: Worker DLL exists
    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    char* slash = strrchr(exe_path, '\\');
    if (slash) *(slash + 1) = '\0';

    char dll_path[MAX_PATH];
    snprintf(dll_path, MAX_PATH, "%sdezlock-worker.dll", exe_path);

    if (GetFileAttributesA(dll_path) == INVALID_FILE_ATTRIBUTES) {
        con_fail("dezlock-worker.dll not found next to this exe.");
        con_info("Make sure both files are in the same folder:");
        con_info("  dezlock-dump.exe");
        con_info("  dezlock-worker.dll");
        wait_for_keypress();
        return 1;
    }
    con_ok("Worker DLL found");

    // ---- Injection ----
    con_step("2/5", "Preparing worker...");

    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);

    char json_path[MAX_PATH], done_path[MAX_PATH];
    snprintf(json_path, MAX_PATH, "%sdezlock-export.json", temp_dir);
    snprintf(done_path, MAX_PATH, "%sdezlock-done", temp_dir);
    DeleteFileA(done_path);
    DeleteFileA(json_path);

    {
        std::string step_msg = "Extracting schema from " + game_display + "...";
        con_step("3/5", step_msg.c_str());
    }
    con_info("This reads class layouts and field offsets from the game's memory.");
    con_info("%s will not be modified. This is read-only.", game_display.c_str());

    if (!inject_dll(pid, dll_path)) {
        con_fail("Could not connect to %s process.", game_display.c_str());
        con_info("Make sure the game is fully loaded (not still on splash screen).");
        con_info("If the problem persists, try restarting %s.", game_display.c_str());
        wait_for_keypress();
        return 1;
    }
    con_ok("Connected to %s", game_display.c_str());

    // ---- Wait for completion ----
    con_step("4/5", "Dumping schema data...");

    const char* spinner = "|/-\\";
    int waited = 0;
    int spin = 0;
    while (waited < timeout_sec * 10) {
        if (GetFileAttributesA(done_path) != INVALID_FILE_ATTRIBUTES)
            break;
        Sleep(100);
        waited++;

        // Spinner every 200ms
        if (waited % 2 == 0) {
            char spin_buf[64];
            snprintf(spin_buf, sizeof(spin_buf), "  %c Working... (%ds)\r",
                     spinner[spin % 4], waited / 10);
            con_print("%s", spin_buf);
            spin++;
        }
    }
    con_print("                              \r"); // clear spinner line

    if (GetFileAttributesA(done_path) == INVALID_FILE_ATTRIBUTES) {
        con_fail("Schema dump timed out after %ds.", timeout_sec);
        con_info("The game might not be fully loaded yet. Try again in a match.");

        char worker_log[MAX_PATH];
        snprintf(worker_log, MAX_PATH, "%sdezlock-worker.txt", temp_dir);
        con_info("Worker log: %s", worker_log);

        wait_for_keypress();
        return 1;
    }
    con_ok("Schema extracted (%.1fs)", waited / 10.0f);

    // ---- Generate output ----
    con_step("5/5", "Generating output files...");

    FILE* fp = fopen(json_path, "rb");
    if (!fp) {
        con_fail("Cannot read export data.");
        wait_for_keypress();
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    std::string json_str(fsize, '\0');
    fread(&json_str[0], 1, fsize, fp);
    fclose(fp);

    json data;
    try {
        data = json::parse(json_str);
    } catch (const std::exception& e) {
        con_fail("Failed to parse export data: %s", e.what());
        wait_for_keypress();
        return 1;
    }

    int total_classes = data.value("total_classes", data.value("class_count", 0));
    int total_enums = data.value("total_enums", data.value("enum_count", 0));
    int rtti_count = data.value("rtti_classes", 0);
    int total_static = data.value("total_static_fields", 0);

    auto modules = parse_modules(data);

    CreateDirectoryA(output_dir.c_str(), nullptr);

    for (auto& mod : modules) {
        std::string module_name = mod.name;
        {
            auto pos = module_name.rfind(".dll");
            if (pos != std::string::npos) module_name = module_name.substr(0, pos);
        }

        std::sort(mod.classes.begin(), mod.classes.end(),
                  [](const ClassInfo& a, const ClassInfo& b) { return a.name < b.name; });
        std::sort(mod.enums.begin(), mod.enums.end(),
                  [](const EnumInfo& a, const EnumInfo& b) { return a.name < b.name; });

        generate_text(mod.classes, data, output_dir, module_name);
        generate_flat(mod.classes, output_dir, module_name);
        generate_hierarchy(mod.classes, output_dir, module_name);
        generate_enums(mod.enums, output_dir, module_name);
        if (gen_headers) {
            generate_headers(mod.classes, mod.enums, output_dir, module_name);
        }

        con_ok("%-20s  %4d classes, %4d enums", mod.name.c_str(),
               (int)mod.classes.size(), (int)mod.enums.size());
    }

    std::string json_out = output_dir + "\\all-modules.json";
    CopyFileA(json_path, json_out.c_str(), FALSE);

    // ---- Signature generation (optional) ----
    int sig_unique = 0, sig_total = 0;
    if (gen_signatures) {
        con_print("\n");
        con_step("SIG", "Generating byte pattern signatures...");

        // Find Python
        char python[256] = {};
        if (!find_python(python, sizeof(python))) {
            con_fail("Python not found in PATH. Install Python 3.x to use --signatures.");
            con_info("You can still run manually: python generate-signatures.py --json %s",
                     json_out.c_str());
        } else {
            // Find generate-signatures.py: check next to exe, then parent dir
            char script_path[MAX_PATH];
            snprintf(script_path, MAX_PATH, "%sgenerate-signatures.py", exe_path);

            if (GetFileAttributesA(script_path) == INVALID_FILE_ATTRIBUTES) {
                // Try parent directory (exe in bin/, script in repo root)
                char parent_path[MAX_PATH];
                snprintf(parent_path, MAX_PATH, "%s..\\generate-signatures.py", exe_path);
                char resolved[MAX_PATH];
                if (GetFullPathNameA(parent_path, MAX_PATH, resolved, nullptr) > 0 &&
                    GetFileAttributesA(resolved) != INVALID_FILE_ATTRIBUTES) {
                    snprintf(script_path, MAX_PATH, "%s", resolved);
                }
            }

            if (GetFileAttributesA(script_path) == INVALID_FILE_ATTRIBUTES) {
                con_fail("generate-signatures.py not found.");
                con_info("Searched: %sgenerate-signatures.py", exe_path);
                con_info("Searched: %s..\\generate-signatures.py", exe_path);
            } else {
                std::string sig_output = output_dir + "\\signatures";
                char args[2048];
                snprintf(args, sizeof(args), "--json \"%s\" --output \"%s\"",
                         json_out.c_str(), sig_output.c_str());

                con_info("Running: %s %s %s", python, script_path, args);
                if (run_python_script(python, script_path, args)) {
                    con_ok("Signatures generated -> %s\\", sig_output.c_str());

                    // Try to read the summary JSON for stats
                    std::string sig_json = sig_output + "\\_all-signatures.json";
                    FILE* sfp = fopen(sig_json.c_str(), "rb");
                    if (sfp) {
                        fseek(sfp, 0, SEEK_END);
                        long ssize = ftell(sfp);
                        fseek(sfp, 0, SEEK_SET);
                        std::string sbuf(ssize, '\0');
                        fread(&sbuf[0], 1, ssize, sfp);
                        fclose(sfp);

                        try {
                            auto sdata = json::parse(sbuf);
                            if (sdata.contains("modules")) {
                                for (const auto& [mod_name, mod_sigs] : sdata["modules"].items()) {
                                    for (const auto& [cls_name, funcs] : mod_sigs.items()) {
                                        for (const auto& f : funcs) {
                                            sig_total++;
                                            if (f.value("unique", false)) sig_unique++;
                                        }
                                    }
                                }
                            }
                        } catch (...) {}
                    }
                } else {
                    con_fail("Signature generation failed. Check output above.");
                }
            }
        }
    }

    // Clean up temp files
    DeleteFileA(done_path);

    // ---- Summary ----
    con_print("\n");
    con_color(CLR_TITLE);
    con_print("  Done!\n\n");
    con_color(CLR_DEFAULT);

    con_print("  %-20s %d\n", "Modules:", (int)modules.size());
    con_print("  %-20s %d\n", "Classes:", total_classes);
    con_print("  %-20s %d\n", "Enums:", total_enums);
    con_print("  %-20s %d\n", "RTTI hierarchies:", rtti_count);
    con_print("  %-20s %d\n", "Static fields:", total_static);
    if (sig_total > 0) {
        con_print("  %-20s %d (%d unique)\n", "Signatures:", sig_total, sig_unique);
    }
    con_print("\n");

    con_color(CLR_OK);
    con_print("  Output: ");
    con_color(CLR_DEFAULT);
    con_print("%s\\\n\n", output_dir.c_str());

    con_color(CLR_DIM);
    con_print("  Quick start:\n");
    con_print("    grep m_iHealth %s\\client.txt\n", output_dir.c_str());
    con_print("    grep MNetworkEnable %s\\client.txt\n", output_dir.c_str());
    con_print("    grep EAbilitySlots %s\\client-enums.txt\n", output_dir.c_str());
    if (gen_signatures && sig_total > 0) {
        con_print("    grep CCitadelInput %s\\signatures\\client.txt\n", output_dir.c_str());
    }

    // Show tips for unused features
    std::vector<std::string> tips;
    if (!gen_headers) tips.push_back("--headers     Generate C++ SDK headers");
    if (!gen_signatures) tips.push_back("--signatures  Generate byte pattern signatures");
    if (!gen_all && (!gen_headers || !gen_signatures)) tips.push_back("--all         Enable all generators");

    if (!tips.empty()) {
        con_print("\n");
        con_print("  Tip: Run with additional flags for more output:\n");
        for (const auto& tip : tips) {
            con_print("    %s\n", tip.c_str());
        }
    }
    con_color(CLR_DEFAULT);

    if (g_log_fp) fclose(g_log_fp);

    wait_for_keypress();
    return 0;
}
