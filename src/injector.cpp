#include "src/injector.hpp"
#include "src/console.hpp"

#include <TlHelp32.h>
#include <cstdio>
#include <vector>

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
