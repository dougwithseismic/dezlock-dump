/**
 * Dezlock Dump — Standalone Schema Extraction Tool
 *
 * Usage: dezlock-dump.exe [--output <dir>] [--wait <seconds>]
 *
 * 1. Finds Deadlock process
 * 2. Injects dezlock-worker.dll via CreateRemoteThread
 * 3. Waits for the worker to finish (writes JSON to %TEMP%)
 * 4. Reads JSON and generates output files:
 *    - schema-dump/client.txt      (greppable text)
 *    - schema-dump/client-flat.txt (flattened with inherited fields)
 *    - schema-dump/client.json     (full JSON)
 *
 * Requires: admin elevation (for process injection)
 * Requires: Deadlock must be running
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

// ============================================================================
// DLL Injection via CreateRemoteThread + LoadLibraryA
// ============================================================================

bool inject_dll(DWORD pid, const char* dll_path) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        printf("  ERROR: OpenProcess failed (err=%lu). Run as admin?\n", GetLastError());
        return false;
    }

    size_t path_len = strlen(dll_path) + 1;
    void* remote_buf = VirtualAllocEx(hProcess, nullptr, path_len,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) {
        printf("  ERROR: VirtualAllocEx failed (err=%lu)\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remote_buf, dll_path, path_len, nullptr)) {
        printf("  ERROR: WriteProcessMemory failed (err=%lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    auto pLoadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(kernel32, "LoadLibraryA"));

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                         pLoadLibrary, remote_buf, 0, nullptr);
    if (!hThread) {
        printf("  ERROR: CreateRemoteThread failed (err=%lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 10000);

    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return exit_code != 0;  // LoadLibraryA returns module handle (nonzero = success)
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
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    ensure_console();

    // Set console title
    SetConsoleTitleA("dezlock-dump - Deadlock Schema Extractor");

    con_print("\n");
    con_color(CLR_TITLE);
    con_print("  dezlock-dump");
    con_color(CLR_DIM);
    con_print("  v1.0.0\n");
    con_color(CLR_DEFAULT);
    con_print("  Runtime schema + RTTI extraction for Deadlock (Source 2)\n");
    con_color(CLR_DIM);
    con_print("  https://github.com/dougwithseismic/dezlock-dump\n");
    con_color(CLR_DEFAULT);
    con_print("\n");

    // Parse args
    std::string output_dir;
    int timeout_sec = 30;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "--wait") == 0 && i + 1 < argc) {
            timeout_sec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            con_print("Usage: dezlock-dump.exe [--output <dir>] [--wait <seconds>]\n\n");
            con_print("  --output  Output directory (default: schema-dump/ next to exe)\n");
            con_print("  --wait    Max wait time for worker DLL (default: 30s)\n");
            wait_for_keypress();
            return 0;
        }
    }

    // Default output dir: schema-dump/ next to the exe
    if (output_dir.empty()) {
        char exe_dir[MAX_PATH];
        GetModuleFileNameA(GetModuleHandleA(nullptr), exe_dir, MAX_PATH);
        char full_path[MAX_PATH];
        GetFullPathNameA(exe_dir, MAX_PATH, full_path, nullptr);
        char* last_slash = strrchr(full_path, '\\');
        if (last_slash) *(last_slash + 1) = '\0';
        output_dir = std::string(full_path) + "schema-dump";
    }

    // ---- Pre-flight checks ----

    // Check 1: Admin privileges
    con_step("1/5", "Checking prerequisites...");

    if (!is_elevated()) {
        con_fail("Not running as administrator.");
        con_print("\n");
        con_color(CLR_WARN);
        con_print("  This tool needs admin privileges to read Deadlock's memory.\n");
        con_print("  Right-click dezlock-dump.exe -> Run as administrator\n");
        con_color(CLR_DEFAULT);
        wait_for_keypress();
        return 1;
    }
    con_ok("Running as administrator");

    // Check 2: Deadlock is running
    DWORD pid = find_process(L"deadlock.exe");
    if (!pid) {
        con_fail("Deadlock is not running.");
        con_print("\n");
        con_color(CLR_WARN);
        con_print("  Please launch Deadlock first, then run this tool.\n");
        con_print("  The game needs to be fully loaded (main menu or in a match).\n");
        con_color(CLR_DEFAULT);
        con_print("\n");
        con_info("Waiting for Deadlock to start...");

        // Wait for deadlock with a spinner
        const char* spinner = "|/-\\";
        int spin = 0;
        int wait_count = 0;
        while (!pid) {
            Sleep(500);
            pid = find_process(L"deadlock.exe");
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
                con_fail("Timed out waiting for Deadlock (5 min). Exiting.");
                wait_for_keypress();
                return 1;
            }
        }
        con_print("\n");
    }
    con_ok("Deadlock found (PID: %lu)", pid);

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

    char inject_path[MAX_PATH];
    snprintf(inject_path, MAX_PATH, "%sdezlock-worker-%lu.dll", temp_dir, GetTickCount());
    CopyFileA(dll_path, inject_path, FALSE);

    char json_path[MAX_PATH], done_path[MAX_PATH];
    snprintf(json_path, MAX_PATH, "%sdezlock-export.json", temp_dir);
    snprintf(done_path, MAX_PATH, "%sdezlock-done", temp_dir);
    DeleteFileA(done_path);
    DeleteFileA(json_path);

    con_step("3/5", "Extracting schema from Deadlock...");
    con_info("This reads class layouts and field offsets from the game's memory.");
    con_info("Deadlock will not be modified. This is read-only.");

    if (!inject_dll(pid, inject_path)) {
        con_fail("Could not connect to Deadlock process.");
        con_info("Make sure the game is fully loaded (not still on splash screen).");
        con_info("If the problem persists, try restarting Deadlock.");
        wait_for_keypress();
        return 1;
    }
    con_ok("Connected to Deadlock");

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

        con_ok("%-20s  %4d classes, %4d enums", mod.name.c_str(),
               (int)mod.classes.size(), (int)mod.enums.size());
    }

    std::string json_out = output_dir + "\\all-modules.json";
    CopyFileA(json_path, json_out.c_str(), FALSE);

    // Clean up temp files
    DeleteFileA(done_path);
    DeleteFileA(inject_path);

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
    con_color(CLR_DEFAULT);

    if (g_log_fp) fclose(g_log_fp);

    wait_for_keypress();
    return 0;
}
