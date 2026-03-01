#include "src/output-generator.hpp"
#include "src/console.hpp"

#include <algorithm>
#include <unordered_set>
#include <cstdio>

using json = nlohmann::json;

// ============================================================================
// Unified field collector (replaces duplicated Collector/FlatCollector/FC)
// ============================================================================

struct FlatCollector {
    const std::unordered_map<std::string, const ClassInfo*>& local;
    const std::unordered_map<std::string, const ClassInfo*>& global;
    std::vector<Field> result;

    const ClassInfo* find(const std::string& name) {
        auto it = local.find(name);
        if (it != local.end()) return it->second;
        // Try C_ client equivalent in local before falling back to global
        if (name.size() > 1 && name[0] == 'C' && name[1] != '_') {
            std::string cn = "C_" + name.substr(1);
            it = local.find(cn);
            if (it != local.end()) return it->second;
        }
        it = global.find(name);
        return (it != global.end()) ? it->second : nullptr;
    }

    void collect(const std::string& name, std::unordered_set<std::string>& visited) {
        if (visited.count(name)) return;
        visited.insert(name);
        const auto* cls = find(name);
        if (!cls) return;
        visited.insert(cls->name);

        for (const auto& f : cls->fields) {
            Field ff = f;
            ff.defined_in = cls->name;
            result.push_back(ff);
        }
        if (!cls->parent.empty())
            collect(cls->parent, visited);
    }
};

// Single-lookup variant (when local == global)
static FlatCollector make_collector(
    const std::unordered_map<std::string, const ClassInfo*>& lookup) {
    return FlatCollector{lookup, lookup, {}};
}

// ============================================================================
// Unified tree writer (replaces duplicated TreeWriter/TW)
// ============================================================================

struct TreeWriter {
    FILE* fp;
    const std::unordered_map<std::string, const ClassInfo*>& lookup;
    int max_depth;

    bool is_ptr(const std::string& type) {
        std::string t = type;
        while (!t.empty() && t.back() == ' ') t.pop_back();
        return !t.empty() && t.back() == '*';
    }

    bool is_handle(const std::string& type) {
        return type.rfind("CHandle<", 0) == 0 || type.rfind("CHandle <", 0) == 0;
    }

    std::string extract_type(const std::string& type) {
        std::string t = type;
        while (!t.empty() && t.back() == '*') t.pop_back();
        while (!t.empty() && t.back() == ' ') t.pop_back();
        if (t.rfind("CHandle<", 0) == 0 || t.rfind("CHandle <", 0) == 0) {
            auto open = t.find('<');
            auto close = t.rfind('>');
            if (open != std::string::npos && close != std::string::npos) {
                std::string inner = t.substr(open + 1, close - open - 1);
                while (!inner.empty() && inner.front() == ' ') inner.erase(inner.begin());
                while (!inner.empty() && inner.back() == ' ') inner.pop_back();
                return inner;
            }
        }
        return t;
    }

    void write(const std::string& class_name, int depth,
               std::unordered_set<std::string>& expanded) {
        if (depth > max_depth) return;

        // Collect all fields (own + inherited)
        auto col = make_collector(lookup);
        std::unordered_set<std::string> visited;
        col.collect(class_name, visited);
        if (col.result.empty()) return;

        std::sort(col.result.begin(), col.result.end(),
                  [](const Field& a, const Field& b) { return a.offset < b.offset; });

        std::string indent(depth * 10, ' ');

        for (const auto& f : col.result) {
            std::string base_type = extract_type(f.type);
            bool expandable = lookup.count(base_type) > 0 &&
                              !expanded.count(base_type) &&
                              base_type != class_name;

            if (is_ptr(f.type)) {
                if (expandable) {
                    fprintf(fp, "%s  +0x%-4X %-30s -> %s\n",
                            indent.c_str(), f.offset, f.name.c_str(), f.type.c_str());
                    expanded.insert(base_type);
                    write(base_type, depth + 1, expanded);
                } else {
                    fprintf(fp, "%s  +0x%-4X %-30s (%s)\n",
                            indent.c_str(), f.offset, f.name.c_str(), f.type.c_str());
                }
            } else if (is_handle(f.type)) {
                fprintf(fp, "%s  +0x%-4X %-30s [handle -> %s]\n",
                        indent.c_str(), f.offset, f.name.c_str(), base_type.c_str());
            } else {
                bool is_embedded = lookup.count(f.type) > 0 &&
                                   !expanded.count(f.type) &&
                                   f.type != class_name;
                if (is_embedded) {
                    fprintf(fp, "%s  +0x%-4X %-30s [embedded %s, +0x%X]\n",
                            indent.c_str(), f.offset, f.name.c_str(),
                            f.type.c_str(), f.offset);
                    expanded.insert(f.type);
                    write(f.type, depth + 1, expanded);
                } else {
                    if (!f.defined_in.empty() && f.defined_in != class_name) {
                        fprintf(fp, "%s  +0x%-4X %-30s (%s, %s)\n",
                                indent.c_str(), f.offset, f.name.c_str(),
                                f.type.c_str(), f.defined_in.c_str());
                    } else {
                        fprintf(fp, "%s  +0x%-4X %-30s (%s)\n",
                                indent.c_str(), f.offset, f.name.c_str(),
                                f.type.c_str());
                    }
                }
            }
        }
    }
};

// ============================================================================
// Build a class lookup from all parsed modules
// ============================================================================

static std::unordered_map<std::string, const ClassInfo*>
build_class_lookup(const std::vector<ModuleData>& modules) {
    std::unordered_map<std::string, const ClassInfo*> lookup;
    for (const auto& mod : modules) {
        for (const auto& cls : mod.classes) {
            lookup[cls.name] = &cls;
        }
    }
    return lookup;
}

// ============================================================================
// parse_fields / parse_modules
// ============================================================================

std::vector<Field> parse_fields(const json& arr) {
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

// ============================================================================
// generate_module_txt
// ============================================================================

void generate_module_txt(const std::vector<ClassInfo>& classes,
                         const std::vector<EnumInfo>& enums,
                         const json& data,
                         const std::string& output_dir, const std::string& module_name,
                         const std::unordered_map<std::string, const ClassInfo*>& global_lookup) {
    std::string txt_path = output_dir + "\\" + module_name + ".txt";
    FILE* fp = fopen(txt_path.c_str(), "w");
    if (!fp) {
        printf("  ERROR: Cannot write %s\n", txt_path.c_str());
        return;
    }

    fprintf(fp, "# Dezlock Schema Dump - %s\n", module_name.c_str());
    fprintf(fp, "# Generated: %s\n", data.value("timestamp", "?").c_str());
    fprintf(fp, "#\n");
    fprintf(fp, "# Sections:\n");
    fprintf(fp, "#   CLASSES    - Each class with its own fields\n");
    fprintf(fp, "#   FLATTENED  - Full memory layout (own + inherited fields)\n");
    fprintf(fp, "#   ENUMS      - Enum definitions and values\n");
    fprintf(fp, "#\n\n");

    // ================================================================
    // Section 1: CLASSES (own fields only)
    // ================================================================
    fprintf(fp, "# ================================================================\n");
    fprintf(fp, "# CLASSES — own fields per class\n");
    fprintf(fp, "# Format: class_name.field_name = 0xOFFSET (type, size) [metadata...]\n");
    fprintf(fp, "# ================================================================\n\n");

    int total_fields = 0;
    for (const auto& cls : classes) {
        fprintf(fp, "# --- %s (size=0x%X", cls.name.c_str(), cls.size);
        if (!cls.parent.empty()) fprintf(fp, ", parent=%s", cls.parent.c_str());
        fprintf(fp, ")\n");

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

    // ================================================================
    // Section 2: FLATTENED (all inherited fields, sorted by offset)
    // ================================================================
    fprintf(fp, "\n# ================================================================\n");
    fprintf(fp, "# FLATTENED — full memory layout (own + inherited fields)\n");
    fprintf(fp, "# Format: class_name.field_name = 0xOFFSET (type, size, defined_in)\n");
    fprintf(fp, "# ================================================================\n\n");

    // Build lookup
    std::unordered_map<std::string, const ClassInfo*> by_name;
    for (const auto& c : classes) by_name[c.name] = &c;

    for (const auto& cls : classes) {
        if (cls.inheritance.size() < 3) continue;

        FlatCollector col{by_name, global_lookup, {}};
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

    // ================================================================
    // Section 3: ENUMS
    // ================================================================
    fprintf(fp, "\n# ================================================================\n");
    fprintf(fp, "# ENUMS — %d enum definitions\n", (int)enums.size());
    fprintf(fp, "# Format: enum_name::VALUE_NAME = value\n");
    fprintf(fp, "# ================================================================\n\n");

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
    printf("  -> %s (%d classes, %d fields, %d enums)\n",
           txt_path.c_str(), (int)classes.size(), total_fields, (int)enums.size());
}

// ============================================================================
// generate_hierarchy
// ============================================================================

void generate_hierarchy(const std::vector<ClassInfo>& classes,
                        const std::string& output_dir, const std::string& module_name,
                        const std::unordered_map<std::string, const ClassInfo*>& global_lookup) {
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
    create_directory_recursive(hier_dir.c_str());

    // Helper: find the topmost schema-known ancestor for categorization
    auto get_category = [&by_name](const std::vector<std::string>& chain,
                                    const std::string& self_name) -> std::string {
        for (int i = (int)chain.size() - 1; i >= 1; i--) {
            if (by_name.count(chain[i])) return chain[i];
        }
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
            create_directory_recursive(cat_dir.c_str());
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
            FlatCollector col{by_name, global_lookup, {}};
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
// generate_globals_txt
// ============================================================================

void generate_globals_txt(const json& data,
                          const std::vector<ModuleData>& modules,
                          const std::string& output_dir,
                          int field_depth) {
    if (!data.contains("globals")) return;

    auto all_classes = build_class_lookup(modules);

    int total_written = 0;
    int schema_expanded = 0;

    std::string globals_path = output_dir + "\\_globals.txt";
    FILE* gfp = fopen(globals_path.c_str(), "w");
    if (!gfp) return;

    fprintf(gfp, "# Dezlock Global Singleton Access Guide\n");
    fprintf(gfp, "# Auto-discovered by scanning .data sections against RTTI vtable catalog\n");
    fprintf(gfp, "#\n");
    fprintf(gfp, "# [schema] globals are expanded with full field trees:\n");
    fprintf(gfp, "#   ->  pointer dereference (follow pointer, then read sub-fields)\n");
    fprintf(gfp, "#   [embedded X, +0xN]  struct is inline at that offset (add offsets)\n");
    fprintf(gfp, "#   [handle -> X]  CHandle entity reference (resolve via entity list)\n");
    fprintf(gfp, "#   (type, DefinedIn)  shows which parent class defines the field\n");
    fprintf(gfp, "#\n\n");

    for (const auto& [mod_name, mod_globals] : data["globals"].items()) {
        if (!mod_globals.is_array() || mod_globals.empty()) continue;

        int mod_schema = 0;
        for (const auto& g : mod_globals) {
            if (g.value("has_schema", false)) mod_schema++;
        }
        fprintf(gfp, "# ================================================================\n");
        fprintf(gfp, "# %s (%d globals, %d with schema)\n", mod_name.c_str(),
                (int)mod_globals.size(), mod_schema);
        fprintf(gfp, "# ================================================================\n\n");

        // Pass 1: Schema globals with field expansion
        for (const auto& g : mod_globals) {
            if (!g.value("has_schema", false)) continue;

            std::string cls_name = g.value("class", "?");
            std::string rva = g.value("rva", "?");
            std::string type = g.value("type", "?");

            fprintf(gfp, "# %s @ %s+%s (%s) [schema]\n",
                    cls_name.c_str(), mod_name.c_str(), rva.c_str(), type.c_str());

            auto cit = all_classes.find(cls_name);
            if (cit != all_classes.end() && !cit->second->inheritance.empty()) {
                fprintf(gfp, "# chain:");
                for (size_t i = 0; i < cit->second->inheritance.size(); i++) {
                    fprintf(gfp, "%s%s", i ? " -> " : " ",
                            cit->second->inheritance[i].c_str());
                }
                fprintf(gfp, "\n");
            }

            if (cit != all_classes.end()) {
                TreeWriter tw{gfp, all_classes, field_depth};
                std::unordered_set<std::string> expanded;
                expanded.insert(cls_name);
                tw.write(cls_name, 0, expanded);
                schema_expanded++;
            }

            fprintf(gfp, "\n");
            total_written++;
        }

        // Pass 2: Non-schema globals (simple listing)
        bool has_non_schema = false;
        for (const auto& g : mod_globals) {
            if (g.value("has_schema", false)) continue;
            if (!has_non_schema) {
                fprintf(gfp, "# --- other globals (no schema fields) ---\n");
                has_non_schema = true;
            }
            fprintf(gfp, "%s::%s = %s (%s)\n",
                    mod_name.c_str(),
                    g.value("class", "?").c_str(),
                    g.value("rva", "?").c_str(),
                    g.value("type", "?").c_str());
            total_written++;
        }
        if (has_non_schema) fprintf(gfp, "\n");
    }

    // Pattern globals section
    if (data.contains("pattern_globals")) {
        fprintf(gfp, "# ================================================================\n");
        fprintf(gfp, "# Pattern-scanned globals (from patterns.json)\n");
        fprintf(gfp, "# ================================================================\n\n");
        for (const auto& [mod_name, mod_pats] : data["pattern_globals"].items()) {
            if (!mod_pats.is_object()) continue;
            for (const auto& [name, val] : mod_pats.items()) {
                std::string rva_str;
                if (val.is_object() && val.contains("rva"))
                    rva_str = val["rva"].get<std::string>();
                else if (val.is_string())
                    rva_str = val.get<std::string>();
                else
                    continue;
                fprintf(gfp, "%s::%s = %s (pattern)\n",
                        mod_name.c_str(), name.c_str(),
                        rva_str.c_str());
                total_written++;
            }
        }
        fprintf(gfp, "\n");
    }

    fclose(gfp);
    printf("  -> %s (%d entries, %d expanded with field trees)\n",
           globals_path.c_str(), total_written, schema_expanded);

    // Generate access-paths if there are schema globals
    if (schema_expanded > 0) {
        generate_access_paths(data, modules, output_dir);
    }
}

// ============================================================================
// generate_access_paths
// ============================================================================

void generate_access_paths(const json& data,
                           const std::vector<ModuleData>& modules,
                           const std::string& output_dir) {
    if (!data.contains("globals")) return;

    auto all_classes = build_class_lookup(modules);

    std::string ap_path = output_dir + "\\_access-paths.txt";
    FILE* apfp = fopen(ap_path.c_str(), "w");
    if (!apfp) return;

    fprintf(apfp, "# Dezlock Access Paths — Schema Global Offset Guide\n");
    fprintf(apfp, "# Only globals with known schema classes, fully expanded.\n");
    fprintf(apfp, "#\n");
    fprintf(apfp, "# Legend:\n");
    fprintf(apfp, "#   ->  pointer dereference (follow pointer, then read field)\n");
    fprintf(apfp, "#   [embedded X, +0xN]  inline struct at that offset (add offsets)\n");
    fprintf(apfp, "#   [handle -> X]  CHandle entity reference (resolve via entity list)\n");
    fprintf(apfp, "#   (type, ClassName)  which parent class defines the field\n");
    fprintf(apfp, "#\n");
    fprintf(apfp, "# Quick grep examples:\n");
    fprintf(apfp, "#   grep m_iHealth access-paths.txt\n");
    fprintf(apfp, "#   grep m_vecAbsOrigin access-paths.txt\n");
    fprintf(apfp, "#   grep \"CGameSceneNode\" access-paths.txt\n");
    fprintf(apfp, "#\n\n");

    int ap_count = 0;
    for (const auto& [mod_name, mod_globals] : data["globals"].items()) {
        if (!mod_globals.is_array()) continue;

        bool has_schema = false;
        for (const auto& g : mod_globals) {
            if (!g.value("has_schema", false)) continue;

            if (!has_schema) {
                fprintf(apfp, "# ================================================================\n");
                fprintf(apfp, "# %s\n", mod_name.c_str());
                fprintf(apfp, "# ================================================================\n\n");
                has_schema = true;
            }

            std::string cls_name = g.value("class", "?");
            std::string rva = g.value("rva", "?");
            std::string type = g.value("type", "?");

            fprintf(apfp, "# %s @ %s+%s (%s)\n",
                    cls_name.c_str(), mod_name.c_str(), rva.c_str(), type.c_str());

            auto cit = all_classes.find(cls_name);
            if (cit != all_classes.end() && !cit->second->inheritance.empty()) {
                fprintf(apfp, "# chain:");
                for (size_t i = 0; i < cit->second->inheritance.size(); i++) {
                    fprintf(apfp, "%s%s", i ? " -> " : " ",
                            cit->second->inheritance[i].c_str());
                }
                fprintf(apfp, "\n");
            }

            if (cit != all_classes.end()) {
                TreeWriter tw{apfp, all_classes, 2};
                std::unordered_set<std::string> expanded;
                expanded.insert(cls_name);
                tw.write(cls_name, 0, expanded);
            }

            fprintf(apfp, "\n");
            ap_count++;
        }
    }

    fclose(apfp);
    printf("  -> %s (%d schema globals with full field trees)\n",
           ap_path.c_str(), ap_count);
}

// ============================================================================
// generate_entity_paths
// ============================================================================

void generate_entity_paths(const json& data,
                           const std::vector<ModuleData>& modules,
                           const std::string& output_dir,
                           int field_depth) {
    // Collect entity classes grouped by module
    struct EntityClass {
        std::string module_name;
        const ClassInfo* cls;
    };
    std::vector<EntityClass> entity_classes;

    for (const auto& mod : modules) {
        for (const auto& cls : mod.classes) {
            for (const auto& parent : cls.inheritance) {
                if (parent == "CEntityInstance" || parent == "C_BaseEntity" ||
                    parent == "CBaseEntity" || parent == "CBasePlayerPawn" ||
                    parent == "C_BasePlayerPawn") {
                    entity_classes.push_back({mod.name, &cls});
                    break;
                }
            }
        }
    }

    if (entity_classes.empty()) return;

    auto ent_lookup = build_class_lookup(modules);

    std::string ep_path = output_dir + "\\_entity-paths.txt";
    FILE* epfp = fopen(ep_path.c_str(), "w");
    if (!epfp) return;

    fprintf(epfp, "# Dezlock Entity Paths — Full Field Trees for Entity Classes\n");
    fprintf(epfp, "# Every class inheriting CEntityInstance / C_BaseEntity, fully expanded.\n");
    fprintf(epfp, "#\n");
    fprintf(epfp, "# Legend:\n");
    fprintf(epfp, "#   ->  pointer dereference (follow pointer, then read field)\n");
    fprintf(epfp, "#   [embedded X, +0xN]  inline struct at that offset (add offsets)\n");
    fprintf(epfp, "#   [handle -> X]  CHandle entity reference (resolve via entity list)\n");
    fprintf(epfp, "#   (type, ClassName)  which parent class defines the field\n");
    fprintf(epfp, "#\n");
    fprintf(epfp, "# Example: grep C_CitadelPlayerPawn _entity-paths.txt\n");
    fprintf(epfp, "#          grep m_iHealth _entity-paths.txt\n");
    fprintf(epfp, "#          grep m_vecAbilities _entity-paths.txt\n");
    fprintf(epfp, "#\n\n");

    // Sort by module then class name
    std::sort(entity_classes.begin(), entity_classes.end(),
        [](const EntityClass& a, const EntityClass& b) {
            if (a.module_name != b.module_name) return a.module_name < b.module_name;
            return a.cls->name < b.cls->name;
        });

    std::string cur_module;
    int ep_count = 0;

    for (const auto& ec : entity_classes) {
        if (ec.module_name != cur_module) {
            cur_module = ec.module_name;
            fprintf(epfp, "# ================================================================\n");
            fprintf(epfp, "# %s\n", cur_module.c_str());
            fprintf(epfp, "# ================================================================\n\n");
        }

        const auto* cls = ec.cls;
        fprintf(epfp, "# %s (size=0x%X)\n", cls->name.c_str(), cls->size);

        if (!cls->inheritance.empty()) {
            fprintf(epfp, "# chain:");
            for (size_t i = 0; i < cls->inheritance.size(); i++) {
                fprintf(epfp, "%s%s", i ? " -> " : " ",
                        cls->inheritance[i].c_str());
            }
            fprintf(epfp, "\n");
        }

        TreeWriter tw{epfp, ent_lookup, field_depth};
        std::unordered_set<std::string> expanded;
        expanded.insert(cls->name);
        tw.write(cls->name, 0, expanded);
        fprintf(epfp, "\n");
        ep_count++;
    }

    fclose(epfp);
    printf("  -> %s (%d entity classes with full field trees)\n",
           ep_path.c_str(), ep_count);
}

// ============================================================================
// generate_protobuf_output
// ============================================================================

void generate_protobuf_output(const json& data,
                              const std::string& output_dir) {
    if (!data.contains("protobuf_messages")) return;

    std::string pb_path = output_dir + "\\_protobuf-messages.txt";
    FILE* pbfp = fopen(pb_path.c_str(), "w");
    if (!pbfp) return;

    fprintf(pbfp, "# Protobuf Message Definitions (decoded from embedded descriptors)\n");
    fprintf(pbfp, "# Generated by dezlock-dump\n\n");

    int total_files = 0, total_msgs = 0;

    for (const auto& [mod_name, mod_data] : data["protobuf_messages"].items()) {
        if (!mod_data.contains("files")) continue;

        for (const auto& pf : mod_data["files"]) {
            std::string fname = pf.value("name", "");
            std::string pkg = pf.value("package", "");
            std::string syntax = pf.value("syntax", "");

            fprintf(pbfp, "// ============================================================\n");
            fprintf(pbfp, "// File: %s  (module: %s)\n", fname.c_str(), mod_name.c_str());
            fprintf(pbfp, "// ============================================================\n");
            if (!syntax.empty())
                fprintf(pbfp, "syntax = \"%s\";\n", syntax.c_str());
            if (!pkg.empty())
                fprintf(pbfp, "package %s;\n", pkg.c_str());
            fprintf(pbfp, "\n");

            // Helper lambda for writing messages recursively
            struct MsgWriter {
                FILE* fp;
                void write(const nlohmann::json& msg, int indent) {
                    std::string pad(indent, ' ');
                    std::string name = msg.value("name", "?");

                    fprintf(fp, "%smessage %s {\n", pad.c_str(), name.c_str());

                    // Oneof decls
                    std::vector<std::string> oneofs;
                    if (msg.contains("oneof_decls")) {
                        for (const auto& od : msg["oneof_decls"])
                            oneofs.push_back(od.get<std::string>());
                    }

                    // Nested enums
                    if (msg.contains("nested_enums")) {
                        for (const auto& e : msg["nested_enums"]) {
                            fprintf(fp, "%s  enum %s {\n", pad.c_str(), e.value("name", "?").c_str());
                            if (e.contains("values")) {
                                for (const auto& v : e["values"]) {
                                    fprintf(fp, "%s    %s = %d;\n", pad.c_str(),
                                            v.value("name", "?").c_str(),
                                            v.value("number", 0));
                                }
                            }
                            fprintf(fp, "%s  }\n\n", pad.c_str());
                        }
                    }

                    // Nested messages
                    if (msg.contains("nested_messages")) {
                        for (const auto& nm : msg["nested_messages"]) {
                            write(nm, indent + 2);
                            fprintf(fp, "\n");
                        }
                    }

                    // Group fields by oneof
                    std::unordered_map<int, std::vector<const nlohmann::json*>> oneof_fields;
                    std::vector<const nlohmann::json*> regular_fields;

                    if (msg.contains("fields")) {
                        for (const auto& f : msg["fields"]) {
                            int oi = f.value("oneof_index", -1);
                            if (oi >= 0)
                                oneof_fields[oi].push_back(&f);
                            else
                                regular_fields.push_back(&f);
                        }
                    }

                    // Write regular fields
                    for (const auto* fp2 : regular_fields) {
                        const auto& f = *fp2;
                        std::string label = f.value("label", "optional");
                        std::string type = f.value("type", "unknown");
                        std::string type_name = f.value("type_name", "");
                        std::string fname2 = f.value("name", "?");
                        int number = f.value("number", 0);

                        std::string display_type = type_name.empty() ? type : type_name;
                        if (!display_type.empty() && display_type[0] == '.')
                            display_type = display_type.substr(1);

                        fprintf(fp, "%s  %s %s %s = %d;\n", pad.c_str(),
                                label.c_str(), display_type.c_str(),
                                fname2.c_str(), number);
                    }

                    // Write oneof groups
                    for (const auto& [oi, fields] : oneof_fields) {
                        std::string oneof_name = (oi < (int)oneofs.size()) ? oneofs[oi] : "unknown_oneof";
                        fprintf(fp, "%s  oneof %s {\n", pad.c_str(), oneof_name.c_str());
                        for (const auto* fp2 : fields) {
                            const auto& f = *fp2;
                            std::string type = f.value("type", "unknown");
                            std::string type_name = f.value("type_name", "");
                            std::string fname2 = f.value("name", "?");
                            int number = f.value("number", 0);
                            std::string display_type = type_name.empty() ? type : type_name;
                            if (!display_type.empty() && display_type[0] == '.')
                                display_type = display_type.substr(1);
                            fprintf(fp, "%s    %s %s = %d;\n", pad.c_str(),
                                    display_type.c_str(), fname2.c_str(), number);
                        }
                        fprintf(fp, "%s  }\n", pad.c_str());
                    }

                    fprintf(fp, "%s}\n", pad.c_str());
                }
            };

            MsgWriter mw{pbfp};

            // Top-level enums
            if (pf.contains("enums")) {
                for (const auto& e : pf["enums"]) {
                    fprintf(pbfp, "enum %s {\n", e.value("name", "?").c_str());
                    if (e.contains("values")) {
                        for (const auto& v : e["values"]) {
                            fprintf(pbfp, "  %s = %d;\n",
                                    v.value("name", "?").c_str(),
                                    v.value("number", 0));
                        }
                    }
                    fprintf(pbfp, "}\n\n");
                }
            }

            // Top-level messages
            if (pf.contains("messages")) {
                for (const auto& msg : pf["messages"]) {
                    mw.write(msg, 0);
                    fprintf(pbfp, "\n");
                    total_msgs++;
                }
            }

            total_files++;
        }
    }

    fclose(pbfp);
    printf("  -> %s (%d files, %d messages)\n", pb_path.c_str(), total_files, total_msgs);
}
