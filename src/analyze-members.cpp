/**
 * dezlock-dump — Vtable Member Offset Analyzer
 *
 * Decodes 128-byte vtable function prologues to extract this-pointer
 * member access patterns. Targeted x86-64 instruction decoder — NOT a
 * full disassembler. Focuses on recognizing [reg+disp] memory operands
 * where reg holds `this` (RCX on Win64 entry, or aliased copies).
 *
 * Multi-threaded per-module using same thread pool pattern as generate-signatures.
 */

#include "analyze-members.hpp"

#include <atomic>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using json = nlohmann::json;

namespace {

// ============================================================================
// Types
// ============================================================================

enum class AccessType : uint8_t {
    Read    = 0x01,
    Write   = 0x02,
    Float   = 0x04,
    Ref     = 0x08,  // LEA — address-of
    Compare = 0x10,
};

struct MemberAccess {
    uint32_t offset = 0;
    uint8_t  size = 0;        // 1, 2, 4, 8, 16
    uint8_t  access_mask = 0; // bitmask of AccessType
    int      func_index = -1; // vtable function index
};

struct ClassLayout {
    std::string class_name;
    int vtable_size = 0;   // total vtable entries
    int analyzed = 0;       // functions successfully analyzed

    // Deduplicated: offset -> merged access info
    struct FieldInfo {
        uint32_t offset = 0;
        uint8_t  max_size = 0;
        uint8_t  access_mask = 0;
        std::vector<int> func_indices; // which vtable functions access this
    };
    std::vector<FieldInfo> fields;
};

// ============================================================================
// Stub detection (reuse logic from generate-signatures)
// ============================================================================

static bool is_stub(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return true;
    if (bytes[0] == 0xC3) return true;  // ret
    if (bytes[0] == 0xCC) return true;  // int3
    if (bytes.size() >= 3) {
        // xor eax, eax; ret
        if (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3) return true;
        // xor al, al; ret
        if (bytes[0] == 0x32 && bytes[1] == 0xC0 && bytes[2] == 0xC3) return true;
        // mov al, 0; ret
        if (bytes[0] == 0xB0 && bytes[2] == 0xC3) return true;
    }
    if (bytes.size() >= 4 && bytes[0] == 0x0F && bytes[1] == 0x57 && bytes[2] == 0xC0 && bytes[3] == 0xC3)
        return true; // xorps xmm0, xmm0; ret
    if (bytes.size() >= 6 && bytes[0] == 0xB8 && bytes[5] == 0xC3)
        return true; // mov eax, imm32; ret
    if (bytes.size() >= 8 && bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x05 && bytes[7] == 0xC3)
        return true; // lea rax, [rip+disp32]; ret

    return false;
}

// ============================================================================
// x86-64 targeted instruction decoder for [this+offset] accesses
// ============================================================================

// Register indices (matching x86-64 encoding order)
enum Reg : uint8_t {
    RAX = 0, RCX = 1, RDX = 2, RBX = 3,
    RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    R8  = 8, R9  = 9, R10 = 10, R11 = 11,
    R12 = 12, R13 = 13, R14 = 14, R15 = 15,
    REG_NONE = 0xFF
};

// Track which registers hold `this` (RCX at entry for Win64 __thiscall)
struct RegState {
    bool is_this[16] = {};

    RegState() {
        is_this[RCX] = true; // Win64: this in RCX
    }

    void set_this(uint8_t reg) { if (reg < 16) is_this[reg] = true; }
    void clear(uint8_t reg) { if (reg < 16) is_this[reg] = false; }
    bool has_this(uint8_t reg) const { return reg < 16 && is_this[reg]; }

    // After CALL, RCX/RDX/R8-R11 are caller-saved (destroyed)
    void invalidate_caller_saved() {
        is_this[RAX] = false;
        is_this[RCX] = false;
        is_this[RDX] = false;
        is_this[R8]  = false;
        is_this[R9]  = false;
        is_this[R10] = false;
        is_this[R11] = false;
    }
};

// Decode one function's bytes and extract member accesses
static std::vector<MemberAccess> decode_function(const std::vector<uint8_t>& bytes, int func_index) {
    std::vector<MemberAccess> accesses;
    RegState regs;
    size_t pos = 0;
    size_t len = bytes.size();

    while (pos < len) {
        size_t insn_start = pos;

        // Skip prefixes (66h, F2h, F3h, 67h)
        uint8_t prefix_66 = 0, prefix_f2 = 0, prefix_f3 = 0;
        while (pos < len) {
            if (bytes[pos] == 0x66) { prefix_66 = 1; pos++; }
            else if (bytes[pos] == 0xF2) { prefix_f2 = 1; pos++; }
            else if (bytes[pos] == 0xF3) { prefix_f3 = 1; pos++; }
            else if (bytes[pos] == 0x67) { pos++; }
            else break;
        }
        if (pos >= len) break;

        // Parse REX prefix
        uint8_t rex = 0, rex_w = 0, rex_r = 0, rex_b = 0;
        if ((bytes[pos] & 0xF0) == 0x40) {
            rex = bytes[pos];
            rex_w = (rex >> 3) & 1;
            rex_r = (rex >> 2) & 1;
            rex_b = rex & 1;
            pos++;
        }
        if (pos >= len) break;

        uint8_t opcode = bytes[pos++];

        // ---- Termination instructions ----
        if (opcode == 0xC3 || opcode == 0xCB) break; // ret
        if (opcode == 0xCC) break; // int3

        // Unconditional JMP (near/short)
        if (opcode == 0xE9) break; // jmp rel32
        if (opcode == 0xEB) break; // jmp rel8

        // ---- CALL — invalidate caller-saved, skip operand ----
        if (opcode == 0xE8) {
            // call rel32
            pos += 4;
            regs.invalidate_caller_saved();
            continue;
        }

        // ---- Two-byte opcode (0F xx) ----
        if (opcode == 0x0F) {
            if (pos >= len) break;
            uint8_t op2 = bytes[pos++];

            // Jcc rel32 — skip displacement, don't terminate
            if (op2 >= 0x80 && op2 <= 0x8F) {
                pos += 4;
                continue;
            }

            // MOVSS/MOVSD/MOVUPS/MOVAPS/MOVDQA with ModRM
            bool is_float_mov = false;
            bool is_float_write = false;

            // MOVSS: F3 0F 10 (load) / F3 0F 11 (store)
            // MOVSD: F2 0F 10 (load) / F2 0F 11 (store)
            if ((prefix_f3 || prefix_f2) && (op2 == 0x10 || op2 == 0x11)) {
                is_float_mov = true;
                is_float_write = (op2 == 0x11);
            }
            // MOVUPS: 0F 10 (load) / 0F 11 (store)
            // MOVAPS: 0F 28 (load) / 0F 29 (store)
            else if (op2 == 0x10 || op2 == 0x11 || op2 == 0x28 || op2 == 0x29) {
                is_float_mov = true;
                is_float_write = (op2 == 0x11 || op2 == 0x29);
            }
            // MOVDQA: 66 0F 6F (load) / 66 0F 7F (store)
            else if (prefix_66 && (op2 == 0x6F || op2 == 0x7F)) {
                is_float_mov = true;
                is_float_write = (op2 == 0x7F);
            }
            // COMISS/UCOMISS: 0F 2E / 0F 2F
            else if (op2 == 0x2E || op2 == 0x2F) {
                is_float_mov = true; // treat as float read for access tracking
            }

            if (is_float_mov && pos < len) {
                uint8_t modrm = bytes[pos++];
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = (modrm & 7) | (rex_b << 3);

                // Handle SIB byte
                if ((modrm & 7) == 4 && mod != 3) {
                    if (pos >= len) break;
                    uint8_t sib = bytes[pos++];
                    // SIB base register
                    rm = (sib & 7) | (rex_b << 3);
                }

                if (mod == 1 && regs.has_this(rm)) {
                    // [this+disp8]
                    if (pos >= len) break;
                    int8_t disp = static_cast<int8_t>(bytes[pos++]);
                    if (disp > 0 && disp < 0x4000) {
                        uint8_t sz = 4; // default float size
                        if (prefix_f2) sz = 8; // MOVSD = double
                        if (op2 == 0x10 || op2 == 0x11) {
                            if (!prefix_f3 && !prefix_f2) sz = 16; // MOVUPS
                        }
                        if (op2 == 0x28 || op2 == 0x29) sz = 16; // MOVAPS
                        if (op2 == 0x6F || op2 == 0x7F) sz = 16; // MOVDQA

                        MemberAccess ma;
                        ma.offset = static_cast<uint32_t>(disp);
                        ma.size = sz;
                        ma.access_mask = static_cast<uint8_t>(AccessType::Float);
                        if (is_float_write) ma.access_mask |= static_cast<uint8_t>(AccessType::Write);
                        else ma.access_mask |= static_cast<uint8_t>(AccessType::Read);
                        ma.func_index = func_index;
                        accesses.push_back(ma);
                    }
                    continue;
                } else if (mod == 2 && regs.has_this(rm)) {
                    // [this+disp32]
                    if (pos + 4 > len) break;
                    int32_t disp = 0;
                    memcpy(&disp, &bytes[pos], 4);
                    pos += 4;
                    if (disp > 0 && disp < 0x4000) {
                        uint8_t sz = 4;
                        if (prefix_f2) sz = 8;
                        if (!prefix_f3 && !prefix_f2 && (op2 == 0x10 || op2 == 0x11)) sz = 16;
                        if (op2 == 0x28 || op2 == 0x29) sz = 16;

                        MemberAccess ma;
                        ma.offset = static_cast<uint32_t>(disp);
                        ma.size = sz;
                        ma.access_mask = static_cast<uint8_t>(AccessType::Float);
                        if (is_float_write) ma.access_mask |= static_cast<uint8_t>(AccessType::Write);
                        else ma.access_mask |= static_cast<uint8_t>(AccessType::Read);
                        ma.func_index = func_index;
                        accesses.push_back(ma);
                    }
                    continue;
                } else {
                    // Skip displacement based on mod
                    if (mod == 1) pos += 1;
                    else if (mod == 2) pos += 4;
                    continue;
                }
            }

            // MOVZX: 0F B6 (byte) / 0F B7 (word)
            // MOVSXD: use 63 (below), MOVSX: 0F BE (byte) / 0F BF (word)
            if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
                if (pos >= len) break;
                uint8_t modrm = bytes[pos++];
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t reg_field = ((modrm >> 3) & 7) | (rex_r << 3);
                uint8_t rm = (modrm & 7) | (rex_b << 3);

                if ((modrm & 7) == 4 && mod != 3) {
                    if (pos >= len) break;
                    uint8_t sib = bytes[pos++];
                    rm = (sib & 7) | (rex_b << 3);
                }

                if (mod == 1 && regs.has_this(rm)) {
                    if (pos >= len) break;
                    int8_t disp = static_cast<int8_t>(bytes[pos++]);
                    if (disp > 0 && disp < 0x4000) {
                        MemberAccess ma;
                        ma.offset = static_cast<uint32_t>(disp);
                        ma.size = (op2 == 0xB6 || op2 == 0xBE) ? 1 : 2;
                        ma.access_mask = static_cast<uint8_t>(AccessType::Read);
                        ma.func_index = func_index;
                        accesses.push_back(ma);
                    }
                    // Dest register gets some value, no longer `this`
                    regs.clear(reg_field);
                    continue;
                } else if (mod == 2 && regs.has_this(rm)) {
                    if (pos + 4 > len) break;
                    int32_t disp = 0;
                    memcpy(&disp, &bytes[pos], 4);
                    pos += 4;
                    if (disp > 0 && disp < 0x4000) {
                        MemberAccess ma;
                        ma.offset = static_cast<uint32_t>(disp);
                        ma.size = (op2 == 0xB6 || op2 == 0xBE) ? 1 : 2;
                        ma.access_mask = static_cast<uint8_t>(AccessType::Read);
                        ma.func_index = func_index;
                        accesses.push_back(ma);
                    }
                    regs.clear(reg_field);
                    continue;
                } else {
                    if (mod == 1) pos += 1;
                    else if (mod == 2) pos += 4;
                    regs.clear(reg_field);
                    continue;
                }
            }

            // Anything else with 0F prefix — skip conservatively
            // Many 0F xx instructions have ModRM
            if (pos < len) {
                uint8_t modrm = bytes[pos];
                uint8_t mod = (modrm >> 6) & 3;
                if (mod != 3) {
                    pos++; // consume ModRM
                    if ((modrm & 7) == 4 && mod != 3) pos++; // SIB
                    if (mod == 1) pos += 1;
                    else if (mod == 2) pos += 4;
                    else if (mod == 0 && (modrm & 7) == 5) pos += 4; // [rip+disp32]
                }
            }
            continue;
        }

        // ---- Regular one-byte opcodes with ModRM ----

        bool has_modrm = false;
        bool is_write = false;
        bool is_lea = false;
        bool is_cmp_test = false;
        uint8_t operand_size = 0; // 0 = auto-determine from REX.W/prefix

        // MOV r/m, r (88/89) — write to memory
        if (opcode == 0x88) { has_modrm = true; is_write = true; operand_size = 1; }
        else if (opcode == 0x89) { has_modrm = true; is_write = true; }
        // MOV r, r/m (8A/8B) — read from memory
        else if (opcode == 0x8A) { has_modrm = true; operand_size = 1; }
        else if (opcode == 0x8B) { has_modrm = true; }
        // LEA r, m (8D) — address calculation
        else if (opcode == 0x8D) { has_modrm = true; is_lea = true; }
        // CMP r/m, r (38/39)
        else if (opcode == 0x38) { has_modrm = true; is_cmp_test = true; operand_size = 1; }
        else if (opcode == 0x39) { has_modrm = true; is_cmp_test = true; }
        // CMP r, r/m (3A/3B)
        else if (opcode == 0x3A) { has_modrm = true; is_cmp_test = true; operand_size = 1; }
        else if (opcode == 0x3B) { has_modrm = true; is_cmp_test = true; }
        // TEST r/m, r (84/85)
        else if (opcode == 0x84) { has_modrm = true; is_cmp_test = true; operand_size = 1; }
        else if (opcode == 0x85) { has_modrm = true; is_cmp_test = true; }
        // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm (80-83)
        else if (opcode >= 0x80 && opcode <= 0x83) {
            has_modrm = true;
            if (opcode == 0x80) operand_size = 1;
            // These could be CMP (modrm /7) — we'll check later
        }
        // MOVSXD (63 with REX.W)
        else if (opcode == 0x63 && rex_w) { has_modrm = true; operand_size = 4; }

        if (has_modrm) {
            if (pos >= len) break;
            uint8_t modrm = bytes[pos++];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t reg_field = ((modrm >> 3) & 7) | (rex_r << 3);
            uint8_t rm = (modrm & 7) | (rex_b << 3);

            // Handle SIB byte
            bool has_sib = false;
            if ((modrm & 7) == 4 && mod != 3) {
                has_sib = true;
                if (pos >= len) break;
                uint8_t sib = bytes[pos++];
                rm = (sib & 7) | (rex_b << 3);
            }

            // Check for CMP in group 80-83 (opcode extension /7)
            if (opcode >= 0x80 && opcode <= 0x83) {
                uint8_t ext = (modrm >> 3) & 7;
                if (ext == 7) is_cmp_test = true;
                // Others (ADD/OR/SUB etc.) are writes
                else is_write = true;
            }

            if (mod == 3) {
                // Register-to-register
                if (opcode == 0x8B || opcode == 0x8A) {
                    // MOV dst, src — if src holds this, dst becomes this
                    if (regs.has_this(rm)) {
                        regs.set_this(reg_field);
                    } else {
                        regs.clear(reg_field);
                    }
                } else if (opcode == 0x89 || opcode == 0x88) {
                    // MOV dst(rm), src(reg) — if src holds this, dst becomes this
                    if (regs.has_this(reg_field)) {
                        regs.set_this(rm);
                    } else {
                        regs.clear(rm);
                    }
                } else {
                    // Other reg-reg ops clear destination
                    if (!is_cmp_test && !is_lea) {
                        if (is_write) regs.clear(rm);
                        else regs.clear(reg_field);
                    }
                }

                // Handle immediate for 80-83
                if (opcode == 0x80 || opcode == 0x82) pos += 1;
                else if (opcode == 0x81) pos += 4;
                else if (opcode == 0x83) pos += 1;

                continue;
            }

            // Memory operand with displacement
            int32_t disp = 0;
            if (mod == 0 && (modrm & 7) == 5 && !has_sib) {
                // [rip+disp32] — skip
                pos += 4;
                if (opcode >= 0x80 && opcode <= 0x83) {
                    if (opcode == 0x80 || opcode == 0x82) pos += 1;
                    else if (opcode == 0x81) pos += 4;
                    else if (opcode == 0x83) pos += 1;
                }
                continue;
            } else if (mod == 1) {
                if (pos >= len) break;
                disp = static_cast<int8_t>(bytes[pos++]);
            } else if (mod == 2) {
                if (pos + 4 > len) break;
                memcpy(&disp, &bytes[pos], 4);
                pos += 4;
            }

            // Handle immediates for 80-83
            if (opcode >= 0x80 && opcode <= 0x83) {
                if (opcode == 0x80 || opcode == 0x82) pos += 1;
                else if (opcode == 0x81) pos += 4;
                else if (opcode == 0x83) pos += 1;
            }

            // Check if base register is `this`
            if (mod != 0 || has_sib) { // mod 0 with rm!=5 means [reg] (no disp) — disp would be 0
                // For mod==0 (no disp), disp is 0, which we filter out below
            }

            if (regs.has_this(rm) && disp > 0 && disp < 0x4000) {
                // Determine access size
                uint8_t sz = operand_size;
                if (sz == 0) {
                    if (rex_w) sz = 8;
                    else if (prefix_66) sz = 2;
                    else sz = 4;
                }

                MemberAccess ma;
                ma.offset = static_cast<uint32_t>(disp);
                ma.size = sz;
                ma.func_index = func_index;

                if (is_lea)
                    ma.access_mask = static_cast<uint8_t>(AccessType::Ref);
                else if (is_cmp_test)
                    ma.access_mask = static_cast<uint8_t>(AccessType::Compare) |
                                     static_cast<uint8_t>(AccessType::Read);
                else if (is_write)
                    ma.access_mask = static_cast<uint8_t>(AccessType::Write);
                else
                    ma.access_mask = static_cast<uint8_t>(AccessType::Read);

                accesses.push_back(ma);
            }

            // If this was a MOV/LEA loading from memory into a register:
            // The dest register now holds derived data, not `this` anymore
            if (!is_write && !is_cmp_test && !is_lea) {
                regs.clear(reg_field);
            }
            if (is_lea && regs.has_this(rm) && mod != 0) {
                // LEA reg, [this+disp] — reg now has derived pointer, not this
                regs.clear(reg_field);
            }

            continue;
        }

        // ---- Simple instructions without ModRM ----

        // Short conditional jumps (70-7F): skip disp8
        if (opcode >= 0x70 && opcode <= 0x7F) {
            pos += 1;
            continue;
        }

        // PUSH/POP reg (50-5F)
        if (opcode >= 0x50 && opcode <= 0x5F) continue;

        // NOP (90)
        if (opcode == 0x90) continue;

        // MOV reg, imm32/imm64 (B8-BF)
        if (opcode >= 0xB8 && opcode <= 0xBF) {
            uint8_t dst = (opcode - 0xB8) | (rex_b << 3);
            regs.clear(dst);
            pos += rex_w ? 8 : 4;
            continue;
        }

        // MOV reg8, imm8 (B0-B7)
        if (opcode >= 0xB0 && opcode <= 0xB7) {
            pos += 1;
            continue;
        }

        // CMP/TEST/ADD/SUB al/ax/eax/rax, imm (04/05/0C/0D/24/25/2C/2D/34/35/3C/3D/A8/A9)
        if (opcode == 0x04 || opcode == 0x0C || opcode == 0x24 || opcode == 0x2C ||
            opcode == 0x34 || opcode == 0x3C || opcode == 0xA8) {
            pos += 1;
            continue;
        }
        if (opcode == 0x05 || opcode == 0x0D || opcode == 0x25 || opcode == 0x2D ||
            opcode == 0x35 || opcode == 0x3D || opcode == 0xA9) {
            pos += 4;
            continue;
        }

        // FF group (call/jmp indirect, push, inc, dec)
        if (opcode == 0xFF) {
            if (pos >= len) break;
            uint8_t modrm = bytes[pos++];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t ext = (modrm >> 3) & 7;

            if ((modrm & 7) == 4 && mod != 3) pos++; // SIB

            if (mod == 1) pos += 1;
            else if (mod == 2) pos += 4;
            else if (mod == 0 && (modrm & 7) == 5) pos += 4;

            // CALL indirect — invalidate caller-saved
            if (ext == 2) regs.invalidate_caller_saved();
            // JMP indirect — terminate
            if (ext == 4) break;

            continue;
        }

        // F6/F7 group (test/not/neg/mul/div r/m)
        if (opcode == 0xF6 || opcode == 0xF7) {
            if (pos >= len) break;
            uint8_t modrm = bytes[pos++];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t ext = (modrm >> 3) & 7;

            if ((modrm & 7) == 4 && mod != 3) pos++; // SIB

            if (mod == 1) pos += 1;
            else if (mod == 2) pos += 4;
            else if (mod == 0 && (modrm & 7) == 5) pos += 4;

            // TEST r/m, imm has immediate
            if (ext == 0) {
                pos += (opcode == 0xF6) ? 1 : 4;
            }
            continue;
        }

        // If we can't decode, bail out to avoid garbage
        break;
    }

    return accesses;
}

// ============================================================================
// Per-class deduplication and merging
// ============================================================================

static ClassLayout analyze_class(const std::string& class_name, const json& vtable_data) {
    ClassLayout layout;
    layout.class_name = class_name;

    if (!vtable_data.contains("functions") || !vtable_data["functions"].is_array())
        return layout;

    const auto& functions = vtable_data["functions"];
    layout.vtable_size = (int)functions.size();

    // Collect all member accesses from all functions
    std::map<uint32_t, ClassLayout::FieldInfo> offset_map;

    for (int fi = 0; fi < (int)functions.size(); fi++) {
        const auto& func = functions[fi];
        if (!func.contains("bytes") || !func["bytes"].is_string())
            continue;

        // Parse hex bytes
        const std::string& hex = func["bytes"].get_ref<const std::string&>();
        std::vector<uint8_t> bytes;
        bytes.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            uint8_t b = 0;
            for (int j = 0; j < 2; j++) {
                char c = hex[i + j];
                b <<= 4;
                if (c >= '0' && c <= '9') b |= (c - '0');
                else if (c >= 'A' && c <= 'F') b |= (c - 'A' + 10);
                else if (c >= 'a' && c <= 'f') b |= (c - 'a' + 10);
            }
            bytes.push_back(b);
        }

        if (bytes.empty() || is_stub(bytes)) continue;

        auto accesses = decode_function(bytes, fi);
        layout.analyzed++;

        for (const auto& ma : accesses) {
            auto& field = offset_map[ma.offset];
            field.offset = ma.offset;
            if (ma.size > field.max_size) field.max_size = ma.size;
            field.access_mask |= ma.access_mask;

            // Track which functions access this field
            bool already = false;
            for (int idx : field.func_indices) {
                if (idx == ma.func_index) { already = true; break; }
            }
            if (!already) field.func_indices.push_back(ma.func_index);
        }
    }

    // Convert map to sorted vector
    layout.fields.reserve(offset_map.size());
    for (auto& [offset, fi] : offset_map) {
        layout.fields.push_back(std::move(fi));
    }

    return layout;
}

// ============================================================================
// Convert AccessType bitmask to JSON array of strings
// ============================================================================

static json access_mask_to_json(uint8_t mask) {
    json arr = json::array();
    if (mask & static_cast<uint8_t>(AccessType::Read))    arr.push_back("read");
    if (mask & static_cast<uint8_t>(AccessType::Write))   arr.push_back("write");
    if (mask & static_cast<uint8_t>(AccessType::Float))   arr.push_back("float");
    if (mask & static_cast<uint8_t>(AccessType::Ref))     arr.push_back("ref");
    if (mask & static_cast<uint8_t>(AccessType::Compare)) arr.push_back("compare");
    return arr;
}

// ============================================================================
// Per-module processing (thread worker)
// ============================================================================

struct ModuleResult {
    std::string mod_name;
    json layouts;  // JSON object: class_name -> layout data
    int classes = 0;
    int fields = 0;
    bool valid = false;
};

static ModuleResult process_module(const json& mod_data) {
    ModuleResult result;

    if (!mod_data.contains("name") || !mod_data.contains("vtables"))
        return result;

    result.mod_name = mod_data["name"].get<std::string>();
    result.layouts = json::object();

    const auto& vtables = mod_data["vtables"];
    if (!vtables.is_array()) return result;

    for (const auto& vt : vtables) {
        if (!vt.contains("class") || !vt["class"].is_string()) continue;

        std::string class_name = vt["class"].get<std::string>();
        auto layout = analyze_class(class_name, vt);

        if (layout.fields.empty()) continue;

        json cls_obj;
        cls_obj["vtable_size"] = layout.vtable_size;
        cls_obj["analyzed"] = layout.analyzed;

        json fields_arr = json::array();
        for (const auto& fi : layout.fields) {
            json fobj;
            fobj["offset"] = fi.offset;
            fobj["size"] = fi.max_size;
            fobj["access"] = access_mask_to_json(fi.access_mask);

            json funcs = json::array();
            for (int idx : fi.func_indices) funcs.push_back(idx);
            fobj["funcs"] = std::move(funcs);

            fields_arr.push_back(std::move(fobj));
        }
        cls_obj["fields"] = std::move(fields_arr);

        result.layouts[class_name] = std::move(cls_obj);
        result.classes++;
        result.fields += (int)layout.fields.size();
    }

    result.valid = (result.classes > 0);
    return result;
}

} // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

MemberAnalysisStats analyze_members(json& data) {
    MemberAnalysisStats stats;

    if (!data.contains("modules") || !data["modules"].is_array())
        return stats;

    const auto& modules = data["modules"];

    // Find modules with vtable data
    std::vector<size_t> work_indices;
    for (size_t i = 0; i < modules.size(); i++) {
        if (modules[i].contains("vtables") && modules[i]["vtables"].is_array() &&
            !modules[i]["vtables"].empty()) {
            work_indices.push_back(i);
        }
    }

    if (work_indices.empty()) return stats;

    // Thread pool
    unsigned int hw_threads = std::thread::hardware_concurrency();
    if (hw_threads == 0) hw_threads = 4;
    unsigned int num_workers = (std::min)(hw_threads, static_cast<unsigned int>(work_indices.size()));

    printf("Analyzing member layouts: %d modules with %u threads...\n",
           static_cast<int>(work_indices.size()), num_workers);

    std::mutex results_mutex;
    json all_layouts = json::object();

    std::vector<std::thread> threads;
    std::atomic<size_t> next_work_idx{0};

    auto worker_fn = [&]() {
        while (true) {
            size_t wi = next_work_idx.fetch_add(1);
            if (wi >= work_indices.size()) break;

            auto result = process_module(modules[work_indices[wi]]);

            if (result.valid) {
                std::lock_guard<std::mutex> lock(results_mutex);
                all_layouts[result.mod_name] = std::move(result.layouts);
                stats.modules_analyzed++;
                stats.classes_analyzed += result.classes;
                stats.total_fields += result.fields;
            }
        }
    };

    for (unsigned int t = 0; t < num_workers; t++) {
        threads.emplace_back(worker_fn);
    }
    for (auto& t : threads) {
        t.join();
    }

    // Merge into data
    if (!all_layouts.empty()) {
        data["member_layouts"] = std::move(all_layouts);
    }

    printf("Member layouts: %d modules, %d classes, %d inferred fields\n",
           stats.modules_analyzed, stats.classes_analyzed, stats.total_fields);

    return stats;
}
