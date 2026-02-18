#!/usr/bin/env python3
"""
import-schema.py — Import dezlock-dump JSON export into compilable C++ SDK headers

Reads dezlock-dump's all-modules.json and generates:
  generated/
    _all-offsets.hpp     — Master offset constants for every class
    _all-enums.hpp       — All enums as enum class
    _all-vtables.hpp     — VTable RVAs and virtual function indices
    {module}/
      {ClassName}.hpp    — Padded struct with static_asserts

Usage:
  python import-schema.py --game deadlock                              # auto-detect JSON from bin/
  python import-schema.py --game deadlock --json path/to/all-modules.json
  python import-schema.py --game deadlock --output ./my-sdk/
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# ============================================================================
# Type mapping (schema type -> C++ type)
# ============================================================================

PRIMITIVE_MAP = {
    "bool": ("bool", 1),
    "int8": ("int8_t", 1),
    "uint8": ("uint8_t", 1),
    "int16": ("int16_t", 2),
    "uint16": ("uint16_t", 2),
    "int32": ("int32_t", 4),
    "uint32": ("uint32_t", 4),
    "int64": ("int64_t", 8),
    "uint64": ("uint64_t", 8),
    "float32": ("float", 4),
    "float": ("float", 4),
    "float64": ("double", 8),
}

# ALIAS_TABLE: schema type -> (cpp_type_or_None, size)
# cpp_type=None means emit as uint8_t blob of the given size (preserves sizeof)
ALIAS_TABLE = {
    # String / symbol types (opaque blobs — internal layout is engine-private)
    "CUtlString":           ("void*", 8),
    "CUtlSymbolLarge":      ("void*", 8),
    "CGlobalSymbol":        (None, 8),
    "CUtlStringToken":      ("uint32_t", 4),
    "CKV3MemberNameWithStorage": (None, 24),

    # Math types
    "Color":                ("uint32_t", 4),
    "QAngle":               ("float[3]", 12),
    "Vector":               ("float[3]", 12),
    "Vector2D":             ("float[2]", 8),
    "Vector4D":             ("float[4]", 16),
    "VectorWS":             ("float[3]", 12),   # world-space Vector
    "VectorAligned":        ("float[4]", 16),   # 16-byte aligned Vector
    "Quaternion":           ("float[4]", 16),
    "QuaternionStorage":    ("float[4]", 16),
    "RotationVector":       ("float[3]", 12),
    "matrix3x4_t":          ("float[12]", 48),
    "matrix3x4a_t":         ("float[12]", 48),
    "CTransform":           (None, 32),         # pos + quat

    # Game time / tick types
    "GameTime_t":           ("float", 4),
    "GameTick_t":           ("int32_t", 4),
    "AnimationTimeFloat":   ("float", 4),

    # Handle types (all are uint32 handles under the hood)
    "AttachmentHandle_t":   ("uint8_t", 1),
    "CAnimParamHandle":     ("uint16_t", 2),
    "CAnimParamHandleMap":  (None, 2),
    "ModelConfigHandle_t":  ("uint16_t", 2),
    "HitGroup_t":           ("int32_t", 4),
    "RenderPrimitiveType_t": ("int32_t", 4),
    "MoveType_t":           ("uint8_t", 1),
    "MoveCollide_t":        ("uint8_t", 1),
    "SolidType_t":          ("uint8_t", 1),
    "SurroundingBoundsType_t": ("uint8_t", 1),
    "RenderMode_t":         ("uint8_t", 1),
    "RenderFx_t":           ("uint8_t", 1),
    "EntityDisolveType_t":  ("int32_t", 4),
    "NPC_STATE":            ("int32_t", 4),
    "Hull_t":               ("int32_t", 4),
    "Activity":             ("int32_t", 4),

    # Resource / sound types (opaque blobs)
    "CSoundEventName":      (None, 16),
    "CFootstepTableHandle": (None, 8),
    "CBodyComponent":       (None, 8),

    # Anim types
    "AnimValueSource":      ("int32_t", 4),
    "AnimParamID":          ("uint32_t", 4),
    "AnimScriptHandle":     ("uint16_t", 2),
    "AnimNodeID":           ("uint32_t", 4),
    "AnimNodeOutputID":     ("uint32_t", 4),
    "AnimStateID":          ("uint32_t", 4),
    "AnimComponentID":      ("uint32_t", 4),
    "AnimTagID":            ("uint32_t", 4),
    "BlendKeyType":         ("int32_t", 4),
    "BinaryNodeTiming":     ("int32_t", 4),
    "BinaryNodeChildOption": ("int32_t", 4),
    "DampingSpeedFunction": ("int32_t", 4),

    # Physics
    "CPhysicsComponent":    (None, 8),
    "CRenderComponent":     (None, 8),

    # Commonly-seen opaque structs (fixed sizes from dezlock-dump)
    "CPiecewiseCurve":      (None, 64),
    "CAnimGraphTagOptionalRef": (None, 32),
    "CAnimGraphTagRef":     (None, 32),
    "CitadelCameraOperationsSequence_t": (None, 136),
    "PulseSymbol_t":        (None, 16),
    "CNetworkVarChainer":   (None, 40),
    "CPanoramaImageName":   (None, 16),
    "CBufferString":        (None, 16),
    "KeyValues3":           (None, 16),
    "CPulseValueFullType":  (None, 24),
    "PulseRegisterMap_t":   (None, 48),

    # Small integer-like types
    "HeroID_t":             ("int32_t", 4),
    "HSequence":            ("int32_t", 4),
    "CPlayerSlot":          ("int32_t", 4),
    "WorldGroupId_t":       ("int32_t", 4),
    "PulseDocNodeID_t":     ("int32_t", 4),
    "PulseRuntimeChunkIndex_t": ("int32_t", 4),
    "ParticleTraceSet_t":   ("int32_t", 4),
    "ParticleColorBlendType_t": ("int32_t", 4),
    "EventTypeSelection_t": ("int32_t", 4),
    "ThreeState_t":         ("int32_t", 4),
    "ParticleAttachment_t": ("int32_t", 4),
    "EModifierValue":       ("int32_t", 4),
    "ParticleOutputBlendMode_t": ("int32_t", 4),
    "Detail2Combo_t":       ("int32_t", 4),
    "ParticleFalloffFunction_t": ("int32_t", 4),
    "ParticleHitboxBiasType_t":  ("int32_t", 4),
    "ParticleEndcapMode_t": ("int32_t", 4),
    "ParticleLightingQuality_t": ("int32_t", 4),
    "ParticleSelection_t":  ("int32_t", 4),
    "SpriteCardPerParticleScale_t": ("int32_t", 4),
    "ParticleAlphaReferenceType_t": ("int32_t", 4),
    "ParticleSequenceCropOverride_t": ("int32_t", 4),
    "ParticleLightTypeChoiceList_t": ("int32_t", 4),
    "ParticleDepthFeatheringMode_t": ("int32_t", 4),
    "ParticleFogType_t":    ("int32_t", 4),
    "ParticleOmni2LightTypeChoiceList_t": ("int32_t", 4),
    "ParticleSortingChoiceList_t": ("int32_t", 4),
    "ParticleOrientationChoiceList_t": ("int32_t", 4),
    "TextureRepetitionMode_t": ("int32_t", 4),
    "SpriteCardShaderType_t": ("int32_t", 4),
    "ParticleDirectionNoiseType_t": ("int32_t", 4),
    "ParticleRotationLockType_t": ("int32_t", 4),
    "ParticlePostProcessPriorityGroup_t": ("int32_t", 4),
    "InheritableBoolType_t": ("int32_t", 4),
    "ClosestPointTestType_t": ("int32_t", 4),
    "ParticleColorBlendMode_t": ("int32_t", 4),
    "ParticleTopology_t":   ("int32_t", 4),
    "PFuncVisualizationType_t": ("int32_t", 4),
    "ParticleVRHandChoiceList_t": ("int32_t", 4),
    "StandardLightingAttenuationStyle_t": ("int32_t", 4),
    "SnapshotIndexType_t":  ("int32_t", 4),
    "PFNoiseType_t":        ("int32_t", 4),
    "PFNoiseTurbulence_t":  ("int32_t", 4),
    "PFNoiseModifier_t":    ("int32_t", 4),
    "AnimVRHandMotionRange_t": ("int32_t", 4),
    "AnimVRFinger_t":       ("int32_t", 4),
    "IKSolverType":         ("int32_t", 4),
    "IKTargetSource":       ("int32_t", 4),
    "JiggleBoneSimSpace":   ("int32_t", 4),
    "AnimPoseControl":      ("int32_t", 4),
    "FacingMode":           ("int32_t", 4),
    "FieldNetworkOption":   ("int32_t", 4),
    "StanceOverrideMode":   ("int32_t", 4),
    "AimMatrixBlendMode":   ("int32_t", 4),
    "SolveIKChainAnimNodeDebugSetting": ("int32_t", 4),
    "AnimNodeNetworkMode":  ("int32_t", 4),
    "ChoiceMethod":         ("int32_t", 4),
    "ChoiceBlendMethod":    ("int32_t", 4),
    "ChoiceChangeMethod":   ("int32_t", 4),
    "FootFallTagFoot_t":    ("int32_t", 4),
    "MatterialAttributeTagType_t": ("int32_t", 4),
    "FootPinningTimingSource": ("int32_t", 4),
    "StepPhase":            ("int32_t", 4),
    "FootLockSubVisualization": ("int32_t", 4),
    "ResetCycleOption":     ("int32_t", 4),
    "IkEndEffectorType":    ("int32_t", 4),
    "IkTargetType":         ("int32_t", 4),
    "Comparison_t":         ("int32_t", 4),
    "ComparisonValueType":  ("int32_t", 4),
    "ConditionLogicOp":     ("int32_t", 4),
    "EDemoBoneSelectionMode": ("int32_t", 4),
    "StateActionBehavior":  ("int32_t", 4),
    "SeqPoseSetting_t":     ("int32_t", 4),
    "StateComparisonValueType": ("int32_t", 4),
    "SelectionSource_t":    ("int32_t", 4),
    "MoodType_t":           ("int32_t", 4),
    "AnimParamButton_t":    ("int32_t", 4),
    "AnimParamNetworkSetting": ("int32_t", 4),
    "CGroundIKSolverSettings": (None, 48),
    "CAnimParamHandleMap":  (None, 2),
}

# CONTAINER_SIZES: template container outer name -> fixed size (or None = use field's size)
CONTAINER_SIZES = {
    "CUtlVector":                   24,
    "CNetworkUtlVectorBase":        24,
    "C_NetworkUtlVectorBase":       24,
    "CUtlVectorEmbeddedNetworkVar": 24,
    "CUtlLeanVector":               16,
    "CUtlOrderedMap":               40,
    "CUtlHashtable":                40,
    "CResourceNameTyped":           None,  # variable size, use field["size"]
    "CEmbeddedSubclass":            16,
    "CStrongHandle":                8,
    "CWeakHandle":                  8,
    "CStrongHandleCopyable":        8,
    "CSmartPtr":                    8,
    "CSmartPropPtr":                8,
    "CAnimGraphParamRef":           None,  # variable size
    "CEntityOutputTemplate":        None,  # variable size
    "CEntityIOOutput":              None,
    "CAnimInputDamping":            None,
    "CRemapFloat":                  None,
    "CPerParticleFloatInput":       None,
    "CPerParticleVecInput":         None,
    "CParticleCollectionFloatInput": None,
    "CParticleCollectionVecInput":  None,
    "CParticleTransformInput":      None,
    "CParticleModelInput":          None,
    "CParticleRemapFloatInput":     None,
    "CRandomNumberGeneratorParameters": None,
    "CAnimGraph2ParamOptionalRef":  None,  # variable size
    "CAnimGraph2ParamRef":          None,
    "CModifierHandleTyped":         None,
    "CSubclassName":                None,
    "CSubclassNameBase":            16,
}


# Resolution statistics tracker
class ResolveStats:
    def __init__(self):
        self.counts = {
            "primitive": 0,
            "alias": 0,
            "template": 0,
            "embedded": 0,
            "handle": 0,
            "enum": 0,
            "pointer": 0,
            "array": 0,
            "bitfield": 0,
            "unresolved": 0,
        }
        self.total = 0

    def record(self, category: str):
        self.counts[category] = self.counts.get(category, 0) + 1
        self.total += 1

    def print_summary(self):
        resolved = self.total - self.counts["unresolved"]
        pct = (resolved / self.total * 100) if self.total > 0 else 0
        print(f"\nType resolution: {resolved} / {self.total} ({pct:.1f}%)")
        for cat in ["primitive", "alias", "template", "embedded", "handle",
                     "enum", "pointer", "array", "bitfield", "unresolved"]:
            c = self.counts.get(cat, 0)
            if c > 0:
                label = "  (blob fallback, sizes correct)" if cat == "unresolved" else ""
                print(f"  {cat + ':':14s}{c:>5d}{label}")


# Global stats instance — set in main() before generation
_stats = ResolveStats()
_all_enums: dict[str, int] = {}   # enum_name -> size
_all_classes: set[str] = set()    # known class names


def schema_to_cpp_type(schema_type: str, size: int) -> tuple[str | None, str]:
    """Resolve a schema type to a C++ type string.

    Returns (cpp_type, category).
    - cpp_type is the C++ type string, or None to emit a sized blob.
    - category is the resolution category for stats tracking.
    - For blobs, caller emits uint8_t name[size] with a comment.
    """
    # 1. Primitives
    if schema_type in PRIMITIVE_MAP:
        return PRIMITIVE_MAP[schema_type][0], "primitive"

    # 2. Alias table
    if schema_type in ALIAS_TABLE:
        cpp, _ = ALIAS_TABLE[schema_type]
        return cpp, "alias"

    # 3. CHandle<T> / CEntityHandle (always uint32)
    if schema_type.startswith("CHandle<") or schema_type.startswith("CEntityHandle"):
        return "uint32_t", "handle"

    # 4. Pointers
    if schema_type.endswith("*"):
        return "void*", "pointer"

    # 5. Bitfields (size=0, type like "bitfield:3")
    if schema_type.startswith("bitfield:"):
        return None, "bitfield"

    # 6. char[N] arrays
    m = re.match(r"char\[(\d+)\]", schema_type)
    if m:
        return f"char[{m.group(1)}]", "array"

    # 7. Fixed-size arrays of known types (e.g. int32[6], Vector[2], GameTime_t[4])
    m = re.match(r"([\w:]+)\[(\d+)\]", schema_type)
    if m:
        base_type = m.group(1)
        count = m.group(2)
        if base_type in PRIMITIVE_MAP:
            return f"{PRIMITIVE_MAP[base_type][0]}[{count}]", "array"
        if base_type in ALIAS_TABLE:
            alias_cpp, alias_sz = ALIAS_TABLE[base_type]
            if alias_cpp is not None:
                # Known concrete type — emit typed array
                bracket = alias_cpp.find("[")
                if bracket == -1:
                    return f"{alias_cpp}[{count}]", "array"
                # alias is already an array (e.g. float[3]) — flatten
                # Vector[2] → float[3][2] won't compile, use blob
                return None, "array"
            # alias is a blob — emit blob with correct total size
            return None, "array"
        # CHandle arrays
        if base_type.startswith("CHandle"):
            return f"uint32_t[{count}]", "array"
        # Enum arrays
        if base_type in _all_enums:
            enum_sz = _all_enums[base_type]
            int_type = {1: "uint8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(
                enum_sz, "int32_t"
            )
            return f"{int_type}[{count}]", "array"
        # Unknown base type array — blob with comment
        return None, "array"

    # 8. Template containers (CUtlVector<T>, CResourceNameTyped<...>, etc.)
    lt = schema_type.find("<")
    if lt != -1:
        outer = schema_type[:lt]
        if outer in CONTAINER_SIZES:
            return None, "template"
        # CHandle inside template
        if outer == "CHandle":
            return "uint32_t", "handle"

    # 9. Enum-typed fields
    if schema_type in _all_enums:
        enum_sz = _all_enums[schema_type]
        int_type = {1: "uint8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(
            enum_sz, "int32_t"
        )
        return int_type, "enum"

    # 10. Embedded schema classes (blob is correct, just categorize)
    if schema_type in _all_classes:
        return None, "embedded"

    # 11. Unresolved — fallback to blob
    return None, "unresolved"


# ============================================================================
# JSON loading (handles dezlock-dump's sometimes-broken escapes)
# ============================================================================

def _strip_static_fields(raw: bytes) -> bytes:
    """Remove all "static_fields": [...] sections from raw JSON bytes.

    This operates on raw bytes before text decoding because the static_fields
    arrays contain binary garbage (raw memory pointers with 0x22/quote bytes
    embedded mid-string) that break both text decoders and regex parsers.

    Strategy: find each `"static_fields"` key, then scan forward for the
    closing `]` that sits at the correct indentation level (the line pattern
    `\\n          ]` — newline + 10 spaces + bracket). Simple bracket-depth
    counting won't work because the binary garbage contains literal [ and ] bytes.
    """
    marker = b'"static_fields"'
    # The closing bracket pattern: \r\n + 10 spaces + ]
    close_pattern = b"\n          ]"
    result = bytearray()
    pos = 0

    while pos < len(raw):
        idx = raw.find(marker, pos)
        if idx == -1:
            result.extend(raw[pos:])
            break

        # Find the comma before "static_fields" (skip whitespace)
        comma_pos = idx - 1
        while comma_pos > pos and raw[comma_pos] in (0x20, 0x09, 0x0A, 0x0D):
            comma_pos -= 1

        # Write everything up to (but not including) the comma
        if raw[comma_pos] == ord(","):
            result.extend(raw[pos:comma_pos])
        else:
            result.extend(raw[pos:idx])

        # Find the closing bracket by searching for the indentation pattern
        bracket_start = raw.find(b"[", idx + len(marker))
        if bracket_start == -1:
            pos = idx + len(marker)
            continue

        close_idx = raw.find(close_pattern, bracket_start)
        if close_idx == -1:
            # Couldn't find close — skip to next class boundary
            # Look for the next `\n        {` or `\n      ]` (class/module end)
            fallback = raw.find(b"\n        }", bracket_start)
            if fallback == -1:
                fallback = raw.find(b"\n      ]", bracket_start)
            if fallback == -1:
                pos = bracket_start  # give up, include remaining
                continue
            pos = fallback
            continue

        # Skip past the closing bracket + ]
        pos = close_idx + len(close_pattern)

    return bytes(result)


def load_json(path: str) -> dict:
    """Load dezlock-dump JSON export.

    Tries clean UTF-8 parse first (works if dezlock-dump was built with the
    seh_read_string + is_json_safe fixes). Falls back to byte-level sanitization
    for older exports that have binary garbage in static_fields.
    """
    # Fast path: try clean parse
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("  (clean parse failed, applying byte-level sanitization...)")

    # Slow path: strip static_fields + sanitize
    with open(path, "rb") as f:
        raw = f.read()

    raw = _strip_static_fields(raw)
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', text)
    text = re.sub(r'\\([^"\\/bfnrtu])', r'\1', text)

    return json.loads(text, strict=False)


# ============================================================================
# Code generation
# ============================================================================

def make_guard(name: str) -> str:
    guard = "SDK_GEN_" + name.upper()
    guard = re.sub(r"[^A-Z0-9_]", "_", guard)
    return guard + "_HPP"


def emit_field(f: dict, cursor: int, lines: list[str]) -> int:
    """Emit a single field with padding. Returns new cursor position."""
    offset = f["offset"]
    size = f["size"]
    name = f["name"]
    schema_type = f["type"]

    # Padding gap
    if offset > cursor:
        gap = offset - cursor
        lines.append(f"    uint8_t _pad{cursor:04X}[0x{gap:X}];")

    cpp_type, category = schema_to_cpp_type(schema_type, size)
    _stats.record(category)

    meta = f.get("metadata", [])
    meta_str = " ".join(f"[{m}]" for m in meta) if meta else ""
    comment = f"// 0x{offset:X} ({schema_type}, {size})"
    if meta_str:
        comment += f" {meta_str}"

    # Bitfields (size=0): emit as comment only
    if category == "bitfield":
        m = re.match(r"bitfield:(\d+)", schema_type)
        bits = m.group(1) if m else "?"
        lines.append(f"    // bitfield {name} : {bits}; {comment}")
        return cursor  # don't advance

    if cpp_type is not None:
        bracket = cpp_type.find("[")
        if bracket != -1:
            base = cpp_type[:bracket]
            arr = cpp_type[bracket:]
            lines.append(f"    {base} {name}{arr}; {comment}")
        else:
            lines.append(f"    {cpp_type} {name}; {comment}")
    elif size > 0:
        lines.append(f"    uint8_t {name}[0x{size:X}]; {comment}")
    else:
        lines.append(f"    // 0x{offset:X} {name} ({schema_type}) — zero size")
        return cursor  # don't advance

    return offset + size if size > 0 else offset


def generate_struct_header(cls: dict, module_name: str, class_lookup: dict,
                           timestamp: str) -> str:
    """Generate a complete .hpp file for one class."""
    name = cls["name"]
    size = cls["size"]
    parent = cls.get("parent")
    fields = sorted(cls.get("fields", []), key=lambda f: f["offset"])

    has_parent = parent and parent in class_lookup
    parent_size = class_lookup[parent]["size"] if has_parent else 0

    guard = make_guard(name)
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// Class: {name}")
    lines.append(f"// Module: {module_name}")
    lines.append(f"// Size: 0x{size:X} ({size} bytes)")
    if parent:
        lines.append(f"// Parent: {parent}")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"#include <cstddef>")
    if has_parent:
        safe_parent = parent.replace("::", "__")
        lines.append(f'#include "{safe_parent}.hpp"')
    lines.append(f"")

    # Struct definition
    if has_parent:
        lines.append(f"#pragma pack(push, 1)")
        lines.append(f"struct {name} : {parent} {{")
    else:
        lines.append(f"#pragma pack(push, 1)")
        lines.append(f"struct {name} {{")

    cursor = parent_size if has_parent else 0
    emitted_fields = []

    for f in fields:
        if f["offset"] < cursor:
            continue  # skip inherited fields
        cursor = emit_field(f, cursor, lines)
        emitted_fields.append(f)

    # Pad to class size
    if cursor < size:
        lines.append(f"    uint8_t _padEnd[0x{size - cursor:X}];")

    lines.append(f"}};")
    lines.append(f"#pragma pack(pop)")
    lines.append(f"")

    # static_asserts
    lines.append(f"static_assert(sizeof({name}) == 0x{size:X}, \"{name} size\");")
    for f in emitted_fields:
        fname = f["name"]
        foff = f["offset"]
        lines.append(f"static_assert(offsetof({name}, {fname}) == 0x{foff:X}, \"{fname}\");")

    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


def generate_all_offsets(modules: list[dict], game: str, timestamp: str) -> str:
    """Generate _all-offsets.hpp with every class from every module."""
    guard = make_guard(f"{game}_all_offsets")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// All class field offsets from runtime schema dump")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"")
    lines.append(f"namespace {game}::generated::offsets {{")
    lines.append(f"")

    total_classes = 0
    total_fields = 0

    for mod in modules:
        mod_name = mod["name"].replace(".dll", "")
        classes = sorted(mod.get("classes", []), key=lambda c: c["name"])

        for cls in classes:
            fields = cls.get("fields", [])
            if not fields:
                continue

            total_classes += 1
            lines.append(f"namespace {cls['name']} {{")

            sorted_fields = sorted(fields, key=lambda f: f["offset"])
            for f in sorted_fields:
                total_fields += 1
                comment = f"// {f['type']} ({f['size']}b)"
                lines.append(
                    f"    constexpr uint32_t {f['name']} = 0x{f['offset']:X}; {comment}"
                )

            lines.append(f"}} // {cls['name']}")
            lines.append(f"")

    lines.append(f"}} // namespace {game}::generated::offsets")
    lines.append(f"")
    lines.append(f"// Total: {total_classes} classes, {total_fields} fields")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


def sanitize_cpp_identifier(name: str) -> str | None:
    """Sanitize a class name into a valid C++ identifier.

    Returns None if the name is too mangled to be useful (template
    instantiations with ?$ prefix, names with only special chars, etc.)
    """
    # Skip MSVC mangled template names (still have ?$ prefix)
    if name.startswith("?$") or name.startswith("?"):
        return None

    # Replace common invalid chars
    s = name.replace("::", "__").replace("<", "_").replace(">", "_")
    s = s.replace(",", "_").replace(" ", "_").replace("&", "_").replace("*", "_")

    # Strip any remaining non-identifier chars
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)

    # Collapse multiple underscores and strip trailing
    s = re.sub(r"_+", "_", s).strip("_")

    if not s or not s[0].isalpha() and s[0] != "_":
        s = "_" + s

    return s if s else None


def generate_all_vtables(modules: list[dict], game: str, timestamp: str) -> str:
    """Generate _all-vtables.hpp with vtable RVAs and function indices."""
    guard = make_guard(f"{game}_all_vtables")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// All vtable RVAs and virtual function indices from RTTI scan")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"")
    lines.append(f"namespace {game}::generated::vtables {{")
    lines.append(f"")

    total_classes = 0
    total_funcs = 0
    skipped = 0

    for mod in modules:
        vtables = mod.get("vtables", [])
        if not vtables:
            continue

        for vt in sorted(vtables, key=lambda v: v["class"]):
            class_name = vt["class"]
            vtable_rva = vt["vtable_rva"]
            funcs = vt.get("functions", [])

            if not funcs:
                continue

            safe_name = sanitize_cpp_identifier(class_name)
            if not safe_name:
                skipped += 1
                continue

            total_classes += 1
            comment = f" // {class_name}" if safe_name != class_name else ""
            lines.append(f"namespace {safe_name} {{{comment}")
            lines.append(f"    constexpr uint32_t vtable_rva = {vtable_rva};")
            lines.append(f"    constexpr int entry_count = {len(funcs)};")
            lines.append(f"    namespace fn {{")

            for func in funcs:
                idx = func["index"]
                rva = func["rva"]
                total_funcs += 1
                lines.append(f"        constexpr int idx_{idx} = {idx}; // rva={rva}")

            lines.append(f"    }}")
            lines.append(f"}} // {safe_name}")
            lines.append(f"")

    lines.append(f"}} // namespace {game}::generated::vtables")
    lines.append(f"")
    lines.append(f"// Total: {total_classes} vtables, {total_funcs} virtual functions")
    if skipped:
        lines.append(f"// Skipped: {skipped} classes with unrepresentable names (templates, mangled)")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


def generate_all_enums(modules: list[dict], game: str, timestamp: str) -> str:
    """Generate _all-enums.hpp with all enums from all modules."""
    guard = make_guard(f"{game}_all_enums")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// All enums from runtime schema dump")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"")
    lines.append(f"namespace {game}::generated::enums {{")
    lines.append(f"")

    total = 0
    for mod in modules:
        for en in sorted(mod.get("enums", []), key=lambda e: e["name"]):
            total += 1
            sz = en.get("size", 4)
            underlying = {1: "uint8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(
                sz, "int32_t"
            )
            lines.append(f"enum class {en['name']} : {underlying} {{")
            for v in en.get("values", []):
                lines.append(f"    {v['name']} = {v['value']},")
            lines.append(f"}};")
            lines.append(f"")

    lines.append(f"}} // namespace {game}::generated::enums")
    lines.append(f"")
    lines.append(f"// Total: {total} enums")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


# ============================================================================
# Main
# ============================================================================

def find_json_path(args) -> str:
    """Resolve JSON input path from args or auto-detect."""
    if args.json:
        return args.json

    if args.dir:
        candidate = os.path.join(args.dir, "all-modules.json")
        if os.path.exists(candidate):
            return candidate
        # Try dezlock-export.json in the dir
        candidate = os.path.join(args.dir, "dezlock-export.json")
        if os.path.exists(candidate):
            return candidate
        print(f"ERROR: No JSON found in {args.dir}")
        sys.exit(1)

    # Auto-detect from bin/schema-dump/ next to this script
    script_dir = Path(__file__).parent
    for subdir in ["bin/schema-dump", "bin", "."]:
        candidate = script_dir / subdir / "all-modules.json"
        if candidate.exists():
            return str(candidate)

    # Try %TEMP%
    temp = os.environ.get("TEMP", os.environ.get("TMP", "/tmp"))
    candidate = os.path.join(temp, "dezlock-export.json")
    if os.path.exists(candidate):
        return candidate

    print("ERROR: No JSON found. Searched bin/schema-dump/, bin/, and %TEMP%")
    print("Usage: python import-schema.py --game deadlock --json path/to/all-modules.json")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Import dezlock-dump schema into compilable C++ SDK")
    parser.add_argument("--game", required=True, help="Game name (e.g. deadlock)")
    parser.add_argument("--json", help="Path to dezlock-export.json or all-modules.json")
    parser.add_argument("--dir", help="Path to directory containing all-modules.json")
    parser.add_argument("--output", help="Output directory (default: ./generated/)")
    parser.add_argument("--modules", help="Comma-separated module filter (e.g. client,server)")
    args = parser.parse_args()

    json_path = find_json_path(args)
    print(f"Loading {json_path}...")

    data = load_json(json_path)
    timestamp = data.get("timestamp", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))

    modules = data.get("modules", [])
    if not modules:
        print("ERROR: No modules found in JSON")
        sys.exit(1)

    # Optional module filter
    if args.modules:
        allowed = set(m.strip() for m in args.modules.split(","))
        # Match with or without .dll
        modules = [
            m for m in modules
            if m["name"] in allowed or m["name"].replace(".dll", "") in allowed
        ]

    # Resolve output directory
    if args.output:
        out_dir = Path(args.output)
    else:
        out_dir = Path(__file__).parent / "generated"

    print(f"Output: {out_dir}")
    print(f"Modules: {len(modules)}")
    print(f"Total classes: {data.get('total_classes', '?')}")
    print(f"Total fields: {data.get('total_fields', '?')}")
    print(f"Total enums: {data.get('total_enums', '?')}")
    print()

    # Ensure output dirs exist
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build global class lookup (for parent resolution across modules)
    global_lookup = {}
    for mod in modules:
        for cls in mod.get("classes", []):
            global_lookup[cls["name"]] = cls

    # Build enum lookup for type resolution (Step 3: enum-typed fields)
    global _all_enums, _all_classes, _stats
    _all_enums = {}
    for mod in modules:
        for en in mod.get("enums", []):
            _all_enums[en["name"]] = en.get("size", 4)

    # Build class name set for embedded class categorization (Step 4)
    _all_classes = set(global_lookup.keys())

    # Reset stats tracker
    _stats = ResolveStats()

    # Generate per-module struct headers
    total_structs = 0
    for mod in modules:
        mod_name = mod["name"].replace(".dll", "")
        classes = mod.get("classes", [])
        if not classes:
            continue

        mod_dir = out_dir / mod_name
        mod_dir.mkdir(exist_ok=True)

        mod_count = 0
        for cls in sorted(classes, key=lambda c: c["name"]):
            if cls["size"] <= 0:
                continue
            if not cls.get("fields"):
                continue

            header = generate_struct_header(cls, mod["name"], global_lookup, timestamp)
            # Sanitize filename (:: is invalid on Windows)
            safe_name = cls["name"].replace("::", "__")
            filepath = mod_dir / f"{safe_name}.hpp"
            filepath.write_text(header, encoding="utf-8")
            mod_count += 1

        total_structs += mod_count
        print(f"  {mod['name']:30s}  {mod_count:4d} structs")

    # Generate _all-offsets.hpp
    offsets_content = generate_all_offsets(modules, args.game, timestamp)
    offsets_path = out_dir / "_all-offsets.hpp"
    offsets_path.write_text(offsets_content, encoding="utf-8")

    # Count for summary
    offset_lines = offsets_content.count("constexpr uint32_t")
    print(f"\n  _all-offsets.hpp: {offset_lines} offset constants")

    # Generate _all-enums.hpp
    enums_content = generate_all_enums(modules, args.game, timestamp)
    enums_path = out_dir / "_all-enums.hpp"
    enums_path.write_text(enums_content, encoding="utf-8")

    enum_count = enums_content.count("enum class ")
    print(f"  _all-enums.hpp: {enum_count} enums")

    # Generate _all-vtables.hpp
    vtables_content = generate_all_vtables(modules, args.game, timestamp)
    vtables_path = out_dir / "_all-vtables.hpp"
    vtables_path.write_text(vtables_content, encoding="utf-8")

    vtable_count = vtables_content.count("constexpr uint32_t vtable_rva")
    vtable_func_count = vtables_content.count("constexpr int idx_")
    print(f"  _all-vtables.hpp: {vtable_count} vtables, {vtable_func_count} functions")

    # Print type resolution statistics
    _stats.print_summary()

    print(f"\nDone! {total_structs} struct headers generated.")
    print(f"Output: {out_dir}")


if __name__ == "__main__":
    main()
