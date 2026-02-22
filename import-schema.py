#!/usr/bin/env python3
"""
import-schema.py — Import dezlock-dump JSON export into compilable C++ SDK headers

Reads dezlock-dump's all-modules.json and generates a cherry-pickable SDK:
  sdk/
    types.hpp                     — Base types (Vec3, QAngle, CHandle, Color, etc.)
    {module}-offsets.hpp          — Per-module constexpr offset constants
    {module}-enums.hpp            — Per-module scoped enum classes
    _all-offsets.hpp              — Consolidated offsets include
    _all-enums.hpp                — Consolidated enums include
    _all-vtables.hpp              — VTable RVAs + function indices
    _globals.hpp                  — Pattern-scanned global pointers (dwEntityList, etc.)
    {module}/
      {ClassName}.hpp             — Per-class padded struct with static_asserts

Usage:
  python import-schema.py --game deadlock                              # auto-detect JSON from bin/
  python import-schema.py --game deadlock --json path/to/all-modules.json
  python import-schema.py --game deadlock --output ./my-sdk/
  python import-schema.py --game cs2 --json path/to/all-modules.json
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# ============================================================================
# v2-style type system — maps schema types to high-quality C++ types
# ============================================================================

# Types that get emitted as named structs in types.hpp
RICH_TYPES = {
    "Vector":           ("Vec3",        12),
    "VectorWS":         ("Vec3",        12),
    "QAngle":           ("QAngle",      12),
    "Color":            ("Color",        4),
    "Vector2D":         ("Vec2",         8),
    "Vector4D":         ("Vec4",        16),
}

# Primitive type mapping (schema -> (cpp_type, size))
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
# cpp_type=None means emit as uint8_t blob of the given size
ALIAS_TABLE = {
    # String / symbol types (opaque blobs)
    "CUtlString":           ("void*", 8),
    "CUtlSymbolLarge":      ("void*", 8),
    "CGlobalSymbol":        (None, 8),
    "CUtlStringToken":      ("uint32_t", 4),
    "CKV3MemberNameWithStorage": (None, 24),

    # Math types (non-rich — these get raw array fallback)
    "VectorAligned":        ("float[4]", 16),
    "Quaternion":           ("float[4]", 16),
    "QuaternionStorage":    ("float[4]", 16),
    "RotationVector":       ("float[3]", 12),
    "matrix3x4_t":          ("float[12]", 48),
    "matrix3x4a_t":         ("float[12]", 48),
    "CTransform":           (None, 32),

    # Game time / tick types
    "GameTime_t":           ("float", 4),
    "GameTick_t":           ("int32_t", 4),
    "AnimationTimeFloat":   ("float", 4),

    # Handle types
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

    # Commonly-seen opaque structs
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
    "CResourceNameTyped":           None,
    "CEmbeddedSubclass":            16,
    "CStrongHandle":                8,
    "CWeakHandle":                  8,
    "CStrongHandleCopyable":        8,
    "CSmartPtr":                    8,
    "CSmartPropPtr":                8,
    "CAnimGraphParamRef":           None,
    "CEntityOutputTemplate":        None,
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
    "CAnimGraph2ParamOptionalRef":  None,
    "CAnimGraph2ParamRef":          None,
    "CModifierHandleTyped":         None,
    "CSubclassName":                None,
    "CSubclassNameBase":            16,
}


# ============================================================================
# Resolution statistics tracker
# ============================================================================

class ResolveStats:
    def __init__(self):
        self.counts = {
            "primitive": 0,
            "alias": 0,
            "rich_type": 0,
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
        for cat in ["primitive", "alias", "rich_type", "template", "embedded", "handle",
                     "enum", "pointer", "array", "bitfield", "unresolved"]:
            c = self.counts.get(cat, 0)
            if c > 0:
                label = "  (blob fallback, sizes correct)" if cat == "unresolved" else ""
                print(f"  {cat + ':':14s}{c:>5d}{label}")


# Global state — set in main() before generation
_stats = ResolveStats()
_all_enums: dict[str, int] = {}
_all_classes: set[str] = set()
_cherry_pick: dict = {}  # loaded from sdk-cherry-pick.json


def schema_to_cpp_type(schema_type: str, size: int) -> tuple[str | None, str]:
    """Resolve a schema type to a C++ type string.

    Returns (cpp_type, category).
    - cpp_type is the C++ type string, or None to emit a sized blob.
    - category is the resolution category for stats tracking.
    """
    # 1. Rich types (Vector -> Vec3, QAngle -> QAngle, etc.)
    if schema_type in RICH_TYPES:
        return RICH_TYPES[schema_type][0], "rich_type"

    # 2. Primitives
    if schema_type in PRIMITIVE_MAP:
        return PRIMITIVE_MAP[schema_type][0], "primitive"

    # 3. Alias table
    if schema_type in ALIAS_TABLE:
        cpp, _ = ALIAS_TABLE[schema_type]
        return cpp, "alias"

    # 4. CHandle<T> / CEntityHandle (always CHandle)
    if schema_type.startswith("CHandle<") or schema_type.startswith("CEntityHandle"):
        return "CHandle", "handle"

    # 5. Pointers
    if schema_type.endswith("*"):
        return "void*", "pointer"

    # 6. Bitfields (size=0, type like "bitfield:3")
    if schema_type.startswith("bitfield:"):
        return None, "bitfield"

    # 7. char[N] arrays
    m = re.match(r"char\[(\d+)\]", schema_type)
    if m:
        return f"char[{m.group(1)}]", "array"

    # 8. Fixed-size arrays of known types
    m = re.match(r"([\w:]+)\[(\d+)\]", schema_type)
    if m:
        base_type = m.group(1)
        count = m.group(2)
        # Rich type arrays
        if base_type in RICH_TYPES:
            rich_name, _ = RICH_TYPES[base_type]
            return f"{rich_name}[{count}]", "array"
        if base_type in PRIMITIVE_MAP:
            return f"{PRIMITIVE_MAP[base_type][0]}[{count}]", "array"
        if base_type in ALIAS_TABLE:
            alias_cpp, _ = ALIAS_TABLE[base_type]
            if alias_cpp is not None:
                bracket = alias_cpp.find("[")
                if bracket == -1:
                    return f"{alias_cpp}[{count}]", "array"
                return None, "array"
            return None, "array"
        if base_type.startswith("CHandle"):
            return f"CHandle[{count}]", "array"
        if base_type in _all_enums:
            enum_sz = _all_enums[base_type]
            int_type = {1: "uint8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(
                enum_sz, "int32_t"
            )
            return f"{int_type}[{count}]", "array"
        return None, "array"

    # 9. Template containers
    lt = schema_type.find("<")
    if lt != -1:
        outer = schema_type[:lt]
        # CNetworkUtlVectorBase<CHandle<T>> -> CHandleVector
        if outer in ("CNetworkUtlVectorBase", "C_NetworkUtlVectorBase"):
            inner = schema_type[lt + 1:-1] if schema_type.endswith(">") else ""
            if inner.startswith("CHandle<"):
                return "CHandleVector", "template"
        if outer in CONTAINER_SIZES:
            return None, "template"
        if outer == "CHandle":
            return "CHandle", "handle"

    # 10. Enum-typed fields
    if schema_type in _all_enums:
        enum_sz = _all_enums[schema_type]
        int_type = {1: "uint8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(
            enum_sz, "int32_t"
        )
        return int_type, "enum"

    # 11. Embedded schema classes (blob)
    if schema_type in _all_classes:
        return None, "embedded"

    # 12. Unresolved — fallback to blob
    return None, "unresolved"


# ============================================================================
# JSON loading (handles dezlock-dump's sometimes-broken escapes)
# ============================================================================

def _strip_static_fields(raw: bytes) -> bytes:
    """Remove all "static_fields": [...] sections from raw JSON bytes."""
    marker = b'"static_fields"'
    close_pattern = b"\n          ]"
    result = bytearray()
    pos = 0

    while pos < len(raw):
        idx = raw.find(marker, pos)
        if idx == -1:
            result.extend(raw[pos:])
            break

        comma_pos = idx - 1
        while comma_pos > pos and raw[comma_pos] in (0x20, 0x09, 0x0A, 0x0D):
            comma_pos -= 1

        if raw[comma_pos] == ord(","):
            result.extend(raw[pos:comma_pos])
        else:
            result.extend(raw[pos:idx])

        bracket_start = raw.find(b"[", idx + len(marker))
        if bracket_start == -1:
            pos = idx + len(marker)
            continue

        close_idx = raw.find(close_pattern, bracket_start)
        if close_idx == -1:
            fallback = raw.find(b"\n        }", bracket_start)
            if fallback == -1:
                fallback = raw.find(b"\n      ]", bracket_start)
            if fallback == -1:
                pos = bracket_start
                continue
            pos = fallback
            continue

        pos = close_idx + len(close_pattern)

    return bytes(result)


def load_json(path: str) -> dict:
    """Load dezlock-dump JSON export."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("  (clean parse failed, applying byte-level sanitization...)")

    with open(path, "rb") as f:
        raw = f.read()

    raw = _strip_static_fields(raw)
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', text)
    text = re.sub(r'\\([^"\\/bfnrtu])', r'\1', text)

    return json.loads(text, strict=False)


def load_cherry_pick(script_dir: Path) -> dict:
    """Load sdk-cherry-pick.json if it exists."""
    for candidate in [
        script_dir / "sdk-cherry-pick.json",
        script_dir / "bin" / "sdk-cherry-pick.json",
    ]:
        if candidate.exists():
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, ValueError) as e:
                print(f"  Warning: Failed to parse {candidate}: {e}")
    return {}


# ============================================================================
# types.hpp generation
# ============================================================================

def generate_types_hpp(timestamp: str) -> str:
    """Generate the base types.hpp with Vec3, QAngle, CHandle, etc."""
    return f"""\
// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT
// Base SDK types matching v2 hand-written quality
// Generated: {timestamp}
#pragma once

#include <cstdint>
#include <cstddef>

namespace sdk {{

// ---- Math types ----

struct Vec2 {{
    float x, y;

    Vec2() : x(0), y(0) {{}}
    Vec2(float x, float y) : x(x), y(y) {{}}

    Vec2 operator+(const Vec2& o) const {{ return {{x + o.x, y + o.y}}; }}
    Vec2 operator-(const Vec2& o) const {{ return {{x - o.x, y - o.y}}; }}
    Vec2 operator*(float s) const {{ return {{x * s, y * s}}; }}
}};

struct Vec3 {{
    float x, y, z;

    Vec3() : x(0), y(0), z(0) {{}}
    Vec3(float x, float y, float z) : x(x), y(y), z(z) {{}}

    Vec3 operator+(const Vec3& o) const {{ return {{x + o.x, y + o.y, z + o.z}}; }}
    Vec3 operator-(const Vec3& o) const {{ return {{x - o.x, y - o.y, z - o.z}}; }}
    Vec3 operator*(float s) const {{ return {{x * s, y * s, z * s}}; }}

    float length_sqr() const {{ return x * x + y * y + z * z; }}
    float length_2d_sqr() const {{ return x * x + y * y; }}
}};

struct Vec4 {{
    float x, y, z, w;
}};

struct QAngle {{
    float pitch, yaw, roll;

    QAngle() : pitch(0), yaw(0), roll(0) {{}}
    QAngle(float p, float y, float r) : pitch(p), yaw(y), roll(r) {{}}
}};

// ---- Color ----

struct Color {{
    uint8_t r, g, b, a;
}};

// ---- Handles ----

struct CHandle {{
    uint32_t value;

    bool is_valid() const {{ return value != 0xFFFFFFFF; }}
    uint32_t index() const {{ return value & 0x7FFF; }}
    uint32_t serial() const {{ return value >> 15; }}
}};

// CNetworkUtlVectorBase<CHandle<T>> — vector of entity handles
struct CHandleVector {{
    uint8_t _data[24]; // CNetworkUtlVectorBase internal layout

    // Access as raw CHandle array (count at offset 0x0, data ptr at 0x8)
    int32_t count() const {{ return *reinterpret_cast<const int32_t*>(_data); }}
    const CHandle* data() const {{ return *reinterpret_cast<const CHandle* const*>(_data + 8); }}
}};

// ---- View matrix ----

struct ViewMatrix {{
    float m[4][4];
}};

// ---- Static asserts ----
static_assert(sizeof(Vec2) == 8);
static_assert(sizeof(Vec3) == 12);
static_assert(sizeof(Vec4) == 16);
static_assert(sizeof(QAngle) == 12);
static_assert(sizeof(Color) == 4);
static_assert(sizeof(CHandle) == 4);
static_assert(sizeof(CHandleVector) == 24);
static_assert(sizeof(ViewMatrix) == 64);

}} // namespace sdk
"""


# ============================================================================
# Per-class struct generation
# ============================================================================

def make_guard(name: str) -> str:
    guard = "SDK_GEN_" + name.upper()
    guard = re.sub(r"[^A-Z0-9_]", "_", guard)
    return guard + "_HPP"


def safe_class_name(name: str) -> str:
    """Convert a class name to a safe filename/identifier."""
    return name.replace("::", "__")


def needs_types_include(fields: list[dict]) -> bool:
    """Check if any field uses a rich type that requires types.hpp."""
    for f in fields:
        schema_type = f["type"]
        if schema_type in RICH_TYPES:
            return True
        # Check array of rich types
        m = re.match(r"([\w:]+)\[(\d+)\]", schema_type)
        if m and m.group(1) in RICH_TYPES:
            return True
        # CHandle fields
        if schema_type.startswith("CHandle<") or schema_type.startswith("CEntityHandle"):
            return True
        # CHandleVector
        lt = schema_type.find("<")
        if lt != -1:
            outer = schema_type[:lt]
            if outer in ("CNetworkUtlVectorBase", "C_NetworkUtlVectorBase"):
                inner = schema_type[lt + 1:-1] if schema_type.endswith(">") else ""
                if inner.startswith("CHandle<"):
                    return True
    return False


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
        return cursor

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
        return cursor

    return offset + size if size > 0 else offset


def get_parent_chain(cls_name: str, class_lookup: dict) -> list[str]:
    """Get the full parent chain for include generation."""
    chain = []
    current = cls_name
    seen = set()
    while current and current in class_lookup:
        if current in seen:
            break
        seen.add(current)
        parent = class_lookup[current].get("parent")
        if parent and parent in class_lookup:
            chain.append(parent)
        current = parent
    return chain


def find_include_module(class_name: str, class_to_module: dict) -> str | None:
    """Find which module a class belongs to."""
    return class_to_module.get(class_name)


def is_entity_class(cls_name: str, class_lookup: dict) -> bool:
    """Check if a class inherits from CEntityInstance (entity hierarchy)."""
    current = cls_name
    seen = set()
    while current and current in class_lookup and current not in seen:
        if current == "CEntityInstance":
            return True
        seen.add(current)
        current = class_lookup[current].get("parent")
    return False


# Maps class name -> subfolder within its module ("entities" or "structs")
_class_subfolder: dict[str, str] = {}


def get_class_subfolder(cls_name: str) -> str:
    """Get the subfolder for a class within its module directory."""
    return _class_subfolder.get(cls_name, "")


def compute_include_path(from_class: str, to_class: str,
                          class_to_module: dict) -> str:
    """Compute the relative #include path from one class file to another.

    Both classes may be in different modules and different subfolders.
    """
    from_module = class_to_module.get(from_class, "")
    to_module = class_to_module.get(to_class, "")
    from_sub = get_class_subfolder(from_class)
    to_sub = get_class_subfolder(to_class)
    to_safe = safe_class_name(to_class)

    same_module = from_module == to_module

    if same_module and from_sub == to_sub:
        # Same folder
        return f'"{to_safe}.hpp"'

    if same_module:
        # Different subfolder within same module
        if from_sub and to_sub:
            return f'"../{to_sub}/{to_safe}.hpp"'
        elif from_sub:
            # from entities/ or structs/ -> module root (shouldn't happen but handle it)
            return f'"../{to_safe}.hpp"'
        else:
            # from module root -> subfolder
            return f'"{to_sub}/{to_safe}.hpp"'

    # Different module
    if from_sub:
        # from module/subfolder/ -> need ../../other_module/[subfolder/]
        prefix = f'"../../{to_module}'
    else:
        # from module/ -> need ../other_module/[subfolder/]
        prefix = f'"../{to_module}'

    if to_sub:
        return f'{prefix}/{to_sub}/{to_safe}.hpp"'
    else:
        return f'{prefix}/{to_safe}.hpp"'


def compute_types_include(cls_name: str) -> str:
    """Compute relative path to types.hpp from a class file's location."""
    sub = get_class_subfolder(cls_name)
    if sub:
        return '"../../types.hpp"'
    return '"../types.hpp"'


def generate_struct_header(cls: dict, module_name: str, class_lookup: dict,
                           class_to_module: dict, timestamp: str) -> str:
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

    # Include types.hpp if any field uses rich types
    use_types = needs_types_include(fields)
    if use_types:
        lines.append(f'#include {compute_types_include(name)}')

    if has_parent:
        inc_path = compute_include_path(name, parent, class_to_module)
        lines.append(f'#include {inc_path}')

    lines.append(f"")

    # Open namespace
    lines.append(f"namespace sdk {{")
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

    # Cherry-pick helper methods
    helpers = _cherry_pick.get("helpers", {}).get(name, {})
    if helpers and helpers.get("methods"):
        lines.append(f"")
        lines.append(f"    // --- Helper methods (from sdk-cherry-pick.json) ---")
        for method in helpers["methods"]:
            lines.append(f"    {method}")

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
        fsize = f["size"]
        schema_type = f["type"]
        # Skip bitfields and zero-size entries
        if schema_type.startswith("bitfield:") or fsize == 0:
            continue
        lines.append(f"static_assert(offsetof({name}, {fname}) == 0x{foff:X}, \"{fname}\");")

    lines.append(f"")
    lines.append(f"}} // namespace sdk")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


# ============================================================================
# Per-module offset constants
# ============================================================================

def generate_module_offsets(classes: list[dict], module_name: str,
                            game: str, timestamp: str) -> str:
    """Generate {module}/_offsets.hpp with constexpr offset constants."""
    mod_clean = module_name.replace(".dll", "")
    guard = make_guard(f"{game}_{mod_clean}_offsets")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// Offset constants for module: {module_name}")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"")
    lines.append(f"namespace sdk::offsets::{mod_clean} {{")
    lines.append(f"")

    total_fields = 0
    for cls in sorted(classes, key=lambda c: c["name"]):
        fields = cls.get("fields", [])
        if not fields:
            continue

        lines.append(f"namespace {cls['name']} {{")
        for f in sorted(fields, key=lambda f: f["offset"]):
            total_fields += 1
            comment = f"// {f['type']} ({f['size']}b)"
            lines.append(
                f"    constexpr uint32_t {f['name']} = 0x{f['offset']:X}; {comment}"
            )
        lines.append(f"}} // {cls['name']}")
        lines.append(f"")

    lines.append(f"}} // namespace sdk::offsets::{mod_clean}")
    lines.append(f"")
    lines.append(f"// Total: {total_fields} fields")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


# ============================================================================
# Per-module enums
# ============================================================================

def generate_module_enums(enums: list[dict], module_name: str,
                          game: str, timestamp: str) -> str:
    """Generate {module}/_enums.hpp with scoped enum classes."""
    mod_clean = module_name.replace(".dll", "")
    guard = make_guard(f"{game}_{mod_clean}_enums")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// Enums for module: {module_name}")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"")
    lines.append(f"namespace sdk::enums::{mod_clean} {{")
    lines.append(f"")

    for en in sorted(enums, key=lambda e: e["name"]):
        sz = en.get("size", 4)
        underlying = {1: "uint8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(
            sz, "int32_t"
        )
        lines.append(f"enum class {en['name']} : {underlying} {{")
        for v in en.get("values", []):
            lines.append(f"    {v['name']} = {v['value']},")
        lines.append(f"}};")
        lines.append(f"")

    lines.append(f"}} // namespace sdk::enums::{mod_clean}")
    lines.append(f"")
    lines.append(f"// Total: {len(enums)} enums")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")

    return "\n".join(lines)


# ============================================================================
# Consolidated includes
# ============================================================================

def generate_all_offsets(module_names: list[str], game: str, timestamp: str) -> str:
    """Generate _all-offsets.hpp that includes all per-module offset files."""
    guard = make_guard(f"{game}_all_offsets")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// Master include for all offset constants")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    for mod_name in sorted(module_names):
        lines.append(f'#include "{mod_name}/_offsets.hpp"')
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")
    return "\n".join(lines)


def generate_all_enums(module_names: list[str], game: str, timestamp: str) -> str:
    """Generate _all-enums.hpp that includes all per-module enum files."""
    guard = make_guard(f"{game}_all_enums")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// Master include for all enums")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    for mod_name in sorted(module_names):
        lines.append(f'#include "{mod_name}/_enums.hpp"')
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")
    return "\n".join(lines)


def generate_globals_hpp(pattern_globals: dict, game: str, timestamp: str) -> str:
    """Generate _globals.hpp with pattern-scanned global pointer offsets."""
    guard = make_guard(f"{game}_globals")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// Pattern-scanned global pointer offsets (from patterns.json)")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"//")
    lines.append(f"// These are RVA offsets from the module base address.")
    lines.append(f"// Usage: uintptr_t entity_list = module_base + globals::client::dwEntityList;")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"#include <cstdint>")
    lines.append(f"")
    lines.append(f"namespace globals {{")

    total = 0
    for mod_name in sorted(pattern_globals.keys()):
        entries = pattern_globals[mod_name]
        if not entries:
            continue
        ns = mod_name.replace(".dll", "").replace(".", "_")
        lines.append(f"")
        lines.append(f"namespace {ns} {{")
        for name in sorted(entries.keys()):
            entry = entries[name]
            # Handle both new object format and legacy string format
            if isinstance(entry, dict):
                rva = entry.get("rva", "0x0")
            else:
                rva = entry  # legacy: plain hex string like "0x24AA0D8"
            lines.append(f"    constexpr uint64_t {name} = {rva};")
            total += 1
        lines.append(f"}} // namespace {ns}")

    lines.append(f"")
    lines.append(f"}} // namespace globals")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")
    return "\n".join(lines), total


def generate_patterns_hpp(pattern_globals: dict, game: str, timestamp: str) -> tuple[str, int]:
    """Generate _patterns.hpp with runtime-scannable byte patterns for global pointers."""
    guard = make_guard(f"{game}_patterns")
    lines = []
    lines.append(f"// Auto-generated by import-schema.py from dezlock-dump — DO NOT EDIT")
    lines.append(f"// Runtime-scannable patterns for global pointers (from patterns.json)")
    lines.append(f"// Generated: {timestamp}")
    lines.append(f"//")
    lines.append(f"// These patterns can be used with any IDA-style pattern scanner to resolve")
    lines.append(f"// global pointers at runtime — no hardcoded offsets needed.")
    lines.append(f"//")
    lines.append(f"// RipRelative: sig points to a MOV/LEA with RIP-relative displacement.")
    lines.append(f"//   addr = (match + rip_offset + 4) + *(int32_t*)(match + rip_offset)")
    lines.append(f"//")
    lines.append(f"// Derived: resolve the base pattern first, then scan for chain_pattern")
    lines.append(f"//   in the resolved function to extract a uint32 field offset.")
    lines.append(f"#pragma once")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append(f"")
    lines.append(f"namespace patterns {{")

    total = 0
    for mod_name in sorted(pattern_globals.keys()):
        entries = pattern_globals[mod_name]
        if not entries:
            continue

        ns = mod_name.replace(".dll", "").replace(".", "_")
        lines.append(f"")
        lines.append(f"namespace {ns} {{")

        for name in sorted(entries.keys()):
            entry = entries[name]
            if not isinstance(entry, dict):
                continue  # skip legacy string-only entries

            mode = entry.get("mode", "rip_relative")

            if mode == "derived":
                derived_from = entry.get("derived_from", "")
                chain_pattern = entry.get("chain_pattern", "")
                chain_offset = entry.get("chain_extract_offset", 0)
                lines.append(f"")
                lines.append(f"namespace {name} {{ // derived from {derived_from}")
                lines.append(f'    constexpr const char* derived_from = "{derived_from}";')
                lines.append(f'    constexpr const char* chain_pattern = "{chain_pattern}";')
                lines.append(f"    constexpr int chain_extract_offset = {chain_offset};")
                lines.append(f"}} // namespace {name}")
                total += 1
            elif "pattern" in entry:
                sig = entry["pattern"]
                rip_offset = entry.get("rip_offset", 0)
                lines.append(f"")
                lines.append(f"namespace {name} {{")
                lines.append(f'    constexpr const char* sig = "{sig}";')
                lines.append(f"    constexpr int rip_offset = {rip_offset};")
                lines.append(f"}} // namespace {name}")
                total += 1

        lines.append(f"")
        lines.append(f"}} // namespace {ns}")

    lines.append(f"")
    lines.append(f"}} // namespace patterns")
    lines.append(f"")
    lines.append(f"#endif // {guard}")
    lines.append(f"")
    return "\n".join(lines), total


def sanitize_cpp_identifier(name: str) -> str | None:
    """Sanitize a class name into a valid C++ identifier."""
    if name.startswith("?$") or name.startswith("?"):
        return None

    s = name.replace("::", "__").replace("<", "_").replace(">", "_")
    s = s.replace(",", "_").replace(" ", "_").replace("&", "_").replace("*", "_")
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")

    if not s or not s[0].isalpha() and s[0] != "_":
        s = "_" + s

    return s if s else None


def generate_all_vtables(modules: list[dict], game: str, timestamp: str) -> str:
    """Generate _all-vtables.hpp with vtable RVAs and virtual function indices."""
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
    lines.append(f"namespace sdk::vtables {{")
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

    lines.append(f"}} // namespace sdk::vtables")
    lines.append(f"")
    lines.append(f"// Total: {total_classes} vtables, {total_funcs} virtual functions")
    if skipped:
        lines.append(f"// Skipped: {skipped} classes with unrepresentable names (templates, mangled)")
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
    parser.add_argument("--output", help="Output directory (default: ./generated/<game>/)")
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
        modules = [
            m for m in modules
            if m["name"] in allowed or m["name"].replace(".dll", "") in allowed
        ]

    # Resolve output directory (fixed: use args.game not bare 'game')
    if args.output:
        out_dir = Path(args.output)
    else:
        out_dir = Path(__file__).parent / "generated" / args.game

    print(f"Output: {out_dir}")
    print(f"Modules: {len(modules)}")
    print(f"Total classes: {data.get('total_classes', '?')}")
    print(f"Total fields: {data.get('total_fields', '?')}")
    print(f"Total enums: {data.get('total_enums', '?')}")
    print()

    out_dir.mkdir(parents=True, exist_ok=True)

    # Build global class lookup (for parent resolution across modules)
    global_lookup = {}
    for mod in modules:
        for cls in mod.get("classes", []):
            global_lookup[cls["name"]] = cls

    # Build class -> module mapping
    class_to_module: dict[str, str] = {}
    for mod in modules:
        mod_clean = mod["name"].replace(".dll", "")
        for cls in mod.get("classes", []):
            class_to_module[cls["name"]] = mod_clean

    # Build enum lookup for type resolution
    global _all_enums, _all_classes, _stats, _cherry_pick
    _all_enums = {}
    for mod in modules:
        for en in mod.get("enums", []):
            _all_enums[en["name"]] = en.get("size", 4)

    # Build class name set
    _all_classes = set(global_lookup.keys())

    # Load cherry-pick config
    script_dir = Path(__file__).parent
    _cherry_pick = load_cherry_pick(script_dir)
    if _cherry_pick:
        helper_count = len(_cherry_pick.get("helpers", {}))
        print(f"Cherry-pick config loaded: {helper_count} classes with helpers")
    else:
        print("No sdk-cherry-pick.json found — generating plain structs for all classes")
    print()

    # Reset stats tracker
    _stats = ResolveStats()

    # Pre-compute subfolder assignments for ALL classes before generating headers.
    # Entity classes (CEntityInstance tree) go in entities/, others in structs/.
    # Modules with NO entity classes skip subfolders entirely (everything at root).
    global _class_subfolder
    _class_subfolder = {}

    for mod in modules:
        useful = [c for c in mod.get("classes", []) if c["size"] > 0 and c.get("fields")]
        entities = [c for c in useful if is_entity_class(c["name"], global_lookup)]
        non_entities = [c for c in useful if not is_entity_class(c["name"], global_lookup)]

        if entities and non_entities:
            # Mixed module — split into entities/ and structs/
            for c in entities:
                _class_subfolder[c["name"]] = "entities"
            for c in non_entities:
                _class_subfolder[c["name"]] = "structs"
        elif entities:
            # All entities — put in entities/ for clarity
            for c in entities:
                _class_subfolder[c["name"]] = "entities"
        # else: all structs or empty — no subfolder (stay at module root)

    # 1. Generate types.hpp
    types_content = generate_types_hpp(timestamp)
    types_path = out_dir / "types.hpp"
    types_path.write_text(types_content, encoding="utf-8")
    print(f"  types.hpp (Vec3, QAngle, CHandle, Color, ViewMatrix, CHandleVector)")

    # 2. Generate per-module struct headers + offset/enum files
    total_structs = 0
    module_names = []

    for mod in modules:
        mod_name = mod["name"].replace(".dll", "")
        classes = mod.get("classes", [])
        enums = mod.get("enums", [])

        # Filter to classes that actually have fields worth generating
        useful_classes = [c for c in classes if c["size"] > 0 and c.get("fields")]
        has_content = bool(useful_classes) or bool(enums)

        if not has_content:
            continue

        module_names.append(mod_name)

        # Create module directory
        mod_dir = out_dir / mod_name
        mod_dir.mkdir(exist_ok=True)

        # Create subdirectories if needed
        subfolders_used = set(get_class_subfolder(c["name"]) for c in useful_classes)
        subfolders_used.discard("")
        for sub in subfolders_used:
            (mod_dir / sub).mkdir(exist_ok=True)

        # Per-module offset constants (only if classes have fields)
        if useful_classes:
            offsets_content = generate_module_offsets(useful_classes, mod["name"], args.game, timestamp)
            offsets_path = mod_dir / "_offsets.hpp"
            offsets_path.write_text(offsets_content, encoding="utf-8")

        # Per-module enums
        if enums:
            enums_content = generate_module_enums(enums, mod["name"], args.game, timestamp)
            enums_path = mod_dir / "_enums.hpp"
            enums_path.write_text(enums_content, encoding="utf-8")

        # Per-class struct headers — write to correct subfolder
        mod_count = 0
        entity_count = 0
        struct_count = 0
        for cls in sorted(useful_classes, key=lambda c: c["name"]):
            header = generate_struct_header(
                cls, mod["name"], global_lookup, class_to_module, timestamp
            )
            safe_name = safe_class_name(cls["name"])
            sub = get_class_subfolder(cls["name"])
            if sub:
                filepath = mod_dir / sub / f"{safe_name}.hpp"
                if sub == "entities":
                    entity_count += 1
                else:
                    struct_count += 1
            else:
                filepath = mod_dir / f"{safe_name}.hpp"
                struct_count += 1
            filepath.write_text(header, encoding="utf-8")
            mod_count += 1

        total_structs += mod_count

        # Show breakdown
        parts = []
        if entity_count:
            parts.append(f"{entity_count} entities")
        if struct_count:
            parts.append(f"{struct_count} structs")
        enum_count = len(enums) if enums else 0
        if enum_count:
            parts.append(f"{enum_count} enums")
        print(f"  {mod['name']:30s}  {', '.join(parts)}")

    # 3. Consolidated includes
    if module_names:
        # _all-offsets.hpp
        all_offsets = generate_all_offsets(module_names, args.game, timestamp)
        (out_dir / "_all-offsets.hpp").write_text(all_offsets, encoding="utf-8")

        # _all-enums.hpp
        all_enums = generate_all_enums(module_names, args.game, timestamp)
        (out_dir / "_all-enums.hpp").write_text(all_enums, encoding="utf-8")

    # 4. _all-vtables.hpp
    vtables_content = generate_all_vtables(modules, args.game, timestamp)
    (out_dir / "_all-vtables.hpp").write_text(vtables_content, encoding="utf-8")

    vtable_count = vtables_content.count("constexpr uint32_t vtable_rva")
    vtable_func_count = vtables_content.count("constexpr int idx_")

    # 5. _globals.hpp (pattern-scanned global pointers)
    globals_count = 0
    pattern_globals = data.get("pattern_globals", {})
    if pattern_globals:
        globals_content, globals_count = generate_globals_hpp(pattern_globals, args.game, timestamp)
        (out_dir / "_globals.hpp").write_text(globals_content, encoding="utf-8")

    # 6. _patterns.hpp (runtime-scannable byte patterns)
    patterns_count = 0
    if pattern_globals:
        # Check if any entry has pattern metadata (new format with objects)
        has_patterns = any(
            isinstance(v, dict) and ("pattern" in v or v.get("mode") == "derived")
            for entries in pattern_globals.values()
            if isinstance(entries, dict)
            for v in entries.values()
        )
        if has_patterns:
            patterns_content, patterns_count = generate_patterns_hpp(
                pattern_globals, args.game, timestamp
            )
            (out_dir / "_patterns.hpp").write_text(patterns_content, encoding="utf-8")

    print(f"\n  _all-offsets.hpp: includes {len(module_names)} modules")
    print(f"  _all-enums.hpp: includes {len(module_names)} modules")
    print(f"  _all-vtables.hpp: {vtable_count} vtables, {vtable_func_count} functions")
    if globals_count:
        print(f"  _globals.hpp: {globals_count} global pointers")
    if patterns_count:
        print(f"  _patterns.hpp: {patterns_count} scannable patterns")

    # Print type resolution statistics
    _stats.print_summary()

    print(f"\nDone! {total_structs} struct headers generated.")
    print(f"Output: {out_dir}")


if __name__ == "__main__":
    main()
