/**
 * dezlock-dump — Vtable Member Offset Analyzer
 *
 * Decodes 128-byte function prologues captured by RTTI to extract
 * this-pointer member access patterns. Reveals field offsets for any
 * class with virtual functions — no PDB needed.
 *
 * Runs as post-processing in main.cpp, merges results into the JSON
 * data object for inclusion in _all-modules.json.
 */

#pragma once

#include <string>
#include "vendor/json.hpp"

struct MemberAnalysisStats {
    int modules_analyzed = 0;
    int classes_analyzed = 0;
    int total_fields = 0;
    int total_accesses = 0;
};

// Analyze vtable function prologues across all modules in the JSON data.
// Merges a "member_layouts" top-level key into `data` in-place.
// Multi-threaded per-module processing.
MemberAnalysisStats analyze_members(nlohmann::json& data);
