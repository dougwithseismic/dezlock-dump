/**
 * dezlock-dump -- C++ port of generate-signatures.py
 *
 * Generates byte pattern signatures from vtable function prologue bytes
 * captured by dezlock-dump. Masks relocatable bytes, detects stubs,
 * deduplicates COMDAT-folded functions, and computes shortest unique
 * prefixes at both module and per-class levels.
 *
 * Called directly from the main exe with already-parsed JSON data.
 */

#pragma once

#include <string>
#include "vendor/json.hpp"

struct SignatureStats {
    int total = 0;
    int unique = 0;
    int class_unique = 0;
    int stubs = 0;
    int duplicates = 0;
};

SignatureStats generate_signatures(const nlohmann::json& data, const std::string& output_dir, int min_length = 6);
