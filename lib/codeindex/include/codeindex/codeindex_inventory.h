/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Public report API for the source-derived C23 capability inventory.
 *
 * This is a report over public
 * headers, their exposed symbols, verified source uses, registered-test
 * reachability, normalized function bodies, and header contract comments.
 * Nothing in the report is an authored finding: callers regenerate it from
 * the checkout with codeindex_inventory_analyze(). */

#ifndef ZCL_CODEINDEX_INVENTORY_H
#define ZCL_CODEINDEX_INVENTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum ci_inventory_duplicate_kind {
    CI_INVENTORY_DUPLICATE_EXACT_BODY = 1,
    CI_INVENTORY_DUPLICATE_ALPHA_SHAPE = 2,
};

enum ci_inventory_test_evidence {
    CI_INVENTORY_TEST_NONE = 0,
    CI_INVENTORY_TEST_SOURCE_ONLY = 1,
    CI_INVENTORY_TEST_REGISTERED_REACHABLE = 2,
};

struct ci_inventory_symbol {
    char name[128];
    char kind;
    char definition_path[256];
    int definition_line;
    char definition_evidence[40];
    char declaration_path[256];
    int declaration_line;
    char signature[512];
    char contract[256];
    int production_use_files;
    int test_use_files;
    enum ci_inventory_test_evidence test_evidence;
    char registered_test_group[128];
    bool multi_arm_definition;
    int definition_arm_count;
    bool constant_return_body;
    char constant_return_value[16];
};

struct ci_inventory_capability {
    char header[256];
    char include_token[256];
    char group[64];
    char purpose[160];
    int symbol_offset;
    int symbol_count;
    int function_count;
    int type_count;
    int macro_count;
    int production_use_files;
    int test_use_files;
    int registered_test_symbols;
    bool purpose_unproven;
};

struct ci_inventory_duplicate {
    enum ci_inventory_duplicate_kind kind;
    char symbol_a[128];
    char path_a[256];
    int line_a;
    char symbol_b[128];
    char path_b[256];
    int line_b;
    int body_tokens;
    int body_lines;
    char evidence[96];
    char proof_needed[160];
};

struct ci_inventory_invariant {
    char header[256];
    char symbol[128];
    char definition_path[256];
    int definition_line;
    char contract[256];
    int production_use_files;
    int test_use_files;
    enum ci_inventory_test_evidence test_evidence;
    char registered_test_group[128];
    bool multi_arm_definition;
    char definition_scope[40];
    char preprocessor_guard[128];
    char constant_return_evidence[40];
    bool constant_return_body;
    char constant_return_value[16];
    char verdict[16];
    char proof_needed[192];
};

struct ci_inventory_definition_arm {
    char header[256];
    char symbol[128];
    char definition_path[256];
    int definition_line;
    char preprocessor_guard[128];
    char constant_return_evidence[40];
    bool constant_return_body;
    char constant_return_value[16];
    char verdict[16];
    char proof_needed[192];
};

struct ci_inventory_test_root_gap {
    char group[128];
    char root_symbol[160];
    char reason[64];
    char verdict[16];
    char proof_needed[192];
};

struct ci_inventory_report {
    uint8_t source_root_sha3[32];
    int files_scanned;
    int production_files;
    int test_files;
    int public_headers;
    int symbols_exposed;
    int registered_test_groups;
    int registered_test_roots_found;
    int registered_test_roots_missing;
    int ambiguous_registered_test_roots;
    int unresolved_include_sites;
    int ambiguous_symbol_use_sites;
    int ambiguous_test_call_edges;
    int unresolved_symbol_definitions;
    int scanner_partial_symbols;
    int arm_baseline_symbols;

    struct ci_inventory_capability *capabilities;
    int capability_count;
    struct ci_inventory_symbol *symbols;
    int symbol_count;
    struct ci_inventory_duplicate *duplicates;
    int duplicate_count;
    struct ci_inventory_invariant *invariants;
    int invariant_count;
    struct ci_inventory_definition_arm *definition_arms;
    int definition_arm_count;
    int multi_arm_symbol_count;
    struct ci_inventory_test_root_gap *test_root_gaps;
    int test_root_gap_count;
};

/* Analyze the maintained C23 source roots plus packages/ and examples/.
 * Third-party vendor/ source and generated build output are deliberately out
 * of scope.  Returns NULL on an allocation, traversal, or stable-read error. */
struct ci_inventory_report *codeindex_inventory_analyze(const char *root);
void codeindex_inventory_free(struct ci_inventory_report *report);

/* Exact stat-bound freshness root over the same file universe.  This reads no
 * source bytes and exists only as a process-local memo key; report identity is
 * always source_root_sha3 above. */
bool codeindex_inventory_stat_root(const char *root, uint8_t out[32]);

const char *codeindex_inventory_duplicate_kind_name(
    enum ci_inventory_duplicate_kind kind);
const char *codeindex_inventory_test_evidence_name(
    enum ci_inventory_test_evidence evidence);

#endif /* ZCL_CODEINDEX_INVENTORY_H */
