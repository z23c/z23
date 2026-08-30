/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private working-set types for the derived capability inventory. */

#ifndef ZCL_CODEINDEX_INVENTORY_INTERNAL_H
#define ZCL_CODEINDEX_INVENTORY_INTERNAL_H

#include "codeindex/codeindex_inventory.h"
#include "codeindex_priv.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct inv_path {
    char path[256];
    int64_t size;
    int64_t mtime_ns;
    int64_t ctime_ns;
    uint64_t device;
    uint64_t inode;
};

struct inv_file {
    char path[256];
    char group[64];
    char purpose[160];
    bool is_header;
    bool is_public_header;
    bool is_test;
    bool is_example;
};

struct inv_symbol_occurrence {
    struct ci_symbol symbol;
    int file_index;
};

struct inv_ref {
    char callee[128];
    char enclosing[128];
    int file_index;
    int line;
};

struct inv_include {
    char token[256];
    int file_index;
    int line;
};

struct inv_body {
    char name[128];
    char path[256];
    int file_index;
    int line;
    int end_line;
    int token_count;
    uint8_t exact_sha3[32];
    uint8_t shape_sha3[32];
    bool constant_return;
    char constant_value[16];
};

struct inv_registered_group {
    char name[128];
    char root_symbol[160];
};

struct inv_scan {
    const char *root;
    struct inv_path *paths;
    int path_count;
    int path_cap;
    struct inv_file *files;
    int file_count;
    int file_cap;
    struct inv_symbol_occurrence *occurrences;
    int occurrence_count;
    int occurrence_cap;
    struct inv_ref *refs;
    int ref_count;
    int ref_cap;
    struct inv_include *includes;
    int include_count;
    int include_cap;
    struct inv_body *bodies;
    int body_count;
    int body_cap;
    struct inv_registered_group *groups;
    int group_count;
    int group_cap;
    int scanner_partial_symbols;
    bool failed;
};

bool inv_collect_paths(struct inv_scan *scan);
bool inv_scan_all(struct inv_scan *scan, uint8_t source_root[32]);
void inv_scan_release(struct inv_scan *scan);

bool inv_read_stable(const struct inv_scan *scan, int file_index,
                     char **out, size_t *out_len);
void inv_scan_includes_and_bodies(struct inv_scan *scan, int file_index,
                                  const char *src, size_t len);
bool inv_read_registered_groups(struct inv_scan *scan);

void inv_cpy(char *dst, size_t cap, const char *src);
bool inv_is_test_path(const char *path);
bool inv_is_public_header_path(const char *path);
void inv_group_for_path(const char *path, char out[64]);

#endif /* ZCL_CODEINDEX_INVENTORY_INTERNAL_H */
