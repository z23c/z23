/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact Z23 C23 ecosystem snapshot derived at call time. */
#ifndef ZCL_SCIENCE_ECOSYSTEM_H
#define ZCL_SCIENCE_ECOSYSTEM_H

#include "science/code_growth.h"
#include "science/science_corpus.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SCIENCE_ECOSYSTEM_PATH_MAX 1024u
#define SCIENCE_ECOSYSTEM_NAME_MAX 64u
#define SCIENCE_ECOSYSTEM_DETAIL_MAX 80u
#define SCIENCE_ECOSYSTEM_PACKAGES_MAX 128u
#define SCIENCE_ECOSYSTEM_CONTEXTS_MAX 32u
#define SCIENCE_ECOSYSTEM_ROOTS_MAX 16u
#define SCIENCE_ECOSYSTEM_TEXT_MAX 16384u
#define SCIENCE_ECOSYSTEM_ERROR_MAX 192u

struct science_ecosystem_named_count {
    char name[SCIENCE_ECOSYSTEM_NAME_MAX];
    char detail[SCIENCE_ECOSYSTEM_DETAIL_MAX];
    uint32_t count;
};

struct science_ecosystem_collect_options {
    bool collect_growth;
    const char *inventory_path;
};

struct science_ecosystem_snapshot {
    char source_root[SCIENCE_ECOSYSTEM_PATH_MAX];

    uint32_t package_count;
    uint32_t package_listed;
    bool packages_truncated;
    struct science_ecosystem_named_count
        packages[SCIENCE_ECOSYSTEM_PACKAGES_MAX];

    uint32_t context_count;
    uint32_t context_listed;
    bool contexts_truncated;
    struct science_ecosystem_named_count
        contexts[SCIENCE_ECOSYSTEM_CONTEXTS_MAX];

    struct science_corpus_report corpus;

    bool index_present;
    bool source_root_sha3_present;
    uint8_t source_root_sha3[32];
    uint32_t indexed_c23_files;
    uint32_t indexed_registry_nodes;
    uint32_t indexed_root_count;
    uint32_t indexed_root_listed;
    bool indexed_roots_truncated;
    struct science_ecosystem_named_count
        indexed_roots[SCIENCE_ECOSYSTEM_ROOTS_MAX];
    bool include_edges_available;
    int64_t include_edge_count;

    bool growth_present;
    char growth_error[SCIENCE_ECOSYSTEM_ERROR_MAX];
    struct science_code_growth_history growth;
};

/* Walk package manifests, feature rooms, and the maintained C23 tree at
 * `root`. Git growth is collected only when options->collect_growth is true;
 * a Git refusal names growth unavailable instead of failing the snapshot.
 * Index facts stay unset until science_ecosystem_bind_index(). */
bool science_ecosystem_collect(
    const char *root,
    const struct science_ecosystem_collect_options *options,
    struct science_ecosystem_snapshot *out,
    char *error, size_t error_cap);

void science_ecosystem_bind_index(
    struct science_ecosystem_snapshot *out, bool present,
    const uint8_t sha3[32], uint32_t c23_files, uint32_t registry_nodes,
    bool include_available, int64_t include_edges,
    const struct science_ecosystem_named_count *roots, uint32_t root_count);

void science_ecosystem_bind_growth(
    struct science_ecosystem_snapshot *out,
    const struct science_code_growth_history *history);

/* Deterministic plain-text companion. Missing evidence is named unavailable
 * or unanswered; it is never printed as a measured zero. */
bool science_ecosystem_format_text(
    const struct science_ecosystem_snapshot *snap,
    char *out, size_t cap, size_t *len);

#endif /* ZCL_SCIENCE_ECOSYSTEM_H */
