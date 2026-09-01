/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Classify every indexed source into one physical product authority. */

#ifndef ZCL_CODEINDEX_CONTEXT_H
#define ZCL_CODEINDEX_CONTEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CI_CONTEXT_NAME_MAX 16
#define CI_CONTEXT_SHAPE_MAX 24
#define CI_CONTEXT_BASIS_MAX 48
#define CI_CONTEXT_MATCH_CAP 10

/* One deterministic navigation classification. This is derived source
 * metadata, never runtime, consensus, custody, or deployment authority. */
struct ci_context_assignment {
    bool production;
    bool orphan;
    bool overlap;
    char context[CI_CONTEXT_NAME_MAX];
    char shape[CI_CONTEXT_SHAPE_MAX];
    char basis[CI_CONTEXT_BASIS_MAX];
    char matches[CI_CONTEXT_MATCH_CAP][CI_CONTEXT_NAME_MAX];
    size_t match_count;
};

const char *const *codeindex_context_names(size_t *count);
/* Resolve a declared module to its physical architecture group. */
bool codeindex_module_group_path(const char *module, char out[64]);
bool codeindex_path_is_production(const char *path);
bool codeindex_context_classify(const char *path,
                                struct ci_context_assignment *out);
/* Domain-separated digest of the full navigation assignment, including basis
 * and every ordered competing match. */
bool codeindex_context_assignment_digest(
    const char *path, const struct ci_context_assignment *assignment,
    uint8_t out[32]);

#endif
