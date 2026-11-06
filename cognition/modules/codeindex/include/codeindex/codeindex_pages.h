/* purpose: Declare import, listing and capacity of unsigned page hints in the code index. */
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_CODEINDEX_PAGES_H
#define ZCL_CODEINDEX_PAGES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
struct codeindex;
/* Stored prose is an unsigned model hint; the tree is a claim until a native
 * resolver independently binds it to a committed subject. */
struct ci_page {
    char directory[256];
    char tree_oid[65];
    char source_commit[65];
    char body[8193];
    uint8_t artifact_root[32];
};

/* Structural validation only; never establishes source freshness. */
bool codeindex_pages_validate_hints(const void *manifest, size_t size,
                                    const struct ci_page *pages, size_t count);

/* -2 if an artifact is untrusted/unavailable, -1 for a read error, otherwise
 * number returned. prior_untrusted explicitly reports an untrusted prior
 * generation even when a later import supplied some independently bound hints. */
int codeindex_pages_list(struct codeindex *ci, const char *directory,
                         struct ci_page *out, int cap, bool *prior_untrusted);
/* Like codeindex_pages_list, but a directory with more than cap rows returns the
 * first cap rows (ordered by tree, source commit, artifact root) and sets
 * *truncated instead of failing. */
int codeindex_pages_list_bounded(struct codeindex *ci, const char *directory,
                                 struct ci_page *out, int cap, bool *prior_untrusted,
                                 bool *truncated);
/* True when importing count more rows still fits the store row limit, so a
 * later rebuild can always carry every row forward. */
bool codeindex_pages_capacity_ok(struct codeindex *ci, size_t count);
/* Store bounded unsigned hints from exact manifest lines as one sealed
 * generation. This does not verify a commit or establish freshness. */
bool codeindex_pages_import_hints(struct codeindex *ci, const void *manifest,
    size_t manifest_size, const struct ci_page *pages, size_t count,
    uint8_t artifact_root[32]);
#if defined(ZCL_TESTING)
bool codeindex_pages_test_reseal(const char *dbpath);
/* Lower the store row limit for tests; 0 restores the real limit. */
void codeindex_pages_test_set_store_cap(size_t cap);
#endif
#endif
