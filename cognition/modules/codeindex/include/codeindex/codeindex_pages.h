/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_CODEINDEX_PAGES_H
#define ZCL_CODEINDEX_PAGES_H

#include <stdint.h>
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

/* -1 for unavailable or corrupt storage, otherwise number returned. */
int codeindex_pages_list(struct codeindex *ci, const char *directory,
                         struct ci_page *out, int cap);
#endif
