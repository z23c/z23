/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Test fixture for struct block_index entries that need merkle root, nonce or
 * solution fields. Those fields live in the optional block_index_hdrext;
 * tbi_ext() gives a test the extension for an entry, creating it on first
 * use. Every extension created here stays on one static list, so a test that
 * never tears its index array down does not leak (the list keeps them
 * reachable) and tbi_ext_release_all() frees them together with their
 * solutions when a test wants to. */

#ifndef TEST_BLOCK_INDEX_EXT_FIXTURE_H
#define TEST_BLOCK_INDEX_EXT_FIXTURE_H

#include "chain/chain.h"
#include "util/safe_alloc.h"

struct tbi_ext_node {
    struct block_index_hdrext ext;
    struct tbi_ext_node *next;
};

static struct tbi_ext_node *g_tbi_ext_head;

static inline struct block_index_hdrext *tbi_ext(struct block_index *bi)
{
    if (bi->ext)
        return bi->ext;
    struct tbi_ext_node *n = zcl_calloc(1, sizeof(*n), "test_block_index_ext");
    if (!n)
        abort();
    n->next = g_tbi_ext_head;
    g_tbi_ext_head = n;
    bi->ext = &n->ext;
    return bi->ext;
}

/* Frees every extension (and its solution). Entries that still point at one
 * must not be read afterwards. */
static inline void tbi_ext_release_all(void)
{
    while (g_tbi_ext_head) {
        struct tbi_ext_node *n = g_tbi_ext_head;
        g_tbi_ext_head = n->next;
        free(n->ext.nSolution);
        free(n);
    }
}

#endif
