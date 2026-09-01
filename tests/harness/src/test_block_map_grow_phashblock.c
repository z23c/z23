/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for the block_map phashBlock use-after-free (Option A).
 *
 * Before the fix, block_index.phashBlock pointed INTO the block_map bucket
 * array, which block_map_grow() free()s and reallocates on every rehash. A
 * lock-free reader dereferencing *phashBlock during a concurrent grow would
 * read freed memory (the live crash was FATAL SIGNAL 11 in
 * push_getheaders_from). Option A points phashBlock at per-node
 * block_index.hashBlock (the node is never freed at runtime), so a bucket
 * realloc can no longer dangle it.
 *
 * This test inserts enough DISTINCT hashes to force several block_map_grow
 * reallocations, then asserts that after the grows every node's phashBlock
 * (a) is non-NULL, (b) still resolves to the correct hash VALUE, (c) points
 * at per-node storage (&node->hashBlock), and (d) is NOT inside the bucket
 * array range. Under the old bucket-backed code, (c)/(d) would fail (or the
 * deref would crash) after a grow. It also confirms value-keyed lookups
 * still work.
 */

#include "test/test_core.h"
#include "validation/chainstate.h"
#include "core/uint256.h"
#include "util/safe_alloc.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int test_block_map_grow_phashblock(void)
{
    int failures = 0;
    TEST_CASE("block_map grow keeps phashBlock valid (UAF Option A)") {
        enum { N = 20000 };  /* > 4096 start cap -> forces multiple grows */
        struct chainstate cs;
        chainstate_init(&cs);

        struct block_index **nodes =
            zcl_calloc(N, sizeof(*nodes), "test_uaf_nodes");
        struct uint256 *hashes =
            zcl_calloc(N, sizeof(*hashes), "test_uaf_hashes");
        ASSERT(nodes != NULL && hashes != NULL);

        for (int i = 0; i < N; i++) {
            struct uint256 h;
            memset(&h, 0, sizeof(h));
            uint64_t v = (uint64_t)i + 1;       /* never zero -> not null */
            memcpy(h.data, &v, sizeof(v));
            h.data[16] = 0x5A;                   /* sentinel, stays non-null */
            hashes[i] = h;
            nodes[i] = chainstate_insert_block_index(&cs, &h);
            ASSERT(nodes[i] != NULL);
        }

        /* Capacity starts at 4096 and grows at 75% load, so 20000 distinct
         * inserts guarantee several block_map_grow reallocations. */
        ASSERT(cs.map_block_index.capacity >= 8192);

        const struct block_map_entry *buckets = cs.map_block_index.buckets;
        size_t cap = cs.map_block_index.capacity;
        const char *bkt_lo = (const char *)buckets;
        const char *bkt_hi = (const char *)(buckets + cap);

        for (int i = 0; i < N; i++) {
            struct block_index *bi = nodes[i];
            /* (a) never NULL */
            ASSERT(bi->phashBlock != NULL);
            /* (b) hash VALUE survived every grow */
            ASSERT(uint256_eq(bi->phashBlock, &hashes[i]));
            /* (c) Option A invariant: points at per-node storage */
            ASSERT(bi->phashBlock == &bi->hashBlock);
            /* (d) defensively, NOT inside the reallocatable bucket array */
            const char *p = (const char *)bi->phashBlock;
            ASSERT(p < bkt_lo || p >= bkt_hi);
            /* lock-free deref pattern: a value copy round-trips */
            struct uint256 copy = *bi->phashBlock;
            ASSERT(uint256_eq(&copy, &hashes[i]));
        }

        /* Lookups still work — keyed off the bucket's own .hash, which is
         * unaffected by Option A. */
        for (int i = 0; i < N; i += 1000) {
            ASSERT(block_map_find(&cs.map_block_index, &hashes[i]) == nodes[i]);
            ASSERT(block_map_find(&cs.map_block_index,
                                  nodes[i]->phashBlock) == nodes[i]);
        }

        free(nodes);
        free(hashes);
        chainstate_free(&cs);
    } TEST_END
    return failures;
}
