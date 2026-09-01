/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test: block_map open-addressing lookup correctness across a
 * grow/rehash, focused on the COLLISION case.
 *
 * block_map_hash() keys off the first 8 bytes of the uint256 as a uint64 and
 * places into bucket idx = hash & (capacity - 1) (chainstate.c:17,57). Two
 * distinct hashes whose first 8 bytes are identical therefore hash to the SAME
 * initial bucket regardless of capacity, exercising the linear-probe path. The
 * grow threshold is size*4 >= capacity*3 (chainstate.c:161) over a 4096-slot
 * initial table, so inserting >=3072 entries forces a rehash from 4096->8192.
 *
 * This asserts that after the rehash every inserted hash — including the
 * deliberately colliding pair — still resolves via block_map_find to its OWN
 * distinct block_index (no shadowing across the probe chain, no key loss across
 * the rehash). The sibling test_block_map_grow_phashblock.c covers the
 * phashBlock UAF invariant; this one is distinct: it targets
 * collision-plus-lookup-after-rehash.
 */

#include "test/test_core.h"
#include "validation/chainstate.h"
#include "core/uint256.h"
#include "util/safe_alloc.h"
#include "chain/chain.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Build a block_index exactly as test_chain.c:186-195 does. */
static struct block_index *make_index(int height)
{
    struct block_index *bi =
        zcl_calloc(1, sizeof(struct block_index), "test_collision_index");
    block_index_init(bi);
    bi->nHeight = height;
    return bi;
}

int test_block_map_grow_collision(void)
{
    int failures = 0;
    TEST_CASE("block_map collision + correct lookup survives a grow/rehash") {
        /* >= 3072 forces a grow from the 4096 initial capacity; 4000 is a
         * comfortable margin past the size*4 >= capacity*3 threshold. */
        enum { N = 4000 };

        struct block_map bm;
        block_map_init(&bm);

        struct block_index **nodes =
            zcl_calloc(N, sizeof(*nodes), "test_collision_nodes");
        struct uint256 *hashes =
            zcl_calloc(N, sizeof(*hashes), "test_collision_hashes");
        ASSERT(nodes != NULL && hashes != NULL);

        /* Two deliberately COLLIDING keys: identical first 8 bytes (so they
         * land in the same initial bucket for ANY capacity) but distinct
         * beyond byte 8, so they are different uint256 keys mapping to
         * different block_index nodes. */
        struct uint256 c0, c1;
        uint256_set_null(&c0);
        uint256_set_null(&c1);
        for (int b = 0; b < 8; b++) {
            c0.data[b] = 0xA5;
            c1.data[b] = 0xA5;            /* shared low 8 bytes -> same bucket */
        }
        c0.data[8] = 0x11;                /* distinct tails -> distinct keys */
        c1.data[8] = 0x22;

        hashes[0] = c0;
        nodes[0] = make_index(700000);
        hashes[1] = c1;
        nodes[1] = make_index(700001);

        /* Sanity: the colliding pair shares the initial bucket but differs as
         * keys. Confirm via the public hash-byte contract. */
        ASSERT(memcmp(c0.data, c1.data, 8) == 0);
        ASSERT(!uint256_eq(&c0, &c1));

        ASSERT(block_map_insert(&bm, &hashes[0], nodes[0]));
        ASSERT(block_map_insert(&bm, &hashes[1], nodes[1]));

        /* Both colliding keys resolve correctly even before any grow: the
         * second must NOT shadow the first along the probe chain. */
        ASSERT(block_map_find(&bm, &hashes[0]) == nodes[0]);
        ASSERT(block_map_find(&bm, &hashes[1]) == nodes[1]);

        /* Fill out to N with distinct non-colliding keys to cross the grow
         * threshold. Vary the first 8 bytes so these land in spread buckets;
         * start the counter above the colliding pattern to stay distinct. */
        for (int i = 2; i < N; i++) {
            struct uint256 h;
            uint256_set_null(&h);
            uint64_t v = (uint64_t)i + 0x1000;   /* distinct, never the A5 run */
            memcpy(h.data, &v, sizeof(v));
            h.data[20] = 0x5A;                    /* sentinel, keeps non-null */
            hashes[i] = h;
            nodes[i] = make_index(800000 + i);
            ASSERT(block_map_insert(&bm, &hashes[i], nodes[i]));
        }

        /* The grow/rehash must have happened: 4000 > 3072 threshold. */
        ASSERT(bm.capacity >= 8192);
        ASSERT(block_map_count(&bm) == (size_t)N);

        /* AFTER the rehash, every inserted hash — including the colliding
         * pair — still finds its OWN distinct block_index with the expected
         * nHeight. */
        for (int i = 0; i < N; i++) {
            struct block_index *found = block_map_find(&bm, &hashes[i]);
            ASSERT(found == nodes[i]);
            ASSERT(found->nHeight == nodes[i]->nHeight);
        }

        /* The colliding pair specifically: still distinct, no shadowing. */
        ASSERT(block_map_find(&bm, &hashes[0]) == nodes[0]);
        ASSERT(block_map_find(&bm, &hashes[1]) == nodes[1]);
        ASSERT(nodes[0]->nHeight != nodes[1]->nHeight);

        /* A key that shares the colliding bucket but was never inserted
         * returns NULL (probe must stop, not alias the pair). */
        struct uint256 miss = c0;
        miss.data[8] = 0x33;              /* same bucket, never inserted */
        ASSERT(block_map_find(&bm, &miss) == NULL);

        for (int i = 0; i < N; i++)
            free(nodes[i]);
        free(nodes);
        free(hashes);
        block_map_free(&bm);
    } TEST_END
    return failures;
}
