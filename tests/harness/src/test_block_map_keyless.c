/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Differential test: the keyless block_map (16-byte bucket {tag, index}, key =
 * index->hashBlock) against the frozen pre-change oracle (48-byte bucket with
 * a duplicated 32-byte key, tests/harness/differential/oracle_block_map.h).
 *
 * Same fixture into both maps: 200k synthetic block_index nodes with random
 * hashes plus adversarial keys that share their first 8 bytes (same
 * block_map_hash tag, same probe start) and keys that share only the low bits
 * (same slot at every capacity up to the mask), inserted in random order with
 * and without reserve() so several grows run.  Every present key and 100k
 * absent keys must find the same pointer; count, block_map_next order (hash
 * bytes and index) and the snapshot array must match; a duplicate insert must
 * fail in both.  The new map also refuses a NULL index and a key that differs
 * from index->hashBlock.
 */

#include "test/test_core.h"
#include "../differential/oracle_block_map.h"
#include "validation/chainstate.h"
#include <stdio.h>

enum { BMK_RANDOM = 200000, BMK_ADV_GROUPS = 400, BMK_ADV_PER = 12,
       BMK_LOWBIT = 3000, BMK_ABSENT = 100000 };
#define BMK_N (BMK_RANDOM + BMK_ADV_GROUPS * BMK_ADV_PER + BMK_LOWBIT)

static uint64_t bmk_rng = 0x9E3779B97F4A7C15ull;

static uint64_t bmk_rand(void)
{
    bmk_rng ^= bmk_rng << 13;
    bmk_rng ^= bmk_rng >> 7;
    bmk_rng ^= bmk_rng << 17;
    return bmk_rng;
}

static void bmk_rand_hash(struct uint256 *h)
{
    for (int j = 0; j < 4; j++) {
        uint64_t r = bmk_rand();
        memcpy(h->data + 8 * j, &r, 8);
    }
}

/* Fill hashes[]: random keys, then groups sharing a tag, then low-bit
 * collisions (first 8 bytes differ only above bit 20). */
static void bmk_fill_keys(struct uint256 *hashes)
{
    size_t n = 0;
    for (; n < BMK_RANDOM; n++)
        bmk_rand_hash(&hashes[n]);
    for (int g = 0; g < BMK_ADV_GROUPS; g++) {
        struct uint256 base;
        bmk_rand_hash(&base);
        for (int k = 0; k < BMK_ADV_PER; k++, n++) {
            bmk_rand_hash(&hashes[n]);
            memcpy(hashes[n].data, base.data, 8);
        }
    }
    for (int k = 0; k < BMK_LOWBIT; k++, n++) {
        bmk_rand_hash(&hashes[n]);
        uint64_t v = ((uint64_t)(bmk_rand() & 0xFFFFFFFFFFull) << 20) | 0x5A5A5u;
        memcpy(hashes[n].data, &v, 8);
    }
}

static void bmk_shuffle(size_t *order, size_t n)
{
    for (size_t i = 0; i < n; i++)
        order[i] = i;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)(bmk_rand() % (i + 1));
        size_t t = order[i];
        order[i] = order[j];
        order[j] = t;
    }
}

static bool bmk_same_probe(const struct block_map *nm,
                           const struct oracle_block_map *om,
                           const struct uint256 *k)
{
    return block_map_find(nm, k) == oracle_block_map_find(om, k);
}

static bool bmk_compare_walk(const struct block_map *nm,
                             const struct oracle_block_map *om)
{
    size_t ni = 0, oi = 0;
    const struct uint256 *nh, *oh;
    struct block_index *nx, *ox;
    for (;;) {
        bool a = block_map_next(nm, &ni, &nh, &nx);
        bool b = oracle_block_map_next(om, &oi, &oh, &ox);
        if (a != b)
            return false;
        if (!a)
            return ni == oi;
        if (nx != ox || memcmp(nh->data, oh->data, 32) != 0 || ni != oi)
            return false;
    }
}

static bool bmk_compare_snapshot(const struct block_map *nm,
                                 const struct oracle_block_map *om)
{
    struct block_index **na = NULL, **oa = NULL;
    size_t nn = 0, on = 0;
    bool ok = block_map_snapshot_indices(nm, &na, &nn) &&
              oracle_block_map_snapshot_indices(om, &oa, &on) && nn == on &&
              (nn == 0 || memcmp(na, oa, nn * sizeof(*na)) == 0);
    free(na);
    free(oa);
    return ok;
}

/* Insert every key in random order into both maps (optionally reserved). */
static bool bmk_build(struct block_map *nm, struct oracle_block_map *om,
                      struct block_index *nodes, const struct uint256 *hashes,
                      bool with_reserve)
{
    if (with_reserve &&
        !(block_map_reserve(nm, BMK_N) && oracle_block_map_reserve(om, BMK_N) &&
          nm->capacity == om->capacity))
        return false;
    size_t *order = zcl_malloc(BMK_N * sizeof(*order), "bmk_order");
    if (!order)
        return false;
    bmk_shuffle(order, BMK_N);
    bool ok = true;
    for (size_t i = 0; ok && i < BMK_N; i++) {
        size_t k = order[i];
        bool a = block_map_insert(nm, &hashes[k], &nodes[k]);
        bool b = oracle_block_map_insert(om, &hashes[k], &nodes[k]);
        ok = a && b && nm->capacity == om->capacity;
    }
    free(order);
    return ok && block_map_count(nm) == oracle_block_map_count(om) &&
           block_map_count(nm) == BMK_N;
}

/* Present keys and absent keys (some sharing a present key's tag). */
static bool bmk_check_finds(const struct block_map *nm,
                            const struct oracle_block_map *om,
                            struct block_index *nodes,
                            const struct uint256 *hashes)
{
    for (size_t i = 0; i < BMK_N; i++)
        if (!bmk_same_probe(nm, om, &hashes[i]) ||
            block_map_find(nm, &hashes[i]) != &nodes[i])
            return false;
    for (size_t i = 0; i < BMK_ABSENT; i++) {
        struct uint256 k;
        bmk_rand_hash(&k);
        if (i % 4 == 0)
            memcpy(k.data, hashes[bmk_rand() % BMK_N].data, 8);
        if (block_map_find(nm, &k) != NULL || !bmk_same_probe(nm, om, &k))
            return false;
    }
    return true;
}

/* Duplicate insert fails in both; the new map also refuses a NULL index and
 * a key that differs from index->hashBlock, leaving the map untouched. */
static bool bmk_check_refusals(struct block_map *nm,
                               struct oracle_block_map *om,
                               struct block_index *nodes,
                               const struct uint256 *hashes)
{
    size_t before = block_map_count(nm);
    if (block_map_insert(nm, &hashes[7], &nodes[7]) ||
        oracle_block_map_insert(om, &hashes[7], &nodes[7]) ||
        block_map_count(nm) != before ||
        block_map_count(nm) != oracle_block_map_count(om))
        return false;
    struct block_index stray;
    block_index_init(&stray);
    stray.hashBlock = hashes[3];
    struct uint256 other = hashes[3];
    other.data[31] ^= 1;
    return !block_map_insert(nm, &other, &stray) &&
           !block_map_insert(nm, &other, NULL) &&
           block_map_count(nm) == BMK_N;
}

/* One full differential pass.  Returns true when every comparison matched. */
static bool bmk_run(struct block_index *nodes, const struct uint256 *hashes,
                    bool with_reserve)
{
    struct block_map nm;
    struct oracle_block_map om;
    block_map_init(&nm);
    oracle_block_map_init(&om);
    bool ok = bmk_build(&nm, &om, nodes, hashes, with_reserve) &&
              bmk_check_finds(&nm, &om, nodes, hashes) &&
              bmk_compare_walk(&nm, &om) && bmk_compare_snapshot(&nm, &om) &&
              bmk_check_refusals(&nm, &om, nodes, hashes);
    block_map_free(&nm);
    oracle_block_map_free(&om);
    return ok;
}

static int bmk_memory_case(void);

int test_block_map_keyless(void)
{
    int failures = 0;
    TEST_CASE("block_map keyless buckets match the frozen 48-byte oracle") {
        struct block_index *nodes =
            zcl_calloc(BMK_N, sizeof(*nodes), "bmk_nodes");
        struct uint256 *hashes =
            zcl_calloc(BMK_N, sizeof(*hashes), "bmk_hashes");
        ASSERT(nodes != NULL && hashes != NULL);
        bmk_fill_keys(hashes);
        for (size_t i = 0; i < BMK_N; i++) {
            block_index_init(&nodes[i]);
            nodes[i].hashBlock = hashes[i];
            nodes[i].phashBlock = &nodes[i].hashBlock;
            nodes[i].nHeight = (int32_t)i;
        }
        ASSERT(bmk_run(nodes, hashes, false));
        ASSERT(bmk_run(nodes, hashes, true));
        free(nodes);
        free(hashes);
    } TEST_END
    failures += bmk_memory_case();
    return failures;
}

static int bmk_memory_case(void)
{
    int failures = 0;
    TEST_CASE("block_map keyless bucket memory at 3.3M entries") {
        struct block_map nm;
        struct oracle_block_map om;
        block_map_init(&nm);
        oracle_block_map_init(&om);
        ASSERT(block_map_reserve(&nm, 3300000));
        ASSERT(oracle_block_map_reserve(&om, 3300000));
        ASSERT(nm.capacity == om.capacity);
        size_t nb = nm.capacity * sizeof(struct block_map_entry);
        size_t ob = om.capacity * sizeof(struct oracle_block_map_entry);
        printf("  [block_map memory] 3.3M entries capacity=%zu old=%zu MB "
               "new=%zu MB saved=%zu MB\n", nm.capacity, ob >> 20, nb >> 20,
               (ob - nb) >> 20);
        ASSERT(ob == (size_t)384 << 20);
        ASSERT(nb == (size_t)128 << 20);
        block_map_free(&nm);
        oracle_block_map_free(&om);
    } TEST_END
    return failures;
}
