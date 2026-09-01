/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Auxiliary UTXO/MMB consistency test — the per-height root carried in the
 * locally built MMB leaf must equal the committed coins_kv set and survive the
 * auxiliary inclusion proof. ZClassic headers do not commit this root, so this
 * test is NOT proof that peer-provided state is consensus/PoW-bound.
 *
 * This is the literal check the keystone exists to make true:
 *   "a height-H boundary leaf's utxo_root == the committed UTXO set at H".
 * It proves three things end-to-end:
 *   (1) the boundary root the live connect path records (coins_kv_commitment)
 *       round-trips through the persisted boundary table;
 *   (2) the leaf carrying that root verifies under the same auxiliary MMB root;
 *   (3) mutating one UTXO changes coins_kv_commitment, so a state-wrong coin
 *       at a height-correct boundary is detectable once local derivation or an
 *       independently trusted root supplies authority.
 */

#include "test/test_core.h"

#include "chain/mmb.h"
#include "chain/mmr.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static struct uint256 kb_txid(uint8_t tag)
{
    struct uint256 t; uint256_set_null(&t);
    t.data[0] = tag; t.data[1] = 0x7E; t.data[31] = 0x42;
    return t;
}

/* Build a deterministic block-metadata leaf for the keystone path. The caller
 * supplies the boundary utxo_root (or NULL for the zero sentinel). */
static void kb_make_leaf(struct mmb_leaf *leaf, uint32_t height,
                         const uint8_t utxo_root[32])
{
    uint8_t block_hash[32], sapling[32], work[32];
    sha3_256((const uint8_t *)&height, 4, block_hash);
    uint32_t h2 = height + 1000000; sha3_256((const uint8_t *)&h2, 4, sapling);
    uint32_t h3 = height + 2000000; sha3_256((const uint8_t *)&h3, 4, work);
    mmb_leaf_from_block(leaf, block_hash, (int32_t)height,
                        1600000000 + height * 75, 0x1d00ffff,
                        sapling, work, utxo_root);
}

/* The boundary-root persist path the tip_finalize reducer step uses runs
 * INSIDE the stage's already-open transaction (batch BEGIN IMMEDIATE +
 * per-step SAVEPOINT). Historically the own-BEGIN coins_kv_boundary_root_set
 * failed there ("cannot start a transaction within a transaction") — the
 * pre-flip 100%-WARN-storm root cause. progress_meta_set is now batch-aware
 * (SAVEPOINT nesting), so BOTH variants must succeed in that context and
 * commit atomically with the outer txn. */
static int test_boundary_root_in_tx(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "keystone_utxo_intx", "main");

    TEST("boundary utxo_root persist targets the store from inside an open txn") {
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(coins_kv_ensure_schema(db));

        uint8_t root[32];
        memset(root, 0x5c, sizeof(root));

        /* Open an explicit transaction, exactly like the stage batch does. */
        ASSERT(sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK);

        /* Both variants succeed inside an open txn: progress_meta_set is
         * batch-aware (nests as a SAVEPOINT when a transaction is already
         * open), and the explicit in-tx variant joins the caller's txn. */
        ASSERT(coins_kv_boundary_root_set(db, 200, root));
        ASSERT(coins_kv_boundary_root_set_in_tx(db, 200, root));

        /* Commit and read it back — the root persisted atomically. */
        ASSERT(sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK);

        uint8_t back[32] = {0};
        bool found = false;
        ASSERT(coins_kv_boundary_root_get(db, 200, back, &found));
        ASSERT(found);
        ASSERT(memcmp(back, root, 32) == 0);

        progress_store_close();
        PASS();
    } _test_next:;

    return failures;
}

int test_keystone_utxo_binding(void);
int test_keystone_utxo_binding(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "keystone_utxo", "main");

    int boundary = MMR_COMMITMENT_INTERVAL; /* H = 100, a real boundary */

    TEST("auxiliary boundary leaf carries the locally computed UTXO root at H") {
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(coins_kv_ensure_schema(db));

        /* A small, known coins_kv set as it would stand at height H. */
        struct uint256 a = kb_txid(0x11), b = kb_txid(0x22), c = kb_txid(0x33);
        uint8_t sc_a[4] = {0xA0,0xA1,0xA2,0xA3};
        uint8_t sc_b[2] = {0xB0,0xB1};
        ASSERT(coins_kv_add(db, a.data, 0, 5000, boundary, true,  sc_a, sizeof(sc_a)));
        ASSERT(coins_kv_add(db, a.data, 1, 6000, boundary, true,  sc_b, sizeof(sc_b)));
        ASSERT(coins_kv_add(db, b.data, 0, 7000, boundary, false, sc_a, sizeof(sc_a)));
        ASSERT(coins_kv_add(db, c.data, 0, 8000, boundary, false, NULL, 0));

        /* The boundary root the live connect path would compute + persist. */
        uint8_t root_expected[32] = {0};
        ASSERT(coins_kv_commitment(db, root_expected) == 0);
        ASSERT(coins_kv_boundary_root_set(db, boundary, root_expected));

        /* Catch-up / rebuild side reads the SAME root back — no refold. */
        uint8_t root_readback[32] = {0};
        bool found = false;
        ASSERT(coins_kv_boundary_root_get(db, boundary, root_readback, &found));
        ASSERT(found);
        ASSERT(memcmp(root_readback, root_expected, 32) == 0);

        /* Build an MMB whose boundary leaf carries that root, prove + verify. */
        struct mmb m;
        mmb_init(&m);
        uint8_t hashes[8][32];
        struct mmb_leaf leaf_at_boundary;
        memset(&leaf_at_boundary, 0, sizeof(leaf_at_boundary));
        for (int i = 0; i < 8; i++) {
            struct mmb_leaf leaf;
            /* Only the boundary index carries a non-zero root; the rest are
             * sentinels, exactly as the live path stamps them. */
            if (i == 5) {
                kb_make_leaf(&leaf, (uint32_t)boundary, root_readback);
                leaf_at_boundary = leaf;
            } else {
                kb_make_leaf(&leaf, (uint32_t)(boundary + i + 1), NULL);
            }
            mmb_hash_leaf(&leaf, hashes[i]);
            ASSERT(mmb_append(&m, &leaf) >= 0);
        }

        uint8_t mmb_root_val[32];
        mmb_root(&m, mmb_root_val);

        struct mmb_proof proof;
        ASSERT(mmb_prove((const uint8_t (*)[32])hashes, 8, 5, &proof));
        ASSERT(mmb_verify(&proof, mmb_root_val));

        /* The proven leaf hash IS the hash of the leaf carrying the boundary
         * root — i.e. the UTXO commitment is bound inside the proven object. */
        uint8_t bound_leaf_hash[32];
        mmb_hash_leaf(&leaf_at_boundary, bound_leaf_hash);
        ASSERT(memcmp(proof.leaf_hash, bound_leaf_hash, 32) == 0);

        /* Auxiliary-field assertion: the root carried in the leaf equals the
         * locally computed coins_kv set at H. ZClassic headers do not commit
         * this field or the MMB root. */
        ASSERT(memcmp(leaf_at_boundary.utxo_root, root_expected, 32) == 0);

        /* State-wrong coin is DETECTABLE: mutate one UTXO value, recompute the
         * commitment, assert it now differs from the bound root. A peer that
         * served this height-correct-but-state-wrong set could no longer match
         * the leaf's committed root. */
        ASSERT(coins_kv_spend(db, b.data, 0));
        ASSERT(coins_kv_add(db, b.data, 0, 7001, boundary, false, sc_a, sizeof(sc_a)));
        uint8_t root_mutated[32] = {0};
        ASSERT(coins_kv_commitment(db, root_mutated) == 0);
        ASSERT(memcmp(root_mutated, leaf_at_boundary.utxo_root, 32) != 0);

        /* A fabricated (forged) root that is NOT coins_kv_commitment of the set
         * cannot equal the bound leaf root either — the binding is to SHA3 over
         * the canonical set, not a free-form 32 bytes. */
        uint8_t forged[32];
        memset(forged, 0xEE, 32);
        ASSERT(memcmp(forged, leaf_at_boundary.utxo_root, 32) != 0);

        progress_store_close();
        PASS();
    } _test_next:;

    failures += test_boundary_root_in_tx();
    return failures;
}
