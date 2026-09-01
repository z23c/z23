/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the golden-height UTXO root ladder (chain/utxo_root_ladder.h,
 * tools/gen_utxo_root_ladder.c) and its live tripwire companion
 * (models/utxo_root_ladder_verify.h). Mirrors test_sha3_windows.c's
 * placeholder-safe structure (the generated table may legitimately hold
 * anywhere from 0 to many rungs depending on what the operator's node.db
 * copy could populate) plus test_self_folded_anchor.c's env-gated heavy
 * section for the dense mmb_root layer, which needs a real ~100 MB
 * mmb_leaves.bin fixture to exercise for real. */

#include "test/test_core.h"

#include "chain/mmb.h"
#include "chain/utxo_root_ladder.h"
#include "models/mmb_leaf_store.h"
#include "models/utxo_root_ladder_verify.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int test_utxo_root_ladder(void)
{
    int failures = 0;

    printf("\n=== test_utxo_root_ladder ===\n");

    /* (1) The table is always internally consistent, whether it is the
     * placeholder (count==0) or populated: lookup() must find every entry
     * it advertises and reject a height no entry has. */
    printf("utxo_root_ladder: lookup() agrees with the compiled table... ");
    {
        ASSERT(utxo_root_ladder_count() == g_utxo_root_ladder_count);
        for (size_t i = 0; i < g_utxo_root_ladder_count; i++) {
            const struct utxo_root_ladder_entry *e =
                utxo_root_ladder_lookup(g_utxo_root_ladder[i].height);
            ASSERT(e != NULL);
            ASSERT(e == &g_utxo_root_ladder[i]);
        }
        /* A height that is never a stride multiple and never the
         * checkpoint height must not resolve. */
        ASSERT(utxo_root_ladder_lookup(-1) == NULL);
        ASSERT(utxo_root_ladder_lookup(1234567) == NULL);
        printf("OK (count=%zu)\n", g_utxo_root_ladder_count);
    }

    /* (2) Every entry carries the provenance the generator promises:
     * SINGLE/DUAL are stride rungs (height % UTXO_ROOT_LADDER_STRIDE == 0),
     * CHECKPOINT is the one zclassicd-verified anchor and its utxo_root/
     * block_hash must never be the all-zero sentinel. */
    printf("utxo_root_ladder: every entry has a real (non-zero) root... ");
    {
        uint8_t zero[32] = {0};
        for (size_t i = 0; i < g_utxo_root_ladder_count; i++) {
            const struct utxo_root_ladder_entry *e = &g_utxo_root_ladder[i];
            ASSERT(memcmp(e->utxo_root, zero, 32) != 0);
            ASSERT(memcmp(e->block_hash, zero, 32) != 0);
            if (e->provenance == UTXO_ROOT_LADDER_SOURCE_CHECKPOINT) {
                /* The one anchor the plan requires: it must appear in the
                 * ladder. */
                ASSERT(e->height == 3056758);
            } else {
                ASSERT((e->height % UTXO_ROOT_LADDER_STRIDE) == 0);
            }
        }
        printf("OK\n");
    }

    /* (3) utxo_root_ladder_verify_against_store() on a FRESH (empty)
     * boundary-root store: every rung reports NOT_YET_REACHED and the
     * aggregate verdict is healthy (true) — an empty store is normal, not
     * a divergence. Then write the FIRST rung's exact root and confirm
     * MATCH; then corrupt it and confirm DIVERGENT flips the aggregate to
     * false. This is the real "state-wrong coin detected" tripwire this
     * lane exists to prove. */
    printf("utxo_root_ladder: verify_against_store detects match vs "
          "divergence... ");
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "utxo_root_ladder", "main");
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(coins_kv_ensure_schema(db));

        struct utxo_root_ladder_verify_result results[128];
        size_t n = 0;
        bool ok = utxo_root_ladder_verify_against_store(db, results,
                                                        sizeof(results) /
                                                            sizeof(results[0]),
                                                        &n);
        ASSERT(ok);
        ASSERT(n == g_utxo_root_ladder_count);
        for (size_t i = 0; i < n; i++)
            ASSERT(results[i].status == UTXO_ROOT_LADDER_VERIFY_NOT_YET_REACHED);

        if (g_utxo_root_ladder_count > 0) {
            const struct utxo_root_ladder_entry *rung = &g_utxo_root_ladder[0];

            ASSERT(coins_kv_boundary_root_set(db, rung->height,
                                              rung->utxo_root));
            ok = utxo_root_ladder_verify_against_store(db, results,
                                                       sizeof(results) /
                                                           sizeof(results[0]),
                                                       &n);
            ASSERT(ok);
            ASSERT(results[0].height == rung->height);
            ASSERT(results[0].status == UTXO_ROOT_LADDER_VERIFY_MATCH);

            uint8_t corrupted[32];
            memcpy(corrupted, rung->utxo_root, 32);
            corrupted[0] ^= 0xff;
            ASSERT(coins_kv_boundary_root_set(db, rung->height, corrupted));
            ok = utxo_root_ladder_verify_against_store(db, results,
                                                       sizeof(results) /
                                                           sizeof(results[0]),
                                                       &n);
            ASSERT(!ok);
            ASSERT(results[0].status == UTXO_ROOT_LADDER_VERIFY_DIVERGENT);
        }

        progress_store_close();
        test_rm_rf_recursive(dir);
        printf("OK\n");
    }

    /* (4) utxo_root_ladder_verify_against_store() rejects a NULL db
     * (defensive-coding contract: log + return false, never crash). */
    printf("utxo_root_ladder: verify_against_store rejects NULL db... ");
    {
        bool ok = utxo_root_ladder_verify_against_store(NULL, NULL, 0, NULL);
        if (!ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* (5) Dense-layer fast path: a store that does not yet cover
     * g_utxo_root_ladder_dense_height must report "not yet reached" (true),
     * never a false divergence — exercised with a tiny synthetic store so
     * this stays hermetic (no multi-MB fixture needed). When the dense
     * anchor is absent (height==-1, e.g. a freshly-regenerated placeholder
     * table with no --leaf-store given), the same call must also return
     * true trivially. */
    printf("utxo_root_ladder: verify_dense_anchor is not-yet-reached-safe... ");
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "utxo_root_ladder_dense", "main");
        char store_path[300];
        snprintf(store_path, sizeof(store_path), "%s/mmb_leaves_tiny.bin", dir);

        struct mmb_leaf_store store;
        ASSERT(mmb_leaf_store_open(&store, store_path));
        /* Append far fewer leaves than any plausible dense_height (which is
         * always in the millions once populated) — the store legitimately
         * cannot cover it yet. */
        uint8_t h[32] = {0};
        for (int i = 0; i < 3; i++) {
            h[0] = (uint8_t)i;
            ASSERT(mmb_leaf_store_append(&store, h));
        }
        ASSERT(mmb_leaf_store_remap(&store));

        uint8_t mismatch[32];
        bool ok = utxo_root_ladder_verify_dense_anchor(&store, mismatch);
        ASSERT(ok);

        mmb_leaf_store_close(&store);
        test_rm_rf_recursive(dir);
        printf("OK\n");
    }

    /* (6) HEAVY: recompute mmb_root() from a REAL mmb_leaves.bin copy
     * (millions of leaves) and confirm it reproduces the locked dense
     * anchor bit-for-bit — opt-in, mirrors test_self_folded_anchor.c's
     * ZCL_SELF_FOLD_ANCHOR_FIXTURE convention.
     *
     *   ZCL_UTXO_LADDER_HEAVY=1 \
     *   ZCL_UTXO_LADDER_LEAF_STORE=/path/to/mmb_leaves.bin \
     *     build/bin/test_parallel --only=utxo_root_ladder
     */
    printf("utxo_root_ladder: dense anchor reproduces from a real leaf "
          "store (opt-in)... ");
    {
        const char *heavy = getenv("ZCL_UTXO_LADDER_HEAVY");
        const char *store_path = getenv("ZCL_UTXO_LADDER_LEAF_STORE");
        bool run_heavy = heavy && heavy[0] && strcmp(heavy, "0") != 0;

        if (g_utxo_root_ladder_dense_height < 0) {
            printf("SKIP (no dense anchor compiled in — regenerate with "
                  "--leaf-store to populate one)\n");
        } else if (!run_heavy || !store_path || !store_path[0]) {
            printf("SKIP (set ZCL_UTXO_LADDER_HEAVY=1 and "
                  "ZCL_UTXO_LADDER_LEAF_STORE=<path to a copy of "
                  "mmb_leaves.bin> to run the real recompute)\n");
        } else {
            struct mmb_leaf_store store;
            ASSERT(mmb_leaf_store_open(&store, store_path));
            uint8_t mismatch[32] = {0};
            bool ok = utxo_root_ladder_verify_dense_anchor(&store, mismatch);
            mmb_leaf_store_close(&store);
            if (!ok) {
                printf("FAIL (recomputed mmb_root does not match the locked "
                      "dense anchor at h=%d)\n", g_utxo_root_ladder_dense_height);
                failures++;
                goto _test_next;
            }
            printf("OK (reproduced dense mmb_root @ h=%d)\n",
                  g_utxo_root_ladder_dense_height);
        }
    }

    goto _done;
_test_next:
    printf("(section aborted)\n");
_done:
    if (failures == 0)
        printf("=== test_utxo_root_ladder: all cases passed ===\n");
    else
        printf("=== test_utxo_root_ladder: %d failure(s) ===\n", failures);
    return failures;
}
