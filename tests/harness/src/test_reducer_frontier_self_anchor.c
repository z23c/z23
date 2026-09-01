/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reducer_frontier_self_anchor — Pillar 3 sourcing: THE trust anchor
 * reducer_frontier_floor()/reducer_frontier_compute_hstar() operate at now
 * PREFERS a self-derived anchor marker (the SHA3-verified
 * <datadir>/utxo-anchor.snapshot artifact the SAME in-fold self-mint hook
 * production uses, services/anchor_selfmint.h) over the baked
 * REDUCER_FRONTIER_TRUSTED_ANCHOR literal — see the "SELF-DERIVED SOURCING"
 * note on that macro in jobs/reducer_frontier.h.
 *
 * THE PROPERTY THIS PROVES:
 *   (1) ABSENT marker (fresh datadir, nothing minted yet) -> the floor falls
 *       back to the compiled checkpoint height, byte-identical to before this
 *       lane.
 *   (2) PRESENT + verified marker -> the floor resolves to the self-derived
 *       height (which equals the compiled height today by construction).
 *   (3) PRESENT but torn/mismatched marker (on-disk corruption after the
 *       fact) -> REFUSED, never adopted; the floor falls back to the
 *       compiled literal, exactly like the absent case — never a borrowed or
 *       torn anchor, never a crash.
 *
 * Reuses the anchor_selfmint fixture pattern (test_anchor_selfmint.c): a
 * lowered test checkpoint override + a handful of real coins_kv rows whose
 * REAL commitment IS the override root, so the production hook mints/verifies
 * identically to the 1.35M-row case. reducer_frontier_test_reset_self_derived_
 * anchor is the test-only hook that clears the process-lifetime resolve
 * cache between cases (the cache is intentionally resolved AT MOST ONCE per
 * process in production — see reducer_frontier.c). */

#include "test/test_core.h"

#include "jobs/reducer_frontier.h"
#include "services/anchor_selfmint.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "chain/checkpoints.h"
#include "util/util.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Test-only hooks — src-private forward decls, same convention as every other
 * consumer of reducer_frontier_test_set_compiled_anchor. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);
void reducer_frontier_test_reset_self_derived_anchor(void);

#define RFSA_CHECK(name, expr) do {                                         \
    if (expr) { printf("  reducer_frontier_self_anchor: %s... OK\n", (name)); } \
    else { printf("  reducer_frontier_self_anchor: %s... FAIL\n", (name));  \
           failures++; }                                                    \
} while (0)

#define TEST_ANCHOR ((int32_t)9182736)

static bool rfsa_seed_coins(sqlite3 *db)
{
    for (int i = 0; i < 5; i++) {
        uint8_t txid[32];
        for (int j = 0; j < 32; j++) txid[j] = (uint8_t)(0x30 + i * 11 + j);
        uint8_t script[5] = { 0x76, 0xa9, 0x14, (uint8_t)i, 0x88 };
        if (!coins_kv_add(db, txid, /*vout=*/(uint32_t)i,
                          /*value=*/200000 + i, /*height=*/i + 1,
                          /*is_coinbase=*/i == 0, script, sizeof(script)))
            return false;
    }
    return true;
}

int test_reducer_frontier_self_anchor(void);
int test_reducer_frontier_self_anchor(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier_self_anchor", "main");

    /* Leave the reducer_frontier compiled-anchor TEST OVERRIDE at its -1
     * sentinel (never call reducer_frontier_test_set_compiled_anchor here):
     * that override short-circuits reducer_frontier_compiled_anchor() before
     * it ever reaches the self-derived-anchor code this test exercises. We
     * instead lower the REAL compiled checkpoint via the sha3-override, the
     * same knob production's own get_sha3_utxo_checkpoint() reads. */
    SetDataDir(dir);

    RFSA_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    RFSA_CHECK("pdb handle", pdb != NULL);
    RFSA_CHECK("coins_kv schema", pdb && coins_kv_ensure_schema(pdb));
    RFSA_CHECK("seed coins", pdb && rfsa_seed_coins(pdb));

    uint8_t real_root[32] = {0};
    RFSA_CHECK("commitment computed",
               pdb && coins_kv_commitment(pdb, real_root) == 0);
    int64_t num_txs = 0, real_count = 0, supply = 0;
    RFSA_CHECK("setinfo",
               pdb && coins_kv_setinfo(pdb, &num_txs, &real_count, &supply));

    struct sha3_utxo_checkpoint cp_ovr;
    memset(&cp_ovr, 0, sizeof(cp_ovr));
    cp_ovr.height = TEST_ANCHOR;
    memcpy(cp_ovr.sha3_hash, real_root, 32);
    cp_ovr.utxo_count = (uint64_t)real_count;
    cp_ovr.total_supply = supply;
    checkpoints_set_sha3_override_for_test(&cp_ovr);

    char snap_path[400];
    snprintf(snap_path, sizeof(snap_path), "%s/utxo-anchor.snapshot", dir);
    setenv("ZCL_MINT_ANCHOR_OUT", snap_path, 1);
    unlink(snap_path);

    reducer_frontier_test_reset_self_derived_anchor();

    /* (1) ABSENT marker (nothing minted yet) -> falls back to the compiled
     * checkpoint, which the override has pinned to TEST_ANCHOR. */
    RFSA_CHECK("(1) no marker -> floor falls back to compiled",
               reducer_frontier_floor() == TEST_ANCHOR);

    /* (2) Mint the verified snapshot via the SAME in-fold hook production
     * runs, reset the process-lifetime resolve cache, and confirm the floor
     * still lands on TEST_ANCHOR — now SOURCED from the self-derived marker
     * rather than only the baked literal. */
    RFSA_CHECK("(2) self-mint hook writes a verified snapshot",
               pdb != NULL);
    if (pdb)
        anchor_selfmint_hook_in_tx(pdb, dir, TEST_ANCHOR);
    {
        struct anchor_snapshot_status st;
        bool ok = anchor_selfmint_snapshot_status(dir, &st);
        RFSA_CHECK("(2) minted artifact verifies against the checkpoint",
                   ok && st.verified);
    }
    reducer_frontier_test_reset_self_derived_anchor();
    RFSA_CHECK("(2) marker present -> floor resolves via self-derived anchor",
               reducer_frontier_floor() == TEST_ANCHOR);

    /* (3) MISMATCH: flip the last byte of the verified artifact (guaranteed
     * to land in the record body, never the fixed-size header) so its
     * recomputed SHA3 no longer reproduces the compiled checkpoint. The
     * resolver must REFUSE it (never adopt, never FATAL — this is a
     * read-only path) and the floor must still fall back to the compiled
     * literal, exactly like case (1). */
    {
        FILE *f = fopen(snap_path, "r+b");
        RFSA_CHECK("(3) snapshot reopened for corruption", f != NULL);
        if (f) {
            RFSA_CHECK("(3) seek to last byte", fseek(f, -1, SEEK_END) == 0);
            int c = fgetc(f);
            RFSA_CHECK("(3) last byte read", c != EOF);
            fseek(f, -1, SEEK_CUR);
            fputc(c ^ 0xFF, f);
            fclose(f);
        }
    }
    {
        struct anchor_snapshot_status st;
        bool ok = anchor_selfmint_snapshot_status(dir, &st);
        RFSA_CHECK("(3) corrupted artifact fails verification",
                   ok && !st.verified);
    }
    reducer_frontier_test_reset_self_derived_anchor();
    RFSA_CHECK("(3) mismatched marker refused -> floor still == compiled",
               reducer_frontier_floor() == TEST_ANCHOR);

    /* Teardown. */
    checkpoints_set_sha3_override_for_test(NULL);
    unsetenv("ZCL_MINT_ANCHOR_OUT");
    unlink(snap_path);
    reducer_frontier_test_reset_self_derived_anchor();
    SetDataDir("");
    progress_store_close();
    return failures;
}
