/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the orphan_utxo_above_tip Condition — the continuous
 * self-healer that detects UTXO rows sitting ABOVE the active chain tip
 * (reorg/rewind orphans) and heals them through the bounded
 * utxo_recovery_clean_above_tip helper.
 *
 * The Condition's detect/remedy/witness function pointers are static in
 * engine/conditions/src/orphan_utxo_above_tip.c. The only public surface is
 * register_orphan_utxo_above_tip() plus the ZCL_TESTING seams
 * (orphan_utxo_above_tip_test_set_node_db / _test_reset /
 * _test_remedy_calls). We therefore drive the Condition the canonical
 * way — through condition_engine_tick() — and assert via the engine's
 * observable state (active count, last_outcome, cleared_count,
 * remedy-call count) together with direct UTXO-row queries against the
 * fixture node_db.
 *
 * Fixture pattern reused from test_utxo_recovery_service.c: a temp
 * SQLite node_db with a `utxos` table, plus a minimal in-RAM main_state
 * chain whose tip height the Condition compares against. The db is wired
 * in via orphan_utxo_above_tip_test_set_node_db(); the tip is wired in
 * via condition_engine_set_main_state().
 */

#include "test/test_core.h"

#include "conditions/orphan_utxo_above_tip.h"
#include "core/arith_uint256.h"
#include "framework/condition.h"
#include "models/database.h"
#include "services/utxo_recovery_service.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OUT_CHECK(name, expr) do {                  \
    printf("orphan_utxo_above_tip: %s... ", (name)); \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }           \
} while (0)

/* Build a minimal linked chain in main_state with tip at height n-1. */
static void out_build_chain(struct main_state *ms, int n)
{
    struct uint256 hashes[256];
    int limit = n < 256 ? n : 256;

    for (int h = 0; h < limit; h++) {
        memset(&hashes[h], 0, sizeof(hashes[h]));
        hashes[h].data[0] = (uint8_t)(h & 0xFF);
        hashes[h].data[1] = (uint8_t)((h >> 8) & 0xFF);
        hashes[h].data[3] = 0xAB; /* distinct salt from other tests */

        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hashes[h]);
        if (!pi) continue;

        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = 1000000 + (uint32_t)h * 150;
        pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        pi->nChainTx = (uint32_t)(h + 1);
        arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));

        if (h > 0)
            pi->pprev = block_map_find(&ms->map_block_index, &hashes[h - 1]);
    }
    if (limit > 0) {
        struct block_index *tip = block_map_find(
            &ms->map_block_index, &hashes[limit - 1]);
        if (tip) active_chain_move_window_tip(&ms->chain_active, tip);
    }
}

/* Insert `count` UTXO rows all at a single height. */
static void out_insert_utxos_at(struct node_db *ndb, int base_id,
                                int height, int count)
{
    node_db_begin(ndb);
    for (int i = 0; i < count; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "INSERT INTO utxos(txid, vout, height, value, script, "
            "is_coinbase) VALUES(X'%032d', %d, %d, 100000, X'51', 0)",
            base_id + i, base_id + i, height);
        node_db_exec(ndb, sql);
    }
    node_db_commit(ndb);
}

/* Open a fresh temp node_db. Returns true on success. */
static bool out_open_db(struct node_db *ndb, const char *tag, char *path_out,
                        size_t path_cap)
{
    snprintf(path_out, path_cap, "./test-tmp/%d_orphan_%s.db",
             getpid(), tag);
    mkdir("./test-tmp", 0755);
    memset(ndb, 0, sizeof(*ndb));
    return node_db_open(ndb, path_out);
}

int test_orphan_utxo_above_tip(void)
{
    printf("\n=== orphan_utxo_above_tip condition tests ===\n");
    int failures = 0;

    /* ── 1. No orphans: utxos all at/below tip → detect false ── */
    {
        condition_engine_reset_for_testing();
        orphan_utxo_above_tip_test_reset();

        struct main_state ms;
        main_state_init(&ms);
        out_build_chain(&ms, 50); /* tip at h=49 */
        condition_engine_set_main_state(&ms);

        char db_path[256];
        struct node_db ndb;
        bool ok = out_open_db(&ndb, "noorphan", db_path, sizeof(db_path));
        if (ok) {
            /* 10 rows, all at or below tip (h=1..10). */
            out_insert_utxos_at(&ndb, 0, 5, 10);
            orphan_utxo_above_tip_test_set_node_db(&ndb);
            register_orphan_utxo_above_tip();

            condition_engine_tick();

            ok = ok && condition_engine_get_active_count() == 0;
            ok = ok && orphan_utxo_above_tip_test_remedy_calls() == 0;
            /* witness() is true (no orphans), so the engine never
             * marks the condition active. */
            OUT_CHECK("no orphans -> detect false, no remedy", ok);

            node_db_close(&ndb);
        } else {
            OUT_CHECK("no orphans (db open failed)", false);
        }
        unlink(db_path);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        orphan_utxo_above_tip_test_reset();
        main_state_free(&ms);
    }

    /* ── 2. Small overshoot heals: <=32 rows above tip ── */
    {
        condition_engine_reset_for_testing();
        orphan_utxo_above_tip_test_reset();

        struct main_state ms;
        main_state_init(&ms);
        out_build_chain(&ms, 50); /* tip at h=49 */
        condition_engine_set_main_state(&ms);

        char db_path[256];
        struct node_db ndb;
        bool ok = out_open_db(&ndb, "small", db_path, sizeof(db_path));
        if (ok) {
            /* 8 rows at tip+1 (h=50) — single-block overshoot, <=32. */
            out_insert_utxos_at(&ndb, 0, 50, 8);
            orphan_utxo_above_tip_test_set_node_db(&ndb);
            register_orphan_utxo_above_tip();

            /* cleared_count is a cumulative lifetime counter on the
             * (static) condition struct; capture a baseline and assert it
             * advances by exactly one when the heal is witnessed. */
            struct condition_runtime_snapshot pre;
            int cleared_before = 0;
            if (condition_engine_get_registered_snapshot(
                    "orphan_utxo_above_tip", &pre))
                cleared_before = pre.cleared_count;

            int64_t above_before = node_db_utxo_count(&ndb);
            condition_engine_tick();
            int64_t above_after = node_db_utxo_count(&ndb);

            /* remedy ran exactly once, returned OK, witness confirmed the
             * heal, so the engine cleared the condition. */
            ok = ok && above_before == 8;
            ok = ok && orphan_utxo_above_tip_test_remedy_calls() == 1;
            ok = ok && above_after == 0;
            ok = ok && condition_engine_get_active_count() == 0;

            struct condition_runtime_snapshot snap;
            ok = ok && condition_engine_get_registered_snapshot(
                           "orphan_utxo_above_tip", &snap);
            ok = ok && snap.cleared_count == cleared_before + 1;
            OUT_CHECK("small overshoot -> remedy OK, rows pruned, "
                      "witness true", ok);

            node_db_close(&ndb);
        } else {
            OUT_CHECK("small overshoot heals (db open failed)", false);
        }
        unlink(db_path);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        orphan_utxo_above_tip_test_reset();
        main_state_free(&ms);
    }

    /* ── 3. Oversized overshoot refuses + pages ── */
    {
        condition_engine_reset_for_testing();
        orphan_utxo_above_tip_test_reset();

        struct main_state ms;
        main_state_init(&ms);
        out_build_chain(&ms, 50); /* tip at h=49 */
        condition_engine_set_main_state(&ms);

        char db_path[256];
        struct node_db ndb;
        bool ok = out_open_db(&ndb, "big", db_path, sizeof(db_path));
        if (ok) {
            /* 40 rows at tip+1 (h=50) — exceeds the 32-row guard. */
            out_insert_utxos_at(&ndb, 0, 50, 40);
            orphan_utxo_above_tip_test_set_node_db(&ndb);
            register_orphan_utxo_above_tip();

            /* cleared_count is a cumulative lifetime counter on the
             * (static) condition struct that survives re-registration, so
             * capture a baseline and assert it does NOT advance (the
             * symptom must not clear). */
            struct condition_runtime_snapshot pre;
            int cleared_before = 0;
            if (condition_engine_get_registered_snapshot(
                    "orphan_utxo_above_tip", &pre))
                cleared_before = pre.cleared_count;

            condition_engine_tick();
            int64_t above_after = node_db_utxo_count(&ndb);

            /* remedy ran (guard refused) -> FAILED; rows remain; the
             * symptom is NOT cleared so the condition stays active. */
            ok = ok && orphan_utxo_above_tip_test_remedy_calls() == 1;
            ok = ok && above_after == 40;
            ok = ok && condition_engine_get_active_count() == 1;

            struct condition_runtime_snapshot snap;
            ok = ok && condition_engine_get_registered_snapshot(
                           "orphan_utxo_above_tip", &snap);
            ok = ok && snap.last_outcome == COND_REMEDY_FAILED;
            ok = ok && snap.cleared_count == cleared_before;
            OUT_CHECK("oversized overshoot -> remedy FAILED, witness "
                      "false (symptom persists)", ok);

            node_db_close(&ndb);
        } else {
            OUT_CHECK("oversized overshoot refuses (db open failed)", false);
        }
        unlink(db_path);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        orphan_utxo_above_tip_test_reset();
        main_state_free(&ms);
    }

    /* ── 4. Tip not established (tip_h == 0) → no false positive ── */
    {
        condition_engine_reset_for_testing();
        orphan_utxo_above_tip_test_reset();

        struct main_state ms;
        main_state_init(&ms); /* no chain built — tip is NULL/height 0 */
        condition_engine_set_main_state(&ms);

        char db_path[256];
        struct node_db ndb;
        bool ok = out_open_db(&ndb, "notip", db_path, sizeof(db_path));
        if (ok) {
            /* Rows present at high heights, but with no established tip
             * the Condition must stay quiet (boot not finalized). */
            out_insert_utxos_at(&ndb, 0, 100, 5);
            orphan_utxo_above_tip_test_set_node_db(&ndb);
            register_orphan_utxo_above_tip();

            condition_engine_tick();

            ok = ok && condition_engine_get_active_count() == 0;
            ok = ok && orphan_utxo_above_tip_test_remedy_calls() == 0;
            /* rows untouched — no heal attempted against an
             * unestablished tip. */
            ok = ok && node_db_utxo_count(&ndb) == 5;
            OUT_CHECK("tip not established -> detect false, witness true",
                      ok);

            node_db_close(&ndb);
        } else {
            OUT_CHECK("tip not established (db open failed)", false);
        }
        unlink(db_path);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        orphan_utxo_above_tip_test_reset();
        main_state_free(&ms);
    }

    return failures;
}
