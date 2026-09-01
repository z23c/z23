/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for reindex_epilogue_derive — the post-reindex derivation that
 * closes tenacity-roadmap item 3. The load-bearing assertion KILLS the named
 * top defect: a reindex that leaves coins_applied_height stale-HIGH over a
 * freshly-rebuilt coin set manufactures the `coins_applied > hstar` coin-tear
 * shape, which (with the never-give-up unit) degrades into an infinite reindex
 * loop. The epilogue must DERIVE every durable value from the replayed mirror:
 *   - reseed coins_kv from node.db `utxos` (+ migration stamp);
 *   - recompute + stamp the SHA3 commitment;
 *   - raise coins_applied_height to tip+1 FIRST, then clamp the tip_finalize
 *     anchor + 8 stage cursors to the replayed tip via the trusted seed;
 *   - self-check H* == replayed tip.
 *
 * In-process (no spawn): an isolated progress.kv + a real <dir>/node.db with a
 * known `utxos` set + a synthetic active chain to a known tip, STALE-HIGH
 * coins_applied as the precondition tear, then assert the post-state. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "coins/utxo_commitment.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "jobs/reducer_frontier_schema.h"
#include "jobs/tip_finalize_stage.h"
#include "models/database.h"
#include "services/reindex_epilogue.h"
#include "services/seed_integrity_gate.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define RE_CHECK(name, expr) do {                              \
    printf("  reindex_epi: %s... ", (name));                   \
    if (expr) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                     \
} while (0)

struct re_chain {
    struct block_index tip;   /* one block at the high tip height */
    struct uint256     hash;
};

static void re_hash(struct uint256 *out, int h)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0xb0 + (h & 0x3F));
    out->data[1] = (uint8_t)(h & 0xFF);
    out->data[2] = (uint8_t)((h >> 8) & 0xFF);
    out->data[3] = (uint8_t)((h >> 16) & 0xFF);
}

/* Install a single synthetic block as the active tip at `tip_h`. The tip is
 * ABOVE the compiled SHA3 finality anchor so the H* hard-floor does not mask
 * the derivation (reducer_frontier clamps H* up to that anchor; below it H*
 * would pin at the floor regardless). The seed gate's linkage walk reads the
 * node.db `blocks` projection, which the fixture leaves empty (pass-with-warn),
 * so no pprev ancestry is needed. install_tip_slot sets the slot + publishes
 * the height WITHOUT a 3M-step pprev fill. */
static bool re_build_chain(struct re_chain *sc, struct main_state *ms, int tip_h)
{
    re_hash(&sc->hash, tip_h);
    block_index_init(&sc->tip);
    sc->tip.phashBlock = &sc->hash;
    sc->tip.nHeight = tip_h;
    sc->tip.nVersion = 4;
    sc->tip.nTime = 1700009000u;
    sc->tip.nBits = 0x1f07ffff;
    sc->tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    arith_uint256_set_u64(&sc->tip.nChainWork, (uint64_t)tip_h + 1);
    if (!block_map_insert(&ms->map_block_index, sc->tip.phashBlock, &sc->tip))
        return false;
    return active_chain_install_tip_slot(&ms->chain_active, &sc->tip);
}

static void re_free_chain(struct re_chain *sc)
{
    memset(sc, 0, sizeof(*sc));
}

/* Insert one row into the node.db `utxos` mirror (the replayed authority). */
static bool re_insert_utxo(struct node_db *ndb, uint8_t tag, uint32_t vout,
                           int64_t value, int32_t height, int is_coinbase)
{
    uint8_t txid[32]; memset(txid, 0, 32);
    txid[0] = tag; txid[31] = 0x5a;
    uint8_t script[5] = {0x76, 0xa9, tag, 0x88, 0xac};
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO utxos"
            "(txid,vout,value,script,script_type,height,is_coinbase) "
            "VALUES(?,?,?,?,0,?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, (int)vout);
    sqlite3_bind_int64(st, 3, value);
    sqlite3_bind_blob(st, 4, script, sizeof(script), SQLITE_STATIC);
    sqlite3_bind_int(st, 5, height);
    sqlite3_bind_int(st, 6, is_coinbase);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

/* Force one stage_cursor to a stale value (the pre-reindex torn precondition). */
static bool re_set_cursor(sqlite3 *db, const char *name, int64_t v)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, v);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static int64_t re_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int64_t out = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-fixture-verify
        out = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return out;
}

static int32_t re_trusted_base(sqlite3 *db)
{
    uint8_t blob[8] = {0}; size_t n = 0; bool found = false;
    if (!progress_meta_get(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                           blob, sizeof(blob), &n, &found) || !found || n != 8)
        return -1;
    int64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | blob[i];
    return (int32_t)v;
}

static bool re_shielded_markers_are(sqlite3 *db, int64_t want)
{
    int64_t sprout = -1, sapling = -1, nf = -1;
    bool sprout_found = false, sapling_found = false, nf_found = false;
    return anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SPROUT, &sprout, &sprout_found) &&
           anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SAPLING, &sapling, &sapling_found) &&
           nullifier_kv_activation_cursor(db, &nf, &nf_found) &&
           sprout_found && sapling_found && nf_found &&
           sprout == want && sapling == want && nf == want;
}

/* This test exercises the epilogue, not the multi-million-block replay loop.
 * Seed its exact durable completion witness directly after using the real
 * begin/reset API; production advances this key one height per block in the
 * same transaction as anchors/nullifiers. */
static bool re_seed_completed_shielded_replay(sqlite3 *db, int64_t target)
{
    char next[24];
    int n = snprintf(next, sizeof(next), "%lld", (long long)(target + 1));
    return n > 0 && (size_t)n < sizeof(next) &&
           shielded_history_begin_full_replay(db, target) &&
           progress_meta_set(db, "shielded_history.full_replay.next",
                             next, (size_t)n);
}

static int mkdir_p_re(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    return (errno == EEXIST) ? 0 : -1;
}

int test_reindex_epilogue(void);
int test_reindex_epilogue(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== reindex_epilogue tests ===\n");
    int failures = 0;
    /* Tip ABOVE the compiled SHA3 finality anchor so H* == tip is meaningful
     * (compute_hstar hard-floors H* at the anchor; a tip below it would pin
     * H* at the floor and mask the derivation under test). */
    const int TIP = (int)REDUCER_FRONTIER_TRUSTED_ANCHOR + 5;

    blocker_module_init();
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "reindex_epi", "main");
    mkdir_p_re("./test-tmp");
    mkdir_p_re(dir);

    char ndb_path[600];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

    /* node.db with a known utxos set (the replayed mirror) + a matching
     * blocks projection ABSENT at the tip (the seed gate passes-with-warn). */
    struct node_db ndb;
    bool db_ok = node_db_open(&ndb, ndb_path);
    RE_CHECK("fixture: node.db opens", db_ok);
    if (!db_ok) return failures;
    /* Point the seed gate at our node.db so the trusted-seed commitment +
     * linkage checks run against the same handle the epilogue stamps. */
    seed_integrity_gate_set_node_db_for_testing(&ndb);

    bool utxos_ok = true;
    utxos_ok &= re_insert_utxo(&ndb, 0x11, 0, 5000, 2, 1);
    utxos_ok &= re_insert_utxo(&ndb, 0x11, 1, 6000, 2, 1);
    utxos_ok &= re_insert_utxo(&ndb, 0x22, 0, 7000, 5, 0);
    utxos_ok &= re_insert_utxo(&ndb, 0x33, 0, 8000, 7, 0);
    RE_CHECK("fixture: utxos seeded", utxos_ok);

    /* Independent control: the SHA3 the epilogue should stamp. */
    uint8_t expect_root[32]; uint64_t expect_count = 0;
    utxo_commitment_sha3_compute(ndb.db, expect_root, &expect_count);
    RE_CHECK("fixture: control utxo_count == 4", expect_count == 4);

    /* progress store + active chain + tip_finalize stage. */
    RE_CHECK("fixture: progress_store opens", progress_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    RE_CHECK("fixture: pdb handle", pdb != NULL);
    uint8_t replay_nf[32] = {0x71};
    RE_CHECK("fixture: exact genesis-to-target shielded replay completed",
             re_seed_completed_shielded_replay(pdb, TIP));
    RE_CHECK("fixture: all shielded markers remain incomplete pre-epilogue",
             re_shielded_markers_are(pdb, (int64_t)TIP + 1));
    RE_CHECK("fixture: replay inserts a nullifier under positive marker",
             nullifier_kv_add(pdb, replay_nf, NULLIFIER_POOL_SAPLING, 9));

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    struct re_chain sc; memset(&sc, 0, sizeof(sc));
    RE_CHECK("fixture: synthetic chain to tip", re_build_chain(&sc, &ms, TIP));
    RE_CHECK("fixture: active height == TIP",
             active_chain_height(&ms.chain_active) == TIP);

    RE_CHECK("fixture: tip_finalize stage init", tip_finalize_stage_init(&ms));
    RE_CHECK("fixture: reducer log schema complete",
             reducer_frontier_ensure_schema(pdb));

    /* ── PRECONDITION: the pre-reindex TORN state. coins_applied stale-HIGH
     * ABOVE the rebuilt tip AND above the finality anchor (the tear generator
     * named in the KNOWN DEFECT — coins_applied > the utxo_apply frontier),
     * upstream cursors stale trailing-low (the raise-only seed must bring them
     * up to tip+1). */
    const int32_t STALE_HIGH = TIP + 1000;
    {
        char *err = NULL;
        bool seed_ok = sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
                       && coins_kv_set_applied_height_in_tx(pdb, STALE_HIGH)
                       && sqlite3_exec(pdb, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
        if (err) sqlite3_free(err);
        RE_CHECK("precond: coins_applied stale-HIGH set", seed_ok);
    }
    RE_CHECK("precond: stale tip_finalize cursor",
             re_set_cursor(pdb, "tip_finalize", 3));
    RE_CHECK("precond: stale utxo_apply cursor",
             re_set_cursor(pdb, "utxo_apply", 3));
    RE_CHECK("precond: stale validate_headers cursor",
             re_set_cursor(pdb, "validate_headers", 3));

    /* GATE-FIRES PROOF (in-test): BEFORE the epilogue, coins_applied is far
     * above the utxo_apply frontier (which sits at the anchor — no rows above
     * it) — the exact coins_applied > frontier tear shape the epilogue erases. */
    {
        int32_t ca = 0; bool found = false;
        coins_kv_get_applied_height(pdb, &ca, &found);
        int32_t ua = 0;
        bool fok = reducer_frontier_log_frontier(pdb, "utxo_apply_log",
                                                 "utxo_apply", &ua);
        RE_CHECK("precond: TEAR present (coins_applied > utxo_apply_frontier+1)",
                 found && fok && ca == STALE_HIGH && ca > ua + 1);
    }

    /* ── RUN THE EPILOGUE. Force the final NF marker write to fail after the
     * two anchor rows were updated. The one completion transaction must roll
     * all three back to positive, then an un-faulted retry may accept. */
    RE_CHECK("fixture: completion interruption trigger installs",
             sqlite3_exec(
                 pdb,
                 "CREATE TRIGGER fail_reindex_completion BEFORE INSERT ON "
                 "progress_meta WHEN NEW.key='nullifier_kv.activation_cursor' "
                 "BEGIN SELECT RAISE(ABORT,'completion interrupted'); END",
                 NULL, NULL, NULL) == SQLITE_OK);
    bool interrupted = reindex_epilogue_derive(&ms, &ndb, dir);
    RE_CHECK("interrupted epilogue refuses",
             !interrupted);
    RE_CHECK("interrupted epilogue keeps all shielded history incomplete",
             re_shielded_markers_are(pdb, (int64_t)TIP + 1));
    RE_CHECK("fixture: completion interruption trigger drops",
             sqlite3_exec(pdb, "DROP TRIGGER fail_reindex_completion",
                          NULL, NULL, NULL) == SQLITE_OK);
    bool derived = reindex_epilogue_derive(&ms, &ndb, dir);
    RE_CHECK("epilogue_derive returns true", derived);

    /* ── POST-STATE assertions (the teeth). */

    /* coins_kv reseeded from the mirror + migration stamp. */
    RE_CHECK("post: coins_kv count == mirror count (4)",
             coins_kv_count(pdb) == 4);
    RE_CHECK("post: coins_kv proven-authority (migration stamp set)",
             coins_kv_is_proven_authority(pdb, NULL));
    {
        int64_t cursor = -1;
        bool found = false, row_found = false;
        RE_CHECK("post: full reindex publishes all shielded completeness last",
                 re_shielded_markers_are(pdb, 0) &&
                 nullifier_kv_activation_cursor(pdb, &cursor, &found) &&
                 found && cursor == 0);
        RE_CHECK("post: completion publication preserves replayed nullifiers",
                 nullifier_kv_get(pdb, replay_nf, NULLIFIER_POOL_SAPLING,
                                  &row_found, NULL) && row_found);
    }

    /* coins_applied_height == tip+1 (dropped from the stale-HIGH 99). */
    {
        int32_t ca = -1; bool found = false;
        bool ok = coins_kv_get_applied_height(pdb, &ca, &found);
        RE_CHECK("post: coins_applied_height == tip+1",
                 ok && found && ca == TIP + 1);
    }

    /* tip_finalize cursor == tip (#31, NEVER tip+1). */
    RE_CHECK("post: tip_finalize cursor == tip (NOT tip+1)",
             re_cursor(pdb, "tip_finalize") == TIP);

    /* 8 upstream cursors == tip+1 (the next-height convention). */
    RE_CHECK("post: utxo_apply cursor == tip+1",
             re_cursor(pdb, "utxo_apply") == TIP + 1);
    RE_CHECK("post: validate_headers cursor == tip+1",
             re_cursor(pdb, "validate_headers") == TIP + 1);
    RE_CHECK("post: header_admit cursor == tip+1",
             re_cursor(pdb, "header_admit") == TIP + 1);
    RE_CHECK("post: body_fetch cursor == tip+1",
             re_cursor(pdb, "body_fetch") == TIP + 1);
    RE_CHECK("post: body_persist cursor == tip+1",
             re_cursor(pdb, "body_persist") == TIP + 1);
    RE_CHECK("post: script_validate cursor == tip+1",
             re_cursor(pdb, "script_validate") == TIP + 1);
    RE_CHECK("post: proof_validate cursor == tip+1",
             re_cursor(pdb, "proof_validate") == TIP + 1);

    /* trusted_base_height == tip. */
    RE_CHECK("post: reducer_trusted_base_height == tip",
             re_trusted_base(pdb) == TIP);

    /* utxo_sha3 stamp == control compute over the mirror. */
    {
        uint8_t got[32]; int32_t gh = -1; uint64_t gc = 0;
        bool ld = utxo_commitment_sha3_load(ndb.db, got, &gh, &gc);
        RE_CHECK("post: utxo_sha3 stamp present", ld);
        RE_CHECK("post: utxo_sha3 == control compute",
                 ld && memcmp(got, expect_root, 32) == 0 &&
                 gc == expect_count && gh == TIP);
    }

    /* H* == replayed tip via reducer_frontier_compute_hstar (TIP is above the
     * compiled finality anchor, so MAX(tip,anchor) == tip). */
    {
        int32_t hs = 0, sf = 0;
        progress_store_tx_lock();
        bool ok = reducer_frontier_compute_hstar(pdb, &hs, &sf);
        progress_store_tx_unlock();
        RE_CHECK("post: H* == replayed tip", ok && hs == TIP);
    }

    /* TEAR GONE: coins_applied (tip+1) is NOT above the utxo_apply frontier. */
    {
        int32_t ca = 0; bool found = false;
        coins_kv_get_applied_height(pdb, &ca, &found);
        int32_t ua = 0;
        bool fok = reducer_frontier_log_frontier(pdb, "utxo_apply_log",
                                                 "utxo_apply", &ua);
        RE_CHECK("post: NO tear (coins_applied <= utxo_apply_frontier+1)",
                 found && fok && ca <= ua + 1);
    }

    tip_finalize_stage_shutdown();
    main_state_free(&ms);
    re_free_chain(&sc);
    progress_store_close();
    seed_integrity_gate_reset_for_testing();
    node_db_close(&ndb);
    test_cleanup_tmpdir(dir);

    /* ── SNAPSHOT IMPORT REGRESSION: a verified snapshot import must derive
     * the exact same durable authority surface as the full replay path. This
     * is the fast-rebuild teeth: snapshot import is no longer just a node.db
     * mirror copy plus a coins_best_block cache write. */
    test_reset_shared_globals();
    blocker_module_init();
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();
    {
        char sdir[256];
        test_fmt_tmpdir(sdir, sizeof(sdir), "reindex_epi", "snapshot");
        mkdir_p_re(sdir);
        char snpath[600];
        snprintf(snpath, sizeof(snpath), "%s/node.db", sdir);

        struct node_db sndb;
        bool sok = node_db_open(&sndb, snpath);
        RE_CHECK("snapshot: node.db opens", sok);
        if (sok) {
            seed_integrity_gate_set_node_db_for_testing(&sndb);
            bool sutxos_ok = true;
            sutxos_ok &= re_insert_utxo(&sndb, 0x44, 0, 11000, 11, 1);
            sutxos_ok &= re_insert_utxo(&sndb, 0x55, 0, 12000, 12, 0);
            sutxos_ok &= re_insert_utxo(&sndb, 0x66, 0, 13000, 13, 0);
            RE_CHECK("snapshot: utxos seeded", sutxos_ok);

            uint8_t sexpect_root[32]; uint64_t sexpect_count = 0;
            utxo_commitment_sha3_compute(sndb.db, sexpect_root,
                                         &sexpect_count);
            RE_CHECK("snapshot: control utxo_count == 3",
                     sexpect_count == 3);

            RE_CHECK("snapshot: progress_store opens",
                     progress_store_open(sdir));
            sqlite3 *spdb = progress_store_db();
            RE_CHECK("snapshot: pdb handle", spdb != NULL);
            RE_CHECK("snapshot: shielded history starts assisted/incomplete",
                     shielded_history_reset_to_boundary(spdb, TIP));

            struct main_state sms;
            memset(&sms, 0, sizeof(sms));
            main_state_init(&sms);
            struct re_chain ssc; memset(&ssc, 0, sizeof(ssc));
            RE_CHECK("snapshot: synthetic chain to tip",
                     re_build_chain(&ssc, &sms, TIP));
            RE_CHECK("snapshot: tip_finalize stage init",
                     tip_finalize_stage_init(&sms));

            const int32_t SNAP_STALE_HIGH = TIP + 777;
            {
                char *err = NULL;
                bool seed_ok =
                    sqlite3_exec(spdb, "BEGIN IMMEDIATE", NULL, NULL, &err)
                        == SQLITE_OK &&
                    coins_kv_set_applied_height_in_tx(spdb, SNAP_STALE_HIGH) &&
                    sqlite3_exec(spdb, "COMMIT", NULL, NULL, &err)
                        == SQLITE_OK;
                if (err) sqlite3_free(err);
                RE_CHECK("snapshot: precond coins_applied stale-HIGH set",
                         seed_ok);
            }
            RE_CHECK("snapshot: precond stale tip_finalize cursor",
                     re_set_cursor(spdb, "tip_finalize", 3));
            RE_CHECK("snapshot: precond stale utxo_apply cursor",
                     re_set_cursor(spdb, "utxo_apply", 3));

            bool sderived = reindex_epilogue_derive_imported_snapshot(
                &sndb, snpath, TIP, ssc.hash.data);
            RE_CHECK("snapshot: imported epilogue returns true", sderived);

            RE_CHECK("snapshot: coins_kv count == mirror count (3)",
                     coins_kv_count(spdb) == 3);
            RE_CHECK("snapshot: coins_kv proven-authority",
                     coins_kv_is_proven_authority(spdb, NULL));
            {
                int64_t cursor = -1;
                bool found = false;
                RE_CHECK("snapshot: imported epilogue cannot publish shielded completeness",
                         re_shielded_markers_are(spdb, TIP) &&
                         nullifier_kv_activation_cursor(spdb, &cursor, &found) &&
                         found && cursor == TIP);
            }
            {
                int32_t ca = -1; bool found = false;
                bool ok = coins_kv_get_applied_height(spdb, &ca, &found);
                RE_CHECK("snapshot: coins_applied_height == tip+1",
                         ok && found && ca == TIP + 1);
            }
            RE_CHECK("snapshot: tip_finalize cursor == tip",
                     re_cursor(spdb, "tip_finalize") == TIP);
            RE_CHECK("snapshot: utxo_apply cursor == tip+1",
                     re_cursor(spdb, "utxo_apply") == TIP + 1);
            RE_CHECK("snapshot: validate_headers cursor == tip+1",
                     re_cursor(spdb, "validate_headers") == TIP + 1);
            RE_CHECK("snapshot: reducer_trusted_base_height == tip",
                     re_trusted_base(spdb) == TIP);
            {
                uint8_t got[32]; int32_t gh = -1; uint64_t gc = 0;
                bool ld = utxo_commitment_sha3_load(sndb.db, got, &gh, &gc);
                RE_CHECK("snapshot: utxo_sha3 stamp present", ld);
                RE_CHECK("snapshot: utxo_sha3 == control compute",
                         ld && memcmp(got, sexpect_root, 32) == 0 &&
                         gc == sexpect_count && gh == TIP);
            }
            {
                int32_t hs = 0, sf = 0;
                progress_store_tx_lock();
                bool ok = reducer_frontier_compute_hstar(spdb, &hs, &sf);
                progress_store_tx_unlock();
                RE_CHECK("snapshot: H* == imported tip", ok && hs == TIP);
            }

            tip_finalize_stage_shutdown();
            main_state_free(&sms);
            re_free_chain(&ssc);
            progress_store_close();
            seed_integrity_gate_reset_for_testing();
            node_db_close(&sndb);
        }
        test_cleanup_tmpdir(sdir);
    }

    /* ── NEGATIVE: empty/unreadable mirror + bad args -> false, no crash. */
    {
        /* NULL ms / ndb / datadir -> false (and the function pages + logs). */
        RE_CHECK("neg: NULL ms -> false",
                 !reindex_epilogue_derive(NULL, NULL, NULL));
        RE_CHECK("neg: imported snapshot bad args -> false",
                 !reindex_epilogue_derive_imported_snapshot(NULL, NULL, -1,
                                                            NULL));
    }
    {
        char ndir[256];
        test_fmt_tmpdir(ndir, sizeof(ndir), "reindex_epi", "neg");
        mkdir_p_re(ndir);
        char npath[600];
        snprintf(npath, sizeof(npath), "%s/node.db", ndir);
        struct node_db nndb;
        bool nok = node_db_open(&nndb, npath);
        RE_CHECK("neg: node.db opens", nok);
        if (nok) {
            seed_integrity_gate_reset_for_testing();
            seed_integrity_gate_set_node_db_for_testing(&nndb);
            progress_store_open(ndir);
            struct main_state nms; memset(&nms, 0, sizeof(nms));
            main_state_init(&nms);
            /* No active chain -> epilogue refuses cleanly (no partial clamp). */
            bool d = reindex_epilogue_derive(&nms, &nndb, ndir);
            RE_CHECK("neg: no-active-tip -> false (no partial clamp)", !d);
            int32_t nv = 0; bool nf = true;
            coins_kv_get_applied_height(progress_store_db(), &nv, &nf);
            RE_CHECK("neg: coins_applied still ABSENT (no partial write)", !nf);
            main_state_free(&nms);
            progress_store_close();
            seed_integrity_gate_reset_for_testing();
            node_db_close(&nndb);
        }
        test_cleanup_tmpdir(ndir);
    }

    blocker_reset_for_testing();
    return failures;
}
