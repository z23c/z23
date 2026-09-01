/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for sync integrity and audit features:
 *   - SHA3 UTXO checkpoint verification logic
 *   - UTXO count sanity check logic
 *   - XOR commitment save/load/compare roundtrip
 *   - bg_hash_verification_service state machine
 *   - Stall recovery window expansion */

#include "test/test_core.h"
#include "net/net.h"
#include "coins/utxo_commitment.h"
#include "chain/checkpoints.h"
#include "services/authority_projection_audit.h"
#include "services/bg_validation_service.h"
#include "services/bg_hash_verification_service.h"
#include "sync/sync_planner.h"
#include "services/utxo_recovery_service.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "validation/main_state.h"
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

/* ── Helper: open in-memory SQLite with node_state + utxos tables ── */

static sqlite3 *open_test_db(void)
{
    sqlite3 *db = NULL;
    sqlite3_open(":memory:", &db);
    sqlite3_exec(db,
        "CREATE TABLE node_state (key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE utxos ("
        "  txid BLOB, vout INT, value INT, script BLOB,"
        "  script_type INT, address_hash BLOB, height INT, is_coinbase INT);",
        NULL, NULL, NULL);
    return db;
}

/* ── SHA3 UTXO checkpoint tests ──────────────────────────────────── */

static int test_integrity_sha3_checkpoint_exists(void)
{
    int failures = 0;

    TEST("integrity: SHA3 UTXO checkpoint is available") {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        ASSERT(cp != NULL);
        ASSERT(cp->height > 0);
        ASSERT(cp->utxo_count > 0);
        ASSERT(cp->total_supply > 0);

        /* SHA3 hash should not be all-zero */
        uint8_t zero[32] = {0};
        ASSERT(memcmp(cp->sha3_hash, zero, 32) != 0);
        ASSERT(memcmp(cp->block_hash, zero, 32) != 0);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_sha3_empty_db(void)
{
    int failures = 0;

    TEST("integrity: SHA3 of empty UTXO set is deterministic") {
        sqlite3 *db = open_test_db();
        uint8_t hash1[32], hash2[32];
        uint64_t count1 = 0, count2 = 0;

        utxo_commitment_sha3_compute(db, hash1, &count1);
        utxo_commitment_sha3_compute(db, hash2, &count2);

        ASSERT(count1 == 0);
        ASSERT(count2 == 0);
        ASSERT(memcmp(hash1, hash2, 32) == 0);

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_sha3_deterministic_with_data(void)
{
    int failures = 0;

    TEST("integrity: SHA3 is deterministic over same UTXO set") {
        sqlite3 *db = open_test_db();

        /* Insert two UTXOs */
        uint8_t txid1[32] = {0}, txid2[32] = {0};
        txid1[0] = 0x11;
        txid2[0] = 0x22;
        sqlite3_stmt *ins = NULL;
        sqlite3_prepare_v2(db,
            "INSERT INTO utxos (txid, vout, value, script, script_type,"
            " address_hash, height, is_coinbase)"
            " VALUES (?, ?, ?, X'76A914', 1, X'00', ?, 0)",
            -1, &ins, NULL);

        sqlite3_bind_blob(ins, 1, txid1, 32, SQLITE_STATIC);
        sqlite3_bind_int(ins, 2, 0);
        sqlite3_bind_int64(ins, 3, 50000000);
        sqlite3_bind_int(ins, 4, 100);
        sqlite3_step(ins);
        sqlite3_reset(ins);

        sqlite3_bind_blob(ins, 1, txid2, 32, SQLITE_STATIC);
        sqlite3_bind_int(ins, 2, 1);
        sqlite3_bind_int64(ins, 3, 25000000);
        sqlite3_bind_int(ins, 4, 200);
        sqlite3_step(ins);
        sqlite3_finalize(ins);

        uint8_t hash1[32], hash2[32];
        uint64_t count1 = 0, count2 = 0;
        utxo_commitment_sha3_compute(db, hash1, &count1);
        utxo_commitment_sha3_compute(db, hash2, &count2);

        ASSERT(count1 == 2);
        ASSERT(count2 == 2);
        ASSERT(memcmp(hash1, hash2, 32) == 0);

        /* Different from empty set */
        sqlite3 *db2 = open_test_db();
        uint8_t empty_hash[32];
        uint64_t empty_count = 0;
        utxo_commitment_sha3_compute(db2, empty_hash, &empty_count);
        ASSERT(memcmp(hash1, empty_hash, 32) != 0);

        sqlite3_close(db2);
        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_sha3_save_load_roundtrip(void)
{
    int failures = 0;

    TEST("integrity: SHA3 save/load roundtrip preserves data") {
        sqlite3 *db = open_test_db();
        uint8_t hash[32];
        memset(hash, 0xAB, 32);

        ASSERT(utxo_commitment_sha3_save(db, hash, 3056758, 1350000));

        uint8_t loaded[32] = {0};
        int32_t height = 0;
        uint64_t count = 0;
        ASSERT(utxo_commitment_sha3_load(db, loaded, &height, &count));
        ASSERT(memcmp(hash, loaded, 32) == 0);
        ASSERT(height == 3056758);
        ASSERT(count == 1350000);

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

/* ── XOR commitment save/load/compare tests ──────────────────────── */

static int test_integrity_xor_save_load_roundtrip(void)
{
    int failures = 0;

    TEST("integrity: XOR commitment save/load roundtrip") {
        sqlite3 *db = open_test_db();

        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0x77, 32);
        utxo_commitment_add(&uc, txid, 3, 42000000, 999);

        ASSERT(utxo_commitment_save_checkpoint(db, &uc));

        struct utxo_commitment loaded;
        ASSERT(utxo_commitment_load_checkpoint(db, &loaded));
        ASSERT(utxo_commitment_equal(&uc, &loaded));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_load_missing(void)
{
    int failures = 0;

    TEST("integrity: XOR load returns false when no checkpoint saved") {
        sqlite3 *db = open_test_db();

        struct utxo_commitment uc;
        ASSERT(!utxo_commitment_load_checkpoint(db, &uc));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

/* ── Height-tracked checkpoint (UTXO_COMMITMENT_HEIGHT_KEY) ─────────
 * Backs the boot-flight-recorder lane's incremental XOR checkpoint fix:
 * utxo_mirror_delta_apply / mirror_rebuild_from_coins_kv stamp a covering
 * height alongside the checkpoint so utxo_commitment_boot_check_and_refresh
 * can skip its O(n) `utxos` scan when the stamp is already trustworthy. */

static int test_integrity_xor_at_height_roundtrip(void)
{
    int failures = 0;

    TEST("integrity: XOR checkpoint save/load AT a covering height") {
        sqlite3 *db = open_test_db();

        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0x55, 32);
        utxo_commitment_add(&uc, txid, 1, 7000000, 500);

        ASSERT(utxo_commitment_save_checkpoint_at_height(db, &uc, 500));

        struct utxo_commitment loaded;
        int32_t h = -1;
        ASSERT(utxo_commitment_load_checkpoint_at_height(db, &loaded, &h));
        ASSERT(utxo_commitment_equal(&uc, &loaded));
        ASSERT(h == 500);

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_plain_save_clears_height(void)
{
    int failures = 0;

    TEST("integrity: plain save_checkpoint clears a prior height stamp") {
        sqlite3 *db = open_test_db();

        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0x66, 32);
        utxo_commitment_add(&uc, txid, 0, 1000, 10);

        /* Stamp a height, then overwrite via the PLAIN (no covering-height
         * claim) save — the load_checkpoint_at_height reader must now
         * refuse to trust ANY height (even the stale one), because a
         * downstream incremental maintainer folding deltas on top of a
         * height that doesn't actually describe this blob would silently
         * corrupt the accumulator (see utxo_mirror_delta_apply). */
        ASSERT(utxo_commitment_save_checkpoint_at_height(db, &uc, 500));
        ASSERT(utxo_commitment_save_checkpoint(db, &uc));

        struct utxo_commitment loaded;
        int32_t h = -1;
        ASSERT(!utxo_commitment_load_checkpoint_at_height(db, &loaded, &h));
        /* The blob itself is still intact via the plain loader. */
        ASSERT(utxo_commitment_load_checkpoint(db, &loaded));
        ASSERT(utxo_commitment_equal(&uc, &loaded));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_boot_check_fast_path_no_scan(void)
{
    int failures = 0;

    TEST("integrity: boot_check_and_refresh fast path skips the O(n) scan "
         "when the height stamp matches") {
        sqlite3 *db = open_test_db();

        /* A checkpoint claiming h=200, but the `utxos` TABLE itself is
         * empty/wrong — if the fast path actually recomputed, it would
         * disagree and refresh. It must NOT recompute at all when the
         * stamp matches mirror_height, so the (deliberately wrong-vs-table)
         * saved digest survives untouched. */
        struct utxo_commitment uc;
        utxo_commitment_init(&uc);
        uint8_t txid[32];
        memset(txid, 0x77, 32);
        utxo_commitment_add(&uc, txid, 2, 42, 199);
        ASSERT(utxo_commitment_save_checkpoint_at_height(db, &uc, 200));

        struct utxo_commitment computed;
        bool refreshed = true;
        ASSERT(utxo_commitment_boot_check_and_refresh(db, 200, &computed, &refreshed));
        ASSERT(!refreshed);
        ASSERT(utxo_commitment_equal(&computed, &uc));

        /* The on-disk checkpoint must be BYTE-IDENTICAL to before — a fast
         * path that touched it would defeat the whole point. */
        struct utxo_commitment still_saved;
        ASSERT(utxo_commitment_load_checkpoint(db, &still_saved));
        ASSERT(utxo_commitment_equal(&still_saved, &uc));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_boot_check_slow_path_refreshes(void)
{
    int failures = 0;

    TEST("integrity: boot_check_and_refresh slow path recomputes + "
         "re-stamps on a genuine mismatch") {
        sqlite3 *db = open_test_db();

        /* Stale checkpoint: no height stamp at all (plain save), and it
         * disagrees with the live `utxos` table below. */
        struct utxo_commitment stale;
        utxo_commitment_init(&stale);
        uint8_t stale_txid[32];
        memset(stale_txid, 0x88, 32);
        utxo_commitment_add(&stale, stale_txid, 0, 1, 1);
        ASSERT(utxo_commitment_save_checkpoint(db, &stale));

        sqlite3_exec(db,
            "INSERT INTO utxos (txid, vout, value, script, script_type,"
            " address_hash, height, is_coinbase)"
            " VALUES (X'9900000000000000000000000000000000000000000000000000000000000000',"
            " 0, 500000, X'76A914', 1, X'00', 300, 0)",
            NULL, NULL, NULL);

        struct utxo_commitment computed;
        bool refreshed = false;
        ASSERT(utxo_commitment_boot_check_and_refresh(db, 300, &computed, &refreshed));
        ASSERT(refreshed);

        struct utxo_commitment ground_truth;
        utxo_commitment_compute_db(db, &ground_truth);
        ASSERT(utxo_commitment_equal(&computed, &ground_truth));

        /* Re-stamped at the asserted mirror_height (300) — a subsequent
         * incremental maintainer can now trust it as a baseline. */
        struct utxo_commitment restamped;
        int32_t h = -1;
        ASSERT(utxo_commitment_load_checkpoint_at_height(db, &restamped, &h));
        ASSERT(h == 300);
        ASSERT(utxo_commitment_equal(&restamped, &ground_truth));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_verify_db_match(void)
{
    int failures = 0;

    TEST("integrity: XOR verify_db matches compute_db for same data") {
        sqlite3 *db = open_test_db();

        /* Insert a UTXO */
        sqlite3_exec(db,
            "INSERT INTO utxos (txid, vout, value, script, script_type,"
            " address_hash, height, is_coinbase)"
            " VALUES (X'DEAD000000000000000000000000000000000000000000000000000000000000',"
            " 0, 100000, X'76A914', 1, X'00', 50, 0)",
            NULL, NULL, NULL);

        struct utxo_commitment computed;
        utxo_commitment_compute_db(db, &computed);
        ASSERT(computed.count > 0);

        /* Verify should pass against itself */
        ASSERT(utxo_commitment_verify_db(db, &computed));

        /* Verify should fail against a wrong commitment */
        struct utxo_commitment wrong;
        utxo_commitment_init(&wrong);
        ASSERT(!utxo_commitment_verify_db(db, &wrong));

        sqlite3_close(db);
        PASS();
    } _test_next:;

    return failures;
}

/* ── UTXO count sanity check tests ───────────────────────────────── */

static int test_integrity_utxo_count_check(void)
{
    int failures = 0;

    TEST("integrity: UTXO count sanity check logic") {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        if (!cp) { PASS(); goto _test_next; }

        /* Simulate count within 10% — should be OK */
        uint64_t good_count = cp->utxo_count;
        double ratio = (double)good_count / (double)cp->utxo_count;
        ASSERT(ratio >= 0.9 && ratio <= 1.1);

        /* Count off by 20% — should trigger warning */
        uint64_t warn_count = (uint64_t)(cp->utxo_count * 0.8);
        ratio = (double)warn_count / (double)cp->utxo_count;
        ASSERT(ratio < 0.9);
        struct utxo_count_check_result warn =
            utxo_recovery_classify_count_check(
                cp->height, cp->height, cp->utxo_count, warn_count);
        ASSERT(warn.level == UTXO_COUNT_CHECK_WARNING);

        /* Count off by 60% — should trigger critical */
        uint64_t crit_count = (uint64_t)(cp->utxo_count * 0.4);
        ratio = (double)crit_count / (double)cp->utxo_count;
        ASSERT(ratio < 0.5);
        struct utxo_count_check_result crit =
            utxo_recovery_classify_count_check(
                cp->height, cp->height, cp->utxo_count, crit_count);
        ASSERT(crit.level == UTXO_COUNT_CHECK_CRITICAL);

        /* Far past the checkpoint, current UTXO count can legitimately
         * drift; the operator needs a stale-reference diagnostic, not a
         * corruption warning. */
        struct utxo_count_check_result stale =
            utxo_recovery_classify_count_check(
                cp->height + 10000, cp->height, cp->utxo_count, warn_count);
        ASSERT(stale.level == UTXO_COUNT_CHECK_INFO_STALE_REFERENCE);

        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_xor_mismatch_policy(void)
{
    int failures = 0;

    TEST("integrity: XOR mismatch classifier splits stale vs corruption") {
        /* Growth past the checkpoint = the set advanced while tracking
         * was frozen (bulk import): stale, refresh — never a candidate. */
        ASSERT(!utxo_recovery_xor_mismatch_is_corruption_candidate(42, 43));
        ASSERT(!utxo_recovery_xor_mismatch_is_corruption_candidate(
            1000000, 1300000));
        /* Equal counts with a differing accumulator (callers only invoke
         * this on a mismatch) = same cardinality, different contents:
         * the clearest corruption signature. */
        ASSERT(utxo_recovery_xor_mismatch_is_corruption_candidate(42, 42));
        /* Shrink below the checkpoint = rows vanished: a
         * silent keyspace-tail truncation class. */
        ASSERT(utxo_recovery_xor_mismatch_is_corruption_candidate(43, 42));
        ASSERT(utxo_recovery_xor_mismatch_is_corruption_candidate(
            1300000, 900000));
        PASS();
    } _test_next:;

    return failures;
}

/* ── bg_hash_verification_service tests ──────────────────────────── */

static int test_integrity_bg_hash_verify_init(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify initializes to idle state") {
        struct bg_hash_verification_service svc;
        bg_hash_verify_init(&svc, NULL, NULL, "/tmp", NULL);

        ASSERT(!svc.thread_started);
        ASSERT(!atomic_load(&svc.stop_requested));

        struct bg_hash_verify_progress p = bg_hash_verify_get_progress(&svc);
        ASSERT(p.state == BG_HASH_VERIFY_IDLE);
        ASSERT(p.verified_height == 0);
        ASSERT(p.chain_height == 0);
        ASSERT(p.mismatches == 0);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_hash_verify_owns_datadir(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify owns the caller's datadir bytes") {
        /* Boot resolves the net-specific datadir into a stack buffer that is
         * gone before the worker preads a body. Retaining that pointer aliased
         * a dead frame straight into the blk path. */
        char caller_path[512];
        snprintf(caller_path, sizeof(caller_path), "%s", "/tmp");
        struct bg_hash_verification_service svc;
        bg_hash_verify_init(&svc, NULL, NULL, caller_path, NULL);
        memset(caller_path, 0xA5, sizeof(caller_path));
        ASSERT(svc.datadir == svc.datadir_storage);
        ASSERT_STR_EQ(svc.datadir, "/tmp");

        /* No datadir => refuse, rather than walk every height, read nothing,
         * and publish "0 mismatches". */
        char oversized[sizeof(svc.datadir_storage) + 1u];
        memset(oversized, 'x', sizeof(oversized) - 1u);
        oversized[sizeof(oversized) - 1u] = '\0';
        struct main_state ms;
        main_state_init(&ms);
        bg_hash_verify_init(&svc, &ms, NULL, oversized, NULL);
        ASSERT(svc.datadir == NULL);
        ASSERT(svc.datadir_storage[0] == '\0');
        ASSERT(!bg_hash_verify_start(&svc).ok);
        ASSERT(!svc.thread_started);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_hash_verify_state_names(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify state names are correct") {
        ASSERT_STR_EQ(bg_hash_verify_state_name(BG_HASH_VERIFY_IDLE), "idle");
        ASSERT_STR_EQ(bg_hash_verify_state_name(BG_HASH_VERIFY_RUNNING), "running");
        ASSERT_STR_EQ(bg_hash_verify_state_name(BG_HASH_VERIFY_COMPLETE), "complete");
        ASSERT_STR_EQ(bg_hash_verify_state_name(BG_HASH_VERIFY_FAILED), "failed");
        ASSERT_STR_EQ(bg_hash_verify_state_name(99), "unknown");
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_hash_verify_no_start_without_ms(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify refuses to start without main_state") {
        struct bg_hash_verification_service svc;
        bg_hash_verify_init(&svc, NULL, NULL, "/tmp", NULL);

        ASSERT(!bg_hash_verify_start(&svc).ok);
        ASSERT(!svc.thread_started);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_hash_verify_supervisor_contract(void)
{
    int failures = 0;

    TEST("integrity: bg_hash_verify registers a chain supervisor contract") {
        bool ok = true;
        supervisor_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);
        struct bg_hash_verification_service svc;
        bg_hash_verify_init(&svc, &ms, NULL, "/tmp", NULL);

        struct zcl_result r = bg_hash_verify_start(&svc);
        ok = ok && r.ok;
        if (r.ok) {
            struct supervisor_snapshot snaps[SUPERVISOR_CAP];
            int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
            const struct supervisor_snapshot *hash = NULL;
            for (int i = 0; i < n; i++) {
                if (strcmp(snaps[i].name, "chain.bg_hash_verify") == 0) {
                    hash = &snaps[i];
                    break;
                }
            }
            ok = ok && hash != NULL;
            if (hash)
                ok = ok && hash->period_secs == 0;
            bg_hash_verify_stop(&svc);
            ok = ok && supervisor_child_count_total() == 0;
        }

        main_state_free(&ms);
        supervisor_reset_for_testing();
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_bg_validation_supervisor_contract(void)
{
    int failures = 0;

    TEST("integrity: bg_validation registers a chain supervisor contract") {
        bool ok = true;
        supervisor_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);
        struct bg_validation_service svc;
        bg_validation_init(&svc, &ms, NULL, "/tmp", NULL);

        ok = ok && bg_validation_start(&svc);
        if (ok) {
            struct supervisor_snapshot snaps[SUPERVISOR_CAP];
            int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
            const struct supervisor_snapshot *valid = NULL;
            for (int i = 0; i < n; i++) {
                if (strcmp(snaps[i].name, "chain.bg_validation") == 0) {
                    valid = &snaps[i];
                    break;
                }
            }
            ok = ok && valid != NULL;
            if (valid)
                ok = ok && valid->period_secs == 0;
            bg_validation_stop(&svc);
            ok = ok && supervisor_child_count_total() == 0;
        }

        main_state_free(&ms);
        supervisor_reset_for_testing();
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

/* ── Stall recovery window expansion tests ───────────────────────── */

static int test_integrity_stall_recovery_plan(void)
{
    int failures = 0;

    TEST("integrity: stall recovery plans getheaders action") {
        struct sync_getheaders_action action;
        struct sync_stall_recovery recovery;

        memset(&action, 0, sizeof(action));
        memset(&recovery, 0, sizeof(recovery));

        /* No recovery → no action */
        syncsvc_plan_recovery_getheaders(&action, &recovery, NULL);
        ASSERT(!action.should_send);

        /* Active recovery → should send */
        recovery.should_recover = true;
        syncsvc_plan_recovery_getheaders(&action, &recovery, NULL);
        ASSERT(action.should_send);
        ASSERT(action.anchor == SYNC_HEADER_REQUEST_TIP);

        /* With tip parent request */
        struct block_index tip, parent;
        memset(&tip, 0, sizeof(tip));
        memset(&parent, 0, sizeof(parent));
        tip.pprev = &parent;
        recovery.should_request_tip_parent = true;
        syncsvc_plan_recovery_getheaders(&action, &recovery, &tip);
        ASSERT(action.should_send);
        ASSERT(action.anchor == SYNC_HEADER_REQUEST_TIP_PARENT);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_stall_recovery_anchor(void)
{
    int failures = 0;

    TEST("integrity: stall recovery anchor selection") {
        struct sync_stall_recovery recovery;
        memset(&recovery, 0, sizeof(recovery));

        /* Not recovering → TIP */
        ASSERT(syncsvc_recovery_header_anchor(&recovery, NULL) ==
               SYNC_HEADER_REQUEST_TIP);

        /* Recovering without tip parent → TIP */
        recovery.should_recover = true;
        ASSERT(syncsvc_recovery_header_anchor(&recovery, NULL) ==
               SYNC_HEADER_REQUEST_TIP);

        /* Recovering with tip parent → TIP_PARENT */
        struct block_index tip, parent;
        memset(&tip, 0, sizeof(tip));
        memset(&parent, 0, sizeof(parent));
        tip.pprev = &parent;
        recovery.should_request_tip_parent = true;
        ASSERT(syncsvc_recovery_header_anchor(&recovery, &tip) ==
               SYNC_HEADER_REQUEST_TIP_PARENT);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_valid_block_at_tip(void)
{
    int failures = 0;

    TEST("integrity: valid block triggers AT_TIP when headers caught up") {
        struct sync_block_acceptance result;
        struct p2p_node node;

        memset(&node, 0, sizeof(node));
        node.starting_height = 1000;
        node.state = PEER_SYNCING_BLOCKS;

        /* Not yet at peer tip */
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 999, 1500, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.reached_peer_tip);

        /* At peer tip, headers caught up */
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 1000, 1001, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(result.reached_peer_tip);
        ASSERT(result.should_set_sync_state);
        ASSERT(result.next_sync_state == SYNC_AT_TIP);
        ASSERT(result.should_update_peer_state);
        ASSERT(result.next_peer_state == PEER_ACTIVE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_integrity_progress_snapshot(void)
{
    int failures = 0;

    TEST("integrity: progress snapshot collects sync metrics") {
        struct sync_progress_snapshot snap;

        syncsvc_collect_progress(&snap, NULL, SYNC_BLOCKS_DOWNLOAD,
                                 500, 1000, 0, 0);
        ASSERT(snap.sync_state == SYNC_BLOCKS_DOWNLOAD);
        ASSERT(snap.chain_height == 500);
        ASSERT(snap.header_height == 1000);
        ASSERT(snap.should_log_progress);

        /* AT_TIP should not log progress */
        syncsvc_collect_progress(&snap, NULL, SYNC_AT_TIP,
                                 1000, 1000, 0, 0);
        ASSERT(!snap.should_log_progress);

        /* AT_TIP with stale tip */
        syncsvc_collect_progress(&snap, NULL, SYNC_AT_TIP,
                                 1000, 1000, 100, 800);
        ASSERT(snap.tip_stale);
        ASSERT(snap.tip_stale_seconds == 700);
        PASS();
    } _test_next:;

    return failures;
}

/* ── Registration ─────────────────────────────────────────────────── */

/* ── Authority(coins)-vs-projection(utxos) redundant cross-check ─────── */

/* Find the named blocker in the process registry; copy its reason. */
static bool find_blocker_reason(const char *id, char *reason_out, size_t cap)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, id) == 0) {
            if (reason_out && cap)
                snprintf(reason_out, cap, "%s", snaps[i].reason);
            return true;
        }
    }
    return false;
}

static int test_integrity_ap_audit_match_no_fire(void)
{
    int failures = 0;

    TEST("integrity: ap-audit matching authority/projection does NOT fire") {
        ap_audit_reset_for_test();

        uint8_t root[32];
        for (int i = 0; i < 32; i++) root[i] = (uint8_t)(i * 7 + 1);

        struct ap_audit_inputs in;
        memset(&in, 0, sizeof(in));
        in.comparable = true;
        in.height = 3176325;
        memcpy(in.auth_root, root, 32);
        memcpy(in.proj_root, root, 32);
        in.auth_count = 1300000;
        in.proj_count = 1300000;

        struct ap_audit_verdict v;
        ap_audit_evaluate(&in, &v);
        ASSERT(!v.violated);

        /* Even repeated clean verdicts must never raise the blocker. */
        ASSERT(!ap_audit_apply_verdict(&v, in.height, in.auth_count,
                                       in.proj_count, in.auth_root,
                                       in.proj_root));
        ASSERT(!ap_audit_apply_verdict(&v, in.height, in.auth_count,
                                       in.proj_count, in.auth_root,
                                       in.proj_root));
        ASSERT(!find_blocker_reason("authority_projection_divergence",
                                    NULL, 0));

        /* A non-comparable input (heights disagreed / moved mid-scan) is a
         * clean no-violation, never a false fire. */
        struct ap_audit_inputs nc = in;
        nc.comparable = false;
        nc.auth_count = 42; /* would differ, but not comparable */
        struct ap_audit_verdict vnc;
        ap_audit_evaluate(&nc, &vnc);
        ASSERT(!vnc.violated);

        ap_audit_reset_for_test();
        PASS();
    } _test_next:;
    return failures;
}

static int test_integrity_ap_audit_divergence_fires(void)
{
    int failures = 0;

    TEST("integrity: ap-audit planted divergence raises blocker w/ both roots") {
        ap_audit_reset_for_test();

        uint8_t auth_root[32], proj_root[32];
        for (int i = 0; i < 32; i++) {
            auth_root[i] = (uint8_t)(i + 1);   /* authority */
            proj_root[i] = (uint8_t)(0xF0 + i); /* projection — different */
        }
        char auth_hex[65] = {0}, proj_hex[65] = {0};
        for (int i = 0; i < 32; i++) {
            snprintf(auth_hex + i * 2, 3, "%02x", auth_root[i]);
            snprintf(proj_hex + i * 2, 3, "%02x", proj_root[i]);
        }

        struct ap_audit_inputs in;
        memset(&in, 0, sizeof(in));
        in.comparable = true;
        in.height = 3176326;
        memcpy(in.auth_root, auth_root, 32);
        memcpy(in.proj_root, proj_root, 32);
        in.auth_count = 1300001;
        in.proj_count = 1300000; /* also a count mismatch */

        struct ap_audit_verdict v;
        ap_audit_evaluate(&in, &v);
        ASSERT(v.violated);
        ASSERT(v.root_mismatch);
        ASSERT(v.count_mismatch);

        /* First confirmation sample: streak=1 — must NOT raise yet. */
        bool raised1 = ap_audit_apply_verdict(&v, in.height, in.auth_count,
                                              in.proj_count, in.auth_root,
                                              in.proj_root);
        ASSERT(!raised1);
        ASSERT(!find_blocker_reason("authority_projection_divergence", NULL, 0));

        /* Second consecutive sample: streak=2 — raises the PERMANENT blocker. */
        bool raised2 = ap_audit_apply_verdict(&v, in.height, in.auth_count,
                                              in.proj_count, in.auth_root,
                                              in.proj_root);
        ASSERT(raised2);

        char reason[BLOCKER_REASON_MAX];
        ASSERT(find_blocker_reason("authority_projection_divergence",
                                   reason, sizeof(reason)));
        /* The alarm names BOTH roots + the height. */
        ASSERT(strstr(reason, auth_hex) != NULL);
        ASSERT(strstr(reason, proj_hex) != NULL);
        ASSERT(strstr(reason, "3176326") != NULL);

        /* A subsequent clean pass self-clears the latch. */
        struct ap_audit_verdict clean;
        memset(&clean, 0, sizeof(clean));
        ASSERT(!ap_audit_apply_verdict(&clean, in.height, in.auth_count,
                                       in.auth_count, in.auth_root,
                                       in.auth_root));
        ASSERT(!find_blocker_reason("authority_projection_divergence", NULL, 0));

        ap_audit_reset_for_test();
        PASS();
    } _test_next:;
    return failures;
}

int test_integrity(void)
{
    int failures = 0;

    /* SHA3 UTXO checkpoint verification */
    failures += test_integrity_sha3_checkpoint_exists();
    failures += test_integrity_sha3_empty_db();
    failures += test_integrity_sha3_deterministic_with_data();
    failures += test_integrity_sha3_save_load_roundtrip();

    /* XOR commitment persistence */
    failures += test_integrity_xor_save_load_roundtrip();
    failures += test_integrity_xor_load_missing();
    failures += test_integrity_xor_at_height_roundtrip();
    failures += test_integrity_xor_plain_save_clears_height();
    failures += test_integrity_xor_boot_check_fast_path_no_scan();
    failures += test_integrity_xor_boot_check_slow_path_refreshes();
    failures += test_integrity_xor_verify_db_match();

    /* UTXO count sanity check */
    failures += test_integrity_utxo_count_check();

    /* XOR mismatch stale-vs-corruption classifier */
    failures += test_integrity_xor_mismatch_policy();

    /* bg_hash_verification_service */
    failures += test_integrity_bg_hash_verify_init();
    failures += test_integrity_bg_hash_verify_owns_datadir();
    failures += test_integrity_bg_hash_verify_state_names();
    failures += test_integrity_bg_hash_verify_no_start_without_ms();
    failures += test_integrity_bg_hash_verify_supervisor_contract();
    failures += test_integrity_bg_validation_supervisor_contract();

    /* Redundant authority(coins)-vs-projection(utxos) cross-check */
    failures += test_integrity_ap_audit_match_no_fire();
    failures += test_integrity_ap_audit_divergence_fires();

    /* Stall recovery and sync integrity */
    failures += test_integrity_stall_recovery_plan();
    failures += test_integrity_stall_recovery_anchor();
    failures += test_integrity_valid_block_at_tip();
    failures += test_integrity_progress_snapshot();

    return failures;
}
