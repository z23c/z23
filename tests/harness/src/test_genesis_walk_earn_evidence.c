/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A node that folds from genesis and follows through the reducer holds a
 * LOCAL_IMPORT active-tip record with ancestry + chainwork only. The genesis
 * walk must earn the best-work and body-bytes flags for the exact tip it
 * verified (bound by HASH) before bg_validation_authority_publish publishes
 * full-history authority. These tests drive the real publisher over a real
 * coins store and controller:
 *   - the completed walk publishes (red before the change);
 *   - each invariant has a refusal case that leaves the record untouched;
 *   - after publication the node advances through live advance and restarts
 *     without losing authority or going back to review. */

#include "test/test_core.h"
#include "test/test_block_map.h"

#include "chain/chain.h"
#include "coins/coins_view.h"
#include "models/block.h"
#include "models/database.h"
#include "services/bg_validation_authority.h"
#include "services/bg_validation_service.h"
#include "services/chain_evidence_authority_service.h"
#include "services/chain_state_service.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#define GW_BLOCKS 6
#define GW_TIP 3

/* One assertion: returns the failure count to add (0 or 1). */
static int gw_check(const char *label, bool cond)
{
    if (cond)
        return 0;
    printf("  FAIL: %s\n", label);
    return 1;
}

struct gw_fixture {
    char dir[256];
    struct node_db ndb;
    struct main_state ms;
    struct block_index *header_tip;
    struct coins_view_cache coins_tip;
    struct chain_evidence_controller authority;
    struct bg_validation_service svc;
    struct uint256 hashes[GW_BLOCKS];
    struct block_index blocks[GW_BLOCKS];
};

static void gw_seed_coins(void)
{
    sqlite3 *pdb = progress_store_db();
    uint8_t txid[32];
    memset(txid, 0x77, sizeof(txid));
    (void)coins_kv_ensure_schema(pdb);
    (void)progress_meta_table_ensure(pdb);
    /* The frontier derive reads both stage logs for a hash witness; empty
     * tables mean "height authoritative, hash unwitnessed", which is all the
     * publisher needs. */
    sqlite3_exec(pdb,  // raw-sql-ok:test-fixture-seeding
                 "CREATE TABLE IF NOT EXISTS validate_headers_log ("
                 "height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
                 "ok INTEGER NOT NULL, fail_reason TEXT,"
                 "validated_at INTEGER NOT NULL, itag BLOB);"
                 "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
                 "height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
                 "ok INTEGER NOT NULL, work_delta_high INTEGER NOT NULL,"
                 "work_delta_low INTEGER NOT NULL,"
                 "utxo_size_after INTEGER NOT NULL,"
                 "reorg_depth INTEGER NOT NULL,"
                 "finalized_at INTEGER NOT NULL, tip_hash BLOB);",
                 NULL, NULL, NULL);
    (void)coins_kv_add(pdb, txid, 0, 5000, 1, false, NULL, 0);
    (void)coins_kv_mark_migration_complete(pdb);
    progress_store_tx_lock();
    sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    (void)coins_kv_set_applied_height_in_tx(pdb, GW_TIP + 1);
    sqlite3_exec(pdb, "COMMIT", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    progress_store_tx_unlock();
}

static void gw_init_blocks(struct gw_fixture *f)
{
    for (int i = 0; i < GW_BLOCKS; i++) {
        memset(f->hashes[i].data, i + 1, 32);
        block_index_init(&f->blocks[i]);
        f->blocks[i].phashBlock = &f->hashes[i];
        f->blocks[i].nHeight = i < 5 ? i : GW_TIP;
        f->blocks[i].pprev = i == 4 ? &f->blocks[GW_TIP]
                           : i == 5 ? &f->blocks[GW_TIP - 1]
                           : (i ? &f->blocks[i - 1] : NULL);
        if (i == 4)
            f->blocks[i].nHeight = GW_TIP + 1;
        f->blocks[i].nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        arith_uint256_set_u64(&f->blocks[i].nChainWork, (uint64_t)i + 1);
        test_block_map_insert(&f->ms.map_block_index, &f->hashes[i],
                              &f->blocks[i]);
        const struct block_index *canon =
            block_map_find(&f->ms.map_block_index, &f->hashes[i]);
        if (canon)
            f->blocks[i].phashBlock = canon->phashBlock;
    }
    /* Block 5 is a rival of the tip (same parent) that stays below it in
     * work until a test raises it. */
    arith_uint256_set_u64(&f->blocks[5].nChainWork, 1);
}

static bool gw_promote_to(struct gw_fixture *f, int idx)
{
    struct chain_evidence_controller_tip_request req = {
        .new_tip = &f->blocks[idx],
        .utxo_max_height = idx,
        .update_header_tip = true,
        .reason = "unit.bootstrap",
    };
    req.verified.header_ancestry_linked = true;
    req.verified.chainwork_recomputed = true;
    req.verified.nakamoto_selected_best_work = true;
    req.verified.block_bytes_hash_checked = true;
    return chain_evidence_controller_promote_tip(&f->authority, &req) ==
           CEC_OK;
}

/* Follow the chain the way a reducer-driven node does: boot to block 1, then
 * the reducer moves the tip and the live follow records forward evidence
 * (LOCAL_IMPORT, ancestry + chainwork only). */
static bool gw_follow_to_tip(struct gw_fixture *f)
{
    if (!gw_promote_to(f, 1))
        return false;
    for (int i = 2; i <= GW_TIP; i++) {
        if (!active_chain_move_window_tip(&f->ms.chain_active, &f->blocks[i]))
            return false;
        if (!chain_evidence_controller_record_finalized_tip(
                &f->authority, &f->blocks[i], "unit.finalize"))
            return false;
    }
    return true;
}

static void gw_free(struct gw_fixture *f);

/* Undo what gw_init opened before a store failed to open: the caller never
 * sees, uses or frees a partial fixture. */
static bool gw_init_fail(struct gw_fixture *f, bool progress_store_opened)
{
    if (progress_store_opened)
        progress_store_close();
    main_state_free(&f->ms);
    test_cleanup_tmpdir(f->dir);
    csr_test_reset_singleton();
    return false;
}

/* True with a complete fixture the caller must gw_free; false with nothing
 * left to free. */
static bool gw_init(struct gw_fixture *f)
{
    memset(f, 0, sizeof(*f));
    chain_evidence_pending_tip_test_reset();
    chain_evidence_controller_test_reset_startup_reconcile();
    csr_test_reset_singleton();
    main_state_init(&f->ms);
    test_make_tmpdir(f->dir, sizeof(f->dir), "genesis_walk_earn", "t");
    if (!progress_store_open(f->dir))
        return gw_init_fail(f, false);
    if (!node_db_open(&f->ndb, ":memory:"))
        return gw_init_fail(f, true);
    gw_seed_coins();
    gw_init_blocks(f);
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&f->coins_tip, &null_view);
    csr_init(csr_instance(), &f->ms.map_block_index, &f->ms.chain_active,
             &f->header_tip, &f->coins_tip, &f->ndb, NULL);
    chain_evidence_controller_init(&f->authority, &f->ndb, csr_instance());
    f->svc.ms = &f->ms;
    f->svc.ndb = &f->ndb;
    atomic_store(&f->svc.verified_tip_height, -1);
    atomic_store(&f->svc.progress.verified_height, -1);
    if (gw_follow_to_tip(f))
        return true;
    gw_free(f);
    return false;
}

static void gw_free(struct gw_fixture *f)
{
    chain_evidence_pending_tip_test_reset();
    csr_free(csr_instance());
    coins_view_cache_free(&f->coins_tip);
    main_state_free(&f->ms);
    node_db_close(&f->ndb);
    progress_store_close();
    test_cleanup_tmpdir(f->dir);
    csr_test_reset_singleton();
}

/* The walk has verified blocks up to `tip_idx` with the given tally. */
static void gw_walk_verified(struct gw_fixture *f, int tip_idx,
                             int64_t skips)
{
    bg_validation_note_verified_tip(&f->svc, f->blocks[tip_idx].nHeight,
                                    &f->blocks[tip_idx]);
    atomic_store(&f->svc.progress.verified_height,
                 f->blocks[tip_idx].nHeight);
    atomic_store(&f->svc.progress.script_verif_skipped_no_undo, skips);
}

static void gw_view(struct gw_fixture *f,
                    struct chain_evidence_controller_view *v)
{
    chain_evidence_controller_snapshot(&f->authority, v);
}

static bool gw_flags_unearned(struct gw_fixture *f)
{
    struct chain_evidence_controller_view v;
    gw_view(f, &v);
    return !v.active_tip_evidence.nakamoto_selected_best_work &&
           !v.active_tip_evidence.block_bytes_hash_checked &&
           v.state != CEC_FULLY_VALIDATED;
}

static bool gw_posture_review_free(struct gw_fixture *f)
{
    struct chain_evidence_controller_view v;
    gw_view(f, &v);
    return v.state == CEC_FULLY_VALIDATED &&
           v.full_validation_origin == CEC_FULL_VALIDATION_GENESIS_HISTORY &&
           v.health_reason[0] == '\0';
}

/* The completed genesis walk publishes: this is the case that stays red
 * until the walk earns the two flags. */
static int test_completed_genesis_walk_publishes(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    struct chain_evidence_controller_view v;
    gw_view(&f, &v);
    failures += gw_check("forward record carries neither flag before the walk",
             !v.active_tip_evidence.nakamoto_selected_best_work &&
             !v.active_tip_evidence.block_bytes_hash_checked);
    gw_walk_verified(&f, GW_TIP, 0);
    struct zcl_result r = bg_validation_authority_publish(&f.svc, false, true);
    failures += gw_check("completed genesis walk publishes authority", r.ok);
    failures += gw_check("posture is review-free genesis history",
             gw_posture_review_free(&f));
    gw_view(&f, &v);
    failures += gw_check("both flags earned on the active tip record",
             v.active_tip_evidence.nakamoto_selected_best_work &&
             v.active_tip_evidence.block_bytes_hash_checked &&
             v.active_tip_evidence.full_validation_complete);
    gw_free(&f);
    return failures;
}

static int refuses(struct gw_fixture *f, bool external_seeded)
{
    struct zcl_result r =
        bg_validation_authority_publish(&f->svc, external_seeded, true);
    return !r.ok && gw_flags_unearned(f) ? 0 : 1;
}

/* A same-height different-hash tip: the walk verified block 3, the live tip
 * is a rival at height 3. A height match alone must not earn bytes. */
static int test_same_height_reorg_refuses(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    gw_walk_verified(&f, 5, 0);
    failures += gw_check("walk verified a rival of the active tip: refuses, untouched",
             refuses(&f, false) == 0);
    gw_free(&f);
    return failures;
}

static int test_no_verified_hash_refuses(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    atomic_store(&f.svc.progress.verified_height, GW_TIP);
    failures += gw_check("height without a walked hash (resume) refuses",
             refuses(&f, false) == 0);
    gw_free(&f);
    return failures;
}

static int test_best_work_failure_refuses(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    gw_walk_verified(&f, GW_TIP, 0);
    arith_uint256_set_u64(&f.blocks[5].nChainWork, 99);
    failures += gw_check("a connectable higher-work rival vetoes: refuses, untouched",
             refuses(&f, false) == 0);
    gw_free(&f);
    return failures;
}

static int test_walk_gaps_refuse(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    gw_walk_verified(&f, GW_TIP, 1);
    failures += gw_check("script skips refuse", refuses(&f, false) == 0);
    gw_walk_verified(&f, GW_TIP, 0);
    atomic_store(&f.svc.progress.verified_height, GW_TIP - 1);
    failures += gw_check("verified below tip refuses", refuses(&f, false) == 0);
    gw_walk_verified(&f, GW_TIP, 0);
    struct zcl_result gap =
        bg_validation_authority_publish(&f.svc, false, false);
    failures += gw_check("a coverage gap refuses", !gap.ok && gw_flags_unearned(&f));
    gw_free(&f);
    return failures;
}

static int test_snapshot_seeded_path_unchanged(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    gw_walk_verified(&f, GW_TIP, 0);
    failures += gw_check("assisted path without root-bound snapshot evidence refuses "
             "and earns nothing", refuses(&f, true) == 0);
    gw_free(&f);
    return failures;
}

/* After publication: the node follows N more blocks, then restarts. The
 * posture stays review-free and authority is never dropped. */
static int test_authority_survives_advance_and_restart(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    gw_walk_verified(&f, GW_TIP, 0);
    failures += gw_check("publishes", bg_validation_authority_publish(
                              &f.svc, false, true).ok);
    failures += gw_check("advance: reducer moves the tip",
             active_chain_move_window_tip(&f.ms.chain_active, &f.blocks[4]));
    failures += gw_check("advance: live follow records the new tip",
             chain_evidence_controller_record_finalized_tip(
                 &f.authority, &f.blocks[4], "unit.finalize"));
    failures += gw_check("review-free after advancing", gw_posture_review_free(&f));
    chain_evidence_controller_test_reset_startup_reconcile();
    chain_evidence_controller_init(&f.authority, &f.ndb, csr_instance());
    failures += gw_check("review-free after restart", gw_posture_review_free(&f));
    struct chain_evidence_controller_view v;
    gw_view(&f, &v);
    failures += gw_check("repaired marker still set after restart",
             v.repaired_active_tip_evidence);
    gw_free(&f);
    return failures;
}

static struct gw_fixture *g_hook_fixture;

/* The interleaving the in-transaction check closes: the walk's tip was
 * checked, then a live advance persists a different tip before the write. */
static void hook_move_persisted_tip(struct chain_evidence_controller *authority)
{
    (void)authority;
    struct gw_fixture *f = g_hook_fixture;
    (void)node_db_state_set(&f->ndb, "cec.active_tip_hash",
                            f->hashes[4].data, 32);
    (void)node_db_state_set_int(&f->ndb, "cec.active_tip_height",
                                f->blocks[4].nHeight);
}

static int test_earn_refuses_when_tip_moves_before_write(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    g_hook_fixture = &f;
    chain_evidence_earn_test_set_before_write_hook(hook_move_persisted_tip);
    struct zcl_result r = chain_evidence_controller_earn_active_tip_evidence(
        &f.authority, &f.hashes[GW_TIP], f.blocks[GW_TIP].nHeight, true,
        true);
    chain_evidence_earn_test_set_before_write_hook(NULL);
    failures += gw_check("earn refuses once the tip moved before the write",
                         !r.ok);
    failures += gw_check("the refusal is the transient tip-moved class",
                         r.code == CEC_EARN_TIP_MOVED);
    failures += gw_check("no flag attached to the moved tip's record",
                         gw_flags_unearned(&f));
    gw_free(&f);
    return failures;
}

/* mark_fully_validated_at_tip: a moved tip is a retryable refusal that
 * writes nothing and never freezes; the exact tip publishes. */
static int test_mark_at_tip_moved_is_retryable_not_frozen(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    struct zcl_result e = chain_evidence_controller_earn_active_tip_evidence(
        &f.authority, &f.hashes[GW_TIP], f.blocks[GW_TIP].nHeight, true,
        true);
    failures += gw_check("earn on the exact tip", e.ok);
    struct uint256 root;
    memset(&root, 0x11, sizeof(root));
    enum chain_evidence_controller_result moved =
        chain_evidence_controller_mark_fully_validated_at_tip(
            &f.authority, &root, &f.hashes[4]);
    failures += gw_check("a different tip is TIP_MOVED",
                         moved == CEC_REJECTED_TIP_MOVED);
    struct chain_evidence_controller_view v;
    gw_view(&f, &v);
    failures += gw_check("not frozen and not published",
                         v.state != CEC_CONTRADICTION_FROZEN &&
                         v.state != CEC_FULLY_VALIDATED);
    failures += gw_check("the exact tip publishes",
                         chain_evidence_controller_mark_fully_validated_at_tip(
                             &f.authority, &root, &f.hashes[GW_TIP]) ==
                             CEC_OK);
    gw_free(&f);
    return failures;
}

/* A genesis-fold node at tip is still CEC_EMPTY: only promote_tip leaves that
 * state, and the reducer's live advance (record_finalized_tip) never does.
 * An ordinary not-yet-following publish attempt must refuse softly and must
 * not latch the controller CONTRADICTION_FROZEN. */
static int test_genesis_mark_from_empty_state_refuses_unfrozen(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    failures += gw_check("fixture state set empty",
                         node_db_state_set(&f.ndb, "cec.sync_state", "empty",
                                           strlen("empty") + 1));
    chain_evidence_controller_init(&f.authority, &f.ndb, csr_instance());
    struct chain_evidence_controller_view v;
    gw_view(&f, &v);
    failures += gw_check("controller is in the empty state", v.state == CEC_EMPTY);
    gw_walk_verified(&f, GW_TIP, 0);
    struct zcl_result r = bg_validation_authority_publish(&f.svc, false, true);
    failures += gw_check("publish refuses", !r.ok);
    failures += gw_check("refusal names the not-yet-following state",
                         strstr(r.message, "not yet tip-following") != NULL);
    chain_evidence_controller_init(&f.authority, &f.ndb, csr_instance());
    gw_view(&f, &v);
    failures += gw_check("controller is not frozen",
                         v.state != CEC_CONTRADICTION_FROZEN);
    failures += gw_check("controller stays empty", v.state == CEC_EMPTY);
    gw_free(&f);
    return failures;
}

/* Two real threads over the one shared handle. B is the live advance: it
 * opens its transaction and parks (hook) before writing the new tip. A is
 * the genesis walk's earn for the OLD tip. The evidence write lock must
 * make A wait for B's commit, after which A sees the new tip and refuses;
 * A must never write the old tip's flags into B's transaction or record. */
static _Atomic int g_b_parked;
static _Atomic int g_b_release;
static _Atomic int g_a_done;
static struct zcl_result g_a_result;

static void sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000,
                          .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static void hook_park_live_advance(void)
{
    atomic_store(&g_b_parked, 1);
    for (int i = 0; i < 1000 && !atomic_load(&g_b_release); i++)
        sleep_ms(10); /* watchdog: 10s, then proceed */
}

static void *thread_live_advance(void *arg)
{
    struct gw_fixture *f = arg;
    (void)chain_evidence_controller_record_finalized_tip(
        &f->authority, &f->blocks[4], "unit.two_thread");
    return NULL;
}

static void *thread_earn_old_tip(void *arg)
{
    struct gw_fixture *f = arg;
    g_a_result = chain_evidence_controller_earn_active_tip_evidence(
        &f->authority, &f->hashes[GW_TIP], f->blocks[GW_TIP].nHeight, true,
        true);
    atomic_store(&g_a_done, 1);
    return NULL;
}

static int test_two_thread_earn_waits_for_live_advance(void)
{
    int failures = 0;
    struct gw_fixture f;
    if (!gw_init(&f))
        return gw_check("fixture", false);
    atomic_store(&g_b_parked, 0);
    atomic_store(&g_b_release, 0);
    atomic_store(&g_a_done, 0);
    failures += gw_check("advance: reducer moves the tip",
                         active_chain_move_window_tip(&f.ms.chain_active,
                                                      &f.blocks[4]));
    chain_evidence_live_test_set_after_begin_hook(hook_park_live_advance);
    pthread_t b, a;
    bool b_started =
        pthread_create(&b, NULL, thread_live_advance, &f) == 0;
    failures += gw_check("start live-advance thread", b_started);
    for (int i = 0; b_started && i < 500 && !atomic_load(&g_b_parked); i++)
        sleep_ms(10);
    bool parked = atomic_load(&g_b_parked) == 1;
    failures += gw_check("live advance parked inside its transaction", parked);
    bool a_started = false;
    if (parked) {
        a_started = pthread_create(&a, NULL, thread_earn_old_tip, &f) == 0;
        failures += gw_check("start earn thread", a_started);
    }
    /* Prove the earn thread reached the lock while B is still parked. */
    for (int i = 0; a_started && i < 500 &&
                    chain_evidence_write_lock_test_waiters() < 1 &&
                    !atomic_load(&g_a_done); i++)
        sleep_ms(10);
    failures += gw_check("earn thread is a waiter on the write lock while "
                         "the live advance is parked",
                         a_started &&
                             chain_evidence_write_lock_test_waiters() >= 1);
    failures += gw_check("earn has not completed while B holds the lock",
                         atomic_load(&g_a_done) == 0);
    atomic_store(&g_b_release, 1);
    if (b_started)
        pthread_join(b, NULL);
    if (a_started)
        pthread_join(a, NULL);
    chain_evidence_live_test_set_after_begin_hook(NULL);
    failures += gw_check("earn refused after the advance committed",
                         !g_a_result.ok);
    failures += gw_check("refusal is TIP_MOVED",
                         g_a_result.code == CEC_EARN_TIP_MOVED);
    failures += gw_check("old tip's flags never reached the record",
                         gw_flags_unearned(&f));
    gw_free(&f);
    return failures;
}

static struct gw_fixture *g_mark_fixture;
static int g_mark_hook_mode;

/* Between the scan/walk and the mark, a same-height rival (blocks[5]) takes
 * over: either the active chain tip (mode 0) or the persisted tip record
 * (mode 1). */
static void hook_same_height_rival(void)
{
    struct gw_fixture *f = g_mark_fixture;
    if (g_mark_hook_mode == 0) {
        (void)active_chain_move_window_tip(&f->ms.chain_active,
                                           &f->blocks[5]);
    } else {
        (void)node_db_state_set(&f->ndb, "cec.active_tip_hash",
                                f->hashes[5].data, 32);
    }
}

static int refused_retryable_unpublished(struct gw_fixture *f, int mode)
{
    int failures = 0;
    g_mark_fixture = f;
    g_mark_hook_mode = mode;
    gw_walk_verified(f, GW_TIP, 0);
    bg_validation_authority_test_set_before_mark_hook(hook_same_height_rival);
    struct zcl_result r = bg_validation_authority_publish(&f->svc, false, true);
    bg_validation_authority_test_set_before_mark_hook(NULL);
    failures += gw_check("same-height rival before the mark refuses", !r.ok);
    failures += gw_check("refusal is the retryable tip-moved class",
                         strstr(r.message, "tip_moved") != NULL);
    struct chain_evidence_controller_view v;
    gw_view(f, &v);
    failures += gw_check("not frozen, not published, no completion flag",
                         v.state != CEC_CONTRADICTION_FROZEN &&
                             v.state != CEC_FULLY_VALIDATED &&
                             !v.active_tip_evidence.full_validation_complete);
    return failures;
}

static int test_mark_refuses_same_height_rival_after_scan(void)
{
    int failures = 0;
    for (int mode = 0; mode < 2; mode++) {
        struct gw_fixture f;
        if (!gw_init(&f)) {
            failures += gw_check("fixture", false);
            continue;
        }
        failures += refused_retryable_unpublished(&f, mode);
        gw_free(&f);
    }
    return failures;
}

int test_genesis_walk_earn_evidence(void)
{
    int failures = 0;
    printf("\n=== genesis_walk_earn_evidence tests ===\n");
    failures += test_completed_genesis_walk_publishes();
    failures += test_same_height_reorg_refuses();
    failures += test_no_verified_hash_refuses();
    failures += test_best_work_failure_refuses();
    failures += test_walk_gaps_refuse();
    failures += test_snapshot_seeded_path_unchanged();
    failures += test_authority_survives_advance_and_restart();
    failures += test_earn_refuses_when_tip_moves_before_write();
    failures += test_mark_at_tip_moved_is_retryable_not_frozen();
    failures += test_two_thread_earn_waits_for_live_advance();
    failures += test_genesis_mark_from_empty_state_refuses_unfrozen();
    failures += test_mark_refuses_same_height_rival_after_scan();
    if (failures == 0)
        printf("  all genesis_walk_earn_evidence tests passed\n");
    return failures;
}
