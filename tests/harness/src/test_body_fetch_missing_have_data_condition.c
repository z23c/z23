/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "conditions/body_fetch_missing_have_data.h"
#include "core/arith_uint256.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "net/download.h"
#include "net/msgprocessor.h"
#include "platform/time_compat.h"
#include "services/sync_monitor.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BFMHD_CHECK(name, expr) do { \
    printf("body_fetch_missing_have_data: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Test seams for the mid-chain (utxo_apply select-idle) candidate — see
 * body_fetch_missing_have_data_test_set_select_idle_stubs(). */
static int64_t g_bfmhd_stub_height = -1;
static int64_t bfmhd_stub_select_idle_height(void) { return g_bfmhd_stub_height; }
static bool bfmhd_stub_select_idle_is_read_failure(void) { return true; }

struct bfmhd_fixture {
    char dir[256];
    struct main_state ms;
    struct download_manager dm;
    struct block_index *tip;
    struct block_index *child;
    struct uint256 hashes[4];
    int tip_h;
    int target;
};

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("SQL failed: %s\n", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool seed_schema(sqlite3 *db)
{
    return
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "fail_reason TEXT, validated_at INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_fetch_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, source TEXT NOT NULL,"
            "bytes INTEGER NOT NULL DEFAULT 0, fetched_at INTEGER NOT NULL,"
            "ok INTEGER NOT NULL, fail_reason TEXT)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
            "ok INTEGER NOT NULL, tip_hash BLOB)");
}

static bool seed_cursor(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool seed_cursors(sqlite3 *db, int validate_cursor,
                         int body_fetch_cursor)
{
    return seed_cursor(db, "validate_headers", validate_cursor) &&
           seed_cursor(db, "body_fetch", body_fetch_cursor);
}

static bool seed_validate_row(sqlite3 *db, int height,
                              const struct uint256 *hash,
                              int ok_flag)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log"
            "(height,hash,ok,fail_reason,validated_at) "
            "VALUES(?,?,?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok_flag);
    if (ok_flag)
        sqlite3_bind_null(st, 4);
    else
        sqlite3_bind_text(st, 4, "invalid-test-header", -1,
                          SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool seed_body_row(sqlite3 *db, int height,
                          const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO body_fetch_log"
            "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
            "VALUES(?,?,'disk',0,1,1,NULL)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static int g_bfmhd_arrival_height = -1;
static struct uint256 g_bfmhd_arrival_hash;
static bool g_bfmhd_arrival_seeded;
static struct block_index *g_bfmhd_arrival_index;

static void bfmhd_seed_arrival_before_remedy_recheck(void)
{
    g_bfmhd_arrival_seeded = seed_body_row(
        progress_store_db(), g_bfmhd_arrival_height,
        &g_bfmhd_arrival_hash);
}

static void bfmhd_seed_arrival_before_remedy_queue(void)
{
    if (g_bfmhd_arrival_index)
        g_bfmhd_arrival_index->nStatus |= BLOCK_HAVE_DATA;
    bfmhd_seed_arrival_before_remedy_recheck();
}

static bool seed_trusted_parent_bfmhd(sqlite3 *db, int height,
                                      const struct uint256 *hash)
{
    if (!db || height < 0 || !hash)
        return false;
    uint8_t encoded_height[8];
    uint64_t value = (uint64_t)height;
    for (size_t i = 0; i < sizeof(encoded_height); i++)
        encoded_height[i] = (uint8_t)(value >> (8u * i));
    return progress_meta_set(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                             encoded_height, sizeof(encoded_height)) &&
           progress_meta_set(db, REDUCER_TRUSTED_BASE_HASH_KEY,
                             hash->data, sizeof(hash->data));
}

static bool row_exists(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT 1 FROM %s WHERE height=?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static struct block_index *insert_index(struct main_state *ms,
                                        struct uint256 *hash,
                                        int height,
                                        struct block_index *prev,
                                        unsigned status)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)height;
    hash->data[1] = 0xBF;
    hash->data[2] = 0x23;

    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->pprev = prev;
    bi->nStatus = status;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    bi->nFile = status & BLOCK_HAVE_DATA ? 0 : -1;
    bi->nDataPos = status & BLOCK_HAVE_DATA ? 8u : 0u;
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)(height + 1));
    return bi;
}

static struct block_index *insert_sibling(struct main_state *ms,
                                          struct uint256 *hash,
                                          int height,
                                          struct block_index *prev,
                                          unsigned status)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)height;
    hash->data[1] = 0xBF;
    hash->data[2] = 0x23;
    hash->data[3] = 0xA5;

    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->pprev = prev;
    bi->nStatus = status;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    bi->nFile = status & BLOCK_HAVE_DATA ? 0 : -1;
    bi->nDataPos = status & BLOCK_HAVE_DATA ? 16u : 0u;
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)(height + 1));
    return bi;
}

static bool setup_fixture(struct bfmhd_fixture *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));
    fx->tip_h = 1;
    fx->target = 2;

    condition_engine_reset_for_testing();
    body_fetch_missing_have_data_test_reset();
    test_make_tmpdir(fx->dir, sizeof(fx->dir), "bf_missing_have_data", tag);
    if (!progress_store_open(fx->dir))
        return false;
    if (!seed_schema(progress_store_db()))
        return false;

    main_state_init(&fx->ms);
    dl_init(&fx->dm);
    sync_monitor_init();
    msgprocessor_test_reset_recent_blocks();

    struct block_index *genesis =
        insert_index(&fx->ms, &fx->hashes[0], 0, NULL,
                     BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
    fx->tip = insert_index(&fx->ms, &fx->hashes[1], fx->tip_h,
                           genesis, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
    fx->child = insert_index(&fx->ms, &fx->hashes[2], fx->target,
                             fx->tip, BLOCK_VALID_TREE);
    if (!genesis || !fx->tip || !fx->child)
        return false;
    if (!active_chain_move_window_tip(&fx->ms.chain_active, fx->tip))
        return false;
    fx->ms.pindex_best_header = fx->child;

    if (!seed_cursors(progress_store_db(), fx->target + 1, fx->target))
        return false;
    if (!seed_validate_row(progress_store_db(), fx->target,
                           fx->child->phashBlock, 1))
        return false;

    sync_monitor_set_context(NULL, &fx->dm, &fx->ms);
    sync_monitor_test_set_tip_advance_ts(0);
    register_body_fetch_missing_have_data();
    return true;
}

static void teardown_fixture(struct bfmhd_fixture *fx)
{
    sync_monitor_set_context(NULL, NULL, NULL);
    condition_engine_reset_for_testing();
    body_fetch_missing_have_data_test_reset();
    dl_free(&fx->dm);
    main_state_free(&fx->ms);
    progress_store_close();
    test_cleanup_tmpdir(fx->dir);
}

static bool queue_has_target(struct bfmhd_fixture *fx)
{
    uint64_t queued = 0;
    dl_get_stats(&fx->dm, NULL, NULL, NULL, NULL, &queued);
    return queued == 1 &&
           fx->dm.queue_len == 1 &&
           fx->dm.queue_heights[0] == fx->target &&
           uint256_eq(&fx->dm.queue[0], fx->child->phashBlock);
}

int test_body_fetch_missing_have_data_condition(void)
{
    printf("\n=== body_fetch_missing_have_data condition tests ===\n");
    int failures = 0;

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "positive");
        struct stage_repair_body_fetch_gap gap;
        ok = ok && stage_repair_body_fetch_missing_have_data_candidate(
            progress_store_db(), fx.target, &gap);
        ok = ok && gap.ready && gap.target_height == fx.target;
        ok = ok && !row_exists(progress_store_db(), "body_fetch_log",
                               fx.target);
        msgprocessor_test_block_mark_seen(fx.child->phashBlock);
        ok = ok && msgprocessor_test_block_already_seen(
            fx.child->phashBlock);

        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "body_fetch_missing_have_data", &snap);
        struct watchdog_stats wd;
        sync_monitor_get_stats(&wd);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && got && snap.last_outcome == COND_REMEDY_UNWITNESSED;
        ok = ok && queue_has_target(&fx);
        ok = ok && !msgprocessor_test_block_already_seen(
            fx.child->phashBlock);
        ok = ok && wd.last_recovery == WATCHDOG_BODY_FRONTIER_MISSING;
        BFMHD_CHECK("detect queues missing active-frontier body and clears "
                    "dedup",
                    ok);

        bool ok2 = seed_body_row(progress_store_db(), fx.target,
                                 fx.child->phashBlock);
        condition_engine_tick();
        ok2 = ok2 && condition_engine_get_active_count() == 0;
        ok2 = ok2 && condition_engine_get_registered_snapshot(
            "body_fetch_missing_have_data", &snap);
        ok2 = ok2 && snap.cleared_count == 1;
        BFMHD_CHECK("body_fetch success row witnesses clear", ok2);
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "arrival_before_queue");
        g_bfmhd_arrival_height = fx.target;
        g_bfmhd_arrival_hash = *fx.child->phashBlock;
        g_bfmhd_arrival_index = fx.child;
        g_bfmhd_arrival_seeded = false;
        body_fetch_missing_have_data_test_set_before_remedy_queue(
            bfmhd_seed_arrival_before_remedy_queue);
        msgprocessor_test_block_mark_seen(fx.child->phashBlock);

        struct watchdog_stats before;
        struct watchdog_stats after;
        struct condition_runtime_snapshot snap_before;
        ok = ok && condition_engine_get_registered_snapshot(
            "body_fetch_missing_have_data", &snap_before);
        sync_monitor_get_stats(&before);
        condition_engine_tick();
        sync_monitor_get_stats(&after);

        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        struct condition_runtime_snapshot snap;
        ok = ok && g_bfmhd_arrival_seeded;
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && queued == 0 && fx.dm.queue_len == 0;
        ok = ok && after.recoveries_total == before.recoveries_total;
        ok = ok && msgprocessor_test_block_already_seen(
            fx.child->phashBlock);
        ok = ok && condition_engine_get_registered_snapshot(
            "body_fetch_missing_have_data", &snap);
        ok = ok && snap.cleared_count == snap_before.cleared_count + 1;
        BFMHD_CHECK("body arrival after final recheck is an atomic queue "
                    "no-op without recovery", ok);
        g_bfmhd_arrival_index = NULL;
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "validate_cursor_not_past");
        ok = ok && seed_cursor(progress_store_db(), "validate_headers",
                               fx.target);
        condition_engine_tick();
        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && queued == 0;
        BFMHD_CHECK("validate cursor not past target suppresses repair", ok);
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "validate_failed");
        ok = ok && seed_validate_row(progress_store_db(), fx.target,
                                     fx.child->phashBlock, 0);
        condition_engine_tick();
        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && queued == 0;
        BFMHD_CHECK("failed validate row suppresses repair", ok);
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "already_observed");
        ok = ok && seed_body_row(progress_store_db(), fx.target,
                                 fx.child->phashBlock);
        condition_engine_tick();
        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && queued == 0;
        BFMHD_CHECK("existing body_fetch row suppresses repair", ok);
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "arrival_before_remedy");
        g_bfmhd_arrival_height = fx.target;
        g_bfmhd_arrival_hash = *fx.child->phashBlock;
        g_bfmhd_arrival_seeded = false;
        body_fetch_missing_have_data_test_set_before_remedy_recheck(
            bfmhd_seed_arrival_before_remedy_recheck);

        struct watchdog_stats before;
        struct watchdog_stats after;
        struct condition_runtime_snapshot snap_before;
        ok = ok && condition_engine_get_registered_snapshot(
            "body_fetch_missing_have_data", &snap_before);
        sync_monitor_get_stats(&before);
        condition_engine_tick();
        sync_monitor_get_stats(&after);

        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        struct condition_runtime_snapshot snap;
        ok = ok && g_bfmhd_arrival_seeded;
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && queued == 0 && fx.dm.queue_len == 0;
        ok = ok && after.recoveries_total == before.recoveries_total;
        ok = ok && condition_engine_get_registered_snapshot(
            "body_fetch_missing_have_data", &snap);
        ok = ok && snap.cleared_count == snap_before.cleared_count + 1;
        BFMHD_CHECK("body arrival between detect and remedy clears without "
                    "queue or recovery", ok);
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "exact_have_data_reason");
        fx.child->nStatus |= BLOCK_HAVE_DATA;
        condition_engine_tick();
        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && queued == 0;
        ok = ok && strcmp(
            body_fetch_missing_have_data_test_last_skip_reason(),
            "exact_have_data") == 0;
        BFMHD_CHECK("exact HAVE_DATA skip has a disjoint stable reason", ok);
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "cursor_only_not_witness");
        condition_engine_tick();
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && seed_cursor(progress_store_db(), "body_fetch",
                               fx.target + 1);
        condition_engine_tick();
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && !stage_repair_body_fetch_observed(progress_store_db(),
                                                     fx.target);
        BFMHD_CHECK("cursor advance without row does not witness", ok);
        teardown_fixture(&fx);
    }

    /* Exact C3 wedge: the finalized window ends at H, while two H+1 children
     * exist. A stale sibling is data-flagged (and even owns the height-keyed
     * body_fetch row), but the validate_headers row and best-header ancestry
     * name the other child, whose body is missing. Height-only selection used
     * to accept the stale sibling's HAVE_DATA/row and suppress the canonical
     * fetch forever. */
    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "canonical_hash_over_stale_sibling");
        struct block_index *stale = insert_sibling(
            &fx.ms, &fx.hashes[3], fx.target, fx.tip,
            BLOCK_VALID_TREE | BLOCK_HAVE_DATA);
        ok = ok && stale && stale != fx.child;
        ok = ok && seed_body_row(progress_store_db(), fx.target,
                                 stale->phashBlock);
        msgprocessor_test_block_mark_seen(fx.child->phashBlock);

        condition_engine_tick();

        struct condition_runtime_snapshot snap;
        ok = ok && condition_engine_get_registered_snapshot(
            "body_fetch_missing_have_data", &snap);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && snap.last_outcome == COND_REMEDY_UNWITNESSED;
        ok = ok && queue_has_target(&fx);
        ok = ok && uint256_eq(&fx.dm.queue[0], fx.child->phashBlock);
        ok = ok && !uint256_eq(&fx.dm.queue[0], stale->phashBlock);
        ok = ok && !msgprocessor_test_block_already_seen(
            fx.child->phashBlock);
        int cleared_before = snap.cleared_count;
        BFMHD_CHECK("canonical validate hash queues over data-flagged stale "
                    "sibling and wrong-hash body row", ok);

        bool ok2 = seed_body_row(progress_store_db(), fx.target,
                                 fx.child->phashBlock);
        condition_engine_tick();
        ok2 = ok2 && condition_engine_get_active_count() == 0;
        ok2 = ok2 && condition_engine_get_registered_snapshot(
            "body_fetch_missing_have_data", &snap);
        ok2 = ok2 && snap.cleared_count == cleared_before + 1;
        BFMHD_CHECK("only exact canonical body row witnesses repair", ok2);
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "canonical_parent_mismatch");
        fx.child->pprev = NULL; /* best-header target no longer extends H */
        struct block_index *other = insert_sibling(
            &fx.ms, &fx.hashes[3], fx.target, fx.tip, BLOCK_VALID_TREE);
        ok = ok && other;

        condition_engine_tick();

        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && queued == 0;
        ok = ok && strcmp(
            body_fetch_missing_have_data_test_last_skip_reason(),
            "visible_parent_mismatch") == 0;
        ok = ok && strcmp(
            body_fetch_missing_have_data_test_last_skip_reason(),
            "exact_have_data") != 0;
        BFMHD_CHECK("canonical target whose parent is not the visible H "
                    "fails closed instead of queueing a sibling", ok);
        teardown_fixture(&fx);
    }

    /* Checkpoint respawn: active_chain intentionally has no H* slot. The
     * durable trusted-base pair is the exact parent witness for the canonical
     * H*+1 best-header child, so the healer must queue that hash. */
    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "durable_checkpoint_parent");
        active_chain_free(&fx.ms.chain_active);
        active_chain_init(&fx.ms.chain_active);
        ok = ok && seed_trusted_parent_bfmhd(
            progress_store_db(), fx.tip_h, fx.tip->phashBlock);
        msgprocessor_test_block_mark_seen(fx.child->phashBlock);

        condition_engine_tick();

        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && queue_has_target(&fx);
        ok = ok && !msgprocessor_test_block_already_seen(
            fx.child->phashBlock);
        BFMHD_CHECK("durable checkpoint parent queues exact H*+1 child",
                    ok);
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "durable_checkpoint_parent_mismatch");
        active_chain_free(&fx.ms.chain_active);
        active_chain_init(&fx.ms.chain_active);
        ok = ok && seed_trusted_parent_bfmhd(
            progress_store_db(), fx.tip_h, &fx.hashes[0]);

        condition_engine_tick();

        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && queued == 0;
        ok = ok && strcmp(
            body_fetch_missing_have_data_test_last_skip_reason(),
            "visible_parent_mismatch") == 0;
        BFMHD_CHECK("mismatched durable checkpoint parent fails closed",
                    ok);
        teardown_fixture(&fx);
    }

    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "canonical_best_hash_mismatch");
        struct block_index *other = insert_sibling(
            &fx.ms, &fx.hashes[3], fx.target, fx.tip, BLOCK_VALID_TREE);
        ok = ok && other;
        fx.ms.pindex_best_header = other;

        condition_engine_tick();

        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && queued == 0;
        ok = ok && strcmp(
            body_fetch_missing_have_data_test_last_skip_reason(),
            "best_hash_mismatch") == 0;
        BFMHD_CHECK("best-header hash disagreement has a disjoint stable "
                    "reason", ok);
        teardown_fixture(&fx);
    }

    /* An ARBITRARY mid-chain height (not the body_fetch frontier cursor) —
     * utxo_apply's select-idle record naming a height the sibling
     * have_data_unreadable Condition already cleared HAVE_DATA for. The
     * frontier-cursor candidate here still names fx.target (h=2); the
     * mid-chain candidate (h=1, fx.tip) is LOWER, so it must win and the
     * queued fetch must be for fx.tip's hash, not fx.child's. */
    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "mid_chain_select_idle");

        fx.tip->nStatus &= ~(unsigned)BLOCK_HAVE_DATA;
        fx.tip->nFile = -1;
        fx.tip->nDataPos = 0;
        g_bfmhd_stub_height = fx.tip_h; /* h=1, below fx.target=2 */
        body_fetch_missing_have_data_test_set_select_idle_stubs(
            bfmhd_stub_select_idle_height,
            bfmhd_stub_select_idle_is_read_failure);

        condition_engine_tick();

        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && queued == 1 && fx.dm.queue_len == 1;
        ok = ok && fx.dm.queue_heights[0] == fx.tip_h;
        ok = ok && uint256_eq(&fx.dm.queue[0], fx.tip->phashBlock);
        BFMHD_CHECK("mid-chain select-idle height (below the frontier "
                    "cursor) is targeted over the frontier candidate", ok);

        g_bfmhd_stub_height = -1;
        teardown_fixture(&fx);
    }

    /* Background validation can discover old disk damage while the live tip
     * is still advancing. Its explicit reducer note must survive HAVE_DATA
     * clearing and queue that exact active-chain hash without waiting for the
     * speculative 60-second stall guard. */
    {
        struct bfmhd_fixture fx;
        bool ok = setup_fixture(&fx, "background_read_note");

        fx.tip->nStatus &= ~(unsigned)BLOCK_HAVE_DATA;
        fx.tip->nFile = -1;
        fx.tip->nDataPos = 0;
        ok = ok && seed_body_row(
            progress_store_db(), fx.tip_h, fx.tip->phashBlock);
        reducer_frontier_body_read_note_record(
            fx.tip_h, 49, 46754837, REDUCER_FRONTIER_BODY_READ_DISK,
            fx.tip->phashBlock);
        sync_monitor_test_set_tip_advance_ts(platform_time_wall_unix());

        condition_engine_tick();

        uint64_t queued = 0;
        dl_get_stats(&fx.dm, NULL, NULL, NULL, NULL, &queued);
        ok = ok && body_fetch_missing_have_data_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && queued == 1 && fx.dm.queue_len == 1;
        ok = ok && fx.dm.queue_heights[0] == fx.tip_h;
        ok = ok && uint256_eq(&fx.dm.queue[0], fx.tip->phashBlock);
        ok = ok && reducer_frontier_body_read_note_active();
        BFMHD_CHECK("explicit background-read note ignores stale fetch row "
                    "and queues exact active hash while tip advances", ok);

        reducer_frontier_body_read_note_reset_for_testing();
        sync_monitor_test_set_tip_advance_ts(0);
        teardown_fixture(&fx);
    }

    return failures;
}
