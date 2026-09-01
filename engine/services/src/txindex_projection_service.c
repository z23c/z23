// one-result-type-ok:json-dump-bool — the sole non-zcl_result surfaces here
// are the CLAUDE.md-convention dump (txindex_dump_state_json, bool), the
// boolean supervisor-registration/rederive latches, and the read-classify enum;
// every fallible DB primitive lives in jobs/txindex_projection.c. There is no
// orchestration result to propagate.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * txindex_projection_service — supervised, bounded backfill for the txindex
 * projection. See services/txindex_projection_service.h for the design
 * contract.
 *
 * Crash-only / projection discipline: a firing DB error or a missing body stops
 * THIS batch and surfaces a coverage blocker in dumpstate; the process and every
 * other stage keep running. It never changes a validity predicate or the primary
 * derivation — it only folds verified persisted bodies (<= H*) into a rebuildable
 * secondary index. */

#include "services/txindex_projection_service.h"

#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/txindex_projection.h"
#include "services/index_fold_guard.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "storage/projection_store.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── observable state (atomics; snapshotted by the dumper) ──────────── */
static _Atomic bool    g_tx_registered      = false;
static _Atomic bool    g_tx_schema_ready    = false;
static _Atomic int64_t g_tx_cursor          = -1;
static _Atomic int64_t g_tx_hstar           = -1;
static _Atomic int64_t g_tx_rows            = 0;
static _Atomic int64_t g_tx_blocks_folded   = 0;   /* lifetime */
static _Atomic int64_t g_tx_ticks           = 0;
static _Atomic int64_t g_tx_last_batch_blocks = 0;
static _Atomic int64_t g_tx_last_batch_us   = 0;
static _Atomic int64_t g_tx_resets          = 0;
static _Atomic bool    g_tx_blocked         = false;
static _Atomic int64_t g_tx_blocked_height  = -1;

static pthread_mutex_t g_tx_digest_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_tx_digest_hex[65];

static struct liveness_contract g_tx_contract;
static _Atomic supervisor_child_id g_tx_id = SUPERVISOR_INVALID_ID;

enum txindex_read_status txindex_projection_classify(bool found, int64_t cursor,
                                                     int64_t hstar)
{
    if (found)
        return TXINDEX_READ_FOUND;
    /* A miss is only definitive once the fold has caught up to the finalized
     * frontier; below it the tx may simply live above the cursor. */
    if (hstar >= 0 && cursor < hstar)
        return TXINDEX_READ_BEHIND;
    return TXINDEX_READ_ABSENT;
}

/* ── one bounded fold batch (tx lock held by caller) ────────────────── */
static int tx_do_batch(struct main_state *ms, const char *datadir, sqlite3 *db)
{
    if (!atomic_load(&g_tx_schema_ready)) {
        if (!txindex_projection_ensure_schema(db))
            return 0;
        int64_t rc0 = txindex_projection_row_count(db);
        atomic_store(&g_tx_rows, rc0 >= 0 ? rc0 : 0);
        atomic_store(&g_tx_schema_ready, true);
    }

    int64_t cursor = -1;
    (void)txindex_projection_get_cursor(db, &cursor);
    int64_t hstar = (int64_t)tip_finalize_stage_cursor();
    atomic_store(&g_tx_hstar, hstar);
    atomic_store(&g_tx_cursor, cursor);

    /* Deep-regression safety net: H* only advances under normal operation, so
     * cursor > H* means a reorg/rewind dropped finalized history below us. A
     * projection folded as a forward-only digest chain cannot partially unwind,
     * so drop-and-rederive from height 0 (cheap, rebuildable by construction). */
    if (hstar >= 0 && cursor > hstar) {
        if (txindex_projection_drop(db) && txindex_projection_ensure_schema(db)) {
            atomic_fetch_add(&g_tx_resets, 1);
            atomic_store(&g_tx_cursor, -1);
            atomic_store(&g_tx_rows, 0);
            pthread_mutex_lock(&g_tx_digest_lock);
            g_tx_digest_hex[0] = '\0';
            pthread_mutex_unlock(&g_tx_digest_lock);
        }
        return 0;
    }
    if (cursor >= hstar) {                  /* caught up to the finalized tip */
        atomic_store(&g_tx_blocked, false);
        atomic_store(&g_tx_last_batch_blocks, 0);
        index_fold_clear_seed_blocker("txindex");
        return 0;
    }

    /* Free-disk precheck: never start/continue the historical fold when disk
     * headroom is low — it raises a named txindex.disk_low blocker and yields,
     * so consensus writes keep their last bytes instead of the catalog filling
     * the disk. */
    if (!index_fold_disk_ok("txindex", "txindex", datadir))
        return 0;

    uint8_t digest[32];
    bool dfound = false;
    if (!txindex_projection_get_digest(db, digest, &dfound))
        return 0;
    if (!dfound)
        memset(digest, 0, 32);

    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        LOG_WARN("txindex", "[txindex] BEGIN failed: %s", sqlite3_errmsg(db));
        return 0;
    }

    int64_t start_us = platform_time_monotonic_us();
    int folded = 0, total_added = 0;
    bool blocked = false;
    int64_t blocked_h = -1, last_good = cursor;

    for (int64_t h = cursor + 1; h <= hstar && folded < TXINDEX_BATCH_BLOCKS;
         h++) {
        struct block_index *bi = active_chain_at(&ms->chain_active, (int)h);
        struct block blk;
        block_init(&blk);
        if (!bi || !read_block_from_disk_index_pread(&blk, bi, datadir)) {
            block_free(&blk);
            blocked = true;
            blocked_h = h;
            /* Name the floor: below the snapshot seed this is a structural
             * DEPENDENCY (bodies never downloaded), above it a transient gap. */
            index_fold_note_absent_body("txindex", "txindex", db, h);
            break;                          /* body absent — coverage floor */
        }
        struct uint256 bh;
        block_get_hash(&blk, &bh);
        int added = 0;
        bool put_ok = txindex_projection_put_block(db, &blk, (int)h, bh.data,
                                                   digest, &added);
        block_free(&blk);
        if (!put_ok) {
            blocked = true;
            blocked_h = h;
            break;                          /* real DB error — surface + stop */
        }
        total_added += added;
        last_good = h;
        folded++;
        if (platform_time_monotonic_us() - start_us >= TXINDEX_BATCH_US)
            break;                          /* wall-time budget spent */
    }

    bool commit = false;
    if (folded > 0 && txindex_projection_set_cursor(db, last_good, digest) &&
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) {
        commit = true;
    }
    if (!commit)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);

    int64_t elapsed = platform_time_monotonic_us() - start_us;
    if (commit && !blocked)
        index_fold_clear_seed_blocker("txindex");
    atomic_store(&g_tx_blocked, blocked);
    atomic_store(&g_tx_blocked_height, blocked ? blocked_h : -1);
    atomic_store(&g_tx_last_batch_blocks, commit ? folded : 0);
    atomic_store(&g_tx_last_batch_us, elapsed);
    if (commit) {
        atomic_store(&g_tx_cursor, last_good);
        atomic_fetch_add(&g_tx_blocks_folded, folded);
        atomic_fetch_add(&g_tx_rows, total_added);
        char hex[65];
        HexStr(digest, 32, false, hex, sizeof(hex));
        pthread_mutex_lock(&g_tx_digest_lock);
        memcpy(g_tx_digest_hex, hex, sizeof(hex));
        pthread_mutex_unlock(&g_tx_digest_lock);
    }
    return commit ? folded : 0;
}

int txindex_projection_service_tick_once(void)
{
    if (!txindex_projection_enabled())
        return 0;
    struct main_state *ms = app_runtime_main_state();
    /* Wave A2 split: fold on the projection handle + projection tx lock, so
     * this batch never serialises on the reducer drive's kernel tx lock. */
    sqlite3 *db = projection_store_db();
    if (!ms || !db)
        return 0;
    char datadir[1024];
    GetDataDir(true, datadir, sizeof(datadir));
    if (!datadir[0])
        return 0;

    /* Non-blocking: if another projection batch owns the store, skip this tick
     * and try again next period. Never blocks the supervisor thread; never
     * stalls the drive beyond one bounded batch we hold ourselves. */
    if (!projection_store_tx_trylock())
        return 0;
    int folded = tx_do_batch(ms, datadir, db);
    projection_store_tx_unlock();
    return folded;
}

enum txindex_read_status txindex_projection_read_locate(
    const uint8_t txid[32], int64_t *height_out, uint8_t block_hash_out[32],
    int64_t *tx_n_out, int64_t *cursor_out)
{
    if (cursor_out) *cursor_out = -1;
    if (!txid || !txindex_projection_enabled())
        return TXINDEX_READ_DISABLED;
    sqlite3 *db = projection_store_db();
    if (!db)
        return TXINDEX_READ_DISABLED;
    if (!projection_store_tx_trylock())
        return TXINDEX_READ_BUSY;
    int64_t cursor = -1;
    (void)txindex_projection_get_cursor(db, &cursor);
    int r = txindex_projection_lookup(db, txid, height_out, block_hash_out,
                                      tx_n_out);
    projection_store_tx_unlock();
    if (cursor_out) *cursor_out = cursor;
    if (r < 0)
        return TXINDEX_READ_BUSY;           /* transient error — fail soft */
    int64_t hstar = (int64_t)tip_finalize_stage_cursor();
    return txindex_projection_classify(r == 1, cursor, hstar);
}

/* ── supervisor child (chain domain, on_tick driven) ────────────────── */
static void tx_tick(struct liveness_contract *c)
{
    (void)c;
    (void)txindex_projection_service_tick_once();
    int64_t marker = atomic_fetch_add(&g_tx_ticks, 1) + 1;
    supervisor_progress(atomic_load(&g_tx_id), marker);
    supervisor_tick(atomic_load(&g_tx_id));
}

bool txindex_projection_service_register(void)
{
    if (!txindex_projection_enabled())
        return false; // raw-return-ok:opt-in-disabled-is-not-a-failure
    supervisor_domains_init();
    if (atomic_load(&g_tx_id) != SUPERVISOR_INVALID_ID)
        return true;                        /* idempotent */
    liveness_contract_init(&g_tx_contract, "chain.txindex");
    atomic_store(&g_tx_contract.period_secs, (int64_t)TXINDEX_TICK_SECONDS);
    atomic_store(&g_tx_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_tx_contract.progress_max_quiet_us, (int64_t)0);
    g_tx_contract.on_tick = tx_tick;
    g_tx_contract.on_stall = NULL;
    supervisor_child_id id =
        supervisor_register_in_domain(g_chain_sup, &g_tx_contract);
    atomic_store(&g_tx_id, id);
    atomic_store(&g_tx_registered, id != SUPERVISOR_INVALID_ID);
    if (id == SUPERVISOR_INVALID_ID)
        LOG_WARN("txindex", "[txindex] supervisor register failed");
    return id != SUPERVISOR_INVALID_ID;
}

bool txindex_projection_service_registered(void)
{
    return atomic_load(&g_tx_registered);
}

/* ── dumpstate `txindex` ─────────────────────────────────────────────── */
static void tx_dump_status(struct json_value *out)
{
    int64_t cursor = atomic_load(&g_tx_cursor);
    int64_t hstar  = atomic_load(&g_tx_hstar);
    json_push_kv_int(out, "cursor", cursor);
    json_push_kv_int(out, "hstar", hstar);
    json_push_kv_int(out, "gap", (hstar > cursor) ? (hstar - cursor) : 0);
    json_push_kv_int(out, "rows", atomic_load(&g_tx_rows));
    json_push_kv_int(out, "blocks_folded_total",
                     atomic_load(&g_tx_blocks_folded));
    json_push_kv_int(out, "ticks", atomic_load(&g_tx_ticks));
    json_push_kv_int(out, "last_batch_blocks",
                     atomic_load(&g_tx_last_batch_blocks));
    json_push_kv_int(out, "last_batch_us", atomic_load(&g_tx_last_batch_us));
    json_push_kv_int(out, "resets", atomic_load(&g_tx_resets));
    json_push_kv_bool(out, "registered", atomic_load(&g_tx_registered));
    bool blocked = atomic_load(&g_tx_blocked);
    json_push_kv_bool(out, "coverage_blocked", blocked);
    if (blocked) {
        json_push_kv_int(out, "blocked_height",
                         atomic_load(&g_tx_blocked_height));
        json_push_kv_str(out, "blocked_reason", "body_absent");
    }
    pthread_mutex_lock(&g_tx_digest_lock);
    json_push_kv_str(out, "digest", g_tx_digest_hex[0] ? g_tx_digest_hex : "");
    pthread_mutex_unlock(&g_tx_digest_lock);
}

bool txindex_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        return false;
    json_set_object(out);
    json_push_kv_bool(out, "enabled", txindex_projection_enabled());

    if (!key || !key[0]) {
        /* Bare status read: atomics only — NO disk touch (health-rollup sweep
         * runs this in a datadir-less process). */
        tx_dump_status(out);
        return true;
    }

    /* keyed query: "<64-hex txid>" */
    char hexbuf[80];
    snprintf(hexbuf, sizeof(hexbuf), "%s", key);
    if (strlen(hexbuf) != 64 || !IsHex(hexbuf)) {
        json_push_kv_str(out, "error", "key must be a 64-hex txid");
        return true;
    }
    uint8_t txid[32];
    if (ParseHex(hexbuf, txid, sizeof(txid)) != 32) {
        json_push_kv_str(out, "error", "txid parse failed");
        return true;
    }

    json_push_kv_str(out, "txid", hexbuf);

    /* The keyed lookup queries the DB directly (independent of the -txindex
     * flag): the projection tables may exist and be inspectable even on a boot
     * that isn't actively backfilling. Only a KEY engages disk; the bare status
     * path above stays side-effect-free. */
    sqlite3 *db = projection_store_db();
    if (!db) {
        json_push_kv_str(out, "error", "projection store not open");
        return true;
    }
    if (!projection_store_tx_trylock()) {
        json_push_kv_bool(out, "busy", true);
        return true;
    }
    int64_t cursor = -1;
    (void)txindex_projection_get_cursor(db, &cursor);
    int64_t height = -1, tx_n = -1;
    uint8_t block_hash[32];
    int r = txindex_projection_lookup(db, txid, &height, block_hash, &tx_n);
    projection_store_tx_unlock();

    json_push_kv_int(out, "cursor", cursor);
    if (r < 0) {
        json_push_kv_str(out, "error", "lookup failed");
        return true;
    }
    int64_t hstar = (int64_t)tip_finalize_stage_cursor();
    switch (txindex_projection_classify(r == 1, cursor, hstar)) {
    case TXINDEX_READ_FOUND: {
        char bhex[65];
        HexStr(block_hash, 32, false, bhex, sizeof(bhex));
        json_push_kv_bool(out, "found", true);
        json_push_kv_int(out, "height", height);
        json_push_kv_str(out, "block_hash", bhex);
        json_push_kv_int(out, "tx_n", tx_n);
        break;
    }
    case TXINDEX_READ_BEHIND: {
        char msg[64];
        snprintf(msg, sizeof(msg), "txindex behind: cursor=%lld",
                 (long long)cursor);
        json_push_kv_bool(out, "found", false);
        json_push_kv_str(out, "error", msg);
        break;
    }
    case TXINDEX_READ_ABSENT:
    default:
        json_push_kv_bool(out, "found", false);
        break;
    }
    return true;
}
