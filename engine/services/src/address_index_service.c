// one-result-type-ok:json-dump-bool — the sole non-zcl_result surfaces here
// are the CLAUDE.md-convention dump (address_index_dump_state_json, bool) and
// the boolean supervisor-registration latch; every fallible DB primitive lives
// in jobs/address_index.c. There is no orchestration result to propagate.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * address_index_service — supervised, bounded backfill for the address_index
 * projection. See services/address_index_service.h for the design contract.
 *
 * Crash-only / projection discipline: a firing DB error or a missing body
 * stops THIS batch and surfaces a coverage blocker in dumpstate; the process
 * and every other stage keep running. It never changes a validity predicate or
 * the primary derivation — it only folds verified persisted bodies (<= H*) into
 * a rebuildable secondary index. */

#include "services/address_index_service.h"

#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "jobs/address_index.h"
#include "jobs/tip_finalize_stage.h"
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
static _Atomic bool    g_ai_registered      = false;
static _Atomic bool    g_ai_schema_ready    = false;
static _Atomic int64_t g_ai_cursor          = -1;
static _Atomic int64_t g_ai_hstar           = -1;
static _Atomic int64_t g_ai_rows            = 0;
static _Atomic int64_t g_ai_blocks_folded   = 0;   /* lifetime */
static _Atomic int64_t g_ai_ticks           = 0;
static _Atomic int64_t g_ai_last_batch_blocks = 0;
static _Atomic int64_t g_ai_last_batch_us   = 0;
static _Atomic int64_t g_ai_resets          = 0;
static _Atomic bool    g_ai_blocked         = false;
static _Atomic int64_t g_ai_blocked_height  = -1;

static pthread_mutex_t g_ai_digest_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_ai_digest_hex[65];

static struct liveness_contract g_ai_contract;
static _Atomic supervisor_child_id g_ai_id = SUPERVISOR_INVALID_ID;

/* ── one bounded fold batch (tx lock held by caller) ────────────────── */
static int ai_do_batch(struct main_state *ms, const char *datadir, sqlite3 *db)
{
    if (!atomic_load(&g_ai_schema_ready)) {
        if (!address_index_ensure_schema(db))
            return 0;
        int64_t rc0 = address_index_row_count(db);
        atomic_store(&g_ai_rows, rc0 >= 0 ? rc0 : 0);
        atomic_store(&g_ai_schema_ready, true);
    }

    int64_t cursor = -1;
    (void)address_index_get_cursor(db, &cursor);
    int64_t hstar = (int64_t)tip_finalize_stage_cursor();
    atomic_store(&g_ai_hstar, hstar);
    atomic_store(&g_ai_cursor, cursor);

    /* Deep-regression safety net: H* only advances under normal operation, so
     * cursor > H* means a reorg/rewind dropped finalized history below us. A
     * projection folded as a forward-only digest chain cannot partially unwind,
     * so drop-and-rederive from height 0 (cheap, rebuildable by construction). */
    if (hstar >= 0 && cursor > hstar) {
        if (address_index_drop(db) && address_index_ensure_schema(db)) {
            atomic_fetch_add(&g_ai_resets, 1);
            atomic_store(&g_ai_cursor, -1);
            atomic_store(&g_ai_rows, 0);
            pthread_mutex_lock(&g_ai_digest_lock);
            g_ai_digest_hex[0] = '\0';
            pthread_mutex_unlock(&g_ai_digest_lock);
        }
        return 0;
    }
    if (cursor >= hstar) {                 /* caught up to the finalized tip */
        atomic_store(&g_ai_blocked, false);
        atomic_store(&g_ai_last_batch_blocks, 0);
        index_fold_clear_seed_blocker("address_index");
        return 0;
    }

    /* Free-disk precheck: never start/continue the historical fold when disk
     * headroom is low — it raises a named address_index.disk_low blocker and
     * yields, so consensus writes keep their last bytes instead of the catalog
     * filling the disk. */
    if (!index_fold_disk_ok("address_index", "address_index", datadir))
        return 0;

    uint8_t digest[32];
    bool dfound = false;
    if (!address_index_get_digest(db, digest, &dfound))
        return 0;
    if (!dfound)
        memset(digest, 0, 32);

    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        LOG_WARN("address_index", "[address_index] BEGIN failed: %s",
                 sqlite3_errmsg(db));
        return 0;
    }

    int64_t start_us = platform_time_monotonic_us();
    int folded = 0, total_added = 0;
    bool blocked = false;
    int64_t blocked_h = -1, last_good = cursor;

    for (int64_t h = cursor + 1; h <= hstar && folded < ADDRESS_INDEX_BATCH_BLOCKS;
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
            index_fold_note_absent_body("address_index", "address_index",
                                            db, h);
            break;                          /* body absent — coverage floor */
        }
        int added = 0;
        bool put_ok = address_index_put_block(db, &blk, (int)h, digest, &added);
        block_free(&blk);
        if (!put_ok) {
            blocked = true;
            blocked_h = h;
            break;                          /* real DB error — surface + stop */
        }
        total_added += added;
        last_good = h;
        folded++;
        if (platform_time_monotonic_us() - start_us >= ADDRESS_INDEX_BATCH_US)
            break;                          /* wall-time budget spent */
    }

    bool commit = false;
    if (folded > 0 && address_index_set_cursor(db, last_good, digest) &&
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) {
        commit = true;
    }
    if (!commit)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);

    int64_t elapsed = platform_time_monotonic_us() - start_us;
    if (commit && !blocked)
        index_fold_clear_seed_blocker("address_index");
    atomic_store(&g_ai_blocked, blocked);
    atomic_store(&g_ai_blocked_height, blocked ? blocked_h : -1);
    atomic_store(&g_ai_last_batch_blocks, commit ? folded : 0);
    atomic_store(&g_ai_last_batch_us, elapsed);
    if (commit) {
        atomic_store(&g_ai_cursor, last_good);
        atomic_fetch_add(&g_ai_blocks_folded, folded);
        atomic_fetch_add(&g_ai_rows, total_added);
        char hex[65];
        HexStr(digest, 32, false, hex, sizeof(hex));
        pthread_mutex_lock(&g_ai_digest_lock);
        memcpy(g_ai_digest_hex, hex, sizeof(hex));
        pthread_mutex_unlock(&g_ai_digest_lock);
    }
    return commit ? folded : 0;
}

int address_index_service_tick_once(void)
{
    if (!address_index_enabled())
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
    int folded = ai_do_batch(ms, datadir, db);
    projection_store_tx_unlock();
    return folded;
}

/* ── supervisor child (chain domain, on_tick driven) ────────────────── */
static void ai_tick(struct liveness_contract *c)
{
    (void)c;
    (void)address_index_service_tick_once();
    int64_t marker = atomic_fetch_add(&g_ai_ticks, 1) + 1;
    supervisor_progress(atomic_load(&g_ai_id), marker);
    supervisor_tick(atomic_load(&g_ai_id));
}

bool address_index_service_register(void)
{
    if (!address_index_enabled())
        return false; // raw-return-ok:opt-in-disabled-is-not-a-failure
    supervisor_domains_init();
    if (atomic_load(&g_ai_id) != SUPERVISOR_INVALID_ID)
        return true;                        /* idempotent */
    liveness_contract_init(&g_ai_contract, "chain.address_index");
    atomic_store(&g_ai_contract.period_secs, (int64_t)ADDRESS_INDEX_TICK_SECONDS);
    atomic_store(&g_ai_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_ai_contract.progress_max_quiet_us, (int64_t)0);
    g_ai_contract.on_tick = ai_tick;
    g_ai_contract.on_stall = NULL;
    supervisor_child_id id =
        supervisor_register_in_domain(g_chain_sup, &g_ai_contract);
    atomic_store(&g_ai_id, id);
    atomic_store(&g_ai_registered, id != SUPERVISOR_INVALID_ID);
    if (id == SUPERVISOR_INVALID_ID)
        LOG_WARN("address_index", "[address_index] supervisor register failed");
    return id != SUPERVISOR_INVALID_ID;
}

bool address_index_service_registered(void)
{
    return atomic_load(&g_ai_registered);
}

/* ── dumpstate `address_index` ──────────────────────────────────────── */
static void ai_dump_status(struct json_value *out)
{
    int64_t cursor = atomic_load(&g_ai_cursor);
    int64_t hstar  = atomic_load(&g_ai_hstar);
    json_push_kv_int(out, "cursor", cursor);
    json_push_kv_int(out, "hstar", hstar);
    json_push_kv_int(out, "gap", (hstar > cursor) ? (hstar - cursor) : 0);
    json_push_kv_int(out, "rows", atomic_load(&g_ai_rows));
    json_push_kv_int(out, "blocks_folded_total",
                     atomic_load(&g_ai_blocks_folded));
    json_push_kv_int(out, "ticks", atomic_load(&g_ai_ticks));
    json_push_kv_int(out, "last_batch_blocks",
                     atomic_load(&g_ai_last_batch_blocks));
    json_push_kv_int(out, "last_batch_us", atomic_load(&g_ai_last_batch_us));
    json_push_kv_int(out, "resets", atomic_load(&g_ai_resets));
    json_push_kv_bool(out, "registered", atomic_load(&g_ai_registered));
    bool blocked = atomic_load(&g_ai_blocked);
    json_push_kv_bool(out, "coverage_blocked", blocked);
    if (blocked) {
        json_push_kv_int(out, "blocked_height",
                         atomic_load(&g_ai_blocked_height));
        json_push_kv_str(out, "blocked_reason", "body_absent");
    }
    pthread_mutex_lock(&g_ai_digest_lock);
    json_push_kv_str(out, "digest",
                     g_ai_digest_hex[0] ? g_ai_digest_hex : "");
    pthread_mutex_unlock(&g_ai_digest_lock);
}

bool address_index_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        return false;
    json_set_object(out);
    json_push_kv_bool(out, "enabled", address_index_enabled());

    if (!key || !key[0]) {
        ai_dump_status(out);
        return true;
    }

    /* keyed query: "<64-hex scripthash>[:<from_height>]" */
    char hexbuf[80];
    int64_t from_height = 0;
    snprintf(hexbuf, sizeof(hexbuf), "%s", key);
    char *colon = strchr(hexbuf, ':');
    if (colon) {
        *colon = '\0';
        from_height = strtoll(colon + 1, NULL, 10);
        if (from_height < 0)
            from_height = 0;
    }
    if (strlen(hexbuf) != 64 || !IsHex(hexbuf)) {
        json_push_kv_str(out, "error",
                         "key must be a 64-hex scripthash [:from_height]");
        return true;
    }
    uint8_t sh[32];
    if (ParseHex(hexbuf, sh, sizeof(sh)) != 32) {
        json_push_kv_str(out, "error", "scripthash parse failed");
        return true;
    }

    json_push_kv_str(out, "scripthash", hexbuf);
    json_push_kv_int(out, "from_height", from_height);

    sqlite3 *db = projection_store_db();
    if (!db) {
        json_push_kv_str(out, "error", "projection store not open");
        return true;
    }
    if (!projection_store_tx_trylock()) {
        json_push_kv_bool(out, "busy", true);
        return true;
    }
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    int64_t balance = 0;
    int n = address_index_query_appearances(db, sh, from_height,
                                            ADDRESS_INDEX_QUERY_MAX_ROWS,
                                            &arr, &balance);
    projection_store_tx_unlock();

    if (n < 0) {
        json_push_kv_str(out, "error", "query failed");
        json_free(&arr);
        return true;
    }
    json_push_kv(out, "appearances", &arr);
    json_push_kv_int(out, "count", n);
    json_push_kv_int(out, "balance", balance);
    if (n == ADDRESS_INDEX_QUERY_MAX_ROWS)
        json_push_kv_bool(out, "truncated", true);
    json_free(&arr);
    return true;
}
