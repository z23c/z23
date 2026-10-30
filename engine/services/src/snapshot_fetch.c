// one-result-type-ok:db-service-write-fn-callbacks — the two remaining bool
// exports (snapsync_discard_staging_write_internal, snapsync_rollback_receive_
// write_internal) are db_service_write_fn callback adapters bound to the shared
// `bool (*)(struct node_db*, void*)` typedef in config/db_service.h (consumed by
// db_service_run_write / snapsync_run_write_internal, and cross-used by
// sync_controller.c and utxo_mirror_sync_service.c). Their bool IS that shared
// write-runner contract's answer, not a snapshot-specific fallible-service
// return. The genuinely fallible receive surface here already returns struct
// zcl_result (snapsync_discard_staging_internal / _txn_internal / _set_staging_
// phase_internal / _exit_turbo_mode_internal / _begin_receive / _handle_end) —
// the callbacks just forward .ok from those.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * snapshot_fetch.c — snapshot chunk receive.
 *
 * Owns the receive-mode database PRAGMA tuning ("turbo mode"),
 * the staging table maintenance, the chunk wire-format parser,
 * and the chunk-application write path. Also handles the trigger
 * point for handing off to verify (snapsync_handle_end). */

#include "net/snapshot_sync_contract.h"
#include "models/database.h"
#include "models/db_txn.h"
#include "models/utxo.h"
#include "coins/utxo_commitment.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/trace.h"

#include "snapshot_sync_internal.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── Staging helpers ─────────────────────────────────────── */

struct zcl_result snapsync_discard_staging_internal(struct node_db *ndb,
                                                    const char *reason)
{
    if (!ndb || !ndb->open)
        return ZCL_ERR(-1, "discard_staging: ndb null or not open");
    bool ok = node_db_exec(ndb, "DELETE FROM " SNAPSYNC_STAGING_TABLE);
    ok &= node_db_exec(ndb,
                       "DELETE FROM node_state WHERE key LIKE 'snapshot_staging_%'");
    if (reason && *reason) {
        ok &= node_db_state_set(ndb, SNAPSYNC_STAGING_LAST_DISCARD_KEY,
                                reason, strlen(reason));
    }
    if (!ok)
        return ZCL_ERR(-2, "discard_staging: exec failed reason=%s",
                       reason ? reason : "");
    return ZCL_OK;
}

struct zcl_result snapsync_discard_staging_txn_internal(struct node_db *ndb,
                                           const char *label,
                                           const char *reason)
{
    if (!ndb || !ndb->open)
        return ZCL_ERR(-1, "discard_staging_txn: ndb null or not open");
    DB_TXN_SCOPE(txn, ndb, label ? label : "snapsync.discard_staging");
    if (!txn)
        return ZCL_ERR(-2, "discard_staging_txn: failed to open db_txn scope");
    struct zcl_result r = snapsync_discard_staging_internal(ndb, reason);
    if (!r.ok)
        return r;
    if (!db_txn_commit(txn))
        return ZCL_ERR(-3, "discard_staging_txn: db_txn_commit failed");
    return ZCL_OK;
}

struct zcl_result snapsync_set_staging_phase_internal(struct node_db *ndb,
                                                      const char *phase)
{
    if (!ndb || !ndb->open || !phase || !*phase)
        return ZCL_ERR(-1, "set_staging_phase: null/closed ndb or empty phase");
    if (!node_db_state_set(ndb, SNAPSYNC_STAGING_PHASE_KEY,
                           phase, strlen(phase)))
        return ZCL_ERR(-2, "set_staging_phase: state_set failed phase=%s", phase);
    return ZCL_OK;
}

bool snapsync_discard_staging_write_internal(struct node_db *ndb, void *ctx)
{
    return snapsync_discard_staging_internal(ndb, (const char *)ctx).ok;
}

static bool snapsync_insert_staging_raw(struct node_db *ndb,
                                        const struct db_utxo *u)
{
    struct snapshot_store_sqlite_ctx sctx;
    struct snapshot_store_port store = {0};

    if (!snapsync_bind_store_internal(&sctx, ndb, &store).ok)
        return false;  // raw-return-ok:bind-only-fails-on-null-ctx/port-both-local-addresses
    return store.staging_insert(store.self, u);
}

int64_t snapsync_staging_count_internal(struct node_db *ndb)
{
    struct snapshot_store_sqlite_ctx sctx;
    struct snapshot_store_port store = {0};

    if (!ndb || !ndb->open || !ndb->db)
        LOG_ERR("snapshot_sync", "staging_count: ndb=%p open=%d db=%p",
                (void*)ndb, ndb ? ndb->open : 0,
                ndb ? (void*)ndb->db : NULL);
    if (!snapsync_bind_store_internal(&sctx, ndb, &store).ok)
        LOG_ERR("snapshot_sync", "staging_count: bind snapshot store failed");
    return store.staging_count(store.self);
}

void snapsync_hash_staging_internal(struct node_db *ndb, uint8_t out[32],
                                    uint64_t *utxo_count)
{
    utxo_commitment_sha3_compute_table(ndb ? ndb->db : NULL,
                                       SNAPSYNC_STAGING_TABLE,
                                       out, utxo_count);
}

/* ── Receive-mode DB tuning ──────────────────────────────── */

static void snapsync_set_db_mode_flag(struct node_db *ndb, bool turbo_mode)
{
    if (!ndb)
        return;
    if (ndb->state_mutex_init)
        zcl_mutex_lock(&ndb->state_mutex);
    ndb->turbo_mode = turbo_mode;
    if (ndb->state_mutex_init)
        zcl_mutex_unlock(&ndb->state_mutex);
}

static bool snapsync_enter_receive_mode_write(struct node_db *ndb, void *ctx)
{
    bool *ok = ctx;

    if (!ndb || !ndb->open) {
        if (ok)
            *ok = false;
        LOG_FAIL("snapshot_sync", "enter_receive_mode: ndb null or not open");
    }

    /* Use synchronous=NORMAL (not OFF) for crash safety.  In WAL mode,
     * NORMAL only fsyncs at WAL checkpoint, not every write — nearly as
     * fast as OFF but the database survives a process crash.  With OFF,
     * a crash during receive leaves the DB in an indeterminate state. */
    if (!node_db_exec(ndb, "PRAGMA synchronous=NORMAL") ||
        !node_db_exec(ndb, "PRAGMA cache_size=-524288") ||
        !node_db_exec(ndb, "PRAGMA wal_autocheckpoint=0")) {
        if (ok)
            *ok = false;
        LOG_FAIL("snapshot_sync", "enter_receive_mode: PRAGMA setup failed");
    }
    {
        struct snapshot_store_sqlite_ctx sctx;
        struct snapshot_store_port store = {0};
        if (snapsync_bind_store_internal(&sctx, ndb, &store).ok)
            (void)store.set_busy_timeout(store.self, 10000);
    }
    snapsync_set_db_mode_flag(ndb, true);
    printf("db: snapshot receive mode (synchronous=NORMAL, WAL deferred, 512MB cache)\n");
    if (ok)
        *ok = true;
    return true;
}

static bool snapsync_exit_receive_mode_write(struct node_db *ndb, void *ctx)
{
    bool *ok = ctx;

    if (!ndb || !ndb->open) {
        if (ok)
            *ok = false;
        LOG_FAIL("snapshot_sync", "exit_receive_mode: ndb null or not open");
    }

    if (!node_db_exec(ndb, "PRAGMA synchronous=NORMAL") ||
        !node_db_restore_cache_size(ndb) ||
        !node_db_exec(ndb, "PRAGMA wal_autocheckpoint=1000")) {
        if (ok)
            *ok = false;
        LOG_FAIL("snapshot_sync", "exit_receive_mode: PRAGMA restore failed");
    }
    if (!node_db_wal_checkpoint(ndb)) {
        if (ok)
            *ok = false;
        LOG_FAIL("snapshot_sync", "exit_receive_mode: WAL checkpoint failed");
    }
    snapsync_set_db_mode_flag(ndb, false);
    printf("db: snapshot receive mode cleared (synchronous=NORMAL, indexes preserved)\n");
    if (ok)
        *ok = true;
    return true;
}

struct zcl_result snapsync_exit_turbo_mode_internal(struct snapshot_sync_service *svc)
{
    bool turbo_active = false;
    bool ok = false;

    if (!svc || !svc->ndb)
        return ZCL_ERR(-1, "exit_turbo_mode: svc or ndb is NULL");

    snapsync_service_lock_internal();
    turbo_active = svc->turbo_active;
    snapsync_service_unlock_internal();
    if (!turbo_active)
        return ZCL_OK;

    ok = snapsync_run_write_internal(svc, snapsync_exit_receive_mode_write, &ok) && ok;

    if (!ok)
        return ZCL_ERR(-2, "exit_turbo_mode: exit_receive_mode write failed");

    snapsync_service_lock_internal();
    svc->turbo_active = false;
    snapsync_service_unlock_internal();

    return ZCL_OK;
}

static bool snapsync_begin_receive_write(struct node_db *ndb, void *ctx)
{
    struct snapshot_sync_service *svc = ctx;
    struct node_db_status status = {0};

    if (!svc || !ndb || !ndb->open)
        LOG_FAIL("snapshot_sync", "begin_receive_write: svc=%p ndb=%p open=%d",
                 (void*)svc, (void*)ndb, ndb ? ndb->open : 0);

    node_db_get_status(ndb, &status);
    if (status.tx_open) {
        if (!node_db_sync_flush(ndb))
            LOG_FAIL("snapshot_sync", "begin_receive: failed to flush stale transaction");
        node_db_get_status(ndb, &status);
        if (status.tx_open) {
            if (!node_db_commit(ndb))
                LOG_FAIL("snapshot_sync", "begin_receive: failed to close stale transaction");
        }
    }
    /* Reset the isolated staging namespace only. Active utxos remain
     * untouched until snapshot_verify passes and atomic_activate promotes
     * the staged rows in one transaction. */
    {
        DB_TXN_SCOPE(txn, ndb, "snapsync.begin_receive");
        if (!txn)
            LOG_FAIL("snapshot_sync", "begin_receive_write: failed to open db_txn scope");

        if (!snapsync_discard_staging_internal(ndb, "begin_receive").ok)
            LOG_FAIL("snapshot_sync", "begin_receive_write: staging cleanup failed");
        if (!snapsync_set_staging_phase_internal(ndb, SNAPSYNC_PHASE_CHUNK_RECEIVE).ok)
            LOG_FAIL("snapshot_sync", "begin_receive_write: failed to set staging phase");

        if (!db_txn_commit(txn))
            LOG_FAIL("snapshot_sync", "begin_receive_write: db_txn_commit failed after staging reset");
    }

    /* Reopen a plain transaction for the chunk receive loop. The
     * chunk writer batches node_db_commit/node_db_begin pairs every
     * SNAPSYNC_BATCH_COMMIT_ROWS rows and relies on having an open
     * transaction at entry. */
    if (!node_db_begin(ndb))
        LOG_FAIL("snapshot_sync", "begin_receive_write: node_db_begin failed for chunk loop");

    svc->received_utxos = 0;
    svc->last_commit_at = 0;
    return true;
}

bool snapsync_rollback_receive_write_internal(struct node_db *ndb, void *ctx)
{
    struct node_db_status status = {0};

    (void)ctx;
    if (!ndb || !ndb->open)
        LOG_FAIL("snapshot_sync", "rollback_receive_write: ndb null or not open");
    node_db_get_status(ndb, &status);
    if (!status.tx_open)
        return true;
    return node_db_rollback(ndb);
}

static bool snapsync_apply_chunk_args_ok(const struct snapshot_sync_service *svc,
                                         const uint8_t *chunk_data, size_t chunk_len)
{
    return svc && svc->ndb && svc->ndb->open && chunk_data && chunk_len >= 4;
}

static bool snapsync_chunk_entry_count_ok(uint32_t entries)
{
    return entries != 0 && entries <= 1000;
}

/* Read a little-endian unsigned integer of nbytes (1..8) from p. */
static uint64_t snapsync_chunk_read_le(const uint8_t *p, size_t nbytes)
{
    uint64_t v = 0;
    for (size_t k = 0; k < nbytes; k++)
        v |= (uint64_t)p[k] << (k * 8);
    return v;
}

/* Decode the fixed 48-byte entry prefix (txid, vout, value, height) and
 * advance *pos past it. The caller has checked that 48 bytes remain. */
static void snapsync_chunk_read_fixed(const uint8_t *chunk_data, size_t *pos, struct db_utxo *u)
{
    size_t p = *pos;

    memcpy(u->txid, chunk_data + p, 32); p += 32;
    u->vout = (uint32_t)snapsync_chunk_read_le(chunk_data + p, 4);
    p += 4;
    u->value = (int64_t)snapsync_chunk_read_le(chunk_data + p, 8);
    p += 8;
    u->height = (int)(chunk_data[p] | (chunk_data[p+1] << 8) |
                (chunk_data[p+2] << 16) | (chunk_data[p+3] << 24));
    p += 4;
    *pos = p;
}

/* Extra bytes that follow a script-length prefix byte: 2 for 253, 4 for 254. */
static size_t snapsync_chunk_varint_ext(uint64_t first)
{
    if (first == 253)
        return 2;
    if (first == 254)
        return 4;
    return 0;
}

/* Script length: the prefix byte itself, or the ext bytes after it (which
 * advances *pos past them). */
static uint64_t snapsync_chunk_varint_value(const uint8_t *chunk_data, size_t *pos,
                                            uint64_t first, size_t ext)
{
    uint64_t v = first;

    if (ext) {
        v = snapsync_chunk_read_le(chunk_data + *pos, ext);
        *pos += ext;
    }
    return v;
}

/* Account the applied rows under the service lock. Returns false when the
 * service is no longer receiving (nothing is counted then). */
static bool snapsync_chunk_account(struct snapshot_sync_service *svc, int applied,
                                   bool *commit_batch, uint64_t *received,
                                   uint64_t *offered_count, uint32_t *serving_peer_id)
{
    snapsync_service_lock_internal();
    if (svc->state != SNAPSYNC_RECEIVING) {
        snapsync_service_unlock_internal();
        return false;
    }

    svc->received_utxos += (uint64_t)applied;
    svc->last_progress_time_us = snapsync_now_us_internal();
    *received = svc->received_utxos;
    *offered_count = svc->offered_count;
    *serving_peer_id = svc->serving_peer_id;
    if (*received - svc->last_commit_at >= SNAPSYNC_BATCH_COMMIT_ROWS) {
        *commit_batch = true;
        svc->last_commit_at = *received;
    }
    snapsync_service_unlock_internal();
    return true;
}

/* When a batch is due, commit and reopen the transaction, then emit the
 * progress event. Returns false when the commit/begin pair failed. */
static bool snapsync_chunk_commit_batch(struct snapshot_sync_service *svc, bool commit_batch,
                                        uint64_t received, uint64_t offered_count,
                                        uint32_t serving_peer_id)
{
    if (!commit_batch)
        return true;
    if (!node_db_commit(svc->ndb) || !node_db_begin(svc->ndb))
        return false; // raw-return-ok:caller snapsync_apply_chunk_local logs the batch commit/begin failure

    double elapsed_s = (double)(snapsync_now_us_internal() - svc->start_time_us) / 1000000.0;
    double rate = elapsed_s > 0 ? (double)received / elapsed_s : 0;
    event_emitf(EV_SNAPSYNC_PROGRESS, serving_peer_id,
                "received=%llu/%llu rate=%.0f/s",
                (unsigned long long)received,
                (unsigned long long)offered_count, rate);
    return true;
}

static int snapsync_apply_chunk_local(struct snapshot_sync_service *svc,
                                      const uint8_t *chunk_data,
                                      size_t chunk_len)
{
    size_t pos = 4;
    int applied = 0;
    uint32_t entries;
    bool commit_batch = false;
    uint32_t serving_peer_id = 0;
    uint64_t offered_count = 0;
    uint64_t received = 0;

    if (!snapsync_apply_chunk_args_ok(svc, chunk_data, chunk_len))
        LOG_ERR("snapshot_sync", "apply_chunk: invalid args svc=%p chunk=%p len=%zu",
                (void*)svc, (void*)chunk_data, chunk_len);

    entries = (uint32_t)snapsync_chunk_read_le(chunk_data, 4);
    if (!snapsync_chunk_entry_count_ok(entries))
        LOG_ERR("snapshot_sync", "apply_chunk: bad entry count %u", entries);

    for (uint32_t i = 0; i < entries; i++) {
        if (pos + 48 > chunk_len) LOG_ERR("snapshot_sync", "apply_chunk: truncated entry %u at pos %zu (need 48, have %zu)", i, pos, chunk_len);

        struct db_utxo u;
        memset(&u, 0, sizeof(u));
        snapsync_chunk_read_fixed(chunk_data, &pos, &u);

        if (pos >= chunk_len) LOG_ERR("snapshot_sync", "apply_chunk: truncated at coinbase flag, entry %u pos %zu", i, pos);
        u.is_coinbase = (chunk_data[pos++] != 0);

        if (pos >= chunk_len) LOG_ERR("snapshot_sync", "apply_chunk: truncated at script varint, entry %u pos %zu", i, pos);
        uint64_t slen = chunk_data[pos++];
        size_t ext = snapsync_chunk_varint_ext(slen);
        if (ext && pos + ext > chunk_len) {
            if (ext == 2) LOG_ERR("snapshot_sync", "apply_chunk: truncated at 2-byte varint, entry %u pos %zu", i, pos);
            else LOG_ERR("snapshot_sync", "apply_chunk: truncated at 4-byte varint, entry %u pos %zu", i, pos);
        }
        slen = snapsync_chunk_varint_value(chunk_data, &pos, slen, ext);
        if (pos + slen > chunk_len) LOG_ERR("snapshot_sync", "apply_chunk: script overflows chunk, entry %u pos %zu slen %llu", i, pos, (unsigned long long)slen);

        u.script = (uint8_t *)(chunk_data + pos);
        u.script_len = (size_t)slen;
        pos += slen;

        u.script_type = utxo_classify_script(u.script, u.script_len,
                                             u.address_hash, &u.has_address);

        if (!snapsync_insert_staging_raw(svc->ndb, &u))
            LOG_ERR("snapshot_sync", "apply_chunk: staging insert failed at entry %u vout=%u", i, u.vout);
        applied++;
    }

    if (!snapsync_chunk_account(svc, applied, &commit_batch, &received,
                                &offered_count, &serving_peer_id))
        return 0;

    if (!snapsync_chunk_commit_batch(svc, commit_batch, received, offered_count, serving_peer_id))
        LOG_ERR("snapshot_sync", "apply_chunk: batch commit/begin failed at %llu UTXOs", (unsigned long long)received);

    return applied;
}

static bool snapsync_apply_chunk_write(struct node_db *ndb, void *ctx)
{
    struct snapsync_apply_chunk_ctx *apply = ctx;

    (void)ndb;
    if (!apply || !apply->svc || !apply->chunk_data)
        LOG_FAIL("snapshot_sync", "apply_chunk_write: null context apply=%p", (void*)apply);
    apply->applied = snapsync_apply_chunk_local(apply->svc,
                                                apply->chunk_data,
                                                apply->chunk_len);
    return apply->applied >= 0;
}

/* ── Begin Receive ───────────────────────────────────────── */

struct zcl_result snapsync_begin_receive(struct snapshot_sync_service *svc)
{
    struct trace_span *ss_span = trace_start("snapsync.begin_receive");

    if (!svc) {
        trace_set_status(ss_span, TRACE_STATUS_ERROR);
        trace_attr_str(ss_span, "error", "null_svc");
        trace_end(ss_span);
        return ZCL_ERR(-1, "begin_receive: svc is NULL");
    }
    trace_attr_int(ss_span, "snap_height", svc->offered_height);

    snapsync_service_lock_internal();
    if (svc->state != SNAPSYNC_NEGOTIATING) {
        event_emitf(EV_SNAPSYNC_VERIFIED, svc->serving_peer_id,
                    "snapshot=FAILED reason=begin_receive_wrong_state state=%s",
                    snapsync_state_name(svc->state));
        snapsync_service_unlock_internal();
        trace_set_status(ss_span, TRACE_STATUS_ERROR);
        trace_attr_str(ss_span, "error", "wrong_state");
        trace_end(ss_span);
        return ZCL_ERR(-2, "begin_receive: wrong state (not NEGOTIATING)");
    }
    if (!svc->ndb) {
        event_emitf(EV_SNAPSYNC_VERIFIED, svc->serving_peer_id,
                    "snapshot=FAILED reason=begin_receive_no_db");
        snapsync_service_unlock_internal();
        trace_set_status(ss_span, TRACE_STATUS_ERROR);
        trace_end(ss_span);
        return ZCL_ERR(-3, "begin_receive: no db");
    }
    if (!svc->ndb->open) {
        event_emitf(EV_SNAPSYNC_VERIFIED, svc->serving_peer_id,
                    "snapshot=FAILED reason=begin_receive_db_closed");
        snapsync_service_unlock_internal();
        trace_set_status(ss_span, TRACE_STATUS_ERROR);
        trace_end(ss_span);
        return ZCL_ERR(-4, "begin_receive: db closed");
    }

    /* Snapshot receive is a live-node path after startup. Keep schema stable
     * and only relax bulk-write pragmas here instead of dropping indexes. */
    bool receive_mode_ok = false;
    if (!snapsync_run_write_internal(svc, snapsync_enter_receive_mode_write,
                                     &receive_mode_ok) ||
        !receive_mode_ok) {
        snapsync_service_unlock_internal();
        trace_set_status(ss_span, TRACE_STATUS_ERROR);
        trace_attr_str(ss_span, "error", "enter_receive_mode");
        trace_end(ss_span);
        return ZCL_ERR(-5, "begin_receive: enter_receive_mode failed");
    }
    svc->turbo_active = true;
    snapsync_service_unlock_internal();

    if (!snapsync_run_write_internal(svc, snapsync_begin_receive_write, svc)) {
        /* Check .ok so a stuck turbo pragma set leaves a trace. */
        if (!snapsync_exit_turbo_mode_internal(svc).ok)
            event_emitf(EV_SNAPSYNC_VERIFIED, 0,
                        "snapshot=FAILED reason=turbo_exit_failed path=begin_receive");
        trace_set_status(ss_span, TRACE_STATUS_ERROR);
        trace_attr_str(ss_span, "error", "begin_receive_write");
        trace_end(ss_span);
        return ZCL_ERR(-6, "begin_receive: begin_receive_write failed");
    }
    if (!sync_set_state(SYNC_SNAPSHOT_RECEIVE, "snapshot receive started")) {
        snapsync_run_write_internal(svc, snapsync_rollback_receive_write_internal, NULL);
        snapsync_reset(svc);
        trace_set_status(ss_span, TRACE_STATUS_ERROR);
        trace_attr_str(ss_span, "error", "sync_set_state");
        trace_end(ss_span);
        return ZCL_ERR(-7, "begin_receive: sync_set_state failed");
    }

    snapsync_service_lock_internal();
    svc->state = SNAPSYNC_RECEIVING;
    svc->last_progress_time_us = snapsync_now_us_internal();  /* start stall timer */
    svc->last_progress_utxos = 0;
    snapsync_set_state(SNAPSYNC_RECEIVING, "receive mode active");
    snapsync_service_unlock_internal();
    trace_end(ss_span);
    return ZCL_OK;
}

/* ── Apply Chunk ─────────────────────────────────────────── */

int snapsync_apply_chunk(struct snapshot_sync_service *svc,
                         const uint8_t *chunk_data, size_t chunk_len)
{
    struct snapsync_apply_chunk_ctx ctx;
    bool restore_turbo = false;
    if (!svc || !chunk_data || chunk_len < 4)
        LOG_ERR("snapshot_sync", "apply_chunk: invalid args svc=%p chunk=%p len=%zu",
                (void*)svc, (void*)chunk_data, chunk_len);

    snapsync_service_lock_internal();

    /* Only accept chunks in RECEIVING state.
     * NEGOTIATING means FlyClient verification hasn't completed yet —
     * do NOT auto-transition, that would bypass chain verification. */
    if (svc->state != SNAPSYNC_RECEIVING) {
        snapsync_service_unlock_internal();
        return 0;
    }
    if (!svc->ndb || !svc->ndb->open) {
        snapsync_service_unlock_internal();
        LOG_ERR("snapshot_sync", "apply_chunk: ndb null or not open during RECEIVING");
    }
    restore_turbo = svc->turbo_active;

    memset(&ctx, 0, sizeof(ctx));
    ctx.svc = svc;
    ctx.chunk_data = zcl_malloc(chunk_len, "snapsync chunk copy");
    if (!ctx.chunk_data) {
        snapsync_service_unlock_internal();
        LOG_ERR("snapshot_sync", "apply_chunk: malloc(%zu) failed for chunk copy", chunk_len);
    }
    memcpy(ctx.chunk_data, chunk_data, chunk_len);
    ctx.chunk_len = chunk_len;
    snapsync_service_unlock_internal();

    if (!snapsync_run_write_internal(svc, snapsync_apply_chunk_write, &ctx)) {
        free(ctx.chunk_data);
        if (restore_turbo)
            snapsync_run_write_internal(svc, snapsync_rollback_receive_write_internal, NULL);
        snapsync_service_lock_internal();
        svc->state = SNAPSYNC_FAILED;
        snapsync_set_state(SNAPSYNC_FAILED, "snapshot chunk apply failed");
        snapsync_service_unlock_internal();
        if (restore_turbo && !snapsync_exit_turbo_mode_internal(svc).ok)
            event_emitf(EV_SNAPSYNC_VERIFIED, 0,
                        "snapshot=FAILED reason=turbo_exit_failed path=chunk_apply");
        LOG_ERR("snapsync", "chunk apply failed");
    }
    free(ctx.chunk_data);
    return ctx.applied;
}

/* Action: handle snapshot end from peer.
 * Validates peer identity and state, finalizes. */
struct zcl_result snapsync_handle_end(struct snapshot_sync_service *svc, uint32_t peer_id)
{
    enum snapshot_sync_state state = SNAPSYNC_IDLE;
    uint32_t serving_peer_id = 0;
    uint64_t received = 0;

    if (!svc) return ZCL_ERR(-1, "handle_end: svc is NULL");
    snapsync_service_lock_internal();
    state = svc->state;
    serving_peer_id = svc->serving_peer_id;
    received = svc->received_utxos;
    snapsync_service_unlock_internal();

    /* Only accept from the peer we're syncing from */
    if (serving_peer_id != peer_id) {
        printf("[snapsync] Ignoring zsnapend from peer %u "
               "(serving from %u)\n", peer_id, serving_peer_id);
        return ZCL_ERR(-2, "handle_end: peer %u not serving peer %u",
                       peer_id, serving_peer_id);
    }

    if (state != SNAPSYNC_RECEIVING) {
        printf("[snapsync] Ignoring zsnapend in state %s\n",
               snapsync_state_name(state));
        return ZCL_ERR(-3, "handle_end: not in RECEIVING state (%s)",
                       snapsync_state_name(state));
    }

    event_emitf(EV_SNAPSHOT_COMPLETE, peer_id,
                "%llu UTXOs received",
                (unsigned long long)received);

    return snapsync_finalize(svc);
}
