/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_helpers — shared static-inline helpers for the eight Job stages
 * in engine/jobs/src.
 *
 *   stage_cursor_persisted    — read the DURABLY committed cursor of an
 *                               upstream stage from the stage_cursor table.
 *   stage_default_block_reader — read a block body from disk via the
 *                               block_index entry (HAVE_DATA guarded).
 *   stage_log_row_count       — SELECT COUNT(*) over a stage's log table
 *                               for the *_dump_state_json observability.
 *   stage_upstream_log_hole_note/_clear — name a typed blocker when a
 *                               stage's floor check proves an upstream
 *                               *_log row SHOULD exist but a SELECT at
 *                               that height finds none (a torn co-commit
 *                               invariant, not "not yet" — see the
 *                               lane/stall-taxonomy audit).
 *   stage_body_read_hold/_clear — name a typed blocker when a block body
 *                               that body_persist already hash+merkle
 *                               verified fails to re-read at a later
 *                               stage (on-disk bytes vanished/corrupted
 *                               after that verification).
 *
 * Each takes a `tag` argument so LOG_WARN attribution stays with the calling
 * stage name ("body_persist", "script_validate", ...). */

#ifndef ZCL_JOBS_STAGE_HELPERS_H
#define ZCL_JOBS_STAGE_HELPERS_H

#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "storage/block_parse_cache.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct stage_cursor_read_result {
    bool ok;        /* false = sqlite/read error; caller must not trust cursor */
    bool found;     /* false + ok = no durable row yet; cursor is 0 */
    uint64_t cursor;
    int sqlite_rc;
};

/* Read the persisted cursor of an upstream stage. Query the stage_cursor
 * table directly rather than the in-memory accessor so the floor reflects
 * what is DURABLY committed, not the in-memory value (0 on fresh init
 * until the first stage_run_once). `tag` is the calling stage's name for
 * log attribution. Missing row is a valid fresh-stage result
 * (ok=true/found=false/cursor=0); sqlite/schema/read failures are explicit
 * (ok=false) so stage gates cannot silently reinterpret corruption as
 * cursor 0.
 *
 * This is the RAW cursor read. The F1 log-derived upstream FRONTIER
 * (stage_upstream_frontier_or_zero below) layers on top for the five
 * pipeline floor checks that gate forward progress; every other reader —
 * self control-flow, the invariant_sentinel's cursor-vs-frontier
 * consistency checks, repair rewind bounds, observability — keeps reading
 * this raw cursor. */
static inline struct stage_cursor_read_result
stage_cursor_read_persisted(sqlite3 *db, const char *name, const char *tag)
{
    struct stage_cursor_read_result r = {
        .ok = false,
        .found = false,
        .cursor = 0,
        .sqlite_rc = SQLITE_MISUSE,
    };
    const char *log_tag = (tag && tag[0]) ? tag : "stage_cursor";

    if (!db || !name || !name[0]) {
        LOG_WARN(log_tag, "[%s] upstream cursor read invalid args db=%p name=%s",
                 log_tag, (void *)db, name ? name : "(null)");
        return r;
    }

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT cursor FROM stage_cursor WHERE name = ?",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        r.sqlite_rc = rc;
        LOG_WARN(log_tag, "[%s] upstream cursor prepare failed stage=%s rc=%d: %s",
                 log_tag, name, rc, sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return r;
    }

    rc = sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        r.sqlite_rc = rc;
        LOG_WARN(log_tag, "[%s] upstream cursor bind failed stage=%s rc=%d: %s",
                 log_tag, name, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        progress_store_tx_unlock();
        return r;
    }

    rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    r.sqlite_rc = rc;
    if (rc == SQLITE_ROW) {
        r.ok = true;
        r.found = true;
        r.cursor = (uint64_t)sqlite3_column_int64(st, 0);
    } else if (rc == SQLITE_DONE) {
        r.ok = true;
    } else {
        LOG_WARN(log_tag, "[%s] upstream cursor step failed stage=%s rc=%d: %s",
                 log_tag, name, rc, sqlite3_errmsg(db));
    }

    int frc = sqlite3_finalize(st);
    if (r.ok && frc != SQLITE_OK) {
        r.ok = false;
        r.sqlite_rc = frc;
        LOG_WARN(log_tag,
                 "[%s] upstream cursor finalize failed stage=%s rc=%d: %s",
                 log_tag, name, frc, sqlite3_errmsg(db));
    }
    progress_store_tx_unlock();
    return r;
}

static inline bool stage_cursor_read_or_zero(sqlite3 *db, const char *name,
                                             const char *tag, uint64_t *out)
{
    if (out)
        *out = 0;

    /* A stage drain holds one outer transaction while its upstream cursor is
     * immutable. Cache that identical SELECT once per thread/batch generation;
     * outside a batch every call still reads durable storage. TLS avoids a
     * cross-thread observer race, and the generation prevents stale reuse. */
    static _Thread_local sqlite3 *cached_db;
    static _Thread_local uint64_t cached_generation;
    static _Thread_local char cached_name[64];
    static _Thread_local struct stage_cursor_read_result cached_result;
    bool batched = stage_batch_active();
    uint64_t generation = batched ? stage_batch_generation() : 0;
    if (batched && cached_db == db && cached_generation == generation &&
        name && strcmp(cached_name, name) == 0) {
        if (!cached_result.ok)
            return false;
        if (out)
            *out = cached_result.found ? cached_result.cursor : 0;
        return true;
    }

    struct stage_cursor_read_result r =
        stage_cursor_read_persisted(db, name, tag);
    if (batched && name && strlen(name) < sizeof(cached_name)) {
        cached_db = db;
        cached_generation = generation;
        memcpy(cached_name, name, strlen(name) + 1);
        cached_result = r;
    }
    if (!r.ok)
        return false;
    if (out)
        *out = r.found ? r.cursor : 0;
    return true;
}

/* Compatibility wrapper for non-critical observers/tests that still want
 * the historical scalar contract. New liveness gates should call
 * stage_cursor_read_or_zero() and handle ok=false explicitly. */
static inline uint64_t stage_cursor_persisted(sqlite3 *db, const char *name,
                                              const char *tag)
{
    uint64_t out = 0;
    (void)stage_cursor_read_or_zero(db, name, tag, &out);
    return out;
}

/* ── F1: read an UPSTREAM stage's log-derived FRONTIER as a progress floor ──
 *
 * The surgical F1 seam. The five pipeline floor checks that gate how far a
 * stage may advance — body_fetch<-validate_headers, script_validate<-
 * body_persist, proof_validate<-script_validate, utxo_apply<-proof_validate,
 * tip_finalize<-utxo_apply — read the UPSTREAM's contiguous ok=1 *_log prefix
 * (reducer_frontier_stage_cursor_derived) instead of its raw stage_cursor row,
 * so the LOG is the read authority for what an upstream has actually PROVEN.
 * The derived value is clamped to the still-written raw cursor: it EQUALS the
 * raw cursor in every contiguous state (the dual-write / single-read
 * equivalence) and only LOWERS the floor to the proven prefix when the
 * upstream's log has a durable hole below its cursor — strictly safer than
 * advancing past an unproven forced cursor.
 *
 * This is ONLY for those upstream-ceiling floor reads. Self control-flow reads,
 * the invariant_sentinel's cursor-vs-log-frontier consistency checks, repair
 * rewind bounds, and observability all keep stage_cursor_read_or_zero (the raw
 * cursor) — they inspect or heal the raw cursor and must SEE it, not the
 * log-clamped frontier.
 *
 * Cached once per (db, batch generation, name): during a drain batch the
 * upstream cursor is immutable, so this walks the upstream log at most once per
 * batch (the derived reader's own memo further dedups a STATIC upstream across
 * batches, keeping the reducer's O(1)-per-finalize fast-forward ratchet).
 * ok=false on a real read error; *out is the frontier otherwise. */
static inline bool stage_upstream_frontier_or_zero(sqlite3 *db, const char *name,
                                                   const char *tag, uint64_t *out)
{
    (void)tag;
    if (out)
        *out = 0;
    static _Thread_local sqlite3 *cached_db;
    static _Thread_local uint64_t cached_generation;
    static _Thread_local char cached_name[64];
    static _Thread_local uint64_t cached_value;
    static _Thread_local bool cached_ok;
    bool batched = stage_batch_active();
    uint64_t generation = batched ? stage_batch_generation() : 0;
    if (batched && cached_db == db && cached_generation == generation &&
        name && strcmp(cached_name, name) == 0) {
        if (!cached_ok)
            return false;
        if (out)
            *out = cached_value;
        return true;
    }

    uint64_t derived = 0;
    bool found = false;
    bool ok = reducer_frontier_stage_cursor_derived(db, name, &derived, &found);
    (void)found;
    if (batched && name && strlen(name) < sizeof(cached_name)) {
        cached_db = db;
        cached_generation = generation;
        memcpy(cached_name, name, strlen(name) + 1);
        cached_value = derived;
        cached_ok = ok;
    }
    if (!ok)
        return false;
    if (out)
        *out = derived;
    return true;
}

/* Shared block-body reader function-pointer type. Every stage that pulls a
 * block body off disk (body_persist, script_validate, proof_validate,
 * utxo_apply) injects a reader of this exact signature; stage_default_block_reader
 * below is the production implementation. The per-stage `*_reader_fn` typedefs
 * in the stage headers alias onto this single type so the four stages share one
 * setter shape without changing their public setter names. */
typedef bool (*stage_block_reader_fn)(struct block *out,
                                      const struct block_index *bi,
                                      const char *datadir,
                                      void *user);

/* Default block-body reader used by stages whose injectable reader is
 * NULL. Guards on out/bi/HAVE_DATA and reads via pread from the block's
 * (nFile, nDataPos) on-disk position. Matches the stage_block_reader_fn
 * signature of every consuming stage. */
static inline bool stage_default_block_reader(struct block *out,
                                              const struct block_index *bi,
                                              const char *datadir, void *user)
{
    (void)user;
    if (!out || !bi || !(bi->nStatus & BLOCK_HAVE_DATA))
        return false;

    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    pos.nFile = bi->nFile;
    pos.nPos = bi->nDataPos;
    return read_block_from_disk_pread(out, &pos, datadir ? datadir : "");
}

/* Read the block body for `height`/`bi`, sharing the deserialized result across
 * the five stages via block_parse_cache when the PRODUCTION default reader is
 * in effect (injected==NULL). A test-injected reader bypasses the cache so the
 * staged-pipeline fake readers keep exact control. The cache hands back a
 * COMPLETE deep clone (block_serialize<->block_deserialize round-trip), so the
 * `out` block every stage receives is exactly equal to a fresh
 * stage_default_block_reader read and is owned by the caller (block_free as
 * before). Same true/false success contract as stage_default_block_reader. */
static inline bool stage_read_block(struct block *out,
                                    const struct block_index *bi,
                                    int height, const char *datadir,
                                    stage_block_reader_fn injected, void *user)
{
    if (injected)
        return injected(out, bi, datadir, user);
    if (!out || !bi || !bi->phashBlock)
        return false;
    return block_parse_cache_get((int32_t)height, bi->phashBlock->data,
                                 bi, datadir, out);
}

/* Acquire one immutable block view for a stage. Production readers pin the
 * shared parse-cache entry; injected test readers keep their historical
 * independently-owned block contract. No cache lock survives this call. */
static inline bool stage_acquire_block_view(
    struct block *owned, struct block_parse_handle *handle,
    const struct block **view, bool *borrowed,
    const struct block_index *bi, int height, const char *datadir,
    stage_block_reader_fn injected, void *user)
{
    if (!owned || !handle || !view || !borrowed || !bi || !bi->phashBlock)
        return false;
    block_init(owned);
    memset(handle, 0, sizeof(*handle));
    *view = NULL;
    *borrowed = injected == NULL;
    bool ok = *borrowed
        ? block_parse_cache_acquire((int32_t)height, bi->phashBlock->data,
                                    bi, datadir, handle)
        : injected(owned, bi, datadir, user);
    if (!ok)
        return false;
    *view = *borrowed ? block_parse_handle_block(handle) : owned;
    if (!*view && *borrowed)
        block_parse_cache_release(handle);
    return *view != NULL;
}

static inline void stage_release_block_view(
    struct block *owned, struct block_parse_handle *handle, bool borrowed)
{
    if (borrowed)
        block_parse_cache_release(handle);
    else if (owned)
        block_free(owned);
}

/* ── Durable upstream-log-row hole (silent-hold audit, lane/stall-taxonomy) ──
 *
 * Every stage's floor check reads an upstream stage's DURABLY persisted
 * cursor and only proceeds when `next_h` is BELOW it — i.e. the upstream
 * stage has already committed a *_log row at `next_h` (the F-2 per-block
 * co-commit invariant: cursor + log row land in the SAME transaction). A
 * SELECT at `next_h` that then finds no row is therefore not "not yet" — it
 * is durable internal damage (the residue of a noncanonical-row purge or a
 * stale-replay artifact that deleted the row without rewinding the
 * cursor). It self-heals via the reducer_frontier_reconcile_light Condition
 * (its own 5 s cadence, independent of this stage), which is why the
 * correct verdict here stays JOB_IDLE, never JOB_BLOCKED — JOB_BLOCKED
 * would feed the supervisor restart-escalation ladder against a dependency
 * this stage cannot resolve itself.
 *
 * A rowless hole in any of script_validate_log, proof_validate_log,
 * body_fetch, body_persist can pin H* silently, with
 * `z23 core sync blockers` reporting nothing (only last_blocked_unix
 * timestamp — see reducer_frontier_reconcile_light.c's detect function and
 * its generic refill-hole scan). This helper generalizes
 * utxo_apply_upstream_hole_note ("reducer_frontier.upstream_log_hole") so
 * every stage names the same class of hole immediately instead of relying solely on
 * staged_sync_supervisor's 60-minute stage-freeze backstop. */
static inline void stage_upstream_log_hole_note(const char *stage_name,
                                                const char *upstream_log_name,
                                                int height,
                                                uint64_t upstream_cursor,
                                                _Atomic int64_t *last_blocked_unix)
{
    const char *sn = (stage_name && stage_name[0]) ? stage_name : "stage";
    char id[BLOCKER_ID_MAX];
    /* blocker-id: *.upstream_log_hole */
    snprintf(id, sizeof(id), "%s.upstream_log_hole", sn);
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "%s row ABSENT at height=%d while the upstream cursor=%llu is "
             "already past it (torn co-commit invariant, not \"not yet\"); "
             "%s holds below the hole until "
             "reducer_frontier_reconcile_light refills the row",
             upstream_log_name ? upstream_log_name : "upstream_log", height,
             (unsigned long long)upstream_cursor, sn);
    struct blocker_record rec;
    int set_rc = -1;
    if (blocker_init(&rec, id, sn, BLOCKER_DEPENDENCY, reason)) {
        snprintf(rec.escape_action, sizeof(rec.escape_action),
                 "reducer_frontier_reconcile_light");
        set_rc = blocker_set(&rec);
    }
    /* blocker_set's own token bucket already dedups a re-fire within its
     * rate-limit window (return 1); only log on a fresh write (0) so a
     * persistent hole logs at that same bounded cadence instead of once per
     * 2 s supervisor tick. */
    if (set_rc == 0)
        LOG_WARN(sn,
                 "[%s] durable upstream hole: %s row ABSENT at height=%d "
                 "while upstream cursor=%llu is already past it — holding "
                 "(cursor unchanged), see blocker %s",
                 sn, upstream_log_name ? upstream_log_name : "upstream_log",
                 height, (unsigned long long)upstream_cursor, id);
    if (last_blocked_unix)
        atomic_store(last_blocked_unix, platform_time_wall_unix());
}

/* Clear the typed hole blocker for `stage_name`. No-op if never raised (or
 * already clear) — safe to call unconditionally on the "row found" path,
 * mirroring utxo_apply_upstream_hole_healed(). */
static inline void stage_upstream_log_hole_clear(const char *stage_name)
{
    char id[BLOCKER_ID_MAX];
    snprintf(id, sizeof(id), "%s.upstream_log_hole",
             (stage_name && stage_name[0]) ? stage_name : "stage");
    blocker_clear(id);
}

/* ── Body-read HOLD (silent-hold audit, lane/stall-taxonomy) ──────────────
 *
 * A stage_read_block() failure for a height whose upstream (body_persist)
 * ALREADY verified hash+merkle before setting BLOCK_HAVE_DATA means the
 * on-disk bytes vanished or were corrupted AFTER that verification (a
 * blk*.dat rotation bug, disk corruption, a deleted/truncated file, a
 * poisoned block_parse_cache slot) — not a "body not fetched yet" wait
 * (that case is body_fetch's own BLOCK_HAVE_DATA gate, unaffected). Unlike
 * body_persist's requeue_body_for_refetch, this stage did not do the
 * hash/merkle verification itself and must not clear BLOCK_HAVE_DATA or
 * trigger a network refetch — it can only wait and let an operator repair
 * the file or reindex. Before this helper, script_validate and
 * proof_validate held the cursor here with NOTHING beyond a bare
 * last_blocked_unix timestamp (relying solely on the 60-minute generic
 * stage-freeze backstop); utxo_apply already names this exact condition
 * via utxo_apply_select_idle_note(UA_SELECT_IDLE_STAGE_READ_FAILED) — this
 * helper ports that same visibility (and adds a registry-visible typed
 * blocker) to every caller. HOLD the cursor (JOB_IDLE; the read is retried
 * every tick). Caller must call stage_body_read_hold_clear(stage_name) on
 * the next successful read of the SAME height (mirrors sv_unresolved_clear
 * / pv_unresolved_clear's clear-on-resolve contract). */
static inline job_result_t stage_body_read_hold(const char *stage_name,
                                                 int height,
                                                 const struct uint256 *hash,
                                                 _Atomic int64_t *last_blocked_unix)
{
    const char *sn = (stage_name && stage_name[0]) ? stage_name : "stage";
    char id[BLOCKER_ID_MAX];
    /* blocker-id: *.body_read_failed */
    snprintf(id, sizeof(id), "%s.body_read_failed", sn);
    char hashhex[65] = "(unknown)";
    if (hash)
        uint256_get_hex(hash, hashhex);
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d hash=%.64s: body read failed after body_persist "
             "verification; bytes changed or vanished; inspect blk*.dat "
             "and the block_index position; stage=%.24s",
             height, hashhex, sn);
    struct blocker_record rec;
    int set_rc = -1;
    if (blocker_init(&rec, id, sn, BLOCKER_TRANSIENT, reason))
        set_rc = blocker_set(&rec);
    if (set_rc == 0)
        LOG_WARN(sn,
                 "[%s] body read failed height=%d hash=%s (body_persist "
                 "already verified it) — holding cursor, see blocker %s",
                 sn, height, hashhex, id);
    if (last_blocked_unix)
        atomic_store(last_blocked_unix, platform_time_wall_unix());
    return JOB_IDLE;
}

/* Clear the typed body-read-hold blocker for `stage_name`. No-op if never
 * raised — safe to call unconditionally right after a successful read. */
static inline void stage_body_read_hold_clear(const char *stage_name)
{
    char id[BLOCKER_ID_MAX];
    snprintf(id, sizeof(id), "%s.body_read_failed",
             (stage_name && stage_name[0]) ? stage_name : "stage");
    blocker_clear(id);
}

/* SELECT COUNT(*) FROM <table>, for the *_dump_state_json log_rows field.
 * `tag` is the calling stage's name for log attribution. Returns -1 on
 * prepare failure or no row. */
static inline int64_t stage_log_row_count(sqlite3 *db, const char *tag,
                                          const char *table)
{
    if (!db || !table || !table[0])
        return -1;

    progress_store_tx_lock();
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN(tag, "[%s] log count prepare failed: %s",
                 tag, sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return -1;
    }
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:progress-kv-kernel-store
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return n;
}

/* Reducer chain-window extender (the missing chain-extender).
 *
 * The reducer's tip_finalize uses a one-block lookahead (finalize H by
 * reading active_chain_at(H+1)) and then collapses the visible chain[]
 * window back to the finalized height via active_chain_move_window_tip, then
 * publishes the authority through the reducer's explicit tip publication.
 * This helper forward-extends the visible chain[] window along the CONTIGUOUS
 * have-data frontier WITHOUT moving the authoritative tip. Stages that read
 * active_chain_at() call it at the top of step_once so the window is supplied
 * to the height they are about to process.
 *
 * The SCAN RANGE is bounded by the best-known header height (a generous upper
 * bound), but the window only ever extends to the CONTIGUOUS have-data frontier
 * that active_chain_extend_window_have_data discovers internally — bodiless /
 * header-only slots are excluded by construction (it accepts a successor only
 * when its pprev is pointer-equal to the prior accepted block AND that
 * successor has BLOCK_HAVE_DATA). It is gated on HAVE_DATA, NOT
 * BLOCK_VALID_SCRIPTS: the body-dependent stages (body_fetch, body_persist,
 * script_validate) must SEE a have-data block before it is script-validated —
 * requiring VALID_SCRIPTS to widen the window is a chicken-and-egg that wedges
 * the body pipeline. Per-stage validity is enforced by each stage on its own
 * cursor, not by what the window happens to expose. So this never pins a
 * bodiless slot even though the scan bound sits at the header tip.
 *
 * Why NOT bound by utxo_apply's cursor (the previous attempt): utxo_apply is
 * the LOWEST of the eight stage cursors. The upstream stages (body_persist,
 * script_validate, proof_validate) each read active_chain_at(their_cursor + 1)
 * and MUST be able to lead utxo_apply for the pipeline to make forward
 * progress. Capping the window at utxo_apply's cursor makes
 * active_chain_at(their_next_h) return NULL for any height above utxo_apply,
 * so bodies can never lead utxo_apply -> every upstream stage goes JOB_IDLE ->
 * steady-state forward-sync wedge. The header-tip scan bound exposes each
 * upstream stage's next block while the internal have-data gate keeps the
 * window from ever crossing the body floor.
 *
 * This still closes the wrong-fork wedge class: pindex_best_header tracks the
 * best known HEADER, which may sit above the have-data frontier on a forked or
 * not-yet-downloaded branch. Even though we now SCAN up to that header height,
 * the have-data extender refuses to fill to a header-only candidate (no
 * BLOCK_HAVE_DATA), so the window stops at the contiguous body frontier and
 * never exposes a bodiless slot (and never triggers the finalized-row
 * false-reorg cascade). pindex_best_header stays the header-ingest / download
 * target elsewhere — only the WINDOW extender changes here.
 *
 * Do not scan the full block map from a stage tick. The live map is millions
 * of entries; a full most-work sweep inside the supervisor can monopolize the
 * liveness thread and prevent repaired cursors from resuming. The have-data
 * extender does a single bounded scan in (window, max_height], with a hard gap
 * cap, so the cost stays O(delta).
 *
 * STRICTLY a no-op unless the caller owns the active-chain window for the
 * current stage step. */

/* Reducer window-extend failure counter. active_chain_extend_window{,_have_data}
 * return false ONLY on a zcl_malloc("active_chain") grow failure (every "nothing
 * to do" no-op returns true); the leaf is already LOG_FAIL'd at the allocation
 * site (chainstate.c), but a caller that discards the boolean via (void) lets a
 * persistently-failing window extend on the fold path stop the stage's
 * progress with no attribution. LOG_WARN below names every failure loudly on
 * ALL EIGHT stages uniformly (node.log / `z23 getnodelog`),
 * and this counter is for direct white-box inspection (the drain-harness test).
 *
 * Deliberately NOT rolled into stage_dump_counters(): this header is
 * static-inline, so every .c that #includes it gets its OWN private copy of this
 * counter (C internal linkage). For header_admit / validate_headers / body_fetch
 * / body_persist the reducer_extend_window_to_candidate CALL SITE and the stage's
 * *_dump_state_json function compile in the SAME translation unit, but for
 * script_validate / proof_validate / utxo_apply / tip_finalize the step call and
 * the dump function live in SIBLING files (e.g. script_validate_stage.c vs
 * script_validate_stage_dump.c) — a per-TU counter surfaced through the shared
 * dump helper would read a permanent, wrong 0 for those four stages even after a
 * real failure. LOG_WARN is therefore the honest cross-stage observability
 * channel; the JSON field is intentionally omitted. */
static _Atomic uint64_t g_reducer_window_extend_failures = 0;
static _Atomic uint64_t g_reducer_window_extend_attempts = 0;

static inline uint64_t reducer_window_extend_failure_count(void)
{
    return atomic_load(&g_reducer_window_extend_failures);
}

static inline uint64_t reducer_window_extend_attempt_count(void)
{
    return atomic_load(&g_reducer_window_extend_attempts);
}

static inline void reducer_extend_window_to_candidate(struct main_state *ms,
                                                       bool authoritative)
{
    if (!authoritative || !ms)
        return;
    /* A stage batch sees one immutable upstream cursor and needs one window
     * exposure, not the same H+1 body-presence proof before every one of its
     * 500 cursor steps. Cache the successful/no-work attempt per thread and
     * batch generation. A failed allocation is deliberately NOT cached so the
     * next step retries and keeps the loud failure counter moving. */
    static _Thread_local struct main_state *cached_ms;
    static _Thread_local uint64_t cached_generation;
    bool batched = stage_batch_active();
    uint64_t generation = batched ? stage_batch_generation() : 0;
    if (batched && cached_ms == ms && cached_generation == generation)
        return;
    atomic_fetch_add(&g_reducer_window_extend_attempts, 1);
    bool success = true;
    /* The wrong-fork wedge this rework fixes is specific to the best-KNOWN
     * HEADER possibly sitting above the have-data frontier on a forked /
     * not-yet-downloaded branch: scanning up to that header height while the
     * have-data extender refuses to fill a header-only slot keeps the window on
     * the contiguous body frontier and never pins a bodiless orphan. So that
     * path uses the header height as a GENEROUS scan bound. A window already
     * at/above that height makes the extender a cheap no-op. */
    if (ms->pindex_best_header) {
        success = active_chain_extend_window_have_data(
                &ms->chain_active, &ms->map_block_index,
                ms->pindex_best_header, ms->pindex_best_header->nHeight);
        if (!success) {
            atomic_fetch_add(&g_reducer_window_extend_failures, 1);
            LOG_WARN("reducer_window",
                     "[reducer_window] have-data window extend failed "
                     "(alloc) header_h=%d", ms->pindex_best_header->nHeight);
        }
        if (batched && success) {
            cached_ms = ms;
            cached_generation = generation;
        }
        return;
    }

    /* No header-ingest writer has run yet (the boot-fold / submitblock /
     * rebuild PRODUCER paths and most unit harnesses leave pindex_best_header
     * NULL). There is no best-header orphan to guard against here, so fall back
     * to the most-work candidate + the plain pprev-walk extender — exactly the
     * pre-rework behaviour (proven safe on origin/main). The candidate selector
     * already requires BLOCK_VALID_TREE + data availability and a failure-free
     * ancestry, so it never names a bodiless orphan; active_chain_extend_window
     * then assembles ONLY that candidate's own pprev path. Skipping this leaves
     * the bound at -1 -> the extender always no-ops -> tip_finalize's lookahead
     * block is never exposed -> the tip stops advancing. */
    struct block_index *cand =
        active_chain_most_work_candidate(&ms->chain_active,
                                         &ms->map_block_index);
    if (cand) {
        success = active_chain_extend_window(&ms->chain_active, cand);
        if (!success) {
            atomic_fetch_add(&g_reducer_window_extend_failures, 1);
            LOG_WARN("reducer_window",
                     "[reducer_window] most-work candidate window extend "
                     "failed (alloc) cand_h=%d", cand->nHeight);
        }
    }
    if (batched && success) {
        cached_ms = ms;
        cached_generation = generation;
    }
}

/* Emit the four generic stage-machine counters (advanced/blocked/idle/error)
 * PLUS step-latency/rate observability into a *_dump_state_json object. These
 * come straight off the stage_t and are identical across every Job stage; the
 * stage's distinctive counters stay inline at each call site. No-op when s is
 * NULL (stage not yet started).
 *
 * Step-latency fields (see util/stage.h "Step timing" for the write side):
 *   last_step_us       — duration of the most recent step() call, us.
 *   step_us_ewma        — EWMA (alpha 1/16) of step duration, us.
 *   steps_per_sec_ewma  — derived at dump time as 1e6 / step_us_ewma; 0.0
 *                         before the first step (step_us_ewma is still 0,
 *                         avoiding a divide-by-zero). Not stored — this
 *                         keeps step_us_ewma the single source of truth for
 *                         "how long a step takes" instead of two counters
 *                         that could drift apart.
 *   steps_total         — sum of advanced/blocked/idle/error_count, i.e. how
 *                         many times stage_run_once actually ran the step()
 *                         body. Not stored separately (each of the four
 *                         counters already persists this information); this
 *                         is a dump-time convenience sum so a caller doesn't
 *                         have to add the four fields itself. */
static inline void stage_dump_counters(struct json_value *out, const stage_t *s)
{
    if (!s)
        return;
    uint64_t advanced = stage_advanced_count(s);
    uint64_t blocked  = stage_blocked_count(s);
    uint64_t idle     = stage_idle_count(s);
    uint64_t error    = stage_error_count(s);
    json_push_kv_int(out, "advanced_count", (int64_t)advanced);
    json_push_kv_int(out, "blocked_count",  (int64_t)blocked);
    json_push_kv_int(out, "idle_count",     (int64_t)idle);
    json_push_kv_int(out, "error_count",    (int64_t)error);
    json_push_kv_int(out, "steps_total",
                     (int64_t)(advanced + blocked + idle + error));

    int64_t last_us = stage_last_step_us(s);
    int64_t ewma_us  = stage_step_us_ewma(s);
    json_push_kv_int(out, "last_step_us", last_us);
    json_push_kv_int(out, "step_us_ewma", ewma_us);
    json_push_kv_real(out, "steps_per_sec_ewma",
                      ewma_us > 0 ? (1000000.0 / (double)ewma_us) : 0.0);
}

/* Emit the three universal opening fields of a *_dump_state_json object —
 * "initialised", "stage_name", "cursor" — in that exact order. Seven of the
 * eight Job stages open with this identical triple; emitting it from one helper
 * keeps the same field values and the same field order downstream consumers
 * see as each stage hand-wrote. The lone exception is validate_headers, which
 * interleaves an "authority" field BETWEEN stage_name and cursor, so it keeps
 * its inline form. Pass the stage's own STAGE_NAME and g_stage so the cursor
 * and `initialised` flag reflect THIS stage (the helper owns no globals — the
 * registry hazard is avoided by keeping ownership at the call site). */
static inline void stage_dump_header(struct json_value *out, const char *name,
                                     const stage_t *s)
{
    json_push_kv_bool(out, "initialised", s != NULL);
    json_push_kv_str (out, "stage_name", name);
    json_push_kv_int (out, "cursor", (int64_t)(s ? stage_cursor(s) : 0));
}

/* Emit the reserved `_health` { ok, reason } key (see CLAUDE.md "Adding
 * state introspection" + engine/controllers/src/diagnostics_health_rollup.c):
 * maps the stage's own `initialised` flag (stage_dump_header above) plus
 * its accumulated error_count (stage_dump_counters above) — no new health
 * logic, just a uniform shape the `unhealthy` rollup can walk. Shared
 * across the stage-machine dumpers (header_admit, validate_headers,
 * body_fetch, body_persist, script_validate, proof_validate) since they
 * all already compute these identical two signals via stage_t. Call this
 * AFTER stage_dump_counters so error_count has already been read once (not
 * load-bearing, just matches call-site reading order). */
static inline void stage_dump_health(struct json_value *out, const char *name,
                                     const stage_t *s)
{
    bool initialised = (s != NULL);
    uint64_t errors = initialised ? stage_error_count(s) : 0;
    bool ok = initialised && errors == 0;
    char reason_buf[160] = "";
    if (!initialised) {
        snprintf(reason_buf, sizeof(reason_buf),
                 "%s stage not initialised", name);
    } else if (errors > 0) {
        snprintf(reason_buf, sizeof(reason_buf),
                 "%s recorded %llu step error(s)", name,
                 (unsigned long long)errors);
    }
    diag_push_health(out, ok, reason_buf);
}

/* Define the shared step_once entry point for a stage whose step body is the
 * uniform shape: bail to JOB_IDLE if the stage or progress.kv handle is not up,
 * extend the active-chain window to the best candidate, then run one cursor-
 * stamped step under the progress.kv tx lock. Four of the eight stages
 * (body_fetch, body_persist, script_validate, proof_validate) share this exact
 * body. The macro re-expands the per-TU file-local `g_stage`/`g_ms`
 * inside each stage's own translation unit, so the emitted machine code is
 * identical to the hand-written form — this collapses the DUPLICATED BODY only,
 * never any stage-specific wiring or ordering. Stages that need a reorg unwind,
 * a recheck pass, a mailbox drain, or projection catch-up keep their bespoke
 * step_once and do NOT use this macro. Pair it with STAGE_DRAIN_IMPL(prefix). */
#define STAGE_STEP_ONCE_SIMPLE(prefix)                              \
    job_result_t prefix##_stage_step_once(void) {                  \
        if (!g_stage) return JOB_IDLE;                             \
        sqlite3 *db = progress_store_db();                        \
        if (!db) return JOB_IDLE;                                 \
        reducer_extend_window_to_candidate(g_ms, true);           \
        progress_store_tx_lock();                                 \
        job_result_t r = stage_run_once(g_stage, db);             \
        progress_store_tx_unlock();                               \
        return r;                                                 \
    }

#endif /* ZCL_JOBS_STAGE_HELPERS_H */
