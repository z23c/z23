/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_persist_stage — implementation. See jobs/body_persist_stage.h.
 *
 * Consumes body_fetch_log and verifies that bodies observed on disk are
 * readable, hash to the active-chain header, and merkle-reconstruct to the
 * admitted header's root. It writes body_persist_log plus its stage cursor in
 * progress.kv, and emits verified bodies into the append-only event log.
 * READ-class failures are never persisted as verdicts: the stage clears
 * BLOCK_HAVE_DATA and holds the cursor until the body is re-fetched (see
 * requeue_body_for_refetch). */

#include "platform/time_compat.h"
#include "jobs/body_persist_stage.h"
#include "jobs/created_outputs_index.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_log_rows.h"
#include "jobs/stage_body_index.h"
#include "body_persist_log_store.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "json/json.h"
#include "primitives/block.h"
#include "storage/block_parse_cache.h"
#include "storage/disk_block_io.h"
#include "jobs/block_header_emit.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/reducer_stage_profile.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STAGE_NAME "body_persist"

/* struct body_fetch_row + the body_persist_log schema/read/write helpers
 * live in body_persist_log_store.c (pure sqlite kernel helpers below the AR
 * layer). */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct main_state *g_ms = NULL;
static stage_t *g_stage = NULL;
static char g_datadir[2048] = {0};
static body_persist_reader_fn g_reader = NULL;
static void *g_reader_user = NULL;
static struct uint256 *g_merkle_txids = NULL;
static size_t g_merkle_txids_capacity = 0;

static _Atomic uint64_t g_verified_total = 0;
static _Atomic uint64_t g_upstream_failed_total = 0;
static _Atomic uint64_t g_read_failed_total = 0;
static _Atomic uint64_t g_header_mismatch_total = 0;
static _Atomic uint64_t g_merkle_mismatch_total = 0;
static _Atomic uint64_t g_header_event_emit_total = 0;
static _Atomic uint64_t g_header_event_emit_fail_total = 0;
static _Atomic int64_t  g_last_step_unix = 0;
static _Atomic int64_t  g_last_blocked_unix = 0;
static _Atomic int64_t  g_last_advance_height = -1;

/* Unfetchable-body detector (silent-hold audit).
 *
 * requeue_body_for_refetch's remedy — "clear BLOCK_HAVE_DATA and let the normal
 * !HAVE_DATA sync path re-download the body" — is only a remedy when the body
 * IS re-requestable. It is NOT at every height: the header-driven body queue
 * (lib/net/src/msg_headers.c) only ever walks heights strictly ABOVE the
 * active-chain tip, so a height at or below the tip whose bytes are not on disk
 * can never be re-requested and this stage idles on it forever. That is exactly
 * the from-genesis wedge (height 0, where genesis IS the tip and no writer ever
 * produced its body). The requeue fires ONCE and the HAVE_DATA gate then idles
 * without re-reading, so a repeat COUNT never grows — the hold is invisible:
 * JOB_IDLE, blocked_count 0, nothing in `dumpstate blocker`. Measured on a bare
 * mainnet cold start 2026-07-27: read_failed_total 1, idle_count 26,545,
 * cursor 0 for 617 s with no blocker naming height 0.
 *
 * So arm a WALL-CLOCK hold instead: remember (height, first requeue time) and,
 * once the HAVE_DATA gate has been idling on that same height for longer than
 * BODY_PERSIST_UNFETCHABLE_HOLD_SECS, NAME it. Cleared on any cursor advance
 * and whenever the stage moves to a different height. */
#define BODY_PERSIST_UNFETCHABLE_HOLD_SECS 60

static _Atomic int64_t g_requeue_height = -1;   /* -1 = nothing armed */
static _Atomic int64_t g_requeue_since_unix = 0;
static _Atomic int     g_unfetchable_hold_secs = BODY_PERSIST_UNFETCHABLE_HOLD_SECS;

#ifdef ZCL_TESTING
void body_persist_stage_set_unfetchable_hold_secs_for_testing(int secs)
{
    atomic_store(&g_unfetchable_hold_secs,
                 secs < 0 ? BODY_PERSIST_UNFETCHABLE_HOLD_SECS : secs);
}
#endif

/* blocker-id: body_persist.body_unfetchable */
#define BODY_UNFETCHABLE_BLOCKER_ID STAGE_NAME ".body_unfetchable"

/* Disarm + clear: the stage advanced, or moved off the held height. */
static void requeue_hold_disarm(void)
{
    if (atomic_exchange(&g_requeue_height, -1) >= 0)
        blocker_clear(BODY_UNFETCHABLE_BLOCKER_ID);
}

/* Arm the hold clock for `height` (called from requeue_body_for_refetch). */
static void requeue_hold_arm(int height)
{
    if (atomic_load(&g_requeue_height) == (int64_t)height)
        return; /* already armed for this height — keep the original clock */
    atomic_store(&g_requeue_height, (int64_t)height);
    atomic_store(&g_requeue_since_unix, platform_time_wall_unix());
    blocker_clear(BODY_UNFETCHABLE_BLOCKER_ID);
}

/* Called from the !BLOCK_HAVE_DATA idle branch. Names the hold once the
 * re-fetch remedy has demonstrably failed to produce a body for this height. */
static void requeue_hold_note_idle(int height, int tip_height)
{
    if (atomic_load(&g_requeue_height) != (int64_t)height)
        return;
    int64_t since = atomic_load(&g_requeue_since_unix);
    int64_t now = platform_time_wall_unix();
    if (since <= 0 || now - since < (int64_t)atomic_load(&g_unfetchable_hold_secs))
        return;

    char reason[BLOCKER_REASON_MAX];
    if (height == 0)
        snprintf(reason, sizeof(reason),
                 "height=0: the GENESIS body is not on disk and can NEVER be "
                 "re-fetched — the header-driven body queue only requests "
                 "heights strictly above the active tip and genesis IS the "
                 "tip. body_persist has held at cursor 0 for %llds; the fold "
                 "cannot leave height 0. Cure: the boot-time genesis anchor "
                 "seed (config/src/boot_services.c) stamps every upstream "
                 "cursor to 1. If this blocker is up, that seed did not run or "
                 "seed_integrity_gate refused it",
                 (long long)(now - since));
    else
        snprintf(reason, sizeof(reason),
                 "height=%d: BLOCK_HAVE_DATA was cleared for re-fetch %llds "
                 "ago and no body arrived (active tip=%d). A height at or "
                 "below the tip cannot be re-requested by the header-driven "
                 "body queue, so this hold does not self-heal; inspect "
                 "blk*.dat and the block_index (nFile,nDataPos) for this "
                 "height",
                 height, (long long)(now - since), tip_height);

    struct blocker_record rec;
    int set_rc = -1;
    if (blocker_init(&rec, BODY_UNFETCHABLE_BLOCKER_ID, STAGE_NAME,
                     BLOCKER_DEPENDENCY, reason))
        set_rc = blocker_set(&rec);
    if (set_rc == 0)
        LOG_WARN(STAGE_NAME,
                 "[body_persist] body re-fetch has not produced a body for "
                 "height=%d in %llds — holding cursor, see blocker %s",
                 height, (long long)(now - since),
                 BODY_UNFETCHABLE_BLOCKER_ID);
}

static void profile_acquire(const struct block_parse_handle *h)
{
    reducer_stage_profile_add(REDUCER_PROFILE_BODY_PERSIST,
                              h->cache_hit ? RPF_CACHE_HITS : RPF_CACHE_MISSES,
                              1);
    reducer_stage_profile_add(REDUCER_PROFILE_BODY_PERSIST, RPF_CACHE_PROBES,
                              h->lookup_probes);
    reducer_stage_profile_observe_us(REDUCER_PROFILE_BODY_PERSIST,
                                     RPF_CACHE_LOCK_WAIT_US, h->lock_wait_us);
    reducer_stage_profile_observe_us(REDUCER_PROFILE_BODY_PERSIST,
                                     RPF_DISK_READ_US, h->disk_read_us);
    reducer_stage_profile_observe_us(REDUCER_PROFILE_BODY_PERSIST,
                                     RPF_PARSE_US, h->parse_us);
}

static void release_stage_block(struct block_parse_handle *handle,
                                struct block *owned, bool borrowed)
{
    if (borrowed)
        block_parse_cache_release(handle);
    else
        block_free(owned);
}

enum merkle_verify_result {
    MERKLE_VERIFY_OK = 0,
    MERKLE_VERIFY_MISMATCH,
    MERKLE_VERIFY_OOM,
};

static enum merkle_verify_result verify_merkle_root(const struct block *blk)
{
    if (!blk || blk->num_vtx > MAX_BLOCK_TRANSACTIONS)
        return MERKLE_VERIFY_MISMATCH;
    if (blk->num_vtx == 0)
        return uint256_is_null(&blk->header.hashMerkleRoot)
            ? MERKLE_VERIFY_OK : MERKLE_VERIFY_MISMATCH;

    if (blk->num_vtx > g_merkle_txids_capacity) {
        size_t new_capacity = g_merkle_txids_capacity > 0
            ? g_merkle_txids_capacity : 1;
        while (new_capacity < blk->num_vtx) {
            new_capacity *= 2;
            if (new_capacity > MAX_BLOCK_TRANSACTIONS)
                new_capacity = MAX_BLOCK_TRANSACTIONS;
        }
        size_t bytes = new_capacity * sizeof(*g_merkle_txids);
        reducer_stage_profile_add(REDUCER_PROFILE_BODY_PERSIST,
                                  RPF_MERKLE_ALLOCS, 1);
        reducer_stage_profile_add(REDUCER_PROFILE_BODY_PERSIST,
                                  RPF_MERKLE_BYTES, bytes);
        struct uint256 *grown = zcl_realloc(
            g_merkle_txids, bytes, "body_persist_merkle_txids");
        if (!grown)
            return MERKLE_VERIFY_OOM;
        g_merkle_txids = grown;
        g_merkle_txids_capacity = new_capacity;
    }
    for (size_t i = 0; i < blk->num_vtx; i++)
        g_merkle_txids[i] = blk->vtx[i].hash;
    struct uint256 root = compute_merkle_root(g_merkle_txids, blk->num_vtx);
    return uint256_eq(&root, &blk->header.hashMerkleRoot)
        ? MERKLE_VERIFY_OK : MERKLE_VERIFY_MISMATCH;
}

/* READ-class failure discipline (mirrors proof_validate's reader handling
 * and chain_restore_repair's HAVE_DATA drop): the stored body failed to
 * read, or read fine but does not belong to the hash-bound active-chain
 * header (wrong/corrupt/torn block on disk). A re-fetched body can change
 * every one of these verdicts, so never persist them as permanent ok=0
 * rows — those statuses sit outside every repair's status set and would
 * pin H*, utxo_apply and tip_finalize forever. But BEFORE clearing, attempt
 * a local position repair (block_index_repair_pos_from_disk): a stale
 * (nFile,nDataPos) with the block still on disk elsewhere is healed by a
 * verified re-store, no re-fetch needed. Only a genuine no-copy-anywhere
 * proceeds: clear BLOCK_HAVE_DATA and
 * re-emit a status event (the projection persists the cleared bit across
 * restarts, same discipline as the success path, but as the lightweight
 * status-only record — see jobs/block_header_emit.h), hold the cursor, and
 * let the normal !HAVE_DATA sync path re-download the body; this stage then
 * retries. While cleared, the HAVE_DATA gate above idles without re-reading,
 * so the counter advances once per requeue, not per step. Only
 * upstream_failed (a deterministic header-consensus verdict re-fetch cannot
 * change) remains a permanent row. */
static job_result_t requeue_body_for_refetch(struct block_index *bi,
                                             int height, const char *what,
                                             _Atomic uint64_t *counter)
{
    /* Local self-heal first: the stored (nFile,nDataPos) can be stale rather
     * than bodiless — a foreign writer on a hardlinked blk file (e.g. a live
     * zclassicd sharing the inode, whose append pointer lags physical EOF)
     * overwrites indexed records while a DUPLICATE copy of the block still
     * exists on disk (2026-08 producer-fold wedge: 314 such positions, every
     * one repairable locally). A hash-targeted rescan re-stores through
     * block_index_set_have_data_verified() and the stage retries the same
     * height next step — no clear, no re-fetch. Only a genuine
     * no-copy-anywhere falls through to clear-and-hold below. */
    if (block_index_repair_pos_from_disk(bi, g_datadir, true)) {
        LOG_WARN(STAGE_NAME,
                 "[body_persist] %s height=%d: repaired (nFile,nDataPos) from "
                 "a local blk-file copy — retrying, HAVE_DATA kept",
                 what, height);
        return JOB_IDLE;
    }

    block_index_status_clear_bits(bi, BLOCK_HAVE_DATA);
    block_index_emit_status_event(bi, STAGE_NAME, &g_header_event_emit_total,
                                  &g_header_event_emit_fail_total);
    atomic_fetch_add(counter, 1);
    atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
    LOG_WARN(STAGE_NAME,
             "[body_persist] %s height=%d: cleared HAVE_DATA, holding cursor "
             "for body re-fetch", what, height);
    requeue_hold_arm(height);
    return JOB_IDLE;
}

static job_result_t step_persist(struct stage_step_ctx *c)
{
    int64_t total_started = platform_time_monotonic_us();
    atomic_store(&g_last_step_unix, platform_time_wall_unix());

    struct main_state *ms = g_ms;
    if (!ms) return JOB_IDLE;
    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;

    int next_h = (int)c->cursor_in;
    if (next_h < 0) return JOB_FATAL;

    uint64_t bf_cursor = 0;
    if (!stage_cursor_read_or_zero(db, "body_fetch", STAGE_NAME,
                                   &bf_cursor))
        return JOB_FATAL;
    if ((uint64_t)next_h >= bf_cursor) {
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;
    }

    struct body_fetch_row upstream;
    int found = body_persist_body_fetch_log_at(db, next_h, &upstream);
    if (found < 0) return JOB_FATAL;
    if (found == 0) {
        /* Row missing despite floor — a durable upstream-log hole, not
         * "not yet" (see stage_upstream_log_hole_note). JOB_IDLE, never
         * JOB_BLOCKED: reducer_frontier_reconcile_light is the healer. */
        stage_upstream_log_hole_note(STAGE_NAME, "body_fetch_log", next_h,
                                     bf_cursor, &g_last_blocked_unix);
        return JOB_IDLE;
    }
    stage_upstream_log_hole_clear(STAGE_NAME);

    if (upstream.ok == 0) {
        if (!body_persist_log_insert(db, next_h, "upstream_failed", false))
            return JOB_FATAL;
        atomic_fetch_add(&g_upstream_failed_total, 1);
        atomic_store(&g_last_advance_height, (int64_t)next_h);
        requeue_hold_disarm();
        c->cursor_out = c->cursor_in + 1;
        return JOB_ADVANCED;
    }

    struct block_index *bi = stage_body_index_at(ms, next_h);
    if (!bi || !bi->phashBlock ||
        !(block_index_status_load(bi) & BLOCK_HAVE_DATA)) {
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        /* The body this stage requeued has still not arrived. Name it once the
         * remedy has demonstrably failed (see requeue_hold_note_idle) — a
         * height at or below the active tip is not re-requestable. */
        requeue_hold_note_idle(next_h, active_chain_height(&ms->chain_active));
        return JOB_IDLE;
    }

    struct block owned;
    block_init(&owned);
    struct block_parse_handle handle;
    memset(&handle, 0, sizeof(handle));
    bool borrowed = g_reader == NULL;
    int64_t acquire_started = platform_time_monotonic_us();
    bool read_ok = borrowed
        ? block_parse_cache_acquire(next_h, bi->phashBlock->data, bi,
                                    g_datadir, &handle)
        : stage_read_block(&owned, bi, next_h, g_datadir, g_reader,
                           g_reader_user);
    if (!read_ok) {
        block_free(&owned);
        return requeue_body_for_refetch(bi, next_h, "read_failed",
                                        &g_read_failed_total);
    }
    if (borrowed) profile_acquire(&handle);
    const struct block *blk = borrowed ? block_parse_handle_block(&handle)
                                       : &owned;
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_BODY_PERSIST, RPF_UPSTREAM_US,
        (uint64_t)(acquire_started - total_started));

    struct uint256 disk_hash;
    int64_t phase_started = platform_time_monotonic_us();
    block_get_hash(blk, &disk_hash);
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_BODY_PERSIST, RPF_BLOCK_HASH_US,
        (uint64_t)(platform_time_monotonic_us() - phase_started));
    if (uint256_cmp(&disk_hash, bi->phashBlock) != 0) {
        release_stage_block(&handle, &owned, borrowed);
        /* Purge any (height,hash) slot the shared block_parse_cache may hold
         * for this key: this stage's own hash check just rejected `blk`, so a
         * cached copy under this key (however it got there) must never be
         * served to the next refetch attempt — see block_parse_cache.h. */
        block_parse_cache_evict(next_h, bi->phashBlock->data);
        return requeue_body_for_refetch(bi, next_h, "header_mismatch",
                                        &g_header_mismatch_total);
    }

    phase_started = platform_time_monotonic_us();
    enum merkle_verify_result merkle_result = verify_merkle_root(blk);
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_BODY_PERSIST, RPF_MERKLE_US,
        (uint64_t)(platform_time_monotonic_us() - phase_started));
    if (merkle_result == MERKLE_VERIFY_OOM) {
        release_stage_block(&handle, &owned, borrowed);
        LOG_RETURN(JOB_FATAL, STAGE_NAME,
                   "[body_persist] merkle scratch allocation failed height=%d",
                   next_h);
    }
    if (merkle_result != MERKLE_VERIFY_OK) {
        release_stage_block(&handle, &owned, borrowed);
        return requeue_body_for_refetch(bi, next_h, "merkle_mismatch",
                                        &g_merkle_mismatch_total);
    }

    /* Index every output this block creates so script_validate (stage 5) can
     * resolve transparent prevouts without -txindex. body_persist (stage 4) is
     * strictly upstream, so the index is complete at/below the script_validate
     * frontier before it is needed (P0 §2.1). Load-bearing for validation:
     * a write failure is fatal, not silently skipped. */
    phase_started = platform_time_monotonic_us();
    if (!created_outputs_index_put_block(db, blk, next_h)) {
        release_stage_block(&handle, &owned, borrowed);
        return JOB_FATAL;
    }
    reducer_stage_profile_observe_us(REDUCER_PROFILE_BODY_PERSIST,
                                     RPF_CREATED_INDEX_US,
                              (uint64_t)(platform_time_monotonic_us() -
                                         phase_started));

    /* The body has landed on disk and round-tripped (hash + merkle verified),
     * so mark BLOCK_HAVE_DATA on the in-memory block_index entry. Then re-emit
     * a lightweight status event with the updated nStatus so the projection
     * persists the HAVE_DATA bit (idempotent — the projection patches its
     * already-durable EV_BLOCK_HEADER row keyed on hash, see
     * jobs/block_header_emit.h). This bump never re-serializes the immutable
     * header fields/solution: reducer_ingest_service.c's EV_BLOCK_HEADER emit
     * already recorded them for this hash before body_persist ever runs (this
     * stage is strictly downstream of body admission). nTx rides the same
     * event: an n_tx=0 row breaks the next boot's nChainTx propagation
     * exactly at this block. */
    block_index_status_fetch_or(bi, BLOCK_HAVE_DATA);
    if (bi->nTx == 0 && blk->num_vtx > 0)
        bi->nTx = (unsigned int)blk->num_vtx;
    phase_started = platform_time_monotonic_us();
    block_index_emit_status_event(bi, "body_persist", &g_header_event_emit_total, &g_header_event_emit_fail_total);
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_BODY_PERSIST, RPF_HEADER_EVENT_US,
        (uint64_t)(platform_time_monotonic_us() - phase_started));

    release_stage_block(&handle, &owned, borrowed);
    phase_started = platform_time_monotonic_us();
    if (!body_persist_log_insert(db, next_h, "verified", true))
        return JOB_FATAL;
    reducer_stage_profile_observe_us(REDUCER_PROFILE_BODY_PERSIST,
                                     RPF_STAGE_LOG_CURSOR_US,
                              (uint64_t)(platform_time_monotonic_us() -
                                         phase_started));
    atomic_fetch_add(&g_verified_total, 1);
    atomic_store(&g_last_advance_height, (int64_t)next_h);
    requeue_hold_disarm();
    c->cursor_out = c->cursor_in + 1;
    reducer_stage_profile_add(REDUCER_PROFILE_BODY_PERSIST, RPF_BLOCKS, 1);
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_BODY_PERSIST, RPF_TOTAL_US,
        (uint64_t)(platform_time_monotonic_us() - total_started));
    return JOB_ADVANCED;
}

bool body_persist_stage_init(struct main_state *ms)
{
    if (!ms) LOG_FAIL("body_persist", "init: NULL main_state");

    sqlite3 *db = progress_store_db();
    if (!db) LOG_FAIL("body_persist",
        "init: progress_store not open");

    pthread_mutex_lock(&g_lock);
    if (g_stage != NULL) {
        bool same = (g_ms == ms);
        pthread_mutex_unlock(&g_lock);
        if (!same)
            LOG_FAIL("body_persist",
                "init: already bound to a different main_state");
        return true;
    }

    if (!body_persist_log_ensure_schema(db)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    /* The forward creation index this stage maintains for script_validate. */
    if (!created_outputs_index_ensure_schema(db)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    GetDataDir(true, g_datadir, sizeof(g_datadir));

    stage_t *s = stage_create(STAGE_NAME, step_persist, NULL);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        LOG_FAIL("body_persist", "init: stage_create failed");
    }

    g_ms = ms;
    g_stage = s;
    pthread_mutex_unlock(&g_lock);

    LOG_INFO("body_persist", "[body_persist] stage initialised");
    return true;
}

STAGE_STEP_ONCE_SIMPLE(body_persist)

int body_persist_stage_drain(int max_steps)
{
    if (max_steps <= 0)
        return 0;
    sqlite3 *batch_db = progress_store_db();
    bool batched = false;
    if (batch_db) {
        progress_store_tx_lock();
        batched = stage_batch_begin(batch_db);
        if (!batched)
            progress_store_tx_unlock();
    }
    int advanced = 0;
    /* Reuse one read fd across this drain's tail reads (append-only forward
     * fold on this thread); exit() closes it. Reads below the sealed frontier
     * take the mmap segment and never reach the pread fd. */
    disk_block_io_read_fd_cache_enter();
    for (int i = 0; i < max_steps; i++) {
        job_result_t r = body_persist_stage_step_once();
        if (r != JOB_ADVANCED)
            break;
        advanced++;
    }
    disk_block_io_read_fd_cache_exit();
    if (batched) {
        (void)stage_batch_end(batch_db,
                              advanced > 0 || stage_batch_dirty());
        /* A prepared statement belongs to exactly one completed outer batch.
         * Finalize after either COMMIT or ROLLBACK so no DB/reorg generation
         * can inherit bindings or statement state from its predecessor. */
        created_outputs_index_batch_reset();
        body_persist_log_store_batch_reset();
        progress_store_tx_unlock();
    }
    return advanced;
}

void body_persist_stage_shutdown(void)
{
    created_outputs_index_batch_reset();
    body_persist_log_store_batch_reset();
    /* Registry hygiene (tests re-init in-process): re-derived from live
     * state the next time the condition fires, so clearing here loses
     * nothing. */
    stage_upstream_log_hole_clear(STAGE_NAME);
    pthread_mutex_lock(&g_lock);
    if (g_stage) {
        stage_destroy(g_stage);
        g_stage = NULL;
    }
    g_ms = NULL;
    g_datadir[0] = '\0';
    g_reader = NULL;
    g_reader_user = NULL;
    free(g_merkle_txids);
    g_merkle_txids = NULL;
    g_merkle_txids_capacity = 0;
    atomic_store(&g_verified_total, (uint64_t)0);
    atomic_store(&g_upstream_failed_total, (uint64_t)0);
    atomic_store(&g_read_failed_total, (uint64_t)0);
    atomic_store(&g_header_mismatch_total, (uint64_t)0);
    atomic_store(&g_merkle_mismatch_total, (uint64_t)0);
    atomic_store(&g_header_event_emit_total, (uint64_t)0);
    atomic_store(&g_header_event_emit_fail_total, (uint64_t)0);
    atomic_store(&g_last_step_unix, (int64_t)0);
    atomic_store(&g_last_blocked_unix, (int64_t)0);
    atomic_store(&g_last_advance_height, (int64_t)-1);
    pthread_mutex_unlock(&g_lock);
}

void body_persist_stage_set_reader(body_persist_reader_fn fn, void *user)
{
    pthread_mutex_lock(&g_lock);
    g_reader = fn;
    g_reader_user = user;
    pthread_mutex_unlock(&g_lock);
}

uint64_t body_persist_stage_cursor(void)
{
    return g_stage ? stage_cursor(g_stage) : 0;
}

int64_t body_persist_stage_step_us_ewma(void)
{
    return g_stage ? stage_step_us_ewma(g_stage) : 0;
}

uint64_t body_persist_stage_verified_total(void)
{
    return atomic_load(&g_verified_total);
}

uint64_t body_persist_stage_upstream_failed_total(void)
{
    return atomic_load(&g_upstream_failed_total);
}

uint64_t body_persist_stage_read_failed_total(void)
{
    return atomic_load(&g_read_failed_total);
}

uint64_t body_persist_stage_header_mismatch_total(void)
{
    return atomic_load(&g_header_mismatch_total);
}

uint64_t body_persist_stage_merkle_mismatch_total(void)
{
    return atomic_load(&g_merkle_mismatch_total);
}

bool body_persist_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    int64_t now = platform_time_wall_unix();
    int64_t last = atomic_load(&g_last_step_unix);

    stage_dump_header(out, STAGE_NAME, g_stage);
    json_push_kv_int (out, "verified_total",
                      (int64_t)atomic_load(&g_verified_total));
    json_push_kv_int (out, "upstream_failed_total",
                      (int64_t)atomic_load(&g_upstream_failed_total));
    json_push_kv_int (out, "read_failed_total",
                      (int64_t)atomic_load(&g_read_failed_total));
    json_push_kv_int (out, "header_mismatch_total",
                      (int64_t)atomic_load(&g_header_mismatch_total));
    json_push_kv_int (out, "merkle_mismatch_total",
                      (int64_t)atomic_load(&g_merkle_mismatch_total));
    json_push_kv_int (out, "header_event_emit_total",
                      (int64_t)atomic_load(&g_header_event_emit_total));
    json_push_kv_int (out, "header_event_emit_fail_total",
                      (int64_t)atomic_load(&g_header_event_emit_fail_total));
    json_push_kv_int (out, "last_advance_height",
                      atomic_load(&g_last_advance_height));
    json_push_kv_int (out, "last_step_unix", last);
    json_push_kv_int (out, "last_step_age_seconds",
                      last > 0 ? now - last : -1);
    json_push_kv_int (out, "last_blocked_unix",
                      atomic_load(&g_last_blocked_unix));
    /* log_rows: the O(1) published counter (seeded once per boot from a COUNT,
     * bumped per insert), read lock-free — never a blocking COUNT(*) over the
     * multi-million-row body_persist_log on the busy RPC path. */
    stage_log_rows_emit(out, "body_persist_log", "log_rows");
    stage_dump_counters(out, g_stage);
    stage_dump_health(out, STAGE_NAME, g_stage);
    return true;
}
