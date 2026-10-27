/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * header_admit_stage — implementation. See jobs/header_admit_stage.h.
 *
 * Single-process singleton; the stage primitive owns cursor/replay and the
 * atomic header_admit_log + stage_cursor commit in progress.kv. */

#include "jobs/header_admit_stage.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "event/event.h"
#include "json/json.h"
#include "jobs/stage_helpers.h"
#include "jobs/mint_fold_ceiling.h"
#include "models/header_admit_log.h"
#include "platform/time_compat.h"
#include "services/chain_state_service.h"
#include "services/header_admit_inbox.h"
#include "header_admit_forward_rewind.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/event_log_singleton.h"
#include "jobs/block_header_emit.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/accept_block_header.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/check_block.h"
#include "validation/process_block.h"
#include "primitives/block.h"

#include <pthread.h>
#include <stdatomic.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STAGE_NAME       "header_admit"

/* Cap the reorg-rewind backward scan. Normal reorgs are 1-6 blocks; a
 * deep stale divergence must not pin the CPU walking back across 3.1M
 * heights every supervisor tick. */
#define HEADER_ADMIT_REORG_REWIND_MAX_DEPTH  10000

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct main_state *g_ms = NULL;
static stage_t *g_stage = NULL;
static _Atomic uint64_t g_admitted_total = 0;
static _Atomic uint64_t g_inbox_drained_total = 0;
static _Atomic uint64_t g_inbox_logged_total = 0;
static _Atomic uint64_t g_reorg_rewind_total = 0;
static _Atomic uint64_t g_reorg_audit_total = 0;
static _Atomic uint64_t g_reorg_audit_height_checks = 0;
static uint64_t g_reorg_audit_batch_generation;
static _Atomic uint64_t g_header_event_emit_total = 0;
static _Atomic uint64_t g_header_event_emit_fail_total = 0;
/* Reducer producer path: count of block_index entries CREATED by the
 * stage from raw header bytes (add_to_block_index). */
static _Atomic uint64_t g_produced_total = 0;
static _Atomic int64_t  g_last_admit_height = -1;
static _Atomic int64_t  g_last_step_unix = 0;
static _Atomic int64_t  g_last_blocked_unix = 0;
#ifdef ZCL_TESTING
static header_admit_authoritative_hook g_authoritative_hook = NULL;
static void *g_authoritative_hook_user = NULL;
#endif

MAILBOX_DEFINE(header_admit, struct header_admit_msg,
               HEADER_ADMIT_INBOX_CAPACITY)

/* Raw headers are staged by hash for the producer. Only the single stage
 * thread touches this ring (drain + step inside step_once); hash hints do not. */
#define HEADER_ADMIT_PENDING_CAP 64

struct pending_header {
    struct uint256       hash;
    struct block_header  header;
    bool                 occupied;
};

static struct pending_header g_pending[HEADER_ADMIT_PENDING_CAP];

bool header_admit_check_contextual_locked(struct main_state *ms,
    const struct chain_params *params, const struct block_header *header,
    struct validation_state *state, bool *parent_known)
{
    if (parent_known) *parent_known = false;
    if (!ms || !params || !header || !state || !parent_known) {
        LOG_WARN("header_admit", "contextual header check has incomplete runtime wiring");
        return state ? validation_state_error(state, "header-context-unwired") : false;
    }
    struct uint256 hash;
    block_header_get_hash(header, &hash);
    if (uint256_eq(&hash, &params->consensus.hashGenesisBlock)) {
        *parent_known = true;
        return true;
    }
    struct block_index *parent = block_map_find(&ms->map_block_index, &header->hashPrevBlock);
    if (!parent) return true;
    *parent_known = true;
    return process_block_should_skip_contextual_header(ms, parent, &params->consensus) ||
        contextual_check_block_header(header, state, params, parent, ms->fCheckpointsEnabled);
}

/* Idempotent by hash; a full ring replaces its next slot. */
static void pending_header_stage(const struct block_header *h)
{
    struct uint256 hash;
    block_header_get_hash(h, &hash);

    int free_slot = -1;
    for (int i = 0; i < HEADER_ADMIT_PENDING_CAP; i++) {
        if (g_pending[i].occupied) {
            if (memcmp(g_pending[i].hash.data, hash.data, 32) == 0)
                return;  /* already staged */
        } else if (free_slot < 0) {
            free_slot = i;
        }
    }
    static int rr = 0;
    int slot = (free_slot >= 0) ? free_slot
                                : (rr = (rr + 1) % HEADER_ADMIT_PENDING_CAP);
    g_pending[slot].hash     = hash;
    g_pending[slot].header   = *h;
    g_pending[slot].occupied = true;
}

/* Consume a staged header landing at want_height; unresolved parents stay. */
static const struct block_header *pending_header_take(struct main_state *ms,
                                                      int want_height)
{
    for (int i = 0; i < HEADER_ADMIT_PENDING_CAP; i++) {
        if (!g_pending[i].occupied)
            continue;
        const struct block_header *h = &g_pending[i].header;
        int produced_height;
        if (want_height == 0 && chain_params_get() &&
            uint256_eq(&g_pending[i].hash, &chain_params_get()->consensus.hashGenesisBlock)) {
            produced_height = 0;
        } else {
            struct block_index *pprev = block_map_find(&ms->map_block_index,
                                                       &h->hashPrevBlock);
            if (!pprev)
                continue;
            produced_height = pprev->nHeight + 1;
        }
        if (produced_height != want_height)
            continue;
        g_pending[i].occupied = false;
        return h;
    }
    return NULL;
}

/* HeaderAdmitLog owns writes through the AR lifecycle on progress.kv. */
static bool log_insert(sqlite3 *db, int height,
                        const struct uint256 *hash,
                        const struct uint256 *parent_hash)
{
    struct db_header_admit_log row = {
        .height      = (int64_t)height,
        .has_parent  = (parent_hash != NULL),
        .admitted_at = platform_time_wall_unix(),
    };
    memcpy(row.hash, hash->data, 32);
    if (parent_hash)
        memcpy(row.parent_hash, parent_hash->data, 32);

    if (!db_header_admit_log_save(db, &row)) {
        LOG_WARN("header_admit", "[header_admit] log save height=%d failed", height);
        return false;
    }
    return true;
}

static void handle_header_admit_msg(const struct header_admit_msg *m)
{
    if (!m) return;

    atomic_fetch_add(&g_inbox_drained_total, 1);

    /* Raw local headers use height=-1; stage them before the hint guard.
     * Production occurs only where the active chain has no block. */
    if (m->has_header)
        pending_header_stage(&m->header);

    struct main_state *ms = g_ms;
    sqlite3 *db = progress_store_db();
    if (!ms || !db || m->height < 0 || m->height > INT32_MAX)
        return;

    struct block_index *bi = active_chain_at(&ms->chain_active,
                                             (int)m->height);
    if (!bi || !bi->phashBlock)
        return;

    if (memcmp(bi->phashBlock->data, m->hash.data, 32) != 0) {
        LOG_WARN("header_admit", "[header_admit] inbox hash mismatch height=%lld peer=%u", (long long)m->height, m->peer_id);
        return;
    }

    const struct uint256 *parent_hash = NULL;
    if (m->height > 0) {
        if (!bi->pprev || !bi->pprev->phashBlock)
            return;
        parent_hash = bi->pprev->phashBlock;
    }

    progress_store_tx_lock();
    bool logged = log_insert(db, (int)m->height, bi->phashBlock, parent_hash);
    progress_store_tx_unlock();
    if (logged)
        atomic_fetch_add(&g_inbox_logged_total, 1);
}

static bool authoritative_admit(struct main_state *ms, struct block_index *bi)
{
#ifdef ZCL_TESTING
    if (g_authoritative_hook)
        return g_authoritative_hook(ms, bi, g_authoritative_hook_user);
#endif

    if (!ms || !bi || !bi->phashBlock)
        return false;

    struct block_index *mapped =
        block_map_find(&ms->map_block_index, bi->phashBlock);
    if (mapped && mapped != bi)
        return false;

    if ((bi->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE)
        bi->nStatus = (bi->nStatus & ~BLOCK_VALID_MASK) |
                      BLOCK_VALID_TREE;
    return true;
}

/* Resolve the header to admit at `height`.
 *
 * active_chain_at() is a body/window accessor; it intentionally returns NULL
 * above the current visible body frontier. Header admission must be able to
 * replay one or more heights above that window after a forward-fork cursor
 * rewind, so fall back to the canonical best-header ancestry exactly like
 * validate_headers. The fallback is accepted only when the candidate links to
 * either the already-visible active parent (height active_tip+1) or a matching
 * prior header_admit row above that point. A fork child at active_tip+1, or a
 * stale prior row, must wait for the reorg/window owner instead of being
 * re-admitted into the same mismatch loop. This changes only the source of the
 * block_index pointer;
 * authoritative_admit() and downstream PoW/body/script stages still own their
 * existing verdicts. */
static struct block_index *ha_resolve_bi(sqlite3 *db,
                                         struct main_state *ms,
                                         int height)
{
    if (!ms || height < 0)
        return NULL;

    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (bi)
        return bi;

    if (ms->pindex_best_header &&
        height <= ms->pindex_best_header->nHeight) {
        bi = block_index_get_ancestor(ms->pindex_best_header, height);
        if (bi &&
            header_admit_forward_replay_parent_ok(db, ms, bi, height))
            return bi;
    }

    return NULL;
}


/* Compare a durable row with the active window. A missing row/window slot is
 * unknown (no-op); SQL failure is fatal. */
static bool log_row_active_match(sqlite3_stmt *st, int height,
                                 bool *out_known, bool *out_matches)
{
    *out_known   = false;
    *out_matches = false;
    if (!st || height < 0)
        return true;

    struct main_state *ms = g_ms;
    struct block_index *bi =
        ms ? active_chain_at(&ms->chain_active, height) : NULL;
    if (!bi || !bi->phashBlock)
        return true;  /* chain has no block here → no-op (out_known=false) */

    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    sqlite3_bind_int(st, 1, height);
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        const void *blob = sqlite3_column_blob(st, 0);
        int nb = sqlite3_column_bytes(st, 0);
        if (blob && nb == 32) {
            *out_known   = true;
            *out_matches = (memcmp(blob, bi->phashBlock->data, 32) == 0);
        }
    }
    return true;
}

static bool rewind_forward_child_if_stale(sqlite3 *db, uint64_t cursor,
                                          bool *out_rewound)
{
    *out_rewound = false;
    if (!g_stage || !g_ms || cursor == 0)
        return true;

    int target = -1;
    const char *reason = "none";
    if (!header_admit_forward_rewind_target(
            db, &g_ms->chain_active, cursor, &target, &reason)) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork target audit failed "
                 "cursor=%llu",
                 (unsigned long long)cursor);
        return false;  // raw-return-ok:logged-above
    }
    if (target < 0)
        return true;

    if (!header_admit_forward_rewind_clamp_downstream(db, target)) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork downstream clamp failed "
                 "target=%d",
                 target);
        return false;  // raw-return-ok:logged-above
    }

    if (!stage_set_cursor(g_stage, db, (uint64_t)target)) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork cursor rewind failed "
                 "from=%llu to=%d",
                 (unsigned long long)cursor, target);
        return false;  // raw-return-ok:logged-above
    }

    atomic_fetch_add(&g_reorg_rewind_total, 1);
    atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
    LOG_WARN("header_admit",
             "[header_admit] forward-fork rewind from=%llu to=%d "
             "reason=%s",
             (unsigned long long)cursor, target, reason);
    event_emitf(EV_REORG_START, 0,
                "header_admit forward_fork_rewind from=%llu to=%d reason=%s",
                (unsigned long long)cursor, target, reason);
    *out_rewound = true;
    return true;
}

/* A divergence can sit below a matching tip, so scan the bounded recent
 * active-window overlap and rewind to the deepest mismatch. This mutates only
 * the stage cursor/log; SQL or cursor persistence failure is fatal. */
static bool rewind_cursor_if_active_chain_reorged(sqlite3 *db)
{
    if (!g_stage || !g_ms)
        return true;

    uint64_t cursor = 0;
    if (!stage_cursor_read_or_zero(db, STAGE_NAME, STAGE_NAME, &cursor))
        return false;
    if (cursor == 0)
        return true;
    if (cursor > (uint64_t)INT32_MAX) {
        LOG_WARN("header_admit", "[header_admit] reorg rewind cursor too large: %llu", (unsigned long long)cursor);
        return false;
    }

    bool rewound_forward = false;
    if (!rewind_forward_child_if_stale(db, cursor, &rewound_forward)) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-child stale audit failed "
                 "cursor=%llu",
                 (unsigned long long)cursor);
        return false;  // raw-return-ok:logged-above
    }
    if (rewound_forward)
        return true;

    /* Scan the recent window below the cursor for the deepest height
     * whose logged hash no longer matches the active chain. */
    int floor_h = (int)cursor - HEADER_ADMIT_REORG_REWIND_MAX_DEPTH;
    if (floor_h < 0) floor_h = 0;
    /* Above the raw lookahead bound active_chain_at() is known NULL. */
    int top_h = (int)cursor - 1;
    int window_h = active_chain_cached_height(&g_ms->chain_active);
    if (top_h > window_h)
        top_h = window_h;

    sqlite3_stmt *match_st = NULL;
    if (top_h >= floor_h && sqlite3_prepare_v2(
            db, "SELECT hash FROM header_admit_log WHERE height=?",
            -1, &match_st, NULL) != SQLITE_OK) {
        LOG_WARN("header_admit", "[header_admit] rewind prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    int deepest_divergent = -1;
    bool audit_ok = true;
    for (int h = top_h; h >= floor_h; h--) {
        atomic_fetch_add_explicit(&g_reorg_audit_height_checks, 1,
                                  memory_order_relaxed);
        bool known = false, matches = false;
        if (!log_row_active_match(match_st, h, &known, &matches)) {
            audit_ok = false;
            break;
        }
        if (known && !matches)
            deepest_divergent = h;  /* keep going: find the lowest one */
    }
    sqlite3_finalize(match_st);
    if (!audit_ok)
        return false;
    if (deepest_divergent < 0)
        return true;  /* recent window is consistent → no rewind */

    if (deepest_divergent == floor_h && floor_h > 0)
        LOG_WARN("header_admit", "[header_admit] reorg rewind cap hit (depth=%d): divergence may extend below floor=%d", HEADER_ADMIT_REORG_REWIND_MAX_DEPTH, floor_h);

    uint64_t rewind_to = (uint64_t)deepest_divergent;
    if (rewind_to >= cursor)
        return true;

    if (!stage_set_cursor(g_stage, db, rewind_to)) {
        LOG_WARN("header_admit", "[header_admit] reorg rewind failed from=%llu to=%llu", (unsigned long long)cursor, (unsigned long long)rewind_to);
        return false;
    }

    atomic_fetch_add(&g_reorg_rewind_total, 1);
    atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
    event_emitf(EV_REORG_START, 0,
                "header_admit reorg_cursor_rewind from=%llu to=%llu",
                (unsigned long long)cursor,
                (unsigned long long)rewind_to);
    return true;
}

/* Produce a mapped index from staged bytes at want_height, or let the caller
 * idle. This touches neither coins, disk nor the active-chain tip. */
static struct block_index *produce_block_index(struct main_state *ms,
                                               int want_height)
{
    /* step_once owns progress-store; cs_main is the inner index lock. */
    zcl_mutex_lock(&ms->cs_main);
    const struct block_header *h = pending_header_take(ms, want_height);
    if (!h) {
        zcl_mutex_unlock(&ms->cs_main);
        return NULL;
    }
    struct validation_state state;
    validation_state_init(&state);
    bool parent_known = false;
    bool allowed = header_admit_check_contextual_locked(ms, chain_params_get(), h, &state, &parent_known);
    struct block_index *bi = allowed && parent_known ? add_to_block_index(ms, h) : NULL;
    zcl_mutex_unlock(&ms->cs_main);
    if (!allowed) {
        LOG_WARN("header_admit", "pending header rejected height=%d reason=%s", want_height, state.reject_reason);
        return NULL;
    }
    if (!bi || !bi->phashBlock) {
        LOG_WARN("header_admit", "[header_admit] produce add_to_block_index failed height=%d", want_height);
        return NULL;
    }
    atomic_fetch_add(&g_produced_total, 1);
    return bi;
}

static job_result_t step_admit(struct stage_step_ctx *c)
{
    atomic_store(&g_last_step_unix, platform_time_wall_unix());

    struct main_state *ms = g_ms;
    if (!ms) return JOB_IDLE;

    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;

    int next_h = (int)c->cursor_in;
    if (next_h < 0) return JOB_FATAL;

    /* The mint driver's ceiling bounds every downstream stage; the normal
     * INT32_MAX ceiling does not clamp admission. */
    if (next_h > mint_fold_ceiling_get())
        return JOB_IDLE;

    struct block_index *bi = ha_resolve_bi(db, ms, next_h);
    if (!bi || !bi->phashBlock) {
        /* No active entry: try the staged raw-header producer. */
        bi = produce_block_index(ms, next_h);
        if (!bi || !bi->phashBlock) return JOB_IDLE;
    }

    const struct uint256 *parent_hash = NULL;
    if (next_h > 0) {
        if (!bi->pprev || !bi->pprev->phashBlock) {
            blocker_init(&c->blocker, "header_admit",
                          "missing_parent",
                          BLOCKER_PERMANENT,
                          "block_index entry has no pprev linkage");
            atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
            return JOB_BLOCKED;
        }
        parent_hash = bi->pprev->phashBlock;
    }

    if (!authoritative_admit(ms, bi)) {
        LOG_WARN("header_admit",
                 "[header_admit] authoritative admit failed height=%d",
                 next_h);
        return JOB_FATAL;
    }

    /* CSR's single-writer lock prevents stale promotion over a newer header. */
    bool promoted = false;
    enum csr_result promote_rc = csr_promote_header_tip(
        csr_instance(), &ms->chain_active, &ms->pindex_best_header, bi,
        "header_admit", &promoted);
#ifdef ZCL_TESTING
    /* Isolated fixtures omit CSR; production has no raw writer. */
    if (promote_rc == CSR_REJECTED_NOT_INITIALIZED) {
        struct block_index *current = ms->pindex_best_header;
        bool advance = current == NULL;
        if (current && current != bi) {
            bool have_work = !arith_uint256_is_zero(&bi->nChainWork) &&
                             !arith_uint256_is_zero(&current->nChainWork);
            advance = have_work
                ? arith_uint256_compare(&bi->nChainWork,
                                        &current->nChainWork) > 0
                : bi->nHeight > current->nHeight;
        }
        if (advance)
            ms->pindex_best_header = bi;
        promote_rc = CSR_OK;
        promoted = advance;
    }
#endif
    (void)promoted;
    if (promote_rc != CSR_OK) {
        LOG_WARN("header_admit",
                 "header promotion failed height=%d code=%s",
                 bi->nHeight, csr_result_name(promote_rc));
        return JOB_FATAL;
    }

    /* Best-effort projection emit follows VALID_TREE promotion. */
    block_index_emit_header_event(bi, "header_admit",
                                  &g_header_event_emit_total,
                                  &g_header_event_emit_fail_total);

    if (!log_insert(db, next_h, bi->phashBlock, parent_hash))
        return JOB_FATAL;

    c->cursor_out = c->cursor_in + 1;
    atomic_fetch_add(&g_admitted_total, 1);
    atomic_store(&g_last_admit_height, (int64_t)next_h);
    return JOB_ADVANCED;
}

/* ── Public API ────────────────────────────────────────────────────── */

#ifdef ZCL_TESTING
void header_admit_stage_set_authoritative_hook(
    header_admit_authoritative_hook hook,
    void *user)
{
    g_authoritative_hook = hook;
    g_authoritative_hook_user = user;
}
#endif

bool header_admit_stage_init(struct main_state *ms)
{
    if (!ms) LOG_FAIL("header_admit", "init: NULL main_state");

    sqlite3 *db = progress_store_db();
    if (!db) LOG_FAIL("header_admit",
        "init: progress_store not open");

    pthread_mutex_lock(&g_lock);

    /* Idempotent: same ms, already initialised → success. */
    if (g_stage != NULL) {
        bool same = (g_ms == ms);
        pthread_mutex_unlock(&g_lock);
        if (!same)
            LOG_FAIL("header_admit",
                "init: already bound to a different main_state");
        return true;
    }

    if (!db_header_admit_log_ensure_schema(db)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    uint64_t persisted_cursor = 0;
    if (!stage_cursor_read_or_zero(db, STAGE_NAME, STAGE_NAME,
                                   &persisted_cursor)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    stage_t *s = stage_create(STAGE_NAME, step_admit, NULL);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        LOG_FAIL("header_admit", "init: stage_create failed");
    }
    if (!stage_set_cursor(s, db, persisted_cursor)) {
        stage_destroy(s);
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    g_ms = ms;
    g_stage = s;
    pthread_mutex_unlock(&g_lock);

    LOG_INFO("header_admit",
             "[header_admit] stage initialised (authoritative)");
    return true;
}

static job_result_t header_admit_owned_stage_step_once(void)
{
    if (!g_stage) return JOB_IDLE;
    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;
    progress_store_tx_lock();
    bool batched = stage_batch_active();
    uint64_t generation = batched ? stage_batch_generation() : 0;
    if (!batched || generation != g_reorg_audit_batch_generation) {
        atomic_fetch_add(&g_reorg_audit_total, 1u);
        if (!rewind_cursor_if_active_chain_reorged(db)) {
            progress_store_tx_unlock();
            LOG_RETURN(JOB_FATAL, "header_admit",
                       "FATAL: active-chain reorg rewind failed");
        }
        if (batched)
            g_reorg_audit_batch_generation = generation;
    }
    (void)mailbox_header_admit_drain(handle_header_admit_msg);
    job_result_t r = stage_run_once(g_stage, db);
    progress_store_tx_unlock();
    return r;
}

#ifdef ZCL_TESTING
static void (*g_main_lock_hook)(void *);
static void *g_main_lock_hook_ctx;

void header_admit_stage_set_main_hook_for_testing(
    void (*hook)(void *), void *ctx)
{
    g_main_lock_hook = hook;
    g_main_lock_hook_ctx = ctx;
}
#endif

/* Observe immediately before real ownership, never instead of ownership. */
static void header_admit_stage_lock_main(struct main_state *ms)
{
#ifdef ZCL_TESTING
    if (g_main_lock_hook)
        g_main_lock_hook(g_main_lock_hook_ctx);
#endif
    zcl_mutex_lock(&ms->cs_main);
}

job_result_t header_admit_stage_step_once(void)
{
    struct main_state *ms = g_ms;
    if (!ms || !g_stage) return JOB_IDLE;
    header_admit_stage_lock_main(ms);
    job_result_t result = header_admit_owned_stage_step_once();
    zcl_mutex_unlock(&ms->cs_main);
    return result;
}

/* Keep the shared batch implementation private; its prior static declaration
 * gives the generated definition internal linkage. The public wrapper owns
 * main before the macro can acquire progress for batch creation. */
static int header_admit_owned_stage_drain(int max_steps);
STAGE_DRAIN_IMPL(header_admit_owned)

int header_admit_stage_drain(int max_steps)
{
    struct main_state *ms = g_ms;
    if (max_steps <= 0 || !ms || !g_stage) return 0;
    header_admit_stage_lock_main(ms);
    int advanced = header_admit_owned_stage_drain(max_steps);
    zcl_mutex_unlock(&ms->cs_main);
    return advanced;
}

void header_admit_stage_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_stage) {
        stage_destroy(g_stage);
        g_stage = NULL;
    }
    g_ms = NULL;
    /* Reset per-init observability state. The persisted cursor in
     * progress.kv is preserved (that's the whole point of the saga);
     * what we reset is what would be misleading across re-inits —
     * lifetime counters that should restart with each bind. */
    atomic_store(&g_admitted_total, (uint64_t)0);
    atomic_store(&g_inbox_drained_total, (uint64_t)0);
    atomic_store(&g_inbox_logged_total, (uint64_t)0);
    atomic_store(&g_reorg_rewind_total, (uint64_t)0);
    atomic_store(&g_reorg_audit_total, (uint64_t)0);
    atomic_store(&g_reorg_audit_height_checks, (uint64_t)0);
    g_reorg_audit_batch_generation = 0;
    atomic_store(&g_header_event_emit_total, (uint64_t)0);
    atomic_store(&g_header_event_emit_fail_total, (uint64_t)0);
    atomic_store(&g_produced_total, (uint64_t)0);
    atomic_store(&g_last_admit_height, (int64_t)-1);
    atomic_store(&g_last_step_unix, (int64_t)0);
    atomic_store(&g_last_blocked_unix, (int64_t)0);
    memset(g_pending, 0, sizeof(g_pending));
#ifdef ZCL_TESTING
    g_authoritative_hook = NULL;
    g_authoritative_hook_user = NULL;
#endif
    pthread_mutex_unlock(&g_lock);
}

uint64_t header_admit_stage_cursor(void)
{
    if (!g_stage)
        return 0;
    return stage_cursor(g_stage);
}

int64_t header_admit_stage_step_us_ewma(void)
{
    return g_stage ? stage_step_us_ewma(g_stage) : 0;
}

uint64_t header_admit_stage_admitted_total(void)
{
    return atomic_load(&g_admitted_total);
}

uint64_t header_admit_stage_reorg_rewind_total(void)
{
    return atomic_load(&g_reorg_rewind_total);
}

uint64_t header_admit_stage_reorg_audit_total(void)
{
    return atomic_load(&g_reorg_audit_total);
}

uint64_t header_admit_stage_produced_total(void)
{
    return atomic_load(&g_produced_total);
}

bool header_admit_stage_has_record(int32_t height,
                                   const struct uint256 *hash)
{
    if (height < 0 || !hash)
        return false;

    sqlite3 *db = progress_store_db();
    if (!db)
        return false;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT hash FROM header_admit_log WHERE height=?",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        progress_store_tx_unlock();
        return false;
    }

    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        const void *blob = sqlite3_column_blob(st, 0);
        int nb = sqlite3_column_bytes(st, 0);
        found = (blob && nb == 32 &&
                 memcmp(blob, hash->data, 32) == 0);
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return found;
}

bool header_admit_stage_dump_state_json(struct json_value *out,
                                         const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    stage_dump_header(out, STAGE_NAME, g_stage);
    json_push_kv_int (out, "admitted_total",
                      (int64_t)atomic_load(&g_admitted_total));
    json_push_kv_int (out, "inbox_drained_total",
                      (int64_t)atomic_load(&g_inbox_drained_total));
    json_push_kv_int (out, "inbox_logged_total",
                      (int64_t)atomic_load(&g_inbox_logged_total));
    json_push_kv_int (out, "reorg_rewind_total",
                      (int64_t)atomic_load(&g_reorg_rewind_total));
    json_push_kv_int (out, "reorg_audit_total",
                      (int64_t)atomic_load(&g_reorg_audit_total));
    json_push_kv_int (out, "reorg_audit_height_checks",
                      (int64_t)atomic_load(&g_reorg_audit_height_checks));
    json_push_kv_int (out, "header_event_emit_total",
                      (int64_t)atomic_load(&g_header_event_emit_total));
    json_push_kv_int (out, "header_event_emit_fail_total",
                      (int64_t)atomic_load(&g_header_event_emit_fail_total));
    json_push_kv_int (out, "produced_total",
                      (int64_t)atomic_load(&g_produced_total));
    json_push_kv_int (out, "last_admit_height",
                      atomic_load(&g_last_admit_height));
    json_push_kv_int (out, "last_step_unix",
                      atomic_load(&g_last_step_unix));
    json_push_kv_int (out, "last_blocked_unix",
                      atomic_load(&g_last_blocked_unix));
    json_push_kv_str(out, "authority", "authoritative");
    stage_dump_counters(out, g_stage);
    stage_dump_health(out, STAGE_NAME, g_stage);
    return true;
}
