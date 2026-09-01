/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain state repository — implementation. See header for the design
 * rationale and the incident class that motivated this service. */

// one-result-type-ok:legacy-csr-enum-contract-with-zcl-result-adapter

#include "services/chain_state_service.h"
#include "chain_state_internal.h"

#include "config/db_service.h"
#include "event/event.h"
#include "services/invariant_sentinel.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

/* ── Default tunables ───────────────────────────────────────── */
#define CSR_DEFAULT_MAX_ORPHAN_ROWS   1000
#define CSR_DEFAULT_STALE_INDEX_GAP   100

/* ── SQLite helpers ─────────────────────────────────────────────
 * The repository must work even when ndb is NULL (unit tests, early
 * boot phases). All helpers return false / -1 when there is no DB,
 * and the caller treats that as "skip this cross-check". */

int64_t csr_internal_sqlite_max_block_height(struct node_db *ndb)
{
    if (!ndb || !ndb->open || !ndb->db)
        LOG_RETURN(-1, "csr", "ndb not available (null or closed)");
    sqlite3_stmt *st = NULL;
    int64_t result = -1;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT MAX(height) FROM blocks", -1, &st, NULL) == SQLITE_OK) {
        if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW &&
            sqlite3_column_type(st, 0) != SQLITE_NULL) {
            result = sqlite3_column_int64(st, 0);
        }
        sqlite3_finalize(st);
    }
    return result;
}

/* Look up a block hash in the SQLite blocks table. Returns:
 *    1 = found, *out_height set
 *    0 = not found
 *   -1 = no DB available (caller should skip the cross-check) */
static int csr_sqlite_block_height(struct node_db *ndb,
                                    const struct uint256 *hash,
                                    int64_t *out_height)
{
    if (!ndb || !ndb->open || !ndb->db || !hash || !out_height)
        LOG_ERR("csr", "invalid args (ndb=%p hash=%p out=%p)",
                (void *)ndb, (void *)hash, (void *)out_height);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT height FROM blocks WHERE hash=? LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_ERR("csr", "sqlite3_prepare_v2 failed: %s", sqlite3_errmsg(ndb->db));
    }
    sqlite3_bind_blob(st, 1, hash->data, 32, SQLITE_STATIC);
    int rc = AR_STEP_ROW_READONLY(st);
    int result;
    if (rc == SQLITE_ROW) {
        *out_height = sqlite3_column_int64(st, 0);
        result = 1;
    } else {
        result = 0;
    }
    sqlite3_finalize(st);
    return result;
}

int64_t csr_internal_sqlite_utxo_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(-1, "csr", "ndb not available");
    /* The CANONICAL coin count is coins_kv (progress.kv, co-committed
     * with the stage cursor) — but only once it is the PROVEN authority
     * (migration stamp + frontier + non-empty, coins_kv.h); a partial
     * mid-migration set must not steer the CSR validation thresholds. The
     * node.db mirror count is the fallback. */
    {
        sqlite3 *pdb = progress_store_db();
        if (pdb && coins_kv_is_proven_authority(pdb, NULL))
            return coins_kv_count(pdb);
    }
    return node_db_utxo_count(ndb);
}

static void csr_set_last_persist_locked(struct chain_state_repository *csr,
                                        int sqlite_rc,
                                        const char *msg)
{
    if (!csr)
        return;
    csr->last_persist_sqlite_rc = sqlite_rc;
    snprintf(csr->last_persist_error, sizeof(csr->last_persist_error),
             "%s", msg ? msg : "");
}

struct csr_persist_state_ctx {
    const char *key;
    const void *value;
    size_t len;
    bool ok;
    int sqlite_rc;
    char msg[128];
};

static bool csr_persist_state_write(struct node_db *ndb, void *ctx)
{
    struct csr_persist_state_ctx *p = ctx;
    struct node_db_status st;

    if (!ndb || !p) {
        if (p) {
            p->sqlite_rc = SQLITE_MISUSE;
            snprintf(p->msg, sizeof(p->msg), "invalid db writer ctx");
        }
        return false;
    }
    p->ok = node_db_state_set(ndb, p->key, p->value, p->len);
    node_db_get_status(ndb, &st);
    p->sqlite_rc = st.last_sqlite_rc;
    snprintf(p->msg, sizeof(p->msg), "op=%s rc=%d %s",
             st.last_op[0] ? st.last_op : "state_set",
             st.last_sqlite_rc, sqlite3_errstr(st.last_sqlite_rc));
    return p->ok;
}

static bool csr_sqlite_busy_or_locked(int rc)
{
    return rc == SQLITE_BUSY || rc == SQLITE_LOCKED;
}

/* CACHE-REFRESH of the derived coins-best: writes the node_state
 * 'coins_best_block' key, which is display / legacy-boot fallback only —
 * the authority is reducer_frontier_derive_coins_best over coins_kv's own
 * co-committed state. */
static enum csr_result csr_persist_coins_best_locked(
    struct chain_state_repository *csr,
    const struct chain_state_commit *commit)
{
    if (!csr || !commit)
        return CSR_REJECTED_NULL_INPUT;
    if (!csr->ndb || !csr->ndb->open) {
        csr_set_last_persist_locked(csr, SQLITE_MISUSE,
                                    "node_db unavailable");
        return CSR_REJECTED_PERSIST;
    }

    struct db_service *dbsvc = csr->db_service;
    const int attempts = 8;
    for (int i = 0; i < attempts; i++) {
        struct csr_persist_state_ctx ctx = {
            .key = "coins_best_block",
            .value = commit->new_coins_best.data,
            .len = 32,
            .ok = false,
            .sqlite_rc = SQLITE_OK,
        };
        bool submitted = false;
        if (dbsvc && db_service_is_started(dbsvc) &&
            db_service_node_db(dbsvc) == csr->ndb) {
            submitted = db_service_run_write(dbsvc,
                                             csr_persist_state_write,
                                             &ctx);
        } else {
            submitted = csr_persist_state_write(csr->ndb, &ctx);
        }

        if (submitted && ctx.ok) {
            csr_set_last_persist_locked(csr, SQLITE_OK, "");
            return CSR_OK;
        }

        csr_set_last_persist_locked(csr, ctx.sqlite_rc, ctx.msg);
        if (csr_sqlite_busy_or_locked(ctx.sqlite_rc) && i + 1 < attempts) {
            struct timespec ts = {
                .tv_sec = 0,
                .tv_nsec = 25000000L * (long)(i + 1),
            };
            nanosleep(&ts, NULL);
            continue;
        }
        return csr_sqlite_busy_or_locked(ctx.sqlite_rc)
            ? CSR_REJECTED_DB_BUSY
            : CSR_REJECTED_PERSIST;
    }
    csr_set_last_persist_locked(csr, SQLITE_BUSY, "bounded retry exhausted");
    return CSR_REJECTED_DB_BUSY;
}

/* ── Validation (caller holds csr->lock) ─────────────────────── */

static bool csr_rollback_authorization_valid(
    const struct chain_state_rollback_authorization *auth)
{
    if (!auth)
        return false;
    if (auth->source == CSR_ROLLBACK_SOURCE_NONE)
        return false;
    if (auth->decision != POLICY_ALLOW)
        return false;
    if (!auth->evidence_class || !*auth->evidence_class)
        return false;
    if (!auth->reason || !*auth->reason)
        return false;
    if (auth->from_height >= 0 && auth->to_height >= 0 &&
        auth->from_height > auth->to_height && auth->max_depth >= 0) {
        int64_t depth = auth->from_height - auth->to_height;
        if (depth > auth->max_depth)
            return false;
    }
    return true;
}

static bool csr_commit_has_rollback_authorization(
    const struct chain_state_commit *commit)
{
    return csr_rollback_authorization_valid(
        commit ? commit->rollback_auth : NULL);
}

static enum csr_result csr_validate_locked(
    struct chain_state_repository *csr,
    const struct chain_state_commit *commit)
{
    /* Step 0: structural NULL checks. */
    if (!commit || !commit->new_tip) return CSR_REJECTED_NULL_INPUT;
    if (!commit->reason || !*commit->reason) return CSR_REJECTED_NULL_INPUT;

    struct block_index *new_tip = commit->new_tip;
    if (!new_tip->phashBlock) return CSR_REJECTED_NULL_INPUT;
    if (new_tip->nHeight < 0) return CSR_REJECTED_NULL_INPUT;

    /* Boot repair may install genesis on a true fresh start, but it must never
     * turn a durable non-genesis finalized floor into a rollback to h=0. That
     * recovery shape belongs to the policy-gated UTXO repair path after a real
     * wipe decision, not to genesis initialization. */
    if (new_tip->nHeight == 0 && commit->rollback_auth &&
        commit->rollback_auth->source == CSR_ROLLBACK_SOURCE_BOOT_REPAIR &&
        csr->chain_active && active_chain_height(csr->chain_active) > 0) {
        return CSR_REJECTED_ROLLBACK_AUTH;
    }

    /* Step 1: the proposed coins_best_block must equal the tip hash.
     * If they disagree, the caller has a bug — refuse rather than
     * silently picking one. This is the fundamental invariant. */
    if (memcmp(commit->new_coins_best.data,
               new_tip->phashBlock->data, 32) != 0) {
        return CSR_REJECTED_COINS_MISMATCH;
    }

    /* Step 2: the new tip must be registered in the in-memory block
     * map. block_map_find returns the canonical block_index pointer
     * for that hash; if it isn't equal to new_tip then the caller is
     * passing a stale or stack-allocated index that the rest of the
     * system doesn't know about. */
    if (csr->block_map) {
        struct block_index *found =
            block_map_find(csr->block_map, new_tip->phashBlock);
        if (!found) return CSR_REJECTED_TIP_NOT_IN_INDEX;
        if (found != new_tip) return CSR_REJECTED_HASH_MISMATCH;
    }

    /* Step 3: pprev must also be in the index (or be NULL for genesis). */
    if (csr->block_map && new_tip->pprev) {
        if (!new_tip->pprev->phashBlock) return CSR_REJECTED_MISSING_PREV;
        struct block_index *prev =
            block_map_find(csr->block_map, new_tip->pprev->phashBlock);
        if (prev != new_tip->pprev) return CSR_REJECTED_MISSING_PREV;
    }

    /* Step 4: SQLite cross-check on the new tip hash itself. If
     * SQLite knows this hash, the height must agree. This is the
     * direct test for the h=60-vs-h=3M class of bug. */
    int64_t sql_h = -1;
    int hf = csr_sqlite_block_height(csr->ndb, new_tip->phashBlock, &sql_h);
    if (hf == 1 && sql_h != new_tip->nHeight) {
        return CSR_REJECTED_HASH_MISMATCH;
    }

    /* Step 5: SQLite tip vs proposed tip. If SQLite holds blocks far
     * above the proposed tip, this commit is rolling the chain
     * backwards in a way that has historically corrupted the UTXO
     * set. Combined with a non-trivial UTXO row count it is the
     * exact disaster shape this guard exists to catch.
     *
     * Carve-out: a forward step relative to the CURRENT active chain
     * tip cannot be a rollback, regardless of what other blocks the
     * block_index has cached above the active chain. This shape arises
     * legitimately during body-pull →
     * reducer activation: body-pull pre-populates the block_index
     * (and SQLite) for hundreds of blocks above the active tip, then
     * reducer activation advances the active tip one block at a
     * time into that pre-populated range. A forward step from h=N to
     * h=N+1 must not be rejected as stale_index merely because sql_max
     * sits above it; the disaster shape requires new_tip < active_tip,
     * so allowing new_tip > active_tip cannot reproduce it. */
    int64_t sql_max = csr_internal_sqlite_max_block_height(csr->ndb);
    if (sql_max >= 0 &&
        sql_max - (int64_t)new_tip->nHeight > csr->stale_index_height_gap) {
        bool forward_from_active_tip = false;
        if (csr->chain_active) {
            int cur_h = active_chain_height(csr->chain_active);
            if (cur_h >= 0 && new_tip->nHeight > cur_h)
                forward_from_active_tip = true;
        }

        if (!forward_from_active_tip) {
            int64_t cur_utxos = csr_internal_sqlite_utxo_count(csr->ndb);
            if (cur_utxos > csr->max_utxo_orphan_rows &&
                !csr_commit_has_rollback_authorization(commit)) {
                return CSR_REJECTED_STALE_INDEX;
            }
        }
    }

    /* Step 6: explicit expected_utxo_count check. The caller can
     * pass the count it believes the new tip should imply; if the
     * SQLite count differs by more than 50% we refuse. */
    if (commit->expected_utxo_count > 0) {
        int64_t actual = csr_internal_sqlite_utxo_count(csr->ndb);
        if (actual >= 0) {
            int64_t diff = actual - commit->expected_utxo_count;
            if (diff < 0) diff = -diff;
            int64_t denom = actual > commit->expected_utxo_count
                ? actual : commit->expected_utxo_count;
            if (denom > 0 && diff * 2 > denom) {  /* >50% drift */
                return CSR_REJECTED_UTXO_DELTA_TOO_BIG;
            }
        }
    }

    /* Step 7: orphan-rows guard for backward moves. Even without an
     * obviously stale block_index, we refuse to silently orphan a
     * large UTXO set unless the caller explicitly opted into a
     * rollback with a typed policy authorization. */
    if (csr->chain_active && !csr_commit_has_rollback_authorization(commit)) {
        int cur_h = active_chain_height(csr->chain_active);
        if (cur_h >= 0 && new_tip->nHeight < cur_h) {
            int64_t cur_utxos = csr_internal_sqlite_utxo_count(csr->ndb);
            if (cur_utxos > csr->max_utxo_orphan_rows) {
                return CSR_REJECTED_UTXO_DELTA_TOO_BIG;
            }
        }
    }

    return CSR_OK;
}

enum csr_result csr_internal_validate_header_identity_locked(
    struct chain_state_repository *csr,
    struct block_index *new_tip,
    const char *reason)
{
    if (!new_tip || !reason || !*reason)
        return CSR_REJECTED_NULL_INPUT;
    if (!new_tip->phashBlock)
        return CSR_REJECTED_NULL_INPUT;
    if (new_tip->nHeight < 0)
        return CSR_REJECTED_NULL_INPUT;

    if (csr->block_map) {
        struct block_index *found =
            block_map_find(csr->block_map, new_tip->phashBlock);
        if (!found)
            return CSR_REJECTED_TIP_NOT_IN_INDEX;
        if (found != new_tip)
            return CSR_REJECTED_HASH_MISMATCH;
    }

    if (csr->block_map && new_tip->pprev) {
        if (!new_tip->pprev->phashBlock)
            return CSR_REJECTED_MISSING_PREV;
        struct block_index *prev =
            block_map_find(csr->block_map, new_tip->pprev->phashBlock);
        if (prev != new_tip->pprev)
            return CSR_REJECTED_MISSING_PREV;
    }

    return CSR_OK;
}

static enum csr_result csr_validate_header_locked(
    struct chain_state_repository *csr,
    const struct chain_state_header_commit *commit)
{
    if (!commit)
        return CSR_REJECTED_NULL_INPUT;
    enum csr_result identity = csr_internal_validate_header_identity_locked(
        csr, commit->new_header_tip, commit->reason);
    if (identity != CSR_OK)
        return identity;

    struct block_index *new_tip = commit->new_header_tip;

    /* Header-tip promotion is chainwork-ranked, mirroring Bitcoin Core's
     * pindexBestHeader semantics: the body-downloader must follow the
     * most-WORK header chain, not merely the highest-HEIGHT one. A fork
     * that is taller by raw height but carries less cumulative proof-of-
     * work must NOT displace the current best header.
     *
     * Conservative fallback (matches accept_block.c's nChainWork repair
     * path and find_most_work_chain): if either side's nChainWork has not
     * been stamped yet (still zero — e.g. flat-index load before the
     * pprev walk recomputes work), we cannot trust the work comparison,
     * so we fall back to the historical height-based regression rule.
     * This never drops a valid higher header just because its work is not
     * yet computed. */
    if (csr->pindex_best_hdr && *csr->pindex_best_hdr &&
        !csr_rollback_authorization_valid(commit->rollback_auth)) {
        struct block_index *cur = *csr->pindex_best_hdr;
        bool have_work = !arith_uint256_is_zero(&new_tip->nChainWork) &&
                         !arith_uint256_is_zero(&cur->nChainWork);
        if (have_work) {
            int work_cmp = arith_uint256_compare(&new_tip->nChainWork,
                                                 &cur->nChainWork);
            /* Strictly-less work is a regression; equal work keeps the
             * incumbent (no churn between equal-work tips). */
            if (work_cmp < 0)
                return CSR_REJECTED_HEADER_REGRESSION;
            /* A strictly-greater-work tip always wins (it IS the new most-
             * work header). But when the candidate does NOT strictly exceed
             * the incumbent's work (work_cmp == 0 here, since < 0 already
             * returned), a LOWER-height tip can never legitimately be the
             * best header on the same most-work chain — admitting it would
             * drag pindex_best_header (and therefore the active-chain window
             * the header pipeline extends to) BACKWARD below heights already
             * in the index, freezing header_admit/validate_headers. This is
             * the regression that lets an inbound msg_headers batch whose
             * pindex_last lands below the current tip clobber best_header
             * downward. Bitcoin Core's pindexBestHeader is never moved
             * backward by an incoming headers batch; mirror that here.
             * A legitimate authorized reorg still rewinds via the
             * rollback_auth escape (checked at the top of this block). */
            if (work_cmp == 0 && new_tip->nHeight < cur->nHeight) {
                /* LANE D / SELF-HEAL (S3): a strictly-lower-height equal-work
                 * header is normally a best-header regression (clobbers
                 * pindex_best_header downward). EXCEPTION: when the incumbent
                 * best-header at new_tip's own height is FAILED, the canonical
                 * equal-work sibling MUST be promotable so the body-downloader
                 * follows it (otherwise sibling-adopt selects a chain whose
                 * header the downloader never re-requests, re-wedging). Pure
                 * read over our own FAILED status; parity-restoring. */
                struct block_index *inc = csr->chain_active
                    ? active_chain_at(csr->chain_active, new_tip->nHeight)
                    : NULL;
                if (!inc || !block_has_any_failure(inc))
                    return CSR_REJECTED_HEADER_REGRESSION;
            }
        } else if (new_tip->nHeight < cur->nHeight) {
            return CSR_REJECTED_HEADER_REGRESSION;
        }
    }

    return CSR_OK;
}

/* ── Event helpers ──────────────────────────────────────────── */

static void csr_emit_commit_event(struct chain_state_repository *csr,
                                   int from_height,
                                   const struct chain_state_commit *commit)
{
    (void)csr;
    event_emitf(EV_CHAIN_TIP_COMMIT, 0,
                "from=%d to=%d reason=%s",
                from_height,
                commit->new_tip ? commit->new_tip->nHeight : -1,
                commit->reason ? commit->reason : "");
}

static void csr_emit_rejected_event(struct chain_state_repository *csr,
                                     int from_height,
                                     const struct chain_state_commit *commit,
                                     enum csr_result rc)
{
    (void)csr;
    int to_h = (commit && commit->new_tip) ? commit->new_tip->nHeight : -1;
    const char *reason = (commit && commit->reason) ? commit->reason : "";
    event_emitf(EV_CHAIN_TIP_REJECTED, 0,
                "code=%s from=%d to=%d reason=%s",
                csr_result_name(rc), from_height, to_h, reason);
    /* csr Step 4 already REFUSED the pair — surface it as the typed
     * authority-pair blocker + one page so it can never stay a quiet
     * reject counter (no second refusal here). */
    if (rc == CSR_REJECTED_HASH_MISMATCH)
        invariant_sentinel_pair_violation("csr_commit", to_h, -1);
}

/* ── Public API ─────────────────────────────────────────────── */

/* Process-lifetime singleton. Storage is zero-initialized by the C
 * runtime; the mutex is brought to life exactly once by pthread_once
 * the first time csr_instance() is called. Boot wires real pointers
 * later via csr_init(csr_instance(), ...). */
static struct chain_state_repository g_csr_singleton;
static pthread_once_t g_csr_singleton_once = PTHREAD_ONCE_INIT;

static void csr_singleton_once_init(void)
{
    pthread_mutex_init(&g_csr_singleton.lock, NULL);
    g_csr_singleton.max_utxo_orphan_rows  = CSR_DEFAULT_MAX_ORPHAN_ROWS;
    g_csr_singleton.stale_index_height_gap = CSR_DEFAULT_STALE_INDEX_GAP;
    /* initialized stays false until csr_init is called with real
     * pointers — any commit attempt before that returns
     * CSR_REJECTED_NOT_INITIALIZED with no side effects. */
}

struct chain_state_repository *csr_instance(void)
{
    pthread_once(&g_csr_singleton_once, csr_singleton_once_init);
    return &g_csr_singleton;
}

static void csr_header_generation_bump(struct chain_state_repository *csr)
{
    uint64_t next = atomic_fetch_add(&csr->header_generation, 1) + 1;
    if (!next)
        atomic_fetch_add(&csr->header_generation, 1);
}

void csr_init(struct chain_state_repository *csr,
              struct block_map        *block_map,
              struct active_chain     *chain_active,
              struct block_index     **pindex_best_hdr,
              struct coins_view_cache *coins_tip,
              struct node_db          *ndb,
              int64_t                 *wallet_scan_h)
{
    if (!csr) return;

    /* Stack-allocated repositories (tests, short-lived helpers) need
     * a full reset and a fresh mutex. The singleton already has its
     * mutex set up by pthread_once — never touch it here, just assign
     * the field pointers under the existing lock so callers that are
     * mid-commit observe a consistent view. */
    if (csr != &g_csr_singleton) {
        memset(csr, 0, sizeof(*csr));
        pthread_mutex_init(&csr->lock, NULL);
    }

    pthread_mutex_lock(&csr->lock);
    csr->block_map        = block_map;
    csr->chain_active     = chain_active;
    csr->pindex_best_hdr  = pindex_best_hdr;
    csr->coins_tip        = coins_tip;
    csr->ndb              = ndb;
    csr->db_service       = NULL;
    csr->wallet_scan_h    = wallet_scan_h;
    csr->max_utxo_orphan_rows  = CSR_DEFAULT_MAX_ORPHAN_ROWS;
    csr->stale_index_height_gap = CSR_DEFAULT_STALE_INDEX_GAP;
    csr->commits_ok = 0;
    atomic_store(&csr->header_generation, 1);
    memset(csr->commits_rejected, 0, sizeof(csr->commits_rejected));
    csr_set_last_persist_locked(csr, SQLITE_OK, "");
    csr->initialized = true;
    pthread_mutex_unlock(&csr->lock);
}

void csr_free(struct chain_state_repository *csr)
{
    if (!csr || !csr->initialized) return;
    /* Singleton lives for the whole process — its mutex is owned by
     * pthread_once and must not be destroyed. Just clear the flag so
     * subsequent commits are rejected cleanly. */
    if (csr != &g_csr_singleton) {
        pthread_mutex_destroy(&csr->lock);
    }
    csr->initialized = false;
    csr_header_generation_bump(csr);
    csr->block_map = NULL;
    csr->chain_active = NULL;
    csr->pindex_best_hdr = NULL;
    csr->coins_tip = NULL;
    csr->ndb = NULL;
    csr->db_service = NULL;
    csr->wallet_scan_h = NULL;
}

#ifdef ZCL_TESTING
void csr_test_reset_singleton(void)
{
    struct chain_state_repository *csr = csr_instance();
    /* Quiescent test-only reset: deliberately does not imply a concurrent
     * production teardown contract for the singleton. */
    csr->initialized = false;
    csr_header_generation_bump(csr);
    csr->block_map = NULL;
    csr->chain_active = NULL;
    csr->pindex_best_hdr = NULL;
    csr->coins_tip = NULL;
    csr->ndb = NULL;
    csr->db_service = NULL;
    csr->wallet_scan_h = NULL;
}
#endif

void csr_set_db_service(struct chain_state_repository *csr,
                        struct db_service *db_service)
{
    if (!csr)
        return;
    pthread_mutex_lock(&csr->lock);
    csr->db_service = db_service;
    pthread_mutex_unlock(&csr->lock);
}

void csr_set_max_utxo_orphan_rows(struct chain_state_repository *csr,
                                   int64_t max_rows)
{
    if (!csr) return;
    pthread_mutex_lock(&csr->lock);
    csr->max_utxo_orphan_rows = max_rows;
    pthread_mutex_unlock(&csr->lock);
}

void csr_set_stale_index_gap(struct chain_state_repository *csr, int gap)
{
    if (!csr) return;
    pthread_mutex_lock(&csr->lock);
    csr->stale_index_height_gap = gap;
    pthread_mutex_unlock(&csr->lock);
}

enum csr_result csr_commit_header_tip(
    struct chain_state_repository *csr,
    const struct chain_state_header_commit *commit)
{
    if (!csr)
        return CSR_REJECTED_NULL_INPUT;
    if (!csr->initialized)
        return CSR_REJECTED_NOT_INITIALIZED;

    pthread_mutex_lock(&csr->lock);
    enum csr_result rc = csr_validate_header_locked(csr, commit);
    if (rc != CSR_OK) {
        csr->commits_rejected[rc]++;
        pthread_mutex_unlock(&csr->lock);
        LOG_WARN("csr", "csr: HEADER_REJECTED code=%s to=%d reason=%s", csr_result_name(rc), (commit && commit->new_header_tip) ? commit->new_header_tip->nHeight : -1, (commit && commit->reason) ? commit->reason : "");
        return rc;
    }

    if (csr->pindex_best_hdr) {
        *csr->pindex_best_hdr = commit->new_header_tip;
        csr_header_generation_bump(csr);
    }
    pthread_mutex_unlock(&csr->lock);

    printf("csr: header tip committed to=%d reason=%s\n",
           commit->new_header_tip->nHeight, commit->reason);
    return CSR_OK;
}

enum csr_result csr_clear_active_tip(
    struct chain_state_repository *csr,
    const struct chain_state_clear_commit *commit)
{
    if (!csr || !commit || !commit->reason)
        return CSR_REJECTED_NULL_INPUT;
    if (!csr->initialized)
        return CSR_REJECTED_NOT_INITIALIZED;
    if (!csr_rollback_authorization_valid(commit->rollback_auth))
        return CSR_REJECTED_ROLLBACK_AUTH;

    pthread_mutex_lock(&csr->lock);

    int from_height = csr->chain_active
        ? active_chain_height(csr->chain_active) : -1;
    if (csr->chain_active) {
        if (!active_chain_move_window_tip(csr->chain_active, NULL)) {
            csr->commits_rejected[CSR_REJECTED_OOM]++;
            pthread_mutex_unlock(&csr->lock);
            return CSR_REJECTED_OOM;
        }
    }

    csr->commits_ok++;
    event_emitf(EV_CHAIN_TIP_COMMIT, 0,
                "from=%d to=-1 reason=%s", from_height, commit->reason);
    pthread_mutex_unlock(&csr->lock);

    printf("csr: active tip cleared from=%d reason=%s\n",
           from_height, commit->reason);
    return CSR_OK;
}

bool csr_restore_in_memory_view(struct chain_state_repository *csr,
                                struct block_index *old_tip,
                                struct block_index *old_header,
                                const struct uint256 *old_coins_best)
{
    if (!csr || !csr->initialized)
        return false;

    pthread_mutex_lock(&csr->lock);
    bool ok = true;
    if (csr->chain_active)
        ok = active_chain_move_window_tip(csr->chain_active, old_tip);
    if (ok && csr->pindex_best_hdr) {
        *csr->pindex_best_hdr = old_header;
        csr_header_generation_bump(csr);
    }
    if (ok && csr->coins_tip && old_coins_best)
        coins_view_cache_set_best_block(csr->coins_tip, old_coins_best);
    pthread_mutex_unlock(&csr->lock);
    return ok;
}

enum csr_result csr_commit_tip(struct chain_state_repository *csr,
                                const struct chain_state_commit *commit)
{
    if (!csr) return CSR_REJECTED_NULL_INPUT;
    if (!csr->initialized) return CSR_REJECTED_NOT_INITIALIZED;

    pthread_mutex_lock(&csr->lock);

    int from_height = csr->chain_active
        ? active_chain_height(csr->chain_active) : -1;

    enum csr_result rc = csr_validate_locked(csr, commit);
    if (rc != CSR_OK) {
        csr->commits_rejected[rc]++;
        csr_emit_rejected_event(csr, from_height, commit, rc);
        pthread_mutex_unlock(&csr->lock);
        LOG_WARN("csr", "csr: REJECTED code=%s from=%d to=%d reason=%s", csr_result_name(rc), from_height, (commit && commit->new_tip) ? commit->new_tip->nHeight : -1, (commit && commit->reason) ? commit->reason : "");
        return rc;
    }

    printf("[csr] commit_tip h=%d reason=%s\n",
           commit->new_tip->nHeight, commit->reason);

    if (commit->persist_coins_best) {
        enum csr_result prc = csr_persist_coins_best_locked(csr, commit);
        if (prc != CSR_OK) {
            csr->commits_rejected[prc]++;
            csr_emit_rejected_event(csr, from_height, commit, prc);
            pthread_mutex_unlock(&csr->lock);
            LOG_WARN("csr", "csr: REJECTED code=%s from=%d to=%d reason=%s " "sqlite_rc=%d detail=%s", csr_result_name(prc), from_height, commit->new_tip ? commit->new_tip->nHeight : -1, commit->reason ? commit->reason : "", csr->last_persist_sqlite_rc, csr->last_persist_error);
            return prc;
        }
    }

    /* Publish the concrete in-memory view only after optional durable
     * cursor persistence succeeds. The remaining failure point is
     * active_chain_move_window_tip realloc/OOM, which aborts before the other
     * in-memory sources are touched. */
    if (csr->chain_active) {
        if (!active_chain_move_window_tip(csr->chain_active, commit->new_tip)) {
            csr->commits_rejected[CSR_REJECTED_OOM]++;
            csr_emit_rejected_event(csr, from_height, commit, CSR_REJECTED_OOM);
            pthread_mutex_unlock(&csr->lock);
            return CSR_REJECTED_OOM;
        }
    }
    if (csr->coins_tip) {
        coins_view_cache_set_best_block(csr->coins_tip,
                                         &commit->new_coins_best);
    }
    if (csr->pindex_best_hdr && commit->update_header_tip) {
        struct block_index *cur_hdr = *csr->pindex_best_hdr;
        /* The rollback-auth carve-out bypasses the >= ratchet on purpose:
         * an authorized restore legitimately moves the header tip DOWN.
         * The restore family is frontier-gated UPSTREAM (Invariant A in
         * utxo_recovery_commit_tip), so this carve-out cannot
         * publish an underivable height from a restore. Ordinary commits
         * keep the forward-only ratchet — pindex_best_header legitimately
         * runs AHEAD of the validated frontier during header-first sync,
         * so do NOT frontier-gate this publish. */
        if (csr_commit_has_rollback_authorization(commit) ||
            csr_internal_header_candidate_strictly_better(commit->new_tip,
                                                           cur_hdr)) {
            *csr->pindex_best_hdr = commit->new_tip;
            csr_header_generation_bump(csr);
        }
    }
    if (csr->wallet_scan_h && commit->wallet_scan_height >= 0) {
        *csr->wallet_scan_h = commit->wallet_scan_height;
    }

    csr->commits_ok++;
    csr_emit_commit_event(csr, from_height, commit);
    pthread_mutex_unlock(&csr->lock);

    printf("csr: tip committed from=%d to=%d reason=%s\n",
           from_height, commit->new_tip->nHeight, commit->reason);
    return CSR_OK;
}
