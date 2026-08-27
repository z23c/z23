// one-result-type-ok:json-dump-bool — E2 (one way out): the sole remaining
// Dump-state export: utxo_parity_dump_state_json.
// dumper. The dump convention (CLAUDE.md "Adding state introspection")
// mandates a bool return (false = couldn't populate), not struct zcl_result;
// every other fallible surface in this file already returns zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_parity_service — see services/utxo_parity_service.h for rationale.
 *
 * Layout:
 *   1. Config + global state
 *   2. Finalized-frontier marker (EV_CHAIN_TIP_COMMIT observer, monotonic)
 *   3. utxo_parity_check_height() — one honest same-height UTXO-SHA3 comparison
 *   4. parity_coarse_block_hash_tick() — coarse getblockhash check at tip
 *   5. utxo_parity_tick_once() — the supervised body (runs both checks)
 *   6. init / set_reference_source / set_rpc_config / reset / dump_state_json
 *
 * Three correctness invariants, all load-bearing:
 *
 *   SAME-HEIGHT (UTXO): the local SHA3 is computed over the LIVE utxos table,
 *   which reflects the set as of the live applied-coins height. There is no
 *   historical "as-of height" local commitment, so a byte DRIFT is only
 *   declared when an EXACT reference is at that SAME applied height
 *   (enforced in utxo_audit_compare_source). The tick therefore compares at
 *   exactly the live applied height — never a relabeled stable_ceiling, which
 *   would strcmp the live set against a reference at a DIFFERENT height and
 *   false-page — and only once that applied height is itself reorg-safe
 *   (at/below frontier - finality_depth).
 *
 *   COARSE BLOCK-HASH: fires at h_check = min(applied,frontier) -
 *   finality_depth — the reorg-safe stable ceiling. Gets our local block
 *   hash via the block index and the reference hash via getblockhash RPC on
 *   the co-located zclassicd. Match → checks_total++. Mismatch → LATCHES
 *   parity_bh_drift_detected (its OWN key — the utxo_drift_detected Condition
 *   pages on either key, but the UTXO SHA3 path's confirmations clear only
 *   THEIR key, never this latch; with the advance-only cache a mismatched
 *   height is never re-examined, so a shared key would let a later SHA3
 *   confirmation silently un-page a real divergence). Any reference
 *   transport error or height-behind-h_check → skips_total++ (NEVER pages).
 *   Once a height is checked it is never re-checked (advance-only cache).
 *
 *   FINALIZED FRONTIER: EV_CHAIN_TIP_COMMIT fires on every active-tip move,
 *   including reorgs and tip-clear ("to=-1"). It is NOT a finality signal.
 *   The frontier marker here is the MONOTONIC maximum of the durable
 *   finalized height (tip_finalize_stage_last_height) and committed,
 *   non-negative "to=" values — it never regresses, so the "dormant until
 *   the frontier advances" invariant holds even across deep reorgs.
 */

#include "services/utxo_parity_service.h"

#include "services/utxo_audit_service.h"
#include "services/utxo_reference_source.h"
#include "jobs/tip_finalize_stage.h"
#include "config/runtime.h"
#include "event/event.h"
#include "models/database.h"
#include "rpc/legacy_rpc_client.h"
#include "rpc/zclassicd_port.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "controllers/wallet_helpers.h"
#include "core/uint256.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ── Constants ─────────────────────────────────────────────────── */

#define PARITY_DEFAULT_FINALITY_DEPTH  100  /* matches ORACLE_TIP_SAFETY_MARGIN */
#define PARITY_DEFAULT_MAX_PER_TICK     1
#define PARITY_RPC_DEFAULT_HOST        "127.0.0.1"

/* ── Global state ──────────────────────────────────────────────── */

static struct {
    pthread_mutex_t lock;       /* guards config + ref pointer + ndb + rpc */
    bool   initialized;
    bool   enabled;
    int    finality_depth;
    int    max_checks_per_tick;
    struct node_db *ndb;
    const struct utxo_reference_source *ref;

    /* RPC config for the coarse block-hash check (getblockhash against the
     * co-located zclassicd). Populated by utxo_parity_set_rpc_config(). */
    struct utxo_parity_rpc_config rpc;

    /* Monotonic finalized-frontier marker (highest stable committed height). */
    _Atomic int32_t finalized_frontier;

    /* Stats (atomic — readable from the dump path without the lock). */
    _Atomic int64_t checks_total;
    _Atomic int64_t matches;
    _Atomic int64_t mismatches;
    _Atomic int64_t coarse_checks;
    _Atomic int64_t reference_errors;
    _Atomic int32_t last_checked_height;
    _Atomic int32_t last_mismatch_height;

    /* Coarse block-hash check stats (advance-only, separate from UTXO SHA3). */
    _Atomic int64_t block_hash_checks;    /* successful comparisons */
    _Atomic int64_t skips_total;          /* transport/height-behind skips */
    _Atomic int32_t last_bh_checked_height; /* last height compared (advance-only) */
    char    last_skip_reason[128];        /* last skip reason (under lock) */

    /* Test seam: override the local-block-hash lookup so unit tests do not
     * require a live block index.  NULL → use active_chain_at in prod. */
    bool (*local_hash_fn)(void *ctx, int32_t height, char out_hex[65]);
    void *local_hash_ctx;

    /* Test seam: override the reference getblockhash RPC.  NULL → real RPC. */
    bool (*ref_hash_fn)(void *ctx, int32_t height, char out_hex[65],
                        int32_t *ref_height_out,
                        char err[128]);
    void *ref_hash_ctx;
} g_parity = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .finalized_frontier = 0,
    .last_checked_height = 0,
    .last_mismatch_height = -1,
    .last_bh_checked_height = 0,
};

/* ── Finalized-frontier marker ─────────────────────────────────── */

/* Raise the monotonic frontier to `h` (ignores regressions / negatives). */
static void parity_frontier_raise(int32_t h)
{
    if (h <= 0)
        return;
    int32_t cur = atomic_load(&g_parity.finalized_frontier);
    while (h > cur) {
        if (atomic_compare_exchange_weak(&g_parity.finalized_frontier,
                                         &cur, h))
            return;
        /* cur reloaded by CAS; loop re-checks h > cur. */
    }
}

/* EV_CHAIN_TIP_COMMIT observer: parse "to=%d" and raise the frontier. The
 * raw "to=" tracks the volatile ACTIVE tip (it can regress on reorg and is
 * "-1" on a tip-clear), so we (a) ignore non-positive values and (b) only
 * ever raise the marker — finality comes from monotonicity + finality_depth,
 * cross-checked against the durable finalized height in the tick. */
static void parity_on_tip_commit(enum event_type type, uint32_t peer_id,
                                 const void *payload, uint32_t payload_len,
                                 void *ctx)
{
    (void)type; (void)peer_id; (void)payload_len; (void)ctx;
    if (!payload)
        return;
    const char *s = strstr((const char *)payload, "to=");
    if (!s)
        return;
    int to = 0;
    if (sscanf(s, "to=%d", &to) != 1)
        return;
    if (to > 0)
        parity_frontier_raise((int32_t)to);
}

void utxo_parity_observe_finalization(void)
{
    /* event_observe APPENDS unconditionally (no (type, fn) dedup) and observer
     * slots are a small fixed pool, so register exactly once per process — a
     * static guard keeps repeated boot/restart cycles from leaking slots. */
    static atomic_bool observed = false;
    bool expected = false;
    if (atomic_compare_exchange_strong(&observed, &expected, true))
        (void)event_observe(EV_CHAIN_TIP_COMMIT, parity_on_tip_commit, NULL);
}

void utxo_parity_set_frontier_for_test(int32_t height)
{
    parity_frontier_raise(height);
}

/* ── Synchronous same-height check ─────────────────────────────── */

struct zcl_result utxo_parity_check_height(int32_t height,
                                           struct utxo_audit_result *out)
{
    if (!out)
        return ZCL_ERR(-1, "utxo_parity: null out");

    pthread_mutex_lock(&g_parity.lock);
    struct node_db *ndb = g_parity.ndb ? g_parity.ndb : app_runtime_node_db();
    const struct utxo_reference_source *ref = g_parity.ref;
    pthread_mutex_unlock(&g_parity.lock);

    if (!ref) {
        memset(out, 0, sizeof(*out));
        out->status = UTXO_AUDIT_ERROR;
        snprintf(out->error, sizeof(out->error), "no reference source");
        return ZCL_ERR(-2, "utxo_parity: no reference source");
    }

    struct zcl_result r = utxo_audit_compare_source(ndb, ref, height, out);

    /* Update counters from the single comparator outcome. */
    atomic_fetch_add(&g_parity.checks_total, 1);
    atomic_store(&g_parity.last_checked_height, height);
    if (!r.ok) {
        atomic_fetch_add(&g_parity.reference_errors, 1);
    } else if (!ref->exact) {
        atomic_fetch_add(&g_parity.coarse_checks, 1);
    } else if (out->status == UTXO_AUDIT_DRIFT) {
        atomic_fetch_add(&g_parity.mismatches, 1);
        atomic_store(&g_parity.last_mismatch_height, height);
    } else if (out->status == UTXO_AUDIT_MATCH) {
        atomic_fetch_add(&g_parity.matches, 1);
    }
    /* LOCAL_ONLY (exact height-skew) is neither a match nor a mismatch:
     * it is intentionally uncounted in either bucket so a transient skew
     * during catch-up does not look like a confirmed match. */
    return r;
}

/* ── Coarse block-hash check ───────────────────────────────────── */

/* Get our local block hash at `height` via the active chain index.
 * Returns false (and leaves out_hex[0]='\0') when the index has no entry. */
static bool parity_local_hash_at(int32_t height, char out_hex[65])
{
    /* Test seam: injected by utxo_parity_set_local_hash_fn(). */
    if (g_parity.local_hash_fn)
        return g_parity.local_hash_fn(g_parity.local_hash_ctx, height, out_hex);

    /* Production: walk the active chain index. */
    struct main_state *ms = wallet_rpc_main_state();
    if (!ms) {
        out_hex[0] = '\0';
        return false;
    }
    struct block_index *bi = active_chain_at(&ms->chain_active, (int)height);
    if (!bi || !bi->phashBlock) {
        out_hex[0] = '\0';
        return false;
    }
    uint256_get_hex(bi->phashBlock, out_hex);
    return true;
}

/* Get the reference block hash at `height` via getblockhash JSON-RPC.
 * On success: fills out_hex (64 hex chars) and *ref_height_out.
 * On transport/parse failure: fills err and returns false.
 * The ref_height_out is always set to `height` on success (getblockhash
 * returns the hash OF the requested height — not a coarse current height). */
static bool parity_ref_hash_at(int32_t height,
                                const struct utxo_parity_rpc_config *rpc,
                                char out_hex[65], int32_t *ref_height_out,
                                char err[128])
{
    /* Test seam: injected by utxo_parity_set_ref_hash_fn(). */
    if (g_parity.ref_hash_fn)
        return g_parity.ref_hash_fn(g_parity.ref_hash_ctx, height,
                                    out_hex, ref_height_out, err);

    const char *host = rpc->host[0] ? rpc->host : PARITY_RPC_DEFAULT_HOST;
    int port         = rpc->port > 0 ? rpc->port : ZCLASSICD_RPC_DEFAULT_PORT;

    char body[256];
    snprintf(body, sizeof(body),
             "{\"jsonrpc\":\"1.0\",\"id\":\"zcl-parity-bh\","
             "\"method\":\"getblockhash\",\"params\":[%d]}", (int)height);

    char *resp = NULL;
    if (!legacy_rpc_call(host, port, rpc->user, rpc->password,
                         body, &resp, err, 128) || !resp) {
        if (resp) free(resp);
        return false;
    }

    /* getblockhash returns {"result":"<64-hex>", ...} */
    char parsed[65] = {0};
    bool ok = legacy_rpc_parse_result_string(resp, parsed, sizeof(parsed),
                                              err, 128);
    free(resp);
    if (!ok)
        return false;
    if (strlen(parsed) != 64) {
        snprintf(err, 128, "getblockhash result not 64 hex chars (got %zu)",
                 strlen(parsed));
        return false;
    }

    memcpy(out_hex, parsed, 65);
    *ref_height_out = height;  /* getblockhash returns the hash of `height` */
    return true;
}

/* One coarse block-hash tick. Computes h_check = min(applied,frontier) -
 * finality_depth, fetches both sides, and updates counters. Returns true
 * if a comparison was attempted (even if skipped), false when preconditions
 * were not met (service quiet). */
static void parity_coarse_block_hash_tick(
    bool rpc_enabled,
    const struct utxo_parity_rpc_config *rpc,
    int32_t frontier, int finality_depth,
    struct node_db *ndb)
{
    if (!rpc_enabled)
        return;

    /* h_check = min(applied, frontier) - finality_depth.  Uses frontier
     * directly (not applied) so the check fires even when the UTXO SHA3
     * path is stalled — "at-tip" means at the reorg-safe stable ceiling. */
    int applied = app_runtime_node_db_utxo_max_height(ndb);
    if (applied <= 0)
        return;
    int32_t safe_top = (int32_t)applied < frontier ? (int32_t)applied : frontier;
    int32_t h_check  = safe_top - (int32_t)finality_depth;
    if (h_check <= 0)
        return;

    /* Advance-only: never re-check the same height. */
    int32_t last_bh = atomic_load(&g_parity.last_bh_checked_height);
    if (h_check <= last_bh)
        return;

    /* ── Local hash ───────────────────────────────────────────── */
    char local_hex[65] = {0};
    if (!parity_local_hash_at(h_check, local_hex) || !local_hex[0]) {
        pthread_mutex_lock(&g_parity.lock);
        snprintf(g_parity.last_skip_reason, sizeof(g_parity.last_skip_reason),
                 "local block hash unavailable at h=%d", (int)h_check);
        pthread_mutex_unlock(&g_parity.lock);
        atomic_fetch_add(&g_parity.skips_total, 1);
        return;
    }

    /* ── Reference hash (getblockhash RPC) ───────────────────── */
    char ref_hex[65] = {0};
    int32_t ref_height = 0;
    char err[128] = {0};
    if (!parity_ref_hash_at(h_check, rpc, ref_hex, &ref_height, err)) {
        /* Transport/parse error: skip, NEVER page. */
        pthread_mutex_lock(&g_parity.lock);
        snprintf(g_parity.last_skip_reason, sizeof(g_parity.last_skip_reason),
                 "ref getblockhash(%d) failed: %.80s", (int)h_check, err);
        pthread_mutex_unlock(&g_parity.lock);
        atomic_fetch_add(&g_parity.skips_total, 1);
        atomic_fetch_add(&g_parity.reference_errors, 1);
        return;
    }

    /* ── Height sanity ────────────────────────────────────────── */
    if (ref_height != h_check) {
        /* Reference replied at a different height than asked — skip. */
        pthread_mutex_lock(&g_parity.lock);
        snprintf(g_parity.last_skip_reason, sizeof(g_parity.last_skip_reason),
                 "ref height %d != h_check %d", (int)ref_height, (int)h_check);
        pthread_mutex_unlock(&g_parity.lock);
        atomic_fetch_add(&g_parity.skips_total, 1);
        return;
    }

    /* ── Advance the advance-only cursor ─────────────────────── */
    int32_t cur = atomic_load(&g_parity.last_bh_checked_height);
    while (h_check > cur) {
        if (atomic_compare_exchange_weak(&g_parity.last_bh_checked_height,
                                          &cur, h_check))
            break;
    }

    /* ── Compare ─────────────────────────────────────────────── */
    bool match = (strcasecmp(local_hex, ref_hex) == 0);
    atomic_fetch_add(&g_parity.block_hash_checks, 1);
    atomic_fetch_add(&g_parity.checks_total, 1);
    atomic_store(&g_parity.last_checked_height, h_check);

    if (match) {
        atomic_fetch_add(&g_parity.matches, 1);
        /* Counters only. A block-hash match must NOT clear utxo_drift_detected
         * (that key is owned by the UTXO SHA3 path, and a hash match at
         * h_check does not refute a UTXO-set divergence at another height),
         * and nothing automatic ever clears the parity_bh latch below. */
        return;
    }

    /* Hash mismatch at a reorg-safe height: a hard contradiction with the
     * reference chain. LATCH it under the BH path's OWN key. Sharing
     * utxo_drift_detected was a missed-page defect (wave-3 review): the SHA3
     * path's confirmations write that key to 0, and the advance-only cursor
     * means this height is never re-examined — a real divergence could be
     * silently un-paged within the same tick. Nothing automatic clears the
     * latch; the operator does, after diagnosing. The utxo_drift_detected
     * Condition pages on either key. */
    atomic_fetch_add(&g_parity.mismatches, 1);
    atomic_store(&g_parity.last_mismatch_height, h_check);
    if (ndb && ndb->open) {
        (void)node_db_state_set_int(ndb, "parity_bh_drift_detected", 1);
        (void)node_db_state_set_int(ndb, "parity_bh_drift_height", h_check);
        (void)node_db_state_set(ndb, "parity_bh_drift_local_hash",
                                local_hex, strlen(local_hex));
        (void)node_db_state_set(ndb, "parity_bh_drift_ref_hash",
                                ref_hex, strlen(ref_hex));
    }

    LOG_WARN("parity",
             "[parity] BLOCK-HASH MISMATCH h=%d local=%s ref=%s",
             (int)h_check, local_hex, ref_hex);
    event_emitf(EV_UTXO_DRIFT_DETECTED, 0,
                "source=block_hash_parity h=%d local=%s ref=%s",
                (int)h_check, local_hex, ref_hex);
}

/* ── Supervised tick body ──────────────────────────────────────── */

void utxo_parity_tick_once(void)
{
    pthread_mutex_lock(&g_parity.lock);
    bool enabled = g_parity.initialized && g_parity.enabled;
    const struct utxo_reference_source *ref = g_parity.ref;
    int finality_depth = g_parity.finality_depth > 0
                             ? g_parity.finality_depth
                             : PARITY_DEFAULT_FINALITY_DEPTH;
    int max_per_tick = g_parity.max_checks_per_tick > 0
                           ? g_parity.max_checks_per_tick
                           : PARITY_DEFAULT_MAX_PER_TICK;
    struct node_db *ndb = g_parity.ndb ? g_parity.ndb : app_runtime_node_db();
    /* Snapshot RPC config under the lock so the coarse block-hash check can
     * use it without re-acquiring the lock. */
    struct utxo_parity_rpc_config rpc = g_parity.rpc;
    bool rpc_has_creds = rpc.user[0] || g_parity.ref_hash_fn;
    pthread_mutex_unlock(&g_parity.lock);

    /* Activation: `enabled` is the master gate. Either the coarse block-hash
     * check (rpc_has_creds) or the UTXO SHA3 check (wired reference) must be
     * ready; otherwise the tick is a quiet no-op. Boot turns `enabled` on only
     * when a co-located zclassicd oracle resolves — an operator with no zclassicd
     * sees neither check arm and no health impact. */
    if (!enabled)
        return;
    if (!ref && !rpc_has_creds)
        return; /* truly dormant — nothing to check */

    /* Cross-check the volatile EV_CHAIN_TIP_COMMIT marker against the durable
     * finalized height; take the max so neither a missed event nor a reorg
     * regresses the frontier. */
    int64_t durable = tip_finalize_stage_last_height();
    if (durable > 0)
        parity_frontier_raise((int32_t)durable);
    int32_t frontier = atomic_load(&g_parity.finalized_frontier);
    if (frontier <= 0)
        return; /* tip not advancing — genuinely dormant */

    /* ── Coarse block-hash check (fires at tip, advance-only) ─────
     * Runs before the UTXO SHA3 check because it is cheap (one RPC call,
     * no local SHA3 recompute) and fires even when applied > stable_ceiling
     * (i.e. exactly when the UTXO check is stalled). Does NOT require a
     * SHA3 reference — block-hash check is independent of the SHA3 path. */
    if (rpc_has_creds)
        parity_coarse_block_hash_tick(enabled, &rpc, frontier,
                                      finality_depth, ndb);

    /* ── UTXO SHA3 check (exact, only when applied is reorg-safe) ─
     * Requires a wired reference source; skip entirely if none. */
    if (!ref)
        return;

    /* Stability gate: only compare at a height that is provably below the
     * frontier by finality_depth (cannot reorg) AND that the live applied
     * set actually reflects. */
    int32_t stable_ceiling = frontier - (int32_t)finality_depth;
    if (stable_ceiling <= 0)
        return;

    int applied = app_runtime_node_db_utxo_max_height(ndb);
    if (applied <= 0)
        return;

    /* The local SHA3 is computed over the LIVE utxos table, so the only height
     * it honestly reflects is `applied`. Compare at exactly that height (never
     * a relabeled stable_ceiling — that would strcmp the live set against a
     * reference at a DIFFERENT height and false-page). Only do so once
     * `applied` is itself reorg-safe (at/below frontier - finality_depth);
     * while the live tip races ahead of finality there is no reorg-safe height
     * whose set the live table reflects, so we wait. */
    if ((int32_t)applied > stable_ceiling)
        return;
    int32_t target = (int32_t)applied;
    if (target <= atomic_load(&g_parity.last_checked_height))
        return; /* already current — nothing new to compare */

    /* Walk forward, bounded, so we never burst the full-set SHA3. */
    for (int i = 0; i < max_per_tick && target > 0; i++) {
        struct utxo_audit_result res;
        (void)utxo_parity_check_height(target, &res);
        /* check_height advances last_checked_height; one stable target per
         * tick is the common case (the frontier advances slowly). */
        break;
    }
}

/* ── init / wiring ─────────────────────────────────────────────── */

struct zcl_result utxo_parity_init(const struct utxo_parity_config *cfg,
                                   struct node_db *ndb)
{
    pthread_mutex_lock(&g_parity.lock);
    g_parity.enabled = cfg ? cfg->enabled : false;
    g_parity.finality_depth = (cfg && cfg->finality_depth > 0)
                                  ? cfg->finality_depth
                                  : PARITY_DEFAULT_FINALITY_DEPTH;
    g_parity.max_checks_per_tick = (cfg && cfg->max_checks_per_tick > 0)
                                       ? cfg->max_checks_per_tick
                                       : PARITY_DEFAULT_MAX_PER_TICK;
    g_parity.ndb = ndb;
    /* Copy RPC config when provided (coarse block-hash check transport). */
    if (cfg)
        g_parity.rpc = cfg->rpc;
    g_parity.initialized = true;
    pthread_mutex_unlock(&g_parity.lock);
    return ZCL_OK;
}

void utxo_parity_set_rpc_config(const struct utxo_parity_rpc_config *rpc)
{
    if (!rpc)
        return;
    pthread_mutex_lock(&g_parity.lock);
    g_parity.rpc = *rpc;
    pthread_mutex_unlock(&g_parity.lock);
}

void utxo_parity_set_reference_source(const struct utxo_reference_source *src)
{
    pthread_mutex_lock(&g_parity.lock);
    g_parity.ref = src;
    pthread_mutex_unlock(&g_parity.lock);
}

/* Test seam: inject a local-block-hash resolver so unit tests do not require
 * a live block index. Pass NULL to restore the production path (active_chain_at). */
void utxo_parity_set_local_hash_fn(
    bool (*fn)(void *ctx, int32_t height, char out_hex[65]), void *ctx)
{
    pthread_mutex_lock(&g_parity.lock);
    g_parity.local_hash_fn = fn;
    g_parity.local_hash_ctx = ctx;
    pthread_mutex_unlock(&g_parity.lock);
}

/* Test seam: inject a reference-getblockhash resolver so unit tests do not
 * open real sockets. Pass NULL to restore the production RPC path. */
void utxo_parity_set_ref_hash_fn(
    bool (*fn)(void *ctx, int32_t height, char out_hex[65],
               int32_t *ref_height_out, char err[128]),
    void *ctx)
{
    pthread_mutex_lock(&g_parity.lock);
    g_parity.ref_hash_fn = fn;
    g_parity.ref_hash_ctx = ctx;
    pthread_mutex_unlock(&g_parity.lock);
}

void utxo_parity_reset_for_test(void)
{
    pthread_mutex_lock(&g_parity.lock);
    g_parity.initialized = false;
    g_parity.enabled = false;
    g_parity.finality_depth = 0;
    g_parity.max_checks_per_tick = 0;
    g_parity.ndb = NULL;
    g_parity.ref = NULL;
    memset(&g_parity.rpc, 0, sizeof(g_parity.rpc));
    g_parity.local_hash_fn = NULL;
    g_parity.local_hash_ctx = NULL;
    g_parity.ref_hash_fn = NULL;
    g_parity.ref_hash_ctx = NULL;
    g_parity.last_skip_reason[0] = '\0';
    pthread_mutex_unlock(&g_parity.lock);
    atomic_store(&g_parity.finalized_frontier, 0);
    atomic_store(&g_parity.checks_total, 0);
    atomic_store(&g_parity.matches, 0);
    atomic_store(&g_parity.mismatches, 0);
    atomic_store(&g_parity.coarse_checks, 0);
    atomic_store(&g_parity.reference_errors, 0);
    atomic_store(&g_parity.last_checked_height, 0);
    atomic_store(&g_parity.last_mismatch_height, -1);
    atomic_store(&g_parity.block_hash_checks, 0);
    atomic_store(&g_parity.skips_total, 0);
    atomic_store(&g_parity.last_bh_checked_height, 0);
}

/* ── State dump (see CLAUDE.md "Adding state introspection") ───── */

bool utxo_parity_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    pthread_mutex_lock(&g_parity.lock);
    bool enabled = g_parity.enabled;
    int finality_depth = g_parity.finality_depth;
    const struct utxo_reference_source *ref = g_parity.ref;
    const char *ref_name = ref && ref->name ? ref->name : "none";
    bool ref_exact = ref ? ref->exact : false;
    struct node_db *ndb = g_parity.ndb;
    char skip_reason[128];
    snprintf(skip_reason, sizeof(skip_reason), "%s", g_parity.last_skip_reason);
    pthread_mutex_unlock(&g_parity.lock);

    bool drift_flag = false;
    bool bh_drift_latched = false;
    if (ndb && ndb->open) {
        int64_t drift = 0;
        if (node_db_state_get_int(ndb, "utxo_drift_detected", &drift))
            drift_flag = (drift != 0);
        int64_t bh = 0;
        if (node_db_state_get_int(ndb, "parity_bh_drift_detected", &bh))
            bh_drift_latched = (bh != 0);
        /* drift_flag is the "is anything paging" summary — OR in the latch so
         * this dump never reads false while the Condition is paging. */
        drift_flag = drift_flag || bh_drift_latched;
    }

    json_push_kv_bool(out, "enabled", enabled);
    /* `active` is the real run predicate the tick checks: enabled AND a wired
     * reference. With no co-located zclassicd, boot leaves both off and this is
     * false (the service is quietly dormant — no health impact, no log spam). */
    json_push_kv_bool(out, "active", enabled && ref != NULL);
    json_push_kv_str (out, "reference_source", ref_name);
    json_push_kv_bool(out, "reference_exact", ref_exact);
    json_push_kv_int (out, "finality_depth", finality_depth);
    json_push_kv_int (out, "finalized_frontier",
                      atomic_load(&g_parity.finalized_frontier));
    json_push_kv_int (out, "last_checked_height",
                      atomic_load(&g_parity.last_checked_height));
    json_push_kv_int (out, "checks_total",
                      atomic_load(&g_parity.checks_total));
    json_push_kv_int (out, "matches", atomic_load(&g_parity.matches));
    json_push_kv_int (out, "mismatches", atomic_load(&g_parity.mismatches));
    json_push_kv_int (out, "coarse_checks",
                      atomic_load(&g_parity.coarse_checks));
    json_push_kv_int (out, "reference_errors",
                      atomic_load(&g_parity.reference_errors));
    json_push_kv_int (out, "last_mismatch_height",
                      atomic_load(&g_parity.last_mismatch_height));
    /* Block-hash parity counters (the at-tip coarse check). */
    json_push_kv_int (out, "block_hash_checks",
                      atomic_load(&g_parity.block_hash_checks));
    json_push_kv_int (out, "skips_total",
                      atomic_load(&g_parity.skips_total));
    json_push_kv_int (out, "last_bh_checked_height",
                      atomic_load(&g_parity.last_bh_checked_height));
    if (skip_reason[0])
        json_push_kv_str(out, "last_skip_reason", skip_reason);
    json_push_kv_bool(out, "drift_flag", drift_flag);
    json_push_kv_bool(out, "bh_drift_latched", bh_drift_latched);

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * app/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed drift_flag above (the file's own "is
     * anything paging" summary, comment a few lines up) — no new health
     * logic. */
    {
        char reason_buf[160] = "";
        if (drift_flag) {
            snprintf(reason_buf, sizeof(reason_buf),
                     "utxo drift detected (bh_drift_latched=%s, "
                     "mismatches=%lld, last_mismatch_height=%lld)",
                     bh_drift_latched ? "true" : "false",
                     (long long)atomic_load(&g_parity.mismatches),
                     (long long)atomic_load(&g_parity.last_mismatch_height));
        }
        diag_push_health(out, !drift_flag, reason_buf);
    }
    return true;
}
