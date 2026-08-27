/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_mirror_sync_service — implementation. See header for design rationale.
 *
 * SAFETY BOUNDARY (load-bearing): this service writes ONLY node.db's `utxos`
 * mirror + the derived wallet/address caches + a node.db cursor key. It READS
 * the coins_kv set on the progress.kv handle (under progress_store_tx_lock)
 * but NEVER writes it and never participates in a coins_kv transaction. A
 * failure here is logged loudly and leaves the cursor unadvanced (the pass
 * re-runs) — it can never roll back or fail anything on the consensus path.
 */

#include "platform/time_compat.h"
#include "services/utxo_mirror_sync_service.h"
#include "services/utxo_mirror_delta.h"

#include "coins/utxo_commitment.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "models/database.h"
#include "models/utxo.h"
#include "jobs/refold_progress.h"
#include "script/script.h"
#include "script/standard.h"
#include "services/chain_state_service.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Global instance pointer ───────────────────────────────── */

/* Per-pass height cap for the incremental delta apply: bounds the write-lock
 * hold so a large post-outage gap catches up over a few passes instead of one
 * multi-second transaction. A normal at-tip pass moves 1–2 heights and writes a
 * handful of rows. */
#define UTXO_MIRROR_DELTA_MAX_HEIGHTS_PER_PASS 2000

struct utxo_mirror_sync_service *g_utxo_mirror_sync = NULL;

static struct liveness_contract g_mirror_contract;
static _Atomic supervisor_child_id g_mirror_supervisor_id =
    SUPERVISOR_INVALID_ID;

/* ── Supervisor wiring (mode B: own thread + heartbeat) ────── */

static int64_t mirror_progress_marker(
    const struct utxo_mirror_sync_service *svc)
{
    /* Monotone: the mirror height only ever climbs forward in normal
     * operation; the supervisor uses this as the liveness "is it moving"
     * signal. rebuilds_run is added so a no-drift steady state (height
     * unchanged) still ticks the marker via the heartbeat's supervisor_tick. */
    return svc ? atomic_load(&svc->last_mirror_height) : 0;
}

static int64_t mirror_deadline_secs(const struct utxo_mirror_sync_service *svc)
{
    int tick = svc && svc->tick_seconds > 0
        ? svc->tick_seconds
        : UTXO_MIRROR_SYNC_DEFAULT_TICK_SECONDS;
    /* A wholesale rebuild of ~1.3M rows can take a few seconds; allow ample
     * slack so a long rebuild pass never trips a false stall. */
    return (int64_t)tick * 4 + 120;
}

static void mirror_supervisor_heartbeat(struct utxo_mirror_sync_service *svc)
{
    supervisor_child_id id = atomic_load(&g_mirror_supervisor_id);
    if (id == SUPERVISOR_INVALID_ID) return;
    supervisor_progress(id, mirror_progress_marker(svc));
    supervisor_tick(id);
}

static void mirror_on_stall(struct liveness_contract *c)
{
    struct utxo_mirror_sync_service *svc =
        c ? (struct utxo_mirror_sync_service *)c->ctx : NULL;
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    LOG_WARN("utxo_mirror",
             "[utxo_mirror] supervisor stall reason=%s mirror_height=%lld "
             "frontier=%lld rebuilds=%lld",
             reason,
             (long long)(svc ? atomic_load(&svc->last_mirror_height) : 0),
             (long long)(svc ? atomic_load(&svc->last_frontier) : 0),
             (long long)(svc ? atomic_load(&svc->rebuilds_run) : 0));
}

static struct zcl_result mirror_register_supervisor(
    struct utxo_mirror_sync_service *svc)
{
    if (!svc)
        return ZCL_ERR(-1, "utxo_mirror: supervisor register: null svc");
    if (!supervisor_start())
        return ZCL_ERR(-2, "utxo_mirror: supervisor_start failed");

    supervisor_child_id id = atomic_load(&g_mirror_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        g_mirror_contract.ctx = svc;
        supervisor_set_period(id, 0);
        supervisor_set_deadline(id, mirror_deadline_secs(svc));
        supervisor_set_progress_max_quiet(id, 0);
        mirror_supervisor_heartbeat(svc);
        return ZCL_OK;
    }

    liveness_contract_init(&g_mirror_contract, "chain.utxo_mirror_sync");
    atomic_store(&g_mirror_contract.period_secs, 0);
    atomic_store(&g_mirror_contract.deadline_secs, mirror_deadline_secs(svc));
    atomic_store(&g_mirror_contract.progress_max_quiet_us, 0);
    g_mirror_contract.ctx = svc;
    g_mirror_contract.on_tick = NULL;
    g_mirror_contract.on_stall = mirror_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_chain_sup, &g_mirror_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-3, "utxo_mirror: supervisor_register failed");
    atomic_store(&g_mirror_supervisor_id, id);
    mirror_supervisor_heartbeat(svc);
    return ZCL_OK;
}

/* ── Drift detection ───────────────────────────────────────── */

/* Read the coins_kv applied frontier + live count from progress.kv. Returns
 * false (frontier unknown) when the store is not open or the frontier is
 * ABSENT (fresh / un-synced datadir) — in which case there is nothing
 * authoritative to mirror and the pass no-ops. */
static bool read_coins_kv_state(int32_t *frontier_out, int64_t *count_out)
{
    sqlite3 *pdb = progress_store_db();
    if (!pdb)
        return false;

    /* The frontier is a single progress_meta key lookup — trivially fast, so
     * it is safe under the shared progress_store_tx_lock. */
    bool found = false;
    int32_t fr = -1;
    progress_store_tx_lock();
    bool got = coins_kv_get_applied_height(pdb, &fr, &found) && found;
    progress_store_tx_unlock();
    if (!got)
        return false;
    *frontier_out = fr;

    /* Never count the live table here. A cursor-equal steady-state pass must be
     * O(1); bounded auditors detect corruption independently. */
    *count_out = -1;
    return true;
}

static struct db_service *mirror_db_service_for(struct node_db *ndb)
{
    struct db_service *dbsvc = app_runtime_db_service();

    if (!ndb || !dbsvc || !db_service_is_started(dbsvc))
        return NULL;
    return db_service_node_db(dbsvc) == ndb ? dbsvc : NULL;
}

static bool mirror_run_db_lane(struct node_db *ndb,
                               db_service_write_fn fn,
                               void *ctx)
{
    struct db_service *dbsvc = mirror_db_service_for(ndb);

    if (!ndb || !fn)
        return false;
    if (dbsvc)
        return db_service_run_write(dbsvc, fn, ctx);
    return fn(ndb, ctx);
}

struct mirror_node_state_ctx {
    int64_t cursor;
    bool mirror_has_rows;
    bool ok;
};

static bool mirror_read_node_state_lane(struct node_db *ndb, void *ctx)
{
    struct mirror_node_state_ctx *s = ctx;

    if (!ndb || !ndb->open || !s)
        return false;
    s->cursor = 0;
    (void)node_db_state_get_int(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &s->cursor);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT EXISTS(SELECT 1 FROM utxos LIMIT 1)",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_mirror", "node state probe prepare failed: %s",
                 sqlite3_errmsg(ndb->db));
        return false;
    }
    if (sqlite3_step(st) != SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        LOG_WARN("utxo_mirror", "node state probe step failed: %s",
                 sqlite3_errmsg(ndb->db));
        sqlite3_finalize(st);
        return false;
    }
    s->mirror_has_rows = sqlite3_column_int(st, 0) != 0;
    sqlite3_finalize(st);
    s->ok = true;
    return true;
}

/* ── Wholesale rebuild: coins_kv → node.db utxos ───────────── */

/* Copy every live coins_kv row into the mirror under ONE node.db txn.
 * Returns the number of rows written, or -1 on a (logged) error. The whole
 * write is atomic: on failure node.db rolls back and the cursor stays put.
 * `frontier` is the coins_kv applied height this scan is asserted consistent
 * through (the caller sets its own applied_through to the same value on
 * success) — used to height-stamp the XOR checkpoint this rebuild also
 * recomputes from scratch, so utxo_mirror_delta_apply can incrementally
 * maintain it from here on instead of the boot-time O(n) refresh doing it. */
static int64_t mirror_rebuild_from_coins_kv(struct node_db *ndb, int32_t frontier)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(-1, "utxo_mirror", "rebuild: node.db unavailable");

    /* Read coins_kv through our OWN read-only connection to progress.kv — NOT
     * the shared progress_store_db() handle under progress_store_tx_lock. A
     * ~1.3M-row scan holding that lock for seconds would STALL the consensus
     * reducer drive (it holds the same lock for every block-apply txn). WAL
     * mode lets this independent reader see the last committed snapshot while
     * the reducer keeps writing. We never WRITE coins_kv — the consensus
     * commit boundary is untouched. progress_store remains the sole WRITER. */
    char pkv_path[PROGRESS_STORE_PATH_MAX];
    if (!progress_store_path(pkv_path, sizeof(pkv_path)))
        LOG_RETURN(-1, "utxo_mirror", "rebuild: progress store path unavailable");

    sqlite3 *rdb = NULL;
    if (sqlite3_open_v2(pkv_path, &rdb, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (rdb) sqlite3_close(rdb);
        LOG_RETURN(-1, "utxo_mirror", "rebuild: open ro progress.kv failed: %s",
                   pkv_path);
    }
    sqlite3_busy_timeout(rdb, 5000);

    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(rdb,
            "SELECT txid, vout, value, height, is_coinbase, script "
            "FROM coins ORDER BY txid, vout",
            -1, &sel, NULL) != SQLITE_OK) {
        const char *emsg = sqlite3_errmsg(rdb);
        char msg[256];
        snprintf(msg, sizeof(msg), "%s", emsg ? emsg : "(no message)");
        sqlite3_close(rdb);
        LOG_RETURN(-1, "utxo_mirror", "rebuild: coins SELECT prepare failed: %s",
                   msg);
    }

    /* Plain transaction — NO ibd_turbo_mode here: turbo DROPS the utxos
     * secondary indexes (idx_utxo_address/value/height) the explorer relies
     * on, and rebuilding them every pass would be both wrong (a window with no
     * address index) and expensive. INSERT OR REPLACE over the live indexes is
     * correct; the one bulk first-run is well within the supervisor deadline. */
    if (!node_db_begin(ndb)) {
        sqlite3_finalize(sel);
        sqlite3_close(rdb);
        LOG_RETURN(-1, "utxo_mirror", "rebuild: node.db BEGIN failed");
    }

    bool ok = node_db_exec(ndb, "DELETE FROM utxos");
    int64_t written = 0;
    struct utxo_commitment uc;
    utxo_commitment_init(&uc);

    while (ok) {
        int rc = sqlite3_step(sel);  // raw-sql-ok:progress-kv-kernel-store
        if (rc == SQLITE_DONE)
            break;
        if (rc != SQLITE_ROW) {
            LOG_WARN("utxo_mirror", "rebuild: coins SELECT step failed rc=%d: %s",
                     rc, sqlite3_errmsg(rdb));
            ok = false;
            break;
        }

        struct db_utxo u;
        memset(&u, 0, sizeof(u));
        const void *txid_blob = sqlite3_column_blob(sel, 0);
        int txid_len = sqlite3_column_bytes(sel, 0);
        if (!txid_blob || txid_len != 32) {
            LOG_WARN("utxo_mirror", "rebuild: malformed txid (len=%d) — skipping row",
                     txid_len);
            continue;   /* a single bad row never aborts the mirror rebuild */
        }
        memcpy(u.txid, txid_blob, 32);
        u.vout        = (uint32_t)sqlite3_column_int(sel, 1);
        u.value       = sqlite3_column_int64(sel, 2);
        int h         = sqlite3_column_int(sel, 3);
        u.height      = h < 0 ? 0 : h;     /* utxos schema CHECK(height >= 0) */
        u.is_coinbase = sqlite3_column_int(sel, 4) != 0;

        const void *sblob = sqlite3_column_blob(sel, 5);
        int slen = sqlite3_column_bytes(sel, 5);
        if (slen < 0) slen = 0;
        if (slen > MAX_SCRIPT_SIZE) {
            /* A UTXO scriptPubKey is <= MAX_SCRIPT_SIZE by consensus; a longer
             * blob is a corrupt source row. Skip it loudly rather than write a
             * malformed mirror entry. */
            LOG_WARN("utxo_mirror", "rebuild: oversize script (len=%d) — skipping row",
                     slen);
            continue;
        }
        /* db_utxo_insert_raw binds u.script with u.script_len; alias the
         * SQLite buffer for the bind (valid until the next step). */
        u.script     = (uint8_t *)sblob;
        u.script_len = (size_t)slen;

        /* Derive the explorer's address columns from the scriptPubKey using
         * the single shared classifier — never hand-roll script parsing. */
        u.script_type = utxo_classify_script(u.script, u.script_len,
                                             u.address_hash, &u.has_address);

        if (!db_utxo_insert_raw(ndb, &u)) {
            LOG_WARN("utxo_mirror",
                     "rebuild: db_utxo_insert_raw failed at vout=%u (height=%d "
                     "value=%lld script_len=%zu script_type=%d has_address=%d): %s",
                     u.vout, (int)u.height, (long long)u.value, u.script_len,
                     (int)u.script_type, (int)u.has_address,
                     sqlite3_errmsg(ndb->db));
            ok = false;
            break;
        }
        /* u.height is already the CHECK(height >= 0)-clamped value actually
         * persisted — feed the identical bytes utxo_commitment_compute_db
         * would read back from this same row, so a future O(n) verification
         * against this stamp matches exactly. */
        utxo_commitment_add(&uc, u.txid, u.vout, u.value, (int32_t)u.height);
        written++;
    }

    sqlite3_finalize(sel);
    sqlite3_close(rdb);

    if (!ok) {
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror", "rebuild: node.db ROLLBACK failed after error");
        LOG_RETURN(-1, "utxo_mirror", "rebuild: aborted after %lld rows",
                   (long long)written);
    }

    /* Height-stamp the freshly rebuilt checkpoint in the SAME transaction —
     * this scan just recomputed it from scratch, so `frontier` (the coins_kv
     * height the caller asserts this pass reflects) is an exact covering
     * height, letting utxo_mirror_delta_apply take over incrementally from
     * here instead of the boot-time refresh redoing this O(n) work. */
    if (!utxo_commitment_save_checkpoint_at_height(ndb->db, &uc, frontier)) {
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror",
                     "rebuild: node.db ROLLBACK failed after commitment error");
        LOG_RETURN(-1, "utxo_mirror",
                   "rebuild: commitment checkpoint save failed at frontier=%d",
                   frontier);
    }

    if (!db_utxo_rebuild_wallet_and_address_caches_in_txn(ndb)) {
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror",
                     "rebuild: node.db ROLLBACK failed after cache error");
        LOG_RETURN(-1, "utxo_mirror",
                   "rebuild: wallet/address cache refresh failed");
    }

    int64_t next_cursor = frontier;
    if (!node_db_state_set(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY,
                           &next_cursor, sizeof(next_cursor))) {
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror",
                     "rebuild: node.db ROLLBACK failed after cursor error");
        LOG_RETURN(-1, "utxo_mirror",
                   "rebuild: cursor persist failed at frontier=%d", frontier);
    }

    if (!node_db_commit(ndb)) {
        if (!node_db_rollback(ndb))
            LOG_WARN("utxo_mirror", "rebuild: node.db ROLLBACK failed after commit fail");
        LOG_RETURN(-1, "utxo_mirror", "rebuild: node.db COMMIT failed");
    }

    return written;
}

struct mirror_rebuild_ctx {
    struct utxo_mirror_sync_service *svc;
    int32_t cursor;          /* current mirror cursor (in) */
    int32_t frontier;        /* coins_kv applied frontier (in) */
    bool mirror_has_rows;    /* O(1) existence probe, not a full count */
    int32_t applied_through; /* height the mirror is consistent through (out) */
    int64_t written;         /* rows changed / written (out) */
    bool cursor_persisted;
    bool used_delta;         /* diagnostics: delta vs wholesale rebuild */
};

static bool mirror_rebuild_and_advance_lane(struct node_db *ndb, void *ctx)
{
    struct mirror_rebuild_ctx *r = ctx;

    if (!ndb || !ndb->open || !r || !r->svc)
        return false;

    app_runtime_node_db_sync_flush_if_needed(ndb);

    /* Incremental delta when the mirror lags the frontier (steady state).
     * Initial/empty construction is the only automatic wholesale path. */
    if (r->cursor > 0 && r->mirror_has_rows && r->frontier > r->cursor) {
        int32_t applied_through = r->cursor;
        int64_t rows = 0;
        int rc = utxo_mirror_delta_apply(ndb, r->cursor, r->frontier,
                                         UTXO_MIRROR_DELTA_MAX_HEIGHTS_PER_PASS,
                                         UTXO_MIRROR_SYNC_CURSOR_KEY,
                                         &applied_through, &rows);
        if (rc == UTXO_MIRROR_DELTA_OK) {
            r->used_delta = true;
            r->written = rows;
            r->applied_through = applied_through;
            r->cursor_persisted = true;
            return true;
        }
        if (rc == UTXO_MIRROR_DELTA_ERROR)
            return false;  /* logged in utxo_mirror_delta_apply; pass re-runs */
        /* Missing causal history is not permission for an automatic million-
         * row rebuild. Quarantine once; an explicit audit/recovery action can
         * later reconstruct the derived mirror. */
        atomic_store(&r->svc->mirror_health, UTXO_MIRROR_QUARANTINED);
        atomic_fetch_add(&r->svc->quarantines_total, 1);
        atomic_store(&r->svc->last_quarantine_unix,
                     platform_time_wall_unix());
        LOG_WARN("utxo_mirror",
                 "mirror quarantined: causal delta/checkpoint missing in "
                 "[%d,%d); automatic wholesale rebuild refused",
                 r->cursor, r->frontier);
        return false;
    }

    atomic_store(&r->svc->mirror_health, UTXO_MIRROR_AUDITING);
    r->written = mirror_rebuild_from_coins_kv(ndb, r->frontier);
    if (r->written < 0) {
        atomic_store(&r->svc->mirror_health, UTXO_MIRROR_QUARANTINED);
        atomic_fetch_add(&r->svc->quarantines_total, 1);
        atomic_store(&r->svc->last_quarantine_unix,
                     platform_time_wall_unix());
        return false;
    }
    r->applied_through = r->frontier;
    r->cursor_persisted = true;
    atomic_store(&r->svc->mirror_health, UTXO_MIRROR_HEALTHY);
    return true;
}

/* ── One sync pass ─────────────────────────────────────────── */

int64_t utxo_mirror_sync_run_once(struct utxo_mirror_sync_service *svc)
{
    if (!svc || !svc->ndb || !svc->ndb->open)
        LOG_RETURN(-1, "utxo_mirror", "run_once: node.db unavailable");
    if (atomic_load(&svc->mirror_health) == UTXO_MIRROR_QUARANTINED)
        return 0;

    /* During a from-genesis refold the coins_kv frontier climbs every pass, so
     * drift is true on every tick and this would DELETE+reinsert the ENTIRE
     * mirror (O(total_coins)) every 5s — quadratic against fold progress. The
     * mirror is a node.db read model (explorer/wallet), not consensus; skip it
     * while refolding and let the first post-refold pass rebuild it once.
     * See docs/work/refold-fold-rate-bottlenecks.md (#3). */
    if (refold_in_progress())
        return 0;

    int32_t frontier = -1;
    int64_t coins_count = -1;
    if (!read_coins_kv_state(&frontier, &coins_count)) {
        /* No authoritative frontier yet (store closed / fresh datadir). Nothing
         * to mirror — not an error. */
        return 0;
    }
    atomic_store(&svc->last_frontier, (int64_t)frontier);

    /* Defer the wholesale rebuild while still catching up. During IBD / P2P
     * body fetch the coins_kv frontier climbs every tick, so drift is true on
     * every 5s pass and this would DELETE+reinsert the ENTIRE ~1.3M-row mirror
     * each time (quadratic against fold progress) — the same storm the refold
     * guard above suppresses, but for non-refold catch-up. The mirror is a
     * node.db read model (explorer/wallet/RPC) that nothing consumes mid-sync;
     * the first within-N-of-tip pass rebuilds it once, and the count-mismatch
     * self-heal below still runs near tip. Fail-open: header tip unknown (-1)
     * leaves the original every-tick behavior. See
     * docs/work/refold-fold-rate-bottlenecks.md (#3).
     *
     * header_tip MUST come from the in-process chain_state_repository
     * (csr_header_height), not chain_projection_best_header_height(): that
     * helper is native-CLIENT-layer — it requires node_rpc_client_datadir(),
     * which is never set inside the node process, so from here it always
     * failed with "native datadir is unset" (11k-16k log lines/day) AND
     * silently returned -1, which defeated BOTH guards above on every tick
     * (both require header_tip > 0) and reproduced exactly the rebuild
     * storm they exist to prevent. */
    int64_t header_tip = csr_header_height(csr_instance());
    if (header_tip > 0 &&
        (int64_t)frontier + UTXO_MIRROR_SYNC_NEAR_TIP_BLOCKS < header_tip) {
        atomic_store(&svc->last_pass_unix, platform_time_wall_unix());
        return 0;
    }
    /* Symmetric guard: also defer when the header chain is BEHIND the coins
     * frontier. A snapshot-bundle seed jumps coins_kv to seed_h while P2P
     * headers are still climbing from genesis, so the header projection reports
     * a tip far BELOW the frontier; the near-tip check above (frontier+N <
     * header_tip) is then false on the bogus-low tip and the wholesale
     * ~1.3M-row rebuild would fire AT THE SEED — far from any real tip and
     * concurrent with the fold — the observed blocks-less crash window. "Near
     * tip" requires the headers to have actually reached the coins frontier,
     * not the reverse. The first pass once headers catch up (header_tip >=
     * frontier) rebuilds it once, near the real tip.
     *
     * frontier is the utxo_apply CURSOR (coins_applied_height), i.e. the NEXT
     * height to apply = last applied + 1 (utxo_apply_stage.c co-commits
     * cursor_in + 1), so compare header_tip against frontier - 1. The raw
     * cursor defers forever at steady state (frontier == tip + 1 > header_tip
     * == tip on every tick): the mirror never completes and every downstream
     * read model (coins view → wallet_verify_utxos prune → vault spendable →
     * the overlay-intent fee reserve) starves on an otherwise healthy node. */
    if (header_tip > 0 && (int64_t)frontier - 1 > header_tip) {
        atomic_store(&svc->last_pass_unix, platform_time_wall_unix());
        return 0;
    }

    struct mirror_node_state_ctx state = {0};
    if (!mirror_run_db_lane(svc->ndb, mirror_read_node_state_lane, &state) ||
        !state.ok) {
        atomic_store(&svc->last_error_unix, platform_time_wall_unix());
        LOG_RETURN(-1, "utxo_mirror", "run_once: node.db state read failed");
    }

    if (state.cursor > (int64_t)frontier) {
        /* Both markers are next-height cursors. This is therefore an
         * authority rewind (normally a reorg), not a harmless one-height
         * representation difference. The forward delta journal has already
         * discarded the losing branch at this point, so decrementing the
         * mirror marker would bless stale rows. Keep the projection frozen
         * until an owner-gated rebuild from a point-in-time authority copy is
         * available. */
        atomic_store(&svc->mirror_health, UTXO_MIRROR_QUARANTINED);
        atomic_fetch_add(&svc->quarantines_total, 1);
        atomic_store(&svc->last_quarantine_unix,
                     platform_time_wall_unix());
        LOG_RETURN(-1, "utxo_mirror",
                   "run_once: mirror cursor=%lld is ahead of next-height "
                   "authority frontier=%d after an authority rewind; mirror "
                   "quarantined (cursor was not decremented)",
                   (long long)state.cursor, frontier);
    }

    /* Cursor equality is the constant-time steady state. Integrity auditing is
     * bounded and independent; this loop never counts either million-row
     * table merely to rediscover that nothing advanced. */
    bool drift = state.cursor != (int64_t)frontier;
    if (!drift) {
        atomic_store(&svc->last_mirror_height, state.cursor);
        atomic_store(&svc->last_pass_unix, platform_time_wall_unix());
        return 0;
    }

    LOG_INFO("utxo_mirror",
             "[utxo_mirror] drift: cursor=%lld -> frontier=%d; "
             "applying causal delta",
             (long long)state.cursor, frontier);

    struct mirror_rebuild_ctx rebuild = {
        .svc = svc,
        .cursor = (int32_t)state.cursor,
        .frontier = frontier,
        .mirror_has_rows = state.mirror_has_rows,
        .applied_through = (int32_t)state.cursor,
        .written = -1,
        .cursor_persisted = false,
        .used_delta = false,
    };
    /* Bracket the complete node.db write lane. The generation changes at both
     * edges so an auditor spanning even a fast rebuild detects the overlap;
     * updates_active covers a sample taken while the transaction is open. */
    atomic_fetch_add(&svc->updates_active, 1u);
    atomic_fetch_add(&svc->update_generation, 1u);
    bool lane_ok = mirror_run_db_lane(svc->ndb,
                                      mirror_rebuild_and_advance_lane,
                                      &rebuild);
    atomic_fetch_add(&svc->update_generation, 1u);
    atomic_fetch_sub(&svc->updates_active, 1u);
    if (!lane_ok || rebuild.written < 0) {
        atomic_store(&svc->last_error_unix, platform_time_wall_unix());
        return -1;  // raw-return-ok:logged-in-mirror_rebuild_from_coins_kv
    }

    if (rebuild.used_delta) {
        atomic_fetch_add(&svc->delta_passes_run, 1);
        atomic_fetch_add(&svc->delta_rows_changed, rebuild.written);
    } else {
        atomic_fetch_add(&svc->rebuilds_run, 1);
    }
    atomic_fetch_add(&svc->rows_written, rebuild.written);
    atomic_store(&svc->last_mirror_height, (int64_t)rebuild.applied_through);
    atomic_store(&svc->last_pass_unix, platform_time_wall_unix());

    LOG_INFO("utxo_mirror",
             "[utxo_mirror] %s mirror: %lld rows, synced to height %d",
             rebuild.used_delta ? "delta-applied" : "rebuilt",
             (long long)rebuild.written, rebuild.applied_through);
    return rebuild.written;
}

/* ── Background thread ─────────────────────────────────────── */

static void *utxo_mirror_sync_thread(void *arg)
{
    struct utxo_mirror_sync_service *svc = arg;
    atomic_store(&svc->state, UTXO_MIRROR_SYNC_RUNNING);

    pthread_mutex_lock(&svc->ready_mutex);
    svc->ready = true;
    pthread_cond_signal(&svc->ready_cond);
    pthread_mutex_unlock(&svc->ready_mutex);

    while (!atomic_load(&svc->stop_requested)) {
        (void)utxo_mirror_sync_run_once(svc);
        mirror_supervisor_heartbeat(svc);

        /* Interruptible sleep: 500 ms ticks so shutdown is prompt. */
        int total_ms = svc->tick_seconds * 1000;
        int slept = 0;
        while (slept < total_ms) {
            if (atomic_load(&svc->stop_requested)) break;
            platform_sleep_ms(500);
            slept += 500;
        }
    }

    atomic_store(&svc->state, UTXO_MIRROR_SYNC_STOPPED);
    return NULL;
}

/* ── Public API ────────────────────────────────────────────── */

void utxo_mirror_sync_init(struct utxo_mirror_sync_service *svc,
                           struct node_db *ndb)
{
    memset(svc, 0, sizeof(*svc));
    svc->ndb = ndb;
    atomic_store(&svc->thread_started, false);
    svc->ready = false;
    pthread_mutex_init(&svc->ready_mutex, NULL);
    pthread_cond_init(&svc->ready_cond, NULL);
    atomic_store(&svc->stop_requested, false);
    atomic_store(&svc->state, UTXO_MIRROR_SYNC_IDLE);
    atomic_store(&svc->mirror_health, UTXO_MIRROR_HEALTHY);
    atomic_store(&svc->rebuilds_run, 0);
    atomic_store(&svc->delta_passes_run, 0);
    atomic_store(&svc->delta_rows_changed, 0);
    atomic_store(&svc->quarantines_total, 0);
    atomic_store(&svc->rows_written, 0);
    atomic_store(&svc->last_mirror_height, 0);
    atomic_store(&svc->last_frontier, 0);
    atomic_store(&svc->last_pass_unix, 0);
    atomic_store(&svc->last_error_unix, 0);
    atomic_store(&svc->last_quarantine_unix, 0);

    int tick = UTXO_MIRROR_SYNC_DEFAULT_TICK_SECONDS;
    const char *env = getenv("ZCL_UTXO_MIRROR_TICK_SECONDS");
    if (env) {
        int v = atoi(env);
        if (v >= 1)
            tick = v;
    }
    svc->tick_seconds = tick;
}

struct zcl_result utxo_mirror_sync_start(struct utxo_mirror_sync_service *svc)
{
    if (!svc || !svc->ndb)
        return ZCL_ERR(-1, "utxo_mirror: start: null svc or ndb");
    if (atomic_load(&svc->thread_started))
        return ZCL_ERR(-2, "utxo_mirror: start: thread already running");

    atomic_store(&svc->stop_requested, false);
    svc->ready = false;
    if (thread_registry_spawn("zcl_utxo_mirror", utxo_mirror_sync_thread, svc,
                                  &svc->thread) != 0)
        return ZCL_ERR(-3, "utxo_mirror: failed to create thread: %s",
                       strerror(errno));
    atomic_store(&svc->thread_started, true);

    /* Bounded ready handshake (same shape as block_pruning_start): don't block
     * app_init indefinitely if the thread wedges before signalling ready. */
    pthread_mutex_lock(&svc->ready_mutex);
    bool ready_ok = true;
    while (!svc->ready) {
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        deadline.tv_sec += 30;
        int rc = pthread_cond_timedwait(&svc->ready_cond,
                                        &svc->ready_mutex, &deadline);
        if (rc == ETIMEDOUT && !svc->ready) {
            ready_ok = false;
            break;
        }
    }
    pthread_mutex_unlock(&svc->ready_mutex);

    if (!ready_ok) {
        atomic_store(&svc->stop_requested, true);
        /* Ownership is retained until the worker exits. Detaching here used
         * to let shutdown destroy svc/ndb while the worker could still touch
         * them. */
        pthread_join(svc->thread, NULL);
        atomic_store(&svc->thread_started, false);
        return ZCL_ERR(-4,
            "utxo_mirror: thread did not signal ready within 30 s — aborted start");
    }

    struct zcl_result sup_r = mirror_register_supervisor(svc);
    if (!sup_r.ok) {
        atomic_store(&svc->stop_requested, true);
        pthread_join(svc->thread, NULL);
        atomic_store(&svc->thread_started, false);
        return sup_r;
    }

    printf("[utxo_mirror] started — tick=%ds\n", svc->tick_seconds);
    return ZCL_OK;
}

void utxo_mirror_sync_stop(struct utxo_mirror_sync_service *svc)
{
    if (!svc || !atomic_load(&svc->thread_started)) return;
    supervisor_child_id id = atomic_load(&g_mirror_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
    atomic_store(&svc->stop_requested, true);
    pthread_join(svc->thread, NULL);
    atomic_store(&svc->thread_started, false);
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_mirror_supervisor_id, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
    pthread_mutex_destroy(&svc->ready_mutex);
    pthread_cond_destroy(&svc->ready_cond);
    printf("[utxo_mirror] stopped\n");
}
