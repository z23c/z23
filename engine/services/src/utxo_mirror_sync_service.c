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
#include "crypto/sha3.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "models/database.h"
#include "models/utxo.h"
#include "jobs/refold_progress.h"
#include "script/script.h"
#include "script/standard.h"
#include "services/chain_state_service.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
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

/* Copy one coins-row txid into out32; false (loudly) on a malformed row —
 * a single bad row never aborts the mirror rebuild. */
static bool mirror_rebuild_row_txid(sqlite3_stmt *sel, uint8_t out32[32])
{
    const void *blob = sqlite3_column_blob(sel, 0);
    int len = sqlite3_column_bytes(sel, 0);
    if (!blob || len != 32) {
        LOG_WARN("utxo_mirror", "rebuild: malformed txid (len=%d) — skipping row",
                 len);
        return false;
    }
    memcpy(out32, blob, 32);
    return true;
}

/* Fold one coins row into the mirror: validate, classify, insert, account
 * into the commitment. SKIPPED rows are loud one-offs (malformed source
 * data) that never abort the rebuild; FAILED is a real node.db write error
 * and aborts the pass. */
enum mirror_row_fold { MIRROR_ROW_FOLDED, MIRROR_ROW_SKIPPED,
                       MIRROR_ROW_FAILED };

static enum mirror_row_fold
mirror_rebuild_fold_row(struct node_db *ndb, sqlite3_stmt *sel,
                        struct utxo_commitment *uc)
{
    struct db_utxo u;
    memset(&u, 0, sizeof(u));
    if (!mirror_rebuild_row_txid(sel, u.txid))
        return MIRROR_ROW_SKIPPED;
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
        return MIRROR_ROW_SKIPPED;
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
        return MIRROR_ROW_FAILED;
    }
    /* u.height is already the CHECK(height >= 0)-clamped value actually
     * persisted — feed the identical bytes utxo_commitment_compute_db
     * would read back from this same row, so a future O(n) verification
     * against this stamp matches exactly. */
    utxo_commitment_add(uc, u.txid, u.vout, u.value, (int32_t)u.height);
    return MIRROR_ROW_FOLDED;
}

#ifdef ZCL_TESTING
static enum utxo_mirror_test_fault g_mirror_fault;
void utxo_mirror_sync_test_set_fault(enum utxo_mirror_test_fault fault)
{
    g_mirror_fault = fault;
}
static void (*g_mirror_post_auth_hook)(void *);
static void *g_mirror_post_auth_ctx;
void utxo_mirror_sync_test_set_post_authority_hook(void (*fn)(void *), void *ctx)
{
    g_mirror_post_auth_hook = fn;
    g_mirror_post_auth_ctx = ctx;
}
static void (*g_mirror_writer_hook)(sqlite3 *, void *);
static void *g_mirror_writer_hook_ctx;
void utxo_mirror_sync_test_set_writer_hook(void (*fn)(sqlite3 *, void *),
                                           void *ctx)
{
    g_mirror_writer_hook = fn;
    g_mirror_writer_hook_ctx = ctx;
}
#define MIRROR_FAULT(x) (g_mirror_fault == (x))
#else
#define MIRROR_FAULT(x) false
#endif

/* Test seam: after the first copied row an armed fault fails the scan so the
 * abort/teardown path runs deterministically mid-rebuild. */
static bool mirror_test_scan_fault(int64_t written)
{
#ifdef ZCL_TESTING
    return (g_mirror_fault == UMS_FAULT_ROLLBACK_FAILS ||
            g_mirror_fault == UMS_FAULT_CLOSE_BUSY) && written >= 1;
#else
    (void)written;
    return false;
#endif
}

static void (*mirror_pre_snapshot_hook)(void *);
static void *mirror_pre_snapshot_ctx;

void utxo_mirror_sync_test_set_pre_snapshot_hook(void (*fn)(void *), void *ctx)
{
    mirror_pre_snapshot_hook = fn;
    mirror_pre_snapshot_ctx = ctx;
}

/* Feed one source row into the canonical SHA3 stream exactly as
 * coins_kv_commitment() does (rows with a short txid are skipped there too). */
static void mirror_rebuild_source_fold(struct sha3_256_ctx *ctx,
                                       sqlite3_stmt *sel)
{
    const uint8_t *txid = sqlite3_column_blob(sel, 0);
    if (!txid || sqlite3_column_bytes(sel, 0) < 32)
        return;
    const uint8_t *script = sqlite3_column_blob(sel, 5);
    int slen = sqlite3_column_bytes(sel, 5);
    utxo_commitment_sha3_write_record(
        ctx, txid, (uint32_t)sqlite3_column_int(sel, 1),
        sqlite3_column_int64(sel, 2), slen > 0 ? script : NULL,
        (uint32_t)(slen > 0 ? slen : 0), (uint32_t)sqlite3_column_int(sel, 3),
        (uint8_t)(sqlite3_column_int(sel, 4) ? 1 : 0));
}

/* Stop responsiveness for the wholesale rebuild: the walk below runs the
 * entire coins table (millions of rows) on the service thread, and a walk
 * that never polls the stop flag keeps the thread alive past the
 * orderly-shutdown join until the external grace SIGKILLs the process — the
 * unclean-stop class. Polled every 4096 rows (a bitmask test + one atomic
 * load — noise against a sqlite step), so a stop unwinds the rebuild in
 * well under a second; the aborted pass rolls back and retries next pass. */
static bool mirror_rebuild_stop_polled(const _Atomic bool *stop,
                                       int64_t written)
{
    return stop && (written & 4095) == 0 && atomic_load(stop);
}

/* Walk the snapshot rows: feed each into the source SHA3 stream and the staged
 * utxos fold. False on a step/fold failure or a stop request (*stopped set). */
static bool mirror_rebuild_scan(struct node_db *ndb, sqlite3 *rdb,
                                sqlite3_stmt *sel, const _Atomic bool *stop,
                                struct utxo_commitment *uc,
                                struct sha3_256_ctx *src_sha, int64_t *written,
                                bool *stopped)
{
    for (;;) {
        int rc = sqlite3_step(sel);  // raw-sql-ok:progress-kv-kernel-store
        if (rc == SQLITE_DONE)
            return true;
        if (rc != SQLITE_ROW) {
            LOG_WARN("utxo_mirror", "rebuild: coins SELECT step failed rc=%d: %s",
                     rc, sqlite3_errmsg(rdb));
            return false;
        }
        if (mirror_rebuild_stop_polled(stop, *written)) {
            LOG_INFO("utxo_mirror",
                     "rebuild: stop requested after %lld rows; aborting staged transaction",
                     (long long)*written);
            *stopped = true;
            return false;
        }
        if (mirror_test_scan_fault(*written)) {
            LOG_WARN("utxo_mirror", "rebuild: injected scan fault");
            return false;
        }
        mirror_rebuild_source_fold(src_sha, sel);
        enum mirror_row_fold rf = mirror_rebuild_fold_row(ndb, sel, uc);
        if (rf == MIRROR_ROW_FAILED)
            return false;
        if (rf == MIRROR_ROW_FOLDED)
            (*written)++;
    }
}

/* A checked SQL count belongs to this connection's read transaction; the
 * ordinary coins_kv count may instead consult the process RAM overlay. */
static bool mirror_snapshot_count(sqlite3 *db, int64_t *out)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM coins", -1, &s, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(s); // raw-sql-ok:progress-kv-kernel-store
    int64_t n = -1;
    if (rc == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_INTEGER)
        n = sqlite3_column_int64(s, 0);
    if (rc == SQLITE_ROW)
        rc = sqlite3_step(s); // raw-sql-ok:progress-kv-kernel-store
    int end = sqlite3_finalize(s);
    if (n < 0 || rc != SQLITE_DONE || end != SQLITE_OK)
        return false;
    *out = n;
    return true;
}

/* The staged read must finish, not merely yield a matching prefix. Use the
 * same column order and existing canonical record encoder as the source. */
static bool mirror_staged_commitment(sqlite3 *db, uint8_t root[32], uint64_t *count)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT txid, vout, value, height, is_coinbase, script FROM utxos ORDER BY txid, vout",
        -1, &s, NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint64_t n = 0;
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        const void *txid = sqlite3_column_blob(s, 0);
        if (!txid || sqlite3_column_bytes(s, 0) != 32) {
            sqlite3_finalize(s);
            return false;
        }
        mirror_rebuild_source_fold(&sha, s);
        n++;
    }
    int end = sqlite3_finalize(s);
    if (rc != SQLITE_DONE || end != SQLITE_OK)
        return false;
    sha3_256_finalize(&sha, root);
    *count = n;
    return true;
}

/* Open the single read snapshot: BEGIN, then the frontier read as the first
 * statement so WAL pins the snapshot there. Returns 0 or a typed
 * UTXO_MIRROR_REBUILD_* refusal; an operator repair is refused when the RAM
 * coins overlay is active (checked again here, AFTER the authority proof, as
 * coins_kv_read_snapshot_open does) because the proof counts overlay-aware
 * while the copy scans durable SQL. */
static int mirror_snapshot_begin(sqlite3 *rdb, int32_t *frontier,
    bool operator_repair, int64_t *source_count, char *reason, size_t cap)
{
    bool found = false;
    if (sqlite3_exec(rdb, "BEGIN", NULL, NULL, NULL) != SQLITE_OK)
        return UTXO_MIRROR_REBUILD_ERROR;
    if (!operator_repair)
        return coins_kv_get_applied_height(rdb, frontier, &found) && found
                   ? 0 : UTXO_MIRROR_REBUILD_ERROR;
    if (!coins_kv_proven_authority_reason(rdb, frontier, reason, cap)) {
        LOG_WARN("utxo_mirror", "operator source authority refused: %s", reason);
        return UTXO_MIRROR_REBUILD_REFUSED;
    }
#ifdef ZCL_TESTING
    if (g_mirror_post_auth_hook)
        g_mirror_post_auth_hook(g_mirror_post_auth_ctx);
#endif
    if (coins_ram_active()) {
        snprintf(reason, cap, "coins_overlay_active");
        LOG_WARN("utxo_mirror", "operator rebuild refused: RAM coins overlay active");
        return UTXO_MIRROR_REBUILD_OVERLAY_ACTIVE;
    }
    return mirror_snapshot_count(rdb, source_count) && *source_count > 0
               ? 0 : UTXO_MIRROR_REBUILD_ERROR;
}


/* Verify BEFORE commit: the staged rows must hash to the snapshot's own
 * commitment. On mismatch roll the whole transaction back (the previous
 * mirror stays unchanged when rollback succeeds). */
static int mirror_rebuild_verified(struct node_db *ndb,
    struct sha3_256_ctx *src_sha, int64_t expected_count)
{
    uint8_t src_root[32], stg_root[32];
    uint64_t stg_count = 0;
    sha3_256_finalize(src_sha, src_root);
    if (!mirror_staged_commitment(ndb->db, stg_root, &stg_count))
        return UTXO_MIRROR_REBUILD_ERROR;
    if (memcmp(src_root, stg_root, 32) != 0 ||
        (expected_count >= 0 && stg_count != (uint64_t)expected_count))
        return UTXO_MIRROR_REBUILD_VERIFY_MISMATCH;
    return 0;
}


/* Failed rollback does not prove restoration. Keep quarantine and propagate
 * an explicitly unsettled result instead of blessing either set. */
static int64_t mirror_rebuild_rollback(struct node_db *ndb, int64_t failure, bool commit_attempted)
{
    /* SQLITE_INTERRUPT and other statement errors can auto-rollback. Before
     * any COMMIT attempt, autocommit proves that this owned transaction has
     * already rolled back. Still invoke the wrapper to discard queued hooks
     * and update node bookkeeping. After failed COMMIT, autocommit alone
     * cannot distinguish rollback from an uncertain commit outcome. */
    bool auto_rollback = !commit_attempted && sqlite3_get_autocommit(ndb->db) != 0;
    bool rolled_back = !MIRROR_FAULT(UMS_FAULT_ROLLBACK_FAILS) &&
                       node_db_rollback(ndb);
    if (!rolled_back && !auto_rollback) {
        LOG_WARN("utxo_mirror", "rebuild rollback failed; mirror state unsettled");
        return UTXO_MIRROR_REBUILD_UNSETTLED;
    }
    return failure;
}

/* ── The rebuild's two private handles ──────────────────────────────────
 * Source: its own read-only progress.kv connection (one snapshot). Writer: a
 * DEDICATED node.db connection, so the shared service handle never carries the
 * rebuild's transaction, statements or failure state. */
struct mirror_source {
    sqlite3 *db;
    sqlite3_stmt *sel;
    int32_t frontier;
    int64_t count;
};

/* True only when the statement finalized and the connection closed cleanly. */
static bool mirror_source_close(struct mirror_source *s)
{
    bool clean = true;
    if (s->sel && sqlite3_finalize(s->sel) != SQLITE_OK)
        clean = false;
    if (s->db && sqlite3_close(s->db) != SQLITE_OK)
        clean = false;
    s->sel = NULL;
    s->db = NULL;
    return clean;
}

/* Open the snapshot reader. Returns 0 or a typed UTXO_MIRROR_REBUILD_* code. */
static int mirror_source_open(struct mirror_source *s, bool operator_repair,
                              char *reason, size_t cap)
{
    memset(s, 0, sizeof(*s));
    s->frontier = -1;
    s->count = -1;
    if (operator_repair && coins_ram_active()) {
        snprintf(reason, cap, "coins_overlay_active");
        LOG_RETURN(UTXO_MIRROR_REBUILD_OVERLAY_ACTIVE, "utxo_mirror",
                   "rebuild refused: RAM coins overlay active");
    }
    /* Read coins_kv through our OWN read-only connection to progress.kv — NOT
     * the shared progress_store_db() handle under progress_store_tx_lock, which
     * a multi-second scan would hold against the consensus reducer. WAL lets
     * this reader see the last committed snapshot; we never WRITE coins_kv. */
    char pkv_path[PROGRESS_STORE_PATH_MAX];
    if (!progress_store_path(pkv_path, sizeof(pkv_path)))
        LOG_RETURN(UTXO_MIRROR_REBUILD_ERROR, "utxo_mirror",
                   "rebuild: progress store path unavailable");
    if (sqlite3_open_v2(pkv_path, &s->db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        (void)mirror_source_close(s);
        LOG_RETURN(UTXO_MIRROR_REBUILD_ERROR, "utxo_mirror",
                   "rebuild: open ro progress.kv failed: %s", pkv_path);
    }
    sqlite3_busy_timeout(s->db, 5000);
    /* ONE read snapshot for the frontier AND the scan (frontier read first so
     * WAL pins the snapshot there). */
    int rc = mirror_snapshot_begin(s->db, &s->frontier, operator_repair,
                                   &s->count, reason, cap);
    if (rc == 0 && sqlite3_prepare_v2(s->db,
            "SELECT txid, vout, value, height, is_coinbase, script "
            "FROM coins ORDER BY txid, vout", -1, &s->sel, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_mirror", "rebuild: coins SELECT prepare failed: %s",
                 sqlite3_errmsg(s->db));
        rc = UTXO_MIRROR_REBUILD_ERROR;
    }
    if (rc != 0)
        (void)mirror_source_close(s);
    if (rc != 0)
        LOG_WARN("utxo_mirror", "rebuild: snapshot unavailable (%d)", rc);
    return rc;
}

#define MIRROR_WRITER_BUSY_MS 5000

struct mirror_writer {
    struct node_db db;
    sqlite3_stmt *ins;
};

/* Checked teardown: finalize the statement this writer owns, then close with
 * the checked helper. If close does not return SQLITE_OK the best-effort
 * node_db_close releases the connection, but the caller must still report the
 * outcome unsettled. */
static bool mirror_writer_close(struct mirror_writer *w)
{
    if (!w->db.open)
        return true;
    if (w->ins)
        (void)sqlite3_finalize(w->ins);
    w->ins = NULL;
    w->db.stmt_utxo_insert = NULL;
#ifdef ZCL_TESTING
    if (MIRROR_FAULT(UMS_FAULT_CLOSE_BUSY) ||
        MIRROR_FAULT(UMS_FAULT_COMMIT_THEN_CLOSE_BUSY))
        node_db_test_fail_next_checked_close();
#endif
    if (node_db_close_checked(&w->db))
        return true;
    LOG_WARN("utxo_mirror", "rebuild writer close not SQLITE_OK; unsettled");
    node_db_close(&w->db);
    return false;
}

/* Open the private writer and BEGIN IMMEDIATE (bounded busy wait). 0 or a
 * typed failure; a failed teardown after a failed open is UNSETTLED. */
static int mirror_writer_open(struct mirror_writer *w, const char *path)
{
    memset(w, 0, sizeof(*w));
    if (!node_db_open_existing_runtime(&w->db, path, "utxo_mirror.rebuild"))
        LOG_RETURN(UTXO_MIRROR_REBUILD_ERROR, "utxo_mirror",
                   "rebuild: private node.db writer open failed");
    sqlite3_busy_timeout(w->db.db, MIRROR_WRITER_BUSY_MS);
#ifdef ZCL_TESTING
    if (g_mirror_writer_hook)
        g_mirror_writer_hook(w->db.db, g_mirror_writer_hook_ctx);
#endif
    /* Plain transaction — NO ibd_turbo_mode: turbo DROPS the utxos secondary
     * indexes the explorer relies on. */
    if (sqlite3_prepare_v2(w->db.db,
            "INSERT OR REPLACE INTO utxos"
            "(txid,vout,value,script,script_type,"
            "address_hash,height,is_coinbase) VALUES(?,?,?,?,?,?,?,?)",
            -1, &w->ins, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_mirror", "rebuild: writer insert prepare failed: %s",
                 sqlite3_errmsg(w->db.db));
        return mirror_writer_close(w) ? UTXO_MIRROR_REBUILD_ERROR
                                      : UTXO_MIRROR_REBUILD_UNSETTLED;
    }
    w->db.stmt_utxo_insert = w->ins;
    if (!node_db_begin_immediate(&w->db)) {
        LOG_WARN("utxo_mirror", "rebuild: writer BEGIN IMMEDIATE failed");
        return mirror_writer_close(w) ? UTXO_MIRROR_REBUILD_ERROR
                                      : UTXO_MIRROR_REBUILD_UNSETTLED;
    }
    return 0;
}

/* Roll back, then tear the writer down. Unsettled when either step cannot
 * prove it completed. */
static int64_t mirror_writer_abort(struct mirror_writer *w, int64_t failure,
                                   bool commit_attempted)
{
    int64_t r = mirror_rebuild_rollback(&w->db, failure, commit_attempted);
    if (!mirror_writer_close(w))
        return UTXO_MIRROR_REBUILD_UNSETTLED;
    return r;
}

struct mirror_stage {
    struct utxo_commitment uc;
    /* Source-side canonical SHA3 over EVERY well-formed snapshot row, the
     * exact record stream coins_kv_commitment() emits. Compared with the SHA3
     * of the staged utxos before anything commits. */
    struct sha3_256_ctx src_sha;
    int64_t written;
};

/* DELETE + copy under the writer's transaction; closes the source. 0, or the
 * (already rolled back and torn down) failure. */
static int64_t mirror_rebuild_stage(struct mirror_writer *w,
    struct mirror_source *src, const _Atomic bool *stop, struct mirror_stage *st)
{
    bool stopped = false;
    utxo_commitment_init(&st->uc);
    sha3_256_init(&st->src_sha);
    st->written = 0;
    bool ok = node_db_exec(&w->db, "DELETE FROM utxos");
    if (ok)
        ok = mirror_rebuild_scan(&w->db, src->db, src->sel, stop, &st->uc,
                                 &st->src_sha, &st->written, &stopped);
    bool closed = mirror_source_close(src);
    if (ok && closed)
        return 0;
    LOG_WARN("utxo_mirror", "rebuild: aborted after %lld rows",
             (long long)st->written);
    return mirror_writer_abort(w, stopped ? UTXO_MIRROR_REBUILD_STOPPED
                                          : UTXO_MIRROR_REBUILD_ERROR, false);
}

/* Verify, then stamp checkpoint + caches + cursor in the SAME transaction.
 * 0, or the typed failure to roll back with. */
static int mirror_rebuild_persist(struct node_db *ndb, struct mirror_stage *st,
                                  int32_t frontier, int64_t expected_count)
{
    int verdict = mirror_rebuild_verified(ndb, &st->src_sha, expected_count);
    if (verdict != 0)
        return verdict;
    /* Height-stamp the freshly rebuilt checkpoint: `frontier` is an exact
     * covering height, letting utxo_mirror_delta_apply take over incrementally. */
    if (!utxo_commitment_save_checkpoint_at_height(ndb->db, &st->uc, frontier)) {
        LOG_WARN("utxo_mirror", "rebuild: commitment checkpoint save failed at frontier=%d", frontier);
        return UTXO_MIRROR_REBUILD_ERROR;
    }
    if (!db_utxo_rebuild_wallet_and_address_caches_in_txn(ndb)) {
        LOG_WARN("utxo_mirror", "rebuild: wallet/address cache refresh failed");
        return UTXO_MIRROR_REBUILD_ERROR;
    }
    int64_t next_cursor = frontier;
    if (!node_db_state_set(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY,
                           &next_cursor, sizeof(next_cursor))) {
        LOG_WARN("utxo_mirror", "rebuild: cursor persist failed at frontier=%d", frontier);
        return UTXO_MIRROR_REBUILD_ERROR;
    }
    return 0;
}

/* Copy every live coins_kv row into the mirror under ONE transaction on a
 * PRIVATE node.db writer. Returns the number of rows written, or a negative
 * UTXO_MIRROR_REBUILD_* code. Ordinary failures roll back; UNSETTLED means a
 * rollback or the writer's checked close could not prove completion and
 * neither restoration nor a healthy mirror is claimed. `shared` is only the
 * path source; it never carries the rebuild's transaction. */
static int64_t mirror_rebuild_from_coins_kv(struct node_db *shared,
                                            int32_t *frontier_out,
                                            const _Atomic bool *stop,
                                            bool operator_repair,
                                            char *reason, size_t reason_cap)
{
    if (mirror_pre_snapshot_hook)
        mirror_pre_snapshot_hook(mirror_pre_snapshot_ctx);
    if (!shared || !shared->open)
        LOG_RETURN(-1, "utxo_mirror", "rebuild: node.db unavailable");

    struct mirror_source src;
    int rc = mirror_source_open(&src, operator_repair, reason, reason_cap);
    if (rc != 0)
        return rc;
    struct mirror_writer w;
    rc = mirror_writer_open(&w, shared->path);
    if (rc != 0) {
        (void)mirror_source_close(&src);
        return rc;
    }
    struct mirror_stage st;
    int32_t frontier = src.frontier;
    int64_t expected = src.count;
    int64_t failure = mirror_rebuild_stage(&w, &src, stop, &st);
    if (failure != 0)
        return failure;
    rc = mirror_rebuild_persist(&w.db, &st, frontier, expected);
    if (rc != 0)
        return mirror_writer_abort(&w, rc, false);
    if (!node_db_commit(&w.db)) {
        LOG_WARN("utxo_mirror", "rebuild: node.db COMMIT failed");
        return mirror_writer_abort(&w, UTXO_MIRROR_REBUILD_ERROR, true);
    }
    if (!mirror_writer_close(&w))
        return UTXO_MIRROR_REBUILD_UNSETTLED;
    *frontier_out = frontier;
    return st.written;
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
    bool operator_repair;    /* authority admission required only for explicit repair */
    char reason[96];         /* refusal token (REFUSED / OVERLAY_ACTIVE) */
};

/* Typed outcomes that leave the previous mirror and its health untouched (a
 * failed authority proof keeps its historical quarantine behaviour). */
static bool mirror_rebuild_left_unchanged(int64_t code)
{
    return code == UTXO_MIRROR_REBUILD_STOPPED ||
           code == UTXO_MIRROR_REBUILD_OVERLAY_ACTIVE;
}

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
    int32_t snap_h = r->frontier;
    r->written = mirror_rebuild_from_coins_kv(ndb, &snap_h,
                                              &r->svc->stop_requested, r->operator_repair,
                                              r->reason, sizeof(r->reason));
    if (mirror_rebuild_left_unchanged(r->written)) {
        /* Stopped or refused before any write (shutdown, RAM overlay, failed
         * authority proof): the mirror is
         * unchanged, so restore HEALTHY — a stop is not corruption and must
         * never quarantine. The service thread exits on the same flag; the
         * next pass (or next boot) retries the rebuild. */
        atomic_store(&r->svc->mirror_health, UTXO_MIRROR_HEALTHY);
        return false;
    }
    if (r->written < 0) {
        atomic_store(&r->svc->mirror_health, UTXO_MIRROR_QUARANTINED);
        atomic_fetch_add(&r->svc->quarantines_total, 1);
        atomic_store(&r->svc->last_quarantine_unix,
                     platform_time_wall_unix());
        return false;
    }
    r->applied_through = snap_h;  /* the SCANNED height, not the earlier read */
    r->cursor_persisted = true;
    atomic_store(&r->svc->mirror_health, UTXO_MIRROR_HEALTHY);
    return true;
}

/* ── One sync pass ─────────────────────────────────────────── */

/* One completion line per rebuild entry point: heights, row count and elapsed
 * milliseconds only. blocks_scanned is the height span the pass advanced. */
static void mirror_log_pass_done(const char *op, int32_t start, int32_t end,
                                 int64_t items, int64_t t0_ms, bool ok)
{
    int32_t span = end > start ? end - start : 0;
    LOG_INFO("utxo_mirror",
             "[utxo_mirror] op=%s start_height=%d end_height=%d "
             "blocks_scanned=%d items=%lld elapsed_ms=%lld result=%s",
             op, start, end, span, (long long)(items < 0 ? 0 : items),
             (long long)(platform_time_monotonic_ms() - t0_ms),
             ok ? "ok" : "failed");
}

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
     * concurrent with the fold (the blocks-less crash window). "Near
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
    int64_t t0_ms = platform_time_monotonic_ms();
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
        mirror_log_pass_done("run_once", rebuild.cursor,
                             rebuild.applied_through, rebuild.written, t0_ms,
                             false);
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
    mirror_log_pass_done("run_once", rebuild.cursor, rebuild.applied_through,
                         rebuild.written, t0_ms, true);
    return rebuild.written;
}

/* ── Operator-driven rebuild ───────────────────────────────── */

int64_t utxo_mirror_rebuild_now(struct utxo_mirror_sync_service *svc)
{
    return utxo_mirror_rebuild_now_reason(svc, NULL, 0);
}

/* Refusals that apply before any state is touched. Returns 0 to proceed or the
 * UTXO_MIRROR_REBUILD_* code to hand back; *frontier is set on proceed. */
static int64_t rebuild_now_preflight(struct utxo_mirror_sync_service *svc,
                                     char *reason, size_t reason_cap,
                                     int32_t *frontier)
{
    if (!svc || !svc->ndb || !svc->ndb->open)
        LOG_RETURN(UTXO_MIRROR_REBUILD_ERROR, "utxo_mirror",
                   "rebuild_now: node.db unavailable");
    if (reason && reason_cap > 0)
        reason[0] = '\0';
    if (coins_ram_active()) {
        if (reason && reason_cap > 0)
            snprintf(reason, reason_cap, "coins_overlay_active");
        LOG_RETURN(UTXO_MIRROR_REBUILD_OVERLAY_ACTIVE, "utxo_mirror",
                   "rebuild_now: refused while the RAM coins overlay is active");
    }
    if (refold_in_progress())
        LOG_RETURN(UTXO_MIRROR_REBUILD_ERROR, "utxo_mirror",
                   "rebuild_now: refused while a refold is in progress");

    int64_t coins_count = -1;
    *frontier = -1;
    if (!read_coins_kv_state(frontier, &coins_count))
        LOG_RETURN(UTXO_MIRROR_REBUILD_ERROR, "utxo_mirror",
                   "rebuild_now: no authoritative frontier");
    return 0;
}

int64_t utxo_mirror_rebuild_now_reason(struct utxo_mirror_sync_service *svc,
                                       char *reason, size_t reason_cap)
{
    int32_t frontier = -1;
    int64_t pre = rebuild_now_preflight(svc, reason, reason_cap, &frontier);
    if (pre != 0)
        return pre;

    int64_t t0_ms = platform_time_monotonic_ms();
    /* cursor 0 forces the wholesale branch; the scan stamps its own snapshot
     * height. Quarantine is cleared only by a verified commit. */
    struct mirror_rebuild_ctx rebuild = {
        .svc = svc, .cursor = 0, .frontier = frontier,
        .mirror_has_rows = false, .applied_through = 0, .written = -1,
        .cursor_persisted = false, .used_delta = false, .operator_repair = true,
    };
    int prior = atomic_load(&svc->mirror_health);
    atomic_fetch_add(&svc->updates_active, 1u);
    atomic_fetch_add(&svc->update_generation, 1u);
    bool lane_ok = mirror_run_db_lane(svc->ndb, mirror_rebuild_and_advance_lane,
                                      &rebuild);
    atomic_fetch_add(&svc->update_generation, 1u);
    atomic_fetch_sub(&svc->updates_active, 1u);
    if (!lane_ok || rebuild.written < 0) {
        atomic_store(&svc->last_error_unix, platform_time_wall_unix());
        mirror_log_pass_done("operator_rebuild", rebuild.cursor,
                             rebuild.applied_through, rebuild.written, t0_ms,
                             false);
        if (mirror_rebuild_left_unchanged(rebuild.written))
            atomic_store(&svc->mirror_health, prior);
        if (reason && reason_cap > 0)
            snprintf(reason, reason_cap, "%s", rebuild.reason);
        return rebuild.written < 0 ? rebuild.written
                                   : UTXO_MIRROR_REBUILD_ERROR;
    }
    atomic_fetch_add(&svc->rebuilds_run, 1);
    atomic_fetch_add(&svc->rows_written, rebuild.written);
    atomic_store(&svc->last_mirror_height, (int64_t)rebuild.applied_through);
    atomic_store(&svc->last_pass_unix, platform_time_wall_unix());
    LOG_INFO("utxo_mirror",
             "[utxo_mirror] operator rebuild: %lld rows, synced to height %d",
             (long long)rebuild.written, rebuild.applied_through);
    mirror_log_pass_done("operator_rebuild", rebuild.cursor,
                         rebuild.applied_through, rebuild.written, t0_ms, true);
    return rebuild.written;
}

/* ── Operator rebuild job (runs on the mirror thread) ──────── */

int utxo_mirror_rebuild_request(struct utxo_mirror_sync_service *svc,
                                uint64_t *id_out)
{
    if (!svc || !atomic_load(&svc->thread_started) ||
        atomic_load(&svc->stop_requested))
        LOG_RETURN(-1, "utxo_mirror",
                   "rebuild_request: no running mirror thread to serve it");
    int rc = 0;
    pthread_mutex_lock(&svc->job_mutex);
    if (svc->job.state == UTXO_MIRROR_JOB_PENDING ||
        svc->job.state == UTXO_MIRROR_JOB_RUNNING) {
        rc = 1;
    } else {
        svc->job.id++;
        svc->job.state = UTXO_MIRROR_JOB_PENDING;
        svc->job.result = 0;
        svc->job.reason[0] = '\0';
    }
    if (id_out)
        *id_out = svc->job.id;
    pthread_mutex_unlock(&svc->job_mutex);
    return rc;
}

void utxo_mirror_rebuild_job_snapshot(struct utxo_mirror_sync_service *svc,
                                      struct utxo_mirror_rebuild_job *out)
{
    pthread_mutex_lock(&svc->job_mutex);
    *out = svc->job;
    pthread_mutex_unlock(&svc->job_mutex);
}

int utxo_mirror_rebuild_job_service(struct utxo_mirror_sync_service *svc)
{
    pthread_mutex_lock(&svc->job_mutex);
    bool pending = svc->job.state == UTXO_MIRROR_JOB_PENDING;
    if (pending)
        svc->job.state = UTXO_MIRROR_JOB_RUNNING;
    pthread_mutex_unlock(&svc->job_mutex);
    if (!pending)
        return 0;

    char reason[sizeof(svc->job.reason)] = "";
    int64_t rows = utxo_mirror_rebuild_now_reason(svc, reason, sizeof(reason));

    pthread_mutex_lock(&svc->job_mutex);
    svc->job.result = rows;
    memcpy(svc->job.reason, reason, sizeof(reason));
    svc->job.quarantined =
        atomic_load(&svc->mirror_health) == UTXO_MIRROR_QUARANTINED;
    svc->job.mirror_height = atomic_load(&svc->last_mirror_height);
    svc->job.state = UTXO_MIRROR_JOB_DONE;
    pthread_mutex_unlock(&svc->job_mutex);
    return 1;
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
        (void)utxo_mirror_rebuild_job_service(svc);
        (void)utxo_mirror_sync_run_once(svc);
        mirror_supervisor_heartbeat(svc);

        /* Interruptible sleep: 500 ms ticks so shutdown is prompt. */
        int total_ms = svc->tick_seconds * 1000;
        int slept = 0;
        while (slept < total_ms) {
            if (atomic_load(&svc->stop_requested)) break;
            platform_sleep_ms(500);
            slept += 500;
            if (utxo_mirror_rebuild_job_service(svc))
                mirror_supervisor_heartbeat(svc);
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
    pthread_mutex_init(&svc->job_mutex, NULL);
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

int utxo_mirror_prepare_key_scan(sqlite3 *db, sqlite3_stmt **out)
{
    return sqlite3_prepare_v2(
        db, "SELECT txid, vout, value, height FROM utxos ORDER BY txid, vout",
        -1, out, NULL);
}
