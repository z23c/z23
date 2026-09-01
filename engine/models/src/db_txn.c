/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * db_txn — scoped database transactions. See header for rationale.
 *
 * ar-validate-skip:txn-wrapper-not-a-row
 *   struct db_txn is a RAII wrapper around BEGIN/COMMIT/ROLLBACK, not
 *   a row record. Validation belongs to the models whose writes the
 *   transaction is scoping.
 *
 * Ownership model
 * ---------------
 * Every handle returned by db_txn_begin is freed by exactly one
 * caller of db_txn_auto_rollback (typically via DB_TXN_SCOPE). The
 * explicit commit/rollback functions set state flags on the handle
 * but do NOT free — that keeps the scope variable valid all the way
 * through the cleanup attribute at scope exit, where auto_rollback
 * is the sole deallocator.
 *
 * Non-scope uses must call db_txn_auto_rollback(&txn) manually after
 * the final commit or rollback (tests do this).
 */

#include "models/db_txn.h"

#include "event/event.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

/* ── Time helper ────────────────────────────────────────────────
 * Local static to keep this module's dependency footprint tiny. */
static int64_t db_txn_now_us(void)
{
    return platform_time_monotonic_us();
}

/* ── Event helpers ──────────────────────────────────────────── */

static void emit_begin(const char *label)
{
    event_emitf(EV_DB_TXN_BEGIN, 0, "label=%s", label ? label : "");
}

static void emit_commit(const char *label, int64_t elapsed_us)
{
    event_emitf(EV_DB_TXN_COMMIT, 0,
                "label=%s elapsed_us=%lld",
                label ? label : "", (long long)elapsed_us);
}

static void emit_rollback(const char *label, const char *reason)
{
    event_emitf(EV_DB_TXN_ROLLBACK, 0,
                "label=%s reason=%s",
                label ? label : "", reason ? reason : "");
}

static void emit_rejected(const char *label, const char *reason)
{
    event_emitf(EV_DB_TXN_REJECTED, 0,
                "label=%s reason=%s",
                label ? label : "?", reason ? reason : "");
}

static void emit_leaked(const char *label)
{
    event_emitf(EV_DB_TXN_LEAKED, 0, "label=%s", label ? label : "");
}

/* ── Disk-critical probe (hexagonal seam) ──────────────────────
 * See db_txn_set_disk_critical_probe() in the header for the rationale
 * (models/ must not #include services/disk_monitor.h directly). */
static db_txn_disk_critical_probe_fn g_disk_critical_probe;

void db_txn_set_disk_critical_probe(db_txn_disk_critical_probe_fn fn)
{
    g_disk_critical_probe = fn;
}

/* ── Lifecycle ──────────────────────────────────────────────── */

struct db_txn *db_txn_begin(struct node_db *db, const char *label)
{
    if (!db || !label || !*label) {
        emit_rejected(label, "null_input");
        return NULL;
    }
    if (!db->open) {
        emit_rejected(label, "db_not_open");
        return NULL;
    }

    /* Disk back-pressure. When the free-space watchdog reports CRITICAL (free
     * below the refuse threshold, default 1 GB), refuse to open a NEW write
     * transaction so we stop adding bytes to a near-full filesystem. This is a
     * NAMED refuse (EV_DB_TXN_REJECTED reason=disk_critical), never a silent
     * stall — callers already handle a NULL begin. It clears automatically the
     * instant the probe goes false: the disk_full_pause remedy reclaims
     * derived bytes (WAL truncate + *.tmp sweep), so writes resume without
     * operator action. The probe (registered by disk_monitor_start() with
     * disk_monitor_is_critical, a lock-free atomic read) returns false
     * whenever it is unset or the watchdog is not running, so this is a
     * no-op on nodes/tests without the monitor. */
    if (g_disk_critical_probe && g_disk_critical_probe()) {
        emit_rejected(label, "disk_critical");
        LOG_NULL("db",
                 "db_txn: REJECTED label='%s' — disk CRITICAL (free below "
                 "refuse threshold); write back-pressure engaged until reclaim "
                 "frees space", label);
    }

    /* Refuse nesting. The node_db layer only supports one transaction
     * at a time; silently nesting would commit the outer parent when
     * the inner closes — exactly the pattern we're trying to kill. */
    struct node_db_status status = {0};
    node_db_get_status(db, &status);
    if (status.tx_open) {
        emit_rejected(label, "already_open");
        LOG_NULL("db",
                "db_txn: REJECTED nesting for label='%s' "
                "(underlying tx already open)", label);
    }

    if (!node_db_begin(db)) {
        emit_rejected(label, "begin_failed");
        return NULL;
    }

    struct db_txn *txn = zcl_calloc(1, sizeof(*txn), "db_txn handle");
    if (!txn) {
        /* begin() succeeded — unwind it so the db isn't left with an
         * unreachable open transaction. */
        node_db_rollback(db);
        emit_rejected(label, "oom");
        return NULL;
    }

    txn->db = db;
    size_t n = strlen(label);
    if (n >= DB_TXN_LABEL_MAX) n = DB_TXN_LABEL_MAX - 1;
    memcpy(txn->label, label, n);
    txn->label[n] = '\0';
    txn->started_us = db_txn_now_us();
    txn->committed   = false;
    txn->rolled_back = false;

    emit_begin(txn->label);
    return txn;
}

bool db_txn_commit(struct db_txn *txn)
{
    if (!txn) return false;

    /* Double-finalise is a programmer bug — emit LEAKED as the audit
     * trail and refuse the operation. Do NOT free; the original
     * allocation still belongs to whoever holds the pointer. */
    if (txn->committed || txn->rolled_back) {
        emit_leaked(txn->label);
        return false;
    }

    bool ok = node_db_commit(txn->db);
    int64_t elapsed = db_txn_now_us() - txn->started_us;
    if (ok) {
        txn->committed = true;
        emit_commit(txn->label, elapsed);
    } else {
        /* SQLite can leave a transaction active after a failed COMMIT (for
         * example, a deferred foreign-key violation). node_db_commit() only
         * issues COMMIT, so explicitly unwind before relinquishing ownership.
         * If rollback itself fails, leave the handle live: scope cleanup gets
         * one more rollback attempt and emits the leak loudly. */
        bool rollback_ok = node_db_rollback(txn->db);
        txn->rolled_back = rollback_ok;
        emit_rollback(txn->label, rollback_ok
                      ? "commit_failed" : "commit_failed_rollback_failed");
    }
    return ok;
}

void db_txn_rollback(struct db_txn *txn)
{
    if (!txn) return;

    /* Rollback after commit is a harmless no-op. Some callers run
     * an error-path cleanup that rolls back without knowing whether
     * a prior commit succeeded — tolerate that. */
    if (txn->committed || txn->rolled_back) return;

    node_db_rollback(txn->db);
    emit_rollback(txn->label, "explicit");
    txn->rolled_back = true;
}

/* ── RAII cleanup helper ────────────────────────────────────── */

void db_txn_auto_rollback(struct db_txn **p)
{
    if (!p || !*p) return;
    struct db_txn *txn = *p;
    *p = NULL;  /* defensive: prevent re-entry if called twice */

    if (txn->committed || txn->rolled_back) {
        /* Clean path: the caller finalised before falling out of
         * scope. Just release the handle. */
        free(txn);
        return;
    }

    /* Leak path: scope exited without committing OR rolling back.
     * Roll the underlying tx back and emit LEAKED so the bug is
     * visible in the event ring. */
    node_db_rollback(txn->db);
    emit_leaked(txn->label);
    emit_rollback(txn->label, "leaked");
    free(txn);
}
