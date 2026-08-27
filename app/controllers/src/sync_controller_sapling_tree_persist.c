/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Sapling tree persist machinery for the sync controller.
 *
 * Split out of sync_controller_sapling_tree.c: the BEGIN-retry + atomic
 * (tree-blob, height) persist path, kept separate from the replay loop so
 * each file stays under the E1 size ceiling. The DEFERRED contract (never
 * nest a BEGIN on a connection already holding a foreign open tx) lives here;
 * the rebuild replay consumes it via sapling_tree_persist_pair_status(). */

#include "controllers/sync_controller.h"
#include "sync_controller_internal.h"

#include "models/database.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* The deferred/live rebuild shares the reducer's
 * node_db connection from another thread, so a persist's BEGIN can nest into
 * the reducer's open batch tx (SQLITE_ERROR, un-retryable), spamming on
 * every checkpoint while the rebuild never completes. The primary cure is the
 * autocommit guard in sapling_tree_persist_pair_status; this bounded retry is
 * the residual defense for a genuine cross-connection BUSY/LOCKED. */
#define SAPLING_TREE_BEGIN_MAX_ATTEMPTS 5
#define SAPLING_TREE_BEGIN_BACKOFF_MS   60
#define SAPLING_TREE_FOREIGN_TX_MAX_DEFERRALS 4

/* Deferrals belong to one calling persist lane. The deferred rebuild is
 * single-threaded, but other callers may persist under their own threads, so
 * a process-global counter would combine unrelated transactions and fire a
 * false livelock blocker. Cap at the threshold to avoid overflow during a
 * genuinely stuck legacy caller. */
static _Thread_local int t_sapling_foreign_tx_deferrals = 0;
static _Thread_local bool t_sapling_foreign_tx_blocker_raised = false;

static void sapling_tree_raise_persist_livelock_blocker(int64_t height)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
            "persist deferring height=%lld after %d attempts: foreign open "
            "transaction on shared reducer connection",
            (long long)height, SAPLING_TREE_FOREIGN_TX_MAX_DEFERRALS);
    struct blocker_record rec;
    if (blocker_init(&rec, "sapling_tree_rebuild.persist_busy",
                     "sync.sapling_tree_rebuild", BLOCKER_TRANSIENT, reason)) {
        rec.retry_budget = SAPLING_TREE_FOREIGN_TX_MAX_DEFERRALS;
        blocker_set(&rec);
    }
    LOG_WARN("sapling_tree_rebuild", "%s", reason);
}

bool sapling_tree_open_persist_lane(struct node_db *reducer_ndb,
                                    struct node_db *persist_ndb,
                                    int height)
{
    if (persist_ndb)
        memset(persist_ndb, 0, sizeof(*persist_ndb));
    bool opened = reducer_ndb && persist_ndb && reducer_ndb->path[0] &&
        strcmp(reducer_ndb->path, ":memory:") != 0 &&
        node_db_open_runtime(persist_ndb, reducer_ndb->path,
                             "sync.sapling_tree_rebuild");
    if (opened)
        return true;

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
            "dedicated persist connection open failed height=%d path=%.170s",
            height, reducer_ndb && reducer_ndb->path[0]
                ? reducer_ndb->path : "(unavailable)");
    struct blocker_record rec;
    if (blocker_init(&rec, "sapling_tree_rebuild.persist_busy",
                     "sync.sapling_tree_rebuild", BLOCKER_TRANSIENT, reason))
        blocker_set(&rec);
    LOG_ERROR("sapling_tree_rebuild", "%s", reason);
    return false;
}

#ifdef ZCL_TESTING
/* See controllers/sync_controller.h. 0 = disabled (real node_db_begin runs);
 * >0 = decrementing count of forced-busy attempts; <0 = forced busy forever
 * (stays negative — never reaches 0). */
static _Atomic int g_sapling_begin_force_busy = 0;

void sapling_tree_rebuild_test_force_begin_busy(int attempts)
{
    atomic_store(&g_sapling_begin_force_busy, attempts);
}

/* Counts persists DEFERRED because the shared node_db connection already held
 * a foreign open tx (the real production failure). Lets a test assert the
 * deferral path actually FIRED, not just "no crash". */
static _Atomic int g_sapling_persist_deferrals = 0;

int sapling_tree_rebuild_test_persist_deferrals(void)
{
    return atomic_load(&g_sapling_persist_deferrals);
}

void sapling_tree_rebuild_test_reset_persist_deferrals(void)
{
    atomic_store(&g_sapling_persist_deferrals, 0);
}
#endif

/* Single BEGIN attempt. Returns true + rc=SQLITE_OK on success, false + the
 * sqlite result code on failure. Under ZCL_TESTING the fault-injection counter
 * above can substitute a simulated SQLITE_BUSY without touching the real
 * connection, so the retry/backoff/blocker logic is deterministically tested. */
static bool sapling_tree_do_begin(struct node_db *ndb, int *rc_out)
{
#ifdef ZCL_TESTING
    int remaining = atomic_load(&g_sapling_begin_force_busy);
    if (remaining != 0) {
        if (remaining > 0)
            atomic_fetch_sub(&g_sapling_begin_force_busy, 1);
        *rc_out = SQLITE_BUSY;
        return false;
    }
#endif
    /* BEGIN IMMEDIATE acquires the writer reservation here, so a dedicated
     * persist connection sees cross-connection contention as BUSY/LOCKED in
     * this bounded retry loop instead of succeeding with a deferred BEGIN and
     * discovering the lock only during the first state mutation. */
    if (node_db_begin_immediate(ndb)) {
        *rc_out = SQLITE_OK;
        return true;
    }
    struct node_db_status st;
    node_db_get_status(ndb, &st);
    *rc_out = st.last_sqlite_rc;
    return false;
}

/* Bounded retry + linear backoff around node_db_begin() for a GENUINE
 * SQLITE_BUSY/LOCKED — a lock lost to another CONNECTION (e.g. the periodic
 * WAL-checkpoint thread), the one contention class that clears on its own.
 * The nested-BEGIN case (a foreign tx open on THIS connection → SQLITE_ERROR
 * "cannot start a transaction within a transaction", which can NEVER clear by
 * retrying) is filtered out upstream by the sqlite3_get_autocommit() guard in
 * sapling_tree_persist_pair_status, so this loop only ever sees the retryable
 * class. Correct classification depends on node_db_begin now preserving the
 * real rc (app/models/src/database.c). Bounded attempts + name-a-blocker on
 * exhaustion (no log spam); waits only on the CALLING thread, so it cannot
 * block the reducer drive (LOCK-ORDER LAW). */
static bool sapling_tree_begin_with_retry(struct node_db *ndb, int64_t height)
{
    for (int attempt = 1; attempt <= SAPLING_TREE_BEGIN_MAX_ATTEMPTS;
         attempt++) {
        int rc = SQLITE_OK;
        if (sapling_tree_do_begin(ndb, &rc))
            return true;

        bool busy = (rc == SQLITE_BUSY || rc == SQLITE_LOCKED);
        bool exhausted = (attempt == SAPLING_TREE_BEGIN_MAX_ATTEMPTS);

        if (!busy || exhausted) {
            char reason[BLOCKER_REASON_MAX];
            snprintf(reason, sizeof(reason),
                    "persist_pair BEGIN failed height=%lld attempt=%d/%d "
                    "rc=%d (%s)", (long long)height, attempt,
                    SAPLING_TREE_BEGIN_MAX_ATTEMPTS, rc,
                    sqlite3_errstr(rc));
            struct blocker_record rec;
            if (blocker_init(&rec, "sapling_tree_rebuild.persist_busy",
                             "sync.sapling_tree_rebuild",
                             BLOCKER_TRANSIENT, reason))
                blocker_set(&rec);
            LOG_WARN("sapling_tree_rebuild", "%s", reason);
            return false;
        }

        int64_t backoff_ms = (int64_t)SAPLING_TREE_BEGIN_BACKOFF_MS * attempt;
        struct timespec ts = {
            .tv_sec = backoff_ms / 1000,
            .tv_nsec = (backoff_ms % 1000) * 1000000L,
        };
        nanosleep(&ts, NULL);
    }
    return false;
}

/* lane/sapling-tree-persist: persist node_state["sapling_tree"] and
 * node_state["sapling_tree_rebuild_height"] as ONE atomic write so a crash
 * can never pair the tree blob with a stale/absent height (the boot-time
 * loader, config/src/boot.c sapling_tree_verify_at_saved_height, trusts that
 * pairing). When the reducer already holds the batch (ndb->sync_in_batch) the
 * pair folds into that outer tx instead of nesting a BEGIN.
 *
 * lane/e3-sapling-rebuild-robust: NEVER nest a BEGIN on a connection that
 * already holds an open tx. The deferred/live rebuild runs on a thread OTHER
 * than the reducer while SHARING the reducer's FULLMUTEX node_db handle; the
 * reducer's batch (sync_controller_blocks.c) keeps a tx open across many
 * blocks. A BEGIN into that live tx returns SQLITE_ERROR "cannot start a
 * transaction within a transaction" — un-retryable while the outer tx lives,
 * the real production failure the old BUSY/LOCKED retry could never clear.
 * ndb->sync_in_batch only tracks the reducer's OWN bookkeeping (and lags a
 * live tx in the begin→flag-set window), so gate the own-BEGIN decision on the
 * ACTUAL connection state via sqlite3_get_autocommit(): a foreign open tx is a
 * transient timing condition, not a state error — DEFER (write nothing) and
 * let the caller retry once the connection returns to autocommit. */
enum sapling_persist_status
sapling_tree_persist_pair_status(struct node_db *ndb,
                                 const void *blob, size_t blob_len,
                                 int64_t height)
{
    bool own_tx = ndb && !ndb->sync_in_batch;
    if (own_tx) {
        if (ndb->db && sqlite3_get_autocommit(ndb->db) == 0) {
#ifdef ZCL_TESTING
            atomic_fetch_add(&g_sapling_persist_deferrals, 1);
#endif
            if (t_sapling_foreign_tx_deferrals <
                SAPLING_TREE_FOREIGN_TX_MAX_DEFERRALS)
                t_sapling_foreign_tx_deferrals++;
            if (t_sapling_foreign_tx_deferrals ==
                    SAPLING_TREE_FOREIGN_TX_MAX_DEFERRALS &&
                !t_sapling_foreign_tx_blocker_raised) {
                sapling_tree_raise_persist_livelock_blocker(height);
                t_sapling_foreign_tx_blocker_raised = true;
            } else {
                if (!t_sapling_foreign_tx_blocker_raised)
                    LOG_INFO("sapling_tree_rebuild",
                            "persist_pair: deferring height=%lld — connection "
                            "holds a foreign open transaction (reducer batch); "
                            "attempt=%d/%d",
                            (long long)height,
                            t_sapling_foreign_tx_deferrals,
                            SAPLING_TREE_FOREIGN_TX_MAX_DEFERRALS);
            }
            return SAPLING_PERSIST_DEFERRED;
        }
        if (!sapling_tree_begin_with_retry(ndb, height)) {
            t_sapling_foreign_tx_deferrals = 0;
            t_sapling_foreign_tx_blocker_raised = false;
            return SAPLING_PERSIST_FAILED;
        }
    }

    bool ok = node_db_state_set(ndb, "sapling_tree", blob, blob_len) &&
              node_db_state_set_int(ndb, "sapling_tree_rebuild_height",
                                    height);

    if (own_tx) {
        if (ok) {
            ok = node_db_commit(ndb);
        } else {
            node_db_rollback(ndb);
        }
    }
    if (own_tx && ok && t_sapling_foreign_tx_blocker_raised)
        blocker_clear("sapling_tree_rebuild.persist_busy");
    if (own_tx && ok) {
        t_sapling_foreign_tx_deferrals = 0;
        t_sapling_foreign_tx_blocker_raised = false;
    }
    return ok ? SAPLING_PERSIST_OK : SAPLING_PERSIST_FAILED;
}

bool sapling_tree_persist_pair_in_open_tx(struct node_db *ndb,
                                          const void *blob, size_t blob_len,
                                          int64_t height)
{
    if (!ndb || !ndb->open || !ndb->db || !blob || blob_len == 0)
        LOG_FAIL("sapling_tree_rebuild",
                 "persist_pair_in_open_tx: invalid args at height=%lld",
                 (long long)height);
    if (sqlite3_get_autocommit(ndb->db) != 0)
        LOG_FAIL("sapling_tree_rebuild",
                 "persist_pair_in_open_tx: caller has no open transaction "
                 "at height=%lld", (long long)height);

    return node_db_state_set(ndb, "sapling_tree", blob, blob_len) &&
           node_db_state_set_int(ndb, "sapling_tree_rebuild_height", height);
}

/* Public bool wrapper (unchanged signature — external callers in
 * wallet_rescan_controller_witness.c and boot_refold_staged.c either own
 * their transaction explicitly or run from the deferred rebuild lane, so
 * OK-vs-not-OK is all they need). The block-index writers use the explicit
 * in-open-tx entry point above; transaction ownership must not be inferred
 * from shared connection state. */
bool sapling_tree_persist_pair(struct node_db *ndb,
                               const void *blob, size_t blob_len,
                               int64_t height)
{
    return sapling_tree_persist_pair_status(ndb, blob, blob_len, height)
           == SAPLING_PERSIST_OK;
}
