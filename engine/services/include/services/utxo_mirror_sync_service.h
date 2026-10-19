/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_mirror_sync_service — keep node.db's explorer `utxos` mirror synced
 * to the authoritative coins_kv set in progress.kv.
 *
 * WHY
 * ---
 * The live consensus reducer (engine/jobs/src/utxo_apply_stage.c) authors the
 * canonical UTXO set ONLY into coins_kv (the `coins` table in progress.kv) —
 * the store gettxoutsetinfo / the SHA3 commitment read. The node.db `utxos`
 * table is a DERIVED read model used by the block explorer, address balances,
 * the richlist, HodlWave, /explorer/stats and circulating supply. It has NO
 * forward writer on the consensus path, so after a cold import seeds `utxos`
 * once it FREEZES at the restore height while coins_kv (correctly) tracks the
 * tip. This service is the missing feeder.
 *
 * DESIGN — incremental next-frontier projection
 * ---------------------------------------------
 * coins_kv and the `utxos` mirror share the same canonical source columns
 * (txid, vout, value, height, is_coinbase, script); `utxos` adds only the
 * DERIVED script_type / address_hash / has_address, which utxo_classify_script
 * computes from a scriptPubKey. Initial construction audits and projects the
 * authoritative table once. Steady-state passes consume causal deltas over
 * [cursor, frontier), with cursor meaning the next height to apply.
 *
 * This is:
 *   - node.db-ONLY: it never touches the coins_kv write path or its commit
 *     boundary. A mirror write failure LOG_FAILs/LOG_WARNs loudly but cannot
 *     roll back or fail anything on the consensus path. The mirror is
 *     rebuildable; the chain is not.
 *   - a DERIVED projection, not consensus state — no consensus logic.
 *   - atomic: mirror rows, derived caches, commitment, and cursor share one
 *     node.db transaction.
 *   - bounded in steady state: no full-table counts or automatic rebuilds.
 *   - fail-closed: missing causal history quarantines the derived mirror for
 *     explicit recovery instead of repeatedly scanning millions of rows.
 *
 * Drift is measured only from the authoritative frontier and durable cursor;
 * a healthy equal-frontier pass is O(1).
 */

#ifndef ZCL_SERVICES_UTXO_MIRROR_SYNC_SERVICE_H
#define ZCL_SERVICES_UTXO_MIRROR_SYNC_SERVICE_H

#include "storage/utxo_mirror_schema.h"
#include "util/result.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sqlite3.h>

struct node_db;

/* ── Defaults ──────────────────────────────────────────────── */

#define UTXO_MIRROR_SYNC_DEFAULT_TICK_SECONDS 5
/* While the applied frontier is more than this many blocks below the header
 * tip we are catching up (IBD / P2P body fetch), the frontier climbs every
 * tick, and a full ~1.3M-row rebuild per tick is quadratic against sync
 * progress. The mirror is an explorer/wallet read model nothing consumes
 * mid-sync, so defer the rebuild until within this window of the tip — the
 * first near-tip pass rebuilds it once. Fail-open: if the header tip is
 * unknown the gate no-ops and the pre-existing every-tick behavior stands. */
#define UTXO_MIRROR_SYNC_NEAR_TIP_BLOCKS 200

/* ── Status ────────────────────────────────────────────────── */

enum utxo_mirror_sync_state {
    UTXO_MIRROR_SYNC_IDLE = 0,
    UTXO_MIRROR_SYNC_RUNNING,
    UTXO_MIRROR_SYNC_STOPPED,
};

enum utxo_mirror_health_state {
    UTXO_MIRROR_HEALTHY = 0,
    UTXO_MIRROR_AUDITING,
    UTXO_MIRROR_QUARANTINED,
};

/* Operator rebuild as a job on the mirror thread. A wholesale rebuild outlasts
 * the node RPC deadline (10 s client, 10 s server kill) and would pin one of
 * the four RPC workers, so the RPC only REQUESTS it; the mirror thread runs it
 * between passes and records the typed outcome here for the caller to poll. */
enum utxo_mirror_job_state {
    UTXO_MIRROR_JOB_IDLE = 0,    /* no job recorded since boot */
    UTXO_MIRROR_JOB_PENDING,     /* requested, not yet picked up */
    UTXO_MIRROR_JOB_RUNNING,
    UTXO_MIRROR_JOB_DONE,        /* result/reason valid */
};

struct utxo_mirror_rebuild_job {
    uint64_t id;                 /* 0 until the first request */
    int      state;              /* enum utxo_mirror_job_state */
    int64_t  result;             /* rows written, or a negative UTXO_MIRROR_REBUILD_* */
    char     reason[96];         /* refusal token, empty if none */
    bool     quarantined;        /* mirror_health at completion */
    int64_t  mirror_height;      /* last_mirror_height at completion */
};

struct utxo_mirror_sync_service {
    /* References (not owned) */
    struct node_db *ndb;

    /* Config: written once by utxo_mirror_sync_init() before the background
     * thread is spawned and never mutated again — pthread_create's
     * happens-before guarantee makes a plain read from the background
     * thread (and from utxo_mirror_sync_dump_state_json on any thread)
     * race-free without atomics. */
    int tick_seconds;

    /* Thread management */
    pthread_t thread;
    /* Flipped by start()/stop() (boot/shutdown callers) and read from
     * utxo_mirror_sync_dump_state_json() on the diagnostics/native thread —
     * genuinely cross-thread, so _Atomic + atomic_store/atomic_load. */
    _Atomic bool thread_started;
    _Atomic bool stop_requested;

    /* Startup synchronization: start() blocks until the thread is live. */
    pthread_mutex_t ready_mutex;
    pthread_cond_t  ready_cond;
    bool            ready;

    /* Progress (atomics for lock-free reads). */
    _Atomic int     state;
    _Atomic int64_t rebuilds_run;       /* total wholesale rebuilds performed */
    _Atomic int64_t delta_passes_run;   /* successful incremental passes */
    _Atomic int64_t delta_rows_changed; /* incremental add/delete operations */
    _Atomic int64_t quarantines_total;  /* causal-delta/checkpoint failures */
    _Atomic int64_t rows_written;       /* total mirror rows REPLACEd (cumulative) */
    _Atomic int64_t last_mirror_height; /* cursor after the last successful pass */
    _Atomic int64_t last_frontier;      /* coins_kv applied frontier last observed */
    _Atomic int64_t last_pass_unix;     /* wall time of last pass */
    _Atomic int64_t last_error_unix;    /* wall time of last failed pass (0 = none) */
    _Atomic int64_t last_quarantine_unix;
    _Atomic int mirror_health;          /* enum utxo_mirror_health_state */

    /* Seqlock-style audit guard. A node.db mirror update changes the
     * generation at BEGIN and END and holds updates_active > 0 for the
     * complete write lane. */
    _Atomic uint64_t update_generation;
    _Atomic uint32_t updates_active;

    /* Operator rebuild job record (see utxo_mirror_rebuild_request). */
    pthread_mutex_t job_mutex;
    struct utxo_mirror_rebuild_job job;
};

/* Global pointer for RPC/native/diagnostics access. Set by boot, NULL before. */
extern struct utxo_mirror_sync_service *g_utxo_mirror_sync;

/* ── Lifecycle ─────────────────────────────────────────────── */

/* Initialize the service struct (does NOT start the thread). Reads
 * ZCL_UTXO_MIRROR_TICK_SECONDS env (optional override). */
void utxo_mirror_sync_init(struct utxo_mirror_sync_service *svc,
                           struct node_db *ndb);

/* Launch the background thread. Non-ok if already running or ndb is NULL. */
struct zcl_result utxo_mirror_sync_start(struct utxo_mirror_sync_service *svc);

/* Signal + join the background thread. Safe to call if not started. */
void utxo_mirror_sync_stop(struct utxo_mirror_sync_service *svc);

/* Run a single sync pass synchronously: initialize an empty mirror once, then
 * apply causal changes over [cursor, frontier). Returns changed mirror rows
 * (0 when already in sync), or -1 on a logged error/quarantine.
 * Exposed for tests and for an explicit one-shot from the diagnostics path. */
int64_t utxo_mirror_sync_run_once(struct utxo_mirror_sync_service *svc);

/* Capture an idle mirror-update generation for cross-store auditors. Returns
 * false while a mirror update is active. A NULL global service is idle at
 * generation zero (tests/early boot: there is no concurrent mirror writer). */
bool utxo_mirror_sync_audit_snapshot(uint64_t *generation_out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
/* Typed failures of a wholesale rebuild (negative return of
 * utxo_mirror_rebuild_now). Ordinary failures establish no successful repair;
 * an opened write transaction is rolled back. UNSETTLED means restoration
 * is unproven after failed rollback; quarantine remains. */
#define UTXO_MIRROR_REBUILD_ERROR            (-1)
#define UTXO_MIRROR_REBUILD_STOPPED          (-2)
#define UTXO_MIRROR_REBUILD_VERIFY_MISMATCH  (-3)
#define UTXO_MIRROR_REBUILD_UNSETTLED        (-4)
/* Refused before any write: the RAM coins overlay is active (its pending set
 * can differ from the durable rows the copy scans), or the durable source
 * failed the authority proof (reason token via utxo_mirror_rebuild_now_reason). */
#define UTXO_MIRROR_REBUILD_OVERLAY_ACTIVE   (-5)
#define UTXO_MIRROR_REBUILD_REFUSED          (-6)

/* Operator repair: rebuild the whole mirror from ONE coins_kv snapshot, verify
 * the staged rows against that snapshot's SHA3 commitment, and only then
 * commit (the commit is the atomic swap). Clears quarantine on success and
 * leaves it set on failure. UNSETTLED requires operator inspection; do not
 * assume the previous mirror was restored. Returns rows written, or a negative
 * UTXO_MIRROR_REBUILD_* code. Never writes coins_kv. */
int64_t utxo_mirror_rebuild_now(struct utxo_mirror_sync_service *svc);

/* As utxo_mirror_rebuild_now, additionally copying a short machine-readable
 * refusal token (empty unless REFUSED / OVERLAY_ACTIVE) into reason. */
int64_t utxo_mirror_rebuild_now_reason(struct utxo_mirror_sync_service *svc,
                                       char *reason, size_t reason_cap);

/* Request an operator rebuild on the mirror thread. Returns 0 and the new job
 * id when queued; 1 and the active job's id when one is already pending or
 * running (nothing queued); -1 when no mirror thread is running to serve it. */
int utxo_mirror_rebuild_request(struct utxo_mirror_sync_service *svc,
                                uint64_t *id_out);

/* Copy the current job record (consistent snapshot). */
void utxo_mirror_rebuild_job_snapshot(struct utxo_mirror_sync_service *svc,
                                      struct utxo_mirror_rebuild_job *out);

/* Run the pending job, if any, on the calling thread (the mirror thread's
 * loop; tests drive it directly). 1 when a job ran, else 0. */
int utxo_mirror_rebuild_job_service(struct utxo_mirror_sync_service *svc);

#ifdef ZCL_TESTING
/* Deterministic fault injection for the private rebuild writer: the scan
 * fails after its first row; ROLLBACK_FAILS additionally reports the writer
 * rollback as failed, CLOSE_BUSY reports the writer close as SQLITE_BUSY.
 * COMMIT_THEN_CLOSE_BUSY lets the copy and COMMIT succeed, then reports the
 * writer close as SQLITE_BUSY (the post-commit teardown branch).
 * Consumed by one rebuild. */
enum utxo_mirror_test_fault { UMS_FAULT_NONE, UMS_FAULT_ROLLBACK_FAILS,
                              UMS_FAULT_COMMIT_THEN_CLOSE_BUSY,
                              UMS_FAULT_CLOSE_BUSY };
void utxo_mirror_sync_test_set_fault(enum utxo_mirror_test_fault fault);

/* Called with the private writer's sqlite handle right after it opens (before
 * BEGIN IMMEDIATE), so a fixture can attach authorizer/trace/progress faults to
 * the connection the rebuild really writes through. NULL clears. */
/* Called after the authority proof passed, before the post-authority overlay
 * check (the snapshot-establishment boundary). NULL clears. */
void utxo_mirror_sync_test_set_post_authority_hook(void (*fn)(void *), void *ctx);

void utxo_mirror_sync_test_set_writer_hook(void (*fn)(sqlite3 *writer, void *ctx),
                                           void *ctx);
#endif

/* Test seam: called inside a wholesale rebuild after the caller read the
 * frontier and before the rebuild opens its snapshot, so a test can advance
 * coins_kv in that window. NULL clears. Never set in production. */
void utxo_mirror_sync_test_set_pre_snapshot_hook(void (*fn)(void *), void *ctx);

/* Prepare the key-ordered (txid, vout, value, height) scan of the mirror for the
 * authority-vs-projection audit. The mirror reader lives in this unit so the
 * utxos-mirror reader freeze (check-no-utxos-mirror-read) stays closed. */
int utxo_mirror_prepare_key_scan(sqlite3 *db, sqlite3_stmt **out);

struct json_value;
bool utxo_mirror_sync_dump_state_json(struct json_value *out,
                                      const char *key);

#endif /* ZCL_SERVICES_UTXO_MIRROR_SYNC_SERVICE_H */
