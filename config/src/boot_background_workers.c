#define _GNU_SOURCE  /* pthread_timedjoin_np */
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot background-workers unit — long-lived helper threads spawned by
 * app_init_services at scattered points during runtime startup and joined by
 * app_shutdown_svc. Start/join helpers remain exposed through
 * boot_background_workers.h and preserve their boot_services.c order.
 * Workers: payment_processor_thread, address_backfill_service_thread,
 * hodl_history_worker_thread, projection_backfill_service_thread. (The
 * fast-sync snapshot-offer worker moved to boot_snapshot_offer.c and the
 * background UTXO-replay worker moved to boot_utxo_replay.c, both to keep
 * this file under E1; both share the worker_on_stall and registration helpers
 * implemented in boot_worker_supervisor.c.)
 * The worker bodies reach the boot context through the boot_services.c
 * accessors (boot_node_db / boot_db_service / boot_running /
 * boot_profile_has_file_service / boot_start_catchup_service /
 * boot_reap_catchup_service) declared in boot_internal.h. The generic thread
 * helpers move here; boot_join_thread_bounded is re-exported because the
 * catchup-job helpers that stay in boot_services.c reuse it.
 */
#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "config/boot_internal.h"
#include "config/boot_background_workers.h"
#include "config/boot_projection_hole_scan.h"
#include "config/boot_snapshot_import.h"
#include "services/hodl_history_service.h"
#include "services/node_db_catchup_service.h"
#include "services/chain_state_service.h"
#include "controllers/store_controller.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"  /* refold_in_progress — suppress projection
                                    * backfill while a mint/refold discards the
                                    * upper tip (see the guard below). */
#include "models/block.h"
#include "event/event.h"
#include "supervisors/domains.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/path_check.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_qos.h"
#include <stdatomic.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>

extern void *backfill_addresses_thread(void *arg);

/* Worker bodies — forward-declared so the start/join pairs below can name them
 * before their definitions further down (matching the original boot_services.c
 * forward declarations). */
static void *payment_processor_thread(void *arg);
static void *address_backfill_service_thread(void *arg);

static bool payment_processor_lane_write(struct node_db *ndb, void *arg)
{
    struct boot_svc_ctx *svc = arg;
    if (!svc || !svc->datadir)
        LOG_FAIL("store", "payment processor lost its runtime owner");
    store_process_payments_with_db(ndb, svc->datadir);
    return true;
}

/* ── Supervisor liveness (Model A — MONITOR; disk_monitor.c exemplar) ─
 *
 * Each background worker keeps its own pthread and gains an observe-only
 * liveness_contract registered ONCE in its domain at the worker's
 * boot_start_*_service. The supervisor never owns or tears down these
 * threads (period_secs == 0); it only watches the heartbeat the worker
 * emits and fires on_stall (log + EV_RECOVERY_ACTION) when the deadline
 * lapses. Behaviour-preserving — it cannot wedge a worker. (The
 * snapshot-offer worker follows the same model from boot_snapshot_offer.c,
 * sharing the helpers below.)
 *
 * Deadline/quiet (set at register; rationale at each heartbeat site):
 * looping workers (payment, projection_backfill, hodl_history) tick +
 * advance a progress marker once per loop; the two single-blocking-call
 * workers (utxo_replay, address_backfill) tick at entry/exit only and are
 * DEADLINE-ONLY (quiet 0) with a generous deadline so a legitimately long
 * call does not false-fire. Shared stall/register helper bodies live in
 * boot_worker_supervisor.c. */

#define PAYMENT_SUPERVISOR_DEADLINE_SEC             120
#define PROJECTION_BACKFILL_SUPERVISOR_DEADLINE_SEC 120
/* NO_PROGRESS window for op.projection_backfill. While BEHIND the marker is the
 * projection cursor height, so a cursor frozen this long (a genuinely stuck
 * backfill, e.g. hole-repair exhausted) surfaces as SUPERVISOR_STALL_NO_PROGRESS
 * instead of hiding behind a loop counter. A caught-up / mid-refold worker beats
 * a synthetic marker instead, so quiescence at the tip never trips this.
 * Generous vs a healthy-but-slow catchup; the deadline gate still catches a
 * fully dead (non-ticking) thread. */
#define PROJECTION_BACKFILL_PROGRESS_QUIET_US       (600LL * 1000000)
/* At-tip synthetic-beat base: above any plausible height so a beat marker never
 * equals a cursor-height marker (disjoint marker namespaces). */
#define PROJECTION_BACKFILL_AT_TIP_BEAT_BASE        (1LL << 40)
/* Terminal projection-stuck typed blocker (hole-repair budget spent, missing
 * connected block still absent). Stable id — height lives in the reason — so the
 * per-loop refresh dedups and the recovery clear finds it. TRANSIENT + escape
 * deadline, no escape_action: the fixed blocker sweep re-arms a bounded number
 * of times then marks it `escalated`, never a growing-negative deadline. */
#define PROJECTION_STUCK_BLOCKER_ID                 "worker.projection_stuck"
#define PROJECTION_STUCK_ESCAPE_DEADLINE_SEC        300
#define HODL_HISTORY_SUPERVISOR_DEADLINE_SEC        900
#define ADDRESS_BACKFILL_SUPERVISOR_DEADLINE_SEC    600
#define HODL_HISTORY_FILL_BATCH                     1
#define HODL_HISTORY_BACKLOG_SLEEP_SEC              1
#define HODL_HISTORY_IDLE_SLEEP_SEC                 15

struct hodl_history_fill_ctx {
    int chain_tip;
    int filled;
};

static bool hodl_history_fill_pending_write(struct node_db *ndb, void *ctx)
{
    struct hodl_history_fill_ctx *fill = ctx;

    if (!ndb || !ndb->open || !ndb->db || !fill)
        return false;
    app_runtime_node_db_sync_flush_if_needed(ndb);
    fill->filled = hodl_history_fill_pending(
        ndb->db, fill->chain_tip, HODL_HISTORY_FILL_BATCH);
    return true;
}

static struct liveness_contract g_payment_contract;
static struct liveness_contract g_projection_backfill_contract;
static struct liveness_contract g_hodl_history_contract;
static struct liveness_contract g_address_backfill_contract;

static _Atomic supervisor_child_id g_payment_sup_id = SUPERVISOR_INVALID_ID;
static _Atomic supervisor_child_id g_projection_backfill_sup_id =
    SUPERVISOR_INVALID_ID;
static _Atomic supervisor_child_id g_hodl_history_sup_id =
    SUPERVISOR_INVALID_ID;
static _Atomic supervisor_child_id g_address_backfill_sup_id =
    SUPERVISOR_INVALID_ID;

/* ── Generic boot thread helpers ───────────────────────────── */

/* Exposed via boot_background_workers.h (single source) so the snapshot-offer
 * worker lifted into boot_snapshot_offer.c spawns/joins through the same
 * plumbing rather than carrying its own raw pthread_create. */
bool boot_start_thread_service(pthread_t *thread,
                                      bool *started,
                                      void *(*entry)(void *),
                                      void *arg)
{
    if (!thread || !started || !entry || *started)
        return false;
    /* Generic boot service starter wrapper for composition-owned helper
     * threads. Callers own the pthread_t and join it explicitly. A
     * thread_registry_spawn equivalent here would require a
     * name-from-caller param; deferred to a focused follow-up.
     * raw-pthread-ok */
    if (pthread_create(thread, NULL, entry, arg) != 0)
        return false;
    *started = true;
    return true;
}

static void boot_join_deadline_from_now(struct timespec *ts, int timeout_sec)
{
    platform_time_realtime_timespec(ts);
    if (timeout_sec < 0)
        timeout_sec = 0;
    ts->tv_sec += timeout_sec;
}

bool boot_join_thread_bounded(pthread_t thread,
                              const char *name,
                              int timeout_sec)
{
    struct timespec deadline;
    int rc;

    boot_join_deadline_from_now(&deadline, timeout_sec);
    rc = platform_thread_join_until(thread, NULL, &deadline);
    if (rc == 0)
        return true;

    if (rc == ETIMEDOUT) {
        fprintf(stderr,
                "[shutdown] %s join timed out after %ds; retaining ownership\n",
                name ? name : "thread", timeout_sec);
    } else {
        fprintf(stderr,
                "[shutdown] %s join failed rc=%d (%s); retaining ownership\n",
                name ? name : "thread", rc, strerror(rc));
    }
    pthread_join(thread, NULL);
    return false;
}

void boot_join_thread_service_named(pthread_t *thread,
                                           bool *started,
                                           const char *name,
                                           int timeout_sec)
{
    if (!thread || !started || !*started)
        return;
    boot_join_thread_bounded(*thread, name, timeout_sec);
    *started = false;
}

/* ── Start/join pairs ──────────────────────────────────────── */

bool boot_start_payment_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    boot_register_worker_supervisor(&g_payment_sup_id, &g_payment_contract,
                                    &g_op_sup, "op.payment_processor",
                                    PAYMENT_SUPERVISOR_DEADLINE_SEC, 0);
    return boot_start_thread_service(&svc->payment_thread,
                                     &svc->payment_thread_started,
                                     payment_processor_thread, svc);
}

void boot_join_payment_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return;
    boot_join_thread_service_named(&svc->payment_thread,
                                   &svc->payment_thread_started,
                                   "payment", 5);
}

bool boot_start_address_backfill_service(struct boot_svc_ctx *svc)
{
    if (!svc || !svc->datadir)
        return false;
    boot_register_worker_supervisor(&g_address_backfill_sup_id,
                                    &g_address_backfill_contract, &g_chain_sup,
                                    "chain.address_backfill",
                                    ADDRESS_BACKFILL_SUPERVISOR_DEADLINE_SEC, 0);
    return boot_start_thread_service(&svc->address_backfill_thread,
                                     &svc->address_backfill_thread_started,
                                     address_backfill_service_thread, svc);
}

void boot_join_address_backfill_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return;
    boot_join_thread_service_named(&svc->address_backfill_thread,
                                   &svc->address_backfill_thread_started,
                                   "address_backfill", 5);
}

bool boot_start_tx_index_service(struct boot_svc_ctx *svc)
{
    if (!svc || !svc->datadir ||
        snapshot_tx_index_job_is_started(&svc->tx_index_job))
        return false;
    return snapshot_tx_index_job_start(&svc->tx_index_job, svc->datadir);
}

/* HODL history worker.
 *
 * Fills the hodl_history table incrementally so /explorer/hodl can
 * render a time-series of "% of supply held > 1 year" without
 * recomputing on every page hit. The worker walks every ~day
 * (HODL_HISTORY_SAMPLE_STRIDE blocks) up to the current chain tip,
 * idempotent on already-filled rows. It drains a bounded backlog quickly
 * after restart/rebuild, then falls back to a slow idle tick once current. */
static void *hodl_history_worker_thread(void *arg)
{
    struct boot_svc_ctx *svc = arg;
    int64_t loop_iterations = 0;

    /* Genuinely-background bulk backfill (linger-style HODL history
     * fill) — never the reducer/net/RPC/tip-follow path (lane/os-armor). */
    zcl_thread_qos_background();

    if (!svc) {
        boot_complete_worker_supervisor(&g_hodl_history_sup_id);
        return NULL;
    }
    /* Settle but observe shutdown once per second (never sleep(15)). */
    for (int i = 0; i < HODL_HISTORY_IDLE_SLEEP_SEC &&
                    !svc->hodl_history_thread_stop; i++)
        sleep(1);
    while (!svc->hodl_history_thread_stop) {
        supervisor_child_id sup_id = atomic_load(&g_hodl_history_sup_id);
        if (sup_id != SUPERVISOR_INVALID_ID) {
            supervisor_tick(sup_id);
            supervisor_progress(sup_id, ++loop_iterations);
            boot_worker_clear_stall_blocker(&g_hodl_history_contract);
        }
        if (svc->state) {
            int tip = active_chain_height(&svc->state->chain_active);
            if (tip > 0) {
                struct db_service *dbsvc = boot_db_service(svc);
                struct node_db *ndb = boot_node_db(svc);
                struct hodl_history_fill_ctx fill = {
                    .chain_tip = tip,
                    .filled = 0,
                };
                int filled = 0;
                if (dbsvc && ndb && ndb->open &&
                    db_service_run_write(
                        dbsvc, hodl_history_fill_pending_write, &fill)) {
                    filled = fill.filled;
                } else {
                    LOG_WARN("service",
                             "HODL history: db service unavailable; "
                             "will retry");
                }
                int sleep_secs = filled >= HODL_HISTORY_FILL_BATCH
                    ? HODL_HISTORY_BACKLOG_SLEEP_SEC
                    : HODL_HISTORY_IDLE_SLEEP_SEC;
                for (int i = 0; i < sleep_secs &&
                                !svc->hodl_history_thread_stop; i++)
                    sleep(1);
                continue;
            }
        }
        for (int i = 0; i < HODL_HISTORY_IDLE_SLEEP_SEC &&
                        !svc->hodl_history_thread_stop; i++)
            sleep(1);
    }
    boot_complete_worker_supervisor(&g_hodl_history_sup_id);
    return NULL;
}

/* Name the terminal projection-stuck state as a TYPED blocker. Called every loop
 * while the hole-repair give-up state holds so the claim stays live (blocker_set
 * self-rate-limits; a re-fired TRANSIENT is not TTL-retired). */
static void projection_backfill_set_stuck_blocker(int stuck_height,
                                                   int first_missing_height,
                                                   int repair_cap,
                                                   int attempts)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "projection stuck at height %d (first missing connected height "
             "%d, repair cap %d, gave up after %d rewind attempts)",
             stuck_height, first_missing_height, repair_cap, attempts);

    struct blocker_record br;
    if (!blocker_init(&br, PROJECTION_STUCK_BLOCKER_ID,
                      "boot.background_workers", BLOCKER_TRANSIENT, reason))
        return;
    br.escape_deadline_secs = PROJECTION_STUCK_ESCAPE_DEADLINE_SEC;
    (void)blocker_set(&br);
}

/* Retire the terminal projection-stuck blocker once the hole is resolved (a
 * new/moved hole, or no hole within the repair cap). Idempotent. */
static void projection_backfill_clear_stuck_blocker(void)
{
    if (blocker_exists(PROJECTION_STUCK_BLOCKER_ID))
        blocker_clear(PROJECTION_STUCK_BLOCKER_ID);
}

static void *projection_backfill_service_thread(void *arg)
{
    struct boot_svc_ctx *svc = arg;
    int last_start_height = -1;
    int last_hole_rewind_height = -1;
    int hole_rewind_attempts = 0;
    bool hole_rewind_gave_up_reported = false;
    int last_projection_cursor = -1;
    struct boot_projection_hole_scan hole_scan;
    boot_projection_hole_scan_init(&hole_scan);
    int64_t loop_iterations = 0;

    /* Genuinely-background bulk backfill worker — never the
     * reducer/net/RPC/tip-follow path (lane/os-armor). */
    zcl_thread_qos_background();

    if (!svc) {
        boot_complete_worker_supervisor(&g_projection_backfill_sup_id);
        return NULL;
    }

    while (!svc->projection_backfill_thread_stop && boot_running(svc)) {
        struct node_db *ndb = boot_node_db(svc);
        int chain_tip = svc->state ?
            active_chain_height(&svc->state->chain_active) : -1;
        int projection_tip = -1;
        int projection_block_tip = -1;
        int first_missing_height = -1;
        bool refolding = refold_in_progress();
        int hstar = reducer_frontier_provable_tip_cached();
        int64_t header_tip = csr_header_height(csr_instance());
        bool tail_folding =
            node_db_catchup_tail_fold_in_progress(header_tip, hstar);

        /* The actual projection cursor (the height the backfill has REACHED),
         * read before the rewind logic below mutates projection_tip. This — not
         * a loop counter — is the supervisor progress marker while behind, so a
         * stuck cursor freezes the marker and NO_PROGRESS can fire. */
        int projection_cursor =
            (ndb && ndb->open) ? node_db_sync_get_tip_height(ndb) : -1;

        /* BEHIND = there is real backfill work to do and it is not being
         * intentionally suppressed by an in-progress mint/refold or canonical
         * tail fold. Only in this state is a frozen cursor a fault; a caught-up
         * (cursor >= tip) or intentionally deferred worker is
         * healthy/quiescent. */
        bool behind = !refolding && !tail_folding &&
                      projection_cursor >= 0 && chain_tip >= 0 &&
                      projection_cursor < chain_tip;
        bool cursor_frozen = behind &&
                             projection_cursor == last_projection_cursor;

        supervisor_child_id sup_id =
            atomic_load(&g_projection_backfill_sup_id);
        if (sup_id != SUPERVISOR_INVALID_ID) {
            supervisor_tick(sup_id);
            /* Progress marker: the cursor height while behind (a frozen cursor
             * freezes the marker → SUPERVISOR_STALL_NO_PROGRESS), else a
             * synthetic beat in a disjoint numeric range so quiescence at the
             * tip never false-trips the gate. */
            int64_t marker = behind
                ? (int64_t)projection_cursor
                : PROJECTION_BACKFILL_AT_TIP_BEAT_BASE + (++loop_iterations);
            supervisor_progress(sup_id, marker);
            /* Retire the stale stall blocker ONLY when the worker is healthy
             * this loop — quiescent (at tip / mid-refold) or the cursor
             * advanced. A behind-and-frozen worker skips the clear so a
             * NO_PROGRESS-raised worker.stall.* blocker stays standing until the
             * cursor moves again — advance-or-name-a-blocker, honestly. */
            bool healthy_this_loop =
                !behind || projection_cursor != last_projection_cursor;
            if (healthy_this_loop)
                boot_worker_clear_stall_blocker(
                    &g_projection_backfill_contract);
        }
        last_projection_cursor = projection_cursor;

        boot_reap_catchup_service(svc);

        /* Defer derived node.db work while a mint/refold rebuilds the upper
         * chain or canonical H* is more than one block behind header_tip.
         * Otherwise its bulk transaction can monopolize the serialized DB
         * service ahead of the canonical fold. A one-block live edge remains
         * eligible; the first loop after either fold closes resumes backfill.
         * Mirrors the ownership guards in node_db_catchup_service.c and
         * utxo_mirror_sync_service.c. */
        if (refolding || tail_folding) {
            for (int i = 0; i < 5 &&
                 !svc->projection_backfill_thread_stop &&
                 boot_running(svc); i++)
                sleep(1);
            continue;
        }

        if (ndb && ndb->open && chain_tip >= 0 &&
            !node_db_sync_catchup_job_is_started(&svc->catchup_job)) {
            projection_tip = node_db_sync_get_tip_height(ndb);
            projection_block_tip = db_block_max_height(ndb);
            bool sparse_prefix =
                boot_projection_sparse_prefix_is_expected(projection_tip,
                                                          chain_tip);
            /* node_db_catchup_service_run always starts its walk at
             * projection_tip + 1 (start = db_tip + 1), so THAT height, not
             * chain_tip, is the slot a fresh catchup pass must resolve to
             * make any progress. Checking chain_tip instead only caught the
             * single-missing-slot case; two-or-more missing top slots left
             * this false while catchup churned (start → immediate
             * first_missing_index_h - 1 == projection_tip, no advance,
             * restart every ~5 s). */
            bool next_slot_present =
                active_chain_at(&svc->state->chain_active,
                                projection_tip + 1) != NULL;
            bool sparse_tip_pending =
                node_db_catchup_sparse_tip_slot_pending(
                    sparse_prefix, projection_tip, chain_tip,
                    next_slot_present);
            if (projection_block_tip >= 0 &&
                projection_tip > projection_block_tip &&
                projection_block_tip < chain_tip &&
                !sparse_prefix) {
                struct block_index *rewind_tip =
                    active_chain_at(&svc->state->chain_active,
                                    projection_block_tip);
                if (rewind_tip && rewind_tip->phashBlock &&
                    node_db_sync_set_tip(ndb, rewind_tip->phashBlock->data,
                                         projection_block_tip)) {
                    event_emitf(EV_RECOVERY_ACTION, 0,
                                "projection-cursor-rewind from=%d to=%d",
                                projection_tip, projection_block_tip);
                    projection_tip = projection_block_tip;
                }
            }
            int repair_cap = projection_tip < chain_tip ? projection_tip : chain_tip;
            bool hole_scan_ran = false;
            bool hole_scan_ok = boot_projection_hole_scan_if_due(
                &hole_scan, ndb, repair_cap, sparse_prefix, behind,
                cursor_frozen, projection_cursor,
                (int64_t)platform_time_wall_time_t(), &hole_scan_ran,
                &first_missing_height);
            if (hole_scan_ran && hole_scan_ok &&
                first_missing_height >= 0 &&
                first_missing_height <= repair_cap &&
                !sparse_prefix) {
                if (first_missing_height != last_hole_rewind_height) {
                    last_hole_rewind_height = first_missing_height;
                    hole_rewind_attempts = 0;
                    hole_rewind_gave_up_reported = false;
                    /* New/moved hole → the previous terminal-stuck claim (if
                     * any) is stale; retire it. A fresh give-up re-raises. */
                    projection_backfill_clear_stuck_blocker();
                }
                if (hole_rewind_attempts < 3) {
                    int rewind_height = first_missing_height - 1;
                    bool rewound = false;
                    hole_rewind_attempts++;
                    if (rewind_height < 0) {
                        rewound = node_db_sync_reset_tip(ndb);
                    } else {
                        struct block_index *rewind_tip =
                            active_chain_at(&svc->state->chain_active,
                                            rewind_height);
                        rewound = rewind_tip && rewind_tip->phashBlock &&
                                  node_db_sync_set_tip(ndb,
                                                       rewind_tip->phashBlock->data,
                                                       rewind_height);
                    }
                    if (rewound) {
                        event_emitf(EV_RECOVERY_ACTION, 0,
                                    "projection-hole-rewind missing=%d "
                                    "from=%d to=%d attempt=%d",
                                    first_missing_height, projection_tip,
                                    rewind_height, hole_rewind_attempts);
                        projection_tip = rewind_height;
                    } else {
                        event_emitf(EV_RECOVERY_ACTION, 0,
                                    "projection-hole-rewind-unavailable "
                                    "missing=%d to=%d attempt=%d",
                                    first_missing_height, rewind_height,
                                    hole_rewind_attempts);
                    }
                } else {
                    /* Terminal stuck state for this hole: the rewind budget is
                     * spent and the missing connected block is still absent.
                     * Emit the give-up event ONCE (no log spam) but name the
                     * TYPED "projection stuck at height N" blocker every loop so
                     * it stays a live claim — advance-or-name-a-blocker. */
                    if (!hole_rewind_gave_up_reported) {
                        event_emitf(EV_RECOVERY_ACTION, 0,
                                    "projection-hole-repair-gave-up missing=%d "
                                    "attempts=%d cap=%d",
                                    first_missing_height, hole_rewind_attempts,
                                    repair_cap);
                        hole_rewind_gave_up_reported = true;
                    }
                    projection_backfill_set_stuck_blocker(
                        projection_tip, first_missing_height, repair_cap,
                        hole_rewind_attempts);
                }
            } else if ((hole_scan_ran && hole_scan_ok &&
                        first_missing_height < 0) || sparse_prefix) {
                last_hole_rewind_height = -1;
                hole_rewind_attempts = 0;
                hole_rewind_gave_up_reported = false;
                /* No hole within the repair cap (or an expected sparse prefix)
                 * → any terminal-stuck claim has resolved; retire it. */
                projection_backfill_clear_stuck_blocker();
            }
            if (projection_tip < chain_tip && !sparse_tip_pending) {
                if (last_start_height != chain_tip) {
                    event_emitf(EV_RECOVERY_ACTION, 0,
                                "projection-backfill-start from=%d to=%d",
                                projection_tip + 1, chain_tip);
                    last_start_height = chain_tip;
                }
                if (!boot_start_catchup_service(svc, svc->datadir)) {
                    fprintf(stderr,
                            "WARNING: projection backfill start failed "
                            "(projection=%d chain=%d)\n",
                            projection_tip, chain_tip);
                }
            }
        }

        for (int i = 0; i < 5 &&
             !svc->projection_backfill_thread_stop &&
             boot_running(svc); i++) {
            sleep(1);
        }
    }

    boot_reap_catchup_service(svc);
    boot_complete_worker_supervisor(&g_projection_backfill_sup_id);
    return NULL;
}

bool boot_start_hodl_history_service(struct boot_svc_ctx *svc)
{
    if (!svc || !svc->datadir)
        return false;
    boot_register_worker_supervisor(&g_hodl_history_sup_id,
                                    &g_hodl_history_contract, &g_op_sup,
                                    "op.hodl_history",
                                    HODL_HISTORY_SUPERVISOR_DEADLINE_SEC, 0);
    svc->hodl_history_thread_stop = false;
    return boot_start_thread_service(&svc->hodl_history_thread,
                                     &svc->hodl_history_thread_started,
                                     hodl_history_worker_thread, svc);
}

void boot_join_hodl_history_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return;
    svc->hodl_history_thread_stop = true;
    boot_join_thread_service_named(&svc->hodl_history_thread,
                                   &svc->hodl_history_thread_started,
                                   "hodl_history", 5);
}

bool boot_start_projection_backfill_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    boot_register_worker_supervisor(&g_projection_backfill_sup_id,
                                    &g_projection_backfill_contract, &g_op_sup,
                                    "op.projection_backfill",
                                    PROJECTION_BACKFILL_SUPERVISOR_DEADLINE_SEC,
                                    PROJECTION_BACKFILL_PROGRESS_QUIET_US);
    svc->projection_backfill_thread_stop = false;
    return boot_start_thread_service(&svc->projection_backfill_thread,
                                     &svc->projection_backfill_thread_started,
                                     projection_backfill_service_thread, svc);
}

void boot_join_projection_backfill_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return;
    svc->projection_backfill_thread_stop = true;
    boot_join_thread_service_named(&svc->projection_backfill_thread,
                                   &svc->projection_backfill_thread_started,
                                   "projection_backfill", 5);
}

void boot_join_tx_index_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return;
    if (!svc->tx_index_job.started)
        return;
    boot_join_thread_bounded(svc->tx_index_job.thread, "snapshot_tx_index", 5);
    svc->tx_index_job.started = false;
}

/* ── Helper threads ────────────────────────────────────────── */

/* Watchdog: detect a stuck chain and clear ONLY the TRANSIENT failure cause
 * (BLOCK_FAILED_CHILD with no BLOCK_FAILED_VALID of its own) on the next
 * block, so a child masked solely by an ancestor's now-cleared failure can be
 * retried. A block carrying its OWN BLOCK_FAILED_VALID is a deterministic,
 * self-attributed verdict (bad PoW / bad sapling root / consensus reject) that
 * a blind retry every 300s would re-admit as a forgery — leave it for the
 * re-derivation invariant (sticky-node plan #2/#11) to repair from peers. */
static void watchdog_check_stuck(struct boot_svc_ctx *svc)
{
    static int64_t last_height_change = 0;
    static int last_height = -1;

    int h = active_chain_height(&svc->state->chain_active);
    int64_t now = (int64_t)platform_time_wall_time_t();

    if (h != last_height) {
        last_height = h;
        last_height_change = now;
        return;
    }

    /* No progress for 5 minutes — try clearing the TRANSIENT failure cause on
     * the next block. We clear BLOCK_FAILED_CHILD only when the block does NOT
     * carry BLOCK_FAILED_VALID: a child failure can be stale once its ancestor
     * was repaired, whereas a self-attributed VALID failure is deterministic
     * and must NOT be blindly un-failed (that re-admits a forgery). */
    if (last_height_change > 0 && now - last_height_change > 300 && h > 100) {
        struct block_index *next = active_chain_at(
            &svc->state->chain_active, h + 1);
        if (!next) {
            /* Not in active chain — scan block map for height h+1 */
            size_t iter = 0;
            struct block_index *bi = NULL;
            while (block_map_next(&svc->state->map_block_index,
                                   &iter, NULL, &bi)) {
                if (bi && bi->nHeight == h + 1 &&
                    block_is_dependency_failed(bi) &&
                    !block_is_permanently_failed(bi)) {
                    block_index_status_clear_bits(bi, BLOCK_FAILED_CHILD);
                    fprintf(stderr, "WATCHDOG: stuck at h=%d for %llds; "
                            "cleared transient BLOCK_FAILED_CHILD on h=%d "
                            "to retry\n", h,
                            (long long)(now - last_height_change),
                            bi->nHeight);
                }
            }
        } else if (block_is_dependency_failed(next) &&
                   !block_is_permanently_failed(next)) {
            block_index_status_clear_bits(next, BLOCK_FAILED_CHILD);
            fprintf(stderr, "WATCHDOG: stuck at h=%d for %llds; cleared "
                    "transient BLOCK_FAILED_CHILD on h=%d to retry\n", h,
                    (long long)(now - last_height_change), next->nHeight);
        } else if (block_is_permanently_failed(next)) {
            /* Deterministic self-attributed failure: a blind clear would
             * re-admit a forgery. Leave it for the re-derivation invariant
             * (re-pull bytes from peers + re-run the stage) to repair. */
            fprintf(stderr, "WATCHDOG: stuck at h=%d for %llds; h=%d carries "
                    "BLOCK_FAILED_VALID (deterministic) — NOT clearing; "
                    "deferring to re-derivation\n", h,
                    (long long)(now - last_height_change), next->nHeight);
        }
        last_height_change = now; /* don't spam — wait another 5 min */
    }
}

static void *payment_processor_thread(void *arg)
{
    struct boot_svc_ctx *svc = arg;
    int64_t loop_iterations = 0;

    /* Genuinely-background linger worker (payment store processing on a
     * 30s tick) — never the reducer/net/RPC/tip-follow path
     * (lane/os-armor). */
    zcl_thread_qos_background();

    /* The frontend kernel spawns this thread BEFORE boot flips
     * svc->running true (boot_services.c starts the kernel ahead of the
     * atomic_store), so entering the while(boot_running) loop immediately
     * made the thread exit at birth on every boot: store payments never
     * ran and the orphaned supervisor contract fired the one-per-boot
     * op.payment_processor time_deadline stall. Wait (bounded) for boot
     * to finish; if it never flips, this was a real shutdown-during-boot
     * and exiting is correct. */
    for (int i = 0; i < 60 && !boot_running(svc); i++)
        sleep(1);

    while (boot_running(svc)) {
        supervisor_child_id sup_id = atomic_load(&g_payment_sup_id);
        if (sup_id != SUPERVISOR_INVALID_ID) {
            supervisor_tick(sup_id);
            supervisor_progress(sup_id, ++loop_iterations);
            boot_worker_clear_stall_blocker(&g_payment_contract);
        }
        for (int i = 0; i < 30 && boot_running(svc); i++)
            sleep(1);
        if (!boot_running(svc))
            break;
        struct db_service *dbsvc = boot_db_service(svc);
        if (!dbsvc || !db_service_run_write(
                dbsvc, payment_processor_lane_write, svc))
            LOG_WARN("store",
                     "payment scan could not enter the canonical DB lane");
        watchdog_check_stuck(svc);
    }
    boot_complete_worker_supervisor(&g_payment_sup_id);
    return NULL;
}

static void *address_backfill_service_thread(void *arg)
{
    struct boot_svc_ctx *svc = arg;
    char *db_path = NULL;
    supervisor_child_id sup_id = atomic_load(&g_address_backfill_sup_id);

    /* Genuinely-background bulk backfill worker — never the
     * reducer/net/RPC/tip-follow path (lane/os-armor). */
    zcl_thread_qos_background();

    if (!svc || !svc->datadir)
        goto done;

    /* Single blocking call: heartbeat at entry and exit only. The
     * generous deadline (600 s) tolerates a legitimately long backfill;
     * progress_max_quiet_us == 0 disables the NO_PROGRESS gate so the
     * silence between entry and exit is not mistaken for a wedge. */
    if (sup_id != SUPERVISOR_INVALID_ID)
        supervisor_tick(sup_id);

    db_path = zcl_malloc(1024, "address_backfill_db_path");
    if (!db_path)
        goto done;
    snprintf(db_path, 1024, "%s/node.db", svc->datadir);
    backfill_addresses_thread(db_path);
    free(db_path);
done:
    if (sup_id != SUPERVISOR_INVALID_ID)
        supervisor_tick(sup_id);
    boot_complete_worker_supervisor(&g_address_backfill_sup_id);
    return NULL;
}
