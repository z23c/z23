/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot background-workers unit — the long-lived helper threads that
 * app_init_services spawns at scattered points during runtime startup and
 * that app_shutdown_svc joins on teardown.
 *
 * Workers in this unit:
 *   - payment_processor_thread        (store payment scanner + tip watchdog)
 *   - address_backfill_service_thread (advisory address aggregation)
 *   - hodl_history_worker_thread      (explorer HODL time-series filler)
 *   - projection_backfill_service_thread (reducer projection catch-up)
 *
 * The fast-sync snapshot-offer worker (build_snapshot_offer_thread) moved to
 * boot_snapshot_offer.{c,h} and the background UTXO-replay worker
 * (background_utxo_replay) moved to boot_utxo_replay.{c,h}, both to keep this
 * unit under the E1 ceiling; each shares the worker_on_stall /
 * boot_register_worker_supervisor helpers declared below and implemented in
 * boot_worker_supervisor.c.
 *
 * Each worker has a boot_start_ / boot_join_ pair declared below; the start
 * calls live at their existing scattered points in app_init_services (boot
 * order preserved) and the joins in app_shutdown_svc. The generic thread
 * helpers (start/bounded-join) move with these workers; boot_join_thread_bounded
 * is exposed because the catchup-job helpers that stay in boot_services.c reuse
 * it.
 *
 * Not for use outside config/src/.
 */

#ifndef ZCL_BOOT_BACKGROUND_WORKERS_H
#define ZCL_BOOT_BACKGROUND_WORKERS_H

#include "supervisors/domains.h"
#include "util/supervisor.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct boot_svc_ctx;

/* Generic diagnostic-budget thread join used by both this unit and the
 * catchup-job helpers that remain in boot_services.c. A timeout is logged,
 * then ownership is retained until the thread exits. */
bool boot_join_thread_bounded(pthread_t thread, const char *name,
                              int timeout_sec);

/* Generic start/named-join plumbing for composition-owned helper threads.
 * Shared so the snapshot-offer worker (boot_snapshot_offer.c) spawns/joins
 * through this single source instead of carrying its own pthread_create. The
 * caller owns the pthread_t and the started flag. */
bool boot_start_thread_service(pthread_t *thread, bool *started,
                               void *(*entry)(void *), void *arg);
void boot_join_thread_service_named(pthread_t *thread, bool *started,
                                    const char *name, int timeout_sec);

/* ── Shared background-worker supervision (Shape 5 — MONITOR) ──────────
 * One observe-only stall handler + one register helper, shared by every
 * background worker in this unit AND the snapshot-offer worker that was
 * lifted into boot_snapshot_offer.c. Single source: the offer TU calls these
 * rather than duplicating them. */

/* Observe-only stall handler installed on every worker contract: logs and
 * emits EV_RECOVERY_ACTION but never blocks or tears down the worker (the
 * supervisor cannot wedge a thread it does not own). */
void worker_on_stall(struct liveness_contract *c);

/* Register a single worker contract into its domain (idempotent — the stored
 * child id guards re-registration). period_secs == 0 means the supervisor
 * never drives the worker; progress_max_quiet_us == 0 means deadline-only. */
void boot_register_worker_supervisor(
    _Atomic supervisor_child_id *slot,
    struct liveness_contract *contract,
    supervisor_domain_t **domain_slot,
    const char *name,
    int64_t deadline_secs,
    int64_t progress_max_quiet_us);

/* Retire the "worker.stall.<name>" TRANSIENT blocker that worker_on_stall may
 * have raised, once the worker is proven alive again. A looping worker calls
 * this each iteration after publishing progress so a recovered worker clears its
 * own stale blocker (the supervisor is observe-only and never re-arms or clears
 * it); a still-wedged worker never reaches the call and leaves the blocker up. */
void boot_worker_clear_stall_blocker(const struct liveness_contract *c);

/* Mark a registered worker complete after its thread exits. This does not clear
 * the slot or unregister the child, so sibling cached child ids remain stable
 * and the register helper remains idempotent. */
void boot_complete_worker_supervisor(_Atomic supervisor_child_id *slot);

/* Store payment processor (store profile). Its runtime-kernel start/stop
 * adapters live in boot_frontend_services.c beside store RPC composition. */
bool boot_start_payment_service(struct boot_svc_ctx *svc);
void boot_join_payment_service(struct boot_svc_ctx *svc);

/* Background UTXO replay after a snapshot import (delta replay). Worker
 * body (background_utxo_replay) moved to boot_utxo_replay.c to keep this
 * unit under the E1 ceiling; declared here (not a dedicated header, same
 * pattern as boot_worker_supervisor.c) since boot_services.c already
 * includes this header for its existing call sites. */
bool boot_start_replay_service(struct boot_svc_ctx *svc);
void boot_join_replay_service(struct boot_svc_ctx *svc);

/* Fast-sync snapshot offer + chunk/block manifest builder moved to
 * config/include/config/boot_snapshot_offer.h (boot_start_offer_service /
 * boot_join_offer_service). boot_services.c includes that header for the
 * unchanged app_init_services / app_shutdown_svc call sites. */

/* Advisory per-address aggregation backfill. */
bool boot_start_address_backfill_service(struct boot_svc_ctx *svc);
void boot_join_address_backfill_service(struct boot_svc_ctx *svc);

/* Explorer HODL-wave history filler. */
bool boot_start_hodl_history_service(struct boot_svc_ctx *svc);
void boot_join_hodl_history_service(struct boot_svc_ctx *svc);

/* Reducer projection backfill watcher (drives the catchup job forward). */
bool boot_start_projection_backfill_service(struct boot_svc_ctx *svc);
void boot_join_projection_backfill_service(struct boot_svc_ctx *svc);

/* Snapshot transaction-index build job. The job init lives in
 * app_init_services; start spawns it, join reaps it on shutdown. */
bool boot_start_tx_index_service(struct boot_svc_ctx *svc);
void boot_join_tx_index_service(struct boot_svc_ctx *svc);

#endif
