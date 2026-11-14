/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* catchup_lifecycle_service — start / ownership-join / poll-reap for the
 * node_db catchup job (struct node_db_sync_catchup_job,
 * controllers/sync_controller.h).
 *
 * Lifted out of engine/composition/src/boot_services.c (boot_start_catchup_service /
 * boot_join_catchup_service / boot_reap_catchup_service), which took
 * `struct boot_svc_ctx *` — a engine/composition/src-internal type ("Not for use
 * outside engine/composition/src/", see config/boot_internal.h) that has no business
 * leaking into engine/services/. These take the job + its inputs directly:
 * boot_services.c and boot_background_workers.c keep extracting
 * node_db/chain/wallet/datadir from `svc` and pass them through, so the
 * two call sites stay thin while the lifecycle POLICY (double-start
 * guard, ownership-preserving join, poll-only reap) lives in
 * one place next to the job it manages.
 *
 * Kept as its own file rather than folded into node_db_catchup_service.c:
 * that file is already well past the E1 800-line target, and the job
 * *lifecycle* (thread spawn/join bookkeeping) is a distinct concern from
 * the job *body* (the block-index catchup algorithm in
 * node_db_catchup_service_run) anyway — so it earns its own file on
 * cohesion grounds, not just size. */

#ifndef ZCL_SERVICES_CATCHUP_LIFECYCLE_SERVICE_H
#define ZCL_SERVICES_CATCHUP_LIFECYCLE_SERVICE_H

#include <stdbool.h>

struct node_db;
struct active_chain;
struct wallet;
struct node_db_sync_catchup_job; /* defined in controllers/sync_controller.h */

/* Start the catchup job if it is not already running. Returns false
 * without side effects if `job` is NULL or already started (avoids
 * routing the expected "already running" case through
 * node_db_sync_catchup_job_start's LOG_FAIL path — matches the former
 * boot_start_catchup_service double-start guard). */
bool catchup_lifecycle_start_origin(struct node_db_sync_catchup_job *job, bool background, struct node_db *ndb, const struct active_chain *chain, struct wallet *w, const char *datadir);
bool catchup_lifecycle_start(struct node_db_sync_catchup_job *job,
                             struct node_db *ndb,
                             const struct active_chain *chain,
                             struct wallet *w,
                             const char *datadir);

/* Ownership-preserving join for shutdown. timeout_sec bounds the initial
 * diagnostic wait; if it expires, the timeout is logged and the join keeps
 * waiting. The worker borrows the job, database, chain, and wallet, so it must
 * never be detached while shutdown frees those objects. No-op if the job is
 * not started. After a successful join, clears job->started. The void shutdown
 * wrapper also clears it on join failure; it cannot report reclamation failure. */
void catchup_lifecycle_join(struct node_db_sync_catchup_job *job,
                            int timeout_sec);

/* Poll-style reap for the background backfill watcher: if the job is
 * running but not yet finished, no-op (returns true — "nothing to reap
 * yet"). Once finished, gives the join a one-second diagnostic deadline; if
 * the thread is still in its epilogue, the timeout is logged and ownership is
 * retained until it exits. A successful eventual join clears job->started.
 * Returns false only when ownership could not be reclaimed. */
bool catchup_lifecycle_reap(struct node_db_sync_catchup_job *job);

#if defined(ZCL_TESTING) && defined(__linux__)
/* Select ETIMEDOUT once on this calling thread; the fallback still joins the
 * real worker. Does not claim that an actual diagnostic deadline elapsed. */
void catchup_lifecycle_force_join_timeout_for_testing(void);
#endif

#endif /* ZCL_SERVICES_CATCHUP_LIFECYCLE_SERVICE_H */
