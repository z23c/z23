/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* catchup_lifecycle_service — start / bounded-join / poll-reap for the
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
 * guard, bounded join with detach-on-timeout, poll-only reap) lives in
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
bool catchup_lifecycle_start(struct node_db_sync_catchup_job *job,
                             struct node_db *ndb,
                             const struct active_chain *chain,
                             struct wallet *w,
                             const char *datadir);

/* Bounded join for shutdown: waits up to timeout_sec for the catchup
 * thread, then detaches instead of blocking (never lets a stuck catchup
 * thread hang shutdown). No-op if the job is not started. Clears
 * job->started unconditionally on return — matches the former
 * boot_join_catchup_service contract. */
void catchup_lifecycle_join(struct node_db_sync_catchup_job *job,
                            int timeout_sec);

/* Poll-style reap for the background backfill watcher: if the job is
 * running but not yet finished, no-op (returns true — "nothing to reap
 * yet"). Once finished, joins it (bounded 1s) and clears job->started.
 * Returns false only if that bounded join itself times out, leaving the
 * job thread detached and job->started still true — matches the former
 * boot_reap_catchup_service contract. */
bool catchup_lifecycle_reap(struct node_db_sync_catchup_job *job);

#endif /* ZCL_SERVICES_CATCHUP_LIFECYCLE_SERVICE_H */
