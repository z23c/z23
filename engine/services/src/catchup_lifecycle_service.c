/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

// one-result-type-ok:catchup-job-bool-contract — E2 (one way out):
// catchup_lifecycle_start/_reap keep the bool contract of the primitives
// they wrap (node_db_sync_catchup_job_start/_is_started,
// controllers/sync_controller.h — not owned by this lane, not a
// zcl_result surface). Returning struct zcl_result here would create an
// asymmetric mismatch with the job API one call down, for no caller that
// needs a richer failure reason: boot_services.c's callers already just
// branch on true/false (see boot_start_catchup_service /
// boot_reap_catchup_service). Every failure path that has a reason
// (bounded-join timeout/error) already logs it via LOG_WARN before
// returning false, so the reason still travels with the failure.

#define _GNU_SOURCE  /* pthread_timedjoin_np */

/* catchup_lifecycle_service — see the header doc comment for the
 * boot_services.c origin + contract. catchup_lifecycle_join_thread_bounded/
 * catchup_lifecycle_join_deadline_from_now mirror
 * engine/composition/src/boot_background_workers.c's boot_join_thread_bounded (bounded
 * pthread_timedjoin_np, log + detach on timeout/error) — kept local
 * instead of shared so this service does not depend on a
 * engine/composition/src-internal header ("Not for use outside engine/composition/src/"). The
 * engine/composition/src original uses a raw fprintf (boot/shutdown code avoids the
 * app-layer log macros); this engine/services/ copy uses LOG_WARN per
 * DEFENSIVE_CODING.md so the reason travels through the same node.log
 * path (and `z23 getnodelog` filter) as every other service failure. */

#include "platform/time_compat.h"
#include "services/catchup_lifecycle_service.h"
#include "controllers/sync_controller.h" /* struct node_db_sync_catchup_job */
#include "util/log_macros.h"
#include "util/util.h"  /* GetDataDir */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
static void catchup_lifecycle_join_deadline_from_now(struct timespec *ts,
                                                      int timeout_sec)
{
    platform_time_realtime_timespec(ts);
    if (timeout_sec < 0)
        timeout_sec = 0;
    ts->tv_sec += timeout_sec;
}
#endif

static bool catchup_lifecycle_join_thread_bounded(pthread_t thread,
                                                   const char *name,
                                                   int timeout_sec)
{
#if defined(__linux__)
    struct timespec deadline;
    int rc;

    catchup_lifecycle_join_deadline_from_now(&deadline, timeout_sec);
    rc = pthread_timedjoin_np(thread, NULL, &deadline);
    if (rc == 0)
        return true;

    if (rc == ETIMEDOUT) {
        LOG_WARN("catchup_lifecycle",
                 "%s join timed out after %ds; retaining ownership",
                 name ? name : "thread", timeout_sec);
    } else {
        LOG_WARN("catchup_lifecycle",
                 "%s join failed rc=%d (%s); retaining ownership",
                 name ? name : "thread", rc, strerror(rc));
    }
    pthread_join(thread, NULL);
    return false;
#else
    (void)timeout_sec;
    int rc = pthread_join(thread, NULL);
    if (rc != 0)
        LOG_WARN("catchup_lifecycle", "%s join failed rc=%d (%s)",
                 name ? name : "thread", rc, strerror(rc));
    return rc == 0;
#endif
}

bool catchup_lifecycle_start(struct node_db_sync_catchup_job *job,
                             struct node_db *ndb,
                             const struct active_chain *chain,
                             struct wallet *w,
                             const char *datadir)
{
    if (!job || node_db_sync_catchup_job_is_started(job))
        return false;

    /* `datadir` is the BASE datadir, but block bodies are persisted under the
     * NET-SPECIFIC datadir (GetDataDir(true); the writer idiom in
     * reducer_ingest_service.c) — the catchup blk reader must look there or
     * it reads an empty/legacy blk dir on regtest/testnet and indexes
     * nothing. Byte-identical on mainnet.
     *
     * This buffer is function-local and this function RETURNS as soon as the
     * worker is spawned, so the job must retain the bytes rather than the
     * pointer — node_db_sync_catchup_job_start() copies into its own
     * args.datadir_storage. Do not "simplify" that copy away. */
    char net_dir[2048];
    GetDataDir(true, net_dir, sizeof(net_dir));
    return node_db_sync_catchup_job_start(job, ndb, chain, w,
                                          net_dir[0] ? net_dir : datadir);
}

void catchup_lifecycle_join(struct node_db_sync_catchup_job *job,
                            int timeout_sec)
{
    if (!job || !job->started)
        return;
    catchup_lifecycle_join_thread_bounded(job->thread, "catchup", timeout_sec);
    job->started = false;
}

bool catchup_lifecycle_reap(struct node_db_sync_catchup_job *job)
{
    if (!job || !job->started)
        return true;
    if (!atomic_load(&job->finished))
        return true;
    if (!catchup_lifecycle_join_thread_bounded(job->thread, "catchup", 1))
        return false; // raw-return-ok:join-already-logged — the bounded
                       // join itself LOG_WARNs the timeout/error reason
                       // before returning false; no second log needed here.
    job->started = false;
    return true;
}
