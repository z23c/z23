/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catchup_lifecycle_service — start/join/reap policy lifted out of
 * engine/composition/src/boot_services.c (boot_start_catchup_service /
 * boot_join_catchup_service / boot_reap_catchup_service). Exercises the
 * double-start guard, the NULL-safety of every entry point, the ownership-preserving
 * join clearing job->started, and the poll-only reap contract (no-op
 * while running, joins + clears once finished). */

#include "test/test_core.h"
#include "services/catchup_lifecycle_service.h"
#include "controllers/sync_controller.h"
#include "models/database.h"
#include "validation/chainstate.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static void *catchup_lifecycle_immediate_worker(void *arg)
{
    (void)arg;
    return NULL;
}

static int catchup_lifecycle_test_null_entries(void)
{
    int failures = 0;
    printf("catchup_lifecycle_service: every entry point is NULL-safe... ");
    bool ok = !catchup_lifecycle_start(NULL, NULL, NULL, NULL, NULL);
    catchup_lifecycle_join(NULL, 0);   /* must not crash */
    ok = ok && catchup_lifecycle_reap(NULL);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int catchup_lifecycle_test_never_started(void)
{
    int failures = 0;
    printf("catchup_lifecycle_service: reap/join no-op on a job never started... ");
    struct node_db_sync_catchup_job job;
    node_db_sync_catchup_job_init(&job);
    bool ok = catchup_lifecycle_reap(&job);
    catchup_lifecycle_join(&job, 0);   /* must not crash */
    ok = ok && !job.started;
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int catchup_lifecycle_test_start_guard(void)
{
    int failures = 0;
    printf("catchup_lifecycle_service: start + double-start guard + join... ");
    struct node_db ndb;
    struct active_chain ac;
    struct node_db_sync_catchup_job job;
    bool db_ok = node_db_open(&ndb, ":memory:");

    active_chain_init(&ac);
    node_db_sync_catchup_job_init(&job);

    bool started = db_ok &&
        catchup_lifecycle_start_origin(&job, true, &ndb, &ac, NULL, NULL);
    bool background_set = started && job.background;
    /* Second start while the first is still (at least momentarily)
     * marked started must fail closed without disturbing the job —
     * mirrors the former boot_start_catchup_service guard that
     * pre-empted node_db_sync_catchup_job_start's LOG_FAIL path. */
    bool double_start_rejected = started &&
        !catchup_lifecycle_start(&job, &ndb, &ac, NULL, NULL);
    bool rejected_preserved_role = job.background;

    catchup_lifecycle_join(&job, 5);
    bool joined_clears_started = !job.started;
    bool legacy_started = catchup_lifecycle_start(&job, &ndb, &ac, NULL, NULL);
    bool legacy_boot = legacy_started && !job.background;
    bool deferred = true;
    int invalid = node_db_sync_catchup_origin(NULL, true, &deferred, NULL, NULL, NULL);
    bool invalid_cleared = invalid < 0 && !deferred;
    catchup_lifecycle_join(&job, 5);

    bool ok = db_ok && started && background_set && double_start_rejected &&
              joined_clears_started && legacy_boot && rejected_preserved_role && invalid_cleared;

    if (ndb.open)
        node_db_close(&ndb);
    active_chain_free(&ac);

    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int catchup_lifecycle_test_poll_reap(void)
{
    int failures = 0;
    printf("catchup_lifecycle_service: reap is a no-op until the job finishes... ");
    struct node_db_sync_catchup_job job;
    node_db_sync_catchup_job_init(&job);
    bool started = pthread_create(&job.thread, NULL,
                                  catchup_lifecycle_immediate_worker, NULL) == 0;
    job.started = started;
    bool pending = started && catchup_lifecycle_reap(&job) && job.started;
    atomic_store(&job.finished, true);
    bool reaped = started && catchup_lifecycle_reap(&job);
    bool ok = pending && reaped && !job.started;
    /* A defective late-reap return may leave started set after joining. */
    job.started = false;
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int catchup_lifecycle_test_datadir_owner(void)
{
    int failures = 0;
    /* Lifetime: catchup_lifecycle_start() resolves the network datadir
     * into a FUNCTION-LOCAL buffer and returns as soon as the worker is
     * spawned, so the job must own the BYTES, not the pointer. */
    printf("catchup_lifecycle_service: the job owns the starter's "
           "datadir bytes... ");
    static const char kDatadir[] = "/nonexistent/catchup-datadir-owner";
    struct node_db ndb;
    struct active_chain ac;
    struct node_db_sync_catchup_job job;

    /* A closed handle makes the worker exit at its first check, so this
     * exercises the hand-off and nothing else. */
    memset(&ndb, 0, sizeof(ndb));
    active_chain_init(&ac);
    node_db_sync_catchup_job_init(&job);

    char caller_path[512];
    snprintf(caller_path, sizeof(caller_path), "%s", kDatadir);
    bool started =
        node_db_sync_catchup_job_start(&job, &ndb, &ac, NULL, caller_path);
    /* Stand in for the starter's frame going away. */
    memset(caller_path, 0xA5, sizeof(caller_path));

    int result = 0;
    bool joined = started &&
        node_db_sync_catchup_job_join(&job, &result);
    bool ok = started && joined &&
        job.args.datadir == job.args.datadir_storage &&
        strcmp(job.args.datadir, kDatadir) == 0;

    /* A datadir that cannot be retained whole is refused at start
     * rather than silently truncated into a wrong path. */
    char oversized[sizeof(job.args.datadir_storage) + 1u];
    memset(oversized, 'x', sizeof(oversized) - 1u);
    oversized[sizeof(oversized) - 1u] = '\0';
    node_db_sync_catchup_job_init(&job);
    ok = ok &&
        !node_db_sync_catchup_job_start(&job, &ndb, &ac, NULL, oversized) &&
        job.args.datadir_storage[0] == '\0';

    active_chain_free(&ac);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

#if defined(ZCL_TESTING) && defined(__linux__)
static int catchup_lifecycle_test_forced_timeout_reap(void)
{
    printf("catchup_lifecycle_service: forced diagnostic timeout is joined and reaped... ");
    struct node_db_sync_catchup_job job;
    node_db_sync_catchup_job_init(&job);
    bool started = pthread_create(&job.thread, NULL,
                                  catchup_lifecycle_immediate_worker, NULL) == 0;
    job.started = started;
    atomic_store(&job.finished, true);
    if (started)
        catchup_lifecycle_force_join_timeout_for_testing();
    bool reaped = started && catchup_lifecycle_reap(&job);
    bool ok = started && reaped && !job.started;
    /* The real ownership join has reclaimed the worker even with the
     * defective fallback return restored; do not attempt a second join. */
    job.started = false;
    if (ok) printf("OK\n");
    else printf("FAIL\n");
    return ok ? 0 : 1;
}
#endif

int test_catchup_lifecycle_service(void)
{
    int failures = 0;
    printf("\n=== catchup_lifecycle_service tests ===\n");
    failures += catchup_lifecycle_test_null_entries();
    failures += catchup_lifecycle_test_never_started();
    failures += catchup_lifecycle_test_start_guard();
    failures += catchup_lifecycle_test_poll_reap();
    failures += catchup_lifecycle_test_datadir_owner();
#if defined(ZCL_TESTING) && defined(__linux__)
    failures += catchup_lifecycle_test_forced_timeout_reap();
#endif
    printf("catchup_lifecycle_service: %d failures\n", failures);
    return failures;
}
