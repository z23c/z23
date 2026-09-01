/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catchup_lifecycle_service — start/join/reap policy lifted out of
 * engine/composition/src/boot_services.c (boot_start_catchup_service /
 * boot_join_catchup_service / boot_reap_catchup_service). Exercises the
 * double-start guard, the NULL-safety of every entry point, the bounded
 * join clearing job->started, and the poll-only reap contract (no-op
 * while running, joins + clears once finished). */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "services/catchup_lifecycle_service.h"
#include "controllers/sync_controller.h"
#include "models/database.h"
#include "validation/chainstate.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

int test_catchup_lifecycle_service(void)
{
    int failures = 0;
    printf("\n=== catchup_lifecycle_service tests ===\n");

    {
        printf("catchup_lifecycle_service: every entry point is NULL-safe... ");
        bool ok = !catchup_lifecycle_start(NULL, NULL, NULL, NULL, NULL);
        catchup_lifecycle_join(NULL, 0);   /* must not crash */
        ok = ok && catchup_lifecycle_reap(NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    {
        printf("catchup_lifecycle_service: reap/join no-op on a job never started... ");
        struct node_db_sync_catchup_job job;
        node_db_sync_catchup_job_init(&job);
        bool ok = catchup_lifecycle_reap(&job);
        catchup_lifecycle_join(&job, 0);   /* must not crash */
        ok = ok && !job.started;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    {
        printf("catchup_lifecycle_service: start + double-start guard + join... ");
        struct node_db ndb;
        struct active_chain ac;
        struct node_db_sync_catchup_job job;
        bool db_ok = node_db_open(&ndb, ":memory:");

        active_chain_init(&ac);
        node_db_sync_catchup_job_init(&job);

        bool started = db_ok &&
            catchup_lifecycle_start(&job, &ndb, &ac, NULL, NULL);
        /* Second start while the first is still (at least momentarily)
         * marked started must fail closed without disturbing the job —
         * mirrors the former boot_start_catchup_service guard that
         * pre-empted node_db_sync_catchup_job_start's LOG_FAIL path. */
        bool double_start_rejected = started &&
            !catchup_lifecycle_start(&job, &ndb, &ac, NULL, NULL);

        catchup_lifecycle_join(&job, 5);
        bool joined_clears_started = !job.started;

        bool ok = db_ok && started && double_start_rejected &&
                  joined_clears_started;

        if (ndb.open)
            node_db_close(&ndb);
        active_chain_free(&ac);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    {
        printf("catchup_lifecycle_service: reap is a no-op until the job finishes... ");
        struct node_db ndb;
        struct active_chain ac;
        struct node_db_sync_catchup_job job;
        bool db_ok = node_db_open(&ndb, ":memory:");

        active_chain_init(&ac);
        node_db_sync_catchup_job_init(&job);

        bool started = db_ok &&
            catchup_lifecycle_start(&job, &ndb, &ac, NULL, NULL);

        /* Give the worker thread a moment to run to completion — the fake
         * in-memory DB catchup is a fast no-op body, so this settles
         * quickly; reap is polled the same way the projection-backfill
         * watcher does in boot_background_workers.c. */
        bool reaped = false;
        for (int i = 0; i < 200 && !reaped; i++) {
            if (atomic_load(&job.finished))
                reaped = catchup_lifecycle_reap(&job);
            else
                platform_sleep_ms(5);
        }

        bool ok = started && reaped && !job.started;

        /* Belt-and-suspenders: never leave a thread dangling if the loop
         * above somehow didn't observe `finished` in time. */
        if (job.started)
            catchup_lifecycle_join(&job, 5);

        if (ndb.open)
            node_db_close(&ndb);
        active_chain_free(&ac);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    {
        /* Lifetime regression. catchup_lifecycle_start() resolves the
         * network datadir into a FUNCTION-LOCAL buffer and returns the
         * instant the worker is spawned. If the job kept that pointer the
         * worker would read a dead stack frame and open block files under
         * whatever later reused it — the live node logged exactly that,
         * whole runs of "cannot open <binary junk>/blocks/blkNNNNN.dat".
         * The job must own the BYTES. */
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
    }

    printf("catchup_lifecycle_service: %d failures\n", failures);
    return failures;
}
