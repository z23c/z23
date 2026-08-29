/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded parallel directory discovery for instant-on bootstrap. Seed
 * ordering remains policy input; concurrency changes only wall-clock latency. */

// supervisor-ok:bounded-bootstrap-probe — joined pool; no resident service

#include "boot_bundle_fetch_probe_internal.h"

#include "net/rom_fetch.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <string.h>

struct bbf_probe_job {
    const struct rom_fetch_peer *peer;
    char *body;
    size_t cap;
    bbf_directory_fetch_fn fetch;
    bool responded;
};

static void *bbf_probe_one(void *arg)
{
    struct bbf_probe_job *job = arg;
    job->responded = job->fetch(job->peer->addr, job->peer->port,
                                job->body, job->cap);
    return NULL;
}

size_t bbf_probe_directories(const struct rom_fetch_peer *peers, size_t np,
                             char *bodies, size_t stride, bool *responded,
                             bbf_directory_fetch_fn fetch)
{
    if (!peers || !bodies || stride < 2 || !responded || !fetch ||
        np == 0 || np > ROM_FETCH_MAX_WORKERS)
        return 0;

    struct bbf_probe_job jobs[ROM_FETCH_MAX_WORKERS];
    pthread_t threads[ROM_FETCH_MAX_WORKERS];
    bool started[ROM_FETCH_MAX_WORKERS] = { false };
    memset(responded, 0, np * sizeof(*responded));

    for (size_t i = 0; i < np; i++) {
        jobs[i] = (struct bbf_probe_job){
            .peer = &peers[i], .body = bodies + i * stride,
            .cap = stride, .fetch = fetch, .responded = false,
        };
        // thread-supervision-ok: bounded joined bootstrap probe pool
        started[i] = thread_registry_spawn("zcl_bbf_probe", bbf_probe_one,
                                            &jobs[i], &threads[i]) == 0;
    }
    /* A spawn failure cannot disable a named seed. Probe it synchronously
     * while successfully spawned peers continue in the background. */
    for (size_t i = 0; i < np; i++)
        if (!started[i])
            (void)bbf_probe_one(&jobs[i]);
    for (size_t i = 0; i < np; i++)
        if (started[i] && pthread_join(threads[i], NULL) != 0)
            LOG_WARN("boot_bundle_fetch",
                     "directory probe worker join failed for seed %zu", i);

    size_t count = 0;
    for (size_t i = 0; i < np; i++) {
        responded[i] = jobs[i].responded;
        count += responded[i] ? 1u : 0u;
    }
    return count;
}

#ifdef ZCL_TESTING
size_t boot_bundle_probe_directories_for_test(
    const struct rom_fetch_peer *peers, size_t np, char *bodies,
    size_t stride, bool *responded, bbf_directory_fetch_fn fetch)
{
    return bbf_probe_directories(peers, np, bodies, stride, responded, fetch);
}
#endif
