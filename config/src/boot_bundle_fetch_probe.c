/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded parallel directory discovery for instant-on bootstrap. Seed
 * ordering remains policy input; concurrency changes only wall-clock latency. */

// supervisor-ok:bounded-bootstrap-probe — joined pool; no resident service

#include "boot_bundle_fetch_probe_internal.h"

#include "net/rom_fetch.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdlib.h>
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
        if (started[i]) { pthread_join(threads[i], NULL); started[i] = false; } /* MUTATION: serial */
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

/* ── Per-chunk manifest ("RMF") fan-out ─────────────────────────────── */

struct bbf_manifest_job {
    const struct rom_fetch_peer *peer;
    const uint8_t *chunk_root;
    uint8_t (*digests)[32];   /* out_cap rows, owned by the caller below */
    uint32_t cap;
    uint32_t num_chunks;
    bbf_manifest_fetch_fn fetch;
    bool ok;
};

static void *bbf_manifest_one(void *arg)
{
    struct bbf_manifest_job *job = arg;
    job->ok = job->fetch(job->peer->addr, job->peer->port, job->chunk_root,
                         job->digests, job->cap, &job->num_chunks);
    return NULL;
}

bool bbf_probe_manifest(const struct rom_fetch_peer *peers, size_t np,
                        const uint8_t chunk_root[32], uint32_t want_chunks,
                        uint8_t (*out_chunk_sha3)[32], uint32_t out_cap,
                        uint32_t *out_num_chunks, bbf_manifest_fetch_fn fetch)
{
    if (!peers || !chunk_root || !out_chunk_sha3 || !out_num_chunks ||
        !fetch || out_cap == 0 || np == 0 || np > ROM_FETCH_MAX_WORKERS)
        return false;
    *out_num_chunks = 0;

    struct bbf_manifest_job jobs[ROM_FETCH_MAX_WORKERS];
    pthread_t threads[ROM_FETCH_MAX_WORKERS];
    bool started[ROM_FETCH_MAX_WORKERS] = { false };
    memset(jobs, 0, sizeof(jobs));

    /* Each probe needs its own digest table — they run at the same time and
     * only one of them will be kept. Bounded: np <= ROM_FETCH_MAX_WORKERS. */
    for (size_t i = 0; i < np; i++) {
        jobs[i].digests = zcl_malloc((size_t)out_cap * 32u,
                                     "bbf_manifest_probe");
        if (!jobs[i].digests) {
            for (size_t k = 0; k < i; k++)
                free(jobs[k].digests);
            LOG_WARN("boot_bundle_fetch",
                     "manifest probe: OOM allocating digest tables");
            return false;
        }
        jobs[i].peer = &peers[i];
        jobs[i].chunk_root = chunk_root;
        jobs[i].cap = out_cap;
        jobs[i].fetch = fetch;
        // thread-supervision-ok: bounded joined bootstrap probe pool
        started[i] = thread_registry_spawn("zcl_bbf_rmf", bbf_manifest_one,
                                           &jobs[i], &threads[i]) == 0;
        if (started[i]) { pthread_join(threads[i], NULL); started[i] = false; } /* MUTATION: serial */
    }
    /* A spawn failure cannot disable a named seed — probe it synchronously
     * while the successfully spawned ones continue in the background. */
    for (size_t i = 0; i < np; i++)
        if (!started[i])
            (void)bbf_manifest_one(&jobs[i]);
    for (size_t i = 0; i < np; i++)
        if (started[i] && pthread_join(threads[i], NULL) != 0)
            LOG_WARN("boot_bundle_fetch",
                     "manifest probe worker join failed for seed %zu", i);

    bool found = false;
    for (size_t i = 0; i < np && !found; i++) {
        if (jobs[i].ok && jobs[i].num_chunks == want_chunks) {
            memcpy(out_chunk_sha3, jobs[i].digests,
                   (size_t)want_chunks * 32u);
            *out_num_chunks = jobs[i].num_chunks;
            found = true;
        }
    }
    for (size_t i = 0; i < np; i++)
        free(jobs[i].digests);
    return found;
}

#ifdef ZCL_TESTING
bool boot_bundle_probe_manifest_for_test(
    const struct rom_fetch_peer *peers, size_t np,
    const uint8_t chunk_root[32], uint32_t want_chunks,
    uint8_t (*out_chunk_sha3)[32], uint32_t out_cap,
    uint32_t *out_num_chunks, bbf_manifest_fetch_fn fetch)
{
    return bbf_probe_manifest(peers, np, chunk_root, want_chunks,
                              out_chunk_sha3, out_cap, out_num_chunks, fetch);
}

size_t boot_bundle_probe_directories_for_test(
    const struct rom_fetch_peer *peers, size_t np, char *bodies,
    size_t stride, bool *responded, bbf_directory_fetch_fn fetch)
{
    return bbf_probe_directories(peers, np, bodies, stride, responded, fetch);
}
#endif
