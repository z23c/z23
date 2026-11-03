/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Full-content digest and file identity behind the projection
 *          store's clean-close receipt (see projection_store.c).
 *
 * The digest is a function of the file bytes alone and is spread over a
 * bounded pool of joined worker threads; a close with a clock stops it once
 * the measured rate says the whole file does not fit the close budget. */

#include "projection_store_digest.h"

#ifndef _WIN32
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "platform/positioned_file.h"
#include "util/hw_profile.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* The receipt digest is chunked so the hash can be spread over threads while
 * its value stays a function of the file bytes alone: the file is cut into
 * fixed chunks, each chunk is hashed on its own, and the receipt value is the
 * hash of the chunk digests under a domain tag. Thread count never enters. */
#define PROJECTION_RECEIPT_CHUNK_BYTES (64ull * 1024ull * 1024ull)
#define PROJECTION_RECEIPT_READ_BYTES (1024u * 1024u)
#define PROJECTION_RECEIPT_WORKERS_MAX 8
#define PROJECTION_RECEIPT_CHUNKS_MAX (1ull << 20)
#define PROJECTION_RECEIPT_DOMAIN "z23.projection.clean_receipt.v3"

/* The rate is judged once this much has been hashed, so a small store
 * always completes. */
#define PROJECTION_RECEIPT_SAMPLE_BYTES (32ull * 1024ull * 1024ull)

static uint64_t g_receipt_chunk_bytes = PROJECTION_RECEIPT_CHUNK_BYTES;
static uint64_t g_receipt_sample_bytes = PROJECTION_RECEIPT_SAMPLE_BYTES;
#ifdef ZCL_TESTING
static int g_receipt_workers_override;
#endif

struct receipt_digest_job {
    struct platform_positioned_file *file;
    uint64_t size;
    uint64_t chunk;
    uint64_t n_chunks;
    unsigned char (*digests)[32];
    atomic_uint_fast64_t next;
    atomic_bool failed;
    projection_store_clock_fn clock;  /* NULL: hash the whole file */
    int64_t started_us;
    uint64_t sample;
    atomic_uint_fast64_t hashed;
    atomic_bool over_budget;
};

/* Count `got` hashed bytes; false once the projected total exceeds the
 * budget, which stops every worker before it reads another block. */
static bool receipt_within_budget(struct receipt_digest_job *job,
                                  uint64_t got)
{
    uint64_t done = atomic_fetch_add(&job->hashed, got) + got;
    if (!job->clock || done < job->sample)
        return true;
    int64_t spent = job->clock() - job->started_us;
    double projected = (double)(spent > 0 ? spent : 0) *
                       ((double)job->size / (double)done);
    if (projected <= (double)PROJECTION_RECEIPT_BUDGET_US)
        return true;
    atomic_store(&job->over_budget, true);
    return false;
}

/* Hash chunk `idx` into job->digests[idx]. positioned reads are pread(2)
 * (platform/modules/platform/src/positioned_file.c:591), which takes its
 * offset as an argument and is safe to share on one descriptor. */
static bool receipt_hash_chunk(struct receipt_digest_job *job, uint64_t idx,
                               unsigned char *buf)
{
    uint64_t begin = idx * job->chunk;
    uint64_t end = job->size - begin < job->chunk ? job->size
                                                  : begin + job->chunk;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    for (uint64_t off = begin; off < end;) {
        size_t want = end - off < PROJECTION_RECEIPT_READ_BYTES
            ? (size_t)(end - off) : PROJECTION_RECEIPT_READ_BYTES;
        int64_t got = platform_positioned_file_read(job->file, buf, want, off);
        if (got <= 0 || (uint64_t)got > want) {
            LOG_ERROR("projection_store",
                      "content digest read failed at %llu chunk %llu",
                      (unsigned long long)off, (unsigned long long)idx);
            return false;
        }
        sha3_256_write(&hash, buf, (size_t)got);
        off += (uint64_t)got;
        if (!receipt_within_budget(job, (uint64_t)got))
            return false;
    }
    sha3_256_finalize(&hash, job->digests[idx]);
    return true;
}

/* Take chunk indices from the shared counter until none remain or any worker
 * has failed. Runs on spawned threads and, as the fallback, on the caller. */
static void receipt_run_worker(struct receipt_digest_job *job)
{
    unsigned char *buf = zcl_malloc(PROJECTION_RECEIPT_READ_BYTES, "proj.receipt");
    if (!buf) {
        LOG_ERROR("projection_store", "content digest buffer alloc failed");
        atomic_store(&job->failed, true);
        return;
    }
    while (!atomic_load(&job->failed)) {
        uint64_t idx = atomic_fetch_add(&job->next, 1);
        if (idx >= job->n_chunks)
            break;
        if (!receipt_hash_chunk(job, idx, buf))
            atomic_store(&job->failed, true);
    }
    free(buf);
}

static void *receipt_worker_main(void *arg)
{
    receipt_run_worker(arg);
    return NULL;
}

static unsigned receipt_worker_count(uint64_t n_chunks)
{
    uint64_t want = PROJECTION_RECEIPT_WORKERS_MAX;
    int online = hw_profile_online_cores();
    if (online > 0 && (uint64_t)online < want)
        want = (uint64_t)online;
#ifdef ZCL_TESTING
    if (g_receipt_workers_override > 0)
        want = (uint64_t)g_receipt_workers_override;
#endif
    if (want > n_chunks)
        want = n_chunks;
    return want ? (unsigned)want : 1u;
}

static void receipt_run_job(struct receipt_digest_job *job)
{
    pthread_t tids[PROJECTION_RECEIPT_WORKERS_MAX];
    unsigned want = receipt_worker_count(job->n_chunks);
    unsigned spawned = 0;
    if (want > PROJECTION_RECEIPT_WORKERS_MAX)
        want = PROJECTION_RECEIPT_WORKERS_MAX;
    if (want > 1) {
        for (unsigned i = 0; i < want; i++)
            // thread-supervision-ok: bounded digest workers, joined below
            if (thread_registry_spawn("proj-receipt", receipt_worker_main,
                                      job, &tids[spawned]) == 0)
                spawned++;
    }
    /* One worker, or a spawn that failed: the caller finishes the chunks no
     * thread took. Same result, only slower. */
    if (spawned < want)
        receipt_run_worker(job);
    for (unsigned i = 0; i < spawned; i++)
        pthread_join(tids[i], NULL);
}

static void receipt_combine(const struct receipt_digest_job *job,
                            char out[65])
{
    struct sha3_256_ctx hash;
    uint8_t wire[8];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const unsigned char *)PROJECTION_RECEIPT_DOMAIN,
                   sizeof(PROJECTION_RECEIPT_DOMAIN));
    zcl_write_u64_le(wire, job->size);
    sha3_256_write(&hash, wire, sizeof(wire));
    zcl_write_u64_le(wire, job->chunk);
    sha3_256_write(&hash, wire, sizeof(wire));
    for (uint64_t i = 0; i < job->n_chunks; i++)
        sha3_256_write(&hash, job->digests[i], 32);
    unsigned char digest[32];
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

/* `clock` NULL hashes every byte; otherwise the digest stops, and fails,
 * once the close budget cannot hold. `stats` (nullable) reports either way. */
static bool projection_content_digest(
    struct platform_positioned_file *file, uint64_t size,
    projection_store_clock_fn clock, struct receipt_digest_stats *stats,
    char out[65])
{
    struct receipt_digest_job job;
    memset(&job, 0, sizeof(job));
    job.file = file;
    job.size = size;
    job.chunk = g_receipt_chunk_bytes;
    job.clock = clock;
    job.sample = g_receipt_sample_bytes;
    if (size == 0 || job.chunk == 0)
        return false;
    job.n_chunks = size / job.chunk + (size % job.chunk ? 1 : 0);
    if (job.n_chunks > PROJECTION_RECEIPT_CHUNKS_MAX) {
        LOG_ERROR("projection_store", "content digest chunk count %llu too large",
                  (unsigned long long)job.n_chunks);
        return false;
    }
    job.digests = zcl_malloc((size_t)job.n_chunks * sizeof(*job.digests), "proj.receipt_tab");
    if (!job.digests) {
        LOG_ERROR("projection_store", "content digest table alloc failed");
        return false;
    }
    atomic_init(&job.next, 0);
    atomic_init(&job.failed, false);
    atomic_init(&job.hashed, 0);
    atomic_init(&job.over_budget, false);
    job.started_us = clock ? clock() : 0;
    receipt_run_job(&job);
    bool ok = !atomic_load(&job.failed);
    if (ok)
        receipt_combine(&job, out);
    if (stats)
        *stats = (struct receipt_digest_stats){
            .size = size, .hashed = atomic_load(&job.hashed),
            .spent_us = clock ? clock() - job.started_us : 0,
            .over_budget = atomic_load(&job.over_budget) };
    free(job.digests);
    return ok;
}

bool projection_file_identity_read(
    const char *path, projection_store_clock_fn clock,
    struct receipt_digest_stats *stats, struct projection_file_identity *out)
{
    if (!path || !out)
        return false;
    memset(out, 0, sizeof(*out));
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    if (!platform_positioned_file_snapshot(&file, &before) || before.size < 100) {
        platform_positioned_file_close(&file);
        return false;
    }
    unsigned char hdr[100];
    int64_t nr = platform_positioned_file_read(&file, hdr, sizeof(hdr), 0);
    /* Field-wise, never memcmp: the snapshot struct's alignment padding is
     * undefined, so a whole-object compare can report an unchanged file as
     * changed and reject a perfectly good projection. */
    bool stable = projection_content_digest(&file, before.size, clock, stats,
                                            out->content_sha3) &&
        platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!stable || nr != (int64_t)sizeof(hdr) ||
        memcmp(hdr, "SQLite format 3\000", 16) != 0)
        return false;
    out->dev = before.volume;
    out->ino = before.file_low;
    out->size = (long long)before.size;
    out->mtime_sec = before.modified_seconds;
    out->mtime_nsec = before.modified_nanoseconds;
    out->ctime_sec = before.changed_seconds;
    out->ctime_nsec = before.changed_nanoseconds;
    out->change_counter = zcl_read_u32_be(hdr + 24);
    out->version_valid_for = zcl_read_u32_be(hdr + 92);
    return true;
}

#ifdef ZCL_TESTING
/* Test seams: a small chunk makes a ~40 KiB fixture span many chunks, and a
 * pinned worker count shows the digest does not depend on it. 0 restores the
 * production value. Production code reads no environment for either. */
void projection_store_receipt_chunk_bytes_for_test(uint64_t bytes)
{
    g_receipt_chunk_bytes = bytes ? bytes : PROJECTION_RECEIPT_CHUNK_BYTES;
}

void projection_store_receipt_workers_for_test(int workers)
{
    g_receipt_workers_override = workers;
}

void projection_store_receipt_sample_bytes_for_test(uint64_t bytes)
{
    g_receipt_sample_bytes = bytes ? bytes : PROJECTION_RECEIPT_SAMPLE_BYTES;
}

bool projection_store_receipt_digest_for_test(const char *path, char out[65])
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    if (!path || !out || !platform_positioned_file_open(&file, path))
        return false;
    bool ok = platform_positioned_file_snapshot(&file, &snap) &&
              projection_content_digest(&file, snap.size, NULL, NULL, out);
    platform_positioned_file_close(&file);
    return ok;
}
#endif
#endif
