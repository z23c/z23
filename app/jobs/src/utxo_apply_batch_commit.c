/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_batch_commit — implementation. See jobs/utxo_apply_batch_commit.h.
 *
 * One mutex guards a handful of scalars plus a fixed-size ring buffer;
 * every field is written once per outer-batch COMMIT (at most a few times a
 * second even on a hot fold), so the lock is never contended in practice.
 * No allocation, no I/O beyond the single LOG_INFO line already required by
 * this lane's mandate. */

#include "jobs/utxo_apply_batch_commit.h"

#include "json/json.h"
#include "util/boot_progress.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdint.h>

/* Depth of the rolling commit_us sample ring. 32 outer-batch commits is
 * enough to see a recent trend (max_steps is typically in the hundreds of
 * heights per batch, so 32 batches already spans a large fold) without
 * costing more than 256 bytes. */
#define UA_BATCH_COMMIT_RING_N 32

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int64_t  g_ring[UA_BATCH_COMMIT_RING_N];
static uint32_t g_ring_pos;
static uint32_t g_ring_count;

static uint64_t g_total_commits;
static int64_t  g_last_commit_us;
static int64_t  g_commit_us_ewma;
static int64_t  g_commit_us_max;

static int32_t g_last_height_lo = -1;
static int32_t g_last_height_hi = -1;
static int32_t g_last_rows;

void utxo_apply_batch_commit_record(int64_t height_before_batch, int rows,
                                     int64_t commit_us)
{
    /* Floor to 1us: a genuinely-sampled commit is always distinguishable
     * from "never recorded" (total_commits == 0), mirroring the identical
     * floor-to-1 idiom in stage_record_step_timing / stage_batch_record_
     * commit_timing (lib/util/src/stage.c). */
    if (commit_us <= 0)
        commit_us = 1;

    int32_t height_lo = (int32_t)(height_before_batch + (rows > 0 ? 1 : 0));
    int32_t height_hi = (int32_t)(height_before_batch + rows);

    LOG_INFO("utxo_apply",
             "[batch_commit] heights=%d..%d rows=%d commit_us=%lld",
             height_lo, height_hi, rows, (long long)commit_us);
    boot_progress_tick("utxo_apply_batch");

    pthread_mutex_lock(&g_lock);
    g_ring[g_ring_pos] = commit_us;
    g_ring_pos = (g_ring_pos + 1) % UA_BATCH_COMMIT_RING_N;
    if (g_ring_count < UA_BATCH_COMMIT_RING_N)
        g_ring_count++;

    g_commit_us_ewma = (g_total_commits == 0)
        ? commit_us
        : g_commit_us_ewma + (commit_us - g_commit_us_ewma) / 16;
    if (commit_us > g_commit_us_max)
        g_commit_us_max = commit_us;

    g_total_commits++;
    g_last_commit_us = commit_us;
    g_last_height_lo = height_lo;
    g_last_height_hi = height_hi;
    g_last_rows = rows;
    pthread_mutex_unlock(&g_lock);
}

void utxo_apply_batch_commit_reset_for_test(void)
{
    pthread_mutex_lock(&g_lock);
    for (uint32_t i = 0; i < UA_BATCH_COMMIT_RING_N; i++)
        g_ring[i] = 0;
    g_ring_pos = 0;
    g_ring_count = 0;
    g_total_commits = 0;
    g_last_commit_us = 0;
    g_commit_us_ewma = 0;
    g_commit_us_max = 0;
    g_last_height_lo = -1;
    g_last_height_hi = -1;
    g_last_rows = 0;
    pthread_mutex_unlock(&g_lock);
}

bool utxo_apply_batch_commit_dump_state_json(struct json_value *out,
                                              const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    pthread_mutex_lock(&g_lock);
    uint64_t total    = g_total_commits;
    int64_t  last_us  = g_last_commit_us;
    int64_t  ewma      = g_commit_us_ewma;
    int64_t  max_us    = g_commit_us_max;
    int32_t  last_lo   = g_last_height_lo;
    int32_t  last_hi   = g_last_height_hi;
    int32_t  last_rows = g_last_rows;
    uint32_t ring_n    = g_ring_count;
    int64_t  ring_sum  = 0;
    for (uint32_t i = 0; i < ring_n; i++)
        ring_sum += g_ring[i];
    pthread_mutex_unlock(&g_lock);

    json_push_kv_int(out, "total_commits", (int64_t)total);
    json_push_kv_int(out, "last_commit_us", last_us);
    json_push_kv_int(out, "commit_us_ewma", ewma);
    json_push_kv_int(out, "commit_us_max", max_us);
    json_push_kv_int(out, "ring_samples", (int64_t)ring_n);
    json_push_kv_int(out, "ring_avg_us", ring_n ? ring_sum / (int64_t)ring_n : 0);
    json_push_kv_int(out, "last_height_lo", last_lo);
    json_push_kv_int(out, "last_height_hi", last_hi);
    json_push_kv_int(out, "last_rows", last_rows);
    return true;
}
