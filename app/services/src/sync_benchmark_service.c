/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sync_benchmark_service — implementation of the zcl.sync_benchmark.v1
 * phase-timed receipt. See services/sync_benchmark_service.h for the contract.
 *
 * Layout:
 *   1. Global state + mutex
 *   2. Cheap sampling helpers (monotonic clock, peak rss)
 *   3. Phase / milestone / counter entry points
 *   4. Receipt builder (shared by dump + durable write)
 *   5. Durable write (atomic rename + fsync)
 *   6. init / reset / dump
 */

// one-result-type-ok:sync-benchmark-no-fallible-surface
/* E2 override. This module has no fallible orchestration surface: the phase
 * stamps and counters return void (a stamp cannot meaningfully fail — a bad
 * phase index is ignored), and the receipt/dump entry points return bool
 * (out valid / write succeeded) rather than a zcl_result. */

#include "services/sync_benchmark_service.h"

#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "util/clientversion.h"
#include "util/hw_profile.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define SB_SUBSYS "sync_benchmark"

/* ── Global state ──────────────────────────────────────────────── */

/* Per-phase measurement state. elapsed_ms == -1 means "not measured". */
enum sb_phase_state { SB_NOT_STARTED = 0, SB_IN_PROGRESS, SB_DONE };

struct sb_phase {
    enum sb_phase_state state;
    int64_t begin_us;    /* monotonic-us stamp at phase_begin */
    int64_t elapsed_ms;  /* -1 until phase_end; else >= 0 */
};

/* Stable wire names for the eight phases (timings_ms keys). Index by enum. */
static const char *const k_phase_name[SYNC_BENCH_PHASE_COUNT] = {
    "peer_discovery", "headers", "manifest", "artifact_download",
    "artifact_verify", "install", "tail_download", "tail_fold",
};

static struct {
    pthread_mutex_t lock;           /* guards every field below */
    bool    initialized;
    char    datadir[512];

    int64_t t0_us;                  /* monotonic origin (sync_benchmark_init) */

    struct sb_phase phase[SYNC_BENCH_PHASE_COUNT];

    int64_t ready_ms;               /* -1 until mark_ready */
    int64_t sovereign_ms;           /* -1 until mark_sovereign */

    /* Resource counters. -1 == unmeasured (never noted); else >= 0. */
    int64_t bytes_downloaded;
    int64_t bytes_reused;
    int64_t bytes_redownloaded;
    int64_t disk_write_bytes;
    int64_t peak_rss_bytes;         /* -1 until first readable sample */

    /* Network context. mbps < 0 / peers < 0 == unmeasured. */
    double  est_mbps;
    int     peer_count;

    char    artifact_id[80];        /* "" == null */
} g_sb = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .est_mbps = -1.0,
    .peer_count = -1,
};

/* ── Sampling helpers ──────────────────────────────────────────── */

static int64_t sb_now_us(void)
{
    return platform_time_monotonic_us();
}

/* Sample VmRSS and fold it into the running peak. Called with g_sb.lock held.
 * Best-effort: an unreadable /proc leaves the peak untouched. */
static void sb_sample_rss_locked(void)
{
    struct os_proc_mem mem;
    if (os_proc_mem_read(&mem) && mem.rss_bytes > 0) {
        if (mem.rss_bytes > g_sb.peak_rss_bytes)
            g_sb.peak_rss_bytes = mem.rss_bytes;
    }
}

/* ── Phase / milestone / counter entry points ──────────────────── */

void sync_benchmark_phase_begin(enum sync_bench_phase phase)
{
    if ((int)phase < 0 || phase >= SYNC_BENCH_PHASE_COUNT)
        return;
    pthread_mutex_lock(&g_sb.lock);
    g_sb.phase[phase].state    = SB_IN_PROGRESS;
    g_sb.phase[phase].begin_us = sb_now_us();
    sb_sample_rss_locked();
    pthread_mutex_unlock(&g_sb.lock);
}

void sync_benchmark_phase_end(enum sync_bench_phase phase)
{
    if ((int)phase < 0 || phase >= SYNC_BENCH_PHASE_COUNT)
        return;
    pthread_mutex_lock(&g_sb.lock);
    struct sb_phase *p = &g_sb.phase[phase];
    if (p->state == SB_IN_PROGRESS) {
        int64_t d_us = sb_now_us() - p->begin_us;
        if (d_us < 0)
            d_us = 0;
        p->elapsed_ms = d_us / 1000;
        p->state      = SB_DONE;
        sb_sample_rss_locked();
    }
    pthread_mutex_unlock(&g_sb.lock);
}

void sync_benchmark_mark_ready(void)
{
    pthread_mutex_lock(&g_sb.lock);
    int64_t d_us = sb_now_us() - g_sb.t0_us;
    g_sb.ready_ms = (d_us < 0) ? 0 : d_us / 1000;
    pthread_mutex_unlock(&g_sb.lock);
}

void sync_benchmark_mark_sovereign(void)
{
    pthread_mutex_lock(&g_sb.lock);
    int64_t d_us = sb_now_us() - g_sb.t0_us;
    g_sb.sovereign_ms = (d_us < 0) ? 0 : d_us / 1000;
    pthread_mutex_unlock(&g_sb.lock);
}

static void sb_note(int64_t *counter, uint64_t bytes)
{
    pthread_mutex_lock(&g_sb.lock);
    if (*counter < 0)
        *counter = 0;
    *counter += (int64_t)bytes;
    pthread_mutex_unlock(&g_sb.lock);
}

void sync_benchmark_note_downloaded(uint64_t bytes)   { sb_note(&g_sb.bytes_downloaded, bytes); }
void sync_benchmark_note_reused(uint64_t bytes)       { sb_note(&g_sb.bytes_reused, bytes); }
void sync_benchmark_note_redownloaded(uint64_t bytes) { sb_note(&g_sb.bytes_redownloaded, bytes); }

void sync_benchmark_set_artifact(const char *artifact_id)
{
    pthread_mutex_lock(&g_sb.lock);
    if (artifact_id && artifact_id[0])
        snprintf(g_sb.artifact_id, sizeof(g_sb.artifact_id), "%s", artifact_id);
    else
        g_sb.artifact_id[0] = '\0';
    pthread_mutex_unlock(&g_sb.lock);
}

/* ── Receipt builder ───────────────────────────────────────────── */

/* Push either an int value or (when v < 0) a null plus a null_reasons entry.
 * `reasons` is the shared null_reasons object being assembled. */
static void sb_push_int_or_null(struct json_value *obj, struct json_value *reasons,
                                const char *key, int64_t v, const char *why)
{
    if (v >= 0) {
        json_push_kv_int(obj, key, v);
    } else {
        struct json_value nul = {0};
        json_init(&nul);
        json_set_null(&nul);
        json_push_kv(obj, key, &nul);
        json_free(&nul);
        json_push_kv_str(reasons, key, why);
    }
}

/* Build the timings_ms object; append per-phase null reasons to `reasons`.
 * Called with g_sb.lock held. */
static void sb_build_timings_locked(struct json_value *timings,
                                    struct json_value *reasons, bool complete)
{
    for (int i = 0; i < SYNC_BENCH_PHASE_COUNT; i++) {
        const struct sb_phase *p = &g_sb.phase[i];
        if (p->state == SB_DONE) {
            json_push_kv_int(timings, k_phase_name[i], p->elapsed_ms);
        } else {
            struct json_value nul = {0};
            json_init(&nul);
            json_set_null(&nul);
            json_push_kv(timings, k_phase_name[i], &nul);
            json_free(&nul);
            json_push_kv_str(reasons, k_phase_name[i],
                             p->state == SB_IN_PROGRESS
                                 ? "phase_started_but_not_completed"
                                 : (complete ? "phase_not_driven_on_this_path"
                                             : "phase_not_reached_before_abort"));
        }
    }
    /* Derived milestones. */
    sb_push_int_or_null(timings, reasons, "t_ready", g_sb.ready_ms,
                        "assisted_readiness_not_reached");
    sb_push_int_or_null(timings, reasons, "t_sovereign", g_sb.sovereign_ms,
                        "sovereign_promotion_not_reached");
}

bool sync_benchmark_build_receipt(struct json_value *out, bool complete,
                                  const char *incomplete_reason)
{
    if (!out)
        return false;
    json_set_object(out);

    json_push_kv_str(out, "schema", "zcl.sync_benchmark.v1");

    pthread_mutex_lock(&g_sb.lock);

    /* source_epoch: the running binary's source identity (dev source epoch). */
    const char *epoch = zcl_build_source_id_sha256();
    if (epoch && epoch[0])
        json_push_kv_str(out, "source_epoch", epoch);
    else {
        struct json_value nul = {0}; json_init(&nul); json_set_null(&nul);
        json_push_kv(out, "source_epoch", &nul); json_free(&nul);
    }

    if (g_sb.artifact_id[0])
        json_push_kv_str(out, "artifact_id", g_sb.artifact_id);
    else {
        struct json_value nul = {0}; json_init(&nul); json_set_null(&nul);
        json_push_kv(out, "artifact_id", &nul); json_free(&nul);
    }

    json_push_kv_bool(out, "complete", complete);
    if (!complete && incomplete_reason && incomplete_reason[0])
        json_push_kv_str(out, "incomplete_reason", incomplete_reason);
    else if (!complete) {
        json_push_kv_str(out, "incomplete_reason", "unspecified");
    } else {
        struct json_value nul = {0}; json_init(&nul); json_set_null(&nul);
        json_push_kv(out, "incomplete_reason", &nul); json_free(&nul);
    }

    /* hardware */
    struct json_value hw = {0};
    json_set_object(&hw);
    json_push_kv_int(&hw, "physical_cores", (int64_t)hw_profile_physical_cores());
    struct os_proc_mem mem;
    if (os_proc_mem_read(&mem) && mem.sys_total_bytes > 0)
        json_push_kv_int(&hw, "total_ram_bytes", mem.sys_total_bytes);
    else {
        struct json_value nul = {0}; json_init(&nul); json_set_null(&nul);
        json_push_kv(&hw, "total_ram_bytes", &nul); json_free(&nul);
    }
    const char *commit = zcl_build_commit();
    json_push_kv_str(&hw, "build_commit", commit ? commit : "unknown");
    json_push_kv(out, "hardware", &hw);
    json_free(&hw);

    /* null_reasons accumulates across timings + resources. */
    struct json_value reasons = {0};
    json_set_object(&reasons);

    /* network */
    struct json_value net = {0};
    json_set_object(&net);
    if (g_sb.est_mbps >= 0.0)
        json_push_kv_real(&net, "estimated_mbps", g_sb.est_mbps);
    else {
        struct json_value nul = {0}; json_init(&nul); json_set_null(&nul);
        json_push_kv(&net, "estimated_mbps", &nul); json_free(&nul);
        json_push_kv_str(&reasons, "estimated_mbps", "not_measured_on_this_path");
    }
    sb_push_int_or_null(&net, &reasons, "peer_count",
                        g_sb.peer_count, "not_measured_on_this_path");
    json_push_kv(out, "network", &net);
    json_free(&net);

    /* timings_ms */
    struct json_value timings = {0};
    json_set_object(&timings);
    sb_build_timings_locked(&timings, &reasons, complete);
    json_push_kv(out, "timings_ms", &timings);
    json_free(&timings);

    /* resources */
    struct json_value res = {0};
    json_set_object(&res);
    sb_push_int_or_null(&res, &reasons, "peak_rss_bytes",
                        g_sb.peak_rss_bytes, "rss_never_sampled");
    /* The old reason here was "not_instrumented_on_this_path", which read as
     * "nobody counts bytes anywhere". Not true, and the vagueness cost real
     * time: sync_benchmark_note_downloaded() IS wired, but from exactly one
     * place — the ROM/checkpoint-bundle fetch (rom_fetch_controller.c) — so a
     * plain P2P block-download sync legitimately leaves this null while the
     * node's download manager is counting block-body bytes the whole time
     * (dl_add_bytes_received, surfaced by `dumpstate sync_monitor` as
     * download_bytes_received). Name the actual scope so a reader looks in the
     * right place instead of concluding bytes are unmeasurable. */
    sb_push_int_or_null(&res, &reasons, "bytes_downloaded",
                        g_sb.bytes_downloaded,
                        "only_rom_bundle_fetch_records_this_"
                        "p2p_block_bytes_are_in_dumpstate_sync_monitor_"
                        "download_bytes_received");
    sb_push_int_or_null(&res, &reasons, "bytes_reused",
                        g_sb.bytes_reused, "no_resume_journal_reuse_recorded");
    sb_push_int_or_null(&res, &reasons, "bytes_redownloaded",
                        g_sb.bytes_redownloaded, "not_instrumented_on_this_path");
    sb_push_int_or_null(&res, &reasons, "disk_write_bytes",
                        g_sb.disk_write_bytes, "not_instrumented_on_this_path");
    json_push_kv(out, "resources", &res);
    json_free(&res);

    pthread_mutex_unlock(&g_sb.lock);

    json_push_kv(out, "null_reasons", &reasons);
    json_free(&reasons);
    return true;
}

/* ── Durable write ─────────────────────────────────────────────── */

bool sync_benchmark_write_receipt(bool complete, const char *incomplete_reason)
{
    pthread_mutex_lock(&g_sb.lock);
    bool armed = g_sb.initialized && g_sb.datadir[0];
    char datadir[sizeof(g_sb.datadir)];
    snprintf(datadir, sizeof(datadir), "%s", g_sb.datadir);
    pthread_mutex_unlock(&g_sb.lock);

    if (!armed) {
        LOG_WARN(SB_SUBSYS, "write_receipt: no datadir armed; skipping");
        return false;
    }

    struct json_value receipt = {0};
    json_init(&receipt);
    if (!sync_benchmark_build_receipt(&receipt, complete, incomplete_reason)) {
        json_free(&receipt);
        LOG_FAIL(SB_SUBSYS, "write_receipt: build failed");
        return false;
    }

    /* Size probe, then a single heap-free bounded serialization. The receipt is
     * fixed-shape (~1.5 KB); a 4 KB stack buffer covers it with headroom. */
    char buf[4096];
    size_t need = json_write(&receipt, buf, sizeof(buf));
    json_free(&receipt);
    if (need >= sizeof(buf)) {
        LOG_FAIL(SB_SUBSYS, "write_receipt: serialized receipt %zu >= %zu bytes",
                 need, sizeof(buf));
        return false;
    }

    /* Atomic publish from a unique, owner-private sibling. */
    char final_path[600];
    char tmp_path[640];
    int fn = snprintf(final_path, sizeof(final_path),
                      "%s/sync_benchmark.json", datadir);
    if (fn <= 0 || (size_t)fn >= sizeof(final_path)) {
        LOG_FAIL(SB_SUBSYS, "write_receipt: datadir path too long");
        return false;
    }

    /* An existing destination must itself be a regular no-reparse file.
     * Missing is allowed; any other open refusal fails closed. */
    struct platform_positioned_file existing;
    platform_positioned_file_init(&existing);
    bool destination_regular =
        platform_positioned_file_open(&existing, final_path);
    platform_positioned_file_close(&existing);
    if (!destination_regular && !platform_private_path_absent(final_path)) {
        LOG_ERROR(SB_SUBSYS,
                  "write_receipt: destination is not a regular no-reparse file");
        return false;
    }

    static _Atomic uint64_t tmp_sequence;
    struct platform_private_file staging;
    platform_private_file_init(&staging);
    bool created = false;
    for (unsigned int attempt = 0; attempt < 16 && !created; attempt++) {
        uint64_t sequence = atomic_fetch_add_explicit(
            &tmp_sequence, 1, memory_order_relaxed);
        int tn = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%llu",
                          final_path, (unsigned long long)sequence);
        if (tn <= 0 || (size_t)tn >= sizeof(tmp_path)) {
            LOG_ERROR(SB_SUBSYS, "write_receipt: staging path too long");
            return false;
        }
        created = platform_private_file_create(tmp_path, &staging);
    }
    if (!created) {
        LOG_ERROR(SB_SUBSYS,
                  "write_receipt: unique private staging creation failed");
        return false;
    }
    if (!platform_private_file_write_at(&staging, buf, need, 0) ||
        !platform_private_file_flush(&staging)) {
        LOG_ERROR(SB_SUBSYS, "write_receipt: durable staging write failed");
        (void)platform_private_file_retire(&staging, tmp_path);
        platform_private_file_close(&staging);
        return false;
    }
    if (!platform_private_file_replace(
            &staging, tmp_path, final_path)) {
        LOG_ERROR(SB_SUBSYS, "write_receipt: atomic handle replace failed");
        (void)platform_private_file_retire(&staging, tmp_path);
        platform_private_file_close(&staging);
        return false;
    }
    if (!platform_private_parent_flush(datadir)) {
        LOG_ERROR(SB_SUBSYS, "write_receipt: parent durability barrier failed");
        return false;
    }
    LOG_INFO(SB_SUBSYS, "wrote sync_benchmark receipt (complete=%s) to %s",
             complete ? "true" : "false", final_path);
    return true;
}

/* ── init / reset / dump ───────────────────────────────────────── */

void sync_benchmark_init(const char *datadir)
{
    pthread_mutex_lock(&g_sb.lock);
    memset(g_sb.phase, 0, sizeof(g_sb.phase));
    for (int i = 0; i < SYNC_BENCH_PHASE_COUNT; i++)
        g_sb.phase[i].elapsed_ms = -1;
    g_sb.t0_us             = sb_now_us();
    g_sb.ready_ms          = -1;
    g_sb.sovereign_ms      = -1;
    g_sb.bytes_downloaded  = -1;
    g_sb.bytes_reused      = -1;
    g_sb.bytes_redownloaded = -1;
    g_sb.disk_write_bytes  = -1;
    g_sb.peak_rss_bytes    = -1;
    g_sb.est_mbps          = -1.0;
    g_sb.peer_count        = -1;
    g_sb.artifact_id[0]    = '\0';
    if (datadir && datadir[0]) {
        snprintf(g_sb.datadir, sizeof(g_sb.datadir), "%s", datadir);
        g_sb.initialized = true;
    } else {
        g_sb.datadir[0]  = '\0';
        g_sb.initialized = true;  /* armed for dump-only (no durable write) */
    }
    pthread_mutex_unlock(&g_sb.lock);
}

void sync_benchmark_reset_for_test(void)
{
    pthread_mutex_lock(&g_sb.lock);
    memset(g_sb.phase, 0, sizeof(g_sb.phase));
    for (int i = 0; i < SYNC_BENCH_PHASE_COUNT; i++)
        g_sb.phase[i].elapsed_ms = -1;
    g_sb.initialized       = false;
    g_sb.datadir[0]        = '\0';
    g_sb.t0_us             = 0;
    g_sb.ready_ms          = -1;
    g_sb.sovereign_ms      = -1;
    g_sb.bytes_downloaded  = -1;
    g_sb.bytes_reused      = -1;
    g_sb.bytes_redownloaded = -1;
    g_sb.disk_write_bytes  = -1;
    g_sb.peak_rss_bytes    = -1;
    g_sb.est_mbps          = -1.0;
    g_sb.peer_count        = -1;
    g_sb.artifact_id[0]    = '\0';
    pthread_mutex_unlock(&g_sb.lock);
}

bool sync_benchmark_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    /* Complete iff the final phase folded and sovereignty was reached — the
     * dump never claims a full sync the instrument did not observe. */
    pthread_mutex_lock(&g_sb.lock);
    bool complete = g_sb.phase[SYNC_BENCH_TAIL_FOLD].state == SB_DONE &&
                    g_sb.sovereign_ms >= 0;
    pthread_mutex_unlock(&g_sb.lock);
    return sync_benchmark_build_receipt(out, complete,
                                        complete ? NULL : "sync_in_progress");
}
