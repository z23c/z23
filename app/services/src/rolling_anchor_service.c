// one-result-type-ok:json-dump-bool-only:rolling_anchor_dump_state_json — rolling_anchor_window_hash_ending_at already returns zcl_result; the dumper stays bool per CLAUDE.md "Adding state introspection".
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Rolling SHA3 anchor extension — see services/rolling_anchor_service.h
 * for the contract.
 *
 * Lifecycle:
 *   1. boot:  rolling_anchor_init(datadir)
 *   2. supervisor tick: rolling_anchor_extend_if_due(ms, datadir)
 *      every 60s under the chain domain. */
#include "platform/time_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "rolling_anchor_file_internal.h"
#include "services/rolling_anchor_service.h"
#include "rolling_anchor_internal.h"
#include "services/oracle_policy.h"
#include "services/quorum_oracle_service.h"
#include "services/seal_service.h"
#include "storage/progress_store.h"
#include "supervisors/domains.h"
#include "chain/chain.h"
#include "chain/sha3_windows.h"
#include "core/serialize.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "json/json.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/main_constants.h"
#include "validation/sync_evidence_policy.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define RA_MAGIC           "ZCLRAW1"     /* 7 bytes + NUL = 8 */
#define RA_MAGIC_LEN       8
#define RA_SCHEMA          1u
#define RA_DEFAULT_DEPTH   ZCL_FINALITY_DEPTH
#define RA_DEFAULT_CAP     10
#define RA_FILE_NAME       "sha3_windows_runtime.dat"
#define RA_RECORD_SIZE     36u            /* i32 + 32 bytes hash */
#define RA_TICK_SECS       60              /* periodic extend cadence */
/* §4d row-8: after this many CONSECUTIVE read failures at/below the sealed
 * input prefix, page a human (a corrupt block frame in the sealed domain is
 * unrecoverable by re-fetch). Above the prefix, a read failure is normal
 * window territory (re-fetch) and never pages. */
#define RA_READ_FAIL_PAGE_THRESHOLD 5
struct ra_record {
    int32_t start_height;
    uint8_t hash[32];
};
static struct {
    pthread_mutex_t lock;
    bool   initialized;
    int    confirmation_depth;
    int    max_extend_per_call;
    struct ra_record *windows;
    int    count;
    int    capacity;
    _Atomic int64_t total_extended;
    _Atomic int64_t total_skipped_policy, total_oracle_divergence_observed;
    _Atomic int64_t total_skipped_depth, total_skipped_missing_body;
    _Atomic int64_t total_read_failures;
    /* CONSECUTIVE read failures: reset to 0 on any successful window commit.
     * Distinct from the monotonic total — this counts a genuinely-stuck
     * sealed-read, the §4d-row-8 page trigger. */
    _Atomic int64_t consecutive_read_failures;
    /* The height the most recent read failure stopped at (the unreadable
     * block frame). Decides page-vs-warn against the sealed prefix. */
    _Atomic int32_t last_read_fail_height, last_missing_body_height;
    /* Page-once latch: set when the row-8 page fires, cleared when the
     * consecutive counter returns to 0 (a successful extend re-arms it). */
    _Atomic bool    read_fail_paged;
    _Atomic int64_t last_extend_unix;
    char   file_path[1024];
    /* Periodic-tick context, populated by rolling_anchor_start. */
    struct main_state    *tick_ms;
    char                  tick_datadir[1024];
} g_ra = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};
static struct liveness_contract g_ra_contract;
static _Atomic supervisor_child_id g_ra_supervisor_id = SUPERVISOR_INVALID_ID;

/* The state-free helpers this file calls — ra_compile_time_end,
 * ra_file_digest, ra_compute_window_hash, and
 * ra_quorum_allows_commit — live in rolling_anchor_compute.c (declared in
 * rolling_anchor_internal.h). None of them touch g_ra or its lock. */

/* Caller holds g_ra.lock. Last committed runtime window's end height
 * (or compile-time end when no runtime windows are present). */
static int ra_runtime_end_locked(void)
{
    int compile_end = ra_compile_time_end();
    if (g_ra.count == 0) return compile_end;
    return g_ra.windows[g_ra.count - 1].start_height +
           (int)SHA3_WINDOW_SIZE - 1;
}

/* Write the in-memory ring to disk atomically. Caller holds lock. */
static bool ra_persist_locked(void)
{
    if (g_ra.file_path[0] == '\0') return false;
    static _Atomic uint64_t tmp_sequence = 0;
    char tmp[1024];
    struct platform_private_file staging;
    platform_private_file_init(&staging);
    bool created = false;
    for (unsigned int attempt = 0; attempt < 16 && !created; attempt++) {
        uint64_t sequence = atomic_fetch_add_explicit(
            &tmp_sequence, 1, memory_order_relaxed);
        int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%" PRIu64,
                         g_ra.file_path, sequence);
        if (n <= 0 || (size_t)n >= sizeof(tmp))
            return false;
        created = platform_private_file_create(tmp, &staging);
    }
    if (!created) {
        fprintf(stderr, "[rolling_anchor] persist: cannot create private staging file\n");
        return false;
    }
    size_t body_len = (size_t)RA_MAGIC_LEN + 4 + 4 +
                      (size_t)g_ra.count * RA_RECORD_SIZE;
    uint8_t *body = zcl_malloc(body_len, "ra_persist.body");
    if (!body) {
        (void)platform_private_file_retire(&staging, tmp);
        platform_private_file_close(&staging);
        return false;
    }
    uint8_t *p = body;
    memcpy(p, RA_MAGIC, RA_MAGIC_LEN); p += RA_MAGIC_LEN;
    uint32_t schema = RA_SCHEMA;
    memcpy(p, &schema, 4); p += 4;
    uint32_t count = (uint32_t)g_ra.count;
    memcpy(p, &count, 4); p += 4;
    for (int i = 0; i < g_ra.count; i++) {
        int32_t h = g_ra.windows[i].start_height;
        memcpy(p, &h, 4); p += 4;
        memcpy(p, g_ra.windows[i].hash, 32); p += 32;
    }
    uint8_t digest[32];
    ra_file_digest(body, body_len, digest);
    bool ok = platform_private_file_write_at(&staging, body, body_len, 0) &&
              platform_private_file_write_at(&staging, digest, 32, body_len) &&
              platform_private_file_flush(&staging);
    free(body);
    if (!ok) {
        (void)platform_private_file_retire(&staging, tmp);
        platform_private_file_close(&staging);
        fprintf(stderr,
                "[rolling_anchor] persist: write/sync failed: %s\n",
                strerror(errno));
        return false;
    }
    if (!platform_private_file_replace(&staging, tmp, g_ra.file_path)) {
        (void)platform_private_file_retire(&staging, tmp);
        platform_private_file_close(&staging);
        fprintf(stderr,
                "[rolling_anchor] persist: rename failed: %s\n",
                strerror(errno));
        return false;
    }
    return rolling_anchor_parent_flush(g_ra.file_path);
}
/* Read + verify file. Returns true on success (file absent counts as
 * success — caller leaves g_ra empty). On corruption returns false;
 * caller decides whether to delete the file. */
static bool ra_load_locked(void)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, g_ra.file_path))
        return platform_private_path_absent(g_ra.file_path);
    struct platform_positioned_file_snapshot before;
    if (!platform_positioned_file_is_private(&file) ||
        !platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        return false;
    }
    uint64_t file_size = before.size;
    if (file_size < (uint64_t)(RA_MAGIC_LEN + 4 + 4 + 32)) {
        fprintf(stderr,
                "[rolling_anchor] load: file too small (%lld bytes)\n",
                (long long)file_size);
        platform_positioned_file_close(&file);
        return false;
    }
    if (file_size > SIZE_MAX) {
        platform_positioned_file_close(&file);
        return false;
    }
    size_t fsz = (size_t)file_size;
    uint8_t *buf = zcl_malloc(fsz, "ra_load.buf");
    if (!buf) {
        platform_positioned_file_close(&file);
        return false;
    }
    size_t offset = 0;
    while (offset < fsz) {
        int64_t got = platform_positioned_file_read(
            &file, buf + offset, fsz - offset, offset);
        if (got <= 0) {
            free(buf);
            platform_positioned_file_close(&file);
            return false;
        }
        offset += (size_t)got;
    }
    struct platform_positioned_file_snapshot after;
    if (!platform_positioned_file_snapshot(&file, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after)) {
        free(buf);
        platform_positioned_file_close(&file);
        return false;
    }
    platform_positioned_file_close(&file);
    /* Layout: body (fsz - 32) || digest (32). */
    size_t body_len = fsz - 32;
    uint8_t expected[32];
    memcpy(expected, buf + body_len, 32);
    uint8_t computed[32];
    ra_file_digest(buf, body_len, computed);
    if (memcmp(expected, computed, 32) != 0) {
        LOG_WARN("rolling_anchor", "[rolling_anchor] load: file SHA3 mismatch — " "discarding runtime anchors");
        free(buf);
        return false;
    }
    if (memcmp(buf, RA_MAGIC, RA_MAGIC_LEN) != 0) {
        fprintf(stderr,
                "[rolling_anchor] load: bad magic — discarding\n");
        free(buf);
        return false;
    }
    uint32_t schema = 0;
    memcpy(&schema, buf + RA_MAGIC_LEN, 4);
    if (schema != RA_SCHEMA) {
        LOG_INFO("rolling_anchor", "[rolling_anchor] load: schema %u != %u — discarding", schema, RA_SCHEMA);
        free(buf);
        return false;
    }
    uint32_t count = 0;
    memcpy(&count, buf + RA_MAGIC_LEN + 4, 4);
    uint64_t expected_size = (uint64_t)RA_MAGIC_LEN + 4 + 4 +
                             (uint64_t)count * RA_RECORD_SIZE;
    if (count > INT_MAX || expected_size != body_len) {
        LOG_WARN("rolling_anchor", "[rolling_anchor] load: size mismatch (count=%u body=%zu) " "— discarding", count, body_len);
        free(buf);
        return false;
    }
    /* Validate monotonic + alignment + contiguity with compile-time
     * prefix. */
    int compile_end = ra_compile_time_end();
    int expected_start =
        (compile_end >= 0) ? compile_end + 1 : 0;
    struct ra_record *recs = NULL;
    if (count > 0) {
        recs = zcl_calloc(count, sizeof(*recs), "ra.load.recs");
        if (!recs) { free(buf); return false; }
    }
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *p = buf + RA_MAGIC_LEN + 4 + 4 +
                            (size_t)i * RA_RECORD_SIZE;
        int32_t h = 0;
        memcpy(&h, p, 4);
        if (h != expected_start || h % SHA3_WINDOW_SIZE != 0) {
            LOG_WARN("rolling_anchor", "[rolling_anchor] load: bad start_height at idx %u " "(got %d expected %d) — discarding", i, h, expected_start);
            free(recs);
            free(buf);
            return false;
        }
        recs[i].start_height = h;
        memcpy(recs[i].hash, p + 4, 32);
        expected_start += (int)SHA3_WINDOW_SIZE;
    }
    free(buf);
    /* Adopt. */
    free(g_ra.windows);
    g_ra.windows  = recs;
    g_ra.count    = (int)count;
    g_ra.capacity = (int)count;
    if (count > 0) {
        LOG_INFO("rolling_anchor", "[rolling_anchor] load: %u windows loaded " "(coverage h=%d..%d)", count, recs[0].start_height, recs[count - 1].start_height + (int)SHA3_WINDOW_SIZE - 1);
    }
    return true;
}
struct zcl_result rolling_anchor_init(const char *datadir,
                          const struct rolling_anchor_config *cfg)
{
    if (!datadir || !datadir[0])
        return ZCL_ERR(-1, "rolling_anchor_init: NULL/empty datadir");
    pthread_mutex_lock(&g_ra.lock);
    if (g_ra.initialized) {
        pthread_mutex_unlock(&g_ra.lock);
        return ZCL_OK;
    }
    g_ra.confirmation_depth =
        (cfg && cfg->confirmation_depth > 0)
            ? cfg->confirmation_depth : RA_DEFAULT_DEPTH;
    g_ra.max_extend_per_call =
        (cfg && cfg->max_extend_per_call > 0)
            ? cfg->max_extend_per_call : RA_DEFAULT_CAP;
    snprintf(g_ra.file_path, sizeof(g_ra.file_path), "%s/%s",
             datadir, RA_FILE_NAME);
    bool ok = ra_load_locked();
    if (!ok) {
        /* Corrupt — wipe so we don't keep refusing to load. */
        (void)platform_private_file_unlink_missing_ok(g_ra.file_path);
        free(g_ra.windows);
        g_ra.windows = NULL;
        g_ra.count = 0;
        g_ra.capacity = 0;
    }
    g_ra.initialized = true;
    pthread_mutex_unlock(&g_ra.lock);
    if (!ok)
        return ZCL_ERR(-2, "rolling_anchor_init: load failed (corrupt file wiped) datadir=%s",
                       datadir);
    return ZCL_OK;
}

static bool ra_note_window_read_failure(int sealed_end,
                                        int next_start,
                                        int fail_h)
{
    if (fail_h < 0 || fail_h <= sealed_end) {
        atomic_fetch_add(&g_ra.total_read_failures, 1);
        atomic_fetch_add(&g_ra.consecutive_read_failures, 1);
        atomic_store(&g_ra.last_read_fail_height, (int32_t)fail_h);
        LOG_WARN("rolling_anchor",
                 "[rolling_anchor] extend: sealed read failed at h=%d "
                 "(window start=%d prefix_end=%d) — stopping",
                 fail_h, next_start, sealed_end);
        return true;
    }
    int64_t skipped =
        atomic_fetch_add(&g_ra.total_skipped_missing_body, 1) + 1;
    atomic_store(&g_ra.last_missing_body_height, (int32_t)fail_h);
    atomic_store(&g_ra.consecutive_read_failures, 0);
    if (skipped == 1 || skipped % 60 == 0) {
        LOG_INFO("rolling_anchor",
                 "[rolling_anchor] extend: missing unsealed block body h=%d "
                 "(window start=%d prefix_end=%d) — extension deferred",
                 fail_h, next_start, sealed_end);
    }
    return false;
}
int rolling_anchor_extend_if_due(struct main_state *ms,
                                  const char *datadir)
{
    if (!ms || !datadir || !datadir[0]) return 0;
    if (!g_ra.initialized) return 0;
    enum oracle_policy_state ops = oracle_policy_get_state();
    if (ops != OP_NORMAL) {  /* B8: evidence, never a gate — self-derived */
        atomic_fetch_add(&g_ra.total_oracle_divergence_observed, 1);
        event_emitf(EV_SYNC_STATE_CHANGE, 0,
                    "rolling_anchor oracle divergence state=%s", oracle_policy_state_name(ops));
    }
    int tip = active_chain_height(&ms->chain_active);
    if (tip < 0) return 0;
    pthread_mutex_lock(&g_ra.lock);
    int current_end = ra_runtime_end_locked();
    int cap = g_ra.max_extend_per_call;
    pthread_mutex_unlock(&g_ra.lock);
    if (current_end < 0) return 0;  /* no compile-time anchors */
    int sealed_end = current_end;
    int next_start = ((current_end + 1) / (int)SHA3_WINDOW_SIZE) *
                     (int)SHA3_WINDOW_SIZE;
    if (next_start <= current_end) {
        /* Should be exactly current_end + 1, but be defensive. */
        next_start = current_end + 1;
        if (next_start % SHA3_WINDOW_SIZE != 0) return 0;
    }
    int extended = 0;
    while (extended < cap) {
        int last_h_in_win = next_start + (int)SHA3_WINDOW_SIZE - 1;
        if (last_h_in_win > zcl_immutable_height(tip)) {
            atomic_fetch_add(&g_ra.total_skipped_depth, 1);
            break;
        }
        if (!ra_quorum_allows_commit(last_h_in_win)) {
            atomic_fetch_add(&g_ra.total_skipped_policy, 1);
            event_emitf(EV_SYNC_STATE_CHANGE, 0,
                        "rolling_anchor quorum split h=%d", last_h_in_win);
            fprintf(stderr,
                    "[rolling_anchor] extend: quorum refused window "
                    "start=%d end=%d\n", next_start, last_h_in_win);
            break;
        }
        uint8_t hash[32];
        int fail_h = -1;
        if (!ra_compute_window_hash(ms, datadir, next_start, hash, &fail_h)) {
            (void)ra_note_window_read_failure(sealed_end, next_start, fail_h);
            break;
        }
        pthread_mutex_lock(&g_ra.lock);
        if (g_ra.count == g_ra.capacity) {
            int new_cap = g_ra.capacity ? g_ra.capacity * 2 : 16;
            struct ra_record *r =
                zcl_realloc(g_ra.windows,
                            (size_t)new_cap * sizeof(*r),
                            "rolling_anchor.windows");
            if (!r) {
                pthread_mutex_unlock(&g_ra.lock);
                break;
            }
            g_ra.windows = r;
            g_ra.capacity = new_cap;
        }
        g_ra.windows[g_ra.count].start_height = next_start;
        memcpy(g_ra.windows[g_ra.count].hash, hash, 32);
        g_ra.count++;
        bool persisted = ra_persist_locked();
        pthread_mutex_unlock(&g_ra.lock);
        if (!persisted) {
            /* Disk write failure - roll back the in-memory entry so
             * we don't claim evidence that is not on disk. */
            pthread_mutex_lock(&g_ra.lock);
            if (g_ra.count > 0) g_ra.count--;
            pthread_mutex_unlock(&g_ra.lock);
            LOG_WARN("rolling_anchor", "[rolling_anchor] extend: persist failed at start=%d " "— in-memory rollback", next_start);
            break;
        }
        char hex[65];
        HexStr(hash, 32, false, hex, sizeof(hex));
        LOG_INFO("rolling_anchor", "[rolling_anchor] extended: start=%d end=%d sha3=%s", next_start, last_h_in_win, hex);
        atomic_fetch_add(&g_ra.total_extended, 1);
        /* A successful commit proves the sealed read path is healthy: clear the
         * consecutive-failure counter and re-arm the row-8 page latch. */
        atomic_store(&g_ra.consecutive_read_failures, 0);
        atomic_store(&g_ra.read_fail_paged, false);
        atomic_store(&g_ra.last_extend_unix, (int64_t)platform_time_wall_time_t());
        sealed_end = last_h_in_win;
        next_start += (int)SHA3_WINDOW_SIZE;
        extended++;
    }
    return extended;
}
/* ── Periodic-tick wrapper ─────────────────────────────────────── */
int rolling_anchor_effective_prefix_end(void)
{
    pthread_mutex_lock(&g_ra.lock);
    int runtime_end = ra_runtime_end_locked();
    pthread_mutex_unlock(&g_ra.lock);
    return runtime_end;
}
struct zcl_result rolling_anchor_window_hash_ending_at(int32_t end_h,
                                                        uint8_t out[32])
{
    if (!out)
        return ZCL_ERR(-1, "window_hash_ending_at: null out end_h=%d", end_h);
    /* A window covers [start .. start+999] ending at start+999, so a window
     * ending at end_h has end_h+1 a multiple of SHA3_WINDOW_SIZE. */
    if (((int64_t)end_h + 1) % (int)SHA3_WINDOW_SIZE != 0)
        return ZCL_ERR(-2, "window_hash_ending_at: end_h=%d not window-end", end_h);
    int32_t start_height = end_h - (int)SHA3_WINDOW_SIZE + 1;
    if (start_height < 0)
        return ZCL_ERR(-3, "window_hash_ending_at: end_h=%d start<0", end_h);
    pthread_mutex_lock(&g_ra.lock);
    /* Compile-time prefix windows first (g_sha3_windows is start-indexed). */
    int compile_end = ra_compile_time_end();
    if (compile_end >= 0 && end_h <= compile_end) {
        size_t idx = (size_t)(start_height / (int)SHA3_WINDOW_SIZE);
        if (idx < g_sha3_windows_count &&
            g_sha3_windows[idx].start_height == start_height) {
            memcpy(out, g_sha3_windows[idx].hash, 32);
            pthread_mutex_unlock(&g_ra.lock);
            return ZCL_OK;
        }
        pthread_mutex_unlock(&g_ra.lock);
        return ZCL_ERR(-4, "window_hash_ending_at: no compile window start=%d", start_height);
    }
    /* Otherwise scan the runtime ring for a matching start_height. */
    for (int i = 0; i < g_ra.count; i++) {
        if (g_ra.windows[i].start_height == start_height) {
            memcpy(out, g_ra.windows[i].hash, 32);
            pthread_mutex_unlock(&g_ra.lock);
            return ZCL_OK;
        }
    }
    pthread_mutex_unlock(&g_ra.lock);
    return ZCL_ERR(-5, "window_hash_ending_at: no runtime window start=%d", start_height);
}
static void rolling_anchor_on_stall(struct liveness_contract *c)
{
    int reason = c ? atomic_load(&c->stall_reason) : SUPERVISOR_STALL_NONE;
    int runtime_end = rolling_anchor_effective_prefix_end();
    int64_t read_failures = atomic_load(&g_ra.total_read_failures);
    const char *reason_name = supervisor_stall_reason_name(
        (enum supervisor_stall_reason)reason);
    LOG_WARN("supervisor", "[supervisor] chain.rolling_anchor stalled reason=%s effective_prefix_end=%d read_failures=%lld", reason_name, runtime_end, (long long)read_failures);
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "chain.rolling_anchor stalled reason=%s effective_prefix_end=%d read_failures=%lld",
                reason_name, runtime_end, (long long)read_failures);
    /* §4d row-8: a corrupt block frame AT OR BELOW the sealed input prefix is
     * unrecoverable by re-fetch — it pages instead of retrying forever. Above
     * the prefix is ordinary window territory (the re-fetch is normal), so we
     * keep the warn-and-retry above and gate the page on BOTH a sustained
     * consecutive-failure count AND a failing height inside the sealed prefix.
     * Page exactly once per escalation (the latch re-arms on any success). */
    int64_t consec = atomic_load(&g_ra.consecutive_read_failures);
    int32_t fail_h = atomic_load(&g_ra.last_read_fail_height);
    if (consec >= RA_READ_FAIL_PAGE_THRESHOLD &&
        fail_h >= 0 && fail_h <= runtime_end + 1 &&
        !atomic_load(&g_ra.read_fail_paged)) {
        atomic_store(&g_ra.read_fail_paged, true);
        LOG_WARN("rolling_anchor", "[rolling_anchor] OPERATOR NEEDED: sealed-domain read failure at h=%d (consecutive=%lld prefix_end=%d) — a corrupt block frame at/below the seal cannot be re-fetched; staying up, paging a human", fail_h, (long long)consec, runtime_end);
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=rolling_anchor_sealed_read_failure consecutive=%lld prefix_end=%d failing_height=%d",
                    (long long)consec, runtime_end, fail_h);
    }
}
static void rolling_anchor_on_tick(struct liveness_contract *c)
{
    (void)c;
    pthread_mutex_lock(&g_ra.lock);
    struct main_state *ms = g_ra.tick_ms;
    char datadir[1024];
    memcpy(datadir, g_ra.tick_datadir, sizeof(datadir));
    pthread_mutex_unlock(&g_ra.lock);
    supervisor_child_id id = atomic_load(&g_ra_supervisor_id);
    if (!ms) {
        supervisor_tick(id);
        return;
    }
    int64_t before_failures = atomic_load(&g_ra.total_read_failures);
    (void)rolling_anchor_extend_if_due(ms, datadir);
    /* Ratify the newest state-seal candidate at depth — the OUTPUT companion
     * to the INPUT window just (maybe) extended above. Best-effort, idempotent;
     * it opens only its own progress.kv txn (no csr->lock / chain_evidence). */
    (void)seal_ratify_tick(ms);
    supervisor_progress(id, (int64_t)rolling_anchor_effective_prefix_end());
    if (atomic_load(&g_ra.total_read_failures) > before_failures)
        supervisor_report_stall(id, SUPERVISOR_STALL_CHILD_REPORTED);
    supervisor_tick(id);
}
struct zcl_result rolling_anchor_start(struct main_state *ms, const char *datadir)
{
    if (!ms || !datadir || !datadir[0])
        return ZCL_ERR(-1, "rolling_anchor_start: bad args ms=%p datadir=%s",
                       (void*)ms, datadir ? datadir : "(null)");
    /* Idempotent — init() returns ZCL_OK if file absent. */
    (void)rolling_anchor_init(datadir, NULL);
    /* Ensure the state-seal ring schema (progress_meta is already ensured by
     * progress_store_open; this is idempotent belt-and-braces so the seal path
     * never races a missing table). The ratifier runs from this service's tick. */
    (void)seal_service_init(progress_store_db());
    pthread_mutex_lock(&g_ra.lock);
    g_ra.tick_ms = ms;
    snprintf(g_ra.tick_datadir, sizeof(g_ra.tick_datadir), "%s", datadir);
    pthread_mutex_unlock(&g_ra.lock);
    supervisor_child_id id = atomic_load(&g_ra_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_period(id, RA_TICK_SECS);
        supervisor_progress(id, (int64_t)rolling_anchor_effective_prefix_end());
        supervisor_tick(id);
        return ZCL_OK;
    }
    liveness_contract_init(&g_ra_contract, "chain.rolling_anchor");
    atomic_store(&g_ra_contract.period_secs, (int64_t)RA_TICK_SECS);
    atomic_store(&g_ra_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_ra_contract.progress_max_quiet_us, (int64_t)0);
    g_ra_contract.on_tick = rolling_anchor_on_tick;
    g_ra_contract.on_stall = rolling_anchor_on_stall;
    supervisor_domains_init();
    id = supervisor_register_in_domain(g_chain_sup, &g_ra_contract);
    atomic_store(&g_ra_supervisor_id, id);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-2, "rolling_anchor_start: supervisor register failed");
    supervisor_progress(id, (int64_t)rolling_anchor_effective_prefix_end());
    supervisor_tick(id);
    return ZCL_OK;
}
void rolling_anchor_stop(void)
{
    supervisor_child_id id = atomic_load(&g_ra_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_period(id, 0);
    pthread_mutex_lock(&g_ra.lock);
    g_ra.tick_ms = NULL;
    g_ra.tick_datadir[0] = '\0';
    pthread_mutex_unlock(&g_ra.lock);
}
bool rolling_anchor_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    pthread_mutex_lock(&g_ra.lock);
    int count = g_ra.count;
    int compile_end = ra_compile_time_end();
    int runtime_end = ra_runtime_end_locked();
    int depth = g_ra.confirmation_depth;
    int cap = g_ra.max_extend_per_call;
    char path_copy[sizeof(g_ra.file_path)];
    memcpy(path_copy, g_ra.file_path, sizeof(path_copy));
    pthread_mutex_unlock(&g_ra.lock);
    json_push_kv_int (out, "runtime_window_count", count);
    json_push_kv_int (out, "compile_time_window_count",
                      (int64_t)g_sha3_windows_count);
    json_push_kv_int (out, "compile_time_prefix_end_height", compile_end);
    json_push_kv_int (out, "effective_prefix_end_height", runtime_end);
    json_push_kv_int (out, "confirmation_depth", depth);
    json_push_kv_int (out, "max_extend_per_call", cap);
    json_push_kv_str (out, "file_path", path_copy);
    json_push_kv_int (out, "total_extended",
                      atomic_load(&g_ra.total_extended));
    json_push_kv_int (out, "total_skipped_policy",
                      atomic_load(&g_ra.total_skipped_policy));
    json_push_kv_int (out, "total_oracle_divergence_observed", atomic_load(&g_ra.total_oracle_divergence_observed));
    json_push_kv_int (out, "total_skipped_depth",
                      atomic_load(&g_ra.total_skipped_depth));
    json_push_kv_int (out, "total_skipped_missing_body",
                      atomic_load(&g_ra.total_skipped_missing_body));
    json_push_kv_int (out, "total_read_failures",
                      atomic_load(&g_ra.total_read_failures));
    json_push_kv_int (out, "consecutive_read_failures",
                      atomic_load(&g_ra.consecutive_read_failures));
    json_push_kv_int (out, "last_read_fail_height",
                      atomic_load(&g_ra.last_read_fail_height));
    json_push_kv_int (out, "last_missing_body_height",
                      atomic_load(&g_ra.last_missing_body_height));
    json_push_kv_bool(out, "read_fail_paged",
                      atomic_load(&g_ra.read_fail_paged));
    json_push_kv_int (out, "last_extend_unix",
                      atomic_load(&g_ra.last_extend_unix));
    return true;
}
void rolling_anchor_reset_for_test(void)
{
    rolling_anchor_stop();
#ifdef ZCL_TESTING
    supervisor_child_id id = atomic_exchange(&g_ra_supervisor_id,
                                             SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
    pthread_mutex_lock(&g_ra.lock);
    free(g_ra.windows);
    g_ra.windows = NULL;
    g_ra.count = 0;
    g_ra.capacity = 0;
    g_ra.initialized = false;
    g_ra.file_path[0] = '\0';
    g_ra.tick_ms = NULL;
    g_ra.tick_datadir[0] = '\0';
    pthread_mutex_unlock(&g_ra.lock);
    atomic_store(&g_ra.total_extended, 0);
    atomic_store(&g_ra.total_skipped_policy, 0);
    atomic_store(&g_ra.total_oracle_divergence_observed, 0);
    atomic_store(&g_ra.total_skipped_depth, 0);
    atomic_store(&g_ra.total_skipped_missing_body, 0);
    atomic_store(&g_ra.total_read_failures, 0);
    atomic_store(&g_ra.consecutive_read_failures, 0);
    atomic_store(&g_ra.last_read_fail_height, -1);
    atomic_store(&g_ra.last_missing_body_height, -1);
    atomic_store(&g_ra.read_fail_paged, false);
    atomic_store(&g_ra.last_extend_unix, 0);
}
#ifdef ZCL_TESTING
struct zcl_result rolling_anchor_test_commit_window(int32_t start_height,
                                                     const uint8_t hash[32])
{
    if (!hash)
        return ZCL_ERR(-1, "rolling_anchor test commit: null hash");
    pthread_mutex_lock(&g_ra.lock);
    int expected_start = ra_runtime_end_locked() + 1;
    if (!g_ra.initialized || start_height != expected_start ||
        start_height % (int32_t)SHA3_WINDOW_SIZE != 0) {
        pthread_mutex_unlock(&g_ra.lock);
        return ZCL_ERR(-1,
                       "rolling_anchor test commit: start=%d expected=%d",
                       start_height, expected_start);
    }
    if (g_ra.count == g_ra.capacity) {
        int new_capacity = g_ra.capacity ? g_ra.capacity * 2 : 16;
        struct ra_record *windows = zcl_realloc(
            g_ra.windows, (size_t)new_capacity * sizeof(*windows),
            "rolling_anchor.test.windows");
        if (!windows) {
            pthread_mutex_unlock(&g_ra.lock);
            return ZCL_ERR(-1, "rolling_anchor test commit: allocation failed");
        }
        g_ra.windows = windows;
        g_ra.capacity = new_capacity;
    }
    g_ra.windows[g_ra.count].start_height = start_height;
    memcpy(g_ra.windows[g_ra.count].hash, hash, 32);
    g_ra.count++;
    bool persisted = ra_persist_locked();
    if (!persisted)
        g_ra.count--;
    pthread_mutex_unlock(&g_ra.lock);
    return persisted ? ZCL_OK
                     : ZCL_ERR(-1, "rolling_anchor test commit: persist failed");
}
void rolling_anchor_test_inject_read_failure(int32_t failing_height)
{ atomic_fetch_add(&g_ra.total_read_failures, 1); atomic_fetch_add(&g_ra.consecutive_read_failures, 1); atomic_store(&g_ra.last_read_fail_height, failing_height); }
void rolling_anchor_test_note_window_read_failure(int32_t sealed_end,
        int32_t next_start, int32_t failing_height)
{ (void)ra_note_window_read_failure(sealed_end, next_start, failing_height); }
int64_t rolling_anchor_test_total_read_failures(void)
{ return atomic_load(&g_ra.total_read_failures); }
int64_t rolling_anchor_test_total_skipped_missing_body(void)
{ return atomic_load(&g_ra.total_skipped_missing_body); }
int64_t rolling_anchor_test_consecutive_read_failures(void)
{ return atomic_load(&g_ra.consecutive_read_failures); }
void rolling_anchor_test_reset_read_failures(void)
{
    atomic_store(&g_ra.consecutive_read_failures, 0);
    atomic_store(&g_ra.total_read_failures, 0);
    atomic_store(&g_ra.total_skipped_missing_body, 0);
    atomic_store(&g_ra.last_read_fail_height, -1);
    atomic_store(&g_ra.last_missing_body_height, -1);
    atomic_store(&g_ra.read_fail_paged, false);
}
void rolling_anchor_test_run_stall_escalation(void)
{ rolling_anchor_on_stall(NULL); }
#endif
