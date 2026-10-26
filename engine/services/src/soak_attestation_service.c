/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * soak_attestation_service — persistent evidence log for the 7-day soak
 * criterion (MVP criterion 7).
 *
 * Appends one JSON line per tick to <datadir>/soak_attestation.jsonl.
 * Fsyncs every SOAK_ATTESTATION_FSYNC_EVERY lines; rotates to .1 at 50 MB.
 *
 * Layout:
 *   1. Global state + mutex
 *   2. File management (open, rotate, fsync)
 *   3. soak_attestation_tick() — tick body
 *   4. soak_attestation_init() / soak_attestation_reset_for_test()
 *   5. soak_dump_state_json()
 *
 * LOCK-ORDER LAW: this service runs on the health-ring periodic tick only.
 * node_health_collect() is safe here (it takes csr->lock THEN coins_kv, the
 * established order on the health/RPC path). This service NEVER touches the
 * reducer drive — no coins_kv held on entry, no csr or chain-evidence init.
 *
 * The g_soak mutex is a leaf mutex (no further mutex is acquired while it is
 * held, aside from the platform file write/flush calls). */

// one-result-type-ok:soak-attest-no-fallible-surface
/* E2 override. soak_attestation_tick() and soak_attestation_init() return
 * void: write failures are best-effort (logged once per streak, never a
 * node halt), so there is no error result to propagate. soak_dump_state_json
 * is a pure introspection query (bool = whether out was valid). */

#include "services/soak_attestation_service.h"
#include "controllers/agent_security_posture.h"
#include "services/node_health_service.h"
#include "json/json.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "util/clientversion.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* ── Global state ──────────────────────────────────────────────── */

static struct {
    pthread_mutex_t lock;           /* guards all fields below */
    bool   initialized;
    char   datadir[512];

    /* Private, no-reparse file handle; file_open says whether it is live. */
    struct platform_private_file file;
    bool   file_open;
    /* Current file size in bytes (approximate; used for rotation). */
    int64_t file_bytes;
    /* Lines written since last fsync. */
    int64_t lines_since_fsync;

    /* Counters (protected by lock; read atomically for dump). */
    _Atomic int64_t lines_written;
    _Atomic int64_t last_ts;
    _Atomic bool    last_healthy;
    _Atomic bool    last_window_eligible;
    _Atomic bool    last_security_review_required;
    _Atomic int64_t rotations;
    _Atomic int64_t write_failures;

    /* Failure-streak latch: 0 = ok, >0 = in a failure streak.
     * We log exactly once when the streak starts (latch goes 0 → 1);
     * subsequent failures in the same streak are silent. */
    int failure_streak;
} g_soak = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

/* ── File management ────────────────────────────────────────────── */

/* Build the primary and rotation paths from the datadir. */
static void soak_path_primary(const char *datadir, char *out, size_t sz)
{
    snprintf(out, sz, "%s/soak_attestation.jsonl", datadir);
}
static void soak_path_rotated(const char *datadir, char *out, size_t sz)
{
    snprintf(out, sz, "%s/soak_attestation.jsonl.1", datadir);
}

/* Open the existing private file or create it owner-private. The service has
 * one locked writer and carries its own explicit append offset. */
static bool soak_open_file(const char *datadir)
{
    char path[560];
    soak_path_primary(datadir, path, sizeof(path));
    platform_private_file_init(&g_soak.file);
    bool opened = platform_private_file_open_locked(path, &g_soak.file);
    if (!opened && platform_private_path_absent(path))
        opened = platform_private_file_create(path, &g_soak.file);
    uint64_t size = 0;
    if (!opened || !platform_private_file_size(&g_soak.file, &size) ||
        size > INT64_MAX) {
        if (opened)
            platform_private_file_close(&g_soak.file);
        LOG_WARN("soak_attest", "open private attestation file failed: %s",
                 path);
        g_soak.file_open = false;
        return false;
    }
    g_soak.file_open = true;
    g_soak.file_bytes = (int64_t)size;
    return true;
}

/* Rotate: rename primary to .1 (overwrites any stale .1), close old fd,
 * open a fresh primary.  Called with g_soak.lock held. */
static bool soak_rotate(void)
{
    const char *dd = g_soak.datadir;
    char primary[560], rotated[560];
    soak_path_primary(dd, primary, sizeof(primary));
    soak_path_rotated(dd, rotated, sizeof(rotated));

    bool replaced = false;
    if (g_soak.file_open) {
        /* The periodic log is best-effort, but a published rotation must be
         * handle-flushed, atomically replaced, and directory-durable. */
        replaced = platform_private_file_replace(
            &g_soak.file, primary, rotated);
        g_soak.file_open = false;
        if (!replaced) {
            platform_private_file_close(&g_soak.file);
        }
    }
    if (!replaced) {
        LOG_WARN("soak_attest", "rotate replace %s -> %s failed; retaining primary evidence",
                 primary, rotated);
        return false;
    }
    if (!platform_private_parent_flush(dd)) {
        LOG_WARN("soak_attest", "rotation directory flush failed: %s", dd);
        return false;
    }
    atomic_fetch_add(&g_soak.rotations, 1);

    /* Open a fresh primary for subsequent writes. */
    g_soak.lines_since_fsync = 0;
    return soak_open_file(dd);
}

/* Called under g_soak.lock. A refusal never reopens an oversized primary
 * for append during the same tick. The next tick may retry the rotation. */
static bool soak_prepare_file(void)
{
    if (!g_soak.file_open && !soak_open_file(g_soak.datadir))
        return false; /* soak_open_file logged the failing path. */
    if (g_soak.file_bytes < SOAK_ATTESTATION_ROTATE_BYTES)
        return true;
    return soak_rotate();
}

/* ── Tick body ──────────────────────────────────────────────────── */

/* Everything one tick records, gathered outside g_soak.lock. */
struct soak_tick_sample {
    struct node_health_snapshot snap;
    struct agent_security_posture security;
    int64_t ts_now;
    bool    security_ok;
    bool    healthy;
    bool    window_eligible;
};

/* Outcome of the locked pre-flight step at the top of the tick. */
enum soak_tick_prepared {
    SOAK_TICK_SKIP,   /* not initialized: silent no-op */
    SOAK_TICK_FAILED, /* prepare failed: failure already counted under lock */
    SOAK_TICK_READY,  /* lock released; the tick may record its line */
};

/* Pre-flight under g_soak.lock: skip when uninitialized, count the failure
 * under the lock when the file cannot be prepared, else release the lock
 * and report ready. Every non-READY outcome is an early return upstream. */
static enum soak_tick_prepared soak_tick_preflight(void)
{
    pthread_mutex_lock(&g_soak.lock);
    if (!g_soak.initialized) {
        pthread_mutex_unlock(&g_soak.lock);
        return SOAK_TICK_SKIP;
    }
    if (!soak_prepare_file()) {
        /* Failed rotation must leave a gap, not grow the old evidence file
         * beyond its bound or report a successful rotation. Retry on the
         * next supervised tick without blocking chain advancement. */
        atomic_fetch_add(&g_soak.write_failures, 1);
        g_soak.failure_streak++;
        pthread_mutex_unlock(&g_soak.lock);
        return SOAK_TICK_FAILED;
    }

    pthread_mutex_unlock(&g_soak.lock);
    return SOAK_TICK_READY;
}

/* Health snapshot — safe to call outside the lock (node_health_collect is
 * reentrant; g_soak.lock must not be held here because the health path
 * itself may take csr->lock THEN coins_kv, and g_soak.lock is unrelated). */
static void soak_collect_tick_sample(struct soak_tick_sample *s)
{
    s->snap = (struct node_health_snapshot){0};
    node_health_collect(&s->snap, NULL, NULL);
    agent_security_posture_collect(&s->security, NULL);

    s->ts_now      = (int64_t)platform_time_wall_time_t();
    s->security_ok =
        agent_security_posture_allows_public_serving(&s->security);
    s->healthy         = s->snap.healthy && s->security_ok;
    s->window_eligible = s->healthy && s->security_ok;
}

/* Escape the degraded_reason into a JSON-safe buffer.
 * degrade_reason is already a C string (at most 128 chars); the only
 * JSON-special chars that appear are '"' and '\' which we replace with a
 * safe '?'.  (This is minimal — not full JSON string escaping — but
 * sufficient for the ASCII-only reason strings this code produces.) */
static void soak_escape_degraded_reason(const char *src, char *out,
                                        size_t out_sz)
{
    size_t out_pos = 0;
    for (; *src && out_pos < out_sz - 1; src++) {
        unsigned char c = (unsigned char)*src;
        if (c == '"' || c == '\\' || c < 0x20) {
            out[out_pos++] = '?';
        } else {
            out[out_pos++] = (char)c;
        }
    }
    out[out_pos] = '\0';
}

/* Format the JSON line.  Keep it compact (one line, no trailing space). */
/*
 * Returns snprintf's own result so the caller can detect failure/truncation. */
static int soak_format_attestation_line(char *line, size_t line_sz,
                                        const struct soak_tick_sample *s,
                                        const char *reason,
                                        const char *source_id,
                                        const char *commit)
{
    return snprintf(line, line_sz,
        "{\"ts\":%lld,\"height\":%d,\"healthy\":%s,"
        "\"degraded_reason\":\"%s\","
        "\"security_review_required\":%s,"
        "\"security_posture_ok\":%s,\"window_eligible\":%s,"
        "\"source_id_sha256\":\"%s\",\"build_commit\":\"%s\","
        "\"uptime_s\":%lld}\n",
        (long long)s->ts_now,
        s->snap.tip_height,
        s->healthy ? "true" : "false",
        s->security_ok ? reason : s->security.status,
        s->security.review_required ? "true" : "false",
        s->security_ok ? "true" : "false",
        s->window_eligible ? "true" : "false",
        source_id ? source_id : "unknown",
        commit ? commit : "unknown",
        (long long)s->snap.uptime_seconds);
}

/* Called with g_soak.lock held when a line could not be written: bump the
 * failure-streak latch and the write_failures counter. */
static void soak_record_write_failure_locked(void)
{
    g_soak.failure_streak++;
    atomic_fetch_add(&g_soak.write_failures, 1);
}

/* Called with g_soak.lock held after a successful append: clear the streak,
 * advance the offsets and counters, keep the fsync cadence. */
static void soak_record_line_written_locked(int line_len,
                                            const struct soak_tick_sample *s)
{
    g_soak.failure_streak = 0;   /* streak cleared */
    g_soak.file_bytes += line_len;
    g_soak.lines_since_fsync++;
    int64_t total = atomic_fetch_add(&g_soak.lines_written, 1) + 1;
    atomic_store(&g_soak.last_ts, s->ts_now);
    atomic_store(&g_soak.last_healthy, s->healthy);
    atomic_store(&g_soak.last_window_eligible, s->window_eligible);
    atomic_store(&g_soak.last_security_review_required,
                 s->security.review_required);

    /* fsync every N lines to bound data-loss window. */
    if (g_soak.lines_since_fsync >= SOAK_ATTESTATION_FSYNC_EVERY) {
        (void)platform_private_file_flush(&g_soak.file);
        g_soak.lines_since_fsync = 0;
    }
    (void)total; /* used above only for readable counter update */
}

void soak_attestation_tick(void)
{
    if (soak_tick_preflight() != SOAK_TICK_READY)
        return;

    struct soak_tick_sample sample;
    soak_collect_tick_sample(&sample);

    char reason_esc[160] = {0};
    soak_escape_degraded_reason(sample.snap.degraded_reason, reason_esc,
                                sizeof(reason_esc));

    const char *source_id = zcl_build_source_id_sha256();
    const char *commit = zcl_build_commit();

    char line[640];
    int line_len = soak_format_attestation_line(line, sizeof(line), &sample,
                                                reason_esc, source_id, commit);

    if (line_len <= 0 || (size_t)line_len >= sizeof(line)) {
        /* Oversized or snprintf error — should never happen with fixed fields. */
        LOG_WARN("soak_attest", "line format failed len=%d", line_len);
        line_len = 0;
    }

    /* Write + failure tracking. */
    pthread_mutex_lock(&g_soak.lock);
    if (line_len > 0 && g_soak.file_open) {
        bool written = platform_private_file_write_at(
            &g_soak.file, line, (size_t)line_len,
            (uint64_t)g_soak.file_bytes);
        if (!written) {
            if (g_soak.failure_streak == 0) {
                LOG_WARN("soak_attest",
                         "write to soak_attestation.jsonl failed");
            }
            soak_record_write_failure_locked();
        } else {
            soak_record_line_written_locked(line_len, &sample);
        }
    } else if (line_len > 0 && !g_soak.file_open) {
        /* fd open failed on this tick cycle (e.g. datadir not yet mounted). */
        if (g_soak.failure_streak == 0)
            LOG_WARN("soak_attest", "fd not open; skipping line write");
        soak_record_write_failure_locked();
    }
    pthread_mutex_unlock(&g_soak.lock);
}

/* ── Init / reset ────────────────────────────────────────────────── */

void soak_attestation_init(const char *datadir)
{
    pthread_mutex_lock(&g_soak.lock);
    if (g_soak.file_open) {
        /* Shutdown/init replacement remains best-effort by service contract. */
        (void)platform_private_file_flush(&g_soak.file);
        platform_private_file_close(&g_soak.file);
        g_soak.file_open = false;
    }
    if (datadir && datadir[0]) {
        snprintf(g_soak.datadir, sizeof(g_soak.datadir), "%s", datadir);
        g_soak.initialized = true;
    } else {
        g_soak.initialized = false;
    }
    g_soak.file_bytes        = 0;
    g_soak.lines_since_fsync = 0;
    g_soak.failure_streak    = 0;
    pthread_mutex_unlock(&g_soak.lock);
}

void soak_attestation_reset_for_test(void)
{
    pthread_mutex_lock(&g_soak.lock);
    if (g_soak.file_open) {
        (void)platform_private_file_flush(&g_soak.file);
        platform_private_file_close(&g_soak.file);
        g_soak.file_open = false;
    }
    g_soak.initialized        = false;
    g_soak.datadir[0]         = '\0';
    g_soak.file_bytes         = 0;
    g_soak.lines_since_fsync  = 0;
    g_soak.failure_streak     = 0;
    pthread_mutex_unlock(&g_soak.lock);
    atomic_store(&g_soak.lines_written, 0);
    atomic_store(&g_soak.last_ts,       0);
    atomic_store(&g_soak.last_healthy,  false);
    atomic_store(&g_soak.last_window_eligible, false);
    atomic_store(&g_soak.last_security_review_required, false);
    atomic_store(&g_soak.rotations,     0);
    atomic_store(&g_soak.write_failures, 0);
}

/* ── State dump (see CLAUDE.md "Adding state introspection") ───── */

bool soak_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    pthread_mutex_lock(&g_soak.lock);
    bool   initialized = g_soak.initialized;
    char   datadir[sizeof(g_soak.datadir)];
    snprintf(datadir, sizeof(datadir), "%s", g_soak.datadir);
    int64_t file_bytes = g_soak.file_bytes;
    pthread_mutex_unlock(&g_soak.lock);

    json_push_kv_bool(out, "initialized",    initialized);
    json_push_kv_str (out, "datadir",        datadir[0] ? datadir : "");
    json_push_kv_int (out, "lines_written",
                      atomic_load(&g_soak.lines_written));
    json_push_kv_int (out, "last_ts",
                      atomic_load(&g_soak.last_ts));
    json_push_kv_bool(out, "last_healthy",
                      atomic_load(&g_soak.last_healthy));
    json_push_kv_bool(out, "last_window_eligible",
                      atomic_load(&g_soak.last_window_eligible));
    json_push_kv_bool(out, "last_security_review_required",
                      atomic_load(&g_soak.last_security_review_required));
    json_push_kv_int (out, "rotations",
                      atomic_load(&g_soak.rotations));
    json_push_kv_int (out, "write_failures",
                      atomic_load(&g_soak.write_failures));
    json_push_kv_int (out, "file_bytes",     file_bytes);
    return true;
}
