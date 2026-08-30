/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_seed_policy — see net/rom_seed_policy.h for the contract. This file
 * owns the process-wide policy/counter state, the tmp+rename JSON
 * persistence (mirrors lib/util/src/boot_status.c's crash-safety pattern),
 * and the pure admission/boost decisions.
 */

/* realpath() reaches this TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O1 and above; the build's
 * -D_POSIX_C_SOURCE=200809L declares it nowhere. Without this the file
 * compiles by accident of optimisation and breaks at -O0, under
 * -U_FORTIFY_SOURCE, and on any non-glibc libc. It must precede every
 * include: after them it does nothing. See lib/util/src/hw_profile.c. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "net/rom_seed_policy.h"

#include "json/json.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/util.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
char *realpath(const char *restrict path, char *restrict resolved_path);
#endif

/* ── process-wide state ─────────────────────────────────────────────── */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_loaded = false;
static char g_datadir_override[512]; /* ZCL_TESTING only; empty = use GetDataDir */

static _Atomic bool     g_enabled = ROM_SEED_POLICY_DEFAULT_ENABLED;
static _Atomic uint64_t g_global_bps = ROM_SEED_POLICY_DEFAULT_GLOBAL_BPS;
static _Atomic uint64_t g_per_peer_bps = ROM_SEED_POLICY_DEFAULT_PER_PEER_BPS;
static _Atomic uint32_t g_max_concurrency = ROM_SEED_POLICY_DEFAULT_MAX_CONCURRENCY;
static _Atomic uint32_t g_boost_days = ROM_SEED_POLICY_DEFAULT_BOOST_DAYS;

static _Atomic bool g_consensus_active = false;

static _Atomic uint64_t g_uploads_started_total = 0;
static _Atomic uint64_t g_uploads_finished_total = 0;
static _Atomic uint64_t g_uploads_refused_total = 0;
static _Atomic uint64_t g_bytes_served_total = 0;
static _Atomic uint32_t g_uploads_active = 0;
static _Atomic uint64_t g_policy_temp_sequence = 0;

/* ── validation (pure) ──────────────────────────────────────────────── */

static bool policy_valid(const struct rom_seed_policy *p, char *err,
                         size_t errlen)
{
    if (!p) {
        if (err && errlen) snprintf(err, errlen, "null policy");
        return false;
    }
    if (p->global_up_bytes_per_sec < ROM_SEED_POLICY_MIN_GLOBAL_BPS ||
        p->global_up_bytes_per_sec > ROM_SEED_POLICY_MAX_GLOBAL_BPS) {
        if (err && errlen)
            snprintf(err, errlen,
                    "global_up_bytes_per_sec out of range [%llu, %llu]",
                    (unsigned long long)ROM_SEED_POLICY_MIN_GLOBAL_BPS,
                    (unsigned long long)ROM_SEED_POLICY_MAX_GLOBAL_BPS);
        return false;
    }
    if (p->per_peer_up_bytes_per_sec < ROM_SEED_POLICY_MIN_PER_PEER_BPS ||
        p->per_peer_up_bytes_per_sec > ROM_SEED_POLICY_MAX_PER_PEER_BPS) {
        if (err && errlen)
            snprintf(err, errlen,
                    "per_peer_up_bytes_per_sec out of range [%llu, %llu]",
                    (unsigned long long)ROM_SEED_POLICY_MIN_PER_PEER_BPS,
                    (unsigned long long)ROM_SEED_POLICY_MAX_PER_PEER_BPS);
        return false;
    }
    if (p->per_peer_up_bytes_per_sec > p->global_up_bytes_per_sec) {
        if (err && errlen)
            snprintf(err, errlen,
                    "per_peer_up_bytes_per_sec must not exceed "
                    "global_up_bytes_per_sec");
        return false;
    }
    if (p->max_concurrent_uploads < ROM_SEED_POLICY_MIN_CONCURRENCY ||
        p->max_concurrent_uploads > ROM_SEED_POLICY_MAX_CONCURRENCY) {
        if (err && errlen)
            snprintf(err, errlen,
                    "max_concurrent_uploads out of range [%u, %u]",
                    ROM_SEED_POLICY_MIN_CONCURRENCY,
                    ROM_SEED_POLICY_MAX_CONCURRENCY);
        return false;
    }
    if (p->generosity_boost_days > ROM_SEED_POLICY_MAX_BOOST_DAYS) {
        if (err && errlen)
            snprintf(err, errlen, "generosity_boost_days exceeds max %u",
                    ROM_SEED_POLICY_MAX_BOOST_DAYS);
        return false;
    }
    return true;
}

/* ── persistence (tmp+rename, mirrors boot_status_publish_locked) ─────── */

static bool policy_path(char *out, size_t out_size)
{
    char datadir[512], canonical[PATH_MAX], requested[600];
    if (g_datadir_override[0])
        (void)snprintf(datadir, sizeof(datadir), "%s", g_datadir_override);
    else
        GetDataDir(false, datadir, sizeof(datadir));
#ifdef _WIN32
    if (!_fullpath(canonical, datadir, sizeof(canonical)))
        return false;
#else
    if (!realpath(datadir, canonical))
        return false;
#endif
    int written = snprintf(requested, sizeof(requested), "%s/%s", canonical,
                           ROM_SEED_POLICY_FILENAME);
    if (written <= 0 || (size_t)written >= sizeof(requested))
        return false;
    char parent[600];
    return platform_private_path_resolve(requested, out, out_size, parent,
                                         sizeof(parent));
}

static void snapshot_locked(struct rom_seed_policy *out)
{
    out->enabled = atomic_load_explicit(&g_enabled, memory_order_relaxed);
    out->global_up_bytes_per_sec =
        atomic_load_explicit(&g_global_bps, memory_order_relaxed);
    out->per_peer_up_bytes_per_sec =
        atomic_load_explicit(&g_per_peer_bps, memory_order_relaxed);
    out->max_concurrent_uploads =
        atomic_load_explicit(&g_max_concurrency, memory_order_relaxed);
    out->generosity_boost_days =
        atomic_load_explicit(&g_boost_days, memory_order_relaxed);
}

static void apply_locked(const struct rom_seed_policy *p)
{
    atomic_store_explicit(&g_enabled, p->enabled, memory_order_relaxed);
    atomic_store_explicit(&g_global_bps, p->global_up_bytes_per_sec,
                          memory_order_relaxed);
    atomic_store_explicit(&g_per_peer_bps, p->per_peer_up_bytes_per_sec,
                          memory_order_relaxed);
    atomic_store_explicit(&g_max_concurrency, p->max_concurrent_uploads,
                          memory_order_relaxed);
    atomic_store_explicit(&g_boost_days, p->generosity_boost_days,
                          memory_order_relaxed);
}

/* Best-effort write; logs and returns on any failure without disturbing the
 * in-memory policy the caller already applied. */
static void persist_locked(const struct rom_seed_policy *p)
{
    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    (void)json_push_kv_str(&root, "schema", ROM_SEED_POLICY_SCHEMA);
    (void)json_push_kv_bool(&root, "enabled", p->enabled);
    (void)json_push_kv_int(&root, "global_up_bytes_per_sec",
                           (int64_t)p->global_up_bytes_per_sec);
    (void)json_push_kv_int(&root, "per_peer_up_bytes_per_sec",
                           (int64_t)p->per_peer_up_bytes_per_sec);
    (void)json_push_kv_int(&root, "max_concurrent_uploads",
                           (int64_t)p->max_concurrent_uploads);
    (void)json_push_kv_int(&root, "generosity_boost_days",
                           (int64_t)p->generosity_boost_days);
    (void)json_push_kv_int(&root, "updated_unix",
                           platform_time_wall_unix());

    char buf[512];
    size_t n = json_write(&root, buf, sizeof(buf));
    json_free(&root);
    if (n == 0 || n >= sizeof(buf)) {
        LOG_WARN("rom_seed_policy", "serialize failed");
        return;
    }

    char final_path[600] = {0};
    char resolved_path[600];
    char parent[600];
    char tmp_path[640];
    if (!policy_path(final_path, sizeof(final_path)) ||
        !platform_private_path_resolve(final_path, resolved_path,
                                       sizeof(resolved_path), parent,
                                       sizeof(parent))) {
        LOG_WARN("rom_seed_policy", "policy destination is not safe: %s",
                 final_path);
        return;
    }

    struct platform_private_file staged;
    platform_private_file_init(&staged);
    bool created = false;
    for (unsigned int attempt = 0; attempt < 64 && !created; attempt++) {
        uint64_t seq = atomic_fetch_add(&g_policy_temp_sequence, 1);
        int written = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%llu",
                               resolved_path, (unsigned long long)seq);
        if (written <= 0 || (size_t)written >= sizeof(tmp_path))
            break;
        created = platform_private_file_create(tmp_path, &staged);
        if (!created && errno != EEXIST)
            break;
    }
    if (!created) {
        LOG_WARN("rom_seed_policy", "private staging create failed for %s",
                 resolved_path);
        return;
    }
    bool ok = platform_private_file_write_at(&staged, buf, n, 0) &&
              platform_private_file_truncate(&staged, n) &&
              platform_private_file_flush(&staged) &&
              platform_private_file_replace(&staged, tmp_path,
                                             resolved_path);
    platform_private_file_close(&staged);
    if (!ok || !platform_private_parent_flush(parent)) {
        LOG_WARN("rom_seed_policy", "durable policy replace failed for %s",
                 resolved_path);
        (void)platform_private_file_unlink_missing_ok(tmp_path);
    }
}

/* Fill `out` from the persisted file. Returns false (out untouched) when
 * the file is missing, unreadable, not a JSON object, or fails bounds
 * validation — every case falls back to the compiled defaults, never a
 * crash and never a half-applied policy. */
static bool load_from_disk(struct rom_seed_policy *out)
{
    char path[600];
    if (!policy_path(path, sizeof(path)))
        return false;

    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    char raw[2048];
    if (!platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size >= sizeof(raw)) {
        platform_positioned_file_close(&file);
        return false;
    }
    int64_t r = platform_positioned_file_read(&file, raw,
                                              (size_t)before.size, 0);
    bool stable = r == (int64_t)before.size &&
                  platform_positioned_file_snapshot(&file, &after) &&
                  before.volume == after.volume &&
                  before.file_low == after.file_low &&
                  before.file_high == after.file_high &&
                  before.size == after.size &&
                  before.modified_seconds == after.modified_seconds &&
                  before.modified_nanoseconds == after.modified_nanoseconds &&
                  before.changed_seconds == after.changed_seconds &&
                  before.changed_nanoseconds == after.changed_nanoseconds;
    platform_positioned_file_close(&file);
    if (!stable)
        return false;
    raw[r] = '\0';

    struct json_value doc;
    if (!json_read(&doc, raw, (size_t)r) || doc.type != JSON_OBJ) {
        json_free(&doc);
        LOG_WARN("rom_seed_policy", "%s is not a JSON object; using defaults",
                 path);
        return false;
    }

    struct rom_seed_policy p;
    memset(&p, 0, sizeof(p));
    p.enabled = json_get_bool(json_get(&doc, "enabled"));
    p.global_up_bytes_per_sec =
        (uint64_t)json_get_int(json_get(&doc, "global_up_bytes_per_sec"));
    p.per_peer_up_bytes_per_sec =
        (uint64_t)json_get_int(json_get(&doc, "per_peer_up_bytes_per_sec"));
    p.max_concurrent_uploads =
        (uint32_t)json_get_int(json_get(&doc, "max_concurrent_uploads"));
    p.generosity_boost_days =
        (uint32_t)json_get_int(json_get(&doc, "generosity_boost_days"));
    json_free(&doc);

    char err[160];
    if (!policy_valid(&p, err, sizeof(err))) {
        LOG_WARN("rom_seed_policy", "%s failed validation (%s); using "
                 "defaults", path, err);
        return false;
    }
    *out = p;
    return true;
}

/* Load-on-first-use: real disk file if present+valid, else the compiled
 * defaults held in memory only. Deliberately never writes the defaults
 * back to disk here — a bare read (rom_seed_policy_get(), and therefore
 * dumpstate/introspection) must never have a disk side effect, since any
 * caller can trigger it, including a passive whole-registry sweep (e.g.
 * the `unhealthy` health rollup, app/controllers/src/diagnostics_health_
 * rollup.c, which walks and invokes every registered dumper) running in a
 * process that never set up a test-isolated datadir. The file is written
 * lazily on the first ACTUAL owner mutation instead — see
 * rom_seed_policy_apply()/_set_enabled()/_reset_to_defaults(), each of
 * which calls persist_locked() explicitly. Caller holds g_lock. */
static void ensure_loaded_locked(void)
{
    if (g_loaded)
        return;
    struct rom_seed_policy p;
    if (load_from_disk(&p)) {
        apply_locked(&p);
    } else {
        struct rom_seed_policy defaults = {
            .enabled = ROM_SEED_POLICY_DEFAULT_ENABLED,
            .global_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_GLOBAL_BPS,
            .per_peer_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_PER_PEER_BPS,
            .max_concurrent_uploads = ROM_SEED_POLICY_DEFAULT_MAX_CONCURRENCY,
            .generosity_boost_days = ROM_SEED_POLICY_DEFAULT_BOOST_DAYS,
        };
        apply_locked(&defaults);
    }
    g_loaded = true;
}

/* ── public read/apply API ─────────────────────────────────────────── */

void rom_seed_policy_get(struct rom_seed_policy *out)
{
    if (!out)
        return;
    pthread_mutex_lock(&g_lock);
    ensure_loaded_locked();
    snapshot_locked(out);
    pthread_mutex_unlock(&g_lock);
}

bool rom_seed_policy_apply(const struct rom_seed_policy *in, char *err,
                           size_t errlen)
{
    if (err && errlen) err[0] = '\0';
    if (!policy_valid(in, err, errlen))
        return false;
    pthread_mutex_lock(&g_lock);
    ensure_loaded_locked();
    apply_locked(in);
    persist_locked(in);
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool rom_seed_policy_set_enabled(bool enabled)
{
    pthread_mutex_lock(&g_lock);
    ensure_loaded_locked();
    struct rom_seed_policy p;
    snapshot_locked(&p);
    p.enabled = enabled;
    apply_locked(&p);
    persist_locked(&p);
    pthread_mutex_unlock(&g_lock);
    return true;
}

bool rom_seed_policy_reset_to_defaults(void)
{
    struct rom_seed_policy defaults = {
        .enabled = ROM_SEED_POLICY_DEFAULT_ENABLED,
        .global_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_GLOBAL_BPS,
        .per_peer_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_PER_PEER_BPS,
        .max_concurrent_uploads = ROM_SEED_POLICY_DEFAULT_MAX_CONCURRENCY,
        .generosity_boost_days = ROM_SEED_POLICY_DEFAULT_BOOST_DAYS,
    };
    pthread_mutex_lock(&g_lock);
    apply_locked(&defaults);
    persist_locked(&defaults);
    g_loaded = true;
    pthread_mutex_unlock(&g_lock);
    return true;
}

/* ── consensus-preempts signal ─────────────────────────────────────── */

void rom_seed_policy_set_consensus_active(bool active)
{
    atomic_store_explicit(&g_consensus_active, active, memory_order_relaxed);
}

bool rom_seed_policy_consensus_active(void)
{
    return atomic_load_explicit(&g_consensus_active, memory_order_relaxed);
}

/* ── pure decisions ─────────────────────────────────────────────────── */

bool rom_seed_policy_admit_upload(uint32_t current_active_uploads)
{
    if (!atomic_load_explicit(&g_enabled, memory_order_relaxed))
        return false;
    if (atomic_load_explicit(&g_consensus_active, memory_order_relaxed))
        return false;
    uint32_t cap =
        atomic_load_explicit(&g_max_concurrency, memory_order_relaxed);
    return current_active_uploads < cap;
}

bool rom_seed_policy_is_boosted(int64_t artifact_first_seen_unix,
                                int64_t now_unix)
{
    if (artifact_first_seen_unix <= 0)
        return false;
    uint32_t days =
        atomic_load_explicit(&g_boost_days, memory_order_relaxed);
    if (days == 0)
        return false;
    if (now_unix < artifact_first_seen_unix)
        return true; /* clock skew: treat as freshly seen, not expired */
    int64_t window_secs = (int64_t)days * 86400;
    return (now_unix - artifact_first_seen_unix) < window_secs;
}

uint64_t rom_seed_policy_effective_per_peer_cap(bool boosted)
{
    uint64_t per_peer =
        atomic_load_explicit(&g_per_peer_bps, memory_order_relaxed);
    uint64_t global =
        atomic_load_explicit(&g_global_bps, memory_order_relaxed);
    uint64_t cap = per_peer;
    if (boosted) {
        uint64_t boosted_cap = per_peer * ROM_SEED_POLICY_DEFAULT_BOOST_MULTIPLIER;
        /* Overflow guard: bytes/sec caps are far below UINT64_MAX/4 given
         * the MAX_PER_PEER_BPS ceiling, but stay defensive. */
        if (boosted_cap < per_peer)
            boosted_cap = global;
        cap = boosted_cap;
    }
    return cap > global ? global : cap;
}

/* ── live counters ─────────────────────────────────────────────────── */

void rom_seed_policy_note_upload_started(void)
{
    atomic_fetch_add_explicit(&g_uploads_started_total, 1,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&g_uploads_active, 1, memory_order_relaxed);
}

void rom_seed_policy_note_upload_finished(uint64_t bytes_sent)
{
    atomic_fetch_add_explicit(&g_uploads_finished_total, 1,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&g_bytes_served_total, bytes_sent,
                              memory_order_relaxed);
    uint32_t prev =
        atomic_load_explicit(&g_uploads_active, memory_order_relaxed);
    while (prev > 0 &&
          !atomic_compare_exchange_weak_explicit(
              &g_uploads_active, &prev, prev - 1, memory_order_relaxed,
              memory_order_relaxed))
        ; /* retry */
}

void rom_seed_policy_note_upload_refused(void)
{
    atomic_fetch_add_explicit(&g_uploads_refused_total, 1,
                              memory_order_relaxed);
}

void rom_seed_policy_get_counters(struct rom_seed_policy_counters *out)
{
    if (!out)
        return;
    out->uploads_started_total =
        atomic_load_explicit(&g_uploads_started_total, memory_order_relaxed);
    out->uploads_finished_total =
        atomic_load_explicit(&g_uploads_finished_total, memory_order_relaxed);
    out->uploads_refused_total =
        atomic_load_explicit(&g_uploads_refused_total, memory_order_relaxed);
    out->bytes_served_total =
        atomic_load_explicit(&g_bytes_served_total, memory_order_relaxed);
    out->uploads_active =
        atomic_load_explicit(&g_uploads_active, memory_order_relaxed);
}

/* ── introspection ──────────────────────────────────────────────────── */

bool rom_seed_policy_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct rom_seed_policy p;
    rom_seed_policy_get(&p);
    struct rom_seed_policy_counters c;
    rom_seed_policy_get_counters(&c);

    struct json_value policy_obj;
    json_init(&policy_obj);
    json_set_object(&policy_obj);
    (void)json_push_kv_bool(&policy_obj, "enabled", p.enabled);
    (void)json_push_kv_int(&policy_obj, "global_up_bytes_per_sec",
                           (int64_t)p.global_up_bytes_per_sec);
    (void)json_push_kv_int(&policy_obj, "per_peer_up_bytes_per_sec",
                           (int64_t)p.per_peer_up_bytes_per_sec);
    (void)json_push_kv_int(&policy_obj, "max_concurrent_uploads",
                           (int64_t)p.max_concurrent_uploads);
    (void)json_push_kv_int(&policy_obj, "generosity_boost_days",
                           (int64_t)p.generosity_boost_days);
    (void)json_push_kv_bool(&policy_obj, "consensus_active",
                            rom_seed_policy_consensus_active());
    (void)json_push_kv(out, "policy", &policy_obj);
    json_free(&policy_obj);

    struct json_value counters_obj;
    json_init(&counters_obj);
    json_set_object(&counters_obj);
    (void)json_push_kv_int(&counters_obj, "uploads_active",
                           (int64_t)c.uploads_active);
    (void)json_push_kv_int(&counters_obj, "uploads_started_total",
                           (int64_t)c.uploads_started_total);
    (void)json_push_kv_int(&counters_obj, "uploads_finished_total",
                           (int64_t)c.uploads_finished_total);
    (void)json_push_kv_int(&counters_obj, "uploads_refused_total",
                           (int64_t)c.uploads_refused_total);
    (void)json_push_kv_int(&counters_obj, "bytes_served_total",
                           (int64_t)c.bytes_served_total);
    (void)json_push_kv(out, "counters", &counters_obj);
    json_free(&counters_obj);

    diag_push_health(out, true, "");
    return true;
}

#ifdef ZCL_TESTING
void rom_seed_policy_test_reset(const char *datadir_override)
{
    pthread_mutex_lock(&g_lock);
    if (datadir_override && datadir_override[0])
        snprintf(g_datadir_override, sizeof(g_datadir_override), "%s",
                datadir_override);
    else
        g_datadir_override[0] = '\0';
    g_loaded = false;
    struct rom_seed_policy defaults = {
        .enabled = ROM_SEED_POLICY_DEFAULT_ENABLED,
        .global_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_GLOBAL_BPS,
        .per_peer_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_PER_PEER_BPS,
        .max_concurrent_uploads = ROM_SEED_POLICY_DEFAULT_MAX_CONCURRENCY,
        .generosity_boost_days = ROM_SEED_POLICY_DEFAULT_BOOST_DAYS,
    };
    apply_locked(&defaults);
    atomic_store_explicit(&g_consensus_active, false, memory_order_relaxed);
    atomic_store_explicit(&g_uploads_started_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_uploads_finished_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_uploads_refused_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_bytes_served_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_uploads_active, 0, memory_order_relaxed);
    pthread_mutex_unlock(&g_lock);
}
#endif
