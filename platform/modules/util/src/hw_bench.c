/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * hw_bench — implementation. See util/hw_bench.h for the contract.
 *
 * Two probes, both pure POSIX syscalls, no external deps:
 *   1. fsync latency  — write+fsync a small probe file ~8 times, median.
 *   2. 4KB pread latency — pread an existing datadir file at ~32 random
 *      offsets, median.
 *
 * Persistence is a plain "key=value\n" flat file (`hw_bench.kv`) written
 * atomically (tmp + rename) — deliberately NOT progress.kv/node.db/any
 * consensus store, and deliberately NOT SQLite: this is a disposable
 * measurement cache keyed by a hardware fingerprint, safe to delete at any
 * time (the next boot just re-measures). */

#include "util/hw_bench.h"

#include "util/hw_profile.h"
#include "util/util.h"              /* GetDataDir */
#include "platform/time_compat.h"   /* platform_time_monotonic_us/realtime_us */
#include "platform/directory_compat.h"
#include "platform/file_metadata.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HW_BENCH_CACHE_FILENAME  "hw_bench.kv"
#define HW_BENCH_PROBE_FILENAME  ".hw_bench_probe.tmp"
#define HW_BENCH_PATH_MAX        PATH_MAX

#define HW_BENCH_FSYNC_SAMPLES         8
#define HW_BENCH_PREAD_SAMPLES         32
#define HW_BENCH_PREAD_CHUNK           4096
#define HW_BENCH_MIN_SAMPLE_FILE_BYTES (128 * 1024)

/* Combined wall-clock budget for BOTH probes; each individual probe is also
 * soft-capped at half that so one slow probe cannot starve the other. */
#define HW_BENCH_TOTAL_BUDGET_US  (300 * 1000)
#define HW_BENCH_PHASE_BUDGET_US  (150 * 1000)

/* Scaling baselines ("healthy NVMe/SSD" reference points) + clamps for the
 * derived tunables. Picked from well-known SSD-vs-HDD latency gaps (SSD
 * fsync ~1-3ms / random 4K read ~0.1-0.3ms; spinning-disk seek-bound fsync
 * and random read commonly land one to two orders of magnitude higher) —
 * not a claim of precision, just "clearly slower than a healthy SSD". */
#define HW_BENCH_FSYNC_BASELINE_US   2000
#define HW_BENCH_BATCH_SIZE_CEILING  2000  /* mirrors refold_cadence's accelerated default */
#define HW_BENCH_PREAD_BASELINE_US   200

struct hw_bench_state {
    bool    valid;      /* at least one of fsync_us/pread_us is measured */
    bool    from_cache;
    int64_t fsync_us;   /* -1 == unmeasured */
    int64_t pread_us;   /* -1 == unmeasured */
    int64_t measured_at_unix;
    char    fingerprint[17];
};

static pthread_mutex_t       g_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool          g_inited = false;
static struct hw_bench_state g_state;

#ifdef ZCL_TESTING
/* Counts real bench_fsync/bench_pread probe PASSES (not cache loads, not
 * query calls). Exists so a test can prove hw_bench_batch_size() et al.
 * never trigger a probe — see test_hw_bench.c's
 * "batch_size never triggers the probe" case, which is the regression test
 * for the hot-path-fsync defect this file's boot-time-init split fixed. */
static _Atomic int g_probe_run_count = 0;

int hw_bench_probe_run_count_for_testing(void)
{
    return atomic_load(&g_probe_run_count);
}
#endif

/* ── Fingerprint ───────────────────────────────────────────────────── */

/* FNV-1a over the hw_profile signature this measurement was taken under.
 * Local (not the shared file_tree_ops one) — one small pure function, no
 * cross-module dependency for a single hash.
 *
 * `datadir` MUST be the resolved datadir, never NULL/empty when one is
 * known: hw_profile_init() is a one-shot latch (first caller wins for the
 * life of the process), and hw_bench_init() is called very early in boot —
 * often before anything else has ever touched hw_profile. Passing NULL here
 * used to win that race and permanently pin hw_profile's sysfs rotational
 * probe to "unknown" (probe_datadir_rotational() refuses a NULL/empty
 * datadir), so storage_pacing's later hw_profile_init(datadir) call became a
 * silent no-op and every box — including a real spinning disk — fell
 * through to the bench/probe fallbacks instead of the direct sysfs answer. */
static void compute_fingerprint(const char *datadir, char out[17])
{
    hw_profile_init(datadir);
    int online = hw_profile_online_cores();
    int physical = hw_profile_physical_cores();
    int64_t ram = hw_profile_ram_bytes();
    const struct hw_profile_isa *isa = hw_profile_isa();
    bool rot_known = false;
    bool rot = hw_profile_datadir_rotational(&rot_known);

    char buf[224];
    int n = snprintf(buf, sizeof(buf),
                     "%d|%d|%lld|%d%d%d%d%d%d%d%d%d|%d%d%d%d%d|%d|%d",
                     online, physical, (long long)ram,
                     isa->avx2, isa->avx512f, isa->avx512vl, isa->avx512bw,
                     isa->avx512dq, isa->vpclmulqdq, isa->vaes, isa->gfni,
                     isa->sha_ni, isa->arm_neon, isa->arm_sha256,
                     isa->arm_sha3, isa->arm_crc32, isa->arm_aes,
                     rot_known ? 1 : 0, rot ? 1 : 0);
    if (n < 0) n = 0;
    if ((size_t)n > sizeof(buf)) n = (int)sizeof(buf);

    uint64_t h = 1469598103934665603ULL; /* FNV-1a offset basis */
    for (int i = 0; i < n; i++) {
        h ^= (unsigned char)buf[i];
        h *= 1099511628211ULL; /* FNV-1a prime */
    }
    snprintf(out, 17, "%016llx", (unsigned long long)h);
}

/* ── Flat-file cache ───────────────────────────────────────────────── */

static bool cache_path(const char *datadir, char *out, size_t outsz)
{
    if (!datadir || !*datadir) return false;
    int n = snprintf(out, outsz, "%s/%s", datadir, HW_BENCH_CACHE_FILENAME);
    return n > 0 && (size_t)n < outsz;
}

static bool load_cache(const char *path, struct hw_bench_state *st)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;

    bool have_fp = false, have_ts = false, have_fsync = false, have_pread = false;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;
        if (strcmp(key, "fingerprint") == 0) {
            snprintf(st->fingerprint, sizeof(st->fingerprint), "%s", val);
            have_fp = strlen(st->fingerprint) == 16;
        } else if (strcmp(key, "measured_at") == 0) {
            st->measured_at_unix = strtoll(val, NULL, 10);
            have_ts = true;
        } else if (strcmp(key, "fsync_us") == 0) {
            st->fsync_us = strtoll(val, NULL, 10);
            have_fsync = true;
        } else if (strcmp(key, "pread_us") == 0) {
            st->pread_us = strtoll(val, NULL, 10);
            have_pread = true;
        }
    }
    fclose(f);
    return have_fp && have_ts && have_fsync && have_pread;
}

/* Best-effort, never fatal: a failed save just means next boot re-measures. */
static bool save_cache(const char *path, const struct hw_bench_state *st)
{
    char tmp[HW_BENCH_PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return false;

    FILE *f = fopen(tmp, "w");
    if (!f) return false;
    fprintf(f, "fingerprint=%s\nmeasured_at=%lld\nfsync_us=%lld\npread_us=%lld\n",
            st->fingerprint, (long long)st->measured_at_unix,
            (long long)st->fsync_us, (long long)st->pread_us);
    bool write_ok = ferror(f) == 0;
    if (fclose(f) != 0) write_ok = false;
    if (!write_ok) { unlink(tmp); return false; }
    if (rename(tmp, path) != 0) { unlink(tmp); return false; }
    return true;
}

/* ── Sampling primitives ──────────────────────────────────────────── */

static int cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

static int64_t median_i64(int64_t *arr, int n)
{
    if (n <= 0) return -1;
    qsort(arr, (size_t)n, sizeof(int64_t), cmp_i64);
    return arr[n / 2];
}

static uint64_t xorshift64(uint64_t *state)
{
    uint64_t x = *state;
    if (x == 0) x = 0x9E3779B97F4A7C15ULL;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

/* Median fsync() latency in us, or -1 if the probe file could not be
 * created/written. `budget_us` bounds how many SAMPLES are attempted, not
 * an individual fsync — a genuinely slow disk's own latency is the
 * measurement, not something to truncate mid-syscall. Needs >= 3 samples
 * to report a median (fewer is too noisy to act on). */
static int64_t bench_fsync(const char *datadir, int64_t budget_us)
{
    char path[HW_BENCH_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", datadir,
                     HW_BENCH_PROBE_FILENAME);
    if (n <= 0 || (size_t)n >= sizeof(path)) return -1;

    (void)platform_private_file_unlink_missing_ok(path);
    struct platform_private_file probe;
    platform_private_file_init(&probe);
    if (!platform_private_file_create(path, &probe)) return -1;

    unsigned char buf[64];
    memset(buf, 0xA5, sizeof(buf));

    int64_t samples[HW_BENCH_FSYNC_SAMPLES];
    int got = 0;
    int64_t start = platform_time_monotonic_us();
    for (int i = 0; i < HW_BENCH_FSYNC_SAMPLES; i++) {
        if (!platform_private_file_write_at(&probe, buf, sizeof(buf), 0) ||
            !platform_private_file_truncate(&probe, sizeof(buf))) break;
        int64_t t0 = platform_time_monotonic_us();
        if (!platform_private_file_flush(&probe)) break;
        int64_t t1 = platform_time_monotonic_us();
        samples[got++] = t1 - t0;
        if (budget_us > 0 && platform_time_monotonic_us() - start > budget_us)
            break;
    }
    platform_private_file_close(&probe);
    (void)platform_private_file_unlink_missing_ok(path);
    return got >= 3 ? median_i64(samples, got) : -1;
}

/* First regular file >= HW_BENCH_MIN_SAMPLE_FILE_BYTES directly under
 * `datadir` (skips dotfiles, including this module's own probe/cache
 * files, and subdirectories — a top-level scan is enough for a heuristic
 * latency probe). */
static bool find_sample_file(const char *datadir, char *out, size_t outsz,
                             off_t *out_size)
{
    struct platform_directory_list list = {0};
    if (!platform_directory_list_regular_sorted(datadir, &list)) return false;
    bool found = false;
    for (size_t i = 0; i < list.count; i++) {
        const char *name = list.entries[i].name;
        if (!name || name[0] == '.') continue;
        char full[HW_BENCH_PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s/%s", datadir, name);
        if (n <= 0 || (size_t)n >= (int)sizeof(full)) continue;
        struct platform_file_metadata metadata;
        if (platform_file_metadata_read(full, &metadata) !=
                PLATFORM_FILE_METADATA_OK ||
            metadata.size < HW_BENCH_MIN_SAMPLE_FILE_BYTES) continue;
        snprintf(out, outsz, "%s", full);
        *out_size = (off_t)metadata.size;
        found = true;
        break;
    }
    platform_directory_list_free(&list);
    return found;
}

/* Median 4KB pread() latency in us, or -1 if no suitable existing file was
 * found or every sample failed. Read-only — never mutates the sample
 * file. */
static int64_t bench_pread(const char *datadir, int64_t budget_us)
{
    char path[HW_BENCH_PATH_MAX];
    off_t size = 0;
    if (!find_sample_file(datadir, path, sizeof(path), &size))
        return -1;

    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path)) return -1;

    off_t max_off = size - HW_BENCH_PREAD_CHUNK;
    if (max_off < 0) { platform_positioned_file_close(&file); return -1; }

    uint64_t seed = (uint64_t)platform_time_monotonic_us() ^
                    0x9E3779B97F4A7C15ULL;
    unsigned char buf[HW_BENCH_PREAD_CHUNK];
    int64_t samples[HW_BENCH_PREAD_SAMPLES];
    int got = 0;
    int64_t start = platform_time_monotonic_us();
    for (int i = 0; i < HW_BENCH_PREAD_SAMPLES; i++) {
        off_t off = (off_t)(xorshift64(&seed) % (uint64_t)(max_off + 1));
        int64_t t0 = platform_time_monotonic_us();
        int64_t r = platform_positioned_file_read(&file, buf, sizeof(buf),
                                                  (uint64_t)off);
        int64_t t1 = platform_time_monotonic_us();
        if (r <= 0) break;
        samples[got++] = t1 - t0;
        if (budget_us > 0 && platform_time_monotonic_us() - start > budget_us)
            break;
    }
    platform_positioned_file_close(&file);
    return got >= 3 ? median_i64(samples, got) : -1;
}

/* ── Lifecycle ─────────────────────────────────────────────────────── */

static const char *source_tag(int64_t measured_value)
{
    return measured_value >= 0 ? "measured" : "fallback";
}

static void hw_bench_log_once(void)
{
    LOG_INFO("hw_bench",
             "[hw_bench] fsync_us=%lld(%s) pread_us=%lld(%s) fp=%s "
             "age=%llds source=%s | derived: batch_size(normal=100)=%d "
             "verify_workers(normal=4)=%d",
             (long long)g_state.fsync_us, source_tag(g_state.fsync_us),
             (long long)g_state.pread_us, source_tag(g_state.pread_us),
             g_state.fingerprint, (long long)hw_bench_age_seconds(),
             g_state.from_cache ? "cache" : "probe",
             hw_bench_batch_size(100), hw_bench_verify_workers(4));
}

bool hw_bench_init(const char *datadir)
{
    if (atomic_load(&g_inited)) return g_state.valid;

    pthread_mutex_lock(&g_lock);
    if (atomic_load(&g_inited)) {
        pthread_mutex_unlock(&g_lock);
        return g_state.valid;
    }

    char resolved[HW_BENCH_PATH_MAX];
    if (datadir && *datadir) {
        snprintf(resolved, sizeof(resolved), "%s", datadir);
    } else {
        GetDataDir(true, resolved, sizeof(resolved));
    }

    struct hw_bench_state st;
    memset(&st, 0, sizeof(st));
    st.fsync_us = -1;
    st.pread_us = -1;

    char fp_now[17];
    compute_fingerprint(resolved, fp_now);

    char cpath[HW_BENCH_PATH_MAX];
    bool have_cache_path = cache_path(resolved, cpath, sizeof(cpath));

    struct hw_bench_state cached;
    memset(&cached, 0, sizeof(cached));
    bool cache_ok = have_cache_path && load_cache(cpath, &cached);

    if (cache_ok && strcmp(cached.fingerprint, fp_now) == 0) {
        st = cached;
        st.from_cache = true;
        st.valid = true;
    } else {
        snprintf(st.fingerprint, sizeof(st.fingerprint), "%s", fp_now);
#ifdef ZCL_TESTING
        atomic_fetch_add(&g_probe_run_count, 1);
#endif
        int64_t total_start = platform_time_monotonic_us();
        st.fsync_us = bench_fsync(resolved, HW_BENCH_PHASE_BUDGET_US);
        int64_t elapsed = platform_time_monotonic_us() - total_start;
        int64_t remaining = HW_BENCH_TOTAL_BUDGET_US - elapsed;
        if (remaining > 10000) { /* need >=10ms left for a meaningful sample */
            int64_t pread_budget =
                remaining < HW_BENCH_PHASE_BUDGET_US ? remaining
                                                     : HW_BENCH_PHASE_BUDGET_US;
            st.pread_us = bench_pread(resolved, pread_budget);
        }
        st.measured_at_unix = platform_time_realtime_us() / 1000000;
        st.from_cache = false;
        st.valid = st.fsync_us >= 0 || st.pread_us >= 0;
        /* Only cache a measurement that actually got SOMETHING — an
         * all-unmeasured result (e.g. read-only datadir at this boot) is
         * left uncached so a later boot with a writable datadir retries
         * instead of being pinned to a permanent miss. */
        if (have_cache_path && st.valid)
            (void)save_cache(cpath, &st);
    }

    g_state = st;
    atomic_store(&g_inited, true);
    pthread_mutex_unlock(&g_lock);

    hw_bench_log_once();
    return true;
}

#ifdef ZCL_TESTING
void hw_bench_reset_for_testing(void)
{
    pthread_mutex_lock(&g_lock);
    memset(&g_state, 0, sizeof(g_state));
    atomic_store(&g_inited, false);
    pthread_mutex_unlock(&g_lock);
}

void hw_bench_set_measured_for_testing(int64_t fsync_us, int64_t pread_us)
{
    pthread_mutex_lock(&g_lock);
    memset(&g_state, 0, sizeof(g_state));
    g_state.fsync_us = fsync_us;
    g_state.pread_us = pread_us;
    g_state.valid = fsync_us >= 0 || pread_us >= 0;
    g_state.from_cache = false;
    g_state.measured_at_unix = platform_time_realtime_us() / 1000000;
    snprintf(g_state.fingerprint, sizeof(g_state.fingerprint),
             "0000000000000000");
    atomic_store(&g_inited, true);
    pthread_mutex_unlock(&g_lock);
}
#endif

/* ── Queries ───────────────────────────────────────────────────────────
 *
 * NONE of these call hw_bench_init() — that would risk running the
 * synchronous fsync/pread probe on whatever thread/lock context first
 * calls a query, which is exactly the hot-path defect this file's
 * boot-time-init split exists to close (see reducer_drain.c's
 * per_stage_batch comment and CLAUDE.md's tenacity notes on unbudgeted
 * disk IO on a hot path). Before hw_bench_init() has been called by
 * SOMEONE (boot.c calls it once, at boot, before the reducer can run;
 * bg_validation_init calls it once at its own startup) every query below
 * just serves its documented "unmeasured" default — a plain atomic load,
 * no lock, no syscall, no allocation. */

int64_t hw_bench_fsync_us(void)
{
    if (!atomic_load(&g_inited)) return -1;
    return g_state.fsync_us;
}

int64_t hw_bench_pread_us(void)
{
    if (!atomic_load(&g_inited)) return -1;
    return g_state.pread_us;
}

bool hw_bench_measured(void)
{
    if (!atomic_load(&g_inited)) return false;
    return g_state.fsync_us >= 0 || g_state.pread_us >= 0;
}

int64_t hw_bench_age_seconds(void)
{
    if (!atomic_load(&g_inited)) return -1;
    if (g_state.measured_at_unix <= 0) return -1;
    int64_t now = platform_time_realtime_us() / 1000000;
    int64_t age = now - g_state.measured_at_unix;
    return age >= 0 ? age : 0;
}

bool hw_bench_from_cache(void)
{
    if (!atomic_load(&g_inited)) return false;
    return g_state.from_cache;
}

const char *hw_bench_fingerprint_hex(void)
{
    if (!atomic_load(&g_inited)) return "";
    return g_state.fingerprint;
}

/* ── Derived tunables ──────────────────────────────────────────────────
 *
 * The hot-path contract: provably allocation-free and syscall-free.
 * `g_inited` false (hw_bench_init() never ran, or hasn't finished) just
 * means "serve the topology fallback unchanged" — never a reason to probe
 * from here. */

int hw_bench_batch_size(int normal_batch)
{
    if (normal_batch <= 0) normal_batch = 1;
    if (!atomic_load(&g_inited)) return normal_batch;

    int64_t fsync_us = g_state.fsync_us;
    if (fsync_us < 0 || fsync_us <= HW_BENCH_FSYNC_BASELINE_US)
        return normal_batch;

    double scale = (double)fsync_us / (double)HW_BENCH_FSYNC_BASELINE_US;
    int64_t scaled = (int64_t)((double)normal_batch * scale);
    if (scaled < normal_batch) scaled = normal_batch;
    if (scaled > HW_BENCH_BATCH_SIZE_CEILING) scaled = HW_BENCH_BATCH_SIZE_CEILING;
    return (int)scaled;
}

int hw_bench_verify_workers(int normal_workers)
{
    if (normal_workers < 1) normal_workers = 1;
    if (!atomic_load(&g_inited)) return normal_workers;

    int64_t pread_us = g_state.pread_us;
    if (pread_us < 0 || pread_us <= HW_BENCH_PREAD_BASELINE_US)
        return normal_workers;

    double scale = (double)pread_us / (double)HW_BENCH_PREAD_BASELINE_US;
    int64_t scaled = (int64_t)((double)normal_workers / scale);
    if (scaled < 1) scaled = 1;
    if (scaled > normal_workers) scaled = normal_workers;
    return (int)scaled;
}

/* ── Introspection ─────────────────────────────────────────────────── */

bool hw_bench_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    /* Deliberate explicit call (like bg_validation_init's), not an
     * implicit one buried in a query — `ops state hw_bench` is an
     * operator-triggered diagnostic call, never the block-ingest hot
     * path, so it is allowed to pay for a first-time measurement here. */
    hw_bench_init(NULL);
    json_set_object(out);

    json_push_kv_int(out, "fsync_us", g_state.fsync_us);
    json_push_kv_int(out, "pread_us", g_state.pread_us);
    json_push_kv_str(out, "fsync_source", source_tag(g_state.fsync_us));
    json_push_kv_str(out, "pread_source", source_tag(g_state.pread_us));
    json_push_kv_str(out, "fingerprint", g_state.fingerprint);
    json_push_kv_bool(out, "from_cache", g_state.from_cache);
    json_push_kv_int(out, "age_seconds", hw_bench_age_seconds());
    json_push_kv_bool(out, "measured", hw_bench_measured());

    struct json_value derived;
    json_init(&derived);
    json_set_object(&derived);
    json_push_kv_int(&derived, "batch_size_normal_100", hw_bench_batch_size(100));
    json_push_kv_str(&derived, "batch_size_source", source_tag(g_state.fsync_us));
    json_push_kv_int(&derived, "verify_workers_normal_4",
                     hw_bench_verify_workers(4));
    json_push_kv_str(&derived, "verify_workers_source", source_tag(g_state.pread_us));
    json_push_kv(out, "derived", &derived);
    json_free(&derived);

    diag_push_health(out, true, "");
    return true;
}
