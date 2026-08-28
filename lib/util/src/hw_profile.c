/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hardware profile organ — implementation. See util/hw_profile.h.
 *
 * Four probes, each pure raw-syscall/sysfs/cpuid, no external deps:
 *   1. Online/physical core count — delegates to util/cpu_topology.h.
 *   2. Total RAM — sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGE_SIZE).
 *   3. x86_64 ISA extensions — __builtin_cpu_supports("...").
 *   4. Datadir storage rotational flag — stat(datadir).st_dev -> major:minor
 *      -> resolve /sys/dev/block/<maj>:<min> -> if it's a partition (has a
 *      "partition" sibling file) walk up to the parent whole-disk dir ->
 *      read queue/rotational.
 *
 * Everything below the probes is pure/allocation-free so the derived
 * tunables and the monotonicity properties they promise are directly
 * unit-testable without touching /sys or spinning up a real DB. */

/* realpath() is declared by <stdlib.h> only under __USE_MISC/__USE_XOPEN_EXTENDED,
 * and the build's -D_POSIX_C_SOURCE=200809L sets neither. Without this the
 * declaration reaches the TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O3 — so any -O0, -U_FORTIFY_SOURCE, or
 * non-glibc build fails with "implicit declaration of realpath", which is a
 * hard error in C23. Matches lib/net/src/connman.c and 26 other TUs. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "util/hw_profile.h"

#include "util/cpu_topology.h"
#include "crypto/blake2b.h"
#include "crypto/sha256.h"
#include "json/json.h"
#if !defined(_WIN32)
#include "platform/device_compat.h"
#endif
#include "util/log_macros.h"

#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

#define HW_PROFILE_BLOCK_ROOT_DEFAULT "/sys/dev/block"
#define HW_PROFILE_ROOT_MAX           256

/* ── Module state ──────────────────────────────────────────────────── */

struct hw_profile_state {
    bool    valid;
    int     online_cores;
    int     physical_cores;
    int64_t ram_bytes;
    struct hw_profile_isa isa;
    bool    rotational;
    bool    rotational_known;
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool g_inited = false;
static struct hw_profile_state g_state;
static char g_block_root[HW_PROFILE_ROOT_MAX] = HW_PROFILE_BLOCK_ROOT_DEFAULT;

/* ── RAM probe ─────────────────────────────────────────────────────── */

static int64_t probe_ram_bytes(void)
{
#if defined(_WIN32)
    MEMORYSTATUSEX status = { .dwLength = sizeof(status) };
    if (!GlobalMemoryStatusEx(&status) || status.ullTotalPhys > INT64_MAX)
        return 0;
    return (int64_t)status.ullTotalPhys;
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_sz = sysconf(_SC_PAGE_SIZE);
    if (pages <= 0 || page_sz <= 0) return 0;
    return (int64_t)pages * (int64_t)page_sz;
#endif
}

/* ── ISA probe ─────────────────────────────────────────────────────── */

static void probe_isa(struct hw_profile_isa *out)
{
    memset(out, 0, sizeof(*out));
#if defined(__x86_64__) || defined(__i386__)
    out->avx2       = __builtin_cpu_supports("avx2");
    out->avx512f    = __builtin_cpu_supports("avx512f");
    out->avx512vl   = __builtin_cpu_supports("avx512vl");
    out->avx512bw   = __builtin_cpu_supports("avx512bw");
    out->avx512dq   = __builtin_cpu_supports("avx512dq");
    out->vpclmulqdq = __builtin_cpu_supports("vpclmulqdq");
    out->gfni       = __builtin_cpu_supports("gfni");
    /* GCC accepts the VAES/SHA names here, while Clang 18 rejects both
     * strings at compile time. Read their architectural leaf bits directly
     * so the same source and exact meaning work with either toolchain. */
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        out->vaes = ((ecx >> 9) & 1u) != 0;   /* CPUID.7.0:ECX[9] */
        out->sha_ni = ((ebx >> 29) & 1u) != 0; /* CPUID.7.0:EBX[29] */
    }
#endif
}

/* ── Storage-rotational probe ──────────────────────────────────────── */

#if !defined(_WIN32)
static bool sysfs_path_exists_local(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool sysfs_read_line_local(const char *path, char *buf, size_t bufsz)
{
    if (bufsz == 0) return false;
    buf[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(buf, 1, bufsz - 1, f);
    fclose(f);
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
    return n > 0;
}

/* Resolve `dev`'s rotational flag under `block_root` (test seam: normally
 * "/sys/dev/block"). Returns false if the major:minor symlink, its
 * resolved target, or queue/rotational cannot be read — callers treat
 * that as "unknown", never fatal. */
static bool probe_rotational_under(const char *block_root, dev_t dev,
                                   bool *out)
{
    char link[HW_PROFILE_ROOT_MAX + 32];
    snprintf(link, sizeof(link), "%s/%u:%u", block_root,
             platform_device_major(dev), platform_device_minor(dev));

    char resolved[PATH_MAX];
    if (!realpath(link, resolved)) return false;

    char partition_marker[sizeof(resolved) + 16];
    snprintf(partition_marker, sizeof(partition_marker), "%s/partition",
             resolved);

    char parent[sizeof(resolved)];
    const char *dev_dir = resolved;
    if (sysfs_path_exists_local(partition_marker)) {
        /* This device node is a partition (e.g. nvme0n1p2, sda1) — its
         * own directory has no queue/, only its whole-disk parent does.
         * Strip the last path component to reach the parent. */
        snprintf(parent, sizeof(parent), "%s", resolved);
        char *slash = strrchr(parent, '/');
        if (slash) *slash = '\0';
        dev_dir = parent;
    }

    char rot_path[sizeof(resolved) + 32];
    snprintf(rot_path, sizeof(rot_path), "%s/queue/rotational", dev_dir);
    char buf[8];
    if (!sysfs_read_line_local(rot_path, buf, sizeof(buf))) return false;
    *out = (buf[0] == '1');
    return true;
}
#endif

static bool probe_datadir_rotational(const char *block_root,
                                     const char *datadir, bool *out)
{
#if defined(_WIN32)
    /* Windows storage stacks do not always expose seek-penalty truth (virtual,
     * Storage Spaces, network and filter volumes). Unknown is safer than
     * silently tuning an HDD as solid-state or vice versa. */
    (void)block_root;
    (void)datadir;
    (void)out;
    return false;
#else
    if (!datadir || !*datadir) return false;
    struct stat st;
    if (stat(datadir, &st) != 0) return false;
    return probe_rotational_under(block_root, st.st_dev, out);
#endif
}

/* ── Lifecycle ─────────────────────────────────────────────────────── */

bool hw_profile_init(const char *datadir)
{
    if (atomic_load(&g_inited)) return g_state.valid;

    pthread_mutex_lock(&g_lock);
    if (atomic_load(&g_inited)) {
        pthread_mutex_unlock(&g_lock);
        return g_state.valid;
    }

    struct hw_profile_state st;
    memset(&st, 0, sizeof(st));

    cpu_topology_init();
    st.online_cores = cpu_topology_logical_cpus();
    st.physical_cores = cpu_topology_physical_cores();
    st.ram_bytes = probe_ram_bytes();
    probe_isa(&st.isa);

    bool rot = false;
    char block_root_copy[HW_PROFILE_ROOT_MAX];
    snprintf(block_root_copy, sizeof(block_root_copy), "%s", g_block_root);
    st.rotational_known = probe_datadir_rotational(block_root_copy, datadir,
                                                    &rot);
    st.rotational = st.rotational_known && rot;

    st.valid = st.online_cores > 0;

    g_state = st;
    atomic_store(&g_inited, true);
    pthread_mutex_unlock(&g_lock);

    if (!g_state.valid) {
        LOG_FAIL("hw_profile",
                 "init: cpu_topology reported zero online cores");
    }
    return true;
}

#ifdef ZCL_TESTING
void hw_profile_reset_for_testing(void)
{
    pthread_mutex_lock(&g_lock);
    memset(&g_state, 0, sizeof(g_state));
    atomic_store(&g_inited, false);
    pthread_mutex_unlock(&g_lock);
}

void hw_profile_set_block_root_for_testing(const char *root)
{
    pthread_mutex_lock(&g_lock);
    if (root) {
        snprintf(g_block_root, sizeof(g_block_root), "%s", root);
    } else {
        snprintf(g_block_root, sizeof(g_block_root), "%s",
                 HW_PROFILE_BLOCK_ROOT_DEFAULT);
    }
    pthread_mutex_unlock(&g_lock);
}
#endif

/* ── Queries ───────────────────────────────────────────────────────── */

int hw_profile_online_cores(void)
{
    hw_profile_init(NULL);
    return g_state.online_cores;
}

int hw_profile_physical_cores(void)
{
    hw_profile_init(NULL);
    return g_state.physical_cores;
}

int64_t hw_profile_ram_bytes(void)
{
    hw_profile_init(NULL);
    return g_state.ram_bytes;
}

enum hw_profile_ram_class hw_profile_ram_class_of(int64_t ram_bytes)
{
    int64_t gib = ram_bytes / (1024LL * 1024 * 1024);
    if (gib < 8) return HW_PROFILE_RAM_LOW;
    if (gib < 32) return HW_PROFILE_RAM_MEDIUM;
    return HW_PROFILE_RAM_HIGH;
}

const struct hw_profile_isa *hw_profile_isa(void)
{
    hw_profile_init(NULL);
    return &g_state.isa;
}

bool hw_profile_datadir_rotational(bool *known)
{
    hw_profile_init(NULL);
    if (known) *known = g_state.rotational_known;
    return g_state.rotational;
}

bool hw_profile_l3_asymmetric(void)
{
    cpu_topology_init();
    int domains = cpu_topology_l3_domains();
    if (domains <= 1) return false;

    int64_t first_size = -1;
    for (int i = 0; i < domains; i++) {
        struct cpu_topology_domain d;
        if (!cpu_topology_domain_at(i, &d)) continue;
        if (first_size < 0) {
            first_size = d.l3_size_bytes;
        } else if (d.l3_size_bytes != first_size) {
            return true;
        }
    }
    return false;
}

int hw_profile_large_l3_domain(void)
{
    if (!hw_profile_l3_asymmetric()) return -1;

    cpu_topology_init();
    int domains = cpu_topology_l3_domains();
    int best = -1;
    int64_t best_size = -1;
    for (int i = 0; i < domains; i++) {
        struct cpu_topology_domain d;
        if (!cpu_topology_domain_at(i, &d)) continue;
        if (d.l3_size_bytes > best_size) {
            best_size = d.l3_size_bytes;
            best = d.id;
        }
    }
    return best;
}

/* ── Derived tunables ──────────────────────────────────────────────── */

#define HW_PROFILE_CACHE_KIB_DEFAULT_FLOOR   (16 * 1024)          /* 16 MiB */
#define HW_PROFILE_CACHE_KIB_DEFAULT_CEIL    (1024 * 1024)        /* 1 GiB */
#define HW_PROFILE_CACHE_KIB_RAM_DIVISOR     (32 * 1024)          /* ~1/32 RAM */

int64_t hw_profile_sqlite_cache_kib(int64_t ram_bytes, int64_t floor_kib,
                                    int64_t ceiling_kib)
{
    if (floor_kib <= 0) floor_kib = HW_PROFILE_CACHE_KIB_DEFAULT_FLOOR;
    if (ceiling_kib <= 0) ceiling_kib = HW_PROFILE_CACHE_KIB_DEFAULT_CEIL;
    if (ceiling_kib < floor_kib) ceiling_kib = floor_kib;

    if (ram_bytes <= 0) return floor_kib;

    int64_t kib = ram_bytes / HW_PROFILE_CACHE_KIB_RAM_DIVISOR;
    if (kib < floor_kib) kib = floor_kib;
    if (kib > ceiling_kib) kib = ceiling_kib;
    return kib;
}

#define HW_PROFILE_MMAP_BYTES_DEFAULT_FLOOR  (64LL * 1024 * 1024)   /* 64 MiB */
#define HW_PROFILE_MMAP_BYTES_DEFAULT_CEIL   (2LL * 1024 * 1024 * 1024) /* 2 GiB */
#define HW_PROFILE_MMAP_BYTES_RAM_DIVISOR    16                     /* ~1/16 RAM */

int64_t hw_profile_sqlite_mmap_bytes(int64_t ram_bytes, int64_t floor_bytes,
                                     int64_t ceiling_bytes)
{
    if (floor_bytes <= 0) floor_bytes = HW_PROFILE_MMAP_BYTES_DEFAULT_FLOOR;
    if (ceiling_bytes <= 0) ceiling_bytes = HW_PROFILE_MMAP_BYTES_DEFAULT_CEIL;
    if (ceiling_bytes < floor_bytes) ceiling_bytes = floor_bytes;

    if (ram_bytes <= 0) return 0;

    int64_t bytes = ram_bytes / HW_PROFILE_MMAP_BYTES_RAM_DIVISOR;
    if (bytes < floor_bytes) bytes = floor_bytes;
    if (bytes > ceiling_bytes) bytes = ceiling_bytes;
    return bytes;
}

#define HW_PROFILE_VERIFY_WORKERS_MIN 2
#define HW_PROFILE_VERIFY_WORKERS_MAX 4

int hw_profile_verify_workers(int physical_cores)
{
    if (physical_cores < 1) physical_cores = 1;
    int workers = physical_cores / 2;
    if (workers < HW_PROFILE_VERIFY_WORKERS_MIN)
        workers = HW_PROFILE_VERIFY_WORKERS_MIN;
    if (workers > HW_PROFILE_VERIFY_WORKERS_MAX)
        workers = HW_PROFILE_VERIFY_WORKERS_MAX;
    return workers;
}

#define HW_PROFILE_SCRIPT_BATCH_LOW_RAM_CAP        10000
#define HW_PROFILE_SCRIPT_BATCH_RAM_THRESHOLD_MB   8192

int hw_profile_script_batch_cap(int64_t ram_bytes)
{
    int64_t ram_mb = ram_bytes > 0 ? ram_bytes / (1024 * 1024) : 0;
    if (ram_mb > 0 && ram_mb < HW_PROFILE_SCRIPT_BATCH_RAM_THRESHOLD_MB)
        return HW_PROFILE_SCRIPT_BATCH_LOW_RAM_CAP;
    return 0; /* unlimited */
}

/* +1x baseline per this many GiB of RAM; cores cap the same multiplier at
 * 1x per 4 physical cores; overall ceiling 8x baseline; floor = baseline. */
#define HW_PROFILE_DRAIN_BATCH_RAM_PER_MULT_GIB 16
#define HW_PROFILE_DRAIN_BATCH_MAX_MULT         8
#define HW_PROFILE_DRAIN_BATCH_MIN_CORES        4
#define HW_PROFILE_DRAIN_BATCH_CORES_PER_MULT   4

int hw_profile_drain_batch(int64_t ram_bytes, int physical_cores, int baseline)
{
    if (baseline < 1) baseline = 1;
    if (ram_bytes <= 0 || physical_cores < HW_PROFILE_DRAIN_BATCH_MIN_CORES)
        return baseline; /* floor — small/unknown host keeps the safe baseline */

    int64_t ram_gib = ram_bytes / (1024LL * 1024 * 1024);
    int64_t mult = 1 + ram_gib / HW_PROFILE_DRAIN_BATCH_RAM_PER_MULT_GIB;
    if (mult > HW_PROFILE_DRAIN_BATCH_MAX_MULT)
        mult = HW_PROFILE_DRAIN_BATCH_MAX_MULT;

    /* Cores independently cap the multiplier (constant in ram_bytes, so the
     * result stays monotone non-decreasing in RAM): don't hand a 4-core box an
     * 8x batch just because it has a lot of RAM. */
    int64_t core_cap = physical_cores / HW_PROFILE_DRAIN_BATCH_CORES_PER_MULT;
    if (core_cap < 1) core_cap = 1;
    if (mult > core_cap) mult = core_cap;

    int64_t batch = (int64_t)baseline * mult;
    if (batch < baseline) batch = baseline;
    if (batch > (int64_t)baseline * HW_PROFILE_DRAIN_BATCH_MAX_MULT)
        batch = (int64_t)baseline * HW_PROFILE_DRAIN_BATCH_MAX_MULT;
    return (int)batch;
}

/* Runtime opt-in gate. Default OFF: the fold's drain cadence is unchanged. */
static _Atomic bool g_derive_drain_batch = false;

void hw_profile_set_derive_drain_batch(bool on)
{
    atomic_store(&g_derive_drain_batch, on);
}

bool hw_profile_derive_drain_batch_enabled(void)
{
    return atomic_load(&g_derive_drain_batch);
}

int hw_profile_drain_batch_effective(int baseline)
{
    if (!atomic_load(&g_derive_drain_batch))
        return baseline; /* lever OFF (default): compiled baseline, no change */
    return hw_profile_drain_batch(hw_profile_ram_bytes(),
                                  hw_profile_physical_cores(), baseline);
}

/* ── Reducer pinning ───────────────────────────────────────────────── */

bool hw_profile_pin_reducer_thread(pthread_t thread)
{
    if (!hw_profile_l3_asymmetric()) {
        LOG_WARN("hw_profile",
                 "pin_reducer_thread: no asymmetric L3 CCDs detected "
                 "(l3_domains=%d); leaving reducer thread unpinned",
                 cpu_topology_l3_domains());
        return false;
    }

    int domain = hw_profile_large_l3_domain();
    int cpus[CPU_TOPOLOGY_MAX_CPUS];
    int n = cpu_topology_largest_l3_domain_cpus(cpus, CPU_TOPOLOGY_MAX_CPUS);

    char cpuset_str[512];
    size_t pos = 0;
    cpuset_str[0] = '\0';
    for (int i = 0; i < n; i++) {
        int written = snprintf(cpuset_str + pos,
                               pos < sizeof(cpuset_str) ? sizeof(cpuset_str) - pos : 0,
                               "%s%d", i ? "," : "", cpus[i]);
        if (written > 0 && (size_t)written < sizeof(cpuset_str) - pos)
            pos += (size_t)written;
        else
            break;
    }

    bool ok = cpu_topology_pin_thread(thread, domain);
    if (ok) {
        LOG_WARN("hw_profile",
                 "pin_reducer_thread: pinned reducer thread to L3 domain %d "
                 "(large-L3 CCD) cpuset=[%s]", domain, cpuset_str);
    } else {
        LOG_WARN("hw_profile",
                 "pin_reducer_thread: cpu_topology_pin_thread failed for "
                 "domain %d cpuset=[%s]; reducer thread left unpinned",
                 domain, cpuset_str);
    }
    return ok;
}

/* ── Introspection ─────────────────────────────────────────────────── */

static const char *ram_class_name(enum hw_profile_ram_class cls)
{
    switch (cls) {
        case HW_PROFILE_RAM_LOW:    return "low";
        case HW_PROFILE_RAM_MEDIUM: return "medium";
        case HW_PROFILE_RAM_HIGH:   return "high";
        default:                    return "unknown";
    }
}

bool hw_profile_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    hw_profile_init(NULL);
    json_set_object(out);

    json_push_kv_int(out, "online_cores", g_state.online_cores);
    json_push_kv_int(out, "physical_cores", g_state.physical_cores);
    json_push_kv_int(out, "ram_bytes", g_state.ram_bytes);
    json_push_kv_str(out, "ram_class",
                     ram_class_name(hw_profile_ram_class_of(g_state.ram_bytes)));

    struct json_value isa;
    json_init(&isa);
    json_set_object(&isa);
    json_push_kv_bool(&isa, "avx2", g_state.isa.avx2);
    json_push_kv_bool(&isa, "avx512f", g_state.isa.avx512f);
    json_push_kv_bool(&isa, "avx512vl", g_state.isa.avx512vl);
    json_push_kv_bool(&isa, "avx512bw", g_state.isa.avx512bw);
    json_push_kv_bool(&isa, "avx512dq", g_state.isa.avx512dq);
    json_push_kv_bool(&isa, "vpclmulqdq", g_state.isa.vpclmulqdq);
    json_push_kv_bool(&isa, "vaes", g_state.isa.vaes);
    json_push_kv_bool(&isa, "gfni", g_state.isa.gfni);
    json_push_kv_bool(&isa, "sha_ni", g_state.isa.sha_ni);
    /* The CPUID capability above is NOT the same claim as "the node is using
     * it". These two disagreed silently for the whole life of the -v3 build
     * (SHA-NI was compiled out by `#ifdef __SHA__`), so report the transform
     * actually installed right next to the capability bit. */
    json_push_kv_str(&isa, "sha256_transform", sha256_implementation());
    json_push_kv_str(&isa, "equihash_blake2b_batch",
                     equihash_blake2b_batch_implementation());
    json_push_kv(out, "isa", &isa);
    json_free(&isa);

    struct json_value storage;
    json_init(&storage);
    json_set_object(&storage);
    json_push_kv_bool(&storage, "rotational_known", g_state.rotational_known);
    json_push_kv_bool(&storage, "rotational", g_state.rotational);
    json_push_kv(out, "storage", &storage);
    json_free(&storage);

    bool asymmetric = hw_profile_l3_asymmetric();
    struct json_value l3;
    json_init(&l3);
    json_set_object(&l3);
    json_push_kv_int(&l3, "domain_count", cpu_topology_l3_domains());
    json_push_kv_bool(&l3, "asymmetric", asymmetric);
    json_push_kv_int(&l3, "large_domain_id", hw_profile_large_l3_domain());
    json_push_kv(out, "l3", &l3);
    json_free(&l3);

    struct json_value derived;
    json_init(&derived);
    json_set_object(&derived);
    json_push_kv_int(&derived, "verify_workers",
                     hw_profile_verify_workers(g_state.physical_cores));
    json_push_kv_int(&derived, "script_batch_cap",
                     hw_profile_script_batch_cap(g_state.ram_bytes));
    json_push_kv_int(&derived, "sqlite_node_db_cache_kib",
                     hw_profile_sqlite_cache_kib(g_state.ram_bytes,
                                                 16 * 1024, 64 * 1024));
    json_push_kv_int(&derived, "sqlite_node_db_mmap_bytes",
                     hw_profile_sqlite_mmap_bytes(g_state.ram_bytes,
                                                  64LL * 1024 * 1024,
                                                  256LL * 1024 * 1024));
    json_push_kv_int(&derived, "sqlite_progress_db_cache_kib",
                     hw_profile_sqlite_cache_kib(g_state.ram_bytes, 0, 0));
    json_push_kv_int(&derived, "sqlite_progress_db_mmap_bytes",
                     hw_profile_sqlite_mmap_bytes(g_state.ram_bytes, 0, 0));
    json_push_kv_bool(&derived, "derive_drain_batch_enabled",
                      hw_profile_derive_drain_batch_enabled());
    json_push_kv_int(&derived, "reducer_drain_batch_1000",
                     hw_profile_drain_batch(g_state.ram_bytes,
                                            g_state.physical_cores, 1000));
    json_push_kv_int(&derived, "header_drain_batch_100",
                     hw_profile_drain_batch(g_state.ram_bytes,
                                            g_state.physical_cores, 100));
    json_push_kv(out, "derived", &derived);
    json_free(&derived);

    json_push_kv_bool(out, "pin_reducer_available", asymmetric);

    diag_push_health(out, g_state.valid,
                     g_state.valid ? "" : "hw profile probe produced no "
                                           "usable core count");
    return true;
}
