/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * CPU topology organ — implementation. See util/cpu_topology.h.
 *
 * Scans, under each cpuN directory in sysfs, the topology and cache
 * subdirectories once, caches the result in a static struct, and never
 * allocates again. Two things are derived from raw sysfs text:
 *
 *   1. Physical core count — the number of distinct
 *      (physical_package_id, core_id) pairs across all present logical
 *      cpus. thread_siblings_list cross-checks the SMT width per core.
 *   2. L3 cache domains — the cache indexN entry with level 3, for each
 *      cpu, grouped by its shared_cpu_list (all cpus quoting the same
 *      list are in the same domain/CCD). size is parsed from the
 *      kernel's "<N>K" format.
 *
 * If /sys is unreadable at all (containers, non-Linux layouts) the whole
 * scan degrades to ONE synthetic domain covering
 * sysconf(_SC_NPROCESSORS_ONLN) cpus with unknown L3 size — always usable,
 * never fatal. cpu_topology_source() reports which path was taken. */
#define _GNU_SOURCE /* pthread_setaffinity_np, CPU_SET */

#include "util/cpu_topology.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/logical_cpu.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <limits.h>
#if !defined(_WIN32)
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sys/stat.h>
#endif
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CPU_TOPOLOGY_DEFAULT_ROOT "/sys/devices/system/cpu"
#define CPU_TOPOLOGY_ROOT_MAX     256
#define CPU_TOPOLOGY_LINE_MAX     256

/* ── Module state ──────────────────────────────────────────────────── */

struct cpu_topology_state {
    bool    valid;
    int     logical_cpus;
    int     physical_cores;
    int     smt_width;     /* max thread_siblings_list width seen; 0 = unknown
                            * (fallback path, or /sys topology without
                            * thread_siblings_list) */
    int     domain_count;
    int     domain_of[CPU_TOPOLOGY_MAX_CPUS]; /* -1 == unassigned */
    struct cpu_topology_domain domains[CPU_TOPOLOGY_MAX_DOMAINS];
    char    source[16]; /* "sysfs" | "fallback" */
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool g_inited = false;
static struct cpu_topology_state g_state;
static char g_sysfs_root[CPU_TOPOLOGY_ROOT_MAX] = CPU_TOPOLOGY_DEFAULT_ROOT;

/* ── Raw /sys readers ──────────────────────────────────────────────── */

#if !defined(_WIN32)
static bool sysfs_path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Read a whole small text file, trim trailing whitespace/newline. Returns
 * false (and leaves buf empty) on any open/read error — every caller
 * treats that as "this cpu doesn't have this file" and degrades gracefully,
 * never fatally. */
static bool sysfs_read_line(const char *path, char *buf, size_t bufsz)
{
    if (bufsz == 0) return false;
    buf[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(buf, 1, bufsz - 1, f);
    fclose(f);
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
        buf[--n] = '\0';
    }
    return n > 0;
}

static bool sysfs_read_int(const char *path, int *out)
{
    char buf[64];
    if (!sysfs_read_line(path, buf, sizeof(buf))) return false;
    char *end = NULL;
    long v = strtol(buf, &end, 10);
    if (end == buf) return false;
    *out = (int)v;
    return true;
}

/* Parse the kernel cache "size" file: digits followed by an optional
 * K/M/G unit suffix (observed on Linux: always "<digits>K"). Returns 0 on
 * a malformed/absent value — callers treat 0 as "unknown", not fatal. */
static int64_t parse_size_bytes(const char *s)
{
    if (!s || !*s) return 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (end == s || v < 0) return 0;
    int64_t mult = 1;
    if (*end == 'K' || *end == 'k') mult = 1024;
    else if (*end == 'M' || *end == 'm') mult = 1024 * 1024;
    else if (*end == 'G' || *end == 'g') mult = 1024 * 1024 * 1024;
    return (int64_t)v * mult;
}

/* Expand a Linux "list" string ("0-7,16-23" or "3" or "0,2,4-6") into
 * individual cpu ids, appended to out[] (capacity cap, starting at
 * *count). Silently stops appending past cap (never overruns) — a
 * pathological >CPU_TOPOLOGY_MAX_CPUS list just gets truncated, which
 * still leaves the module usable rather than fatally erroring. */
static void expand_cpu_list(const char *list, int *out, int cap, int *count)
{
    const char *p = list;
    while (p && *p) {
        const char *comma = strchr(p, ',');
        size_t tok_len = comma ? (size_t)(comma - p) : strlen(p);
        char tok[32];
        if (tok_len >= sizeof(tok)) tok_len = sizeof(tok) - 1;
        memcpy(tok, p, tok_len);
        tok[tok_len] = '\0';

        char *dash = strchr(tok, '-');
        long lo, hi;
        if (dash) {
            *dash = '\0';
            lo = strtol(tok, NULL, 10);
            hi = strtol(dash + 1, NULL, 10);
        } else {
            lo = hi = strtol(tok, NULL, 10);
        }
        for (long c = lo; c <= hi; c++) {
            if (*count >= cap) return;
            if (c < 0 || c >= CPU_TOPOLOGY_MAX_CPUS) continue;
            out[(*count)++] = (int)c;
        }
        p = comma ? comma + 1 : NULL;
    }
}
#endif

/* ── Scan ──────────────────────────────────────────────────────────── */

static int sysconf_cpu_count(void)
{
    uint32_t n = platform_logical_cpu_count();
    return n > (uint32_t)INT_MAX ? INT_MAX : (int)n;
}

static void fill_fallback(struct cpu_topology_state *st)
{
    memset(st, 0, sizeof(*st));
    for (int i = 0; i < CPU_TOPOLOGY_MAX_CPUS; i++) st->domain_of[i] = -1;

    int n = sysconf_cpu_count();
    if (n > CPU_TOPOLOGY_MAX_CPUS) n = CPU_TOPOLOGY_MAX_CPUS;

    st->logical_cpus  = n;
    st->physical_cores = n; /* SMT topology unknown on the fallback path */
    st->smt_width     = 0;  /* unknown */
    st->domain_count  = 1;
    st->domains[0].id = 0;
    st->domains[0].l3_size_bytes = 0;
    st->domains[0].cpu_count = n;
    for (int i = 0; i < n; i++) {
        st->domains[0].cpus[i] = i;
        st->domain_of[i] = 0;
    }
    snprintf(st->source, sizeof(st->source), "fallback");
    st->valid = true;
}

#if defined(_WIN32)
static int windows_group_cpu_id(WORD group, BYTE bit)
{
    uint64_t id = bit;
    for (WORD g = 0; g < group; g++)
        id += GetActiveProcessorCount(g);
    return id < CPU_TOPOLOGY_MAX_CPUS ? (int)id : -1;
}

static int windows_mask_count(KAFFINITY mask)
{
    int count = 0;
    while (mask) {
        count += (int)(mask & 1u);
        mask >>= 1;
    }
    return count;
}

static bool scan_windows(struct cpu_topology_state *st)
{
    DWORD bytes = 0;
    if (GetLogicalProcessorInformationEx(RelationAll, NULL, &bytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0)
        return false;
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *records =
        zcl_malloc(bytes, "cpu_topology.windows_records");
    if (!records || !GetLogicalProcessorInformationEx(RelationAll, records,
                                                        &bytes)) {
        free(records);
        return false;
    }

    memset(st, 0, sizeof(*st));
    for (int i = 0; i < CPU_TOPOLOGY_MAX_CPUS; i++) st->domain_of[i] = -1;
    st->logical_cpus = sysconf_cpu_count();
    if (st->logical_cpus > CPU_TOPOLOGY_MAX_CPUS)
        st->logical_cpus = CPU_TOPOLOGY_MAX_CPUS;

    BYTE *cursor = (BYTE *)records;
    BYTE *end = cursor + bytes;
    while (cursor < end) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *record =
            (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)cursor;
        if (record->Size == 0 || cursor + record->Size > end)
            break;
        if (record->Relationship == RelationProcessorCore) {
            st->physical_cores++;
            int siblings = 0;
            for (WORD i = 0; i < record->Processor.GroupCount; i++)
                siblings += windows_mask_count(
                    record->Processor.GroupMask[i].Mask);
            if (siblings > st->smt_width) st->smt_width = siblings;
        } else if (record->Relationship == RelationCache &&
                   record->Cache.Level == 3 &&
                   st->domain_count < CPU_TOPOLOGY_MAX_DOMAINS) {
            struct cpu_topology_domain *domain =
                &st->domains[st->domain_count];
            domain->id = st->domain_count;
            domain->l3_size_bytes = record->Cache.CacheSize;
            GROUP_AFFINITY affinity = record->Cache.GroupMask;
            for (BYTE bit = 0; bit < sizeof(KAFFINITY) * 8; bit++) {
                if ((affinity.Mask & ((KAFFINITY)1 << bit)) == 0)
                    continue;
                int cpu = windows_group_cpu_id(affinity.Group, bit);
                if (cpu >= 0 && domain->cpu_count < CPU_TOPOLOGY_MAX_CPUS) {
                    domain->cpus[domain->cpu_count++] = cpu;
                    st->domain_of[cpu] = domain->id;
                }
            }
            st->domain_count++;
        }
        cursor += record->Size;
    }
    free(records);

    if (st->physical_cores <= 0)
        st->physical_cores = st->logical_cpus;
    if (st->physical_cores > st->logical_cpus)
        st->physical_cores = st->logical_cpus;
    if (st->domain_count == 0) {
        fill_fallback(st);
        return true;
    }
    for (int cpu = 0; cpu < st->logical_cpus; cpu++) {
        if (st->domain_of[cpu] < 0 &&
            st->domains[0].cpu_count < CPU_TOPOLOGY_MAX_CPUS) {
            st->domains[0].cpus[st->domains[0].cpu_count++] = cpu;
            st->domain_of[cpu] = 0;
        }
    }
    snprintf(st->source, sizeof(st->source), "windows");
    st->valid = true;
    return true;
}
#endif

/* Find the L3 cache index dir under cpu<cpu>/cache and read its size +
 * shared_cpu_list. Returns false if this cpu has no level==3 cache entry
 * (e.g. containers that expose topology but not cache info). */
#if !defined(_WIN32)
static bool find_l3_cache(const char *root, int cpu, int64_t *size_out,
                          char *shared_list_out, size_t shared_list_cap)
{
    for (int idx = 0; idx < 16; idx++) {
        char base[CPU_TOPOLOGY_ROOT_MAX + 64];
        snprintf(base, sizeof(base), "%s/cpu%d/cache/index%d", root, cpu, idx);
        if (!sysfs_path_exists(base)) {
            if (idx == 0) continue; /* index0 sometimes absent; keep trying */
            break;
        }
        char level_path[sizeof(base) + 16];
        snprintf(level_path, sizeof(level_path), "%s/level", base);
        int level = 0;
        if (!sysfs_read_int(level_path, &level) || level != 3) continue;

        char size_path[sizeof(base) + 16];
        snprintf(size_path, sizeof(size_path), "%s/size", base);
        char size_buf[64];
        sysfs_read_line(size_path, size_buf, sizeof(size_buf));
        *size_out = parse_size_bytes(size_buf);

        char shared_path[sizeof(base) + 32];
        snprintf(shared_path, sizeof(shared_path), "%s/shared_cpu_list", base);
        if (!sysfs_read_line(shared_path, shared_list_out, shared_list_cap))
            return false;
        return true;
    }
    return false;
}

/* Read topology/thread_siblings_list for `cpu` and return how many entries
 * it expands to (the SMT width of that cpu's core; 0 if unavailable). Used
 * only to cross-check the (package,core) pair count — not stored per-cpu,
 * since the domain/physical-core model above is already sufficient for
 * the public API. */
static int smt_width_of(const char *root, int cpu)
{
    char path[CPU_TOPOLOGY_ROOT_MAX + 64];
    snprintf(path, sizeof(path), "%s/cpu%d/topology/thread_siblings_list",
             root, cpu);
    char buf[CPU_TOPOLOGY_LINE_MAX];
    if (!sysfs_read_line(path, buf, sizeof(buf))) return 0;
    int tmp[64];
    int count = 0;
    expand_cpu_list(buf, tmp, (int)(sizeof(tmp) / sizeof(tmp[0])), &count);
    return count;
}

/* Full /sys scan. Returns false if the root itself is unusable (missing,
 * or yields zero present logical cpus) — caller falls back on false. */
static bool scan_sysfs(const char *root, struct cpu_topology_state *st)
{
    if (!sysfs_path_exists(root)) return false;

    memset(st, 0, sizeof(*st));
    for (int i = 0; i < CPU_TOPOLOGY_MAX_CPUS; i++) st->domain_of[i] = -1;

    /* Unique (package,core) pairs seen, for physical-core counting. */
    struct { int pkg; int core; } cores_seen[CPU_TOPOLOGY_MAX_CPUS];
    int cores_seen_count = 0;
    int max_smt_width = 0;

    int present_count = 0;
    for (int cpu = 0; cpu < CPU_TOPOLOGY_MAX_CPUS; cpu++) {
        char cpu_dir[CPU_TOPOLOGY_ROOT_MAX + 32];
        snprintf(cpu_dir, sizeof(cpu_dir), "%s/cpu%d", root, cpu);
        if (!sysfs_path_exists(cpu_dir)) {
            if (cpu == 0) continue; /* tolerate an absent cpu0 (unusual, but
                                     * don't permanently bail on index 0) */
            break; /* Linux numbers logical cpus contiguously from 0; a
                    * gap means we've walked past the last present cpu. */
        }
        present_count = cpu + 1;

        char pkg_path[sizeof(cpu_dir) + 40];
        char core_path[sizeof(cpu_dir) + 40];
        snprintf(pkg_path, sizeof(pkg_path),
                 "%s/topology/physical_package_id", cpu_dir);
        snprintf(core_path, sizeof(core_path), "%s/topology/core_id", cpu_dir);

        int pkg = 0, core = 0;
        bool have_topology = sysfs_read_int(pkg_path, &pkg) &&
                             sysfs_read_int(core_path, &core);
        if (have_topology) {
            bool seen = false;
            for (int i = 0; i < cores_seen_count; i++) {
                if (cores_seen[i].pkg == pkg && cores_seen[i].core == core) {
                    seen = true;
                    break;
                }
            }
            if (!seen && cores_seen_count < CPU_TOPOLOGY_MAX_CPUS) {
                cores_seen[cores_seen_count].pkg = pkg;
                cores_seen[cores_seen_count].core = core;
                cores_seen_count++;
            }
            int w = smt_width_of(root, cpu);
            if (w > max_smt_width) max_smt_width = w;
        }

        if (st->domain_of[cpu] != -1) continue; /* already assigned by a
                                                    * sibling's shared_cpu_list */

        int64_t l3_size = 0;
        char shared_list[CPU_TOPOLOGY_LINE_MAX];
        if (find_l3_cache(root, cpu, &l3_size, shared_list, sizeof(shared_list))) {
            if (st->domain_count >= CPU_TOPOLOGY_MAX_DOMAINS) continue;
            struct cpu_topology_domain *d = &st->domains[st->domain_count];
            d->id = st->domain_count;
            d->l3_size_bytes = l3_size;
            d->cpu_count = 0;
            expand_cpu_list(shared_list, d->cpus, CPU_TOPOLOGY_MAX_CPUS,
                            &d->cpu_count);
            for (int i = 0; i < d->cpu_count; i++) {
                int c = d->cpus[i];
                if (c >= 0 && c < CPU_TOPOLOGY_MAX_CPUS) st->domain_of[c] = d->id;
            }
            st->domain_count++;
        }
    }

    if (present_count == 0) return false;
    if (present_count > CPU_TOPOLOGY_MAX_CPUS) present_count = CPU_TOPOLOGY_MAX_CPUS;
    st->logical_cpus = present_count;
    st->physical_cores = cores_seen_count > 0 ? cores_seen_count : present_count;
    st->smt_width = max_smt_width;

    /* No cache info anywhere (containers with topology/ but no cache/) —
     * synthesize one domain covering every present cpu so every logical
     * cpu still resolves to a domain and the pin API stays usable. */
    if (st->domain_count == 0) {
        struct cpu_topology_domain *d = &st->domains[0];
        d->id = 0;
        d->l3_size_bytes = 0;
        d->cpu_count = present_count;
        for (int i = 0; i < present_count; i++) {
            d->cpus[i] = i;
            st->domain_of[i] = 0;
        }
        st->domain_count = 1;
    } else {
        /* Any present cpu that found no L3 entry (heterogeneous /sys
         * export) still needs a domain — fold it into domain 0 rather
         * than leaving a -1 hole that domain_of()/pin_thread() cannot
         * serve. */
        for (int i = 0; i < present_count; i++) {
            if (st->domain_of[i] == -1) {
                struct cpu_topology_domain *d = &st->domains[0];
                if (d->cpu_count < CPU_TOPOLOGY_MAX_CPUS) {
                    d->cpus[d->cpu_count++] = i;
                    st->domain_of[i] = d->id;
                }
            }
        }
    }

    snprintf(st->source, sizeof(st->source), "sysfs");
    st->valid = true;
    return true;
}
#endif

/* ── Lifecycle ─────────────────────────────────────────────────────── */

bool cpu_topology_init(void)
{
    if (atomic_load(&g_inited)) return g_state.valid;

    pthread_mutex_lock(&g_lock);
    if (atomic_load(&g_inited)) {
        pthread_mutex_unlock(&g_lock);
        return g_state.valid;
    }

    struct cpu_topology_state st;
#if defined(_WIN32)
    if (!scan_windows(&st))
        fill_fallback(&st);
#else
    if (!scan_sysfs(g_sysfs_root, &st)) {
        fill_fallback(&st);
    }
#endif
    g_state = st;
    atomic_store(&g_inited, true);
    pthread_mutex_unlock(&g_lock);

    if (!g_state.valid) {
        LOG_FAIL("cpu_topology",
                 "init: both /sys scan and sysconf fallback failed to "
                 "produce a usable topology");
    }
    return true;
}

void cpu_topology_set_sysfs_root_for_testing(const char *root)
{
    pthread_mutex_lock(&g_lock);
    if (root) {
        snprintf(g_sysfs_root, sizeof(g_sysfs_root), "%s", root);
    } else {
        snprintf(g_sysfs_root, sizeof(g_sysfs_root), "%s",
                 CPU_TOPOLOGY_DEFAULT_ROOT);
    }
    pthread_mutex_unlock(&g_lock);
}

#ifdef ZCL_TESTING
void cpu_topology_reset_for_testing(void)
{
    pthread_mutex_lock(&g_lock);
    memset(&g_state, 0, sizeof(g_state));
    atomic_store(&g_inited, false);
    pthread_mutex_unlock(&g_lock);
}
#endif

/* ── Queries ───────────────────────────────────────────────────────── */

int cpu_topology_logical_cpus(void)
{
    cpu_topology_init();
    return g_state.logical_cpus;
}

int cpu_topology_physical_cores(void)
{
    cpu_topology_init();
    return g_state.physical_cores;
}

int cpu_topology_l3_domains(void)
{
    cpu_topology_init();
    return g_state.domain_count;
}

int cpu_topology_domain_of(int cpu)
{
    cpu_topology_init();
    if (cpu < 0 || cpu >= CPU_TOPOLOGY_MAX_CPUS) return -1;
    return g_state.domain_of[cpu];
}

int cpu_topology_largest_l3_domain_cpus(int *out, int cap)
{
    cpu_topology_init();
    if (!out || cap <= 0 || g_state.domain_count <= 0) return 0;

    int best = 0;
    for (int i = 1; i < g_state.domain_count; i++) {
        if (g_state.domains[i].l3_size_bytes > g_state.domains[best].l3_size_bytes)
            best = i;
    }

    int n = g_state.domains[best].cpu_count;
    if (n > cap) n = cap;
    memcpy(out, g_state.domains[best].cpus, (size_t)n * sizeof(int));
    return n;
}

bool cpu_topology_domain_at(int idx, struct cpu_topology_domain *out)
{
    cpu_topology_init();
    if (!out || idx < 0 || idx >= g_state.domain_count)
        LOG_FAIL("cpu_topology", "domain_at: index %d out of range (have %d)",
                 idx, g_state.domain_count);
    *out = g_state.domains[idx];
    return true;
}

const char *cpu_topology_source(void)
{
    cpu_topology_init();
    return g_state.source;
}

/* ── Pinning ───────────────────────────────────────────────────────── */

bool cpu_topology_pin_thread(pthread_t thread, int domain)
{
    cpu_topology_init();
    if (domain < 0 || domain >= g_state.domain_count) {
        LOG_FAIL("cpu_topology", "pin_thread: invalid domain %d (have %d)",
                 domain, g_state.domain_count);
    }

#if defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    int n = g_state.domains[domain].cpu_count;
    for (int i = 0; i < n; i++) {
        int c = g_state.domains[domain].cpus[i];
        if (c >= 0 && c < CPU_SETSIZE) CPU_SET(c, &set);
    }

    int rc = pthread_setaffinity_np(thread, sizeof(set), &set);
    if (rc != 0) {
        LOG_FAIL("cpu_topology",
                 "pin_thread: pthread_setaffinity_np failed for domain %d: "
                 "errno=%d (%s)", domain, rc, strerror(rc));
    }
    return true;
#else
    (void)thread;
    return false;
#endif
}

/* ── Introspection ─────────────────────────────────────────────────── */

bool cpu_topology_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    cpu_topology_init();
    json_set_object(out);

    json_push_kv_str(out, "source", g_state.source);
    json_push_kv_int(out, "logical_cpus", g_state.logical_cpus);
    json_push_kv_int(out, "physical_cores", g_state.physical_cores);
    json_push_kv_int(out, "smt_threads_per_core", g_state.smt_width);
    json_push_kv_int(out, "l3_domains", g_state.domain_count);

    int largest = 0;
    for (int i = 1; i < g_state.domain_count; i++) {
        if (g_state.domains[i].l3_size_bytes > g_state.domains[largest].l3_size_bytes)
            largest = i;
    }
    json_push_kv_int(out, "largest_l3_domain", largest);
    json_push_kv_int(out, "largest_l3_size_bytes",
                     g_state.domains[largest].l3_size_bytes);

    struct json_value domains_arr;
    json_init(&domains_arr);
    json_set_array(&domains_arr);
    for (int i = 0; i < g_state.domain_count; i++) {
        const struct cpu_topology_domain *d = &g_state.domains[i];
        struct json_value dv;
        json_init(&dv);
        json_set_object(&dv);
        json_push_kv_int(&dv, "id", d->id);
        json_push_kv_int(&dv, "l3_size_bytes", d->l3_size_bytes);
        json_push_kv_int(&dv, "cpu_count", d->cpu_count);

        struct json_value cpus_arr;
        json_init(&cpus_arr);
        json_set_array(&cpus_arr);
        for (int c = 0; c < d->cpu_count; c++) {
            struct json_value cv;
            json_init(&cv);
            json_set_int(&cv, d->cpus[c]);
            json_push_back(&cpus_arr, &cv);
            json_free(&cv);
        }
        json_push_kv(&dv, "cpus", &cpus_arr);
        json_free(&cpus_arr);

        json_push_back(&domains_arr, &dv);
        json_free(&dv);
    }
    json_push_kv(out, "domains", &domains_arr);
    json_free(&domains_arr);

    diag_push_health(out, g_state.valid,
                     g_state.valid ? "" : "topology scan produced no usable cpus");
    return true;
}
