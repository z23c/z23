/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * CPU topology organ: discovers the machine's real CPU topology (physical
 * cores, SMT siblings, L3 cache domains / CCDs) from the native host
 * authority (/sys on Linux; sysctl on Darwin) so worker pools can be sized
 * by physical reality instead of a bare
 * sysconf(_SC_NPROCESSORS_ONLN) core count. Pure, allocation-free after
 * init; degrades gracefully (sysconf fallback) when /sys is unreadable
 * (containers) — see docs/DEFENSIVE_CODING.md + CLAUDE.md "Adding state
 * introspection" for the conventions this module follows.
 *
 * Motivating case: the AMD Ryzen 9 7950X3D has two L3 cache domains (CCDs)
 * — one carries 96 MB of 3D V-Cache, the other a plain 32 MB — that a bare
 * core count cannot distinguish. Pinning a cache-sensitive worker pool to
 * the larger domain is a measured win; this module is what makes that
 * decision possible. This module does NOT itself size or pin any pool —
 * that integration is a separate lane; this is discovery + a pin primitive
 * only. */

#ifndef ZCL_CPU_TOPOLOGY_H
#define ZCL_CPU_TOPOLOGY_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

/* Static registry capacity. 1024 logical cpus / 64 L3 domains is generous
 * headroom over anything on the market today (largest known: a few hundred
 * logical cpus, a handful of CCDs per socket). */
#define CPU_TOPOLOGY_MAX_CPUS    1024
#define CPU_TOPOLOGY_MAX_DOMAINS 64
#define CPU_TOPOLOGY_MAX_PERFORMANCE_LEVELS 8

struct json_value; /* fwd; see json/json.h */

/* One L3 cache domain (a CCD on multi-CCD AMD parts; the whole package on a
 * single-L3-domain machine; a synthetic single domain covering every
 * logical cpu on the sysconf fallback path). */
struct cpu_topology_domain {
    int     id;                            /* 0-based, stable within a run */
    int64_t l3_size_bytes;                 /* 0 if unknown */
    int     cpu_count;
    int     cpus[CPU_TOPOLOGY_MAX_CPUS];   /* logical cpu ids in this domain */
};

/* A scheduler performance level reported by the host. Darwin arm64 exposes
 * these as hw.perflevelN sysctls (for example Performance and Efficiency on
 * Apple Silicon). They are observations only: Z23 does not infer CPU ids or
 * pin work to a level because macOS does not publish a stable affinity map. */
struct cpu_topology_performance_level {
    char    name[32];
    int     logical_cpus;
    int     physical_cores;
    int64_t l2_size_bytes; /* 0 when the host does not publish it */
};

/* ── Lifecycle ─────────────────────────────────────────────────────── */

/* Idempotent, thread-safe. Safe to call from multiple threads or multiple
 * times — the first caller does the scan, everyone else observes the
 * cached result. NEVER fatal: on total /sys failure it still succeeds with
 * cpu_topology_source() == "fallback" and a single-domain topology derived
 * from sysconf(_SC_NPROCESSORS_ONLN). Returns false only if even that
 * fallback yields zero usable cpus (not observed on real Linux). */
bool cpu_topology_init(void);

/* Test seam: override the /sys base directory (default
 * "/sys/devices/system/cpu") that cpu_topology_init() scans. Pass NULL to
 * restore the default. Call BEFORE cpu_topology_init() (or after
 * cpu_topology_reset_for_testing()) — init caches its result and will not
 * re-scan on a later call. Lets tests point at a nonexistent directory to
 * exercise the fallback path, or a fixture tree to exercise the parser. */
void cpu_topology_set_sysfs_root_for_testing(const char *root);

#ifdef ZCL_TESTING
/* Test hook: drop the cached topology so the next cpu_topology_init() call
 * re-scans (honoring a fresh cpu_topology_set_sysfs_root_for_testing()
 * override). Production never calls this. */
void cpu_topology_reset_for_testing(void);
#endif

/* ── Queries (pure; no allocation; O(1) or O(domains)) ───────────────── */

/* Logical CPU count. Calls cpu_topology_init() if not yet initialized. */
int cpu_topology_logical_cpus(void);

/* Physical core count: logical / SMT width, derived from /sys topology
 * (unique physical_package_id + core_id pairs). Always 1 <= cores <=
 * logical_cpus. On the fallback path, equals logical_cpus (SMT topology
 * unknown). */
int cpu_topology_physical_cores(void);

/* Number of distinct L3 cache domains found. Always >= 1 (the fallback
 * path reports exactly 1 domain covering every logical cpu). */
int cpu_topology_l3_domains(void);

/* Which domain id owns logical cpu `cpu`. Returns -1 if `cpu` is out of
 * range or was never assigned to a domain (should not happen post-init —
 * every logical cpu belongs to exactly one domain). */
int cpu_topology_domain_of(int cpu);

/* Fill `out` (capacity `cap`) with the logical cpu ids belonging to the
 * domain with the LARGEST L3 cache (the V-Cache CCD on a 7950X3D-class
 * part). Ties (equal L3 size, or L3 size unknown/0 everywhere) pick the
 * lowest domain id. Returns the number of ids written (0..cap); if `cap`
 * is smaller than the domain's cpu_count the list is truncated, not
 * overrun. */
int cpu_topology_largest_l3_domain_cpus(int *out, int cap);

/* Read-only snapshot of one domain (L3 size + full cpu list) by 0-based
 * index (0 <= idx < cpu_topology_l3_domains()). Returns false + leaves
 * `out` unwritten if `idx` is out of range. */
bool cpu_topology_domain_at(int idx, struct cpu_topology_domain *out);

/* "sysfs" once a real /sys topology was parsed, "darwin_sysctl" once the
 * Darwin host authority was observed, or "fallback" once only
 * sysconf(_SC_NPROCESSORS_ONLN) was available. Calls cpu_topology_init() if
 * not yet initialized. */
const char *cpu_topology_source(void);

/* Host-published scheduler performance levels. Zero means unavailable, not
 * homogeneous. `at` fails without modifying `out` for an invalid index. */
int cpu_topology_performance_levels(void);
bool cpu_topology_performance_level_at(
    int idx, struct cpu_topology_performance_level *out);

/* ── Pinning (advisory; never fatal) ──────────────────────────────────── */

/* Pin `thread` to the logical cpus belonging to `domain`
 * (pthread_setaffinity_np wrapper). Pinning is advisory: a failure here is
 * NEVER a reason to abort the caller's thread, it only means the thread
 * keeps running unpinned. Returns false + LOG_FAIL on any error (invalid
 * domain id, or the underlying pthread_setaffinity_np call failing) —
 * check the return value only if the caller wants to know whether the pin
 * took, never to decide whether to continue running. */
bool cpu_topology_pin_thread(pthread_t thread, int domain);

/* ── `z23 dumpstate cpu_topology` ─────────────────────────────── */

/* Dump-state-json wired into diagnostics_registry's g_dumpers[]. `out`
 * must be JSON-initialized by the caller. `key` is unused (one dump
 * returns the whole topology). Calls cpu_topology_init() itself, so it is
 * safe to query even if boot never called it explicitly. */
bool cpu_topology_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_CPU_TOPOLOGY_H */
