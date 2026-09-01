/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mem_pressure — the memory-pressure organ (Rung 1 follow-on,
 * docs/adr/0003-os-substrate-verdict.md + docs/work/os-substrate-plan.md).
 *
 * WHY: node_health_service.c has warned on high RSS since the node's
 * earliest days (HEALTH_RSS_WARNING_MB, "high_memory_usage") and
 * agent_resources.c independently classifies cgroup memory pressure
 * (memory_pressure=warn/watch/ok) — both are OBSERVE-ONLY. The live
 * incident that motivated this module: RSS at 11.4 GB against a 4 GB warn
 * threshold with ZERO corrective mechanism — the node just kept climbing
 * until an external OOM killer or operator intervened. This module is the
 * missing REMEDY half: a typed level ladder + a registry of cheap,
 * NON-CONSENSUS shrink callbacks that fire automatically once pressure
 * crosses HIGH.
 *
 * LEVELS: computed as current-usage / denominator, where the denominator is
 * the best available ceiling in this priority order:
 *   1. cgroup memory.high (the soft cap the kernel throttles reclaim
 *      against — the most accurate "getting close to trouble" signal when
 *      set)
 *   2. cgroup memory.max (the hard OOM-kill ceiling)
 *   3. observed host available memory against system total RAM (Darwin and
 *      Linux bare-metal/non-systemd)
 *   4. process RSS against system total RAM when host availability is unknown
 * current usage is cgroup memory.current when a cgroup denominator was
 * selected (matches what the kernel enforces against). With an observed host
 * availability value it is total minus available, so Commons/background work
 * yields to unified-memory contention created by the rest of the Mac too;
 * otherwise it is this process's RSS. Thresholds are env-tunable percentages
 * of that denominator (ZCL_MEM_PRESSURE_ELEVATED_PCT / _HIGH_PCT / _CRITICAL_PCT,
 * defaults 50/75/90 — see mem_pressure_thresholds_from_env()).
 *
 * SINKS: any subsystem with a cheap, safe, reversible way to shed RAM can
 * register a shrink callback (mem_pressure_register_sink). NEVER register a
 * sink that touches consensus-authoritative state (block_index, the coins/
 * UTXO working set, Sapling/Sprout anchors/nullifiers, the active chain) —
 * those are correctness-critical in-RAM structures, not caches; evicting
 * them mid-operation is a correctness bug, not a memory optimization. Safe
 * candidates are read-through caches derived from already-persisted data
 * (a parsed-block LRU, a relay-layer buffer) or the allocator itself
 * (malloc_trim, the built-in default sink — see mem_pressure.c).
 *
 * POLLING: ticks on the EXISTING engine/modules/health periodic ring (the same
 * pattern engine/composition/src/boot_sd_watchdog.c uses) every
 * MEM_PRESSURE_POLL_SECS — no dedicated thread. See
 * engine/composition/src/boot_mem_pressure.c for the boot wiring.
 *
 * Thread safety: the level + last-reading fields are atomics (lock-free
 * snapshot reads); the sink registry is a fixed-capacity array guarded by
 * a mutex only during register/walk (walking runs on the health sweeper
 * thread, registration typically happens once at boot from each
 * subsystem's own init path).
 */

#ifndef ZCL_UTIL_MEM_PRESSURE_H
#define ZCL_UTIL_MEM_PRESSURE_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEM_PRESSURE_MAX_SINKS 16
#define MEM_PRESSURE_POLL_SECS 5

enum mem_pressure_level {
    MEM_NOMINAL = 0,
    MEM_ELEVATED,
    MEM_HIGH,
    MEM_CRITICAL,
};

const char *mem_pressure_level_name(enum mem_pressure_level level);

/* A registered shrink callback. The CALLER owns the storage (typically a
 * static file-scope struct in the registering subsystem) — it must outlive
 * every future poll tick, i.e. never register a stack-local instance.
 * `shrink` is invoked from the health sweeper thread on a MEM_HIGH-or-worse
 * tick; it must be fast (this runs on the shared periodic-tick thread,
 * holding no chain locks) and must never block on I/O that could itself be
 * memory-pressure-sensitive. */
struct mem_pressure_sink {
    const char *name;
    void (*shrink)(enum mem_pressure_level level, void *ctx);
    void *ctx;
    _Atomic int64_t last_shrink_unix;   /* 0 = never fired */
    _Atomic int64_t shrink_calls;
};

/* Register a sink. Returns false (logged) if the registry is full
 * (MEM_PRESSURE_MAX_SINKS) or `sink`/`sink->shrink` is NULL. Idempotent
 * re-registration of the SAME pointer is a no-op (returns true) so a
 * subsystem's lazy-init path can call this on every entry without
 * growing the registry. */
bool mem_pressure_register_sink(struct mem_pressure_sink *sink);

/* Current level as of the last poll tick. Lock-free. */
enum mem_pressure_level mem_pressure_current(void);

/* Run one poll cycle: read os_proc_mem, recompute the level, and — if the
 * level is MEM_HIGH or MEM_CRITICAL — walk every registered sink calling
 * its shrink callback. Exposed directly (not just via the health-ring
 * registration) so tests can drive it deterministically without waiting on
 * the sweeper thread. Safe to call from any single thread; concurrent
 * calls are not expected in production (the health ring serializes ticks)
 * but are not unsafe — the registry mutex + atomics prevent torn state. */
void mem_pressure_poll_tick(void);

/* Register mem_pressure_poll_tick on the existing health periodic ring
 * (MEM_PRESSURE_POLL_SECS cadence) — no dedicated thread. Idempotent.
 * Returns false if the health ring registration failed (registry full). */
bool mem_pressure_start(void);

/* Unregister from the health ring. Safe to call even if never started. */
void mem_pressure_stop(void);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. Exposes
 * level, the raw os_proc_mem reading, which denominator was selected, the
 * configured threshold percentages, and per-sink {name, last_shrink_unix,
 * shrink_calls}. */
struct json_value;
bool mem_pressure_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
/* Reset the sink registry + level state between tests. Does NOT touch the
 * os_proc test override (see platform/os_proc.h) — callers manage that
 * separately. */
void mem_pressure_reset_for_testing(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_UTIL_MEM_PRESSURE_H */
