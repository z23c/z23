/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hardware bench organ: a boot-time MEASUREMENT companion to hw_profile
 * (which derives tunables from TOPOLOGY — core count, RAM size, ISA). This
 * module measures the two latencies topology cannot see:
 *
 *   1. fsync latency  — median wall time of ~8 fsync() calls on a small
 *      probe file in the datadir. Dominates batch-commit throughput (the
 *      genesis fold's jbd2_log_wait_commit wait).
 *   2. 4KB random pread latency — median wall time of ~32 pread() calls at
 *      random offsets into an existing datadir file. Proxies concurrent
 *      random-I/O cost (background-validation worker contention).
 *
 * Both probes run ONCE per (datadir, hardware fingerprint) pair, capped at
 * a combined 300ms wall-clock budget, and the result is cached in a small
 * flat file under the datadir (`hw_bench.kv` — NOT a consensus store, NOT
 * progress.kv; a plain key=value cache this module owns end to end). A
 * later boot with the SAME fingerprint (see hw_bench_fingerprint_hex) loads
 * the cache instead of re-measuring; a fingerprint mismatch (different
 * core/RAM/ISA/rotational signature — e.g. moved to different hardware or a
 * VM resize) invalidates the cache and re-measures.
 *
 * Consumers call the two derived-tunable wrappers below (hw_bench_batch_size,
 * hw_bench_verify_workers), NOT the raw latencies directly. Each wrapper
 * takes the topology-derived value hw_profile would have produced as its
 * `normal_*` argument and returns it UNCHANGED whenever a measurement is not
 * yet available (never fatal, never blocks boot on a probe failure) — the
 * measured path only ever refines the topology fallback, never replaces the
 * safety of having one.
 *
 * CALLER CONTRACT — hw_bench_init() is the ONLY function in this file that
 * may run the probe, and it must be called EXPLICITLY, at a one-time
 * initialization point that is NOT a hot path (boot.c calls it once, at
 * boot, before the block-ingest reducer can ever run; bg_validation_init
 * calls it once at its own service startup). Every query and derived-tunable
 * function below is a plain atomic-load-and-arithmetic read of the
 * already-published result: if hw_bench_init() has not yet completed
 * (anywhere, by anyone) they serve the documented "unmeasured" default —
 * they NEVER call hw_bench_init() themselves, and so can never inject a
 * synchronous fsync/pread probe into a caller's hot path or a held lock. */

#ifndef ZCL_HW_BENCH_H
#define ZCL_HW_BENCH_H

#include <stdbool.h>
#include <stdint.h>

struct json_value; /* fwd; see json/json.h */

/* ── Lifecycle ─────────────────────────────────────────────────────── */

/* Idempotent, thread-safe: the first caller does the probe-or-load (up to
 * the combined 300ms budget above), everyone else observes the cached
 * result via a lock-free fast path. `datadir` may be NULL, in which case the
 * real node datadir (util/util.h's GetDataDir) is resolved. NEVER fatal — a
 * failed sub-probe or an unwritable cache file just leaves that field
 * unmeasured; callers fall back to their topology-derived default. Always
 * returns true.
 *
 * MUST be called explicitly by an owner at a one-time, non-hot-path
 * initialization point — see the CALLER CONTRACT above. Do not add a new
 * call to this function from inside a per-block / per-batch / lock-held
 * loop; add a one-time call at that subsystem's own init instead (follow
 * bg_validation_init's example in bg_validation_service.c). */
bool hw_bench_init(const char *datadir);

#ifdef ZCL_TESTING
/* Test hook: drop the cached measurement so the next hw_bench_init() call
 * re-probes. Production never calls this. */
void hw_bench_reset_for_testing(void);

/* Test hook: force the measured state directly (bypassing any probe/cache
 * I/O) so the derived-tunable formulas (hw_bench_batch_size,
 * hw_bench_verify_workers) can be unit-tested deterministically. Pass -1
 * for either argument to simulate "unmeasured". Production never calls
 * this. */
void hw_bench_set_measured_for_testing(int64_t fsync_us, int64_t pread_us);

/* Test hook: count of real bench_fsync/bench_pread probe PASSES since
 * process start (cache loads and query calls never increment this). Used to
 * prove the query/derived-tunable functions below never trigger a probe.
 * Production never calls this. */
int hw_bench_probe_run_count_for_testing(void);
#endif

/* ── Queries — atomic-load-only; NEVER call hw_bench_init() (see the
 * CALLER CONTRACT above). Each serves its "unmeasured" default until some
 * owner has explicitly called hw_bench_init() at least once. ───────────── */

/* Median fsync() latency in microseconds over the probe file, or -1 if
 * unmeasured (hw_bench_init() has not completed yet, the probe never ran,
 * or the datadir was not writable). */
int64_t hw_bench_fsync_us(void);

/* Median 4KB random pread() latency in microseconds over an existing
 * datadir file, or -1 if unmeasured (hw_bench_init() has not completed yet,
 * no suitable file was found, or the probe never ran). */
int64_t hw_bench_pread_us(void);

/* True iff EITHER latency above is measured (loaded from cache or freshly
 * probed this boot) — i.e. at least one derived tunable below can move off
 * its topology fallback. False if hw_bench_init() has not completed yet. */
bool hw_bench_measured(void);

/* Seconds since the current measurement was taken (cache write time, or
 * "now" for a fresh probe), or -1 if never measured (including when
 * hw_bench_init() has not completed yet). */
int64_t hw_bench_age_seconds(void);

/* True iff the current measurement came from the on-disk cache (not a
 * fresh probe this boot). Meaningless when hw_bench_measured() is false. */
bool hw_bench_from_cache(void);

/* 16 lowercase hex chars identifying the (cores, ram, isa, rotational)
 * signature the current measurement was taken under, or "" if
 * hw_bench_init() has not completed yet. Static buffer, valid until the
 * next hw_bench_init() call on another thread. */
const char *hw_bench_fingerprint_hex(void);

/* ── Derived tunables — pure passthrough of `normal_*` when unmeasured;
 * a plain atomic-load-and-arithmetic read, provably allocation-free and
 * syscall-free (safe to call from a hot path / under a held lock). ─────── */

/* Per-stage-per-drain batch-commit size (see reducer_drain.c). Slower
 * measured fsync => bigger batch (fewer, larger commits amortize the fsync
 * cost); never returns less than `normal_batch` (the topology/legacy
 * default already tuned for the common case) and never more than
 * HW_BENCH_BATCH_SIZE_CEILING. Returns `normal_batch` unchanged when fsync
 * is unmeasured or at/below the fast-storage baseline. */
int hw_bench_batch_size(int normal_batch);

/* Background-validation worker count (see bg_validation_service.c). Slower
 * measured random-read latency => fewer concurrent workers (less I/O
 * contention on the storage device); never returns more than
 * `normal_workers` (the topology-derived count) and never less than 1.
 * Returns `normal_workers` unchanged when pread is unmeasured or at/below
 * the fast-storage baseline. */
int hw_bench_verify_workers(int normal_workers);

/* ── `z23 dumpstate hw_bench` ─────────────────────────────────── */

bool hw_bench_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_HW_BENCH_H */
