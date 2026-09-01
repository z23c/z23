/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hardware profile organ: probes the machine ONCE at boot (online cores,
 * total RAM, native x86/arm64 ISA extensions, datadir storage rotational flag) and
 * derives runtime tunables from that measured reality instead of pinned
 * constants — SQLite cache/mmap sizing, background-validation verify
 * parallelism, and an optional reducer-thread pin onto the large-L3 CCD on
 * asymmetric multi-CCD parts (e.g. the AMD Ryzen 9 7950X3D's 96 MB V-Cache
 * CCD vs its plain 32 MB CCD).
 *
 * L3 topology (including asymmetric-CCD detection) is NOT reimplemented
 * here — it is read straight from util/cpu_topology.h, which already owns
 * that sysfs scan + the pin primitive. This module adds the three probes
 * cpu_topology does not cover (RAM, ISA, storage rotational) plus the
 * derived-tunable functions, and composes cpu_topology's pin primitive
 * behind an advisory, opt-in call. See CLAUDE.md "Adding state
 * introspection" for the dumper convention this module follows. */

#ifndef ZCL_HW_PROFILE_H
#define ZCL_HW_PROFILE_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

struct json_value; /* fwd; see json/json.h */

/* ── Types ─────────────────────────────────────────────────────────── */

enum hw_profile_ram_class {
    HW_PROFILE_RAM_LOW = 0,   /* < 8 GiB physical RAM */
    HW_PROFILE_RAM_MEDIUM,    /* 8 GiB .. < 32 GiB */
    HW_PROFILE_RAM_HIGH,      /* >= 32 GiB */
};

/* Native ISA extensions relevant to this codebase's crypto/hash paths
 * (Equihash, SHA2/SHA3, checksums, ChaCha/Poly1305, BLS12-381 field
 * arithmetic). Each architecture's fields remain false elsewhere. arm64
 * fields come from the OS feature authority, never from build-host flags. */
struct hw_profile_isa {
    bool avx2;
    bool avx512f;
    bool avx512vl;
    bool avx512bw;
    bool avx512dq;
    bool vpclmulqdq;
    bool vaes;
    bool gfni;
    bool sha_ni;
    bool arm_neon;
    bool arm_sha256;
    bool arm_sha3;
    bool arm_crc32;
    bool arm_aes;
};

/* ── Lifecycle ─────────────────────────────────────────────────────── */

/* Idempotent, thread-safe: the first caller does the probe (cores, RAM,
 * ISA, and — if `datadir` is non-NULL — the datadir's storage rotational
 * flag), everyone else observes the cached result. `datadir` may be NULL
 * (rotational stays unknown) for callers that only need cores/RAM/ISA
 * (e.g. bg_validation_init, which runs before a datadir is guaranteed
 * mounted). NEVER fatal — a failed sub-probe just leaves that field at
 * its "unknown" default. Always returns true. */
bool hw_profile_init(const char *datadir);

#ifdef ZCL_TESTING
/* Test hook: drop the cached profile so the next hw_profile_init() call
 * re-probes. Production never calls this. */
void hw_profile_reset_for_testing(void);
/* Test seam: override the /sys/dev/block base directory (default
 * "/sys/dev/block") that the storage-rotational probe resolves
 * major:minor symlinks under. Pass NULL to restore the default. */
void hw_profile_set_block_root_for_testing(const char *root);
#endif

/* ── Queries (call hw_profile_init() internally if not yet probed) ──── */

int      hw_profile_online_cores(void);     /* == cpu_topology_logical_cpus() */
int      hw_profile_physical_cores(void);   /* == cpu_topology_physical_cores() */
int64_t  hw_profile_ram_bytes(void);        /* total physical RAM, 0 if unknown */
enum hw_profile_ram_class hw_profile_ram_class_of(int64_t ram_bytes);
const struct hw_profile_isa *hw_profile_isa(void);

/* Datadir storage rotational flag. Returns false (spinning-disk unknown
 * defaults to "not rotational", i.e. the SSD-shaped tuning path) unless a
 * real probe succeeded; *known is set to whether the probe actually
 * resolved a rotational flag (false on containers/tmpfs/no datadir). */
bool hw_profile_datadir_rotational(bool *known);

/* True iff >1 L3 domain exists AND at least two differ in size (the
 * 7950X3D-class asymmetric-CCD case). False on single-domain or
 * symmetric-multi-domain machines. */
bool hw_profile_l3_asymmetric(void);

/* cpu_topology domain id of the largest-L3 domain, ONLY when
 * hw_profile_l3_asymmetric() is true (-1 otherwise — pinning to "the
 * largest" domain is meaningless when every domain is the same size). */
int hw_profile_large_l3_domain(void);

/* ── Derived tunables — pure, allocation-free, monotone in `ram_bytes`
 *    (more RAM never lowers the derived value; the plateau above
 *    `ceiling_*` is why "monotone" means non-decreasing, not strictly
 *    increasing). A non-positive floor/ceiling argument falls back to the
 *    documented default for that argument. ─────────────────────────── */

/* SQLite page-cache size in KiB (negative-PRAGMA units), scaled ~1/32 of
 * RAM, clamped to [floor_kib, ceiling_kib]. Defaults: floor 16 MiB,
 * ceiling 1 GiB. Callers pick floor/ceiling matching their DB's role —
 * e.g. database.c's node.db keeps its historical 64 MiB ceiling;
 * progress_store.c's hot fold DB allows up to 1 GiB. */
int64_t hw_profile_sqlite_cache_kib(int64_t ram_bytes, int64_t floor_kib,
                                    int64_t ceiling_kib);

/* SQLite mmap window size in bytes, scaled ~1/16 of RAM, clamped to
 * [floor_bytes, ceiling_bytes]. Defaults: floor 64 MiB, ceiling 2 GiB.
 * IMPORTANT: database.c's node.db has a hard-documented 256 MiB safety
 * ceiling (concurrent secondary opens can SIGSEGV on stale mmap pages
 * above that) — pass ceiling_bytes=256*1024*1024 there; this function
 * only scales DOWN for low-RAM machines, it never raises a caller's
 * ceiling. */
int64_t hw_profile_sqlite_mmap_bytes(int64_t ram_bytes, int64_t floor_bytes,
                                     int64_t ceiling_bytes);

/* Background-validation script-verification worker count: physical_cores
 * / 2, clamped to [2, 4] (same clamp bg_validation_service.c has always
 * used — this just sources the numerator from measured physical cores via
 * cpu_topology instead of an inline nproc/2 guess). */
int hw_profile_verify_workers(int physical_cores);

/* Per-block script-verify batch cap. Returns 0 (unlimited) on machines
 * with >= 8 GiB RAM (or unknown RAM); returns 10000 below that, to bound
 * peak RSS during background validation on constrained machines. */
int hw_profile_script_batch_cap(int64_t ram_bytes);

/* Reducer/header drain batch: how many blocks a stage folds/admits between
 * COMMIT/fsync points. Scales UP off the caller's compiled `baseline` (used as
 * the FLOOR) with more RAM and more cores — a big-RAM many-core host commits
 * fewer, larger batches (less fsync/journal overhead per block), a small host
 * keeps the safe baseline. Pure, allocation-free, monotone NON-DECREASING in
 * `ram_bytes` (more RAM never lowers the result). A non-positive ram/cores
 * argument, or fewer than 4 cores, returns `baseline` unchanged. Result is
 * clamped to [baseline, baseline * 8]. */
int hw_profile_drain_batch(int64_t ram_bytes, int physical_cores, int baseline);

/* Runtime opt-in gate (-derive-drain-batch) for the RAM/core-derived drain
 * batch above. Default OFF: hw_profile_drain_batch_effective() returns the
 * caller's compiled baseline unchanged, so a normal boot's fold cadence is
 * byte-for-byte what it is today. Thread-safe (plain atomic). Set ONCE at
 * argv parse, before the reducer can run. */
void hw_profile_set_derive_drain_batch(bool on);
bool hw_profile_derive_drain_batch_enabled(void);

/* Gate-aware convenience — the single call the fold's drain sites use:
 * returns `baseline` when the -derive-drain-batch lever is OFF (the default),
 * else hw_profile_drain_batch(measured_ram, measured_cores, baseline). */
int hw_profile_drain_batch_effective(int baseline);

/* ── Reducer pinning (advisory; NEVER fatal) ─────────────────────────
 *
 * Pins `thread` onto the largest-L3 CCD's cpuset via
 * cpu_topology_pin_thread(), logging the chosen cpuset, ONLY when
 * hw_profile_l3_asymmetric() is true. Returns false (and logs why,
 * without failing the caller) when the topology is symmetric/unknown or
 * the underlying pin call fails — callers gate this behind an explicit
 * opt-in flag (e.g. -pin-reducer) and must never treat a false return as
 * fatal. */
bool hw_profile_pin_reducer_thread(pthread_t thread);

/* ── `z23 dumpstate hw_profile` ───────────────────────────────── */

bool hw_profile_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_HW_PROFILE_H */
