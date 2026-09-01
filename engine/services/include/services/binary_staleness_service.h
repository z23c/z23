/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Binary Staleness — detects a running process whose in-memory image no
 * longer matches the binary file sitting at its own exec path.
 *
 * Motivation
 * ----------
 * `make deploy` replaces the binary file on disk, but an already-running
 * process keeps serving its old in-memory image (normal on Linux — a
 * replaced-on-disk executable does not affect an already-mapped process).
 * Nothing else in the node ever compares "what am I running" against
 * "what's on disk right now", so status/health schemas can silently drift
 * vs newer CLI clients built from the same repo.
 *
 * Detection trick
 * ----------------
 * `/proc/self/exe` is a magic symlink into the kernel's `exe_file`
 * reference: reading through it (open/fopen on the literal path
 * "/proc/self/exe") ALWAYS returns the exact bytes of the running image,
 * even after the file at the original pathname has been replaced by a
 * `mv`/rename-based deploy — the running process keeps its old inode
 * open. So:
 *
 *   - BOOT: `readlink("/proc/self/exe")` resolves the real on-disk path
 *     the process was exec'd from (stripping the kernel's " (deleted)"
 *     suffix if the original dentry is already gone). We hash the
 *     RUNNING IMAGE via the "/proc/self/exe" fd (immune to later
 *     replacement) — this is the fixed baseline for the life of the
 *     process — and separately `stat()` the RESOLVED PATH (by path
 *     string, not by fd) for a cheap mtime+size baseline.
 *   - TICK: `stat()` the resolved path again (by path — this follows
 *     ordinary pathname resolution, so a replaced file is visible).
 *     Only if mtime or size changed since the last tick do we re-open
 *     the resolved path (again by path, so we read whatever is CURRENTLY
 *     there) and re-hash it. A hash mismatch against the boot baseline
 *     means the on-disk binary is no longer what this process is
 *     running — `ops.binary_stale` — and the process should be
 *     restarted to pick up the deployed build.
 *
 * Cost
 * ----
 * One SHA3-256 pass over the binary at boot, one `stat()` per tick
 * (cheap), and a re-hash ONLY when `stat()` reports a change — never a
 * hash on every tick, so a multi-hundred-MB binary costs nothing on a
 * quiescent node.
 *
 * Blocker
 * -------
 * `ops.binary_stale` is a BLOCKER_TRANSIENT (util/blocker.h) — the
 * running process itself isn't broken, but it is serving a stale build,
 * and an operator restart clears it (there is nothing to auto-retry).
 * The reason text carries both digests' short-hex identity plus the
 * resolved path, mtime, and size so the operator can see exactly what
 * changed. Edge-triggered: set once when staleness is first observed,
 * cleared once the on-disk content matches the running image again
 * (e.g. the deploy was reverted to the same build).
 *
 * Surfacing
 * ---------
 * Folded into the existing `boot` dumpstate subsystem's JSON (see
 * `chain_restore_dump_state_json`) under a nested "binary_staleness" key
 * — deliberately NOT a new top-level dumper (see CLAUDE.md "Adding state
 * introspection" — don't bump the dumper count for a signal that fits an
 * existing surface). Also surfaced as a cheap "binary_stale" bool in both
 * the bounded and full paths of `z23 healthcheck` (see
 * event_healthcheck_controller.c).
 *
 * Thread safety
 * -------------
 * Owns its own pthread + mutex, same shape as disk_monitor.c.
 * `binary_staleness_is_stale()` is a lock-free atomic read for hot-path
 * callers. `binary_staleness_check_now()` is the single code path used
 * by both the thread and tests.
 */

#ifndef ZCL_SERVICES_BINARY_STALENESS_SERVICE_H
#define ZCL_SERVICES_BINARY_STALENESS_SERVICE_H

#include "util/result.h"
#include <stdbool.h>
#include <stdint.h>

/* ── Tunables ───────────────────────────────────────────────── */

/* "slow periodic tick" — a stale-binary condition is not urgent enough
 * to poll every few seconds; 5 minutes is frequent enough that an
 * operator sees it well within a soak window without adding measurable
 * background cost. */
#define BINARY_STALENESS_DEFAULT_POLL_SECONDS 300

#define BINARY_STALENESS_BLOCKER_ID "ops.binary_stale"
#define BINARY_STALENESS_OWNER      "binary_staleness"

/* ── Config ─────────────────────────────────────────────────── */

struct binary_staleness_config {
    int poll_seconds; /* 0 = use default (300s) */
};

void binary_staleness_config_defaults(struct binary_staleness_config *cfg);

/* ── Status snapshot (read-only) ────────────────────────────── */

struct binary_staleness_status {
    bool    running;              /* background thread is active */
    bool    boot_captured;        /* boot baseline has been captured */
    bool    stale;                /* on-disk content != running image */
    bool    path_valid;           /* the resolved exe path was stat-able
                                    * last time we tried */
    char    exe_path[512];        /* resolved /proc/self/exe target */
    char    boot_digest_hex[65];  /* SHA3-256 of the running image, hex */
    char    last_disk_digest_hex[65]; /* SHA3-256 last read from disk, hex
                                    * (empty until the first rehash) */
    int64_t boot_mtime;           /* baseline mtime (unix seconds), -1 if
                                    * unknown */
    int64_t boot_size;            /* baseline size in bytes, -1 if unknown */
    int64_t last_probe_mtime;     /* most recent stat() mtime observed */
    int64_t last_probe_size;      /* most recent stat() size observed */
    int64_t last_check_unix;      /* wall-clock time of the last tick, 0 if
                                    * never ticked */
    int64_t check_count;          /* ticks run (boot capture excluded) */
    int64_t rehash_count;         /* times the on-disk content was
                                    * actually re-hashed (stat changed) */
    int64_t stale_transitions;    /* number of ok->stale edges observed */
    int64_t probe_failures;       /* stat()/open() failures on the
                                    * resolved path since start */
};

void binary_staleness_status_snapshot(struct binary_staleness_status *out);

/* See CLAUDE.md "Adding state introspection". Deliberately NOT registered
 * as its own top-level dumper — callers fold this into an existing
 * dumper's JSON (see chain_restore_dump_state_json). Reentrant-safe. */
struct json_value;
bool binary_staleness_dump_state_json(struct json_value *out, const char *key);

/* ── Hot-path query (lock-free) ─────────────────────────────── */

/* True if the most recent tick found the on-disk binary's content
 * different from the running image. False before boot capture. */
bool binary_staleness_is_stale(void);

/* ── Lifecycle ──────────────────────────────────────────────── */

/* Captures the boot baseline synchronously (readlink + hash the running
 * image via /proc/self/exe, stat the resolved path), then starts the
 * background polling thread. Returns a non-ok zcl_result if already
 * running or if the boot baseline capture fails (e.g. /proc is
 * unavailable — non-Linux or a sandboxed environment without /proc).
 * Safe to call from any thread. */
struct zcl_result binary_staleness_start(
    const struct binary_staleness_config *cfg);

/* Stop and join. Safe to call when not running. */
void binary_staleness_stop(void);

/* ── Testable primitives ─────────────────────────────────────── */

/* Capture the boot baseline without starting the thread. Exposed so
 * `binary_staleness_start` and tests share one code path. Returns false
 * (LOG_FAIL) if /proc/self/exe cannot be resolved or hashed. */
bool binary_staleness_capture_boot_stamp(void);

/* Run one check cycle: stat the resolved path, rehash + compare only if
 * mtime/size changed since the last tick, and flip the
 * `ops.binary_stale` typed blocker on any ok<->stale edge. This is the
 * exact code path the background thread calls every poll_seconds; tests
 * call it directly. Returns the post-check stale state. No-op (returns
 * false) if the boot baseline has not been captured yet. */
bool binary_staleness_check_now(void);

/* ── Test hooks ──────────────────────────────────────────────── */

#ifdef ZCL_TESTING
/* Wipe all state (boot baseline, counters, overrides, blocker) back to
 * "never started". Does not touch a running thread — callers must
 * `binary_staleness_stop()` first if one is active. */
void binary_staleness_reset_for_testing(void);

/* Force the boot baseline to fixed values instead of reading the real
 * /proc/self/exe (the test binary itself never changes, so a real-file
 * test can't exercise the mismatch path). `digest_hex` must be exactly
 * 64 lowercase hex chars (32 bytes). Also marks boot_captured=true and
 * seeds last_probe_mtime/size so the next check_now() has a baseline to
 * diff against. */
void binary_staleness_test_force_boot_stamp(const char *digest_hex,
                                            int64_t mtime, int64_t size,
                                            const char *path);

/* Force the NEXT (and every subsequent, until cleared) check_now() call
 * to use these values instead of touching the real filesystem. Set a
 * different value between check_now() calls to simulate the on-disk
 * binary changing across ticks. */
void binary_staleness_test_force_probe(const char *digest_hex,
                                       int64_t mtime, int64_t size);

/* Stop forcing check_now()'s probe — subsequent calls hit the real
 * filesystem again (against g_bs.exe_path, which is likely also a test
 * override). */
void binary_staleness_test_clear_probe_override(void);
#endif

#endif /* ZCL_SERVICES_BINARY_STALENESS_SERVICE_H */
