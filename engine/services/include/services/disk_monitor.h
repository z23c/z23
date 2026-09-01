/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Disk Monitor — background free-space watcher.
 *
 * Motivation
 * ----------
 * A full disk is the second-most-common operational failure mode
 * after "the user accidentally deleted the data directory". Today
 * nothing inside the node notices until SQLite starts returning
 * I/O errors mid-transaction, by which time the boot safety rails
 * have long since been evaluated and the node may be mid-write
 * to a filesystem that just filled.
 *
 * This service runs one pthread that polls the platform capacity seam on the
 * data directory every N seconds. When free bytes drop below
 * `warn_free_bytes` it emits `EV_DISK_LOW` (operators should
 * rotate/clean). When free bytes drop below `refuse_free_bytes`
 * it emits `EV_DISK_CRITICAL` and flips an atomic flag that the
 * mempool, block processor, and any other write-heavy path can
 * inspect to refuse new work.
 *
 * Recovery: if free bytes climb back above the corresponding
 * threshold the state-transition edge emits `EV_DISK_OK` and
 * clears the critical flag. The transitions are sticky — we
 * don't flap between OK and LOW on every tick.
 *
 * Thread safety
 * -------------
 * The monitor owns a pthread and a mutex guarding lifecycle
 * state. `disk_monitor_is_critical()` is lock-free (atomic) so
 * the mempool / block processor hot path has no contention.
 * `disk_monitor_free_bytes()` is a standalone UTF-8-path wrapper usable
 * without the thread running — tests call it
 * directly.
 */

#ifndef ZCL_SERVICES_DISK_MONITOR_H
#define ZCL_SERVICES_DISK_MONITOR_H

#include "util/result.h"
#include <stdbool.h>
#include <stdint.h>

/* ── Tunables / defaults ────────────────────────────────────── */

#define DISK_MONITOR_DEFAULT_WARN_BYTES    (int64_t)(5LL * 1024 * 1024 * 1024)
#define DISK_MONITOR_DEFAULT_REFUSE_BYTES  (int64_t)(1LL * 1024 * 1024 * 1024)
#define DISK_MONITOR_DEFAULT_POLL_SECONDS  60

/* ── Config ─────────────────────────────────────────────────── */

struct disk_monitor_config {
    const char *datadir;             /* absolute path to watch */
    int64_t     warn_free_bytes;     /* 0 = use default (5 GB)  */
    int64_t     refuse_free_bytes;   /* 0 = use default (1 GB)  */
    int         poll_seconds;        /* 0 = use default (60s)   */
};

void disk_monitor_config_defaults(struct disk_monitor_config *cfg);

/* ── Status snapshot (read-only) ────────────────────────────── */

enum disk_monitor_level {
    DISK_MONITOR_OK = 0,
    DISK_MONITOR_LOW,
    DISK_MONITOR_CRITICAL,
};

struct disk_monitor_status {
    bool    running;
    enum disk_monitor_level level;
    int64_t last_free_bytes;    /* -1 if never polled */
    int64_t last_poll_unix;     /* 0 if never polled  */
    int64_t warn_free_bytes;    /* resolved threshold */
    int64_t refuse_free_bytes;  /* resolved threshold */
    char    datadir[512];
};

void disk_monitor_status_snapshot(struct disk_monitor_status *out);

/* `z23 dumpstate disk_monitor` — free-space watchdog snapshot.
 * See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool disk_monitor_dump_state_json(struct json_value *out, const char *key);

/* ── Lifecycle ──────────────────────────────────────────────── */

/* Start the background thread. Returns a non-ok result if already
 * running or if the datadir path can't be stat'd. Safe to call from
 * any thread. Running the first poll is synchronous so callers know
 * the current level before the function returns. */
struct zcl_result disk_monitor_start(const struct disk_monitor_config *cfg);

/* Stop and join. Safe to call when not running. */
void disk_monitor_stop(void);

/* Force an immediate poll (same code path the thread uses). Used
 * by tests so they don't have to sleep for `poll_seconds`. */
void disk_monitor_poll_now(void);

/* ── Hot-path queries (lock-free) ───────────────────────────── */

/* Returns true if the most recent poll classified the state as
 * DISK_MONITOR_CRITICAL. Block processing, mempool acceptance,
 * and any write-heavy code path should check this before
 * committing new bytes. */
bool disk_monitor_is_critical(void);

/* Current level as last observed. */
enum disk_monitor_level disk_monitor_level(void);

/* ── Standalone primitive (testable) ────────────────────────── */

/* Return free bytes on the filesystem containing `path`. Returns
 * -1 on any platform capacity-query error. This is the only place in the service
 * that touches the kernel, so tests stub it by pointing at a
 * temp directory they control. */
int64_t disk_monitor_free_bytes(const char *path);

/* Process-local unit-test seam. A negative value restores the platform query. */
void disk_monitor_set_free_bytes_for_test(int64_t bytes);

#endif /* ZCL_SERVICES_DISK_MONITOR_H */
