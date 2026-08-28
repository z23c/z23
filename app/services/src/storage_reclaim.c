/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * storage_reclaim — see header for rationale. This is the public reclaim
 * entry point the disk_full_pause condition calls so a near-full disk can
 * actually free derived bytes (and the condition clears) instead of latching.
 */

// one-result-type-ok:reclaim-counts-out-struct — E2 (one way out): the public
// surface is best-effort and reports a COUNT SUMMARY, not a fallible op whose
// reason must travel. storage_reclaim_derived() always runs every source it can
// (a failed/absent source is recorded in sources_ok/sources_total, never an
// error return) and returns a struct storage_reclaim_result; the underlying
// fallible checkpoints (progress_store_checkpoint / db_maintenance_checkpoint_now)
// already carry their own reasons. storage_reclaim_run_count() returns a counter.

#include "services/storage_reclaim.h"

#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "services/db_maintenance.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static _Atomic int64_t g_reclaim_runs;

int64_t storage_reclaim_run_count(void)
{
    return atomic_load(&g_reclaim_runs);
}

/* Unlink "<x>.tmp" crash orphans older than the min-age guard. An atomic
 * write-then-rename creates "<path>.tmp" and renames it within well under a
 * second, so a .tmp older than the guard cannot be an in-flight write — it is
 * a leftover from a process that died mid-write. Top level only (the datadir
 * root), regular files only, never a symlink or directory. Returns the count
 * removed and accumulates freed bytes into *bytes_out. */
static int sweep_stale_tmp(const char *datadir, int64_t *bytes_out)
{
    if (!datadir || !*datadir)
        return 0;
    struct platform_directory_list entries;
    if (!platform_directory_list_regular_sorted(datadir, &entries)) {
        LOG_WARN("storage_reclaim",
                 "[reclaim] directory enumeration failed: %s", datadir);
        return 0;
    }
    int removed = 0;
    time_t now = platform_time_wall_time_t();
    for (size_t i = 0; i < entries.count; i++) {
        const char *name = entries.entries[i].name;
        size_t n = strlen(name);
        if (n < 4 || strcmp(name + n - 4, ".tmp") != 0)
            continue;
        char path[2048];
        int pn = snprintf(path, sizeof(path), "%s/%s", datadir, name);
        if (pn <= 0 || pn >= (int)sizeof(path))
            continue;
        struct platform_positioned_file inspected;
        struct platform_positioned_file_snapshot snapshot;
        platform_positioned_file_init(&inspected);
        if (!platform_positioned_file_open_beneath(
                &inspected, datadir, name) ||
            !platform_positioned_file_snapshot(&inspected, &snapshot)) {
            platform_positioned_file_close(&inspected);
            continue;
        }
        platform_positioned_file_close(&inspected);
        int64_t now_seconds = (int64_t)now;
        uint64_t age = (uint64_t)now_seconds -
                       (uint64_t)snapshot.modified_seconds;
        if (snapshot.modified_seconds > now_seconds ||
            age < STORAGE_RECLAIM_TMP_MIN_AGE_SECS)
            continue; /* young: may be an in-flight atomic write — leave it */
        if (snapshot.size > INT64_MAX || snapshot.file_high != 0)
            continue;

        struct platform_private_file candidate;
        struct platform_private_file_identity expected = {
            .volume = snapshot.volume,
            .file = snapshot.file_low,
        };
        platform_private_file_init(&candidate);
        bool deleted = platform_private_file_open_locked(path, &candidate) &&
            platform_private_file_retire_if_identity(
                &candidate, path, &expected);
        platform_private_file_close(&candidate);
        if (deleted) {
            removed++;
            if (bytes_out) *bytes_out += (int64_t)snapshot.size;
        } else {
            LOG_WARN("storage_reclaim",
                     "[reclaim] exact-file retirement refused: %s", path);
        }
    }
    platform_directory_list_free(&entries);
    return removed;
}

struct storage_reclaim_result storage_reclaim_derived(const char *datadir)
{
    struct storage_reclaim_result r = {0};

    /* 1. progress.kv WAL → checkpoint+truncate (the cursor log). */
    r.sources_total++;
    if (progress_store_checkpoint())
        r.sources_ok++;

    /* 2. node.db WAL → checkpoint+truncate (UTXO set + explorer tables). */
    r.sources_total++;
    if (db_maintenance_checkpoint_now().ok)
        r.sources_ok++;

    /* 3. Sweep stale *.tmp crash orphans under the datadir. */
    r.tmp_files_removed = sweep_stale_tmp(datadir, &r.tmp_bytes_removed);

    atomic_fetch_add(&g_reclaim_runs, 1);

    LOG_INFO("storage_reclaim",
             "[reclaim] derived bytes freed: sources_ok=%d/%d tmp_removed=%d "
             "tmp_bytes=%lld datadir=%s",
             r.sources_ok, r.sources_total, r.tmp_files_removed,
             (long long)r.tmp_bytes_removed, datadir ? datadir : "");
    return r;
}
