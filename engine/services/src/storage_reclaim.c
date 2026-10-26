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

/* Build "<datadir>/<name>" into path, but only for a name that ends in
 * ".tmp". Returns false when the name has no .tmp suffix or the joined path
 * would not fit path_size (snprintf truncation rules apply). */
static bool format_tmp_entry_path(const char *datadir, const char *name,
                                  char *path, size_t path_size)
{
    size_t n = strlen(name);
    if (n < 4 || strcmp(name + n - 4, ".tmp") != 0)
        return false;
    int pn = snprintf(path, path_size, "%s/%s", datadir, name);
    return pn > 0 && pn < (int)path_size;
}

/* Open name beneath datadir (no symlink escape) and snapshot the file it
 * resolved to. Returns false when either step fails; the handle is closed on
 * both paths and *out is filled only on success. */
static bool snapshot_file_beneath(const char *datadir, const char *name,
                                  struct platform_positioned_file_snapshot *out)
{
    struct platform_positioned_file inspected;
    platform_positioned_file_init(&inspected);
    if (!platform_positioned_file_open_beneath(&inspected, datadir, name) ||
        !platform_positioned_file_snapshot(&inspected, out)) {
        platform_positioned_file_close(&inspected);
        return false;
    }
    platform_positioned_file_close(&inspected);
    return true;
}

/* True when the snapshot's mtime is in the future or younger than the
 * min-age guard. */
static bool tmp_snapshot_is_young(
    const struct platform_positioned_file_snapshot *snapshot, time_t now)
{
    int64_t now_seconds = (int64_t)now;
    uint64_t age = (uint64_t)now_seconds -
                   (uint64_t)snapshot->modified_seconds;
    return snapshot->modified_seconds > now_seconds ||
           age < STORAGE_RECLAIM_TMP_MIN_AGE_SECS;
}

/* True when the snapshot's size cannot be narrowed to int64_t or its file
 * identity cannot be carried in the 32-bit file_low field alone. */
static bool tmp_snapshot_size_or_id_overflows(
    const struct platform_positioned_file_snapshot *snapshot)
{
    return snapshot->size > INT64_MAX || snapshot->file_high != 0;
}

/* Retire (unlink) path only if it still is the exact file the snapshot saw:
 * open it locked, compare volume/file identity, then close. */
static bool retire_tmp_if_identity_matches(
    const char *path, const struct platform_positioned_file_snapshot *snapshot)
{
    struct platform_private_file candidate;
    struct platform_private_file_identity expected = {
        .volume = snapshot->volume,
        .file = snapshot->file_low,
    };
    platform_private_file_init(&candidate);
    bool deleted = platform_private_file_open_locked(path, &candidate) &&
        platform_private_file_retire_if_identity(&candidate, path, &expected);
    platform_private_file_close(&candidate);
    return deleted;
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
        char path[2048];
        if (!format_tmp_entry_path(datadir, name, path, sizeof(path)))
            continue;
        struct platform_positioned_file_snapshot snapshot;
        if (!snapshot_file_beneath(datadir, name, &snapshot))
            continue;
        if (tmp_snapshot_is_young(&snapshot, now))
            continue; /* young: may be an in-flight atomic write — leave it */
        if (tmp_snapshot_size_or_id_overflows(&snapshot))
            continue;
        if (retire_tmp_if_identity_matches(path, &snapshot)) {
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
