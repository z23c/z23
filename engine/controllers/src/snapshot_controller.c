/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Snapshot-based import from legacy C++ ZClassic node.
 *
 * Creates timestamped snapshots of the C++ data dir using hard links
 * (instant for block files) and clean LevelDB copies. The import that
 * consumes these snapshots is a parallel LevelDB-to-SQLite bulk import
 * (~1-2 minutes).
 *
 * This file holds the snapshot directory management + snapshot_create,
 * plus the shared SQLite transaction helpers used by every snapshot
 * worker thread. The siblings:
 *
 *   snapshot_controller_import.c   — parallel LevelDB→SQLite import
 *   snapshot_controller_txindex.c  — background tx-index builder
 *
 * See snapshot_controller_internal.h for cross-sibling declarations. */

#pragma GCC diagnostic ignored "-Wformat-truncation"
#include "platform/time_compat.h"
#include "platform/directory_compat.h"
#include "controllers/snapshot_controller.h"
#include "snapshot_controller_internal.h"
#include "config/file_ops.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "util/log_macros.h"

/* ZCL_MAGIC used in legacy_import.c, not needed here. */

/* ── Shared SQLite transaction helpers (declared in
 * snapshot_controller_internal.h, used by the import and tx-index
 * siblings) ── */

bool snapshot_sql_exec_checked(struct node_db *ndb,
                               const char *sql,
                               const char *label)
{
    if (!ndb || !ndb->open || !sql) {
        LOG_FAIL("snapshot", "sql_exec_checked: ndb=%p open=%d sql=%p",
                (void *)ndb, ndb ? ndb->open : 0, (void *)sql);
    }
    if (!node_db_exec(ndb, sql)) {
        LOG_FAIL("snapshot", "snapshot: %s failed: %s",
                label, ndb->db ? sqlite3_errmsg(ndb->db)
                               : "db unavailable");
    }
    return true;
}

bool snapshot_tx_begin_checked(struct node_db *ndb,
                               const char *label)
{
    if (!ndb || !ndb->open || !node_db_begin(ndb)) {
        LOG_FAIL("snapshot", "snapshot: %s failed: %s",
                label, (ndb && ndb->db) ? sqlite3_errmsg(ndb->db)
                                        : "db unavailable");
    }
    return true;
}

bool snapshot_tx_commit_checked(struct node_db *ndb,
                                const char *label)
{
    if (!ndb || !ndb->open || !node_db_commit(ndb)) {
        LOG_FAIL("snapshot", "snapshot: %s failed: %s",
                label, (ndb && ndb->db) ? sqlite3_errmsg(ndb->db)
                                        : "db unavailable");
    }
    return true;
}

void snapshot_tx_rollback_best_effort(struct node_db *ndb,
                                      const char *label)
{
    if (!ndb || !ndb->open)
        return;
    if (!node_db_rollback(ndb)) {
        LOG_WARN("snapshot", "snapshot: %s failed: %s", label, ndb->db ? sqlite3_errmsg(ndb->db) : "db unavailable");
    }
}

/* ---- Snapshot directory management ---- */

static bool snapshot_name_valid(const char *name)
{
    if (!name || strlen(name) != 15 || name[8] != '_') return false;
    for (size_t i = 0; i < 15; ++i) {
        if (i == 8) continue;
        if (name[i] < '0' || name[i] > '9') return false;
    }
    return true;
}

static void rotate_snapshots(const char *snapshots_dir, int max_keep, const char *current)
{
    struct platform_directory_list list;
    if (!platform_directory_list_real_sorted(snapshots_dir, &list)) return;

    /* Count real snapshot dirs (YYYYMMDD_HHMMSS format) */
    int count = 0;
    for (size_t i = 0; i < list.count; i++) {
        if (snapshot_name_valid(list.entries[i].name) && strcmp(list.entries[i].name, current) != 0)
            count++;
    }

    /* Remove oldest if over limit */
    int to_remove = count - max_keep;
    if (to_remove > 0) {
        for (size_t i = 0; i < list.count && to_remove > 0; i++) {
            if (!snapshot_name_valid(list.entries[i].name) || strcmp(list.entries[i].name, current) == 0)
                continue;
            char path[1024];
            int path_len = snprintf(path, sizeof(path), "%s/%s",
                                    snapshots_dir, list.entries[i].name);
            if (path_len <= 0 || (size_t)path_len >= sizeof(path))
                continue;
            printf("snapshot: removing old snapshot %s\n",
                   list.entries[i].name);
            dir_remove_tree(path);
            to_remove--;
        }
    }

    platform_directory_list_free(&list);
}

static const char *snapshot_claim_directory(const char *legacy_datadir,
                                            const char *c23_datadir,
                                            char snapshots_dir[2048], char ts[16])
{
    if (!legacy_datadir || !c23_datadir ||
        strlen(legacy_datadir) + sizeof("/blocks/index") > 2048)
        return NULL;

    int len = snprintf(snapshots_dir, 2048,
                       "%s/snapshots", c23_datadir);
    if (len < 0 || (size_t)len >= 2048) return NULL;
    /* Reserve room for the timestamp and longest suffix used below. */
    if ((size_t)len + 1 + 15 + sizeof("/blocks/index") > 2048) return NULL;
    if (!platform_directory_ensure(snapshots_dir, 0700)) return NULL;

    /* Create timestamped snapshot dir */
    time_t now = platform_time_wall_time_t();
    struct tm *tm = localtime(&now);
    static char snap_dir[2048];
    if (!tm || strftime(ts, 16, "%Y%m%d_%H%M%S", tm) != 15) return NULL;
    len = snprintf(snap_dir, sizeof(snap_dir), "%s/%s", snapshots_dir, ts);
    if (len < 0 || (size_t)len >= sizeof(snap_dir)) return NULL;
    if (platform_directory_create(snap_dir, 0700) != 0) {
        int error = errno;
        if (error == EEXIST)
            LOG_WARN("snapshot", "snapshot: %s already exists; keep it and retry with a new timestamp", snap_dir);
        else
            LOG_WARN("snapshot", "snapshot: cannot create directory %s: %s", snap_dir, strerror(error));
        return NULL;
    }
    return snap_dir;
}

const char *snapshot_create(const char *legacy_datadir,
                            const char *c23_datadir,
                            int max_keep)
{
    if (max_keep < 1) max_keep = 2;
    char snapshots_dir[2048], ts[16];
    const char *snap_dir = snapshot_claim_directory(legacy_datadir, c23_datadir,
                                                    snapshots_dir, ts);
    if (!snap_dir) return NULL;

    struct timespec t0;
    platform_time_monotonic_timespec(&t0);

    /* Hard-link block files (instant — same filesystem) */
    char src[2048], dst[2048];
    snprintf(dst, sizeof(dst), "%s/blocks", snap_dir);
    if (!platform_directory_ensure(dst, 0700)) {
        dir_remove_tree(snap_dir);
        return NULL;
    }

    printf("snapshot: copying block files...\n");
    fflush(stdout);
    snprintf(src, sizeof(src), "%s/blocks", legacy_datadir);
    snprintf(dst, sizeof(dst), "%s/blocks", snap_dir);
    int copied = block_files_copy(src, dst);
    if (copied < 0) {
        LOG_WARN("snapshot", "snapshot: block file copy failed from %s to %s", src, dst);
        dir_remove_tree(snap_dir);
        return NULL;
    }
    if (copied == 0) {
        LOG_WARN("snapshot", "snapshot: failed to copy block files from %s to %s", src, dst);
        dir_remove_tree(snap_dir);
        return NULL;
    }
    printf("snapshot: %d block files copied\n", copied);

    /* Copy block index LevelDB */
    printf("snapshot: copying blocks/index...\n");
    fflush(stdout);
    snprintf(src, sizeof(src), "%s/blocks/index", legacy_datadir);
    snprintf(dst, sizeof(dst), "%s/blocks/index", snap_dir);
    if (!dir_copy(src, dst)) {
        LOG_WARN("snapshot", "snapshot: failed to copy block index from %s to %s", src, dst);
        dir_remove_tree(snap_dir);
        return NULL;
    }
    printf(" done\n");

    /* Copy chainstate LevelDB */
    printf("snapshot: copying chainstate...\n");
    fflush(stdout);
    snprintf(src, sizeof(src), "%s/chainstate", legacy_datadir);
    snprintf(dst, sizeof(dst), "%s/chainstate", snap_dir);
    if (!dir_copy(src, dst)) {
        LOG_WARN("snapshot", "snapshot: failed to copy chainstate from %s to %s", src, dst);
        dir_remove_tree(snap_dir);
        return NULL;
    }
    printf(" done\n");

    struct timespec t1;
    platform_time_monotonic_timespec(&t1);
    double elapsed = (double)(t1.tv_sec - t0.tv_sec) +
                     (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    rotate_snapshots(snapshots_dir, max_keep, ts);
    printf("snapshot: created %s in %.1fs\n", ts, elapsed);
    fflush(stdout);

    return snap_dir;
}
