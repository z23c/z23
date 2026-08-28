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
#include "controllers/snapshot_controller.h"
#include "snapshot_controller_internal.h"
#include "config/file_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
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

static void rotate_snapshots(const char *snapshots_dir, int max_keep)
{
    struct dirent **entries;
    int n = scandir(snapshots_dir, &entries, NULL, alphasort);
    if (n < 0) return;

    /* Count real snapshot dirs (YYYYMMDD_HHMMSS format) */
    int count = 0;
    for (int i = 0; i < n; i++) {
        if (entries[i]->d_name[0] != '.' && strlen(entries[i]->d_name) == 15)
            count++;
    }

    /* Remove oldest if over limit */
    int to_remove = count - max_keep;
    if (to_remove > 0) {
        for (int i = 0; i < n && to_remove > 0; i++) {
            if (entries[i]->d_name[0] == '.' ||
                strlen(entries[i]->d_name) != 15)
                continue;
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s",
                     snapshots_dir, entries[i]->d_name);
            printf("snapshot: removing old snapshot %s\n",
                   entries[i]->d_name);
            dir_remove_tree(path);
            to_remove--;
        }
    }

    for (int i = 0; i < n; i++) free(entries[i]);
    free(entries);
}

const char *snapshot_create(const char *legacy_datadir,
                            const char *c23_datadir,
                            int max_keep)
{
    if (max_keep < 1) max_keep = 2;

    /* Create snapshots directory */
    char snapshots_dir[2048];
    snprintf(snapshots_dir, sizeof(snapshots_dir),
             "%s/snapshots", c23_datadir);
    mkdir(snapshots_dir, 0700);

    /* Rotate old snapshots first */
    rotate_snapshots(snapshots_dir, max_keep);

    /* Create timestamped snapshot dir */
    time_t now = platform_time_wall_time_t();
    struct tm *tm = localtime(&now);
    static char snap_dir[2048];
    char ts[16];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm);
    snprintf(snap_dir, sizeof(snap_dir), "%s/%s", snapshots_dir, ts);
    mkdir(snap_dir, 0700);

    struct timespec t0;
    platform_time_monotonic_timespec(&t0);

    /* Hard-link block files (instant — same filesystem) */
    char src[2048], dst[2048];
    snprintf(dst, sizeof(dst), "%s/blocks", snap_dir);
    mkdir(dst, 0700);

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
    printf("snapshot: created %s in %.1fs\n", ts, elapsed);
    fflush(stdout);

    return snap_dir;
}
