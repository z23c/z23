/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Opt-in pre-migration backup for a BREAKING schema step.
 *
 * node.db can be tens of gigabytes; an operator cannot casually copy it
 * before every upgrade "just in case" (that is the whole reason a newer
 * binary opening an older database needs a read-compatible path at all —
 * see database_migrate.c). -db-backup-before-migrate is the opposite
 * choice for the one upgrade an operator judges worth the wait and the
 * disk: it is default OFF for exactly the reason it exists, since the copy
 * this makes is the same size as the database itself.
 *
 * ar-validate-skip:connection-handle-not-a-row
 *   Operates on the struct node_db connection handle and the raw sqlite3*
 *   database file, not a row record (same rationale as database_migrate.c).
 */

#include "util/log_macros.h"
#include "models/database.h"
#include "models/database_internal.h"
#include "platform/disk_space.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* A fixed slack beyond the source file's own size. The destination file
 * SQLite writes back is at minimum the source's page count, but the backup
 * API also has to create and grow that destination file from scratch on
 * this same filesystem, so a flat margin is simpler and more conservative
 * than trying to model page-level overhead exactly. */
#define NODE_DB_BACKUP_FREE_SPACE_MARGIN_BYTES ((uint64_t)64 * 1024 * 1024)

static int64_t g_free_bytes_override_for_test = -1;

void node_db_backup_set_free_bytes_override_for_test(int64_t bytes)
{
    g_free_bytes_override_for_test = bytes;
}

static bool backup_has_room(uint64_t available_bytes, uint64_t db_size_bytes)
{
    uint64_t margin = NODE_DB_BACKUP_FREE_SPACE_MARGIN_BYTES;
    if (db_size_bytes > UINT64_MAX - margin)
        return false; // raw-return-ok:overflow-guard-treat-as-no-room
    return available_bytes >= db_size_bytes + margin;
}

/* Refuses (LOG_FAIL -> false) unless at least a database-size-plus-margin
 * of free space sits beside ndb->path. Kept in its own function so that
 * node_db_backup_before_breaking_migration()'s own cyclomatic complexity
 * stays low: every branch here is the space-refusal path, none of it is
 * the actual copy. */
static bool backup_check_space(struct node_db *ndb, int old_schema_version,
                                uint64_t *out_db_size)
{
    struct stat st;
    if (stat(ndb->path, &st) != 0)
        LOG_FAIL("db", "migrate: backup: cannot stat %s before schema v%d",
                 ndb->path, old_schema_version);
    uint64_t db_size = (uint64_t)st.st_size;

    uint64_t available = 0;
    if (g_free_bytes_override_for_test >= 0) {
        available = (uint64_t)g_free_bytes_override_for_test;
    } else if (!platform_disk_space_available(ndb->path, &available)) {
        LOG_FAIL("db", "migrate: backup: free-space query failed for %s",
                 ndb->path);
    }

    if (!backup_has_room(available, db_size))
        LOG_FAIL("db",
            "migrate: refusing to apply the breaking schema step above "
            "v%d — pre-migration backup needs %llu bytes free beside %s "
            "(database size + margin) but only %llu are available; free "
            "space, or drop -db-backup-before-migrate to proceed unbacked",
            old_schema_version,
            (unsigned long long)(db_size +
                NODE_DB_BACKUP_FREE_SPACE_MARGIN_BYTES),
            ndb->path, (unsigned long long)available);

    *out_db_size = db_size;
    return true;
}

/* Copies ndb's live database onto a TEMPORARY sibling file via SQLite's
 * online backup API, then renames it into place only once the copy is
 * verified complete — so a reader never observes a partially written
 * "<path>.schema<N>.bak" left by a crash or a failed copy mid-step. */
static bool backup_copy_to_tmp_and_rename(struct node_db *ndb,
                                          const char *bak_path,
                                          const char *tmp_path)
{
    sqlite3 *dest = NULL;
    if (sqlite3_open(tmp_path, &dest) != SQLITE_OK) {
        const char *errmsg = dest ? sqlite3_errmsg(dest) : "sqlite3_open failed";
        LOG_WARN("db", "migrate: backup: could not create %s: %s", tmp_path,
                 errmsg);
        if (dest)
            sqlite3_close(dest);
        (void)remove(tmp_path);
        return false;
    }

    sqlite3_backup *backup =
        sqlite3_backup_init(dest, "main", ndb->db, "main");
    if (!backup) {
        LOG_WARN("db", "migrate: backup: sqlite3_backup_init failed for "
                 "%s: %s", tmp_path, sqlite3_errmsg(dest));
        sqlite3_close(dest);
        (void)remove(tmp_path);
        return false;
    }

    int step_rc;
    do {
        step_rc = sqlite3_backup_step(backup, 256);
    } while (step_rc == SQLITE_OK);
    int finish_rc = sqlite3_backup_finish(backup);
    sqlite3_close(dest);

    if (step_rc != SQLITE_DONE) {
        LOG_WARN("db", "migrate: backup: copy of %s to %s failed (rc=%d)",
                 ndb->path, tmp_path, step_rc);
        (void)remove(tmp_path);
        return false;
    }
    if (finish_rc != SQLITE_OK) {
        LOG_WARN("db", "migrate: backup: finish failed for %s (rc=%d)",
                 tmp_path, finish_rc);
        (void)remove(tmp_path);
        return false;
    }
    if (rename(tmp_path, bak_path) != 0) {
        LOG_WARN("db", "migrate: backup: rename %s -> %s failed",
                 tmp_path, bak_path);
        (void)remove(tmp_path);
        return false;
    }
    return true;
}

bool node_db_backup_before_breaking_migration(struct node_db *ndb,
                                              int old_schema_version)
{
    /* LOG_FAIL (not LOG_ERR) below: LOG_ERR's own `return -1;` is meant for
     * int-returning callers and would come back through this bool-returning
     * function as a truthy `true`, silently inverting every refusal into a
     * permit. LOG_FAIL logs the same way and returns `false`. */
    if (!ndb || !ndb->open)
        LOG_FAIL("db", "migrate: backup requested against a closed handle");

    const char *flag = getenv("ZCL_DB_BACKUP_BEFORE_MIGRATE");
    if (!flag || strcmp(flag, "1") != 0)
        return true; /* opt-in feature, not requested: no-op success */

    uint64_t db_size = 0;
    if (!backup_check_space(ndb, old_schema_version, &db_size))
        return false; // raw-return-ok:backup_check_space-already-logged-via-log_fail

    char bak_path[1200];
    int n = snprintf(bak_path, sizeof(bak_path), "%s.schema%d.bak",
                     ndb->path, old_schema_version);
    if (n <= 0 || (size_t)n >= sizeof(bak_path))
        LOG_FAIL("db", "migrate: backup: path too long for %s", ndb->path);

    char tmp_path[1216];
    n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", bak_path);
    if (n <= 0 || (size_t)n >= sizeof(tmp_path))
        LOG_FAIL("db", "migrate: backup: temp path too long for %s",
                 ndb->path);
    (void)remove(tmp_path); /* clear any stale temp from a prior crash */

    if (!backup_copy_to_tmp_and_rename(ndb, bak_path, tmp_path))
        return false; // raw-return-ok:backup_copy_to_tmp_and_rename-already-logged-via-log_warn

    LOG_WARN("db", "migrate: wrote pre-migration backup %s (schema v%d, "
             "%llu bytes) before applying a breaking schema step",
             bak_path, old_schema_version, (unsigned long long)db_size);
    return true;
}
