/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Existing-file node.db schema preflight.  This unit has one job: classify an
 * on-disk database before the normal READWRITE|CREATE open is allowed to run.
 * It never creates, journals, checkpoints, migrates, quarantines or renames.
 *
 * ar-validate-skip:connection-schema-classifier-not-a-row
 *   This file classifies a database connection before any model row exists.
 *   Row validation remains owned by the models using the admitted handle.
 */

#include "models/database_internal.h"
#include "platform/fd_path.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "platform/fd_path.h"

#define NODE_DB_PREFLIGHT_URI_MAX 128

struct preflight_sidecars {
    bool wal;
    bool shm;
    off_t wal_size;
};

static struct node_db_schema_preflight preflight_result(
    enum node_db_schema_preflight_state state, int32_t version,
    const char *detail)
{
    return (struct node_db_schema_preflight) {
        .state = state,
        .version = version,
        .detail = detail,
    };
}

static bool read_header(int fd, unsigned char header[20])
{
    size_t off = 0;
    while (off < 20) {
        ssize_t n = pread(fd, header + off, 20 - off, (off_t)off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        return false;
    }
    return memcmp(header, "SQLite format 3", 16) == 0;
}

static bool probe_one_sidecar(const char *path, const char *suffix,
                              bool *present, off_t *size_out)
{
    char side[1400];
    int n = snprintf(side, sizeof(side), "%s%s", path, suffix);
    if (n <= 0 || (size_t)n >= sizeof(side))
        return false;
    struct stat st;
    if (stat(side, &st) == 0) {
        if (!S_ISREG(st.st_mode))
            return false; // raw-return-ok:nonregular-sidecar-is-unknown
        *present = true;
        if (size_out)
            *size_out = st.st_size;
        return true;
    }
    if (errno != ENOENT)
        return false;
    *present = false;
    if (size_out)
        *size_out = -1;
    return true;
}

static bool probe_sidecars(const char *path, struct preflight_sidecars *out)
{
    memset(out, 0, sizeof(*out));
    out->wal_size = -1;
    return probe_one_sidecar(path, "-wal", &out->wal, &out->wal_size) &&
           probe_one_sidecar(path, "-shm", &out->shm, NULL);
}

/* A cleanly closed WAL database retains header byte 18 == 2 but has no
 * wal-index. Plain SQLITE_OPEN_READONLY would create -wal/-shm in that state.
 * Bind immutable SQLite to the already-open inode through the platform's
 * magic fd-reopen path instead; this cannot follow a later path replacement
 * and deliberately ignores sidecars. The caller only selects it when no
 * non-empty WAL and no SHM exists. */
static int open_quiet_wal_immutable(int fd, sqlite3 **db_out)
{
    char fd_path[64];
    char uri[NODE_DB_PREFLIGHT_URI_MAX];
    if (!platform_fd_path(fd_path, sizeof(fd_path), fd, NULL))
        return SQLITE_CANTOPEN;
    int n = snprintf(uri, sizeof(uri), "file:%s?mode=ro&immutable=1",
                     fd_path);
    if (n <= 0 || (size_t)n >= sizeof(uri))
        return SQLITE_CANTOPEN;
    return sqlite3_open_v2(uri, db_out,
                           SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX |
                           SQLITE_OPEN_URI,
                           NULL);
}

static int count_tables(sqlite3 *db, int *count_out)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT count(*) FROM sqlite_master WHERE type='table'",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        rc = sqlite3_step(stmt); // raw-sql-ok:read-only-schema-preflight
        if (rc == SQLITE_ROW) {
            *count_out = sqlite3_column_int(stmt, 0);
            rc = SQLITE_OK;
        }
    }
    sqlite3_finalize(stmt);
    return rc;
}

static int table_exists(sqlite3 *db, const char *name, bool *exists_out)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt)
        rc = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt); // raw-sql-ok:read-only-schema-preflight
        if (rc == SQLITE_ROW) {
            *exists_out = sqlite3_column_int(stmt, 0) == 1;
            rc = SQLITE_OK;
        }
    }
    sqlite3_finalize(stmt);
    return rc;
}

static bool parse_migration_version(const unsigned char *text, int bytes,
                                    int *version_out)
{
    if (!text || bytes <= 0 || bytes > 10)
        return false;
    char buf[12];
    memcpy(buf, text, (size_t)bytes);
    buf[bytes] = '\0';
    for (int i = 0; i < bytes; i++) {
        if (buf[i] < '0' || buf[i] > '9')
            return false;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(buf, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value < 0 || value > INT_MAX)
        return false;
    *version_out = (int)value;
    return true;
}

static bool migration_ledger_consistent(sqlite3 *db, int32_t marker,
                                        const char **detail_out)
{
    bool present = false;
    if (table_exists(db, "schema_migrations", &present) != SQLITE_OK) {
        *detail_out = "SCHEMA_VERSION_UNKNOWN: cannot inspect migration ledger";
        return false;
    }
    if (!present)
        return true;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT version FROM schema_migrations", -1, &stmt, NULL);
    if (rc != SQLITE_OK || !stmt) {
        sqlite3_finalize(stmt);
        *detail_out = "SCHEMA_VERSION_UNKNOWN: migration ledger unreadable";
        return false;
    }
    bool ok = true;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) { // raw-sql-ok:read-only-schema-preflight
        int version = 0;
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        int bytes = sqlite3_column_bytes(stmt, 0);
        if (sqlite3_column_type(stmt, 0) != SQLITE_TEXT ||
            !parse_migration_version(text, bytes, &version)) {
            *detail_out = "SCHEMA_VERSION_UNKNOWN: malformed migration ledger";
            ok = false;
            break;
        }
        if (version > marker) {
            *detail_out = "SCHEMA_VERSION_UNKNOWN: marker contradicts migration ledger";
            ok = false;
            break;
        }
    }
    if (ok && rc != SQLITE_DONE) {
        *detail_out = "SCHEMA_VERSION_UNKNOWN: migration ledger read failed";
        ok = false;
    }
    sqlite3_finalize(stmt);
    return ok;
}

static struct node_db_schema_preflight inspect_schema(sqlite3 *db)
{
    int tables = 0;
    if (count_tables(db, &tables) != SQLITE_OK)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: SQLite schema is unreadable");
    if (tables == 0)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_FRESH, 0,
            "empty SQLite database");

    bool node_state = false;
    if (table_exists(db, "node_state", &node_state) != SQLITE_OK)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: cannot inspect node_state");
    if (!node_state)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: recognized tables exist without node_state");

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT value FROM node_state WHERE key='schema_version'",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK || !stmt) {
        sqlite3_finalize(stmt);
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: schema marker is unreadable");
    }

    int rows = 0;
    int32_t version = 0;
    bool malformed = false;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) { // raw-sql-ok:read-only-schema-preflight
        rows++;
        if (rows != 1 || sqlite3_column_type(stmt, 0) != SQLITE_BLOB ||
            sqlite3_column_bytes(stmt, 0) != (int)sizeof(version) ||
            !sqlite3_column_blob(stmt, 0)) {
            malformed = true;
            continue;
        }
        memcpy(&version, sqlite3_column_blob(stmt, 0), sizeof(version));
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: schema marker read failed");
    if (rows != 1)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            rows == 0
                ? "SCHEMA_VERSION_UNKNOWN: schema marker missing"
                : "SCHEMA_VERSION_UNKNOWN: contradictory schema markers");
    if (malformed)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: schema marker is not one 4-byte blob");
    if (version <= 0)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, version,
            "SCHEMA_VERSION_UNKNOWN: schema marker is unsupported");
    if (version > NODE_DB_MAX_SCHEMA)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_NEWER, version,
                                "newer schema marker");

    const char *detail = NULL;
    if (!migration_ledger_consistent(db, version, &detail))
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, version,
                                detail);
    return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_SUPPORTED, version,
                            "supported schema marker");
}

struct node_db_schema_preflight node_db_schema_preflight_existing(
    const char *path)
{
    if (!path || path[0] == '\0')
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: database path missing");
    if (strcmp(path, ":memory:") == 0)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_FRESH, 0,
                                "in-memory database");

    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno == ENOENT)
            return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_FRESH, 0,
                                    "database path absent");
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: database path cannot be inspected");
    }
    if (!S_ISREG(st.st_mode))
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: database path is not a regular file");
    if (st.st_size == 0)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_FRESH, 0,
                                "empty database file");

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: database file cannot be read");
    unsigned char header[20] = { 0 };
    if (!read_header(fd, header)) {
        close(fd);
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: invalid or unreadable SQLite header");
    }

    bool wal_mode = header[18] == 2;
    struct preflight_sidecars sidecars;
    if (!probe_sidecars(path, &sidecars)) {
        close(fd);
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: database sidecars cannot be inspected");
    }

    sqlite3 *db = NULL;
    int rc;
    if (wal_mode && !sidecars.shm &&
        (!sidecars.wal || sidecars.wal_size == 0)) {
        rc = open_quiet_wal_immutable(fd, &db);
    } else if (wal_mode && sidecars.wal && sidecars.shm) {
        rc = sqlite3_open_v2(path, &db,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL);
    } else if (wal_mode) {
        close(fd);
        return preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            sidecars.wal && sidecars.wal_size > 0
                ? "SCHEMA_VERSION_UNKNOWN: unrecovered WAL has no wal-index"
                : "SCHEMA_VERSION_UNKNOWN: contradictory WAL sidecars");
    } else {
        rc = sqlite3_open_v2(path, &db,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL);
    }

    struct node_db_schema_preflight out;
    if (rc != SQLITE_OK || !db) {
        out = preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: read-only SQLite open failed");
    } else if (sqlite3_busy_timeout(db, 10000) != SQLITE_OK) {
        out = preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: cannot bound preflight lock wait");
    } else if (sqlite3_exec(db, "PRAGMA query_only=ON", NULL, NULL, NULL) !=
               SQLITE_OK) {
        out = preflight_result(NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN, 0,
            "SCHEMA_VERSION_UNKNOWN: cannot enforce query-only preflight");
    } else {
        out = inspect_schema(db);
    }
    if (db)
        sqlite3_close(db);
    close(fd);
    return out;
}
