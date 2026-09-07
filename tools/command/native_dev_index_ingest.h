/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: dev.index sqlite store — schema, open/close, and per-source
 * incremental ingest (tools/command/native_dev_index_ingest.c). */
#ifndef ZCL_NATIVE_DEV_INDEX_INGEST_H
#define ZCL_NATIVE_DEV_INDEX_INGEST_H

#include "command/native_dev_index_catalog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct sqlite3 sqlite3;

/* Resolve index.db's path: `index_override` when non-empty (the CLI's
 * --index=<path>, used verbatim), else <state_root_override or the default
 * zclassic23 root>/index/index.db. No environment variable is consulted —
 * --index and --state-root are the only overrides, and they are independent:
 * --index alone moves the database without touching where sources are read
 * from. `create`: when true, creates the `index` directory if absent (an
 * ingest call); when false (status/search), never touches the filesystem
 * here. */
bool dev_index_db_path(const char *index_override,
                       const char *state_root_override, bool create,
                       char *out, size_t cap);

/* Open the index database. `create`: true opens/creates it (an ingest call,
 * schema is created or migrated as needed); false opens an existing db
 * read-only for status/search and touches nothing on disk otherwise.
 * *out_missing is set true (and *out_db left NULL) when create=false and no
 * index.db exists yet — not an error, the honest "no index yet" case. err
 * receives a message on a real failure; *out_db is NULL on failure. */
bool dev_index_db_open(bool create, const char *index_override,
                       const char *state_root_override, sqlite3 **out_db,
                       bool *out_missing, char *err, size_t err_cap);
void dev_index_db_close(sqlite3 *db);

struct dev_index_ingest_result {
    const char *source_id;
    int64_t files_seen;
    int64_t rows_added;
    int64_t rows_skipped; /* lines that failed to parse this run, not fatal */
};

/* Ingest every currently-named file of one source: read each file from its
 * saved cursor (0 for a never-seen file, or one whose prefix hash no longer
 * matches what was last ingested — see docs/INDEX.md's rename/rewrite
 * section) to EOF, stopping at the last complete line, insert one `rows` +
 * `rows_fts` row per new line (identical (source_id, row content) rows
 * already present are silently ignored, never duplicated), and advance the
 * cursor. A source naming no files yet is success with rows_added=0. */
bool dev_index_ingest_source(sqlite3 *db, const struct dev_index_source *src,
                             const char *state_root_override,
                             struct dev_index_ingest_result *result,
                             char *err, size_t err_cap);

struct dev_index_source_status {
    const char *source_id;
    int64_t rows;
    char newest_ts[32];
    bool has_rows;
    int64_t seconds_since_newest; /* only meaningful when has_rows */
    int64_t bytes_behind;         /* sum of (current size - cursor offset) */
    int64_t rows_skipped;         /* cumulative unparseable lines, all files */
};

/* now_wall_ms: the caller's clock read (platform/clock.h clock_now_wall_ms),
 * passed in rather than read here so the handler owns the one clock read
 * and a test can inject it. */
bool dev_index_source_status(sqlite3 *db, const struct dev_index_source *src,
                             const char *state_root_override,
                             int64_t now_wall_ms,
                             struct dev_index_source_status *out, char *err,
                             size_t err_cap);

#endif /* ZCL_NATIVE_DEV_INDEX_INGEST_H */
