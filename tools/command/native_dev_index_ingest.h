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

/* Resolve ~/.local/state/zclassic23/index/index.db (ZCL_INDEX_STATE_DIR
 * overrides the zclassic23 root the same way every sibling evidence-ledger
 * path does). Creates the `index` directory if absent; never creates or
 * opens the database file itself. */
bool dev_index_db_path(char *out, size_t cap);

/* Open (creating if absent) the index database and its schema: `rows`,
 * `cursors`, and the `rows_fts` FTS5 virtual table. err receives a message
 * on failure; *out_db is NULL on failure. */
bool dev_index_db_open(sqlite3 **out_db, char *err, size_t err_cap);
void dev_index_db_close(sqlite3 *db);

struct dev_index_ingest_result {
    const char *source_id;
    int64_t files_seen;
    int64_t rows_added;
};

/* Ingest every currently-named file of one source: read each file from its
 * saved cursor (0 for a never-seen or rotated/shrunk file) to EOF, stopping
 * at the last complete line, insert one `rows` + `rows_fts` row per line,
 * and advance the cursor to the byte offset actually consumed. A source
 * naming no files yet is success with rows_added=0. */
bool dev_index_ingest_source(sqlite3 *db, const struct dev_index_source *src,
                             struct dev_index_ingest_result *result,
                             char *err, size_t err_cap);

struct dev_index_source_status {
    const char *source_id;
    int64_t rows;
    char newest_ts[32];
    bool has_rows;
    int64_t seconds_since_newest; /* only meaningful when has_rows */
    int64_t bytes_behind;         /* sum of (current size - cursor offset) */
};

/* now_wall_ms: the caller's clock read (platform/clock.h clock_now_wall_ms),
 * passed in rather than read here so the handler owns the one clock read
 * and a test can inject it. */
bool dev_index_source_status(sqlite3 *db, const struct dev_index_source *src,
                             int64_t now_wall_ms,
                             struct dev_index_source_status *out, char *err,
                             size_t err_cap);

#endif /* ZCL_NATIVE_DEV_INDEX_INGEST_H */
