/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: dev.index FTS5 search over the rows/rows_fts tables
 * (tools/command/native_dev_index_search.c). */
#ifndef ZCL_NATIVE_DEV_INDEX_SEARCH_H
#define ZCL_NATIVE_DEV_INDEX_SEARCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct sqlite3 sqlite3;

#define DEV_INDEX_SEARCH_MAX_HITS 50u
#define DEV_INDEX_SEARCH_DEFAULT_LIMIT 20u

struct dev_index_search_hit {
    char source_id[64];
    char ts[32];
    char text[512];
};

struct dev_index_search_result {
    struct dev_index_search_hit hits[DEV_INDEX_SEARCH_MAX_HITS];
    size_t count;
};

/* query is passed to FTS5 MATCH as given (so a bare word searches OR/AND
 * per FTS5 default, and "key:value" hits the flattened kv term literally
 * because rows_fts is tokenized with tokenchars=':'). source_id_filter may
 * be NULL/empty for no filter. limit is clamped to
 * [1, DEV_INDEX_SEARCH_MAX_HITS]. Returns false only on a database error
 * (a malformed MATCH query is reported through err, not a crash). */
bool dev_index_search(sqlite3 *db, const char *query,
                      const char *source_id_filter, size_t limit,
                      struct dev_index_search_result *out, char *err,
                      size_t err_cap);

#endif /* ZCL_NATIVE_DEV_INDEX_SEARCH_H */
