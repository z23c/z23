/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the codeindex store's private cross-TU contract — the definition
 * of `struct ci_store`, the handle whose fields the write half and the read
 * half and identity reads dereference.
 *
 * codeindex_store.c owns the WRITE half: the row hash, pragmas + schema,
 * open/close, the canonical-generation binding, transaction control, and
 * every `ci_store_put_*`. codeindex_store_read.c owns the READ half: every
 * query that steps rows back out (`ci_store_meta_get`, the symbol/ref/file/
 * group lookups, and the include-edge count). The split happened when the
 * combined file passed the 800-line shape ceiling; the handle layout is all
 * and checked read cleanup cross that seam; only the store, store-read, and
 * store-identity translation units may include this header. The handle stays
 * OPAQUE to the rest of cognition/modules/codeindex, which reaches it through the
 * ci_store_db()/ci_store_lock()/ci_store_unlock() accessors in
 * codeindex_priv.h.
 */

#ifndef ZCL_CODEINDEX_STORE_INTERNAL_H
#define ZCL_CODEINDEX_STORE_INTERNAL_H

#include "codeindex_priv.h"
#include "platform/positioned_file.h"
#include "platform/read_mapping.h"

#include <pthread.h>
#include <stdbool.h>

struct ci_store {
    sqlite3        *db;
    sqlite3_stmt   *put_file_stmt;   /* reused only inside a write transaction */
    sqlite3_stmt   *put_symbol_stmt; /* finalized before COMMIT or ROLLBACK */
    sqlite3_stmt   *put_include_stmt; /* reused only inside a write transaction */
    sqlite3_stmt   *put_ref_stmt;    /* finalized before COMMIT or ROLLBACK */
    sqlite3_stmt   *include_page_stmt; /* reset and cleared after each read */
    sqlite3_stmt   *defs_by_name_stmt; /* reset and cleared after each read */
    sqlite3_stmt   *refs_by_enclosing_stmt; /* reset and cleared after each read */
    sqlite3_stmt   *refs_by_callee_stmt;
    sqlite3_stmt   *refs_by_callee_file_stmt;
    sqlite3_stmt   *refs_by_enclosing_file_stmt;
    sqlite3_stmt   *symbol_by_name_stmt;
    sqlite3_stmt   *symbol_by_name_path_stmt;
    pthread_mutex_t lock;   /* recursive: held begin..commit; reads take briefly */
    int             bound_fd; /* immutable canonical inode, -1 for :memory: */
    struct platform_positioned_file bound_file;
    struct platform_read_mapping mapping;
    bool            has_bound_file;
    bool            readonly;
};

int ci_store_read_finish(sqlite3_stmt **slot, bool complete);

#endif /* ZCL_CODEINDEX_STORE_INTERNAL_H */
