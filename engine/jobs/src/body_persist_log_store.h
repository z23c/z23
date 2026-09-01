/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_persist_log_store — durable body_persist_log schema + read/write
 * helpers, split out of body_persist_stage.c to keep that file under the
 * framework file-size ceiling. Pure sqlite kernel helpers: they take a
 * sqlite3 handle and touch no body_persist module state. */

#ifndef ZCL_JOBS_BODY_PERSIST_LOG_STORE_H
#define ZCL_JOBS_BODY_PERSIST_LOG_STORE_H

#include <stdbool.h>

struct sqlite3;

/* One upstream body_fetch_log row (source + ok-flag) at a given height. */
struct body_fetch_row {
    int ok;
    char source[64];
};

bool body_persist_log_ensure_schema(struct sqlite3 *db);

/* Read the upstream body_fetch_log {source, ok} at `height`. Returns 1 if a
 * row was found, 0 if not, -1 on a query error. */
int body_persist_body_fetch_log_at(struct sqlite3 *db, int height,
                                   struct body_fetch_row *out);

bool body_persist_log_insert(struct sqlite3 *db, int height,
                             const char *source, bool ok);

/* Finalize the thread-local per-batch cached statements. Call at each stage
 * drain-batch boundary (after COMMIT or ROLLBACK) and at shutdown, so no
 * statement outlives its batch generation. */
void body_persist_log_store_batch_reset(void);

#endif /* ZCL_JOBS_BODY_PERSIST_LOG_STORE_H */
