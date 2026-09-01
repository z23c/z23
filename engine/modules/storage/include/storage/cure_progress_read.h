/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read-only progress.kv probes for the offline sovereign-cure status packet. */

#ifndef ZCL_STORAGE_CURE_PROGRESS_READ_H
#define ZCL_STORAGE_CURE_PROGRESS_READ_H

#include <stdint.h>

struct sqlite3;

struct cure_progress_sample {
    int64_t height;
    int64_t time_unix;
};

struct cure_body_persist_row {
    char source[64];
};

/* Return 1 for two monotonic successful utxo_apply samples separated by at
 * least min_window_seconds, 0 when durable evidence is insufficient, -1 on a
 * read/schema error. Never writes or creates schema. */
int cure_progress_read_eta_samples(
    struct sqlite3 *db, int64_t min_window_seconds,
    struct cure_progress_sample *older, struct cure_progress_sample *newer);

/* Return 1 when body_persist_log contains height, 0 when absent, -1 on a
 * read/schema error. Never writes or creates schema. */
int cure_progress_read_body_persist(
    struct sqlite3 *db, int64_t height, struct cure_body_persist_row *out);

#endif /* ZCL_STORAGE_CURE_PROGRESS_READ_H */
