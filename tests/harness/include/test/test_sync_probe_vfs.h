/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A SQLite VFS wrapper for tests that must see durability, not just results.
 * It records, in order, the syncs of the database file and of the write-ahead
 * log, and the truncations of the log, and can fail log syncs. A clean close
 * hides all of this: the data is on disk either way. */

#ifndef ZCL_TEST_SYNC_PROBE_VFS_H
#define ZCL_TEST_SYNC_PROBE_VFS_H

#include <stdbool.h>

enum spv_kind {
    SPV_SYNC_DB,    /* xSync on the main database file */
    SPV_SYNC_WAL,   /* xSync on the write-ahead log */
    SPV_TRUNC_WAL,  /* xTruncate on the write-ahead log */
    SPV_KINDS
};

/* Register the wrapper as the default VFS; connections opened afterwards are
 * observed. Returns false when SQLite has no default VFS. */
bool spv_install(void);

/* Unregister it. Close every observed connection first. */
void spv_uninstall(void);

/* Forget the recorded events. */
void spv_reset(void);

/* How many events of `kind` were recorded since the last reset. */
int spv_count(enum spv_kind kind);

/* Position of the first event of `kind` in the recorded order, or -1. */
int spv_first(enum spv_kind kind);

/* Make every log sync fail with an I/O error until switched off. */
void spv_fail_wal_sync(bool on);

#endif
