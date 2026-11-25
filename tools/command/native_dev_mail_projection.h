/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Disposable derived mail locators; authoritative mail and grants remain external. */
#ifndef ZCL_NATIVE_DEV_MAIL_PROJECTION_H
#define ZCL_NATIVE_DEV_MAIL_PROJECTION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct sqlite3 sqlite3;
#define DEV_MAIL_REF_MAX 255
#define DEV_MAIL_STREAM_MAX 128
struct dev_mail_tuple {
    char boot[37];
    int64_t dev, inode, size, mtime_ns, ctime_ns, frontier, skipped;
    unsigned char source_sha3[32];
    bool partial;
};
struct dev_mail_locator {
    int64_t offset, end, seq;
    char sha3[65];
    char ref[DEV_MAIL_REF_MAX + 1];
};
struct dev_mail_rebuild;
/* Caller securely opens the owner-private index DB; a newly created empty DB
 * receives the normal dev.index schema. Existing incompatible DBs refuse. */
bool dev_mail_projection_index_prepare(sqlite3 *db, bool newly_created);
/* Under all native stream locks, atomically discard only derived mail tables.
 * Generic dev.index rows, cursors and FTS are never touched. */
bool dev_mail_projection_reset(sqlite3 *db);
/* Acquire all native stream locks before begin. Do not acquire a stream lock
 * while this transaction is open. A failed add poisons the transaction;
 * commit or abort releases it. No fixed history-size allocation is required. */
struct dev_mail_rebuild *dev_mail_projection_begin(sqlite3 *db, const char *stream,
                                                    const struct dev_mail_tuple *after);
struct dev_mail_rebuild *dev_mail_projection_begin_append(sqlite3 *db, const char *stream,
    const struct dev_mail_tuple *before, const struct dev_mail_tuple *after);
bool dev_mail_projection_add(struct dev_mail_rebuild *tx, const struct dev_mail_locator *row);
bool dev_mail_projection_commit(struct dev_mail_rebuild *tx);
/* Final skipped count is learned while scanning; all descriptor identity and
 * complete-frontier fields must remain equal to those bound at begin. */
bool dev_mail_projection_commit_scanned(struct dev_mail_rebuild *tx,
                                        const struct dev_mail_tuple *final);
void dev_mail_projection_abort(struct dev_mail_rebuild *tx);
/* Stored metadata is advisory, never the actual descriptor's identity. */
bool dev_mail_projection_get(sqlite3 *db, const char *stream, struct dev_mail_tuple *out);
/* Caller owns native stream locks and supplies verified descriptor tuples and
 * parsed complete rows. False always means unavailable; retry via full scan.
 * Rebuild replaces one entire stream; append requires exact prior tuple.
 * Transaction commits all rows and the new frontier together. */
bool dev_mail_projection_rebuild(sqlite3 *db, const char *stream,
    const struct dev_mail_tuple *after, const struct dev_mail_locator *rows, size_t count);
bool dev_mail_projection_append(sqlite3 *db, const char *stream,
    const struct dev_mail_tuple *before, const struct dev_mail_tuple *after,
    const struct dev_mail_locator *rows, size_t count);
/* Exact-ref result is usable only on true; *count is zero on every failure.
 * Caller validates stream set and tuples before/after, resolves exact rows,
 * and validates grants live. No returned locator is authority. */
bool dev_mail_projection_find(sqlite3 *db, const char *stream,
    const struct dev_mail_tuple *expected, const char *ref,
    struct dev_mail_locator *out, size_t capacity, size_t *count);
/* Diagnostic after an unavailable find. CORRUPT is returned only for a
 * proven missing, altered or malformed authenticated node. Busy, allocation,
 * unsupported version, collision and result-cap limits remain UNKNOWN. */
enum dev_mail_probe_result { DEV_MAIL_PROBE_UNKNOWN, DEV_MAIL_PROBE_CLEAN, DEV_MAIL_PROBE_CORRUPT };
enum dev_mail_probe_result dev_mail_projection_probe(sqlite3 *db, const char *stream,
    const struct dev_mail_tuple *expected, const char *ref, size_t cap);
#endif
