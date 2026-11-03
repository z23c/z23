/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private interface between projection_store.c and the clean-close receipt
 * digest in projection_store_digest.c. */

#ifndef ZCL_STORAGE_PROJECTION_STORE_DIGEST_H
#define ZCL_STORAGE_PROJECTION_STORE_DIGEST_H

#include "storage/projection_store.h"

#include <stdbool.h>
#include <stdint.h>

#ifndef _WIN32
/* Close-time budget. A receipt only saves the next boot a paced background
 * quick_check, so a close with a clock hashes the file only while the
 * measured rate says the whole digest fits this budget. */
#define PROJECTION_RECEIPT_BUDGET_US (2ll * 1000ll * 1000ll)

struct projection_file_identity {
    unsigned long long dev;
    unsigned long long ino;
    long long size;
    long long mtime_sec;
    long long mtime_nsec;
    long long ctime_sec;
    long long ctime_nsec;
    uint32_t change_counter;
    uint32_t version_valid_for;
    char content_sha3[65];
};

/* What one digest hashed, for the close log and tests. */
struct receipt_digest_stats {
    uint64_t size;
    uint64_t hashed;
    int64_t spent_us;
    bool over_budget;
};

/* Identity of the SQLite file at `path` and the digest of every byte of it,
 * stable across the read. `clock` NULL hashes the whole file; otherwise the
 * digest stops, and the read fails, once the projected total exceeds the
 * budget. `stats` (nullable) reports what was hashed either way. */
bool projection_file_identity_read(
    const char *path, projection_store_clock_fn clock,
    struct receipt_digest_stats *stats, struct projection_file_identity *out);
#endif

#endif /* ZCL_STORAGE_PROJECTION_STORE_DIGEST_H */
