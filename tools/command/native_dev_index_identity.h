/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: dev.index row identity (content-addressed row_key) and per-file
 * cursor bookkeeping, shared by ingest and by nothing else
 * (tools/command/native_dev_index_identity.c). Split out of
 * native_dev_index_ingest.c to keep that file under the file-size target. */
#ifndef ZCL_NATIVE_DEV_INDEX_IDENTITY_H
#define ZCL_NATIVE_DEV_INDEX_IDENTITY_H

#include <sha3/sha3.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct sqlite3 sqlite3;

/* Hash the first `n` bytes of `path` (n==0 hashes the empty string). Used
 * both to fingerprint a cursor's already-ingested prefix and, on the next
 * ingest, to re-check that fingerprint against whatever now sits at that
 * path. Returns false only on an I/O error or a file shorter than n. */
bool dev_index_hash_prefix(const char *path, int64_t n,
                          unsigned char out[SHA3_256_OUTPUT_SIZE]);

/* A row's identity: SHA3-256 over source_id, a separator byte, and the raw
 * line bytes. Two lines with the same content in the same source hash
 * identically, which is exactly the point: whichever one reaches INSERT
 * first wins and the other is silently ignored (see
 * native_dev_index_ingest.c's header comment). */
void dev_index_row_key(const char *source_id, const char *line,
                      unsigned char out[SHA3_256_OUTPUT_SIZE]);

/* One file's saved ingest position within one source. */
struct dev_index_cursor {
    int64_t byte_offset;
    int64_t inode;
    int64_t size;
    unsigned char prefix_hash[SHA3_256_OUTPUT_SIZE];
    bool has_prefix_hash;
    int64_t rows_skipped_total;
    bool found;
};

bool dev_index_get_cursor(sqlite3 *db, const char *source_id,
                         const char *file_path, struct dev_index_cursor *out);

bool dev_index_set_cursor(sqlite3 *db, const char *source_id,
                         const char *file_path, int64_t offset, int64_t inode,
                         int64_t size,
                         const unsigned char prefix_hash[SHA3_256_OUTPUT_SIZE],
                         int64_t rows_skipped_total);

/* The byte offset it is safe to resume reading `path` from: 0 unless a
 * cursor exists, its saved offset still fits inside the file, AND hashing
 * the file's current first `byte_offset` bytes reproduces the hash saved at
 * that cursor. Neither inode nor size is trusted on its own — a `mv` onto
 * identical bytes changes inode but must not restart, and a same-size
 * in-place rewrite changes neither but must. */
int64_t dev_index_trusted_offset(const struct dev_index_cursor *cursor,
                                const char *path, int64_t size);

/* Next `rows.seq` value for `source_id` (1 for a source with no rows yet). */
int64_t dev_index_next_seq(sqlite3 *db, const char *source_id);

#endif /* ZCL_NATIVE_DEV_INDEX_IDENTITY_H */
