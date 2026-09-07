/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.index row identity + cursor bookkeeping. See
 * native_dev_index_identity.h and native_dev_index_ingest.c's header
 * comment for why identity, not the byte-offset cursor alone, is what makes
 * ingest idempotent. Every direct sqlite3_step call below carries the
 * `// raw-sql-ok:index-store` marker for the same reason as
 * native_dev_index_ingest.c.
 */

#include "command/native_dev_index_identity.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

bool dev_index_hash_prefix(const char *path, int64_t n,
                          unsigned char out[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    if (n <= 0) {
        sha3_256_finalize(&ctx, out);
        return true;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return false;
    unsigned char buf[65536];
    int64_t remaining = n;
    bool ok = true;
    while (remaining > 0) {
        size_t want = remaining < (int64_t)sizeof(buf) ? (size_t)remaining
                                                       : sizeof(buf);
        size_t got = fread(buf, 1, want, fp);
        if (got == 0) {
            ok = false;
            break;
        }
        sha3_256_write(&ctx, buf, got);
        remaining -= (int64_t)got;
    }
    fclose(fp);
    if (!ok)
        return false;
    sha3_256_finalize(&ctx, out);
    return true;
}

void dev_index_row_key(const char *source_id, const char *line,
                      unsigned char out[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)source_id, strlen(source_id));
    static const unsigned char sep = 0x1f;
    sha3_256_write(&ctx, &sep, 1);
    sha3_256_write(&ctx, (const unsigned char *)line, strlen(line));
    sha3_256_finalize(&ctx, out);
}

bool dev_index_get_cursor(sqlite3 *db, const char *source_id,
                         const char *file_path, struct dev_index_cursor *out)
{
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    static const char *sql =
        "SELECT byte_offset, inode, size, prefix_hash, rows_skipped_total "
        "FROM cursors WHERE source_id=?1 AND file_path=?2";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, source_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, file_path, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st); // raw-sql-ok:index-store
    if (rc == SQLITE_ROW) {
        out->byte_offset = sqlite3_column_int64(st, 0);
        out->inode = sqlite3_column_int64(st, 1);
        out->size = sqlite3_column_int64(st, 2);
        const void *blob = sqlite3_column_blob(st, 3);
        int blen = sqlite3_column_bytes(st, 3);
        if (blob && blen == SHA3_256_OUTPUT_SIZE) {
            memcpy(out->prefix_hash, blob, SHA3_256_OUTPUT_SIZE);
            out->has_prefix_hash = true;
        }
        out->rows_skipped_total = sqlite3_column_int64(st, 4);
        out->found = true;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

bool dev_index_set_cursor(sqlite3 *db, const char *source_id,
                         const char *file_path, int64_t offset, int64_t inode,
                         int64_t size,
                         const unsigned char prefix_hash[SHA3_256_OUTPUT_SIZE],
                         int64_t rows_skipped_total)
{
    sqlite3_stmt *st = NULL;
    static const char *sql =
        "INSERT INTO cursors(source_id, file_path, inode, size, byte_offset,"
        " prefix_hash, rows_skipped_total) VALUES (?1,?2,?3,?4,?5,?6,?7)"
        " ON CONFLICT(source_id, file_path) DO UPDATE SET"
        " inode=excluded.inode, size=excluded.size,"
        " byte_offset=excluded.byte_offset, prefix_hash=excluded.prefix_hash,"
        " rows_skipped_total=excluded.rows_skipped_total";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, source_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, file_path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, inode);
    sqlite3_bind_int64(st, 4, size);
    sqlite3_bind_int64(st, 5, offset);
    sqlite3_bind_blob(st, 6, prefix_hash, SHA3_256_OUTPUT_SIZE, SQLITE_STATIC);
    sqlite3_bind_int64(st, 7, rows_skipped_total);
    int rc = sqlite3_step(st); // raw-sql-ok:index-store
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

int64_t dev_index_trusted_offset(const struct dev_index_cursor *cursor,
                                const char *path, int64_t size)
{
    if (!cursor->found || cursor->byte_offset <= 0)
        return 0;
    if (cursor->byte_offset > size || !cursor->has_prefix_hash)
        return 0;
    unsigned char actual[SHA3_256_OUTPUT_SIZE];
    if (!dev_index_hash_prefix(path, cursor->byte_offset, actual))
        return 0;
    if (memcmp(actual, cursor->prefix_hash, SHA3_256_OUTPUT_SIZE) != 0)
        return 0;
    return cursor->byte_offset;
}

int64_t dev_index_next_seq(sqlite3 *db, const char *source_id)
{
    sqlite3_stmt *st = NULL;
    static const char *sql =
        "SELECT COALESCE(MAX(seq),0)+1 FROM rows WHERE source_id=?1";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 1;
    sqlite3_bind_text(st, 1, source_id, -1, SQLITE_STATIC);
    int64_t next = 1;
    if (sqlite3_step(st) == SQLITE_ROW) // raw-sql-ok:index-store
        next = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return next;
}
