/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonically hash codeindex rows for verify-on-read adoption. */

#include "codeindex_priv.h"

#include "base/serialize_le.h"
#include "util/log_macros.h"

#include <sqlite3.h>

#include <limits.h>
#include <string.h>

#define CI_PROJECTION_MAX_BYTES (UINT64_C(512) * UINT64_C(1024) * UINT64_C(1024))

void ci_symbol_row_hash(const struct ci_symbol *sym, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const uint8_t tag = 0x02;
    sha3_256_write(&ctx, &tag, 1);
    const char *fields[] = {sym->name, sym->def_path, sym->decl_path,
                            sym->signature, sym->doc, sym->guard, sym->group};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        sha3_256_write(&ctx, (const unsigned char *)fields[i],
                       strlen(fields[i]) + 1);
    unsigned char scalars[10] = {
        (unsigned char)sym->kind, sym->partial ? 1u : 0u,
    };
    zcl_write_i32_le(scalars + 2u, sym->def_line);
    zcl_write_i32_le(scalars + 6u, sym->decl_line);
    sha3_256_write(&ctx, scalars, sizeof(scalars));
    sha3_256_finalize(&ctx, out);
}

enum ci_projection_kind {
    CI_PROJECTION_TEXT = 1,
    CI_PROJECTION_I32 = 2,
    CI_PROJECTION_BOOL = 3,
    CI_PROJECTION_BLOB32 = 4,
};

struct ci_projection_column {
    enum ci_projection_kind kind;
    size_t capacity;
};

struct ci_projection_table {
    uint8_t tag;
    const char *sql;
    const struct ci_projection_column *columns;
    size_t column_count;
    uint64_t row_limit;
};

struct ci_projection_hash {
    struct sha3_256_ctx sha;
    uint64_t bytes;
};

static bool projection_write(struct ci_projection_hash *hash,
                             const void *bytes, size_t length)
{
    if (!hash || (length > 0 && !bytes) ||
        hash->bytes > CI_PROJECTION_MAX_BYTES ||
        (uint64_t)length > CI_PROJECTION_MAX_BYTES - hash->bytes)
        return false;
    sha3_256_write(&hash->sha, bytes, length);
    hash->bytes += (uint64_t)length;
    return true;
}

static bool projection_u64(struct ci_projection_hash *hash, uint64_t value)
{
    uint8_t encoded[8];
    zcl_write_u64_le(encoded, value);
    return projection_write(hash, encoded, sizeof(encoded));
}

static bool projection_i32(struct ci_projection_hash *hash, int32_t value)
{
    uint8_t encoded[4];
    zcl_write_i32_le(encoded, value);
    return projection_write(hash, encoded, sizeof(encoded));
}

static bool projection_bytes(struct ci_projection_hash *hash,
                             const void *bytes, size_t length)
{
    return projection_u64(hash, (uint64_t)length) &&
           projection_write(hash, bytes, length);
}

static bool projection_meta_value_locked(struct ci_store *store,
                                         const char *key, void *value,
                                         size_t capacity, size_t *length,
                                         bool *found)
{
    if (length) *length = 0;
    if (found) *found = false;
    sqlite3 *db = ci_store_db(store);
    sqlite3_stmt *statement = NULL;
    if (!db || !key || !length || !found ||
        sqlite3_prepare_v2(db, "SELECT v FROM meta WHERE k=?", -1,
                           &statement, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(statement, 1, key, -1, SQLITE_TRANSIENT) ==
              SQLITE_OK;
    int rc = ok ? sqlite3_step(statement) : SQLITE_ERROR;  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW) {
        int count = sqlite3_column_bytes(statement, 0);
        const void *bytes = sqlite3_column_blob(statement, 0);
        ok = count >= 0 && (size_t)count <= capacity &&
             (count == 0 || (bytes && value));
        if (ok) {
            if (count > 0) memcpy(value, bytes, (size_t)count);
            *length = (size_t)count;
            *found = true;
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    if (sqlite3_finalize(statement) != SQLITE_OK) ok = false;
    return ok;
}

static bool projection_meta_locked(struct ci_store *store,
                                   struct ci_projection_hash *hash,
                                   const char *key, const void *expected,
                                   size_t expected_length, uint8_t tag)
{
    unsigned char value[64];
    if (expected_length > sizeof(value)) return false;
    size_t length = 0;
    bool found = false;
    if (!projection_meta_value_locked(store, key, value, sizeof(value),
                                      &length, &found) ||
        !found || length != expected_length ||
        (expected && memcmp(value, expected, expected_length) != 0))
        return false;
    return projection_write(hash, &tag, sizeof(tag)) &&
           projection_bytes(hash, value, length);
}

static bool projection_column(struct ci_projection_hash *hash,
                              sqlite3_stmt *statement, int column,
                              const struct ci_projection_column *spec)
{
    uint8_t kind = (uint8_t)spec->kind;
    if (!projection_write(hash, &kind, sizeof(kind))) return false;

    int storage = sqlite3_column_type(statement, column);
    if (spec->kind == CI_PROJECTION_TEXT) {
        if (storage != SQLITE_TEXT) return false;
        int count = sqlite3_column_bytes(statement, column);
        const unsigned char *text = sqlite3_column_text(statement, column);
        if (count < 0 || (size_t)count >= spec->capacity ||
            (count > 0 && (!text || memchr(text, 0, (size_t)count))))
            return false;
        return projection_bytes(hash, text, (size_t)count);
    }
    if (spec->kind == CI_PROJECTION_I32) {
        if (storage != SQLITE_INTEGER) return false;
        sqlite3_int64 value = sqlite3_column_int64(statement, column);
        if (value < 0 || value > INT32_MAX) return false;
        return projection_i32(hash, (int32_t)value);
    }
    if (spec->kind == CI_PROJECTION_BOOL) {
        if (storage != SQLITE_INTEGER) return false;
        sqlite3_int64 value = sqlite3_column_int64(statement, column);
        if (value != 0 && value != 1) return false;
        uint8_t boolean = value != 0 ? 1u : 0u;
        return projection_write(hash, &boolean, sizeof(boolean));
    }
    if (spec->kind == CI_PROJECTION_BLOB32) {
        if (storage != SQLITE_BLOB ||
            sqlite3_column_bytes(statement, column) != 32)
            return false;
        const void *blob = sqlite3_column_blob(statement, column);
        return blob && projection_write(hash, blob, 32);
    }
    return false;
}

static bool projection_table(struct ci_store *store,
                             struct ci_projection_hash *hash,
                             const struct ci_projection_table *table)
{
    sqlite3_stmt *statement = NULL;
    sqlite3 *db = ci_store_db(store);
    if (!db || sqlite3_prepare_v2(db, table->sql, -1, &statement, NULL) !=
                   SQLITE_OK)
        return false;
    bool ok = projection_write(hash, &table->tag, sizeof(table->tag));
    uint64_t rows = 0;
    int rc = SQLITE_DONE;
    while (ok && (rc = sqlite3_step(statement)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        if (rows == table->row_limit) {
            ok = false;
            break;
        }
        static const uint8_t row_tag = 0xa1;
        ok = projection_write(hash, &row_tag, sizeof(row_tag));
        for (size_t i = 0; ok && i < table->column_count; i++)
            ok = projection_column(hash, statement, (int)i,
                                   &table->columns[i]);
        rows++;
    }
    if (ok && rc != SQLITE_DONE) ok = false;
    int finalize_rc = sqlite3_finalize(statement);
    if (finalize_rc != SQLITE_OK) ok = false;
    static const uint8_t end_tag = 0xaf;
    return ok && projection_write(hash, &end_tag, sizeof(end_tag)) &&
           projection_u64(hash, rows);
}

static bool projection_root_locked(struct ci_store *store, uint8_t out[32])
{
    static const struct ci_projection_column group_columns[] = {
        {CI_PROJECTION_TEXT, sizeof(((struct ci_group *)0)->path)},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_group *)0)->kind)},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_group *)0)->parent)},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_group *)0)->purpose)},
    };
    static const struct ci_projection_column file_columns[] = {
        {CI_PROJECTION_TEXT, sizeof(((struct ci_file *)0)->path)},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_file *)0)->group)},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_file *)0)->purpose)},
    };
    static const struct ci_projection_column symbol_columns[] = {
        {CI_PROJECTION_TEXT, sizeof(((struct ci_symbol *)0)->name)},
        {CI_PROJECTION_TEXT, 2},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_symbol *)0)->def_path)},
        {CI_PROJECTION_I32, 0},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_symbol *)0)->decl_path)},
        {CI_PROJECTION_I32, 0},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_symbol *)0)->signature)},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_symbol *)0)->doc)},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_symbol *)0)->guard)},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_symbol *)0)->group)},
        {CI_PROJECTION_BOOL, 0},
        {CI_PROJECTION_BLOB32, 0},
    };
    static const struct ci_projection_column ref_columns[] = {
        {CI_PROJECTION_TEXT, sizeof(((struct ci_ref *)0)->callee)},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_ref *)0)->ref_file)},
        {CI_PROJECTION_I32, 0},
        {CI_PROJECTION_TEXT, sizeof(((struct ci_ref *)0)->enclosing)},
    };
    static const struct ci_projection_table tables[] = {
        {0x10,
         "SELECT path,kind,parent,purpose FROM groups ORDER BY "
         "path COLLATE BINARY,kind COLLATE BINARY,parent COLLATE BINARY,"
         "purpose COLLATE BINARY",
         group_columns, sizeof(group_columns) / sizeof(group_columns[0]),
         UINT64_C(4096)},
        {0x20,
         "SELECT path,\"group\",purpose FROM files ORDER BY "
         "path COLLATE BINARY,\"group\" COLLATE BINARY,purpose COLLATE BINARY",
         file_columns, sizeof(file_columns) / sizeof(file_columns[0]),
         UINT64_C(1048576)},
        {0x30,
         "SELECT " CI_SYM_COLS " FROM symbols ORDER BY "
         "name COLLATE BINARY,kind COLLATE BINARY,def_path COLLATE BINARY,"
         "def_line,decl_path COLLATE BINARY,decl_line,signature COLLATE BINARY,"
         "doc COLLATE BINARY,guard COLLATE BINARY,\"group\" COLLATE BINARY,"
         "partial,row_sha3",
         symbol_columns, sizeof(symbol_columns) / sizeof(symbol_columns[0]),
         UINT64_C(2097152)},
        {0x40,
         "SELECT callee_name,ref_file,ref_line,enclosing FROM refs ORDER BY "
         "callee_name COLLATE BINARY,ref_file COLLATE BINARY,ref_line,"
         "enclosing COLLATE BINARY",
         ref_columns, sizeof(ref_columns) / sizeof(ref_columns[0]),
         UINT64_C(4194304)},
    };

    struct ci_projection_hash hash = {0};
    static const char domain[] = "zcl.codeindex.retrieval_projection.v1";
    sha3_256_init(&hash.sha);
    bool ok = projection_write(&hash, domain, sizeof(domain));
    ok = ok && projection_meta_locked(store, &hash, "ci_schema_version",
                                      CI_SCHEMA_VERSION,
                                      sizeof(CI_SCHEMA_VERSION) - 1, 0x01) &&
         projection_meta_locked(store, &hash, "store_format", CI_STORE_FORMAT,
                                sizeof(CI_STORE_FORMAT) - 1, 0x02) &&
         projection_meta_locked(store, &hash, "source_root_sha3", NULL, 32,
                                0x03);
    for (size_t i = 0; ok && i < sizeof(tables) / sizeof(tables[0]); i++)
        ok = projection_table(store, &hash, &tables[i]);
    if (ok) sha3_256_finalize(&hash.sha, out);
    return ok;
}

bool ci_store_retrieval_projection_root(struct ci_store *store,
                                        uint8_t out[32])
{
    if (!store || !out)
        LOG_FAIL("codeindex", "null retrieval projection argument");
    uint8_t result[32];
    ci_store_lock(store);
    bool ok = projection_root_locked(store, result);
    ci_store_unlock(store);
    if (!ok) LOG_FAIL("codeindex", "canonical retrieval projection failed");
    memcpy(out, result, sizeof(result));
    return true;
}

bool ci_store_retrieval_projection_is_valid(struct ci_store *store,
                                             bool *valid)
{
    if (valid) *valid = false;
    if (!store || !valid)
        LOG_FAIL("codeindex", "null retrieval projection verifier argument");
    uint8_t sealed[32], actual[32];
    size_t length = 0;
    bool found = false;
    ci_store_lock(store);
    bool ok = projection_meta_value_locked(
        store, CI_RETRIEVAL_PROJECTION_META, sealed, sizeof(sealed),
        &length, &found);
    if (ok && found && length == sizeof(sealed)) {
        bool projected = projection_root_locked(store, actual);
        if (projected)
            *valid = memcmp(sealed, actual, sizeof(sealed)) == 0;
        /* A malformed logical row is an observed invalid derived generation,
         * not an authority failure. The retrieval opener will discard it and
         * deterministically rebuild from source. */
    }
    ci_store_unlock(store);
    if (!ok) LOG_FAIL("codeindex", "read retrieval projection metadata");
    return true;
}
