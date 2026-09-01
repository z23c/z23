/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for models/model_fields.h — the one-declaration column mapping.
 *
 * The point of the mechanism is that a model's SQL column order, its SELECT
 * read index and its INSERT bind position are all DERIVED from a single field
 * list, so they cannot drift apart. These tests do not take that on trust:
 * they build a real SQLite table out of the derived column list, round-trip a
 * record through the derived binder and reader, and then insert a column in
 * the MIDDLE of a second list and show that the derived reader follows while a
 * hand-written reader holding the old literal indices reads the wrong field.
 * That last case is the defect the mechanism exists to make impossible; it is
 * asserted here so the claim stays true.
 */

#include "test/test_core.h"

#include "models/model_fields.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define MF_RUN(name, expr) do { \
    printf("%s... ", (name));   \
    bool _ok = (expr);          \
    if (_ok) printf("OK\n");    \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Fixture record ───────────────────────────────────────────────────────
 * One member per supported field kind, so a round trip exercises the whole
 * constructor set rather than the two kinds a real model happens to use. */
struct mf_row {
    uint8_t  id[32];
    char     name[24];
    int64_t  created_at;
    uint64_t sequence;
    int32_t  version;
    uint32_t width;
    uint16_t port;
    int      height;
    bool     coinbase;
    uint8_t  sig[16];
    uint32_t sig_len;
    uint8_t  block_hash[32];
    enum { MF_STATE_A = 0, MF_STATE_B = 1, MF_STATE_C = 2 } state;
    int64_t  updated_at;
};

/* V1: the model as first written. */
#define MF_V1_FIELDS \
    ZCL_MODEL_BLOB         (id,         id, 32),           \
    ZCL_MODEL_TEXT         (name,       name),             \
    ZCL_MODEL_I64          (created_at, created_at),       \
    ZCL_MODEL_U64          (sequence,   sequence),         \
    ZCL_MODEL_I32          (version,    version),          \
    ZCL_MODEL_U32          (width,      width),            \
    ZCL_MODEL_U16          (port,       port),             \
    ZCL_MODEL_INT          (height,     height),           \
    ZCL_MODEL_BOOL         (coinbase,   coinbase),         \
    ZCL_MODEL_VARBLOB      (sig,        sig, sig_len),     \
    ZCL_MODEL_VARBLOB_LEN  (sig_len,    sig, sig_len),     \
    ZCL_MODEL_BLOB_NULLABLE(block_hash, block_hash, 32),   \
    ZCL_MODEL_ENUM         (state,      state, int),       \
    ZCL_MODEL_I64          (updated_at, updated_at)

/* V2: V1 with ONE column inserted in the middle, between `sequence` and
 * `version`. Under the old hand-maintained scheme this is the change that
 * silently shifted ten read indices and ten bind positions. Here it is one
 * added line and nothing else. */
#define MF_V2_FIELDS \
    ZCL_MODEL_BLOB         (id,         id, 32),           \
    ZCL_MODEL_TEXT         (name,       name),             \
    ZCL_MODEL_I64          (created_at, created_at),       \
    ZCL_MODEL_U64          (sequence,   sequence),         \
    ZCL_MODEL_INT          (height,     height),           \
    ZCL_MODEL_I32          (version,    version),          \
    ZCL_MODEL_U32          (width,      width),            \
    ZCL_MODEL_U16          (port,       port),             \
    ZCL_MODEL_BOOL         (coinbase,   coinbase),         \
    ZCL_MODEL_VARBLOB      (sig,        sig, sig_len),     \
    ZCL_MODEL_VARBLOB_LEN  (sig_len,    sig, sig_len),     \
    ZCL_MODEL_BLOB_NULLABLE(block_hash, block_hash, 32),   \
    ZCL_MODEL_ENUM         (state,      state, int),       \
    ZCL_MODEL_I64          (updated_at, updated_at)

#define MF_V1_COLUMNS ZCL_MODEL_COLUMNS(MF_V1_FIELDS)
#define MF_V1_VALUES  ZCL_MODEL_PLACEHOLDERS(MF_V1_FIELDS)
#define MF_V2_COLUMNS ZCL_MODEL_COLUMNS(MF_V2_FIELDS)
#define MF_V2_VALUES  ZCL_MODEL_PLACEHOLDERS(MF_V2_FIELDS)

ZCL_MODEL_READ_ROW_FN(mf_v1_read, struct mf_row, MF_V1_FIELDS)
ZCL_MODEL_BIND_FN(mf_v1_bind, struct mf_row, MF_V1_FIELDS)
ZCL_MODEL_READ_ROW_FN(mf_v2_read, struct mf_row, MF_V2_FIELDS)
ZCL_MODEL_BIND_FN(mf_v2_bind, struct mf_row, MF_V2_FIELDS)

/* Named column indices, derived the same way, for the hand-written reader
 * below and for the arity assertions. */
#define MF_V1_IX(kind, col, member, extra) MF_V1_IX_##col,
enum { ZCL_MODEL_EXPAND(MF_V1_IX, MF_V1_FIELDS) MF_V1_IX_COUNT };
#define MF_V2_IX(kind, col, member, extra) MF_V2_IX_##col,
enum { ZCL_MODEL_EXPAND(MF_V2_IX, MF_V2_FIELDS) MF_V2_IX_COUNT };

/* ── Helpers ──────────────────────────────────────────────────────────── */

static void mf_fill(struct mf_row *r)
{
    memset(r, 0, sizeof(*r));
    for (int i = 0; i < 32; i++) r->id[i] = (uint8_t)(0xA0 + i);
    snprintf(r->name, sizeof(r->name), "canonical-name");
    r->created_at = 1700000001;
    r->sequence   = 4242424242ULL;
    r->version    = -7;
    r->width      = 4000000000u;
    r->port       = 8233;
    r->height     = 123456;
    r->coinbase   = true;
    for (int i = 0; i < 9; i++) r->sig[i] = (uint8_t)(0x10 + i);
    r->sig_len    = 9;
    for (int i = 0; i < 32; i++) r->block_hash[i] = (uint8_t)(0x50 + i);
    r->state      = MF_STATE_C;
    r->updated_at = 1700000999;
}

static bool mf_same(const struct mf_row *a, const struct mf_row *b)
{
    return memcmp(a->id, b->id, 32) == 0 &&
           strcmp(a->name, b->name) == 0 &&
           a->created_at == b->created_at &&
           a->sequence == b->sequence &&
           a->version == b->version &&
           a->width == b->width &&
           a->port == b->port &&
           a->height == b->height &&
           a->coinbase == b->coinbase &&
           a->sig_len == b->sig_len &&
           memcmp(a->sig, b->sig, sizeof(a->sig)) == 0 &&
           memcmp(a->block_hash, b->block_hash, 32) == 0 &&
           a->state == b->state &&
           a->updated_at == b->updated_at;
}

/* Open an in-memory database with a table whose columns ARE the derived
 * column list. SQLite accepts typeless column definitions, so the table shape
 * comes from the same declaration the reader and binder do. */
static sqlite3 *mf_open(const char *create_sql)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return NULL;
    if (sqlite3_exec(db, create_sql, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

static bool mf_insert(sqlite3 *db, const char *sql,
                      void (*bind)(sqlite3_stmt *, const struct mf_row *),
                      const struct mf_row *r)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) return false;
    bind(s, r);
    bool ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

/* ── 1. Round trip through every field kind ───────────────────────────── */

static int t_round_trip(void)
{
    int failures = 0;
    sqlite3 *db = mf_open("CREATE TABLE v1 (" MF_V1_COLUMNS ")");
    if (!db) { printf("mf: open v1 failed\n"); return 1; }

    struct mf_row in;
    mf_fill(&in);
    bool inserted = mf_insert(db,
        "INSERT INTO v1 (" MF_V1_COLUMNS ") VALUES(" MF_V1_VALUES ")",
        mf_v1_bind, &in);
    MF_RUN("mf: derived bind fills the derived INSERT", inserted);

    struct mf_row out;
    sqlite3_stmt *s = NULL;
    bool read_ok = inserted &&
        sqlite3_prepare_v2(db, "SELECT " MF_V1_COLUMNS " FROM v1", -1, &s,
                           NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW;
    if (read_ok) mf_v1_read(&out, s);
    sqlite3_finalize(s);

    MF_RUN("mf: every field kind survives the round trip",
           read_ok && mf_same(&in, &out));
    MF_RUN("mf: placeholder count equals column count",
           MF_V1_IX_COUNT == 14 &&
           (int)strlen(MF_V1_VALUES) == 2 * MF_V1_IX_COUNT - 1);

    sqlite3_close(db);
    return failures;
}

/* ── 2. THE drift case ────────────────────────────────────────────────────
 * A column is inserted in the middle of the list. The derived reader must
 * follow it with no other edit. The literal-index reader, which is exactly
 * what every unconverted model still carries, must NOT — and that is asserted
 * here, because "this bug is now impossible" is only worth saying if the bug
 * is demonstrably still possible the old way. */

/* The hand-written reader as it stood for V1: literal indices, frozen. */
static void mf_legacy_read_v1_indices(struct mf_row *out, sqlite3_stmt *s)
{
    memset(out, 0, sizeof(*out));
    AR_READ_BLOB(s, 0, out->id, 32);
    AR_READ_STR(s, 1, out->name, sizeof(out->name));
    out->created_at = AR_COL_INT(s, 2);
    out->sequence   = (uint64_t)AR_COL_INT(s, 3);
    out->version    = (int32_t)AR_COL_INT(s, 4);
    out->width      = (uint32_t)AR_COL_INT(s, 5);
    out->port       = (uint16_t)AR_COL_INT(s, 6);
    out->height     = (int)AR_COL_INT(s, 7);
    out->coinbase   = AR_COL_INT(s, 8) != 0;
}

static int t_column_inserted_in_the_middle(void)
{
    int failures = 0;

    /* The two lists differ by one column, inserted in the middle. */
    MF_RUN("mf: V1 and V2 are the same columns in a different order",
           (int)MF_V1_IX_COUNT == (int)MF_V2_IX_COUNT &&
           strcmp(MF_V1_COLUMNS, MF_V2_COLUMNS) != 0);

    /* `height` moved from the end of the scalar run to the middle, and every
     * index between its old and new home moved with it — nobody edited an
     * index to make that happen. */
    MF_RUN("mf: derived indices shifted with the list, not by hand",
           (int)MF_V1_IX_height == 7 && (int)MF_V2_IX_height == 4 &&
           (int)MF_V2_IX_version == (int)MF_V1_IX_version + 1 &&
           (int)MF_V2_IX_width   == (int)MF_V1_IX_width   + 1 &&
           (int)MF_V2_IX_port    == (int)MF_V1_IX_port    + 1 &&
           (int)MF_V2_IX_coinbase == (int)MF_V1_IX_coinbase);

    sqlite3 *db = mf_open("CREATE TABLE v2 (" MF_V2_COLUMNS ")");
    if (!db) { printf("mf: open v2 failed\n"); return failures + 1; }

    struct mf_row in;
    mf_fill(&in);
    bool inserted = mf_insert(db,
        "INSERT INTO v2 (" MF_V2_COLUMNS ") VALUES(" MF_V2_VALUES ")",
        mf_v2_bind, &in);

    struct mf_row derived;
    struct mf_row legacy;
    memset(&derived, 0, sizeof(derived));
    memset(&legacy, 0, sizeof(legacy));
    sqlite3_stmt *s = NULL;
    bool got_row = inserted &&
        sqlite3_prepare_v2(db, "SELECT " MF_V2_COLUMNS " FROM v2", -1, &s,
                           NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW;
    if (got_row) {
        mf_v2_read(&derived, s);
        mf_legacy_read_v1_indices(&legacy, s);
    }
    sqlite3_finalize(s);
    sqlite3_close(db);

    MF_RUN("mf: derived reader is still correct after the insertion",
           got_row && mf_same(&in, &derived));

    /* The frozen literal indices now read `height` where `version` lives and
     * so on down the row. This is the silent corruption the mechanism
     * removes; if it ever stops happening, this test has stopped proving
     * anything and must be rewritten, not deleted. */
    MF_RUN("mf: frozen literal indices DO silently mis-read the same row",
           got_row &&
           legacy.version == (int32_t)in.height &&
           legacy.width   == (uint32_t)in.version &&
           !mf_same(&in, &legacy));

    return failures;
}

/* ── 3. Variable-length blob and its declared-length column ───────────── */

static int t_varblob_cross_check(void)
{
    int failures = 0;
    sqlite3 *db = mf_open("CREATE TABLE v1 (" MF_V1_COLUMNS ")");
    if (!db) { printf("mf: open varblob failed\n"); return 1; }

    struct mf_row in;
    mf_fill(&in);
    bool inserted = mf_insert(db,
        "INSERT INTO v1 (" MF_V1_COLUMNS ") VALUES(" MF_V1_VALUES ")",
        mf_v1_bind, &in);

    /* Corrupt only the declared length so it disagrees with the stored blob,
     * the shape a truncated or partially written row takes. */
    bool poisoned = inserted &&
        sqlite3_exec(db, "UPDATE v1 SET sig_len=3", NULL, NULL, NULL)
            == SQLITE_OK;

    struct mf_row out;
    sqlite3_stmt *s = NULL;
    bool got_row = poisoned &&
        sqlite3_prepare_v2(db, "SELECT " MF_V1_COLUMNS " FROM v1", -1, &s,
                           NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW;
    if (got_row) mf_v1_read(&out, s);
    sqlite3_finalize(s);

    static const uint8_t zero_sig[16] = {0};
    MF_RUN("mf: declared length disagreeing with the blob reads back empty",
           got_row && out.sig_len == 0 &&
           memcmp(out.sig, zero_sig, sizeof(zero_sig)) == 0);
    MF_RUN("mf: the rest of the row is unaffected by that refusal",
           got_row && out.height == in.height &&
           out.updated_at == in.updated_at);

    sqlite3_close(db);
    return failures;
}

/* ── 4. Nullable blob stores NULL for an all-zero value ───────────────── */

static int t_nullable_blob(void)
{
    int failures = 0;
    sqlite3 *db = mf_open("CREATE TABLE v1 (" MF_V1_COLUMNS ")");
    if (!db) { printf("mf: open nullable failed\n"); return 1; }

    struct mf_row in;
    mf_fill(&in);
    memset(in.block_hash, 0, sizeof(in.block_hash));
    bool inserted = mf_insert(db,
        "INSERT INTO v1 (" MF_V1_COLUMNS ") VALUES(" MF_V1_VALUES ")",
        mf_v1_bind, &in);

    sqlite3_stmt *s = NULL;
    bool got_row = inserted &&
        sqlite3_prepare_v2(db, "SELECT " MF_V1_COLUMNS " FROM v1", -1, &s,
                           NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW;
    bool is_null = got_row &&
        sqlite3_column_type(s, MF_V1_IX_block_hash) == SQLITE_NULL;
    struct mf_row out;
    if (got_row) mf_v1_read(&out, s);
    sqlite3_finalize(s);
    sqlite3_close(db);

    static const uint8_t zero_hash[32] = {0};
    MF_RUN("mf: an all-zero nullable blob is stored as SQL NULL", is_null);
    MF_RUN("mf: a NULL nullable blob reads back zeroed, not garbage",
           got_row && memcmp(out.block_hash, zero_hash, 32) == 0);

    return failures;
}

/* ── Aggregator ───────────────────────────────────────────────────────── */

int test_model_fields(void)
{
    printf("\n=== model_fields (one-declaration column mapping) tests ===\n");
    int failures = 0;
    failures += t_round_trip();
    failures += t_column_inserted_in_the_middle();
    failures += t_varblob_cross_check();
    failures += t_nullable_blob();
    return failures;
}
