/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * model_fields.h — declare a model's persisted columns ONCE.
 *
 * ── The defect this exists to make impossible ─────────────────────────────
 * Before this header every ActiveRecord model spelled its columns out three
 * times by hand:
 *
 *   1. a comma-separated SQL column-name string (`BLOG_POST_COLUMNS`),
 *   2. a read-row body with hardcoded indices `AR_READ_BLOB(s, 0, ...)`
 *      … `out->stored_at = AR_COL_INT(s, 14);`,
 *   3. an INSERT bind list with hardcoded positions `AR_BIND_BLOB(s, 1, ...)`.
 *
 * Insert a column in the middle of (1) and every index in (2) and (3) below it
 * shifts by one. There is NO compiler error and NO test failure unless a test
 * happens to cover that exact field — the symptom is one field silently
 * reading another field's value, which looks plausible in the data.
 *
 * Here the model declares its fields once, in a `.def` list, and all three
 * spellings are DERIVED from that one list. Column order, read index and bind
 * position cannot disagree because none of them is written down.
 *
 * ── How to use it ─────────────────────────────────────────────────────────
 * Declare the list in engine/models/include/models/def/<model>_fields.def:
 *
 *     #define BLOG_POST_FIELDS \
 *         ZCL_MODEL_BLOB(event_id,  event_id,  32), \
 *         ZCL_MODEL_TEXT(blog_name, blog_name),     \
 *         ZCL_MODEL_U64 (sequence,  sequence)
 *
 * Then in the model's .c file:
 *
 *     #include "models/model_fields.h"
 *     #include "models/def/blog_post_fields.def"
 *
 *     #define BLOG_POST_COLUMNS ZCL_MODEL_COLUMNS(BLOG_POST_FIELDS)
 *     #define BLOG_POST_VALUES  ZCL_MODEL_PLACEHOLDERS(BLOG_POST_FIELDS)
 *
 *     ZCL_MODEL_READ_ROW_FN(blog_post_read_row, struct db_blog_post,
 *                           BLOG_POST_FIELDS)
 *     ZCL_MODEL_BIND_FN(blog_post_bind, struct db_blog_post, BLOG_POST_FIELDS)
 *
 * `BLOG_POST_COLUMNS` is an ordinary string literal, so it still concatenates
 * into SQL exactly as the hand-written macro did:
 *
 *     "SELECT " BLOG_POST_COLUMNS " FROM blog_posts WHERE event_id=?"
 *     "INSERT INTO blog_posts (" BLOG_POST_COLUMNS ") VALUES(" BLOG_POST_VALUES ")"
 *
 * ── Cost ──────────────────────────────────────────────────────────────────
 * Compile-time only. No runtime field registry, no {name,type,offset} table,
 * no allocation, no global state, no reflection. The generated read/bind
 * bodies are the same AR_READ_* / AR_BIND_* calls a human would have written,
 * with a local `int` cursor the optimizer folds away. A field-list mistake is
 * a build error, never a runtime surprise.
 *
 * ── Which types exist and why ─────────────────────────────────────────────
 * The set below was taken from the corpus, not guessed. Measured over
 * engine/models/src (86 files) at the time of writing: AR_BIND_INT 584,
 * AR_COL_INT 364, AR_BIND_BLOB 342, AR_BIND_TEXT 328, AR_READ_STR 182,
 * AR_READ_BLOB 144, AR_COL_BYTES 56, AR_BIND_NULL 36, AR_COL_TEXT 9,
 * AR_COL_DOUBLE 0. The integer reads break down as 206 bare int64_t,
 * 72 (int), 28 (uint32_t), 24 (uint64_t), 17 bool `!= 0`, 11 (int32_t),
 * 3 (uint16_t), and 9 enum casts. Every one of those has a constructor
 * below. There is deliberately no DOUBLE: the corpus contains none, and an
 * unused type is an untested type.
 *
 * ── What is deliberately NOT covered ──────────────────────────────────────
 * Conditional binds (bind NULL when a member is empty), owning heap blobs
 * (`uint8_t *raw_tx` + malloc on read), and columns whose value is computed
 * rather than stored. Those models keep hand-written bind bodies; they can
 * still derive their column string and read body from a list. The mechanism
 * is opt-in per model, never a blanket rewrite.
 */

#ifndef ZCL_MODELS_MODEL_FIELDS_H
#define ZCL_MODELS_MODEL_FIELDS_H

#include "models/activerecord.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

/* ── Field constructors ───────────────────────────────────────────────────
 * Each expands to a parenthesised 4-tuple (Kind, column, member, extra).
 * The parentheses are what keep one field as ONE macro argument, so the
 * field list can be counted and walked. `Kind` is an undefined token used
 * only for ## dispatch below.
 *
 *   col     the SQL column name, stringized for the column list
 *   member  the struct member name
 *   extra   per-kind: fixed blob length, enum type, or length member
 */
#define ZCL_MODEL_BLOB(col, member, len)     (Blob, col, member, len)
#define ZCL_MODEL_TEXT(col, member)          (Text, col, member, 0)
#define ZCL_MODEL_I64(col, member)           (I64, col, member, 0)
#define ZCL_MODEL_U64(col, member)           (U64, col, member, 0)
#define ZCL_MODEL_I32(col, member)           (I32, col, member, 0)
#define ZCL_MODEL_U32(col, member)           (U32, col, member, 0)
#define ZCL_MODEL_U16(col, member)           (U16, col, member, 0)
#define ZCL_MODEL_INT(col, member)           (Int, col, member, 0)
#define ZCL_MODEL_BOOL(col, member)          (Bool, col, member, 0)
#define ZCL_MODEL_ENUM(col, member, type)    (Enum, col, member, type)

/* Fixed-width blob that is stored as SQL NULL while it is all-zero, which is
 * how "not observed yet" is spelled in several tables. Reads identically to
 * ZCL_MODEL_BLOB (AR_READ_BLOB already zero-fills a NULL column). */
#define ZCL_MODEL_BLOB_NULLABLE(col, member, len) \
    (BlobOrNull, col, member, len)

/* Variable-length blob held INLINE in a fixed-capacity array, with an
 * explicit length member. Read clamps to sizeof(member) and sets the length
 * member from the actual stored byte count; a blob that does not fit reads
 * back as empty rather than truncated. */
#define ZCL_MODEL_VARBLOB(col, member, len_member) \
    (VarBlob, col, member, len_member)

/* The declared-length column that accompanies a ZCL_MODEL_VARBLOB. It must
 * appear AFTER its VARBLOB in the same list: the read cross-checks the
 * declared length against the bytes actually stored and zeroes both on
 * disagreement, which is the existing hand-written behaviour. */
#define ZCL_MODEL_VARBLOB_LEN(col, member, len_member) \
    (VarBlobLen, col, member, len_member)

/* ── Token pasting ──────────────────────────────────────────────────────── */
#define ZCL_MF_CAT(a, b)  ZCL_MF_CAT_(a, b)
#define ZCL_MF_CAT_(a, b) a##b

/* True when any byte of a fixed-width blob member is set. Used only by the
 * nullable-blob bind, which stores SQL NULL for an all-zero value. */
static inline bool zcl_mf_bytes_any(const uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (bytes[i]) return true;
    return false;
}

/* ── Per-field emitters ─────────────────────────────────────────────────── */

/* Column name. `col` is stringized, so it is never macro-expanded. */
#define ZCL_MF_COL(kind, col, member, extra) #col

/* One SQL placeholder per field. */
#define ZCL_MF_QMARK(kind, col, member, extra) "?"

/* Read/bind dispatch on the tuple's Kind token. */
#define ZCL_MF_READ(kind, col, member, extra) \
    ZCL_MF_CAT(ZCL_MF_READ_, kind)(member, extra)
#define ZCL_MF_BIND(kind, col, member, extra) \
    ZCL_MF_CAT(ZCL_MF_BIND_, kind)(member, extra)

/* Read bodies. `_zm_s` is the statement, `_zm_r` the record, `_zm_i` the
 * running column index — all three are declared by ZCL_MODEL_READ_ROW_FN.
 * AR_READ_BLOB evaluates its column argument twice, so blob reads latch the
 * index into a local first; the scalar readers evaluate it once. */
#define ZCL_MF_READ_Blob(m, n) do { \
        const int _zm_c = _zm_i++; \
        AR_READ_BLOB(_zm_s, _zm_c, _zm_r->m, n); \
    } while (0);
#define ZCL_MF_READ_Text(m, n) do { \
        const int _zm_c = _zm_i++; \
        AR_READ_STR(_zm_s, _zm_c, _zm_r->m, sizeof(_zm_r->m)); \
    } while (0);
#define ZCL_MF_READ_BlobOrNull(m, n) ZCL_MF_READ_Blob(m, n)
#define ZCL_MF_READ_I64(m, n)  _zm_r->m = (int64_t)AR_COL_INT(_zm_s, _zm_i++);
#define ZCL_MF_READ_U64(m, n)  _zm_r->m = (uint64_t)AR_COL_INT(_zm_s, _zm_i++);
#define ZCL_MF_READ_I32(m, n)  _zm_r->m = (int32_t)AR_COL_INT(_zm_s, _zm_i++);
#define ZCL_MF_READ_U32(m, n)  _zm_r->m = (uint32_t)AR_COL_INT(_zm_s, _zm_i++);
#define ZCL_MF_READ_U16(m, n)  _zm_r->m = (uint16_t)AR_COL_INT(_zm_s, _zm_i++);
#define ZCL_MF_READ_Int(m, n)  _zm_r->m = (int)AR_COL_INT(_zm_s, _zm_i++);
#define ZCL_MF_READ_Bool(m, n) _zm_r->m = AR_COL_INT(_zm_s, _zm_i++) != 0;
#define ZCL_MF_READ_Enum(m, t) _zm_r->m = (t)AR_COL_INT(_zm_s, _zm_i++);

#define ZCL_MF_READ_VarBlob(m, lenm) do { \
        const int _zm_c = _zm_i++; \
        const int _zm_n = AR_COL_BYTES(_zm_s, _zm_c); \
        const void *_zm_p = sqlite3_column_blob(_zm_s, _zm_c); \
        if (_zm_p && _zm_n > 0 && (size_t)_zm_n <= sizeof(_zm_r->m)) { \
            memcpy(_zm_r->m, _zm_p, (size_t)_zm_n); \
            _zm_r->lenm = (uint32_t)_zm_n; \
        } else { \
            memset(_zm_r->m, 0, sizeof(_zm_r->m)); \
            _zm_r->lenm = 0; \
        } \
    } while (0);

#define ZCL_MF_READ_VarBlobLen(m, lenm) do { \
        const int _zm_c = _zm_i++; \
        if ((uint64_t)_zm_r->lenm != (uint64_t)AR_COL_INT(_zm_s, _zm_c)) { \
            memset(_zm_r->m, 0, sizeof(_zm_r->m)); \
            _zm_r->lenm = 0; \
        } \
    } while (0);

/* Bind bodies. `_zm_i` starts at 1 because SQLite parameters are 1-based.
 * Every AR_BIND_* evaluates its position argument exactly once. */
#define ZCL_MF_BIND_Blob(m, n)  AR_BIND_BLOB(_zm_s, _zm_i++, _zm_r->m, n);
#define ZCL_MF_BIND_Text(m, n)  AR_BIND_TEXT(_zm_s, _zm_i++, _zm_r->m);
#define ZCL_MF_BIND_BlobOrNull(m, n) do { \
        const int _zm_p = _zm_i++; \
        if (zcl_mf_bytes_any(_zm_r->m, (size_t)(n))) \
            AR_BIND_BLOB(_zm_s, _zm_p, _zm_r->m, n); \
        else \
            AR_BIND_NULL(_zm_s, _zm_p); \
    } while (0);
#define ZCL_MF_BIND_I64(m, n)   AR_BIND_INT(_zm_s, _zm_i++, (int64_t)_zm_r->m);
#define ZCL_MF_BIND_U64(m, n)   AR_BIND_INT(_zm_s, _zm_i++, (int64_t)_zm_r->m);
#define ZCL_MF_BIND_I32(m, n)   AR_BIND_INT(_zm_s, _zm_i++, (int64_t)_zm_r->m);
#define ZCL_MF_BIND_U32(m, n)   AR_BIND_INT(_zm_s, _zm_i++, (int64_t)_zm_r->m);
#define ZCL_MF_BIND_U16(m, n)   AR_BIND_INT(_zm_s, _zm_i++, (int64_t)_zm_r->m);
#define ZCL_MF_BIND_Int(m, n)   AR_BIND_INT(_zm_s, _zm_i++, (int64_t)_zm_r->m);
#define ZCL_MF_BIND_Bool(m, n)  AR_BIND_INT(_zm_s, _zm_i++, _zm_r->m ? 1 : 0);
#define ZCL_MF_BIND_Enum(m, t)  AR_BIND_INT(_zm_s, _zm_i++, (int64_t)_zm_r->m);
#define ZCL_MF_BIND_VarBlob(m, lenm) \
    AR_BIND_BLOB(_zm_s, _zm_i++, _zm_r->m, (int)_zm_r->lenm);
#define ZCL_MF_BIND_VarBlobLen(m, lenm) \
    AR_BIND_INT(_zm_s, _zm_i++, (int64_t)_zm_r->lenm);

#include "models/def/model_fields_tables.def"

/* ── Public expansions ────────────────────────────────────────────────────
 * All four derive from the SAME field list, so they cannot disagree. */

/* "col_a,col_b,col_c" — drops straight into a SELECT list or an INSERT
 * column clause, exactly where the hand-written _COLUMNS macro used to go. */
#define ZCL_MODEL_COLUMNS(...) ZCL_MF_JOIN(ZCL_MF_COL, __VA_ARGS__)

/* "?,?,?" — one placeholder per column, so an INSERT's VALUES list can never
 * be a different length than its column list. */
#define ZCL_MODEL_PLACEHOLDERS(...) ZCL_MF_JOIN(ZCL_MF_QMARK, __VA_ARGS__)

/* Expand a field list through a caller-supplied per-field op, for the
 * occasional extra derivation a model needs. The common one is a named
 * column-index enum, so a hand-written guard or UPDATE never spells a numeric
 * column index either:
 *
 *   #define MD_IX(kind, col, member, extra) MD_IX_##col,
 *   enum { ZCL_MODEL_EXPAND(MD_IX, MARKET_DOWNLOAD_FIELDS) MD_IX_COUNT };
 *
 * The op receives the whole (Kind, col, member, extra) tuple and emits its own
 * separators. */
#define ZCL_MODEL_EXPAND(op, ...) ZCL_MF_SEQ(op, __VA_ARGS__)

/* Define a row reader:  static void fn(rec_type *out, sqlite3_stmt *s)
 * Column indices are the list's own order; nothing names an index. */
#define ZCL_MODEL_READ_ROW_FN(fn, rec_type, ...) \
    static void fn(rec_type *_zm_r, sqlite3_stmt *_zm_s) \
    { \
        int _zm_i = 0; \
        memset(_zm_r, 0, sizeof(*_zm_r)); \
        ZCL_MF_SEQ(ZCL_MF_READ, __VA_ARGS__) \
        (void)_zm_i; \
    }

/* Define a parameter binder:  static void fn(sqlite3_stmt *s, const rec_type *r)
 * Bind positions are the list's own order; nothing names a position. */
#define ZCL_MODEL_BIND_FN(fn, rec_type, ...) \
    static void fn(sqlite3_stmt *_zm_s, const rec_type *_zm_r) \
    { \
        int _zm_i = 1; \
        ZCL_MF_SEQ(ZCL_MF_BIND, __VA_ARGS__) \
        (void)_zm_i; \
    }

#endif /* ZCL_MODELS_MODEL_FIELDS_H */
