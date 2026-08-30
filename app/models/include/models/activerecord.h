/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord-style ORM base for C23.
 *
 * Pattern:
 *   struct db_block blk = {.height = 100, ...};
 *   if (!db_block_save(&ndb, &blk))
 *       printf("Error: %s\n", ndb.last_error);
 *
 * CRUD convention for every model:
 *   _save()         — INSERT OR REPLACE (create/update)
 *   _find()         — SELECT by primary key
 *   _find_by_*()    — SELECT by indexed column
 *   _delete()       — DELETE by primary key
 *   _count()        — SELECT COUNT(*)
 *   _each()         — iterate all rows via callback
 *   _where_*()      — filtered queries return arrays
 *
 * Lifecycle:
 *   validate → before_save → SQL INSERT/UPDATE → after_save
 *   before_destroy → SQL DELETE → after_destroy
 *
 * Preferred model implementation shape:
 *   1. DEFINE_MODEL_CALLBACKS(model_name)
 *   2. Optional DEFINE_MODEL_BEFORE_SAVE_READY(model_name, hook_fn)
 *   3. validate_* function using validates_* macros
 *   4. _save() using AR_BEGIN_SAVE / AR_ADHOC_SAVE / AR_FINISH_SAVE
 *   5. _find() / _list() / _exists() using AR_QUERY_* helpers
 *   6. _delete() using AR_ADHOC_DESTROY / AR_CACHED_DESTROY
 *
 * Relationships:
 *   db_block_transactions()  — Block has_many Transactions
 *   db_tx_block()            — Transaction belongs_to Block
 *   db_utxo_transaction()    — UTXO belongs_to Transaction
 *   db_wallet_utxo_key()     — WalletUTXO belongs_to WalletKey
 *   db_sapling_note_key()    — SaplingNote belongs_to SaplingKey
 *
 * Database-handle genericity:
 *   The AR_PREPARE / AR_EXEC / AR_ADHOC_* / AR_CACHED_* macros below
 *   accept any struct pointer with a `sqlite3 *db` member, not only
 *   `struct node_db *`. Subsystems whose handle wraps the same `node.db`
 *   (e.g. `struct wallet_sqlite` — borrowed handle) plug into the same
 *   validate → before_save → SQL → after_save lifecycle without growing
 *   a parallel framework. See the `ndb` entry in "Parameter conventions"
 *   below for the contract this depends on.
 */

#ifndef ZCL_DB_ACTIVERECORD_H
#define ZCL_DB_ACTIVERECORD_H

#include "event/event.h"
#include "models/ar_after_commit.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* Forward declarations for validators referenced by validates_* macros.
 * Implementations live in app/views/src/format_helpers.c (string utility)
 * and app/models/src/shared_validators.c. Declared here so model files
 * don't have to include those headers explicitly. */
bool zcl_is_hex_string(const char *s, size_t expected_len);
bool zcl_validate_zcl_address(const char *addr);

/* Maximum error message length */
#define AR_ERROR_MAX 256

/* Maximum callbacks per model per hook */
#define AR_MAX_CALLBACKS 4

/* Validation result — accumulates errors like ActiveModel::Errors */
struct ar_errors {
    char messages[8][AR_ERROR_MAX];
    int count;
};

static inline void ar_errors_clear(struct ar_errors *e)
{
    e->count = 0;
}

static inline void ar_errors_add(struct ar_errors *e, const char *field,
                                  const char *msg)
{
    if (e->count >= 8) return;
    snprintf(e->messages[e->count], AR_ERROR_MAX, "%s %s", field, msg);
    e->count++;
}

static inline bool ar_errors_any(const struct ar_errors *e)
{
    return e->count > 0;
}

static inline const char *ar_errors_full(const struct ar_errors *e)
{
    return e->count > 0 ? e->messages[0] : "";
}

/* All error messages joined by "; " */
static inline void ar_errors_full_messages(const struct ar_errors *e,
                                            char *buf, size_t buflen)
{
    if (e->count == 0) { buf[0] = '\0'; return; }
    buf[0] = '\0';
    size_t off = 0;
    for (int i = 0; i < e->count && off < buflen - 1; i++) {
        if (i > 0) {
            int n = snprintf(buf + off, buflen - off, "; ");
            off += (size_t)n;
        }
        int n = snprintf(buf + off, buflen - off, "%s", e->messages[i]);
        off += (size_t)n;
    }
}

/* Validation macros — use in validate_* functions */

#define validates_presence_of(errors, record, field) do { \
    static const uint8_t _zero[sizeof((record)->field)] = {0}; \
    if (memcmp(&(record)->field, _zero, sizeof((record)->field)) == 0) \
        ar_errors_add(errors, #field, "can't be blank"); \
} while (0)

#define validates_range(errors, record, field, min_val, max_val) do { \
    if ((record)->field < (min_val) || (record)->field > (max_val)) \
        ar_errors_add(errors, #field, "is out of range"); \
} while (0)

#define validates_positive(errors, record, field) do { \
    if ((record)->field <= 0) \
        ar_errors_add(errors, #field, "must be positive"); \
} while (0)

#define validates_blob_size(errors, data, len, expected, name) do { \
    if ((len) != (expected)) \
        ar_errors_add(errors, name, "has wrong size"); \
} while (0)

#define validates_non_negative(errors, record, field) do { \
    if ((record)->field < 0) \
        ar_errors_add(errors, #field, "must be non-negative"); \
} while (0)

#define validates_length_of(errors, record, field, min_len, max_len) do { \
    if ((record)->field < (min_len) || (record)->field > (max_len)) \
        ar_errors_add(errors, #field, "has wrong length"); \
} while (0)

#define validates_inclusion_of(errors, record, field, vals, nvals) do { \
    bool _found = false; \
    for (size_t _i = 0; _i < (nvals); _i++) \
        if ((record)->field == (vals)[_i]) { _found = true; break; } \
    if (!_found) \
        ar_errors_add(errors, #field, "is not included in the list"); \
} while (0)

#define validates_max(errors, record, field, max_val) do { \
    if ((record)->field > (max_val)) \
        ar_errors_add(errors, #field, "exceeds maximum"); \
} while (0)

#define validates_min(errors, record, field, min_val) do { \
    if ((record)->field < (min_val)) \
        ar_errors_add(errors, #field, "below minimum"); \
} while (0)

#define validates_not_zero(errors, record, field) do { \
    if ((record)->field == 0) \
        ar_errors_add(errors, #field, "can't be zero"); \
} while (0)

/* Validates a money amount is in consensus range [0, MAX_MONEY].
 * Use for ZCL values: UTXO amounts, fees, balances. */
#define validates_money_range(errors, record, field, max_money) do { \
    if ((record)->field < 0 || (record)->field > (max_money)) \
        ar_errors_add(errors, #field, "is out of money range"); \
} while (0)

/* Validates string field is not empty. */
#define validates_string_present(errors, str, name) do { \
    if (!(str) || (str)[0] == '\0') \
        ar_errors_add(errors, name, "can't be blank"); \
} while (0)

/* Validates a custom condition with a custom message. */
#define validates_custom(errors, cond, field, msg) do { \
    if (!(cond)) \
        ar_errors_add(errors, field, msg); \
} while (0)

/* Validates a C-string field has exactly `expected` characters
 * (excluding the terminating NUL). Use for fixed-width keys, hashes,
 * fingerprints. */
#define validates_length_eq(errors, record, field, expected) do { \
    if (!(record)->field || strlen((record)->field) != (size_t)(expected)) \
        ar_errors_add(errors, #field, "has wrong length"); \
} while (0)

/* Validates a C-string field is exactly `expected_len` characters AND
 * every character is [0-9a-fA-F]. Delegates to zcl_is_hex_string in
 * views/format_helpers.h. Use for txid / blockhash / sha3-256 fields. */
#define validates_hex_string(errors, record, field, expected_len) do { \
    if (!zcl_is_hex_string((record)->field, (size_t)(expected_len))) \
        ar_errors_add(errors, #field, "is not a hex string of the expected length"); \
} while (0)

/* Validates a C-string field is a syntactically and cryptographically
 * valid ZCL address (transparent t1/t3 with Base58Check, or Sapling zs1
 * with bech32). Delegates to zcl_validate_zcl_address in
 * models/shared_validators.h. Does NOT accept cross-chain addresses;
 * use a service-layer validator for ZSLP cross-chain recipients. */
#define validates_zcl_address(errors, record, field) do { \
    if (!zcl_validate_zcl_address((record)->field)) \
        ar_errors_add(errors, #field, "is not a valid ZCL address"); \
} while (0)

/* ── DRY Macros ────────────────────────────────────────────────── */

/* Define a model's callback registry with lazy init.
 * Usage: DEFINE_MODEL_CALLBACKS(utxo) generates db_utxo_callbacks(). */
#define DEFINE_MODEL_CALLBACKS(model) \
    static struct ar_callbacks model##_cbs; \
    static bool model##_cbs_init = false; \
    struct ar_callbacks *db_##model##_callbacks(void) { \
        if (!model##_cbs_init) { \
            ar_callbacks_init(&model##_cbs); \
            model##_cbs_init = true; \
        } \
        return &model##_cbs; \
    }

/* Define a lazy callback-registration helper for a single before_save hook.
 * Usage:
 *   DEFINE_MODEL_BEFORE_SAVE_READY(contact, contact_before_save)
 * Produces:
 *   static struct ar_callbacks *contact_callbacks_ready(void)
 */
#define DEFINE_MODEL_BEFORE_SAVE_READY(model, hook_fn) \
    static struct ar_callbacks *model##_callbacks_ready(void) { \
        struct ar_callbacks *cbs = db_##model##_callbacks(); \
        bool hook_present = false; \
        for (int i = 0; i < cbs->n_before_save; i++) { \
            if (cbs->before_save[i] == (hook_fn)) { \
                hook_present = true; \
                break; \
            } \
        } \
        if (!hook_present) { \
            ar_register_before_save(cbs, hook_fn); \
        } \
        return cbs; \
    }

/* Define a lazy callback-registration helper for a single before_validate
 * hook. Use this for normalization/canonicalization that validators must see
 * (trimming strings, filling default timestamps, uppercasing keys). */
#define DEFINE_MODEL_BEFORE_VALIDATE_READY(model, hook_fn) \
    static struct ar_callbacks *model##_callbacks_ready(void) { \
        struct ar_callbacks *cbs = db_##model##_callbacks(); \
        bool hook_present = false; \
        for (int i = 0; i < cbs->n_before_validate; i++) { \
            if (cbs->before_validate[i] == (hook_fn)) { \
                hook_present = true; \
                break; \
            } \
        } \
        if (!hook_present) { \
            ar_register_before_validate(cbs, hook_fn); \
        } \
        return cbs; \
    }

/* Safe malloc with NULL check — returns false from enclosing function. */
#define AR_MALLOC_OR_FAIL(ptr, size) do { \
    (ptr) = malloc(size); /* raw-alloc-ok:ar-framework-macro */ \
    if (!(ptr)) return false; \
} while (0)

/* Safe blob read from SQLite with size validation. */
#define AR_READ_BLOB(stmt, col, dest, expected_len) do { \
    int _blen = sqlite3_column_bytes(stmt, col); \
    const void *_bdata = sqlite3_column_blob(stmt, col); \
    if (_bdata && _blen >= (int)(expected_len)) \
        memcpy(dest, _bdata, expected_len); \
    else \
        memset(dest, 0, expected_len); \
} while (0)

/* Safe string read from SQLite. */
#define AR_READ_STR(stmt, col, dest, max_len) do { \
    const char *_s = (const char *)sqlite3_column_text(stmt, col); \
    if (_s) { \
        size_t _l = strlen(_s); \
        if (_l >= (max_len)) _l = (max_len) - 1; \
        memcpy(dest, _s, _l); \
        (dest)[_l] = 0; \
    } else { \
        (dest)[0] = 0; \
    } \
} while (0)

/* ── SQLite Statement Macros ──────────────────────────────────── *
 * Eliminate prepare/bind/step/finalize boilerplate.
 *
 * Usage:
 *   AR_PREPARE(ndb, s, "SELECT * FROM blocks WHERE height = ?");
 *   AR_BIND_INT(s, 1, height);
 *   if (!AR_STEP_ROW(s)) { AR_FINALIZE(s); return false; }
 *   int h = AR_COL_INT(s, 0);
 *   AR_FINALIZE(s);
 */

/* Prepare a statement. Logs on failure, returns false from enclosing fn. */
#define AR_PREPARE(ndb, stmt, sql) do { \
    if (sqlite3_prepare_v2((ndb)->db, sql, -1, &(stmt), NULL) != SQLITE_OK) { \
        fprintf(stderr, "AR_PREPARE failed: %s\n", \
                sqlite3_errmsg((ndb)->db)); \
        return false; \
    } \
} while (0)

/* Prepare, but don't return — for functions that need custom error handling. */
#define AR_PREPARE_OR(ndb, stmt, sql, fail_action) do { \
    if (sqlite3_prepare_v2((ndb)->db, sql, -1, &(stmt), NULL) != SQLITE_OK) { \
        fprintf(stderr, "AR_PREPARE failed: %s\n", \
                sqlite3_errmsg((ndb)->db)); \
        fail_action; \
    } \
} while (0)

/* Bind helpers */
#define AR_BIND_INT(stmt, pos, val) \
    sqlite3_bind_int64(stmt, pos, (int64_t)(val))

#define AR_BIND_BLOB(stmt, pos, data, len) \
    sqlite3_bind_blob(stmt, pos, data, (int)(len), SQLITE_STATIC)

#define AR_BIND_TEXT(stmt, pos, str) \
    sqlite3_bind_text(stmt, pos, str, -1, SQLITE_STATIC)

#define AR_BIND_DOUBLE(stmt, pos, val) \
    sqlite3_bind_double(stmt, pos, val)

#define AR_BIND_NULL(stmt, pos) \
    sqlite3_bind_null(stmt, pos)

/* Step and check result */
#define AR_STEP_ROW(stmt)  (sqlite3_step(stmt) == SQLITE_ROW)
#define AR_STEP_DONE(stmt) (sqlite3_step(stmt) == SQLITE_DONE)

/* Column readers */
#define AR_COL_INT(stmt, col)    sqlite3_column_int64(stmt, col)
#define AR_COL_DOUBLE(stmt, col) sqlite3_column_double(stmt, col)
#define AR_COL_TEXT(stmt, col)   ((const char *)sqlite3_column_text(stmt, col))
#define AR_COL_BYTES(stmt, col)  sqlite3_column_bytes(stmt, col)

/* Finalize */
#define AR_FINALIZE(stmt) do { \
    if (stmt) { sqlite3_finalize(stmt); (stmt) = NULL; } \
} while (0)

/* Execute a simple SQL statement (no bindings, no result). */
#define AR_EXEC(ndb, sql) do { \
    char *_err = NULL; \
    if (sqlite3_exec((ndb)->db, sql, NULL, NULL, &_err) != SQLITE_OK) { \
        if (_err) { \
            fprintf(stderr, "AR_EXEC failed: %s\n", _err); \
            sqlite3_free(_err); \
        } \
    } \
} while (0)

/* Prepare-or-return helper for query/list functions that return a value.
 * Usage:
 *   AR_PREPARE_RET(ndb, s, "SELECT ...", 0);
 */
#define AR_PREPARE_RET(ndb, stmt, sql, ret) do { \
    if (sqlite3_prepare_v2((ndb)->db, sql, -1, &(stmt), NULL) != SQLITE_OK || \
        !(stmt)) { \
        fprintf(stderr, "AR_PREPARE_RET failed: %s\n", \
                sqlite3_errmsg((ndb)->db)); \
        return (ret); \
    } \
} while (0)

#define AR_PREPARE_BOOL(ndb, stmt, sql) \
    AR_PREPARE_RET(ndb, stmt, sql, false)

/* Standard row-list loop for array outputs.
 * Usage:
 *   int count = 0;
 *   AR_LIST_ROWS(s, out, max, row_reader(out_row, s));
 *   return count;
 */
#define AR_LIST_ROWS(stmt, out, max, row_code) do { \
    while (AR_STEP_ROW(stmt) && (size_t)count < (max)) { \
        memset(&(out)[count], 0, sizeof((out)[count])); \
        row_code; \
        count++; \
    } \
} while (0)

#define AR_FIND_ONE_CACHED(stmt, out, row_code) do { \
    if (!AR_STEP_ROW(stmt)) \
        return false; \
    memset((out), 0, sizeof(*(out))); \
    row_code; \
    return true; \
} while (0)

#define AR_FINALIZE_STEP_DONE(stmt, ok) do { \
    (ok) = AR_STEP_DONE(stmt); \
    AR_FINALIZE(stmt); \
} while (0)

/* ── DRY Query Macros ─────────────────────────────────────────── *
 * Eliminate repetitive count/find patterns across models.
 *
 * Recommended usage:
 *   - cached INSERT/REPLACE save:
 *       AR_BEGIN_SAVE(...); bind cached stmt; AR_FINISH_SAVE(...)
 *   - ad hoc INSERT/REPLACE save:
 *       AR_ADHOC_SAVE(...)
 *   - single-row read:
 *       AR_QUERY_ONE_BOOL(...)
 *   - existence read:
 *       AR_QUERY_EXISTS(...)
 *   - list read:
 *       AR_QUERY_LIST(...)
 *   - ad hoc DELETE:
 *       AR_ADHOC_DESTROY(...)
 *   - cached DELETE:
 *       AR_CACHED_DESTROY(...)
 *   - simple UPDATE/DELETE execution:
 *       AR_EXEC_BOOL(...) or AR_EXEC_CHANGED_BOOL(...)
 *
 * AR_BEGIN_SAVE: validate + before_save lifecycle
 * AR_FINISH_SAVE: after_save + return
 * AR_CACHED_SAVE: validate → before_save → bind+step cached stmt → after_save
 * AR_CACHED_COUNT: reset cached count stmt → step → return int
 * AR_CACHED_FIND_RESET: reset + clear bindings on a cached stmt
 *
 * Parameter conventions:
 *   ndb
 *     Any struct pointer that exposes a `sqlite3 *db` member.
 *     Canonically `struct node_db *` (app/models/include/models/database.h).
 *     The macros below only do `(ndb)->db` to extract the SQLite handle,
 *     so any aliased handle struct works — for example
 *     `struct wallet_sqlite *` (lib/wallet/include/wallet/wallet_sqlite.h),
 *     which holds a *borrowed* handle to the same `node.db` file.
 *     All subsystems sharing node.db converge on this one macro
 *     family rather than each growing parallel `XXX_BEGIN_SAVE`
 *     machinery.
 *   stmt
 *     local `sqlite3_stmt *` variable for ad hoc statements, or a cached stmt
 *     field like `ndb->stmt_peer_delete` for cached paths.
 *   sql
 *     fixed SQL literal. Do not pass user-built SQL fragments here.
 *   cbs
 *     `struct ar_callbacks *` for the current model type.
 *   model_name
 *     short string used for validation logging, e.g. `"wallet_tx"`.
 *   record
 *     pointer to the model record being saved or destroyed.
 *   validate_fn
 *     function with shape `bool validate(const record_type *, struct ar_errors *)`.
 *   bind_code
 *     one or more `AR_BIND_*` calls, optionally with small `if/else` branches.
 *   row_code
 *     row deserialization logic for the current statement row.
 *   out
 *     output array or record filled by query helpers.
 *   max
 *     maximum number of rows to write into `out`.
 */

/* AR_BEGIN_SAVE(cbs, model_name, record, validate_fn)
 * cbs: callbacks for the model
 * model_name: short log label
 * record: model pointer being saved
 * validate_fn: model validation function
 * Effect: runs before_validate -> validate -> after_validate -> before_save. */
#define AR_BEGIN_SAVE(cbs, model_name, record, validate_fn) do { \
    AR_VALIDATE_RECORD((cbs), (model_name), (record), (validate_fn)); \
    if (!ar_run_before_save((cbs), (void *)(record))) return false; \
} while (0)

/* AR_FINISH_SAVE(cbs, record, ok)
 * cbs: callbacks for the model
 * record: saved model pointer
 * ok: bool result from SQL execution
 * Effect: runs after_save when ok — unchanged, still at STATEMENT time — then
 * queues the record's after_commit hooks for the open transaction (or fires
 * them now if there is none), then returns ok. A model with no after_commit
 * hook is byte-for-byte unaffected. A save whose after_commit can neither
 * fire nor be queued returns false, so an observer is never silently skipped;
 * the caller's transaction then rolls back the row too. */
#define AR_FINISH_SAVE(cbs, record, ok) do { \
    if (ok) { \
        ar_run_after_save((cbs), (void *)(record)); \
        if (!ar_run_after_commit((cbs), (void *)(record))) return false; \
    } \
    return (ok); \
} while (0)

/* AR_BEGIN_DESTROY(cbs, record)
 * cbs: callbacks for the model
 * record: model pointer being deleted
 * Effect: runs before_destroy and returns false if it vetoes the delete. */
#define AR_BEGIN_DESTROY(cbs, record) do { \
    if (!ar_run_before_destroy((cbs), (void *)(record))) return false; \
} while (0)

/* AR_FINISH_DESTROY(cbs, record, ok)
 * cbs: callbacks for the model
 * record: deleted model pointer
 * ok: bool result from SQL execution
 * Effect: runs after_destroy when ok, then returns ok from the function. */
#define AR_FINISH_DESTROY(cbs, record, ok) do { \
    if (ok) ar_run_after_destroy((cbs), (void *)(record)); \
    return (ok); \
} while (0)

/* AR_ADHOC_SAVE(ndb, stmt, sql, cbs, model_name, record, validate_fn, bind_code)
 * Use for locally prepared INSERT/REPLACE saves.
 * bind_code should fill every parameter on stmt before execution. */
#define AR_ADHOC_SAVE(ndb, stmt, sql, cbs, model_name, record, validate_fn, bind_code) do { \
    AR_BEGIN_SAVE((cbs), (model_name), (record), (validate_fn)); \
    AR_PREPARE_BOOL((ndb), (stmt), (sql)); \
    bind_code; \
    bool _ok = false; \
    AR_FINALIZE_STEP_DONE((stmt), _ok); \
    AR_FINISH_SAVE((cbs), (record), _ok); \
} while (0)

/* AR_ADHOC_DESTROY(ndb, stmt, sql, cbs, record, bind_code)
 * Use for locally prepared DELETE statements with destroy callbacks. */
#define AR_ADHOC_DESTROY(ndb, stmt, sql, cbs, record, bind_code) do { \
    AR_BEGIN_DESTROY((cbs), (record)); \
    AR_PREPARE_BOOL((ndb), (stmt), (sql)); \
    bind_code; \
    bool _ok = false; \
    AR_FINALIZE_STEP_DONE((stmt), _ok); \
    AR_FINISH_DESTROY((cbs), (record), _ok); \
} while (0)

/* AR_CACHED_DESTROY(stmt, cbs, record, bind_code)
 * stmt: cached prepared DELETE statement already owned by node_db. */
#define AR_CACHED_DESTROY(stmt, cbs, record, bind_code) do { \
    AR_BEGIN_DESTROY((cbs), (record)); \
    AR_RESET((stmt)); \
    bind_code; \
    bool _ok = AR_STEP_DONE((stmt)); \
    AR_FINISH_DESTROY((cbs), (record), _ok); \
} while (0)

/* AR_QUERY_EXISTS(ndb, stmt, sql, bind_code)
 * Returns true when the SELECT yields at least one row. */
#define AR_QUERY_EXISTS(ndb, stmt, sql, bind_code) do { \
    AR_PREPARE_BOOL((ndb), (stmt), (sql)); \
    bind_code; \
    bool _found = AR_STEP_ROW((stmt)); \
    AR_FINALIZE((stmt)); \
    return _found; \
} while (0)

/* AR_QUERY_ONE_BOOL(ndb, stmt, sql, bind_code, row_code)
 * Returns false when no row exists; otherwise runs row_code and returns true. */
#define AR_QUERY_ONE_BOOL(ndb, stmt, sql, bind_code, row_code) do { \
    AR_PREPARE_BOOL((ndb), (stmt), (sql)); \
    bind_code; \
    if (!AR_STEP_ROW((stmt))) { \
        AR_FINALIZE((stmt)); \
        return false; \
    } \
    row_code; \
    AR_FINALIZE((stmt)); \
    return true; \
} while (0)

/* AR_QUERY_LIST(ndb, stmt, sql, out, max, bind_code, row_code)
 * out: output array
 * max: max rows to write
 * row_code: should populate out[count] for the current row. */
#define AR_QUERY_LIST(ndb, stmt, sql, out, max, bind_code, row_code) do { \
    int count = 0; \
    AR_PREPARE_RET((ndb), (stmt), (sql), 0); \
    bind_code; \
    AR_LIST_ROWS((stmt), (out), (max), row_code); \
    AR_FINALIZE((stmt)); \
    return count; \
} while (0)

#define AR_QUERY_COUNT_BOUND(ndb, stmt, sql, bind_code) do { \
    int _count = 0; \
    AR_PREPARE_RET((ndb), (stmt), (sql), 0); \
    bind_code; \
    if (AR_STEP_ROW((stmt))) \
        _count = (int)AR_COL_INT((stmt), 0); \
    AR_FINALIZE((stmt)); \
    return _count; \
} while (0)

#define AR_QUERY_INT64_BOUND(ndb, stmt, sql, bind_code) do { \
    int64_t _value = 0; \
    AR_PREPARE_RET((ndb), (stmt), (sql), 0); \
    bind_code; \
    if (AR_STEP_ROW((stmt))) \
        _value = AR_COL_INT((stmt), 0); \
    AR_FINALIZE((stmt)); \
    return _value; \
} while (0)

/* AR_EXEC_BOOL(ndb, stmt, sql, bind_code)
 * Use for UPDATE/DELETE/INSERT statements where SQLITE_DONE is sufficient. */
#define AR_EXEC_BOOL(ndb, stmt, sql, bind_code) do { \
    AR_PREPARE_BOOL((ndb), (stmt), (sql)); \
    bind_code; \
    bool _ok = false; \
    AR_FINALIZE_STEP_DONE((stmt), _ok); \
    return _ok; \
} while (0)

/* AR_EXEC_CHANGED_BOOL(ndb, stmt, sql, bind_code)
 * Same as AR_EXEC_BOOL, but also requires sqlite3_changes(ndb->db) > 0. */
#define AR_EXEC_CHANGED_BOOL(ndb, stmt, sql, bind_code) do { \
    AR_PREPARE_BOOL((ndb), (stmt), (sql)); \
    bind_code; \
    bool _ok = false; \
    AR_FINALIZE_STEP_DONE((stmt), _ok); \
    return _ok && sqlite3_changes((ndb)->db) > 0; \
} while (0)

/* Count via a pre-cached SELECT COUNT(*) statement.
 * Usage: return AR_CACHED_COUNT(ndb->stmt_peer_count); */
#define AR_CACHED_COUNT(stmt) do { \
    sqlite3_reset(stmt); \
    int _c = 0; \
    if (AR_STEP_ROW(stmt)) \
        _c = (int)AR_COL_INT(stmt, 0); \
    return _c; \
} while (0)

/* Reset a cached statement for reuse (no finalize). */
#define AR_RESET(stmt) sqlite3_reset(stmt)

#define AR_QUERY_COUNT_SQL(ndb, sql) do { \
    sqlite3_stmt *_s = NULL; \
    int _count = 0; \
    AR_PREPARE_RET((ndb), _s, (sql), 0); \
    if (AR_STEP_ROW(_s)) \
        _count = (int)AR_COL_INT(_s, 0); \
    AR_FINALIZE(_s); \
    return _count; \
} while (0)

#define AR_QUERY_INT64_SQL(ndb, sql) do { \
    sqlite3_stmt *_s = NULL; \
    int64_t _value = 0; \
    AR_PREPARE_RET((ndb), _s, (sql), 0); \
    if (AR_STEP_ROW(_s)) \
        _value = AR_COL_INT(_s, 0); \
    AR_FINALIZE(_s); \
    return _value; \
} while (0)

/* ── Validate + Save lifecycle macro ──────────────────────────── *
 * Standard lifecycle: before_validate → validate → after_validate →
 * before_save → SQL → after_save.
 * Use in _save() implementations to eliminate boilerplate.
 *
 * Usage:
 *   AR_VALIDATE_AND_SAVE(ndb, record, model_name, validate_fn, sql_fn)
 */
#define AR_LOG_VALIDATION_FAILURE(model, errors) do { \
    char _msgs[512]; \
    ar_errors_full_messages(errors, _msgs, sizeof(_msgs)); \
    fprintf(stderr, "%s validation FAILED: %s\n", model, _msgs); \
    event_emitf(EV_MODEL_VALIDATION_FAILED, 0, \
                "model=%s errors=%s", (model), _msgs); \
} while (0)

/* Standard validation lifecycle:
 * before_validate -> validate -> after_validate
 * Returns false from the enclosing save when validation fails or a callback
 * halts the record. */
#define AR_VALIDATE_RECORD(cbs, model_name, record, validate_fn) do { \
    struct ar_errors _errors; \
    ar_errors_clear(&_errors); \
    if (!ar_run_before_validate((cbs), (void *)(record))) return false; \
    if (!(validate_fn)((record), &_errors)) { \
        AR_LOG_VALIDATION_FAILURE((model_name), &_errors); \
        return false; \
    } \
    ar_run_after_validate((cbs), (void *)(record)); \
} while (0)

/* ── Callback System ───────────────────────────────────────────── */

/* Callback signature: returns false to halt the operation.
 * before_save returning false prevents the save.
 * before_destroy returning false prevents the delete. */
typedef bool (*ar_before_cb)(void *record, void *ctx);
typedef void (*ar_after_cb)(void *record, void *ctx);

/* Async callback — queued for background execution.
 * Does not block the save/destroy operation. */
typedef void (*ar_async_cb)(void *record_copy, size_t record_size, void *ctx);

/* Per-model callback registry.
 * Each model type that wants callbacks declares a static instance. */
struct ar_callbacks {
    ar_before_cb before_validate[AR_MAX_CALLBACKS];
    ar_before_cb before_save[AR_MAX_CALLBACKS];
    ar_after_cb  after_save[AR_MAX_CALLBACKS];
    ar_after_cb  after_commit[AR_MAX_CALLBACKS];
    ar_before_cb before_destroy[AR_MAX_CALLBACKS];
    ar_after_cb  after_destroy[AR_MAX_CALLBACKS];
    ar_after_cb  after_validate[AR_MAX_CALLBACKS];
    ar_async_cb  after_save_async[AR_MAX_CALLBACKS];
    ar_async_cb  after_destroy_async[AR_MAX_CALLBACKS];
    int n_before_validate;
    int n_after_validate;
    int n_before_save;
    int n_after_save;
    int n_after_commit;
    int n_before_destroy;
    int n_after_destroy;
    int n_after_save_async;
    int n_after_destroy_async;
    size_t record_size;  /* size of the record struct for async copy */
    void *ctx;
};

static inline void ar_callbacks_init(struct ar_callbacks *cb)
{
    memset(cb, 0, sizeof(*cb));
}

static inline void ar_callbacks_set_ctx(struct ar_callbacks *cb, void *ctx)
{
    cb->ctx = ctx;
}

static inline bool ar_register_before_validate(struct ar_callbacks *cb,
                                                ar_before_cb fn)
{
    if (cb->n_before_validate >= AR_MAX_CALLBACKS) return false;
    cb->before_validate[cb->n_before_validate++] = fn;
    return true;
}

static inline bool ar_register_after_validate(struct ar_callbacks *cb,
                                               ar_after_cb fn)
{
    if (cb->n_after_validate >= AR_MAX_CALLBACKS) return false;
    cb->after_validate[cb->n_after_validate++] = fn;
    return true;
}

static inline bool ar_register_before_save(struct ar_callbacks *cb,
                                            ar_before_cb fn)
{
    if (cb->n_before_save >= AR_MAX_CALLBACKS) return false;
    cb->before_save[cb->n_before_save++] = fn;
    return true;
}

static inline bool ar_register_after_save(struct ar_callbacks *cb,
                                           ar_after_cb fn)
{
    if (cb->n_after_save >= AR_MAX_CALLBACKS) return false;
    cb->after_save[cb->n_after_save++] = fn;
    return true;
}

/* Register a hook that must not outrun durability: it fires once, in
 * registration order, after the OUTERMOST transaction COMMITS, and not at all
 * if the transaction rolls back. Outside a transaction it fires immediately
 * after the statement succeeds, which is the same instant. Use this — not
 * after_save — for anything an external observer can see: an emitted event, a
 * pushed projection, a notification. after_save still fires when the
 * STATEMENT steps and is unchanged.
 *
 * `record_size` is mandatory because a queued hook is handed a COPY (the
 * caller's record is routinely a stack local that is gone by commit time).
 * Pass sizeof(*record) for the model's row struct. Registering the same
 * callbacks with two different record sizes is refused. */
static inline bool ar_register_after_commit(struct ar_callbacks *cb,
                                             ar_after_cb fn,
                                             size_t record_size)
{
    if (!fn || record_size == 0) return false;
    if (cb->n_after_commit >= AR_MAX_CALLBACKS) return false;
    if (cb->record_size == 0) cb->record_size = record_size;
    else if (cb->record_size != record_size) return false;
    cb->after_commit[cb->n_after_commit++] = fn;
    return true;
}

static inline bool ar_register_before_destroy(struct ar_callbacks *cb,
                                               ar_before_cb fn)
{
    if (cb->n_before_destroy >= AR_MAX_CALLBACKS) return false;
    cb->before_destroy[cb->n_before_destroy++] = fn;
    return true;
}

static inline bool ar_register_after_destroy(struct ar_callbacks *cb,
                                              ar_after_cb fn)
{
    if (cb->n_after_destroy >= AR_MAX_CALLBACKS) return false;
    cb->after_destroy[cb->n_after_destroy++] = fn;
    return true;
}

static inline bool ar_register_after_save_async(struct ar_callbacks *cb,
                                                 ar_async_cb fn)
{
    if (cb->n_after_save_async >= AR_MAX_CALLBACKS) return false;
    cb->after_save_async[cb->n_after_save_async++] = fn;
    return true;
}

static inline bool ar_register_after_destroy_async(struct ar_callbacks *cb,
                                                    ar_async_cb fn)
{
    if (cb->n_after_destroy_async >= AR_MAX_CALLBACKS) return false;
    cb->after_destroy_async[cb->n_after_destroy_async++] = fn;
    return true;
}

static inline void ar_set_record_size(struct ar_callbacks *cb, size_t sz)
{
    cb->record_size = sz;
}

/* Run callbacks — return false if any before_ callback returns false */

static inline bool ar_run_before_validate(struct ar_callbacks *cb, void *record)
{
    for (int i = 0; i < cb->n_before_validate; i++)
        if (!cb->before_validate[i](record, cb->ctx)) return false;
    return true;
}

static inline void ar_run_after_validate(struct ar_callbacks *cb, void *record)
{
    for (int i = 0; i < cb->n_after_validate; i++)
        cb->after_validate[i](record, cb->ctx);
}

static inline bool ar_run_before_save(struct ar_callbacks *cb, void *record)
{
    for (int i = 0; i < cb->n_before_save; i++)
        if (!cb->before_save[i](record, cb->ctx)) return false;
    return true;
}

/* Queue this record's after_commit hooks against the open transaction (or
 * fire them now if there is none). Returns false when a hook can neither fire
 * nor be queued, which the save must treat as a failure — see
 * models/ar_after_commit.h. */
static inline bool ar_run_after_commit(struct ar_callbacks *cb, void *record)
{
    for (int i = 0; i < cb->n_after_commit; i++)
        if (!ar_after_commit_enqueue(cb->after_commit[i], cb->ctx, record,
                                     cb->record_size))
            return false;
    return true;
}

static inline void ar_run_after_save(struct ar_callbacks *cb, void *record)
{
    for (int i = 0; i < cb->n_after_save; i++)
        cb->after_save[i](record, cb->ctx);
}

static inline bool ar_run_before_destroy(struct ar_callbacks *cb, void *record)
{
    for (int i = 0; i < cb->n_before_destroy; i++)
        if (!cb->before_destroy[i](record, cb->ctx)) return false;
    return true;
}

static inline void ar_run_after_destroy(struct ar_callbacks *cb, void *record)
{
    for (int i = 0; i < cb->n_after_destroy; i++)
        cb->after_destroy[i](record, cb->ctx);
}

/* Run async callbacks — copies record and dispatches.
 * In the current implementation, runs synchronously (inline).
 * A future thread-pool dispatch would replace the loop body. */
static inline void ar_run_after_save_async(struct ar_callbacks *cb, void *record)
{
    if (cb->n_after_save_async == 0) return;
    for (int i = 0; i < cb->n_after_save_async; i++)
        cb->after_save_async[i](record, cb->record_size, cb->ctx);
}

static inline void ar_run_after_destroy_async(struct ar_callbacks *cb, void *record)
{
    if (cb->n_after_destroy_async == 0) return;
    for (int i = 0; i < cb->n_after_destroy_async; i++)
        cb->after_destroy_async[i](record, cb->record_size, cb->ctx);
}

/* ── Relationship Macros ───────────────────────────────────────── */

/* These document model relationships. Actual query functions are
 * declared in the respective model headers. */

/* has_many: parent model has multiple child records.
 * Convention: db_<parent>_<children>(ndb, pk, *out, max) → count */

/* belongs_to: child model references a parent by foreign key.
 * Convention: db_<child>_<parent>(ndb, fk, *out) → bool */

/* ── Router ────────────────────────────────────────────────────── */

/* RPC route with before_action filters.
 * A route maps method name → handler, with optional filters. */
#define AR_MAX_FILTERS 4

struct ar_route;

typedef bool (*ar_filter_fn)(const char *method, void *ctx);

struct ar_route {
    const char *method;
    const char *category;
    bool (*handler)(const void *params, bool help, void *result);
    ar_filter_fn before_filters[AR_MAX_FILTERS];
    int n_filters;
};

struct ar_router {
    struct ar_route routes[256];
    size_t num_routes;
    ar_filter_fn global_filters[AR_MAX_FILTERS];
    int n_global_filters;
};

static inline void ar_router_init(struct ar_router *r)
{
    memset(r, 0, sizeof(*r));
}

static inline bool ar_router_add_filter(struct ar_router *r,
                                          ar_filter_fn fn)
{
    if (r->n_global_filters >= AR_MAX_FILTERS) return false;
    r->global_filters[r->n_global_filters++] = fn;
    return true;
}

static inline bool ar_router_add_route(struct ar_router *r,
                                        const char *method,
                                        const char *category,
                                        bool (*handler)(const void *, bool, void *))
{
    if (r->num_routes >= 256) return false;
    struct ar_route *route = &r->routes[r->num_routes++];
    route->method = method;
    route->category = category;
    route->handler = handler;
    route->n_filters = 0;
    return true;
}

static inline bool ar_route_add_filter(struct ar_router *r,
                                        const char *method,
                                        ar_filter_fn fn)
{
    for (size_t i = 0; i < r->num_routes; i++) {
        if (strcmp(r->routes[i].method, method) == 0) {
            struct ar_route *route = &r->routes[i];
            if (route->n_filters >= AR_MAX_FILTERS) return false;
            route->before_filters[route->n_filters++] = fn;
            return true;
        }
    }
    return false;
}

static inline const struct ar_route *ar_router_find(const struct ar_router *r,
                                                      const char *method)
{
    for (size_t i = 0; i < r->num_routes; i++)
        if (strcmp(r->routes[i].method, method) == 0)
            return &r->routes[i];
    return NULL;
}

/* Dispatch: run global filters → route filters → handler */
static inline bool ar_router_dispatch(struct ar_router *r,
                                       const char *method,
                                       const void *params,
                                       bool help,
                                       void *result,
                                       void *filter_ctx)
{
    const struct ar_route *route = ar_router_find(r, method);
    if (!route) return false;

    for (int i = 0; i < r->n_global_filters; i++)
        if (!r->global_filters[i](method, filter_ctx)) return false;

    for (int i = 0; i < route->n_filters; i++)
        if (!route->before_filters[i](method, filter_ctx)) return false;

    return route->handler(params, help, result);
}

#endif
