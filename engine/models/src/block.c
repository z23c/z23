/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: Block
 *
 * validates :hash, :prev_hash, :merkle_root, presence: true
 * validates :height, :file_num, :data_pos, :undo_pos, numericality: { >= 0 }
 * validates :height, maximum: 100_000_000
 * validates :time, :bits, not_zero: true
 * validates :num_tx, range: [0, 100_000]
 *
 * has_many :transactions
 * has_many :utxos, through: height
 * belongs_to :prev_block
 * has_one :next_block
 *
 * after_save -> emit EV_MODEL_SAVED */

#include "models/block.h"
#include "util/log_macros.h"
#include "encoding/utilstrencodings.h"
#include "models/tx_index.h"
#include "models/utxo.h"
#include "chain/chain.h"
#include "event/event.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "util/ar_step_readonly.h"
#include "support/log_throttle.h"
#include <string.h>
#include <stdio.h>

#define DB_BLOCK_SAVE_MAX_ATTEMPTS 1200
#define DB_BLOCK_SAVE_RETRY_MS 25
#define DB_BLOCK_HEADER_MISMATCH_LOG_SECS 60

/* Header validation deliberately falls through to other hash-bound sources
 * when a historical blocks row is stale. A from-genesis fold can encounter
 * that same source failure tens of times per second, so emit the first WARN
 * and a periodic keepalive instead of writing one journal record per block. */
static struct log_throttle g_header_mismatch_log = LOG_THROTTLE_INIT;

/* ── Callbacks ─────────────────────────────────────────────────── */

DEFINE_MODEL_CALLBACKS(block)

/* before_save: validate height and hash presence */
static bool block_before_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_block *b = record;
    if (b->height < 0) {
        LOG_FAIL("block", "before_save REJECTED: negative height %d", b->height);
    }
    /* Check hash is not all zeros */
    static const uint8_t zero[32] = {0};
    if (memcmp(b->hash, zero, 32) == 0) {
        LOG_FAIL("block", "before_save REJECTED: null hash");
    }
    return true;
}

/* after_save: emit model-specific event */
static void block_after_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_block *b = record;
    event_emitf(EV_BLOCK_SAVED, 0, "height=%d ntx=%d", b->height, b->num_tx);
    event_emitf(EV_MODEL_SAVED, 0, "model=block height=%d ntx=%d",
                b->height, b->num_tx);
}

static void block_init_hooks(void)
{
    static bool done = false;
    if (done) return;
    struct ar_callbacks *cbs = db_block_callbacks();
    ar_register_before_save(cbs, block_before_save);
    ar_register_after_save(cbs, block_after_save);
    done = true;
}

static void db_block_bind_insert(sqlite3_stmt *s, const struct db_block *b)
{
    AR_BIND_BLOB(s, 1, b->hash, 32);
    AR_BIND_INT(s, 2, b->height);
    AR_BIND_BLOB(s, 3, b->prev_hash, 32);
    AR_BIND_INT(s, 4, b->version);
    AR_BIND_BLOB(s, 5, b->merkle_root, 32);
    AR_BIND_INT(s, 6, b->time);
    AR_BIND_INT(s, 7, b->bits);
    AR_BIND_BLOB(s, 8, b->nonce, 32);
    AR_BIND_BLOB(s, 9, b->solution, (int)b->solution_len);
    AR_BIND_BLOB(s, 10, b->chain_work, 32);
    AR_BIND_INT(s, 11, b->status);
    AR_BIND_INT(s, 12, b->file_num);
    AR_BIND_INT(s, 13, b->data_pos);
    AR_BIND_INT(s, 14, b->undo_pos);
    AR_BIND_INT(s, 15, b->num_tx);
    AR_BIND_BLOB(s, 16, b->sapling_root, 32);
    AR_BIND_BLOB(s, 17, b->sprout_root, 32);
    AR_BIND_INT(s, 18, b->sapling_value);
    AR_BIND_INT(s, 19, b->sprout_value);
}

static bool db_block_step_is_retryable(int rc)
{
    return rc == SQLITE_BUSY || rc == SQLITE_LOCKED;
}

static bool db_block_step_done_retry(sqlite3 *db,
                                     sqlite3_stmt *s,
                                     const char *stmt_name,
                                     int height,
                                     const uint8_t hash[32],
                                     int *rc_out,
                                     int *attempts_out)
{
    int rc = SQLITE_OK;
    int attempts = 0;

    if (!db || !s || !stmt_name) {
        if (rc_out)
            *rc_out = SQLITE_MISUSE;
        if (attempts_out)
            *attempts_out = 0;
        return false;
    }

    for (; attempts < DB_BLOCK_SAVE_MAX_ATTEMPTS; attempts++) {
        rc = AR_STEP_ROW_READONLY(s);
        if (rc == SQLITE_DONE)
            break;
        sqlite3_reset(s);
        if (!db_block_step_is_retryable(rc))
            break;
        sqlite3_sleep(DB_BLOCK_SAVE_RETRY_MS);
    }

    if (rc != SQLITE_DONE) {
        char hash_hex[65];
        HexStr(hash, 32, false, hash_hex, sizeof(hash_hex));
        LOG_WARN("chain", "%s: failed height=%d hash=%s step_rc=%d " "step_msg=%s db_rc=%d db_msg=%s attempts=%d", stmt_name, height, hash_hex, rc, sqlite3_errstr(rc), sqlite3_errcode(db), sqlite3_errmsg(db), attempts);
    }

    if (rc_out)
        *rc_out = rc;
    if (attempts_out)
        *attempts_out = attempts;
    return rc == SQLITE_DONE;
}

static void db_block_reset_cached_readers(struct node_db *ndb)
{
    if (!ndb)
        return;
    if (ndb->stmt_block_by_hash)
        sqlite3_reset(ndb->stmt_block_by_hash);
    if (ndb->stmt_block_by_height)
        sqlite3_reset(ndb->stmt_block_by_height);
    if (ndb->stmt_state_get)
        sqlite3_reset(ndb->stmt_state_get);
}

static bool db_block_has_canonical_conflict(struct node_db *ndb,
                                            const struct db_block *b,
                                            bool *conflict_out)
{
    sqlite3_stmt *s = NULL;
    int rc;

    if (conflict_out)
        *conflict_out = false;
    if (!ndb || !ndb->open || !b || !conflict_out)
        return false;

    rc = sqlite3_prepare_v2(ndb->db,
        "SELECT 1 FROM blocks "
        "WHERE height=? AND hash<>? AND status>=3 LIMIT 1",
        -1, &s, NULL);
    if (rc != SQLITE_OK || !s) {
        ndb->last_sqlite_rc = rc;
        snprintf(ndb->last_op, sizeof(ndb->last_op), "%s",
                 "db_block_save_canonical.conflict_prepare");
        return false;
    }

    AR_BIND_INT(s, 1, b->height);
    AR_BIND_BLOB(s, 2, b->hash, 32);
    rc = AR_STEP_ROW_READONLY(s);
    *conflict_out = (rc == SQLITE_ROW);
    sqlite3_finalize(s);

    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        ndb->last_sqlite_rc = rc;
        snprintf(ndb->last_op, sizeof(ndb->last_op), "%s",
                 "db_block_save_canonical.conflict_select");
        return false;
    }

    return true;
}

/* ── Validation ────────────────────────────────────────────────── */

bool db_block_validate(const struct db_block *b, struct ar_errors *errors)
{
    ar_errors_clear(errors);

    /* Required fields */
    validates_presence_of(errors, b, hash);
    if (b->height != 0)
        validates_presence_of(errors, b, prev_hash);
    validates_presence_of(errors, b, merkle_root);

    /* Range checks */
    validates_non_negative(errors, b, height);
    validates_max(errors, b, height, 100000000);
    validates_not_zero(errors, b, time);
    validates_max(errors, b, time, 4294967295U);
    validates_not_zero(errors, b, bits);

    /* Transaction count */
    validates_non_negative(errors, b, num_tx);
    validates_max(errors, b, num_tx, 100000);

    /* File position */
    validates_non_negative(errors, b, file_num);
    validates_non_negative(errors, b, data_pos);
    validates_non_negative(errors, b, undo_pos);

    /* Equihash solution */
    validates_custom(errors,
        b->solution_len <= (size_t)INT32_MAX,
        "solution_len", "exceeds max size");
    validates_custom(errors,
        !(b->solution_len > 0 && !b->solution),
        "solution", "length set but pointer is null");

    return !ar_errors_any(errors);
}

/* ── Save ──────────────────────────────────────────────────────── */

bool db_block_save(struct node_db *ndb, const struct db_block *b)
{
    if (!ndb || !ndb->open || !ndb->stmt_block_insert) return false;

    block_init_hooks();
    struct ar_callbacks *cbs = db_block_callbacks();
    AR_BEGIN_SAVE(cbs, "block", b, db_block_validate);

    sqlite3_stmt *s = ndb->stmt_block_insert;
    bool locked_stmt = false;
    if (ndb->state_mutex_init) {
        zcl_mutex_lock(&ndb->state_mutex);
        locked_stmt = true;
    }

    int rc = SQLITE_OK;
    int attempts = 0;
    for (; attempts < DB_BLOCK_SAVE_MAX_ATTEMPTS; attempts++) {
        sqlite3_reset(s);
        sqlite3_clear_bindings(s);
        db_block_bind_insert(s, b);
        rc = AR_STEP_ROW_READONLY(s);
        if (rc == SQLITE_DONE)
            break;
        sqlite3_reset(s);
        if (!db_block_step_is_retryable(rc))
            break;
        sqlite3_sleep(DB_BLOCK_SAVE_RETRY_MS);
    }

    sqlite3_reset(s);
    ndb->last_sqlite_rc = rc;
    snprintf(ndb->last_op, sizeof(ndb->last_op), "%s", "db_block_save");
    if (locked_stmt)
        zcl_mutex_unlock(&ndb->state_mutex);

    bool ok = rc == SQLITE_DONE;
    if (!ok) {
        static int lock_err_count = 0;
        char hash_hex[65];
        HexStr(b->hash, 32, false, hash_hex, sizeof(hash_hex));
        if (db_block_step_is_retryable(rc)) {
            lock_err_count++;
            if (lock_err_count <= 3 || (lock_err_count % 1000 == 0)) {
                LOG_WARN("db_block_save", "db_block_save: locked stmt=block_insert " "height=%d hash=%s attempts=%d total=%d " "step_rc=%d step_msg=%s db_rc=%d db_msg=%s", b->height, hash_hex, attempts, lock_err_count, rc, sqlite3_errstr(rc), sqlite3_errcode(ndb->db), sqlite3_errmsg(ndb->db));
            }
        } else {
            LOG_WARN("db_block_save", "db_block_save: failed stmt=block_insert " "height=%d hash=%s step_rc=%d step_msg=%s " "db_rc=%d db_msg=%s attempts=%d", b->height, hash_hex, rc, sqlite3_errstr(rc), sqlite3_errcode(ndb->db), sqlite3_errmsg(ndb->db), attempts);
        }
    }

    AR_FINISH_SAVE(cbs, b, ok);
}

bool db_block_save_canonical(struct node_db *ndb, const struct db_block *b)
{
    if (!ndb || !ndb->open || !b)
        return false;

    bool has_conflict = false;
    db_block_reset_cached_readers(ndb);
    if (!db_block_has_canonical_conflict(ndb, b, &has_conflict))
        LOG_FAIL("db_block_save_canonical", "db_block_save_canonical: conflict check failed height=%d last_op=%s last_rc=%d", b->height, ndb->last_op, ndb->last_sqlite_rc);
    if (!has_conflict)
        return db_block_save(ndb, b);

    sqlite3_stmt *s = NULL;
    bool locked_stmt = false;
    if (ndb->state_mutex_init) {
        zcl_mutex_lock(&ndb->state_mutex);
        locked_stmt = true;
    }
    db_block_reset_cached_readers(ndb);

    int prep_rc = sqlite3_prepare_v2(ndb->db,
        "UPDATE blocks SET status=? "
        "WHERE height=? AND hash<>? AND status>=3",
        -1, &s, NULL);
    if (prep_rc != SQLITE_OK || !s) {
        char hash_hex[65];
        HexStr(b->hash, 32, false, hash_hex, sizeof(hash_hex));
        LOG_WARN("db_block_save_canonical", "db_block_save_canonical: prepare failed " "stmt=block_demote_same_height height=%d hash=%s " "prep_rc=%d prep_msg=%s db_rc=%d db_msg=%s", b->height, hash_hex, prep_rc, sqlite3_errstr(prep_rc), sqlite3_errcode(ndb->db), sqlite3_errmsg(ndb->db));
        if (s)
            sqlite3_finalize(s);
        if (locked_stmt)
            zcl_mutex_unlock(&ndb->state_mutex);
        return false;
    }

    AR_BIND_INT(s, 1, BLOCK_VALID_TREE);
    AR_BIND_INT(s, 2, b->height);
    AR_BIND_BLOB(s, 3, b->hash, 32);

    int demote_rc = SQLITE_OK;
    bool demoted = db_block_step_done_retry(ndb->db, s,
        "db_block_save_canonical: block_demote_same_height",
        b->height, b->hash, &demote_rc, NULL);
    sqlite3_finalize(s);
    ndb->last_sqlite_rc = demote_rc;
    snprintf(ndb->last_op, sizeof(ndb->last_op), "%s",
             "db_block_save_canonical.demote");
    int changed = sqlite3_changes(ndb->db);
    if (locked_stmt)
        zcl_mutex_unlock(&ndb->state_mutex);
    if (!demoted)
        return false;

    if (changed > 0) {
        char hash_hex[65];
        HexStr(b->hash, 32, false, hash_hex, sizeof(hash_hex));
        LOG_INFO("db_block_save_canonical", "db_block_save_canonical: demoted %d stale " "same-height projection row(s) height=%d hash=%s", changed, b->height, hash_hex);
    }

    db_block_reset_cached_readers(ndb);
    return db_block_save(ndb, b);
}

bool db_block_prepare_file_position_scan(sqlite3 *db,
                                         sqlite3_stmt **stmt_out)
{
    if (!db || !stmt_out)
        LOG_FAIL("block", "file-position scan prepare called with invalid arguments");

    *stmt_out = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT hash, height, file_num, data_pos, num_tx"
        " FROM blocks WHERE file_num >= 0"
        " ORDER BY file_num, data_pos",
        -1, stmt_out, NULL);
    if (rc != SQLITE_OK || !*stmt_out) {
        LOG_FAIL("block", "failed to prepare file-position scan: rc=%d msg=%s",
                 rc, sqlite3_errmsg(db));
    }
    return true;
}

/* ── Read helpers ──────────────────────────────────────────────── */

static void read_block_cols(sqlite3_stmt *s, int col,
                            struct db_block *out)
{
    AR_READ_BLOB(s, col, out->prev_hash, 32);     col++;
    out->version = (int)AR_COL_INT(s, col++);
    AR_READ_BLOB(s, col, out->merkle_root, 32);    col++;
    out->time = (uint32_t)AR_COL_INT(s, col++);
    out->bits = (uint32_t)AR_COL_INT(s, col++);
    AR_READ_BLOB(s, col, out->nonce, 32);          col++;
    out->solution_len = (size_t)AR_COL_BYTES(s, col);
    out->solution = NULL;                           col++;
    AR_READ_BLOB(s, col, out->chain_work, 32);     col++;
    out->status = (int)AR_COL_INT(s, col++);
    out->file_num = (int)AR_COL_INT(s, col++);
    out->data_pos = (int)AR_COL_INT(s, col++);
    out->undo_pos = (int)AR_COL_INT(s, col++);
    out->num_tx = (int)AR_COL_INT(s, col++);
    AR_READ_BLOB(s, col, out->sapling_root, 32);   col++;
    AR_READ_BLOB(s, col, out->sprout_root, 32);    col++;
    out->sapling_value = AR_COL_INT(s, col++);
    out->sprout_value = AR_COL_INT(s, col++);
}

/* ── Find ──────────────────────────────────────────────────────── */

bool db_block_find_by_hash(struct node_db *ndb,
                           const uint8_t hash[32],
                           struct db_block *out)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = ndb->stmt_block_by_hash;
    sqlite3_reset(s);
    AR_BIND_BLOB(s, 1, hash, 32);
    if (!AR_STEP_ROW(s)) {
        sqlite3_reset(s);
        return false;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->hash, hash, 32);
    out->height = (int)AR_COL_INT(s, 0);
    read_block_cols(s, 1, out);
    sqlite3_reset(s);
    return true;
}

bool db_block_find_by_height(struct node_db *ndb, int height,
                             struct db_block *out)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = ndb->stmt_block_by_height;
    sqlite3_reset(s);
    AR_BIND_INT(s, 1, height);
    if (!AR_STEP_ROW(s)) {
        sqlite3_reset(s);
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->height = height;
    AR_READ_BLOB(s, 0, out->hash, 32);
    read_block_cols(s, 1, out);
    sqlite3_reset(s);
    return true;
}

/* ── Solution accessor ─────────────────────────────────────────── */

/* Materialise the Equihash solution BLOB for a connected block.
 *
 * `status>=3` matches the canonical connected-block floor used by
 * db_block_max_height() and the idx_blocks_height unique index — we only
 * trust solutions on rows that won an active-chain slot. A NULL/empty
 * column, missing row, or oversize blob all return false so the caller
 * keeps failing Equihash validation rather than ever passing without a
 * verified solution. */
bool db_block_load_solution_by_height(struct node_db *ndb, int height,
                                      unsigned char *out, size_t *out_len,
                                      size_t max)
{
    if (out_len) *out_len = 0;
    if (!ndb || !ndb->open || !out || !out_len || max == 0) {
        /* LOG_WARN, not LOG_FAIL/LOG_NULL: those macros return for us and
         * LOG_NULL would yield NULL where a bool is expected. */
        LOG_WARN("block", "load_solution: null arg / closed db (height=%d)",
                 height);
        return false;
    }

    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT solution FROM blocks WHERE height=? AND status>=3",
        false);
    AR_BIND_INT(s, 1, height);

    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;   /* no connected row at this height */
    }

    int blen = AR_COL_BYTES(s, 0);
    const void *bdata = sqlite3_column_blob(s, 0);
    if (!bdata || blen <= 0) {
        AR_FINALIZE(s);
        return false;   /* solution column empty — backfill required */
    }
    if ((size_t)blen > max) {
        LOG_WARN("block", "load_solution: oversize solution height=%d "
                 "len=%d max=%zu", height, blen, max);
        AR_FINALIZE(s);
        return false;
    }

    memcpy(out, bdata, (size_t)blen);
    *out_len = (size_t)blen;
    AR_FINALIZE(s);
    return true;
}

bool db_block_load_header_by_hash_height(struct node_db *ndb, int height,
                                         const uint8_t hash[32],
                                         struct block_header *out)
{
    if (!ndb || !ndb->open || !hash || !out) {
        LOG_WARN("block", "load_header: null arg / closed db (height=%d)",
                 height);
        return false;
    }

    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT version,prev_hash,merkle_root,sapling_root,time,bits,"
        "nonce,solution FROM blocks "
        "WHERE height=? AND hash=? AND status>=3 LIMIT 1",
        false);
    AR_BIND_INT(s, 1, height);
    AR_BIND_BLOB(s, 2, hash, 32);

    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }

    int sol_len = AR_COL_BYTES(s, 7);
    const void *sol = sqlite3_column_blob(s, 7);
    if (!sol || sol_len <= 0 || sol_len > MAX_SOLUTION_SIZE) {
        if (sol_len > MAX_SOLUTION_SIZE)
            LOG_WARN("block", "load_header: oversize solution height=%d "
                     "len=%d", height, sol_len);
        AR_FINALIZE(s);
        return false;
    }

    block_header_init(out);
    out->nVersion = (int32_t)AR_COL_INT(s, 0);
    AR_READ_BLOB(s, 1, out->hashPrevBlock.data, 32);
    AR_READ_BLOB(s, 2, out->hashMerkleRoot.data, 32);
    AR_READ_BLOB(s, 3, out->hashFinalSaplingRoot.data, 32);
    out->nTime = (uint32_t)AR_COL_INT(s, 4);
    out->nBits = (uint32_t)AR_COL_INT(s, 5);
    AR_READ_BLOB(s, 6, out->nNonce.data, 32);
    memcpy(out->nSolution, sol, (size_t)sol_len);
    out->nSolutionSize = (size_t)sol_len;
    AR_FINALIZE(s);

    struct uint256 computed;
    block_header_get_hash(out, &computed);
    if (memcmp(computed.data, hash, 32) != 0) {
        uint64_t repeats = 0;
        if (log_throttle_should_emit(&g_header_mismatch_log, 0,
                                     platform_time_wall_unix(),
                                     DB_BLOCK_HEADER_MISMATCH_LOG_SECS,
                                     &repeats))
            LOG_WARN("block", "load_header: stored row does not hash-bind "
                     "height=%d repeats=%llu", height,
                     (unsigned long long)repeats);
        block_header_init(out);
        return false;
    }
    return true;
}

/* ── Raw header read (quarantine evidence) ─────────────────────── */

/* Column layout of BLOCK_RAW_HEADER_SEL: hash(0) version(1) prev_hash(2)
 * merkle_root(3) sapling_root(4) time(5) bits(6) nonce(7) solution(8). NO
 * status filter, NO hash-bind gate — the caller classifies the row. */
#define BLOCK_RAW_HEADER_SEL_COLS \
    "hash,version,prev_hash,merkle_root,sapling_root,time,bits,nonce,solution"

/* Reconstruct a canonical block_header from a BLOCK_RAW_HEADER_SEL row exactly
 * as stored. Returns false only when the Equihash solution column is
 * missing/empty/oversize (a header we cannot re-hash); every other field is a
 * fixed 32-byte / integer column read verbatim, so a poisoned value survives
 * into `out` for the caller's block_row_verify() to reject. sapling_root is a
 * nullable projection column — a NULL/short value leaves the field zero (which
 * only hash-binds for a genuinely pre-Sapling block; a post-Sapling row with a
 * dropped root then fails the caller's hash-bind, never silently passes). */
static bool block_raw_header_from_row(sqlite3_stmt *s, struct block_header *out,
                                      uint8_t out_stored_hash[32])
{
    if (out_stored_hash)
        AR_READ_BLOB(s, 0, out_stored_hash, 32);

    int sol_len = AR_COL_BYTES(s, 8);
    const void *sol = sqlite3_column_blob(s, 8);
    if (!sol || sol_len <= 0 || sol_len > MAX_SOLUTION_SIZE) {
        if (sol_len > MAX_SOLUTION_SIZE)
            LOG_WARN("block", "load_raw_header: oversize solution len=%d",
                     sol_len);
        return false;
    }

    block_header_init(out);
    out->nVersion = (int32_t)AR_COL_INT(s, 1);
    AR_READ_BLOB(s, 2, out->hashPrevBlock.data, 32);
    AR_READ_BLOB(s, 3, out->hashMerkleRoot.data, 32);
    AR_READ_BLOB(s, 4, out->hashFinalSaplingRoot.data, 32);
    out->nTime = (uint32_t)AR_COL_INT(s, 5);
    out->nBits = (uint32_t)AR_COL_INT(s, 6);
    AR_READ_BLOB(s, 7, out->nNonce.data, 32);
    memcpy(out->nSolution, sol, (size_t)sol_len);
    out->nSolutionSize = (size_t)sol_len;
    return true;
}

bool db_block_load_raw_header_by_hash(struct node_db *ndb,
                                      const uint8_t hash[32],
                                      struct block_header *out)
{
    if (!ndb || !ndb->open || !hash || !out) {
        LOG_WARN("block", "load_raw_header_by_hash: null arg / closed db");
        return false;
    }
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT " BLOCK_RAW_HEADER_SEL_COLS " FROM blocks WHERE hash=? LIMIT 1",
        false);
    AR_BIND_BLOB(s, 1, hash, 32);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    bool ok = block_raw_header_from_row(s, out, NULL);
    AR_FINALIZE(s);
    return ok;
}

bool db_block_load_raw_header_by_height(struct node_db *ndb, int height,
                                        struct block_header *out,
                                        uint8_t out_stored_hash[32])
{
    if (out_stored_hash)
        memset(out_stored_hash, 0, 32);
    if (!ndb || !ndb->open || !out) {
        LOG_WARN("block", "load_raw_header_by_height: null arg / closed db "
                 "(height=%d)", height);
        return false;
    }
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT " BLOCK_RAW_HEADER_SEL_COLS " FROM blocks WHERE height=? "
        "LIMIT 1", false);
    AR_BIND_INT(s, 1, height);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    bool ok = block_raw_header_from_row(s, out, out_stored_hash);
    AR_FINALIZE(s);
    return ok;
}

/* ── Delete ────────────────────────────────────────────────────── */

bool db_block_delete(struct node_db *ndb, const uint8_t hash[32])
{
    if (!ndb->open) return false;

    struct ar_callbacks *cbs = db_block_callbacks();
    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    memcpy(blk.hash, hash, 32);
    AR_BEGIN_DESTROY(cbs, &blk);

    /* dependent: :destroy — delete child transactions */
    sqlite3_stmt *dt = NULL;
    AR_PREPARE_OR(ndb, dt, "DELETE FROM transactions WHERE block_hash=?", dt = NULL);
    if (dt) {
        AR_BIND_BLOB(dt, 1, hash, 32);
        (void)AR_STEP_DONE(dt);
        AR_FINALIZE(dt);
    }

    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s, "DELETE FROM blocks WHERE hash=?");
    AR_BIND_BLOB(s, 1, hash, 32);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (ok)
        event_emitf(EV_MODEL_DESTROYED, 0, "model=block");
    AR_FINISH_DESTROY(cbs, &blk, ok);
}

/* Delete a `blocks` row by height. The header-only quarantine path uses this
 * ONLY when the row's `hash` column is missing/short — otherwise it cannot be
 * addressed by db_block_delete's 32-byte key. Runs through the AR destroy
 * lifecycle like db_block_delete; the record carries only the height (the
 * block destroy hooks do not inspect the hash). No transactions cascade: a
 * hashless imported header row cannot own transactions (their FK is
 * block_hash), and we have no hash to match. */
bool db_block_delete_by_height(struct node_db *ndb, int height)
{
    if (!ndb->open) {
        LOG_FAIL("block", "delete_by_height: db not open (height=%d)", height);
    }

    struct ar_callbacks *cbs = db_block_callbacks();
    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    blk.height = height;

    sqlite3_stmt *s = NULL;
    AR_ADHOC_DESTROY(ndb, s, "DELETE FROM blocks WHERE height=?", cbs, &blk,
                     AR_BIND_INT(s, 1, height));
}

/* ── Queries ───────────────────────────────────────────────────── */

int db_block_max_height(struct node_db *ndb)
{
    if (!ndb->open) return -1;
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT MAX(height) FROM blocks WHERE status>=3",
        -1);
    int h = -1;
    if (AR_STEP_ROW(s))
        h = (int)AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return h;
}

int db_block_max_height_any_status(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return -1;
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT MAX(height) FROM blocks",
        -1);
    int h = -1;
    if (AR_STEP_ROW(s))
        h = (int)AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return h;
}

int db_block_count(struct node_db *ndb)
{
    if (!ndb->open) return 0;
    AR_QUERY_COUNT_SQL(ndb, "SELECT COUNT(*) FROM blocks");
}

bool db_block_update_sapling_tree_data(struct node_db *ndb,
                                       const uint8_t hash[32],
                                       const uint8_t *tree_data,
                                       size_t tree_data_len)
{
    if (!ndb || !ndb->open || !hash || (!tree_data && tree_data_len > 0))
        LOG_FAIL("block", "update_sapling_tree_data: invalid args");
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "UPDATE blocks SET sapling_tree_data=? WHERE hash=?");
    if (sqlite3_bind_blob(s, 1, tree_data, (int)tree_data_len,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_blob(s, 2, hash, 32, SQLITE_STATIC) != SQLITE_OK) {
        AR_FINALIZE(s);
        LOG_FAIL("block", "update_sapling_tree_data: bind failed");
    }
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    return ok;
}

bool db_block_tip_height_and_time(struct node_db *ndb,
                                  int64_t *height_out, int64_t *time_out)
{
    if (height_out) *height_out = 0;
    if (time_out) *time_out = 0;
    if (!ndb || !ndb->open)
        return false;
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "SELECT COALESCE(MAX(height),0), COALESCE(MAX(time),0)"
        " FROM blocks WHERE status>=3");
    bool ok = false;
    if (AR_STEP_ROW(s)) {
        if (height_out) *height_out = AR_COL_INT(s, 0);
        if (time_out) *time_out = AR_COL_INT(s, 1);
        ok = true;
    }
    AR_FINALIZE(s);
    return ok;
}

/* ── Relationships ─────────────────────────────────────────────── */

/* has_many :transactions */
int db_block_transactions(struct node_db *ndb, const uint8_t hash[32],
                          struct db_tx_index *out, size_t max)
{
    return db_tx_find_by_block(ndb, hash, out, max);
}

/* belongs_to :prev_block */
bool db_block_prev(struct node_db *ndb, const struct db_block *b,
                   struct db_block *out)
{
    return db_block_find_by_hash(ndb, b->prev_hash, out);
}

/* has_one :next_block */
bool db_block_next(struct node_db *ndb, const struct db_block *b,
                   struct db_block *out)
{
    return db_block_find_by_height(ndb, b->height + 1, out);
}

/* ── Scope: hashes in height range ────────────────────────────── */

int db_block_hashes_in_range(struct node_db *ndb,
                             int start_height, int end_height,
                             uint8_t (*hashes_out)[32], size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT hash FROM blocks WHERE height >= ? "
        "AND height <= ? ORDER BY height ASC",
        hashes_out, max,
        AR_BIND_INT(s, 1, start_height);
        AR_BIND_INT(s, 2, end_height),
        AR_READ_BLOB(s, 0, hashes_out[count], 32));
}
