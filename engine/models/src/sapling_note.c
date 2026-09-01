/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: SaplingNote.
 *
 * SaplingNote:
 *   validates :txid, :ivk, :nullifier, :cm, :pk_d, :diversifier, :rcm, presence
 *   validates :value, money_range: [0, MAX_MONEY]
 *   validates :source, inclusion: [local, view]
 *   belongs_to :sapling_key */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/ar_step_readonly.h"
#include "models/wallet_tx.h"
#include "models/wallet_tx_internal.h"
#include "models/wallet_key.h"
#include "wallet/sapling_keys.h"
#include "chain/chainparams.h"
#include "event/event.h"
#include "storage/wallet_projection.h"
#include "util/safe_alloc.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ── Callbacks ─────────────────────────────────────────────────── */

DEFINE_MODEL_CALLBACKS(sapling_note)

static bool sapling_note_source_valid(const char *source)
{
    return source &&
           (strcmp(source, DB_SAPLING_NOTE_SOURCE_LOCAL) == 0 ||
            strcmp(source, DB_SAPLING_NOTE_SOURCE_VIEW) == 0);
}

static void sapling_note_default_source(struct db_sapling_note *n)
{
    if (n && n->source[0] == '\0')
        snprintf(n->source, sizeof(n->source), "%s",
                 DB_SAPLING_NOTE_SOURCE_LOCAL);
}

/* ── Validation ────────────────────────────────────────────────── */

bool db_sapling_note_validate(const struct db_sapling_note *n,
                               struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, n, txid);
    validates_money_range(errors, n, value, 2100000000000000LL);
    validates_presence_of(errors, n, ivk);
    validates_presence_of(errors, n, nullifier);
    validates_presence_of(errors, n, cm);
    validates_presence_of(errors, n, pk_d);
    validates_presence_of(errors, n, diversifier);
    validates_presence_of(errors, n, rcm);
    validates_max(errors, n, memo_len, 512);
    validates_non_negative(errors, n, block_height);
    validates_string_present(errors, n->source, "source");
    validates_custom(errors, sapling_note_source_valid(n->source), "source",
                     "must be local or view");
    if (n->is_spent) {
        static const uint8_t z[32] = {0};
        if (memcmp(n->spent_txid, z, 32) == 0)
            ar_errors_add(errors, "spent_txid", "can't be blank when spent");
    }
    return !ar_errors_any(errors);
}

/* ── Row Deserialization ──────────────────────────────────────── */

void db_sapling_note_read_row(sqlite3_stmt *s, int col,
                              struct db_sapling_note *out)
{
    memset(out, 0, sizeof(*out));
    AR_READ_BLOB(s, col, out->txid, 32);                   col++;
    out->output_index = (uint32_t)AR_COL_INT(s, col++);
    out->value = AR_COL_INT(s, col++);
    AR_READ_BLOB(s, col, out->rcm, 32);                    col++;
    /* memo: variable-length, capped at 512 */
    {
        int memo_len = AR_COL_BYTES(s, col);
        const void *memo = sqlite3_column_blob(s, col);
        if (memo && memo_len > 0) {
            size_t ml = (size_t)memo_len < 512 ? (size_t)memo_len : 512;
            memcpy(out->memo, memo, ml);
            out->memo_len = ml;
        }
    }
    col++;
    AR_READ_BLOB(s, col, out->ivk, 32);                    col++;
    AR_READ_BLOB(s, col, out->diversifier, 11);             col++;
    AR_READ_BLOB(s, col, out->pk_d, 32);                   col++;
    AR_READ_BLOB(s, col, out->cm, 32);                     col++;
    AR_READ_BLOB(s, col, out->nullifier, 32);              col++;
    if (sqlite3_column_type(s, col) != SQLITE_NULL)
        out->block_height = (int)AR_COL_INT(s, col);
    col++;
    if (col < sqlite3_column_count(s))
        AR_READ_STR(s, col, out->source, sizeof(out->source));
    sapling_note_default_source(out);

    /* Derive bech32 z-address from diversifier+pk_d for in-memory use. */
    const struct chain_params *cp = chain_params_get();
    if (cp)
        sapling_encode_payment_address(out->diversifier, out->pk_d,
            cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
            out->address, sizeof(out->address));
}

/* Read spent_txid from a column after the standard note columns */
void wallet_tx_read_spent_txid(sqlite3_stmt *s, int col,
                               struct db_sapling_note *n)
{
    const void *st = sqlite3_column_blob(s, col);
    if (st && sqlite3_column_bytes(s, col) >= 32) {
        memcpy(n->spent_txid, st, 32);
        n->is_spent = true;
    }
}

/* ── SaplingNote CRUD ─────────────────────────────────────────── */

bool db_sapling_note_save(struct node_db *ndb, const struct db_sapling_note *n)
{
    if (!ndb->open) return false;
    struct db_sapling_note *mut = (struct db_sapling_note *)n;
    sapling_note_default_source(mut);
    struct ar_callbacks *cbs = db_sapling_note_callbacks();
    AR_BEGIN_SAVE(cbs, "sapling_note", n, db_sapling_note_validate);

    /* Derive bech32 z-address if not already set */
    if (!mut->address[0]) {
        const struct chain_params *cp = chain_params_get();
        if (cp)
            sapling_encode_payment_address(mut->diversifier, mut->pk_d,
                cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                mut->address, sizeof(mut->address));
    }

    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "INSERT OR REPLACE INTO wallet_sapling_notes"
        "(txid,output_index,value,rcm,memo,ivk,diversifier,pk_d,cm,"
        "nullifier,block_height,spent_txid,address,source)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    AR_BIND_BLOB(s, 1, n->txid, 32);
    AR_BIND_INT(s, 2, (int)n->output_index);
    AR_BIND_INT(s, 3, n->value);
    AR_BIND_BLOB(s, 4, n->rcm, 32);
    if (n->memo_len > 0)
        AR_BIND_BLOB(s, 5, n->memo, (int)n->memo_len);
    else
        AR_BIND_NULL(s, 5);
    AR_BIND_BLOB(s, 6, n->ivk, 32);
    AR_BIND_BLOB(s, 7, n->diversifier, 11);
    AR_BIND_BLOB(s, 8, n->pk_d, 32);
    AR_BIND_BLOB(s, 9, n->cm, 32);
    AR_BIND_BLOB(s, 10, n->nullifier, 32);
    if (n->block_height > 0)
        AR_BIND_INT(s, 11, n->block_height);
    else
        AR_BIND_NULL(s, 11);
    if (n->is_spent)
        AR_BIND_BLOB(s, 12, n->spent_txid, 32);
    else
        AR_BIND_NULL(s, 12);
    if (n->address[0])
        AR_BIND_TEXT(s, 13, n->address);
    else
        AR_BIND_NULL(s, 13);
    AR_BIND_TEXT(s, 14, n->source);
    bool ok = AR_STEP_DONE(s);
    AR_FINALIZE(s);
    if (ok && !wallet_projection_emit_note_decrypted(
            n->txid, n->output_index, n->value, n->cm, n->block_height)) {
        LOG_WARN("wallet_projection", "[wallet_projection] note decrypted projection emit failed");
    }
    AR_FINISH_SAVE(cbs, n, ok);
}

enum db_mark_spent_result db_sapling_note_mark_spent(
                                struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spent_by[32])
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !nullifier || !spent_by)
        return DB_MARK_SPENT_ERROR;
    AR_PREPARE_BOOL(ndb, s,
        "UPDATE wallet_sapling_notes SET spent_txid=?"
        " WHERE nullifier=?");
    AR_BIND_BLOB(s, 1, spent_by, 32);
    AR_BIND_BLOB(s, 2, nullifier, 32);
    {
        bool ok = false;
        AR_FINALIZE_STEP_DONE(s, ok);
        /* ok==false  → the UPDATE statement itself failed (busy/error/
         *              corrupt) — a REAL write error, fatal.
         * ok==true but changes()==0 → statement ran fine, no row matched
         *              this nullifier: the note is simply not in our index
         *              (we only track wallet notes). BENIGN — caller skips. */
        if (!ok)
            return DB_MARK_SPENT_ERROR;
        return sqlite3_changes(ndb->db) > 0
            ? DB_MARK_SPENT_OK
            : DB_MARK_SPENT_NOT_FOUND;
    }
}

enum db_mark_spent_result db_sapling_note_reserve_spend(
                                struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spent_by[32])
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !nullifier || !spent_by)
        return DB_MARK_SPENT_ERROR;
    AR_PREPARE_BOOL(ndb, s,
        "UPDATE wallet_sapling_notes SET spent_txid=?"
        " WHERE nullifier=? AND (spent_txid IS NULL OR spent_txid=?)");
    AR_BIND_BLOB(s, 1, spent_by, 32);
    AR_BIND_BLOB(s, 2, nullifier, 32);
    AR_BIND_BLOB(s, 3, spent_by, 32);
    {
        bool ok = false;
        AR_FINALIZE_STEP_DONE(s, ok);
        if (!ok)
            return DB_MARK_SPENT_ERROR;
        return sqlite3_changes(ndb->db) > 0
            ? DB_MARK_SPENT_OK
            : DB_MARK_SPENT_NOT_FOUND;
    }
}

bool db_sapling_note_release_reservation(struct node_db *ndb,
                                         const uint8_t spent_by[32])
{
    if (!ndb || !ndb->open || !spent_by)
        LOG_FAIL("sapling_note", "release reservation: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "UPDATE wallet_sapling_notes SET spent_txid=NULL WHERE spent_txid=?");
    AR_BIND_BLOB(s, 1, spent_by, 32);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    return ok;
}

enum db_sapling_note_reservation_state db_sapling_note_reservation_probe(
                                struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spending_txid[32])
{
    if (!ndb || !ndb->open || !nullifier || !spending_txid) {
        LOG_ERROR("sapling_note", "reservation probe: invalid argument");
        return DB_NOTE_RESERVATION_ERROR;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT spent_txid FROM wallet_sapling_notes "
            "WHERE nullifier=? LIMIT 1", -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_ERROR("sapling_note", "reservation probe prepare failed: %s",
                  sqlite3_errmsg(ndb->db));
        if (s) sqlite3_finalize(s);
        return DB_NOTE_RESERVATION_ERROR;
    }
    sqlite3_bind_blob(s, 1, nullifier, 32, SQLITE_TRANSIENT);
    int rc = AR_STEP_ROW_READONLY(s);
    enum db_sapling_note_reservation_state state =
        DB_NOTE_RESERVATION_ERROR;
    if (rc == SQLITE_DONE) {
        state = DB_NOTE_RESERVATION_MISSING;
    } else if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(s, 0) == SQLITE_NULL) {
            state = DB_NOTE_RESERVATION_AVAILABLE;
        } else {
            const uint8_t *spent = sqlite3_column_blob(s, 0);
            int spent_len = sqlite3_column_bytes(s, 0);
            state = spent && spent_len == 32 &&
                    memcmp(spent, spending_txid, 32) == 0
                ? DB_NOTE_RESERVATION_SAME_TX
                : DB_NOTE_RESERVATION_CONFLICT;
        }
    } else {
        LOG_ERROR("sapling_note", "reservation probe step failed: %s",
                  sqlite3_errmsg(ndb->db));
    }
    sqlite3_finalize(s);
    return state;
}

bool db_sapling_note_mark_spent_bool_compat(struct node_db *ndb,
                                const uint8_t nullifier[32],
                                const uint8_t spent_by[32])
{
    return db_sapling_note_mark_spent(ndb, nullifier, spent_by)
           == DB_MARK_SPENT_OK;
}

int64_t db_sapling_note_balance(struct node_db *ndb)
{
    return db_sapling_note_balance_with_count(ndb, NULL);
}

int64_t db_sapling_note_encumbered_balance(struct node_db *ndb)
{
    int64_t total = 0;
    int count = 0;

    (void)wallet_tx_query_total_and_count(ndb,
        "SELECT COALESCE(SUM(n.value),0), COUNT(*) "
        "FROM wallet_sapling_notes n "
        "JOIN wallet_transactions w ON w.txid=n.spent_txid "
        "WHERE n.spent_txid IS NOT NULL "
        "AND (w.block_hash IS NULL OR length(w.block_hash)!=32 "
        "OR w.block_hash=zeroblob(32))",
        NULL, 0, &total, &count);
    return total;
}

int64_t db_sapling_note_balance_with_count(struct node_db *ndb, int *note_count)
{
    int64_t total = 0;
    int count = 0;

    (void)wallet_tx_query_total_and_count(ndb,
        "SELECT COALESCE(SUM(n.value),0), COUNT(*) "
        "FROM wallet_sapling_notes n "
        "WHERE n.spent_txid IS NULL",
        NULL, 0, &total, &count);
    if (note_count)
        *note_count = count;
    return total;
}

int64_t db_sapling_note_balance_for_ivk(struct node_db *ndb,
                                        const uint8_t ivk[32])
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(value),0) FROM wallet_sapling_notes"
        " WHERE ivk=? AND spent_txid IS NULL",
        AR_BIND_BLOB(s, 1, ivk, 32));
}

int64_t db_sapling_note_balance_for_ivk_minconf(struct node_db *ndb,
                                                const uint8_t ivk[32],
                                                int tip_height, int minconf)
{
    if (!ndb || !ndb->open) return 0;
    /* minconf<=0 → no confirmation requirement (count everything unspent). */
    if (minconf <= 0)
        return db_sapling_note_balance_for_ivk(ndb, ivk);

    /* A note at block_height h has (tip - h + 1) confirmations; require that to
     * be >= minconf, i.e. block_height <= tip - minconf + 1. Unconfirmed notes
     * (NULL block_height) never satisfy minconf>=1 and are excluded. */
    int max_height = tip_height - minconf + 1;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(value),0) FROM wallet_sapling_notes"
        " WHERE ivk=? AND spent_txid IS NULL"
        "   AND block_height IS NOT NULL AND block_height >= 1"
        "   AND block_height <= ?",
        AR_BIND_BLOB(s, 1, ivk, 32);
        AR_BIND_INT(s, 2, max_height));
}

int64_t db_sapling_note_balance_for_address(struct node_db *ndb,
                                            const char *address)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || !address || address[0] == '\0')
        return 0;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(value),0) FROM wallet_sapling_notes "
        "WHERE spent_txid IS NULL AND address=?",
        AR_BIND_TEXT(s, 1, address));
}

int64_t db_sapling_note_balance_for_exact_value(struct node_db *ndb,
                                                int64_t value)
{
    sqlite3_stmt *s = NULL;

    if (!ndb || !ndb->open || value <= 0)
        return 0;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COALESCE(SUM(value),0) FROM wallet_sapling_notes "
        "WHERE spent_txid IS NULL AND value=?",
        AR_BIND_INT(s, 1, value));
}

int db_sapling_note_list_unspent(struct node_db *ndb,
                                 struct db_sapling_note *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid,output_index,value,rcm,memo,ivk,diversifier,pk_d,"
        "cm,nullifier,block_height,source"
        " FROM wallet_sapling_notes WHERE spent_txid IS NULL"
        " ORDER BY value DESC",
        out, max,
        (void)0,
        db_sapling_note_read_row(s, 0, &out[count]));
}

int db_sapling_note_count_unspent(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return 0;
    AR_QUERY_COUNT_SQL(ndb,
        "SELECT COUNT(*) FROM wallet_sapling_notes WHERE spent_txid IS NULL");
}

bool db_sapling_note_witness_summary(
    struct node_db *ndb, int tip_height,
    struct db_sapling_witness_summary *out)
{
    sqlite3_stmt *s = NULL;

    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->tip_height = tip_height;
    if (!ndb || !ndb->open || tip_height < 0)
        return false;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*),"
            " COALESCE(SUM(CASE WHEN witness_data IS NOT NULL"
            " AND length(witness_data)>0 AND witness_height=?"
            " THEN 1 ELSE 0 END),0),"
            " COALESCE(SUM(CASE WHEN witness_data IS NULL"
            " OR length(witness_data)=0 THEN 1 ELSE 0 END),0),"
            " COALESCE(SUM(CASE WHEN witness_data IS NOT NULL"
            " AND length(witness_data)>0 AND witness_height!=?"
            " THEN 1 ELSE 0 END),0)"
            " FROM wallet_sapling_notes"
            " WHERE spent_txid IS NULL AND source=?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    AR_BIND_INT(s, 1, tip_height);
    AR_BIND_INT(s, 2, tip_height);
    AR_BIND_TEXT(s, 3, DB_SAPLING_NOTE_SOURCE_LOCAL);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    out->local_unspent_notes = (int)AR_COL_INT(s, 0);
    out->ready_notes = (int)AR_COL_INT(s, 1);
    out->missing_notes = (int)AR_COL_INT(s, 2);
    out->stale_notes = (int)AR_COL_INT(s, 3);
    AR_FINALIZE(s);
    return out->local_unspent_notes >= 0 && out->ready_notes >= 0 &&
           out->missing_notes >= 0 && out->stale_notes >= 0 &&
           out->ready_notes + out->missing_notes + out->stale_notes ==
               out->local_unspent_notes;
}

int db_sapling_note_count_unspent_view_for_address(struct node_db *ndb,
                                                   const char *address)
{
    if (!ndb || !ndb->open || !address || address[0] == '\0')
        return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_COUNT_BOUND(ndb, s,
        "SELECT COUNT(*) FROM wallet_sapling_notes"
        " WHERE spent_txid IS NULL AND source=? AND address=?",
        AR_BIND_TEXT(s, 1, DB_SAPLING_NOTE_SOURCE_VIEW);
        AR_BIND_TEXT(s, 2, address));
}

int db_sapling_note_list_unspent_alloc(struct node_db *ndb,
                                       struct db_sapling_note **out)
{
    if (!out) return -1;
    *out = NULL;
    if (!ndb || !ndb->open) return -1;

    int n = db_sapling_note_count_unspent(ndb);
    if (n <= 0)
        return 0;

    /* Size to the live count; re-read may see a couple extra rows if a write
     * raced, so the fixed-size load below simply stops at our allocated count
     * (correct: AR_QUERY_LIST honors max). A short-read is also fine. */
    struct db_sapling_note *buf =
        zcl_calloc((size_t)n, sizeof(struct db_sapling_note),
                   "sapling notes unspent");
    if (!buf)
        return -1;

    int got = db_sapling_note_list_unspent(ndb, buf, (size_t)n);
    *out = buf;
    return got;
}

int db_sapling_note_list_unspent_for_ivk(struct node_db *ndb,
                                          const uint8_t ivk[32],
                                          struct db_sapling_note *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid,output_index,value,rcm,memo,ivk,diversifier,pk_d,"
        "cm,nullifier,block_height,source"
        " FROM wallet_sapling_notes WHERE spent_txid IS NULL AND ivk=?"
        " ORDER BY value DESC",
        out, max,
        AR_BIND_BLOB(s, 1, ivk, 32),
        db_sapling_note_read_row(s, 0, &out[count]));
}

int db_sapling_note_list_all(struct node_db *ndb,
                              struct db_sapling_note *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid,output_index,value,rcm,memo,ivk,diversifier,pk_d,"
        "cm,nullifier,block_height,source,spent_txid"
        " FROM wallet_sapling_notes ORDER BY block_height DESC",
        out, max,
        (void)0,
        db_sapling_note_read_row(s, 0, &out[count]);
        wallet_tx_read_spent_txid(s, 12, &out[count]));
}

/* Read one coinanalysis row. The z-address is derived only when both
 * diversifier and pk_d are present AND correctly sized; malformed rows
 * (NULL or truncated blobs) leave the emitted address empty. */
static void sapling_note_read_analysis_row(sqlite3_stmt *s,
                                            struct db_sapling_note *n)
{
    memset(n, 0, sizeof(*n));
    AR_READ_BLOB(s, 0, n->txid, 32);
    n->output_index = (uint32_t)AR_COL_INT(s, 1);
    n->value = AR_COL_INT(s, 2);
    n->block_height = (int)AR_COL_INT(s, 3);
    wallet_tx_read_spent_txid(s, 4, n);
    const void *ndiv = sqlite3_column_blob(s, 5);
    const void *npkd = sqlite3_column_blob(s, 6);
    AR_READ_BLOB(s, 5, n->diversifier, 11);
    AR_READ_BLOB(s, 6, n->pk_d, 32);
    n->witness_height = (int)AR_COL_INT(s, 7);
    if (ndiv && npkd &&
        sqlite3_column_bytes(s, 5) == 11 && sqlite3_column_bytes(s, 6) == 32)
        sapling_encode_payment_address(n->diversifier, n->pk_d,
                                       "zs", n->address, sizeof(n->address));
}

int db_sapling_note_list_all_analysis(struct node_db *ndb,
                                      struct db_sapling_note *out, size_t max)
{
    if (!ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT txid, output_index, value, block_height, spent_txid,"
        " diversifier, pk_d, witness_height"
        " FROM wallet_sapling_notes ORDER BY block_height",
        out, max,
        (void)0,
        sapling_note_read_analysis_row(s, &out[count]));
}

bool db_sapling_note_save_witness(struct node_db *ndb,
                                   const uint8_t txid[32], uint32_t output_index,
                                   const uint8_t *witness_blob, size_t blob_len,
                                   int height)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "UPDATE wallet_sapling_notes SET witness_data=?,witness_height=?"
        " WHERE txid=? AND output_index=?",
        -1, &s, NULL);
    if (!s) LOG_FAIL("sapling_note", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, witness_blob, (int)blob_len);
    AR_BIND_INT(s, 2, height);
    AR_BIND_BLOB(s, 3, txid, 32);
    AR_BIND_INT(s, 4, (int)output_index);
    bool ok = AR_STEP_DONE(s);
    AR_FINALIZE(s);
    return ok;
}

bool db_sapling_note_save_witness_and_nullifier(
    struct node_db *ndb, const uint8_t txid[32], uint32_t output_index,
    const uint8_t *witness_blob, size_t blob_len, int height,
    const uint8_t nullifier[32])
{
    if (!ndb || !ndb->open || !txid || !witness_blob || blob_len == 0 ||
        !nullifier)
        return false;
    struct db_sapling_note note;
    sqlite3_stmt *read = NULL;
    AR_PREPARE_BOOL(ndb, read,
        "SELECT txid,output_index,value,rcm,memo,ivk,diversifier,pk_d,cm,"
        "nullifier,block_height,source FROM wallet_sapling_notes"
        " WHERE txid=? AND output_index=?");
    AR_BIND_BLOB(read, 1, txid, 32);
    AR_BIND_INT(read, 2, (int)output_index);
    if (!AR_STEP_ROW(read)) {
        AR_FINALIZE(read);
        return false;
    }
    db_sapling_note_read_row(read, 0, &note);
    AR_FINALIZE(read);
    memcpy(note.nullifier, nullifier, sizeof(note.nullifier));

    struct ar_callbacks *cbs = db_sapling_note_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "UPDATE wallet_sapling_notes SET witness_data=?,witness_height=?,"
        " nullifier=? WHERE txid=? AND output_index=?",
        cbs, "sapling_note", &note, db_sapling_note_validate,
        AR_BIND_BLOB(s, 1, witness_blob, (int)blob_len);
        AR_BIND_INT(s, 2, height);
        AR_BIND_BLOB(s, 3, note.nullifier, 32);
        AR_BIND_BLOB(s, 4, note.txid, 32);
        AR_BIND_INT(s, 5, (int)note.output_index));
}

bool db_sapling_note_load_witness(struct node_db *ndb,
                                   const uint8_t txid[32], uint32_t output_index,
                                   uint8_t **witness_blob_out, size_t *blob_len_out,
                                   int *height_out)
{
    if (!ndb->open) return false;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "SELECT witness_data,witness_height FROM wallet_sapling_notes"
        " WHERE txid=? AND output_index=?",
        -1, &s, NULL);
    if (!s) LOG_FAIL("sapling_note", "prepare failed: %s", sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)output_index);
    if (!AR_STEP_ROW(s)) { AR_FINALIZE(s); return false; }

    int wlen = AR_COL_BYTES(s, 0);
    const void *wdata = sqlite3_column_blob(s, 0);
    if (!wdata || wlen <= 0 || wlen > 8192) { AR_FINALIZE(s); return false; }

    *witness_blob_out = zcl_malloc((size_t)wlen, "wallet_tx witness blob");
    if (!*witness_blob_out) { AR_FINALIZE(s); return false; }
    memcpy(*witness_blob_out, wdata, (size_t)wlen);
    *blob_len_out = (size_t)wlen;
    if (height_out)
        *height_out = (int)AR_COL_INT(s, 1);
    AR_FINALIZE(s);
    return true;
}

bool db_sapling_note_delete_all(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return false;
    return node_db_exec(ndb, "DELETE FROM wallet_sapling_notes");
}

bool db_sapling_note_delete(struct node_db *ndb, const uint8_t txid[32],
                            uint32_t output_index)
{
    if (!ndb || !ndb->open || !txid)
        return false; /* raw-return-ok:invalid delete key is caller error */
    struct db_sapling_note note;
    memset(&note, 0, sizeof(note));
    memcpy(note.txid, txid, sizeof(note.txid));
    note.output_index = output_index;
    struct ar_callbacks *cbs = db_sapling_note_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_DESTROY(ndb, s,
        "DELETE FROM wallet_sapling_notes WHERE txid=? AND output_index=?",
        cbs, &note,
        AR_BIND_BLOB(s, 1, txid, 32);
        AR_BIND_INT(s, 2, (int)output_index));
}

bool db_sapling_note_delete_for_tx(struct node_db *ndb,
                                   const uint8_t txid[32])
{
    if (!ndb || !ndb->open || !txid)
        return false;
    for (;;) {
        sqlite3_stmt *s = NULL;
        AR_PREPARE_BOOL(ndb, s,
            "SELECT output_index FROM wallet_sapling_notes"
            " WHERE txid=? LIMIT 1");
        AR_BIND_BLOB(s, 1, txid, 32);
        if (!AR_STEP_ROW(s)) {
            AR_FINALIZE(s);
            return true;
        }
        uint32_t output_index = (uint32_t)AR_COL_INT(s, 0);
        AR_FINALIZE(s);
        if (!db_sapling_note_delete(ndb, txid, output_index))
            LOG_FAIL("sapling_note",
                     "delete_for_tx: deleting one note row failed");
    }
}

bool db_sapling_note_replace_all(struct node_db *ndb,
                                 const struct db_sapling_note *rows,
                                 size_t count)
{
    size_t i = 0;
    bool ok = true;

    if (!ndb || !ndb->open)
        return false;
    if (count > 0 && !rows)
        return false;

    ok = node_db_begin(ndb);
    ok = ok && db_sapling_note_delete_all(ndb);
    for (i = 0; ok && i < count; i++)
        ok = db_sapling_note_save(ndb, &rows[i]);
    if (!ok) {
        node_db_rollback(ndb);
        return false;
    }
    return node_db_commit(ndb);
}

static bool db_sapling_note_delete_view_rows(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return false;
    sqlite3_stmt *s = NULL;
    AR_EXEC_BOOL(ndb, s,
        "DELETE FROM wallet_sapling_notes WHERE source=?",
        AR_BIND_TEXT(s, 1, DB_SAPLING_NOTE_SOURCE_VIEW));
}

bool db_sapling_note_replace_view_rows(struct node_db *ndb,
                                       const struct db_sapling_note *rows,
                                       size_t count)
{
    size_t i = 0;
    bool ok = true;

    if (!ndb || !ndb->open)
        return false;
    if (count > 0 && !rows)
        return false;

    ok = node_db_begin(ndb);
    ok = ok && db_sapling_note_delete_view_rows(ndb);
    for (i = 0; ok && i < count; i++) {
        struct db_sapling_note row = rows[i];
        snprintf(row.source, sizeof(row.source), "%s",
                 DB_SAPLING_NOTE_SOURCE_VIEW);
        ok = db_sapling_note_save(ndb, &row);
    }
    if (!ok) {
        node_db_rollback(ndb);
        return false;
    }
    return node_db_commit(ndb);
}

void db_sapling_note_free(struct db_sapling_note *n)
{
    if (!n) return;
    free(n->witness_data);
    n->witness_data = NULL;
    n->witness_data_len = 0;
}

/* ── Relationships ─────────────────────────────────────────────── */

/* SaplingNote belongs_to :sapling_key */
bool db_sapling_note_key(struct node_db *ndb, const struct db_sapling_note *n,
                         struct db_sapling_key *out)
{
    return db_sapling_key_find_by_ivk(ndb, n->ivk, out);
}
