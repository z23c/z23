/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ActiveRecord projection for buyer-signed file-market payment claims.
 * Exact claim/offer wires survive restart; their mutable reconciliation
 * status never replaces wallet-note or canonical-chain authority. */

#include "models/market_payment_claim.h"

#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(market_payment_claim)

static bool market_payment_status_valid(const char *status)
{
    return status &&
        (strcmp(status, "PENDING") == 0 ||
         strcmp(status, "CONFIRMED") == 0 ||
         strcmp(status, "UNKNOWN") == 0 ||
         strcmp(status, "CONFLICTED") == 0 ||
         strcmp(status, "REJECTED") == 0);
}

bool db_market_payment_claim_validate(
    const struct market_payment_claim_record *record,
    struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!record) {
        ar_errors_add(errors, "record", "is NULL");
        return false;
    }
    validates_custom(errors,
        file_payment_auth_verify_for_offer(&record->payment,
                                            &record->offer) ==
            FILE_PAYMENT_AUTH_OK,
        "claim_wire", "must verify against the signed offer");
    validates_custom(errors, market_payment_status_valid(record->status),
                     "status", "is invalid");
    validates_string_present(errors, record->status_reason,
                             "status_reason");
    validates_range(errors, record, output_index, -1, INT32_MAX);
    validates_non_negative(errors, record, block_height);
    validates_non_negative(errors, record, confirmations);
    validates_positive(errors, record, observed_at);
    validates_non_negative(errors, record, reconciled_at);
    if (strcmp(record->status, "CONFIRMED") == 0) {
        validates_custom(errors,
            record->output_index >= 0 && record->block_height > 0 &&
            record->confirmations >= (int)FILE_MARKET_PAYMENT_MIN_CONFIRMATIONS,
            "status", "confirmed requires canonical output and confirmations");
    }
    return !ar_errors_any(errors);
}

bool db_market_payment_claim_save(
    struct node_db *ndb, const struct market_payment_claim_record *record)
{
    uint8_t claim_wire[FILE_MARKET_PAYMENT_WIRE_BYTES];
    uint8_t offer_wire[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
    size_t offer_wire_len = 0;
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "payment claim save: database is not open");
    if (!record)
        LOG_FAIL("market", "payment claim save: record is NULL");
    if (file_payment_auth_encode(&record->payment, claim_wire) !=
            FILE_PAYMENT_AUTH_OK ||
        file_offer_auth_encode_into(&record->offer, offer_wire,
                                    sizeof(offer_wire),
                                    &offer_wire_len) != FILE_OFFER_AUTH_OK)
        LOG_FAIL("market", "payment claim save: canonical wire encode failed");

    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs = db_market_payment_claim_callbacks();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO market_payment_claims("
        "claim_id,offer_id,txid,buyer_pubkey,chunk_start,chunks_paid,"
        "amount_zat,claim_wire,offer_wire,status,status_reason,output_index,"
        "block_height,confirmations,observed_at,reconciled_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(claim_id) DO UPDATE SET "
        "status=excluded.status,status_reason=excluded.status_reason,"
        "output_index=excluded.output_index,"
        "block_height=excluded.block_height,"
        "confirmations=excluded.confirmations,"
        "reconciled_at=excluded.reconciled_at",
        cbs, "market_payment_claim", record,
        db_market_payment_claim_validate,
        AR_BIND_BLOB(s, 1, record->payment.claim_id, 32);
        AR_BIND_BLOB(s, 2, record->payment.offer_id, 32);
        AR_BIND_BLOB(s, 3, record->payment.txid, 32);
        AR_BIND_BLOB(s, 4, record->payment.buyer_pubkey, 32);
        AR_BIND_INT(s, 5, record->payment.chunk_start);
        AR_BIND_INT(s, 6, record->payment.chunks_paid);
        AR_BIND_INT(s, 7, record->payment.amount_zat);
        AR_BIND_BLOB(s, 8, claim_wire, sizeof(claim_wire));
        AR_BIND_BLOB(s, 9, offer_wire, (int)offer_wire_len);
        AR_BIND_TEXT(s, 10, record->status);
        AR_BIND_TEXT(s, 11, record->status_reason);
        AR_BIND_INT(s, 12, record->output_index);
        AR_BIND_INT(s, 13, record->block_height);
        AR_BIND_INT(s, 14, record->confirmations);
        AR_BIND_INT(s, 15, record->observed_at);
        AR_BIND_INT(s, 16, record->reconciled_at));
}

static bool market_payment_claim_read_row(
    sqlite3_stmt *s, struct market_payment_claim_record *out)
{
    const uint8_t *claim_wire = sqlite3_column_blob(s, 0);
    const uint8_t *offer_wire = sqlite3_column_blob(s, 1);
    int claim_len = sqlite3_column_bytes(s, 0);
    int offer_len = sqlite3_column_bytes(s, 1);
    if (!claim_wire || claim_len != (int)FILE_MARKET_PAYMENT_WIRE_BYTES ||
        !offer_wire ||
        (offer_len != (int)FILE_MARKET_OFFER_WIRE_BYTES &&
         offer_len != (int)FILE_MARKET_OFFER_WIRE_BYTES_V2))
        LOG_FAIL("market", "payment claim row has malformed wire lengths");

    memset(out, 0, sizeof(*out));
    if (file_payment_auth_decode(claim_wire, (size_t)claim_len,
                                 &out->payment) != FILE_PAYMENT_AUTH_OK ||
        file_offer_auth_decode(offer_wire, (size_t)offer_len,
                               &out->offer) != FILE_OFFER_AUTH_OK)
        LOG_FAIL("market", "payment claim row canonical decode failed");
    AR_READ_STR(s, 2, out->status, sizeof(out->status));
    AR_READ_STR(s, 3, out->status_reason, sizeof(out->status_reason));
    out->output_index = (int)AR_COL_INT(s, 4);
    out->block_height = (int)AR_COL_INT(s, 5);
    out->confirmations = (int)AR_COL_INT(s, 6);
    out->observed_at = AR_COL_INT(s, 7);
    out->reconciled_at = AR_COL_INT(s, 8);
    return true;
}

bool db_market_payment_claim_find(
    struct node_db *ndb, const uint8_t claim_id[32],
    struct market_payment_claim_record *out)
{
    if (!ndb || !ndb->open || !claim_id || !out)
        LOG_FAIL("market", "payment claim find: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT claim_wire,offer_wire,status,status_reason,output_index,"
        "block_height,confirmations,observed_at,reconciled_at "
        "FROM market_payment_claims WHERE claim_id=?",
        AR_BIND_BLOB(s, 1, claim_id, 32),
        if (!market_payment_claim_read_row(s, out)) {
            AR_FINALIZE(s);
            return false;
        });
}

int db_market_payment_claim_list_for_buyer(
    struct node_db *ndb, const uint8_t offer_id[32],
    const uint8_t buyer_pubkey[32],
    struct market_payment_claim_record *out, size_t max)
{
    if (!ndb || !ndb->open || !offer_id || !buyer_pubkey ||
        (!out && max > 0))
        LOG_RETURN(0, "market", "payment claim list: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT claim_wire,offer_wire,status,status_reason,output_index,"
        "block_height,confirmations,observed_at,reconciled_at "
        "FROM market_payment_claims WHERE offer_id=? AND buyer_pubkey=? "
        "ORDER BY chunk_start",
        out, max,
        AR_BIND_BLOB(s, 1, offer_id, 32);
        AR_BIND_BLOB(s, 2, buyer_pubkey, 32),
        if (!market_payment_claim_read_row(s, &out[count])) continue);
}

int db_market_payment_claim_list_for_chunk(
    struct node_db *ndb, const uint8_t offer_id[32],
    const uint8_t buyer_pubkey[32], uint32_t chunk_index,
    struct market_payment_claim_record *out, size_t max)
{
    if (!ndb || !ndb->open || !offer_id || !buyer_pubkey ||
        (!out && max > 0))
        LOG_RETURN(0, "market", "payment chunk claim list: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT claim_wire,offer_wire,status,status_reason,output_index,"
        "block_height,confirmations,observed_at,reconciled_at "
        "FROM market_payment_claims WHERE offer_id=? AND buyer_pubkey=? "
        "AND chunk_start<=? AND chunks_paid>? - chunk_start "
        "ORDER BY chunk_start DESC",
        out, max,
        AR_BIND_BLOB(s, 1, offer_id, 32);
        AR_BIND_BLOB(s, 2, buyer_pubkey, 32);
        AR_BIND_INT(s, 3, chunk_index);
        AR_BIND_INT(s, 4, chunk_index),
        if (!market_payment_claim_read_row(s, &out[count])) continue);
}

int db_market_payment_claim_count_for_offer(
    struct node_db *ndb, const uint8_t offer_id[32])
{
    if (!ndb || !ndb->open || !offer_id)
        LOG_RETURN(0, "market", "payment claim offer count: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_QUERY_COUNT_BOUND(ndb, s,
        "SELECT COUNT(*) FROM market_payment_claims WHERE offer_id=?",
        AR_BIND_BLOB(s, 1, offer_id, 32));
}

/* Settlement evidence only: a CONFIRMED row always survives this prune. */
int db_market_payment_claim_prune_unconfirmed_for_offer(
    struct node_db *ndb, const uint8_t offer_id[32])
{
    if (!ndb || !ndb->open || !offer_id)
        LOG_RETURN(0, "market", "payment claim prune: invalid arguments");
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "DELETE FROM market_payment_claims "
        "WHERE offer_id=? AND status<>'CONFIRMED'", 0);
    AR_BIND_BLOB(s, 1, offer_id, 32);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    return ok ? sqlite3_changes(ndb->db) : 0;
}

enum market_payment_authority_state db_market_payment_observe_authority(
    struct node_db *ndb, const struct file_payment *payment,
    const char *seller_address,
    const uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES],
    int tip_height, const uint8_t tip_hash[32],
    struct market_payment_authority_observation *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!ndb || !ndb->open || !payment || !seller_address ||
        !seller_address[0] || !memo || tip_height < 0 || !tip_hash || !out) {
        LOG_ERR("market", "payment authority observation has invalid inputs");
        return MARKET_PAYMENT_AUTHORITY_UNKNOWN;
    }

    /* The active in-memory tip and SQLite canonical projection must name the
     * same block. Otherwise an absent payment is ambiguous, never pending or
     * zero. */
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*) FROM blocks "
            "WHERE hash=? AND height=? AND status>=3",
            -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_ERR("market", "payment authority tip query prepare failed: %s",
                sqlite3_errmsg(ndb->db));
        return MARKET_PAYMENT_AUTHORITY_UNKNOWN;
    }
    AR_BIND_BLOB(s, 1, tip_hash, 32);
    AR_BIND_INT(s, 2, tip_height);
    int tip_matches = 0;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        tip_matches = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    if (tip_matches != 1)
        return MARKET_PAYMENT_AUTHORITY_UNKNOWN;

    /* One exact locally-decrypted Sapling output, in the transaction row for
     * a canonical block, is the receipt authority. spent_txid is deliberately
     * ignored: later spending the seller's received note does not revoke the
     * historical purchase. */
    s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*),MIN(n.output_index),MIN(n.block_height),"
            "MIN(b.time) FROM wallet_sapling_notes n "
            "JOIN transactions t ON t.txid=n.txid "
            "AND t.block_height=n.block_height "
            "JOIN blocks b ON b.hash=t.block_hash "
            "AND b.height=t.block_height AND b.status>=3 "
            "WHERE n.txid=? AND n.address=? AND n.value=? "
            "AND n.memo=? AND n.source='local'",
            -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_ERR("market", "payment authority exact-note query failed: %s",
                sqlite3_errmsg(ndb->db));
        return MARKET_PAYMENT_AUTHORITY_UNKNOWN;
    }
    AR_BIND_BLOB(s, 1, payment->txid, 32);
    AR_BIND_TEXT(s, 2, seller_address);
    AR_BIND_INT(s, 3, payment->amount_zat);
    AR_BIND_BLOB(s, 4, memo, FILE_MARKET_PAYMENT_MEMO_BYTES);
    int exact_count = 0;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        exact_count = sqlite3_column_int(s, 0);
        if (exact_count > 0) {
            out->output_index = sqlite3_column_int(s, 1);
            out->block_height = sqlite3_column_int(s, 2);
            out->block_time = sqlite3_column_int64(s, 3);
        }
    }
    sqlite3_finalize(s);
    if (exact_count == 1) {
        if (out->block_height <= 0 || out->block_height > tip_height)
            return MARKET_PAYMENT_AUTHORITY_CONFLICTED;
        out->confirmations = tip_height - out->block_height + 1;
        out->state = out->confirmations >=
            (int)FILE_MARKET_PAYMENT_MIN_CONFIRMATIONS
            ? MARKET_PAYMENT_AUTHORITY_CONFIRMED
            : MARKET_PAYMENT_AUTHORITY_PENDING;
        return out->state;
    }
    if (exact_count > 1)
        return MARKET_PAYMENT_AUTHORITY_CONFLICTED;

    /* If the claimed tx is already canonical but contains no exact seller
     * note, this claim can never become true at a later confirmation depth. */
    s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*) FROM transactions t JOIN blocks b "
            "ON b.hash=t.block_hash AND b.height=t.block_height "
            "AND b.status>=3 WHERE t.txid=?",
            -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_ERR("market", "payment authority tx query failed: %s",
                sqlite3_errmsg(ndb->db));
        return MARKET_PAYMENT_AUTHORITY_UNKNOWN;
    }
    AR_BIND_BLOB(s, 1, payment->txid, 32);
    int canonical_tx = 0;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        canonical_tx = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    out->state = canonical_tx > 0
        ? MARKET_PAYMENT_AUTHORITY_CONFLICTED
        : MARKET_PAYMENT_AUTHORITY_PENDING;
    return out->state;
}
