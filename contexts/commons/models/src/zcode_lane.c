/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ActiveRecord projection for immutable ZCODE lane receipt roots. */

#include "models/zcode_lane.h"

#include "util/log_macros.h"

#include <string.h>

DEFINE_MODEL_CALLBACKS(zcode_lane_receipt)

static bool lane_hex(const char *value, bool zero_allowed)
{
    if (!value) return false;
    if (zero_allowed && !value[0]) return true;
    if (strlen(value) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

bool db_zcode_lane_receipt_validate(
    const struct db_zcode_lane_receipt *row, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, lane_hex(row->receipt_id, false),
                     "receipt_id", "must be a SHA3 root");
    validates_custom(errors, lane_hex(row->source_root_sha3, false),
                     "source_root_sha3", "must be a SHA3 root");
    validates_custom(errors, lane_hex(row->task_root_sha3, false),
                     "task_root_sha3", "must be a SHA3 root");
    validates_custom(errors, lane_hex(row->candidate_root_sha3, false),
                     "candidate_root_sha3", "must be a SHA3 root");
    validates_custom(errors, lane_hex(row->proof_policy_root_sha3, false),
                     "proof_policy_root_sha3", "must be a SHA3 root");
    validates_custom(errors, lane_hex(row->proof_set_root_sha3, true),
                     "proof_set_root_sha3", "must be empty or a SHA3 root");
    validates_custom(errors, lane_hex(row->prior_receipt_root_sha3, true),
                     "prior_receipt_root_sha3", "must be empty or a SHA3 root");
    validates_custom(errors, lane_hex(row->signer_pubkey, false),
                     "signer_pubkey", "must be an Ed25519 public key");
    validates_custom(errors, row->lane >= 1 && row->lane <= 3,
                     "lane", "must be FRONTIER, CANDIDATE, or PROVEN");
    validates_custom(errors,
        (row->lane == 1 && !row->proof_set_root_sha3[0] &&
         !row->prior_receipt_root_sha3[0]) ||
        (row->lane > 1 && row->proof_set_root_sha3[0] &&
         row->prior_receipt_root_sha3[0]),
        "lane_roots", "must match the immutable promotion shape");
    validates_custom(errors, row->created_at > 0,
                     "created_at", "must be positive");
    return !ar_errors_any(errors);
}

bool db_zcode_lane_receipt_save(
    struct node_db *ndb, const struct db_zcode_lane_receipt *row)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("model", "db_zcode_lane_receipt_save: bad args");
    AR_ADHOC_SAVE(ndb, st,
        "INSERT INTO zcode_lane_receipts "
        "(receipt_id,source_root_sha3,task_root_sha3,candidate_root_sha3,"
        "proof_policy_root_sha3,proof_set_root_sha3,"
        "prior_receipt_root_sha3,signer_pubkey,lane,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(receipt_id) DO NOTHING",
        db_zcode_lane_receipt_callbacks(), "zcode_lane_receipt", row,
        db_zcode_lane_receipt_validate,
        AR_BIND_TEXT(st, 1, row->receipt_id);
        AR_BIND_TEXT(st, 2, row->source_root_sha3);
        AR_BIND_TEXT(st, 3, row->task_root_sha3);
        AR_BIND_TEXT(st, 4, row->candidate_root_sha3);
        AR_BIND_TEXT(st, 5, row->proof_policy_root_sha3);
        AR_BIND_TEXT(st, 6, row->proof_set_root_sha3);
        AR_BIND_TEXT(st, 7, row->prior_receipt_root_sha3);
        AR_BIND_TEXT(st, 8, row->signer_pubkey);
        AR_BIND_INT(st, 9, row->lane);
        AR_BIND_INT(st, 10, row->created_at));
}

static void lane_read(struct db_zcode_lane_receipt *out, sqlite3_stmt *st)
{
    AR_READ_STR(st, 0, out->receipt_id, sizeof(out->receipt_id));
    AR_READ_STR(st, 1, out->source_root_sha3, sizeof(out->source_root_sha3));
    AR_READ_STR(st, 2, out->task_root_sha3, sizeof(out->task_root_sha3));
    AR_READ_STR(st, 3, out->candidate_root_sha3,
                sizeof(out->candidate_root_sha3));
    AR_READ_STR(st, 4, out->proof_policy_root_sha3,
                sizeof(out->proof_policy_root_sha3));
    AR_READ_STR(st, 5, out->proof_set_root_sha3,
                sizeof(out->proof_set_root_sha3));
    AR_READ_STR(st, 6, out->prior_receipt_root_sha3,
                sizeof(out->prior_receipt_root_sha3));
    AR_READ_STR(st, 7, out->signer_pubkey, sizeof(out->signer_pubkey));
    out->lane = (int)AR_COL_INT(st, 8);
    out->created_at = AR_COL_INT(st, 9);
}

#define ZCODE_LANE_COLS \
    "receipt_id,source_root_sha3,task_root_sha3,candidate_root_sha3," \
    "proof_policy_root_sha3,proof_set_root_sha3,prior_receipt_root_sha3," \
    "signer_pubkey,lane,created_at"

bool db_zcode_lane_receipt_find(
    struct node_db *ndb, const char *receipt_id,
    struct db_zcode_lane_receipt *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !receipt_id || !out) return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " ZCODE_LANE_COLS " FROM zcode_lane_receipts "
        "WHERE receipt_id=?",
        AR_BIND_TEXT(st, 1, receipt_id), lane_read(out, st));
}

bool db_zcode_lane_latest(
    struct node_db *ndb, const char *source_root_sha3,
    struct db_zcode_lane_receipt *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !source_root_sha3 || !out) return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " ZCODE_LANE_COLS " FROM zcode_lane_receipts "
        "WHERE source_root_sha3=? ORDER BY lane DESC,created_at DESC LIMIT 1",
        AR_BIND_TEXT(st, 1, source_root_sha3), lane_read(out, st));
}
