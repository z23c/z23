/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Recursive, fail-closed ZSLP Type-1 validity projection. Consensus-neutral:
 * this decides application token balances, never block/transaction validity. */

#include "models/zslp_validity.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "models/activerecord.h"
#include "models/database.h"
#include "models/zslp_ledger.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "util/log_macros.h"
#include "zslp/slp.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define ZSLP_VALIDITY_MAX_DEPTH 256
#define ZSLP_VALIDITY_MAX_INPUTS 4096
#define ZSLP_VALIDITY_SCRIPT_MAX 2048

DEFINE_MODEL_CALLBACKS(zslp_validity)

struct zslp_validity_row {
    uint8_t txid[32];
    uint8_t token_id[32];
    bool has_token_id;
    int32_t tx_type;
    enum zslp_validity_status status;
    char reason[64];
    int32_t block_height;
    int64_t input_units;
    int64_t output_units;
    int64_t burned_units;
    int64_t minted_units;
    int32_t baton_vout;
};

struct zslp_input_row {
    uint8_t prev_txid[32];
    int32_t prev_vout;
    bool has_ledger;
    uint8_t token_id[32];
    int64_t amount;
    int32_t role;
    enum zslp_validity_status parent_status;
    bool parent_same_token;
};

static bool validity_row_validate(const struct zslp_validity_row *r,
                                  struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!r) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }
    validates_non_negative(errors, r, tx_type);
    validates_non_negative(errors, r, block_height);
    validates_non_negative(errors, r, input_units);
    validates_non_negative(errors, r, output_units);
    validates_non_negative(errors, r, burned_units);
    validates_non_negative(errors, r, minted_units);
    validates_non_negative(errors, r, baton_vout);
    if (r->status < ZSLP_VALIDITY_UNKNOWN ||
        r->status > ZSLP_VALIDITY_INVALID)
        ar_errors_add(errors, "status", "is invalid");
    if (!r->reason[0])
        ar_errors_add(errors, "reason", "is empty");
    return !ar_errors_any(errors);
}

static bool validity_save(struct node_db *ndb,
                          const struct zslp_validity_row *row)
{
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("zslp_validity", "save: invalid argument");
    sqlite3_stmt *s = NULL;
    struct ar_callbacks *cbs = db_zslp_validity_callbacks();
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO zslp_validity"
        "(txid,token_id,tx_type,status,reason,block_height,input_units,"
        "output_units,burned_units,minted_units,baton_vout)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        cbs, "zslp_validity", row, validity_row_validate,
        AR_BIND_BLOB(s, 1, row->txid, 32);
        if (row->has_token_id)
            AR_BIND_BLOB(s, 2, row->token_id, 32);
        else
            AR_BIND_NULL(s, 2);
        AR_BIND_INT(s, 3, row->tx_type);
        AR_BIND_INT(s, 4, row->status);
        AR_BIND_TEXT(s, 5, row->reason);
        AR_BIND_INT(s, 6, row->block_height);
        AR_BIND_INT(s, 7, row->input_units);
        AR_BIND_INT(s, 8, row->output_units);
        AR_BIND_INT(s, 9, row->burned_units);
        AR_BIND_INT(s, 10, row->minted_units);
        AR_BIND_INT(s, 11, row->baton_vout));
}

static void token_id_internal(const uint8_t wire[32], uint8_t out[32])
{
    for (int i = 0; i < 32; i++)
        out[i] = wire[31 - i];
}

static enum zslp_validity_status validity_existing(
    struct node_db *ndb, const uint8_t txid[32], uint8_t token_id[32],
    bool *has_token, char *reason, size_t reason_size)
{
    if (has_token) *has_token = false;
    if (reason && reason_size) reason[0] = 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT status,reason,token_id FROM zslp_validity WHERE txid=?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return ZSLP_VALIDITY_UNKNOWN;
    AR_BIND_BLOB(s, 1, txid, 32);
    enum zslp_validity_status status = ZSLP_VALIDITY_UNKNOWN;
    if (AR_STEP_ROW(s)) {
        status = (enum zslp_validity_status)AR_COL_INT(s, 0);
        const char *why = AR_COL_TEXT(s, 1);
        if (reason && reason_size)
            snprintf(reason, reason_size, "%s", why ? why : "unknown");
        if (token_id && AR_COL_BYTES(s, 2) == 32) {
            AR_READ_BLOB(s, 2, token_id, 32);
            if (has_token) *has_token = true;
        }
    }
    AR_FINALIZE(s);
    return status;
}

enum zslp_validity_status zslp_validity_get(
    struct node_db *ndb, const uint8_t txid[32], char *reason,
    size_t reason_size)
{
    if (!ndb || !ndb->open || !txid) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "database_unavailable");
        return ZSLP_VALIDITY_UNKNOWN;
    }
    return validity_existing(ndb, txid, NULL, NULL, reason, reason_size);
}

static bool read_slp_script(struct node_db *ndb, const uint8_t txid[32],
                            uint8_t script[ZSLP_VALIDITY_SCRIPT_MAX],
                            size_t *script_len, int32_t *height)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT script,block_height FROM op_returns "
            "WHERE txid=? AND is_slp=1", -1, &s, NULL) != SQLITE_OK || !s)
        LOG_FAIL("zslp_validity", "read_slp_script: prepare failed");
    AR_BIND_BLOB(s, 1, txid, 32);
    bool found = false;
    if (AR_STEP_ROW(s)) {
        int n = AR_COL_BYTES(s, 0);
        if (n > 0 && n <= ZSLP_VALIDITY_SCRIPT_MAX) {
            AR_READ_BLOB(s, 0, script, (size_t)n);
            *script_len = (size_t)n;
            *height = (int32_t)AR_COL_INT(s, 1);
            found = true;
        }
    }
    AR_FINALIZE(s);
    return found; // raw-return-ok:missing ancestry is a caller-classified UNKNOWN
}

static bool output_read_db(struct node_db *ndb, const uint8_t txid[32],
                           int32_t vout, uint8_t address[20], bool *has_address)
{
    *has_address = false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT address_hash FROM tx_outputs WHERE txid=? AND vout=?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, vout);
    bool exists = false;
    if (AR_STEP_ROW(s)) {
        exists = true;
        if (AR_COL_BYTES(s, 0) == 20) {
            AR_READ_BLOB(s, 0, address, 20);
            *has_address = true;
        }
    }
    AR_FINALIZE(s);
    return exists;
}

static bool output_read_live(const struct transaction *tx, int32_t vout,
                             uint8_t address[20], bool *has_address)
{
    *has_address = false;
    if (!tx || vout < 0 || (size_t)vout >= tx->num_vout)
        return false;
    const struct tx_out *o = &tx->vout[vout];
    utxo_classify_script(o->script_pub_key.data, o->script_pub_key.size,
                         address, has_address);
    return true;
}

static bool recursively_validate_tx(struct node_db *ndb,
                                    const uint8_t txid[32], int depth);

static size_t inputs_read_db(struct node_db *ndb, const uint8_t txid[32],
                             const uint8_t target[32],
                             struct zslp_input_row *rows, size_t cap,
                             bool recurse, int depth, bool *truncated)
{
    *truncated = false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT prev_txid,prev_vout FROM tx_inputs WHERE txid=? "
            "ORDER BY vin_index", -1, &s, NULL) != SQLITE_OK || !s)
        return 0;
    AR_BIND_BLOB(s, 1, txid, 32);
    size_t count = 0;
    while (AR_STEP_ROW(s)) {
        if (count == cap) { *truncated = true; break; }
        if (AR_COL_BYTES(s, 0) != 32) continue;
        memset(&rows[count], 0, sizeof(rows[count]));
        AR_READ_BLOB(s, 0, rows[count].prev_txid, 32);
        rows[count].prev_vout = (int32_t)AR_COL_INT(s, 1);
        count++;
    }
    AR_FINALIZE(s);

    for (size_t i = 0; i < count; i++) {
        if (recurse)
            (void)recursively_validate_tx(ndb, rows[i].prev_txid, depth + 1);
        sqlite3_stmt *ls = NULL;
        if (sqlite3_prepare_v2(ndb->db,
                "SELECT token_id,amount,role FROM zslp_ledger "
                "WHERE txid=? AND vout=?", -1, &ls, NULL) == SQLITE_OK && ls) {
            AR_BIND_BLOB(ls, 1, rows[i].prev_txid, 32);
            AR_BIND_INT(ls, 2, rows[i].prev_vout);
            if (AR_STEP_ROW(ls) && AR_COL_BYTES(ls, 0) == 32) {
                rows[i].has_ledger = true;
                AR_READ_BLOB(ls, 0, rows[i].token_id, 32);
                rows[i].amount = AR_COL_INT(ls, 1);
                rows[i].role = (int32_t)AR_COL_INT(ls, 2);
            }
            AR_FINALIZE(ls);
        }
        uint8_t parent_token[32];
        bool parent_has_token = false;
        rows[i].parent_status = validity_existing(
            ndb, rows[i].prev_txid, parent_token, &parent_has_token, NULL, 0);
        rows[i].parent_same_token =
            parent_has_token && memcmp(parent_token, target, 32) == 0;
        if (!parent_has_token) {
            sqlite3_stmt *ps = NULL;
            if (sqlite3_prepare_v2(ndb->db,
                    "SELECT 1 FROM zslp_transfers WHERE txid=? AND token_id=? "
                    "LIMIT 1", -1, &ps, NULL) == SQLITE_OK && ps) {
                AR_BIND_BLOB(ps, 1, rows[i].prev_txid, 32);
                AR_BIND_BLOB(ps, 2, target, 32);
                if (AR_STEP_ROW(ps)) {
                    rows[i].parent_same_token = true;
                    rows[i].parent_status = ZSLP_VALIDITY_UNKNOWN;
                }
                AR_FINALIZE(ps);
            }
        }
    }
    return count;
}

static size_t inputs_read_live(struct node_db *ndb,
                               const struct transaction *tx,
                               const uint8_t target[32],
                               struct zslp_input_row *rows, size_t cap,
                               bool *truncated)
{
    *truncated = tx->num_vin > cap;
    size_t count = tx->num_vin < cap ? tx->num_vin : cap;
    for (size_t i = 0; i < count; i++) {
        memset(&rows[i], 0, sizeof(rows[i]));
        memcpy(rows[i].prev_txid, tx->vin[i].prevout.hash.data, 32);
        rows[i].prev_vout = (int32_t)tx->vin[i].prevout.n;
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(ndb->db,
                "SELECT token_id,amount,role FROM zslp_ledger "
                "WHERE txid=? AND vout=?", -1, &s, NULL) == SQLITE_OK && s) {
            AR_BIND_BLOB(s, 1, rows[i].prev_txid, 32);
            AR_BIND_INT(s, 2, rows[i].prev_vout);
            if (AR_STEP_ROW(s) && AR_COL_BYTES(s, 0) == 32) {
                rows[i].has_ledger = true;
                AR_READ_BLOB(s, 0, rows[i].token_id, 32);
                rows[i].amount = AR_COL_INT(s, 1);
                rows[i].role = (int32_t)AR_COL_INT(s, 2);
            }
            AR_FINALIZE(s);
        }
        uint8_t parent_token[32];
        bool parent_has_token = false;
        rows[i].parent_status = validity_existing(
            ndb, rows[i].prev_txid, parent_token, &parent_has_token, NULL, 0);
        rows[i].parent_same_token =
            parent_has_token && memcmp(parent_token, target, 32) == 0;
    }
    return count;
}

static void mark_inputs_spent(struct node_db *ndb,
                              const struct zslp_input_row *inputs,
                              size_t count, const uint8_t spender[32],
                              int32_t height)
{
    for (size_t i = 0; i < count; i++)
        if (inputs[i].has_ledger)
            (void)zslp_ledger_mark_valid_spent(
                ndb, inputs[i].prev_txid, inputs[i].prev_vout, spender,
                height);
}

static void row_set(struct zslp_validity_row *row,
                    enum zslp_validity_status status, const char *reason)
{
    row->status = status;
    snprintf(row->reason, sizeof(row->reason), "%s", reason);
}

static bool validate_message(struct node_db *ndb, const uint8_t txid[32],
                             const struct transaction *live_tx,
                             const struct slp_message *msg, int32_t height,
                             bool recurse, int depth)
{
    struct zslp_validity_row row;
    memset(&row, 0, sizeof(row));
    memcpy(row.txid, txid, 32);
    row.tx_type = msg->type;
    row.block_height = height;
    row.baton_vout = msg->mint_baton_vout;
    row.has_token_id = true;
    if (msg->type == SLP_TX_GENESIS)
        memcpy(row.token_id, txid, 32);
    else
        token_id_internal(msg->token_id.data, row.token_id);

    struct zslp_input_row inputs[ZSLP_VALIDITY_MAX_INPUTS];
    bool inputs_truncated = false;
    size_t input_count = live_tx
        ? inputs_read_live(ndb, live_tx, row.token_id, inputs,
                           ZSLP_VALIDITY_MAX_INPUTS, &inputs_truncated)
        : inputs_read_db(ndb, txid, row.token_id, inputs,
                         ZSLP_VALIDITY_MAX_INPUTS, recurse, depth,
                         &inputs_truncated);
    if (inputs_truncated) {
        row_set(&row, ZSLP_VALIDITY_UNKNOWN, "input_limit_exceeded");
        return validity_save(ndb, &row);
    }

    uint64_t token_inputs = 0;
    int batons = 0;
    bool mixed_token = false, unknown_parent = false, invalid_parent = false;
    for (size_t i = 0; i < input_count; i++) {
        if (inputs[i].has_ledger && inputs[i].role == ZSLP_LEDGER_TOKEN) {
            if (memcmp(inputs[i].token_id, row.token_id, 32) != 0) {
                mixed_token = true;
                continue;
            }
            if ((uint64_t)inputs[i].amount > UINT64_MAX - token_inputs) {
                row_set(&row, ZSLP_VALIDITY_INVALID, "input_quantity_overflow");
                mark_inputs_spent(ndb, inputs, input_count, txid, height);
                return validity_save(ndb, &row);
            }
            token_inputs += (uint64_t)inputs[i].amount;
        }
        if (inputs[i].has_ledger &&
            inputs[i].role == ZSLP_LEDGER_MINT_BATON &&
            memcmp(inputs[i].token_id, row.token_id, 32) == 0)
            batons++;
        if (inputs[i].parent_same_token &&
            inputs[i].parent_status == ZSLP_VALIDITY_UNKNOWN)
            unknown_parent = true;
        if (inputs[i].parent_same_token &&
            inputs[i].parent_status == ZSLP_VALIDITY_INVALID)
            invalid_parent = true;
    }
    if (token_inputs > INT64_MAX) {
        row_set(&row, ZSLP_VALIDITY_UNKNOWN, "input_quantity_unrepresentable");
        mark_inputs_spent(ndb, inputs, input_count, txid, height);
        return validity_save(ndb, &row);
    }
    row.input_units = (int64_t)token_inputs;

    uint8_t address[20];
    bool has_address = false;
#define OUTPUT_EXISTS(vout_)                                                \
    (live_tx ? output_read_live(live_tx, (vout_), address, &has_address)    \
             : output_read_db(ndb, txid, (vout_), address, &has_address))

    if (msg->type == SLP_TX_GENESIS) {
        if (msg->initial_quantity > (uint64_t)INT64_MAX) {
            row_set(&row, ZSLP_VALIDITY_UNKNOWN, "quantity_unrepresentable");
        } else if (msg->initial_quantity > 0 && !OUTPUT_EXISTS(1)) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "genesis_token_vout_missing");
        } else if (msg->mint_baton_vout &&
                   !OUTPUT_EXISTS(msg->mint_baton_vout)) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "genesis_baton_vout_missing");
        } else {
            row_set(&row, ZSLP_VALIDITY_VALID, "valid_genesis");
            row.output_units = (int64_t)msg->initial_quantity;
            row.minted_units = (int64_t)msg->initial_quantity;
            if (msg->initial_quantity > 0) {
                (void)OUTPUT_EXISTS(1);
                (void)zslp_ledger_record_valid_output(
                    ndb, row.token_id, txid, 1, row.output_units,
                    has_address ? address : NULL, height, ZSLP_LEDGER_TOKEN);
            }
            if (msg->mint_baton_vout) {
                (void)OUTPUT_EXISTS(msg->mint_baton_vout);
                (void)zslp_ledger_record_valid_output(
                    ndb, row.token_id, txid, msg->mint_baton_vout, 0,
                    has_address ? address : NULL, height,
                    ZSLP_LEDGER_MINT_BATON);
            }
        }
    } else if (msg->type == SLP_TX_MINT) {
        mark_inputs_spent(ndb, inputs, input_count, txid, height);
        if (unknown_parent) {
            row_set(&row, ZSLP_VALIDITY_UNKNOWN, "mint_parent_unknown");
        } else if (invalid_parent || batons != 1) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "mint_baton_lineage_invalid");
        } else if (msg->additional_quantity > (uint64_t)INT64_MAX) {
            row_set(&row, ZSLP_VALIDITY_UNKNOWN, "quantity_unrepresentable");
        } else if (msg->additional_quantity > 0 && !OUTPUT_EXISTS(1)) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "mint_token_vout_missing");
        } else if (msg->mint_baton_vout &&
                   !OUTPUT_EXISTS(msg->mint_baton_vout)) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "mint_baton_vout_missing");
        } else {
            row_set(&row, ZSLP_VALIDITY_VALID, "valid_mint");
            row.output_units = (int64_t)msg->additional_quantity;
            row.minted_units = row.output_units;
            if (row.output_units > 0) {
                (void)OUTPUT_EXISTS(1);
                (void)zslp_ledger_record_valid_output(
                    ndb, row.token_id, txid, 1, row.output_units,
                    has_address ? address : NULL, height, ZSLP_LEDGER_TOKEN);
            }
            if (msg->mint_baton_vout) {
                (void)OUTPUT_EXISTS(msg->mint_baton_vout);
                (void)zslp_ledger_record_valid_output(
                    ndb, row.token_id, txid, msg->mint_baton_vout, 0,
                    has_address ? address : NULL, height,
                    ZSLP_LEDGER_MINT_BATON);
            }
        }
    } else if (msg->type == SLP_TX_SEND) {
        mark_inputs_spent(ndb, inputs, input_count, txid, height);
        uint64_t output_sum = 0;
        bool missing_output = false, output_overflow = false;
        for (int i = 0; i < msg->num_outputs; i++) {
            uint64_t q = msg->output_quantities[i];
            if (q > UINT64_MAX - output_sum) output_overflow = true;
            else output_sum += q;
            if (q > 0 && !OUTPUT_EXISTS(i + 1)) missing_output = true;
        }
        if (output_overflow) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "output_quantity_overflow");
        } else if (output_sum > (uint64_t)INT64_MAX) {
            row_set(&row, ZSLP_VALIDITY_UNKNOWN, "quantity_unrepresentable");
        } else if (unknown_parent) {
            row_set(&row, ZSLP_VALIDITY_UNKNOWN, "send_parent_unknown");
        } else if (invalid_parent || token_inputs == 0) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "send_ancestry_invalid");
        } else if (mixed_token) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "mixed_token_inputs");
        } else if (missing_output) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "send_output_missing");
        } else if (output_sum > token_inputs) {
            row_set(&row, ZSLP_VALIDITY_INVALID, "send_output_exceeds_input");
        } else {
            row_set(&row, ZSLP_VALIDITY_VALID, "valid_send");
            row.output_units = (int64_t)output_sum;
            row.burned_units = (int64_t)(token_inputs - output_sum);
            for (int i = 0; i < msg->num_outputs; i++) {
                uint64_t q = msg->output_quantities[i];
                if (q == 0) continue;
                (void)OUTPUT_EXISTS(i + 1);
                (void)zslp_ledger_record_valid_output(
                    ndb, row.token_id, txid, i + 1, (int64_t)q,
                    has_address ? address : NULL, height, ZSLP_LEDGER_TOKEN);
            }
        }
    } else {
        row.has_token_id = false;
        row_set(&row, ZSLP_VALIDITY_INVALID, "unsupported_transaction_type");
    }
#undef OUTPUT_EXISTS
    return validity_save(ndb, &row);
}

static bool recursively_validate_tx(struct node_db *ndb,
                                    const uint8_t txid[32], int depth)
{
    char old_reason[64];
    enum zslp_validity_status old =
        validity_existing(ndb, txid, NULL, NULL, old_reason, sizeof(old_reason));
    if (old == ZSLP_VALIDITY_VALID || old == ZSLP_VALIDITY_INVALID)
        return true;
    if (depth > ZSLP_VALIDITY_MAX_DEPTH) {
        struct zslp_validity_row row;
        memset(&row, 0, sizeof(row));
        memcpy(row.txid, txid, 32);
        row_set(&row, ZSLP_VALIDITY_UNKNOWN, "ancestry_depth_exceeded");
        return validity_save(ndb, &row);
    }
    uint8_t script[ZSLP_VALIDITY_SCRIPT_MAX];
    size_t script_len = 0;
    int32_t height = 0;
    if (!read_slp_script(ndb, txid, script, &script_len, &height))
        return false; // raw-return-ok:caller records missing ancestry
    struct slp_message msg;
    if (!slp_parse(script, script_len, &msg)) {
        struct zslp_validity_row row;
        memset(&row, 0, sizeof(row));
        memcpy(row.txid, txid, 32);
        row.block_height = height;
        row_set(&row, ZSLP_VALIDITY_INVALID, "malformed_slp");
        return validity_save(ndb, &row);
    }
    return validate_message(ndb, txid, NULL, &msg, height, true, depth);
}

bool zslp_validity_apply_live(struct node_db *ndb,
                              const struct transaction *tx,
                              const struct slp_message *msg, int32_t height)
{
    if (!ndb || !ndb->open || !tx || !msg || height < 0)
        LOG_FAIL("zslp_validity", "apply_live: invalid argument");
    zslp_validity_mark_live_spends(ndb, tx, height);
    return validate_message(ndb, tx->hash.data, tx, msg, height, false, 0);
}

void zslp_validity_mark_live_spends(struct node_db *ndb,
                                    const struct transaction *tx,
                                    int32_t height)
{
    if (!ndb || !ndb->open || !tx || height < 0)
        return;
    for (size_t i = 0; i < tx->num_vin; i++) {
        const struct outpoint *op = &tx->vin[i].prevout;
        if (!outpoint_is_null(op))
            (void)zslp_ledger_mark_valid_spent(
                ndb, op->hash.data, (int32_t)op->n, tx->hash.data, height);
    }
}

static void digest_le64(struct sha3_256_ctx *ctx, uint64_t v)
{
    uint8_t le[8];
    zcl_write_u64_le(le, v);
    sha3_256_write(ctx, le, sizeof(le));
}

bool zslp_validity_apply_height(struct node_db *ndb, int32_t height,
                                const uint8_t prev_digest[32],
                                uint8_t out_digest[32])
{
    if (!ndb || !ndb->open || height < 0 || !prev_digest || !out_digest)
        LOG_FAIL("zslp_validity", "apply_height: invalid argument");
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT txid FROM op_returns WHERE block_height=? AND is_slp=1 "
            "ORDER BY txid", -1, &s, NULL) != SQLITE_OK || !s)
        LOG_FAIL("zslp_validity", "apply_height: tx scan prepare failed h=%d",
                 height);
    AR_BIND_INT(s, 1, height);
    while (AR_STEP_ROW(s)) {
        uint8_t txid[32];
        if (AR_COL_BYTES(s, 0) != 32) continue;
        AR_READ_BLOB(s, 0, txid, 32);
        (void)recursively_validate_tx(ndb, txid, 0);
    }
    AR_FINALIZE(s);

    /* Every transparent spend consumes a token/baton outpoint even when the
     * spender carries no valid ZSLP declaration (that is an explicit burn). */
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT prev_txid,prev_vout,txid FROM tx_inputs "
            "WHERE block_height=? ORDER BY txid,vin_index",
            -1, &s, NULL) != SQLITE_OK || !s)
        LOG_FAIL("zslp_validity", "apply_height: spend scan failed h=%d",
                 height);
    AR_BIND_INT(s, 1, height);
    while (AR_STEP_ROW(s)) {
        if (AR_COL_BYTES(s, 0) != 32 || AR_COL_BYTES(s, 2) != 32) continue;
        uint8_t prev[32], spender[32];
        AR_READ_BLOB(s, 0, prev, 32);
        int32_t vout = (int32_t)AR_COL_INT(s, 1);
        AR_READ_BLOB(s, 2, spender, 32);
        (void)zslp_ledger_mark_valid_spent(ndb, prev, vout, spender, height);
    }
    AR_FINALIZE(s);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, prev_digest, 32);
    digest_le64(&ctx, (uint64_t)height);
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT txid,status,reason,input_units,output_units,burned_units,"
            "minted_units FROM zslp_validity WHERE block_height=? ORDER BY txid",
            -1, &s, NULL) != SQLITE_OK || !s)
        LOG_FAIL("zslp_validity", "apply_height: digest scan failed h=%d",
                 height);
    AR_BIND_INT(s, 1, height);
    while (AR_STEP_ROW(s)) {
        if (AR_COL_BYTES(s, 0) != 32) continue;
        sha3_256_write(&ctx,
                       (const uint8_t *)sqlite3_column_blob(s, 0), 32);
        digest_le64(&ctx, (uint64_t)AR_COL_INT(s, 1));
        const char *reason = AR_COL_TEXT(s, 2);
        if (reason) sha3_256_write(&ctx, (const uint8_t *)reason, strlen(reason));
        for (int col = 3; col <= 6; col++)
            digest_le64(&ctx, (uint64_t)AR_COL_INT(s, col));
    }
    AR_FINALIZE(s);
    sha3_256_finalize(&ctx, out_digest);
    return true;
}

bool zslp_validity_is_caught_up(struct node_db *ndb, int32_t provable_tip,
                                int32_t *cursor_out)
{
    int32_t cursor = -1;
    uint8_t digest[32];
    bool read = ndb && ndb->open &&
                zslp_ledger_get_cursor(ndb, &cursor, digest);
    if (cursor_out) *cursor_out = cursor;
    return read && provable_tip >= 0 && cursor >= provable_tip;
}

bool zslp_validity_inputs_match(struct node_db *ndb,
                                const struct transaction *tx,
                                const uint8_t token_id[32],
                                enum zslp_ledger_role required_role,
                                char *reason, size_t reason_size)
{
    if (reason && reason_size) reason[0] = 0;
    if (!ndb || !ndb->open || !tx || !token_id) {
        if (reason && reason_size) snprintf(reason, reason_size, "db_unavailable");
        return false;
    }
    int matches = 0;
    for (size_t i = 0; i < tx->num_vin; i++) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(ndb->db,
                "SELECT token_id,role FROM zslp_ledger "
                "WHERE txid=? AND vout=?", -1, &s, NULL) != SQLITE_OK || !s)
            continue;
        AR_BIND_BLOB(s, 1, tx->vin[i].prevout.hash.data, 32);
        AR_BIND_INT(s, 2, tx->vin[i].prevout.n);
        if (AR_STEP_ROW(s) && AR_COL_BYTES(s, 0) == 32) {
            uint8_t got[32];
            AR_READ_BLOB(s, 0, got, 32);
            int role = (int)AR_COL_INT(s, 1);
            if (memcmp(got, token_id, 32) != 0 ||
                role != (int)required_role) {
                AR_FINALIZE(s);
                if (reason && reason_size)
                    snprintf(reason, reason_size, "input_token_or_role_mismatch");
                return false;
            }
            matches++;
        }
        AR_FINALIZE(s);
    }
    if (matches == 0) {
        if (reason && reason_size)
            snprintf(reason, reason_size, "no_valid_token_input");
        return false;
    }
    return true;
}

int64_t zslp_validity_count(struct node_db *ndb,
                            enum zslp_validity_status status)
{
    if (!ndb || !ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COUNT(*) FROM zslp_validity WHERE status=?",
        AR_BIND_INT(s, 1, status));
}

bool zslp_validity_token_summary(
    struct node_db *ndb, const uint8_t token_id[32],
    struct zslp_token_validity_summary *out)
{
    if (!ndb || !ndb->open || !token_id || !out)
        return false;
    memset(out, 0, sizeof(*out));
    out->validated_height = -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT minted_units,burned_units,block_height FROM zslp_validity "
            "WHERE token_id=? AND status=1 ORDER BY block_height,txid",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    AR_BIND_BLOB(s, 1, token_id, 32);
    uint64_t minted = 0, burned = 0;
    bool overflow = false;
    while (AR_STEP_ROW(s)) {
        uint64_t m = (uint64_t)AR_COL_INT(s, 0);
        uint64_t b = (uint64_t)AR_COL_INT(s, 1);
        if (m > UINT64_MAX - minted || b > UINT64_MAX - burned)
            overflow = true;
        else { minted += m; burned += b; }
        int32_t h = (int32_t)AR_COL_INT(s, 2);
        if (h > out->validated_height) out->validated_height = h;
    }
    AR_FINALIZE(s);
    if (overflow || minted > INT64_MAX || burned > minted ||
        burned > INT64_MAX || minted - burned > INT64_MAX)
        return false;
    out->total_minted = (int64_t)minted;
    out->total_burned = (int64_t)burned;
    out->circulating_supply = (int64_t)(minted - burned);

    if (sqlite3_prepare_v2(ndb->db,
            "SELECT txid,vout FROM zslp_ledger WHERE token_id=? AND role=2 "
            "AND spent_by_txid IS NULL ORDER BY created_height DESC LIMIT 1",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    AR_BIND_BLOB(s, 1, token_id, 32);
    if (AR_STEP_ROW(s) && AR_COL_BYTES(s, 0) == 32) {
        out->baton_active = true;
        AR_READ_BLOB(s, 0, out->baton_txid, 32);
        out->baton_vout = (int32_t)AR_COL_INT(s, 1);
    }
    AR_FINALIZE(s);
    return true;
}
