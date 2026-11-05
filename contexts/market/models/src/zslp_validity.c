/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Fail-closed ZSLP Type-1 validity projection over a transaction's ancestry.
 * Consensus-neutral: this decides application token balances, never
 * block/transaction validity.
 *
 * Every ancestor without a verdict is judged, once, before its children. Each
 * judgement is a function of the transaction and its parents' rows alone, so a
 * verdict does not depend on when it was reached. A walk that would pass the
 * bounds below is refused before it writes anything: the transaction stays
 * UNKNOWN and settles when a later walk fits, never as a guess. */

#include "models/zslp_validity.h"

#include "base/safe_alloc.h"
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
#include <stdlib.h>
#include <string.h>

#define ZSLP_VALIDITY_MAX_DEPTH 256
#define ZSLP_VALIDITY_MAX_INPUTS 4096
#define ZSLP_VALIDITY_SCRIPT_MAX 2048

/* What one transaction may cost: this many ancestors without a verdict, and
 * this many inputs read across them. Ancestors settle at their own heights, so
 * only an unsettled token reaches these. */
#define ZSLP_VALIDITY_WALK_MAX_TXS 1024
#define ZSLP_VALIDITY_WALK_MAX_INPUTS 16384
#define ZSLP_VALIDITY_WALK_SLOTS 2048 /* a power of two above MAX_TXS */
#define ZSLP_VALIDITY_WALK_MAX_PATH (ZSLP_VALIDITY_MAX_DEPTH + 1)
#define ZSLP_VALIDITY_REASON_TOO_DEEP "ancestry_depth_exceeded"
#define ZSLP_VALIDITY_REASON_TOO_WIDE "ancestry_work_exceeded"

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

struct zslp_input_totals {
    uint64_t token_inputs;
    int batons;
    bool mixed_token;
    bool unknown_parent;
    bool invalid_parent;
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

static bool validity_output_exists(const struct transaction *live_tx,
                                   struct node_db *ndb, const uint8_t txid[32],
                                   int32_t vout, uint8_t address[20],
                                   bool *has_address)
{
    return live_tx
        ? output_read_live(live_tx, vout, address, has_address)
        : output_read_db(ndb, txid, vout, address, has_address);
}

static size_t validity_inputs_fetch_prevouts(sqlite3_stmt *s,
                                             struct zslp_input_row *rows,
                                             size_t cap, bool *truncated)
{
    size_t count = 0;
    while (AR_STEP_ROW(s)) {
        if (count == cap) { *truncated = true; break; }
        if (AR_COL_BYTES(s, 0) != 32) continue;
        memset(&rows[count], 0, sizeof(rows[count]));
        AR_READ_BLOB(s, 0, rows[count].prev_txid, 32);
        rows[count].prev_vout = (int32_t)AR_COL_INT(s, 1);
        count++;
    }
    return count;
}

static void validity_inputs_enrich_row(struct node_db *ndb,
                                       struct zslp_input_row *row,
                                       const uint8_t target[32])
{
    sqlite3_stmt *ls = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT token_id,amount,role FROM zslp_ledger "
            "WHERE txid=? AND vout=?", -1, &ls, NULL) == SQLITE_OK && ls) {
        AR_BIND_BLOB(ls, 1, row->prev_txid, 32);
        AR_BIND_INT(ls, 2, row->prev_vout);
        if (AR_STEP_ROW(ls) && AR_COL_BYTES(ls, 0) == 32) {
            row->has_ledger = true;
            AR_READ_BLOB(ls, 0, row->token_id, 32);
            row->amount = AR_COL_INT(ls, 1);
            row->role = (int32_t)AR_COL_INT(ls, 2);
        }
        AR_FINALIZE(ls);
    }
    uint8_t parent_token[32];
    bool parent_has_token = false;
    row->parent_status = validity_existing(
        ndb, row->prev_txid, parent_token, &parent_has_token, NULL, 0);
    row->parent_same_token =
        parent_has_token && memcmp(parent_token, target, 32) == 0;
    if (!parent_has_token) {
        sqlite3_stmt *ps = NULL;
        if (sqlite3_prepare_v2(ndb->db,
                "SELECT 1 FROM zslp_transfers WHERE txid=? AND token_id=? "
                "LIMIT 1", -1, &ps, NULL) == SQLITE_OK && ps) {
            AR_BIND_BLOB(ps, 1, row->prev_txid, 32);
            AR_BIND_BLOB(ps, 2, target, 32);
            if (AR_STEP_ROW(ps)) {
                row->parent_same_token = true;
                row->parent_status = ZSLP_VALIDITY_UNKNOWN;
            }
            AR_FINALIZE(ps);
        }
    }
}

static size_t inputs_select_db(struct node_db *ndb, const uint8_t txid[32],
                               struct zslp_input_row *rows, size_t cap,
                               bool *truncated)
{
    *truncated = false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT prev_txid,prev_vout FROM tx_inputs WHERE txid=? "
            "ORDER BY vin_index", -1, &s, NULL) != SQLITE_OK || !s)
        return 0;
    AR_BIND_BLOB(s, 1, txid, 32);
    size_t count = validity_inputs_fetch_prevouts(s, rows, cap, truncated);
    AR_FINALIZE(s);
    return count;
}

static size_t inputs_read_db(struct node_db *ndb, const uint8_t txid[32],
                             const uint8_t target[32],
                             struct zslp_input_row *rows, size_t cap,
                             bool *truncated)
{
    size_t count = inputs_select_db(ndb, txid, rows, cap, truncated);
    for (size_t i = 0; i < count; i++)
        validity_inputs_enrich_row(ndb, &rows[i], target);
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

static void validity_note_input_baton(struct zslp_input_totals *t,
                                      const struct zslp_input_row *in,
                                      const uint8_t token_id[32])
{
    if (in->has_ledger && in->role == ZSLP_LEDGER_MINT_BATON &&
        memcmp(in->token_id, token_id, 32) == 0)
        t->batons++;
    if (in->parent_same_token && in->parent_status == ZSLP_VALIDITY_UNKNOWN)
        t->unknown_parent = true;
    if (in->parent_same_token && in->parent_status == ZSLP_VALIDITY_INVALID)
        t->invalid_parent = true;
}

/* Fills the input totals; false only when the running token input sum
 * overflows uint64_t, which the caller records as input_quantity_overflow. */
static bool validity_inputs_total(const struct zslp_input_row *inputs,
                                  size_t count, const uint8_t token_id[32],
                                  struct zslp_input_totals *t)
{
    t->token_inputs = 0;
    t->batons = 0;
    t->mixed_token = false;
    t->unknown_parent = false;
    t->invalid_parent = false;
    for (size_t i = 0; i < count; i++) {
        if (inputs[i].has_ledger && inputs[i].role == ZSLP_LEDGER_TOKEN) {
            if (memcmp(inputs[i].token_id, token_id, 32) != 0) {
                t->mixed_token = true;
                continue;
            }
            if ((uint64_t)inputs[i].amount > UINT64_MAX - t->token_inputs)
                return false;
            t->token_inputs += (uint64_t)inputs[i].amount;
        }
        validity_note_input_baton(t, &inputs[i], token_id);
    }
    return true;
}

static void validity_record_minted_outputs(struct node_db *ndb,
                                           const struct transaction *live_tx,
                                           const uint8_t txid[32],
                                           const struct slp_message *msg,
                                           int32_t height,
                                           const uint8_t token_id[32],
                                           int64_t token_units)
{
    uint8_t address[20];
    bool has_address = false;
    if (token_units > 0) {
        (void)validity_output_exists(live_tx, ndb, txid, 1, address,
                                     &has_address);
        (void)zslp_ledger_record_valid_output(
            ndb, token_id, txid, 1, token_units,
            has_address ? address : NULL, height, ZSLP_LEDGER_TOKEN);
    }
    if (msg->mint_baton_vout) {
        (void)validity_output_exists(live_tx, ndb, txid, msg->mint_baton_vout,
                                     address, &has_address);
        (void)zslp_ledger_record_valid_output(
            ndb, token_id, txid, msg->mint_baton_vout, 0,
            has_address ? address : NULL, height, ZSLP_LEDGER_MINT_BATON);
    }
}

static void validity_validate_genesis(struct node_db *ndb,
                                      const uint8_t txid[32],
                                      const struct transaction *live_tx,
                                      const struct slp_message *msg,
                                      int32_t height,
                                      struct zslp_validity_row *row)
{
    uint8_t address[20];
    bool has_address = false;
    if (msg->initial_quantity > (uint64_t)INT64_MAX) {
        row_set(row, ZSLP_VALIDITY_UNKNOWN, "quantity_unrepresentable");
    } else if (msg->initial_quantity > 0 &&
               !validity_output_exists(live_tx, ndb, txid, 1, address,
                                       &has_address)) {
        row_set(row, ZSLP_VALIDITY_INVALID, "genesis_token_vout_missing");
    } else if (msg->mint_baton_vout &&
               !validity_output_exists(live_tx, ndb, txid,
                                       msg->mint_baton_vout, address,
                                       &has_address)) {
        row_set(row, ZSLP_VALIDITY_INVALID, "genesis_baton_vout_missing");
    } else {
        row_set(row, ZSLP_VALIDITY_VALID, "valid_genesis");
        row->output_units = (int64_t)msg->initial_quantity;
        row->minted_units = (int64_t)msg->initial_quantity;
        validity_record_minted_outputs(ndb, live_tx, txid, msg, height,
                                       row->token_id, row->output_units);
    }
}

static void validity_validate_mint(struct node_db *ndb,
                                   const uint8_t txid[32],
                                   const struct transaction *live_tx,
                                   const struct slp_message *msg,
                                   int32_t height,
                                   const struct zslp_input_row *inputs,
                                   size_t input_count,
                                   const struct zslp_input_totals *totals,
                                   struct zslp_validity_row *row)
{
    mark_inputs_spent(ndb, inputs, input_count, txid, height);
    uint8_t address[20];
    bool has_address = false;
    if (totals->unknown_parent) {
        row_set(row, ZSLP_VALIDITY_UNKNOWN, "mint_parent_unknown");
    } else if (totals->invalid_parent || totals->batons != 1) {
        row_set(row, ZSLP_VALIDITY_INVALID, "mint_baton_lineage_invalid");
    } else if (msg->additional_quantity > (uint64_t)INT64_MAX) {
        row_set(row, ZSLP_VALIDITY_UNKNOWN, "quantity_unrepresentable");
    } else if (msg->additional_quantity > 0 &&
               !validity_output_exists(live_tx, ndb, txid, 1, address,
                                       &has_address)) {
        row_set(row, ZSLP_VALIDITY_INVALID, "mint_token_vout_missing");
    } else if (msg->mint_baton_vout &&
               !validity_output_exists(live_tx, ndb, txid,
                                       msg->mint_baton_vout, address,
                                       &has_address)) {
        row_set(row, ZSLP_VALIDITY_INVALID, "mint_baton_vout_missing");
    } else {
        row_set(row, ZSLP_VALIDITY_VALID, "valid_mint");
        row->output_units = (int64_t)msg->additional_quantity;
        row->minted_units = row->output_units;
        validity_record_minted_outputs(ndb, live_tx, txid, msg, height,
                                       row->token_id, row->output_units);
    }
}

static void validity_send_outputs_scan(struct node_db *ndb,
                                       const struct transaction *live_tx,
                                       const uint8_t txid[32],
                                       const struct slp_message *msg,
                                       uint64_t *output_sum,
                                       bool *missing_output,
                                       bool *output_overflow)
{
    uint8_t address[20];
    bool has_address = false;
    *output_sum = 0;
    *missing_output = false;
    *output_overflow = false;
    for (int i = 0; i < msg->num_outputs; i++) {
        uint64_t q = msg->output_quantities[i];
        if (q > UINT64_MAX - *output_sum)
            *output_overflow = true;
        else
            *output_sum += q;
        if (q > 0 && !validity_output_exists(live_tx, ndb, txid, i + 1,
                                             address, &has_address))
            *missing_output = true;
    }
}

static void validity_send_outputs_record(struct node_db *ndb,
                                         const struct transaction *live_tx,
                                         const uint8_t txid[32],
                                         const struct slp_message *msg,
                                         int32_t height,
                                         const uint8_t token_id[32])
{
    uint8_t address[20];
    bool has_address = false;
    for (int i = 0; i < msg->num_outputs; i++) {
        uint64_t q = msg->output_quantities[i];
        if (q == 0) continue;
        (void)validity_output_exists(live_tx, ndb, txid, i + 1, address,
                                     &has_address);
        (void)zslp_ledger_record_valid_output(
            ndb, token_id, txid, i + 1, (int64_t)q,
            has_address ? address : NULL, height, ZSLP_LEDGER_TOKEN);
    }
}

static void validity_validate_send(struct node_db *ndb,
                                   const uint8_t txid[32],
                                   const struct transaction *live_tx,
                                   const struct slp_message *msg,
                                   int32_t height,
                                   const struct zslp_input_row *inputs,
                                   size_t input_count,
                                   const struct zslp_input_totals *totals,
                                   struct zslp_validity_row *row)
{
    mark_inputs_spent(ndb, inputs, input_count, txid, height);
    uint64_t output_sum = 0;
    bool missing_output = false, output_overflow = false;
    validity_send_outputs_scan(ndb, live_tx, txid, msg, &output_sum,
                               &missing_output, &output_overflow);
    if (output_overflow) {
        row_set(row, ZSLP_VALIDITY_INVALID, "output_quantity_overflow");
    } else if (output_sum > (uint64_t)INT64_MAX) {
        row_set(row, ZSLP_VALIDITY_UNKNOWN, "quantity_unrepresentable");
    } else if (totals->unknown_parent) {
        row_set(row, ZSLP_VALIDITY_UNKNOWN, "send_parent_unknown");
    } else if (totals->invalid_parent || totals->token_inputs == 0) {
        row_set(row, ZSLP_VALIDITY_INVALID, "send_ancestry_invalid");
    } else if (totals->mixed_token) {
        row_set(row, ZSLP_VALIDITY_INVALID, "mixed_token_inputs");
    } else if (missing_output) {
        row_set(row, ZSLP_VALIDITY_INVALID, "send_output_missing");
    } else if (output_sum > totals->token_inputs) {
        row_set(row, ZSLP_VALIDITY_INVALID, "send_output_exceeds_input");
    } else {
        row_set(row, ZSLP_VALIDITY_VALID, "valid_send");
        row->output_units = (int64_t)output_sum;
        row->burned_units = (int64_t)(totals->token_inputs - output_sum);
        validity_send_outputs_record(ndb, live_tx, txid, msg, height,
                                     row->token_id);
    }
}

static void validity_row_start(struct zslp_validity_row *row,
                               const uint8_t txid[32],
                               const struct slp_message *msg, int32_t height)
{
    memset(row, 0, sizeof(*row));
    memcpy(row->txid, txid, 32);
    row->tx_type = msg->type;
    row->block_height = height;
    row->baton_vout = msg->mint_baton_vout;
    row->has_token_id = true;
    if (msg->type == SLP_TX_GENESIS)
        memcpy(row->token_id, txid, 32);
    else
        token_id_internal(msg->token_id.data, row->token_id);
}

/* `inputs` is caller storage for this transaction's inputs: the live path sizes
 * it to the transaction, a stored transaction uses ZSLP_VALIDITY_MAX_INPUTS. */
static bool validate_message(struct node_db *ndb, const uint8_t txid[32],
                             const struct transaction *live_tx,
                             const struct slp_message *msg, int32_t height,
                             struct zslp_input_row *inputs)
{
    struct zslp_validity_row row;
    validity_row_start(&row, txid, msg, height);

    bool inputs_truncated = false;
    size_t input_count = live_tx
        ? inputs_read_live(ndb, live_tx, row.token_id, inputs,
                           ZSLP_VALIDITY_MAX_INPUTS, &inputs_truncated)
        : inputs_read_db(ndb, txid, row.token_id, inputs,
                         ZSLP_VALIDITY_MAX_INPUTS, &inputs_truncated);
    if (inputs_truncated) {
        row_set(&row, ZSLP_VALIDITY_UNKNOWN, "input_limit_exceeded");
        return validity_save(ndb, &row);
    }

    struct zslp_input_totals totals;
    if (!validity_inputs_total(inputs, input_count, row.token_id, &totals)) {
        row_set(&row, ZSLP_VALIDITY_INVALID, "input_quantity_overflow");
        mark_inputs_spent(ndb, inputs, input_count, txid, height);
        return validity_save(ndb, &row);
    }
    if (totals.token_inputs > INT64_MAX) {
        row_set(&row, ZSLP_VALIDITY_UNKNOWN, "input_quantity_unrepresentable");
        mark_inputs_spent(ndb, inputs, input_count, txid, height);
        return validity_save(ndb, &row);
    }
    row.input_units = (int64_t)totals.token_inputs;

    if (msg->type == SLP_TX_GENESIS)
        validity_validate_genesis(ndb, txid, live_tx, msg, height, &row);
    else if (msg->type == SLP_TX_MINT)
        validity_validate_mint(ndb, txid, live_tx, msg, height, inputs,
                               input_count, &totals, &row);
    else if (msg->type == SLP_TX_SEND)
        validity_validate_send(ndb, txid, live_tx, msg, height, inputs,
                               input_count, &totals, &row);
    else {
        row.has_token_id = false;
        row_set(&row, ZSLP_VALIDITY_INVALID, "unsupported_transaction_type");
    }
    return validity_save(ndb, &row);
}

/* ── Bounded ancestry walk ─────────────────────────────────────────── */

struct zslp_walk_node {
    uint8_t txid[32];
    uint32_t edge_start;
    uint32_t edge_count;
    uint32_t edge_next;
    uint32_t longest; /* transactions on the longest unsettled path from here */
    bool on_path;
};

enum zslp_walk_result {
    ZSLP_WALK_OK,
    ZSLP_WALK_TOO_DEEP,
    ZSLP_WALK_TOO_WIDE,
};

/* All of a walk's state lives here, on the heap. `rows` holds one transaction's
 * inputs at a time. */
struct zslp_walk {
    struct node_db *ndb;
    uint32_t node_count;
    uint32_t edge_count;
    uint32_t order_count;
    uint32_t path_len;
    uint16_t slots[ZSLP_VALIDITY_WALK_SLOTS]; /* node index + 1; 0 is empty */
    uint32_t path[ZSLP_VALIDITY_WALK_MAX_PATH];
    uint32_t order[ZSLP_VALIDITY_WALK_MAX_TXS]; /* parents before children */
    struct zslp_walk_node nodes[ZSLP_VALIDITY_WALK_MAX_TXS];
    uint8_t edges[ZSLP_VALIDITY_WALK_MAX_INPUTS][32];
    struct zslp_input_row rows[ZSLP_VALIDITY_MAX_INPUTS];
};

/* The node for txid, or -1 with *slot_out at the free slot it would take. */
static int32_t walk_find(const struct zslp_walk *w, const uint8_t txid[32],
                         uint32_t *slot_out)
{
    uint32_t hash = 2166136261u;
    for (int i = 0; i < 32; i++)
        hash = (hash ^ txid[i]) * 16777619u;
    uint32_t slot = hash & (ZSLP_VALIDITY_WALK_SLOTS - 1);
    while (w->slots[slot]) {
        int32_t index = (int32_t)w->slots[slot] - 1;
        if (memcmp(w->nodes[index].txid, txid, 32) == 0)
            return index;
        slot = (slot + 1) & (ZSLP_VALIDITY_WALK_SLOTS - 1);
    }
    *slot_out = slot;
    return -1;
}

/* Reads the inputs a stored transaction would walk; false past the bound. A
 * transaction with no readable declaration has none, as it is judged alone. */
static bool walk_read_edges(struct zslp_walk *w, struct zslp_walk_node *node)
{
    uint8_t script[ZSLP_VALIDITY_SCRIPT_MAX];
    size_t script_len = 0;
    int32_t height = 0;
    struct slp_message msg;
    if (!read_slp_script(w->ndb, node->txid, script, &script_len, &height) ||
        !slp_parse(script, script_len, &msg))
        return true;
    bool truncated = false;
    size_t count = inputs_select_db(w->ndb, node->txid, w->rows,
                                    ZSLP_VALIDITY_MAX_INPUTS, &truncated);
    if (count > ZSLP_VALIDITY_WALK_MAX_INPUTS - w->edge_count)
        return false;
    for (size_t i = 0; i < count; i++)
        memcpy(w->edges[w->edge_count + i], w->rows[i].prev_txid, 32);
    node->edge_start = w->edge_count;
    node->edge_count = (uint32_t)count;
    w->edge_count += (uint32_t)count;
    return true;
}

static enum zslp_walk_result walk_push(struct zslp_walk *w,
                                       const uint8_t txid[32])
{
    if (w->path_len == ZSLP_VALIDITY_WALK_MAX_PATH)
        return ZSLP_WALK_TOO_DEEP;
    if (w->node_count == ZSLP_VALIDITY_WALK_MAX_TXS)
        return ZSLP_WALK_TOO_WIDE;
    uint32_t slot = 0;
    (void)walk_find(w, txid, &slot);
    uint32_t index = w->node_count;
    struct zslp_walk_node *node = &w->nodes[index];
    memset(node, 0, sizeof(*node));
    memcpy(node->txid, txid, 32);
    node->longest = 1;
    node->on_path = true;
    if (!walk_read_edges(w, node))
        return ZSLP_WALK_TOO_WIDE;
    w->slots[slot] = (uint16_t)(index + 1);
    w->node_count++;
    w->path[w->path_len++] = index;
    return ZSLP_WALK_OK;
}

/* A parent needs judging unless it holds a verdict or declares no token. */
static bool walk_parent_unsettled(struct node_db *ndb, const uint8_t txid[32])
{
    enum zslp_validity_status status =
        validity_existing(ndb, txid, NULL, NULL, NULL, 0);
    if (status == ZSLP_VALIDITY_VALID || status == ZSLP_VALIDITY_INVALID)
        return false;
    uint8_t script[ZSLP_VALIDITY_SCRIPT_MAX];
    size_t script_len = 0;
    int32_t height = 0;
    return read_slp_script(ndb, txid, script, &script_len, &height);
}

static enum zslp_walk_result walk_follow_edge(struct zslp_walk *w,
                                              struct zslp_walk_node *node)
{
    const uint8_t *parent = w->edges[node->edge_start + node->edge_next];
    node->edge_next++;
    uint32_t slot = 0;
    int32_t seen = walk_find(w, parent, &slot);
    if (seen < 0)
        return walk_parent_unsettled(w->ndb, parent) ? walk_push(w, parent)
                                                     : ZSLP_WALK_OK;
    /* On the path means the damaged inputs form a loop; no real chain can,
     * and the depth cap is what has always ended one. */
    const struct zslp_walk_node *known = &w->nodes[seen];
    if (known->on_path ||
        w->path_len + known->longest > ZSLP_VALIDITY_WALK_MAX_PATH)
        return ZSLP_WALK_TOO_DEEP;
    if (known->longest >= node->longest)
        node->longest = known->longest + 1;
    return ZSLP_WALK_OK;
}

static void walk_finish_node(struct zslp_walk *w, uint32_t index)
{
    struct zslp_walk_node *node = &w->nodes[index];
    node->on_path = false;
    w->order[w->order_count++] = index;
    w->path_len--;
    if (w->path_len > 0) {
        struct zslp_walk_node *child = &w->nodes[w->path[w->path_len - 1]];
        if (node->longest >= child->longest)
            child->longest = node->longest + 1;
    }
}

/* Lists every unsettled ancestor once, parents first, reading but never
 * writing. Whether a walk fits therefore depends only on the settled rows it
 * starts from, and a walk that does not fit leaves no partial trace. */
static enum zslp_walk_result walk_plan(struct zslp_walk *w,
                                       const uint8_t root[32])
{
    w->node_count = 0;
    w->edge_count = 0;
    w->order_count = 0;
    w->path_len = 0;
    memset(w->slots, 0, sizeof(w->slots));
    enum zslp_walk_result result = walk_push(w, root);
    while (result == ZSLP_WALK_OK && w->path_len > 0) {
        uint32_t index = w->path[w->path_len - 1];
        struct zslp_walk_node *node = &w->nodes[index];
        if (node->edge_next < node->edge_count)
            result = walk_follow_edge(w, node);
        else
            walk_finish_node(w, index);
    }
    return result;
}

/* Judges one stored transaction from the rows of its inputs as they stand. */
static bool validity_judge_stored(struct node_db *ndb, const uint8_t txid[32],
                                  struct zslp_input_row *rows)
{
    enum zslp_validity_status old =
        validity_existing(ndb, txid, NULL, NULL, NULL, 0);
    if (old == ZSLP_VALIDITY_VALID || old == ZSLP_VALIDITY_INVALID)
        return true;
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
    return validate_message(ndb, txid, NULL, &msg, height, rows);
}

/* Records a walk the bound refused. Only this transaction's row moves, to
 * UNKNOWN with its token so a child sees an unsettled parent of that token,
 * and it settles when a later walk fits. A GENESIS is judged at once: its
 * verdict reads nothing from its ancestry. */
static bool validity_refuse_walk(struct node_db *ndb, const uint8_t txid[32],
                                 enum zslp_walk_result result,
                                 struct zslp_input_row *rows)
{
    uint8_t script[ZSLP_VALIDITY_SCRIPT_MAX];
    size_t script_len = 0;
    int32_t height = 0;
    struct slp_message msg;
    if (!read_slp_script(ndb, txid, script, &script_len, &height) ||
        !slp_parse(script, script_len, &msg))
        return false; // raw-return-ok:only a parsed transaction has a walk
    if (msg.type == SLP_TX_GENESIS)
        return validate_message(ndb, txid, NULL, &msg, height, rows);
    struct zslp_validity_row row;
    validity_row_start(&row, txid, &msg, height);
    row_set(&row, ZSLP_VALIDITY_UNKNOWN,
            result == ZSLP_WALK_TOO_DEEP ? ZSLP_VALIDITY_REASON_TOO_DEEP
                                         : ZSLP_VALIDITY_REASON_TOO_WIDE);
    return validity_save(ndb, &row);
}

/* True when an earlier attempt at this height refused this transaction. That
 * refusal stands for the height: a later transaction in the same scan may have
 * settled ancestors since, and walking again would then give an interrupted
 * height a verdict the uninterrupted one did not have at this point. */
static bool validity_refused_at_height(struct node_db *ndb,
                                       const uint8_t txid[32], int32_t height)
{
    sqlite3_stmt *s = NULL;
    AR_QUERY_EXISTS(ndb, s,
        "SELECT 1 FROM zslp_validity WHERE txid=? AND block_height=? "
        "AND status=0 AND reason IN(?,?)",
        AR_BIND_BLOB(s, 1, txid, 32);
        AR_BIND_INT(s, 2, height);
        AR_BIND_TEXT(s, 3, ZSLP_VALIDITY_REASON_TOO_DEEP);
        AR_BIND_TEXT(s, 4, ZSLP_VALIDITY_REASON_TOO_WIDE));
}

/* Settles one transaction of the height being applied. False only when the
 * walk's memory is unavailable: nothing was stored, so the height can retry. */
static bool validity_apply_tx(struct node_db *ndb, const uint8_t txid[32],
                              int32_t height)
{
    enum zslp_validity_status old =
        validity_existing(ndb, txid, NULL, NULL, NULL, 0);
    if (old == ZSLP_VALIDITY_VALID || old == ZSLP_VALIDITY_INVALID ||
        validity_refused_at_height(ndb, txid, height))
        return true;
    struct zslp_walk *w = zcl_malloc(sizeof(*w), "zslp_validity_walk");
    if (!w)
        LOG_FAIL("zslp_validity", "apply_tx: no memory for a walk at h=%d",
                 height);
    w->ndb = ndb;
    enum zslp_walk_result result = walk_plan(w, txid);
    if (result == ZSLP_WALK_OK) {
        for (uint32_t i = 0; i < w->order_count; i++)
            (void)validity_judge_stored(ndb, w->nodes[w->order[i]].txid,
                                        w->rows);
    } else {
        (void)validity_refuse_walk(ndb, txid, result, w->rows);
    }
    free(w);
    return true;
}

bool zslp_validity_apply_live(struct node_db *ndb,
                              const struct transaction *tx,
                              const struct slp_message *msg, int32_t height)
{
    if (!ndb || !ndb->open || !tx || !msg || height < 0)
        LOG_FAIL("zslp_validity", "apply_live: invalid argument");
    zslp_validity_mark_live_spends(ndb, tx, height);
    /* inputs_read_live stores at most this many before it reports truncation. */
    size_t rows = tx->num_vin < ZSLP_VALIDITY_MAX_INPUTS
        ? tx->num_vin : ZSLP_VALIDITY_MAX_INPUTS;
    struct zslp_input_row *inputs =
        zcl_malloc((rows ? rows : 1) * sizeof(*inputs), "zslp_validity_inputs");
    if (!inputs)
        LOG_FAIL("zslp_validity", "apply_live: no memory for %zu inputs at h=%d",
                 rows, height);
    bool saved = validate_message(ndb, tx->hash.data, tx, msg, height, inputs);
    free(inputs);
    return saved;
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

/* Prepare helper: the caller keeps the LOG_FAIL so log lines stay in
 * zslp_validity_apply_height. */
static bool validity_scan_prepare(sqlite3 *db, const char *sql,
                                  sqlite3_stmt **stmt)
{
    return sqlite3_prepare_v2(db, sql, -1, stmt, NULL) == SQLITE_OK &&
           *stmt != NULL;
}

static bool validity_apply_height_txids(struct node_db *ndb, sqlite3_stmt *s,
                                        int32_t height)
{
    while (AR_STEP_ROW(s)) {
        uint8_t txid[32];
        if (AR_COL_BYTES(s, 0) != 32) continue;
        AR_READ_BLOB(s, 0, txid, 32);
        if (!validity_apply_tx(ndb, txid, height))
            return false; // raw-return-ok:apply_tx logged and the height retries
    }
    return true;
}

static void validity_apply_height_spends(struct node_db *ndb, sqlite3_stmt *s,
                                         int32_t height)
{
    while (AR_STEP_ROW(s)) {
        if (AR_COL_BYTES(s, 0) != 32 || AR_COL_BYTES(s, 2) != 32) continue;
        uint8_t prev[32], spender[32];
        AR_READ_BLOB(s, 0, prev, 32);
        int32_t vout = (int32_t)AR_COL_INT(s, 1);
        AR_READ_BLOB(s, 2, spender, 32);
        (void)zslp_ledger_mark_valid_spent(ndb, prev, vout, spender, height);
    }
}

static void validity_apply_height_digest(struct sha3_256_ctx *ctx,
                                         sqlite3_stmt *s)
{
    while (AR_STEP_ROW(s)) {
        if (AR_COL_BYTES(s, 0) != 32) continue;
        sha3_256_write(ctx,
                       (const uint8_t *)sqlite3_column_blob(s, 0), 32);
        digest_le64(ctx, (uint64_t)AR_COL_INT(s, 1));
        const char *reason = AR_COL_TEXT(s, 2);
        if (reason) sha3_256_write(ctx, (const uint8_t *)reason, strlen(reason));
        for (int col = 3; col <= 6; col++)
            digest_le64(ctx, (uint64_t)AR_COL_INT(s, col));
    }
}

bool zslp_validity_apply_height(struct node_db *ndb, int32_t height,
                                const uint8_t prev_digest[32],
                                uint8_t out_digest[32])
{
    if (!ndb || !ndb->open || height < 0 || !prev_digest || !out_digest)
        LOG_FAIL("zslp_validity", "apply_height: invalid argument");
    sqlite3_stmt *s = NULL;
    if (!validity_scan_prepare(ndb->db,
            "SELECT txid FROM op_returns WHERE block_height=? AND is_slp=1 "
            "ORDER BY txid", &s))
        LOG_FAIL("zslp_validity", "apply_height: tx scan prepare failed h=%d",
                 height);
    AR_BIND_INT(s, 1, height);
    bool applied = validity_apply_height_txids(ndb, s, height);
    AR_FINALIZE(s);
    if (!applied)
        return false; // raw-return-ok:apply_tx logged and the height retries

    /* Every transparent spend consumes a token/baton outpoint even when the
     * spender carries no valid ZSLP declaration (that is an explicit burn). */
    if (!validity_scan_prepare(ndb->db,
            "SELECT prev_txid,prev_vout,txid FROM tx_inputs "
            "WHERE block_height=? ORDER BY txid,vin_index", &s))
        LOG_FAIL("zslp_validity", "apply_height: spend scan failed h=%d",
                 height);
    AR_BIND_INT(s, 1, height);
    validity_apply_height_spends(ndb, s, height);
    AR_FINALIZE(s);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, prev_digest, 32);
    digest_le64(&ctx, (uint64_t)height);
    if (!validity_scan_prepare(ndb->db,
            "SELECT txid,status,reason,input_units,output_units,burned_units,"
            "minted_units FROM zslp_validity WHERE block_height=? ORDER BY txid",
            &s))
        LOG_FAIL("zslp_validity", "apply_height: digest scan failed h=%d",
                 height);
    AR_BIND_INT(s, 1, height);
    validity_apply_height_digest(&ctx, s);
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

static void reason_set(char *reason, size_t reason_size, const char *text)
{
    if (reason && reason_size)
        snprintf(reason, reason_size, "%s", text);
}

/* Per-vin ledger probe: 1 = token and role match, 0 = no ledger row for the
 * outpoint (including a failed prepare), -1 = token or role mismatch. */
static int validity_input_vin_ledger_check(struct node_db *ndb,
                                           const struct transaction *tx,
                                           size_t vin_index,
                                           const uint8_t token_id[32],
                                           int required_role)
{
    sqlite3_stmt *s = NULL;
    if (!validity_scan_prepare(ndb->db,
            "SELECT token_id,role FROM zslp_ledger "
            "WHERE txid=? AND vout=?", &s))
        return 0;
    AR_BIND_BLOB(s, 1, tx->vin[vin_index].prevout.hash.data, 32);
    AR_BIND_INT(s, 2, tx->vin[vin_index].prevout.n);
    int result = 0;
    if (AR_STEP_ROW(s) && AR_COL_BYTES(s, 0) == 32) {
        uint8_t got[32];
        AR_READ_BLOB(s, 0, got, 32);
        int role = (int)AR_COL_INT(s, 1);
        if (memcmp(got, token_id, 32) != 0 || role != required_role)
            result = -1;
        else
            result = 1;
    }
    AR_FINALIZE(s);
    return result;
}

bool zslp_validity_inputs_match(struct node_db *ndb,
                                const struct transaction *tx,
                                const uint8_t token_id[32],
                                enum zslp_ledger_role required_role,
                                char *reason, size_t reason_size)
{
    if (reason && reason_size) reason[0] = 0;
    if (!ndb || !ndb->open || !tx || !token_id) {
        reason_set(reason, reason_size, "db_unavailable");
        return false;
    }
    int matches = 0;
    for (size_t i = 0; i < tx->num_vin; i++) {
        int check = validity_input_vin_ledger_check(
            ndb, tx, i, token_id, (int)required_role);
        if (check < 0) {
            reason_set(reason, reason_size, "input_token_or_role_mismatch");
            return false;
        }
        matches += check;
    }
    if (matches == 0) {
        reason_set(reason, reason_size, "no_valid_token_input");
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

static bool validity_totals_unrepresentable(uint64_t minted, uint64_t burned)
{
    return minted > INT64_MAX || burned > minted ||
           burned > INT64_MAX || minted - burned > INT64_MAX;
}

/* Accumulates minted/burned sums and the highest validated height; returns
 * true when a uint64_t sum overflowed, having still scanned every row. */
static bool validity_summary_accumulate(
    sqlite3_stmt *s, struct zslp_token_validity_summary *out,
    uint64_t *minted, uint64_t *burned)
{
    uint64_t minted_total = 0, burned_total = 0;
    bool overflow = false;
    while (AR_STEP_ROW(s)) {
        uint64_t m = (uint64_t)AR_COL_INT(s, 0);
        uint64_t b = (uint64_t)AR_COL_INT(s, 1);
        if (m > UINT64_MAX - minted_total || b > UINT64_MAX - burned_total)
            overflow = true;
        else { minted_total += m; burned_total += b; }
        int32_t h = (int32_t)AR_COL_INT(s, 2);
        if (h > out->validated_height) out->validated_height = h;
    }
    *minted = minted_total;
    *burned = burned_total;
    return overflow;
}

static void validity_summary_load_baton(
    sqlite3_stmt *s, struct zslp_token_validity_summary *out)
{
    if (AR_STEP_ROW(s) && AR_COL_BYTES(s, 0) == 32) {
        out->baton_active = true;
        AR_READ_BLOB(s, 0, out->baton_txid, 32);
        out->baton_vout = (int32_t)AR_COL_INT(s, 1);
    }
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
    bool overflow = validity_summary_accumulate(s, out, &minted, &burned);
    AR_FINALIZE(s);
    if (overflow || validity_totals_unrepresentable(minted, burned))
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
    validity_summary_load_baton(s, out);
    AR_FINALIZE(s);
    return true;
}
