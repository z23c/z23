/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: SwapContract (atomic cross-chain HTLC)
 *
 * Owns the integrity and persistence contract for the `zswp_contracts`
 * table. The HTLC script builder/parser lives in core/modules/script/src/htlc.c. */

#include "models/swap_contract.h"
#include "util/log_macros.h"

#include <ctype.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>

DEFINE_MODEL_CALLBACKS(swap_contract)

static bool read_swap_blob(sqlite3_stmt *s, int col, void *dest,
                           int expected_len, const char *column)
{
    int got = sqlite3_column_bytes(s, col);
    const void *blob = sqlite3_column_blob(s, col);
    if (!blob || got != expected_len)
        LOG_FAIL("htlc",
                 "zswp_contracts.%s blob length mismatch: got=%d expected=%d",
                 column, got, expected_len);

    AR_READ_BLOB(s, col, dest, expected_len);
    return true;
}

static bool read_swap_optional_blob(sqlite3_stmt *s, int col, void *dest,
                                    int expected_len, const char *column,
                                    bool *present)
{
    *present = false;
    if (sqlite3_column_type(s, col) == SQLITE_NULL) {
        memset(dest, 0, (size_t)expected_len);
        return true;
    }

    if (!read_swap_blob(s, col, dest, expected_len, column))
        LOG_FAIL("htlc", "zswp_contracts.%s rejected", column);

    *present = true;
    return true;
}

static bool is_lowercase_hex(const char *s)
{
    if (!s) return false;
    for (; *s; ++s)
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f')))
            return false;
    return true;
}

bool db_swap_contract_validate(const struct swap_contract *swap,
                               struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!swap) {
        ar_errors_add(errors, "swap", "is NULL");
        return false;
    }

    static const uint8_t zero32[32] = {0};

    validates_presence_of(errors, swap, swap_id);
    if (swap->swap_id[0]) {
        validates_custom(errors,
            is_lowercase_hex(swap->swap_id),
            "swap_id", "must be lowercase hex");
    }
    static const enum swap_role valid_roles[] = {
        SWAP_INITIATOR, SWAP_PARTICIPANT
    };
    static const enum swap_state valid_states[] = {
        SWAP_PENDING, SWAP_FUNDED, SWAP_REDEEMED, SWAP_REFUNDED, SWAP_EXPIRED
    };
    static const enum swap_chain valid_chains[] = {
        SWAP_CHAIN_ZCL, SWAP_CHAIN_BTC, SWAP_CHAIN_LTC, SWAP_CHAIN_DOGE
    };
    validates_inclusion_of(errors, swap, role,  valid_roles,  2);
    validates_inclusion_of(errors, swap, state, valid_states, 5);
    validates_inclusion_of(errors, swap, chain, valid_chains, 4);
    validates_custom(errors,
        memcmp(swap->secret_hash, zero32, 32) != 0,
        "secret_hash", "can't be all zero");
    if (swap->has_secret) {
        validates_custom(errors,
            memcmp(swap->secret, zero32, 32) != 0,
            "secret", "can't be all zero when has_secret is true");
    }
    validates_positive(errors, swap, amount);
    validates_not_zero(errors, swap, locktime);
    validates_presence_of(errors, swap, my_address);
    validates_presence_of(errors, swap, counter_address);
    validates_range(errors, swap, redeem_script_len, 1, 256);
    validates_presence_of(errors, swap, p2sh_address);
    validates_non_negative(errors, swap, created_at);

    return !ar_errors_any(errors);
}

/* Single source of truth for the zswp_contracts column list. Position-coupled
 * to row_to_swap() and the db_swap_save() bind sequence (columns 0..15). */
#define SWAP_COLS \
    "swap_id,role,state,chain,secret_hash,secret,amount,locktime," \
    "my_address,counter_address,funding_txid,funding_vout," \
    "redeem_script,redeem_script_len,p2sh_address,created_at"

bool db_swap_save(struct node_db *ndb, const struct swap_contract *swap)
{
    if (!ndb || !ndb->open) LOG_FAIL("htlc", "db_swap_save: db not open");
    if (!swap) LOG_FAIL("htlc", "db_swap_save: swap is NULL");

    struct ar_callbacks *cbs = db_swap_contract_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO zswp_contracts(" SWAP_COLS ")"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        cbs, "swap_contract", swap, db_swap_contract_validate,
        AR_BIND_TEXT(s, 1, swap->swap_id);
        AR_BIND_INT(s, 2, swap->role);
        AR_BIND_INT(s, 3, swap->state);
        AR_BIND_INT(s, 4, swap->chain);
        AR_BIND_BLOB(s, 5, swap->secret_hash, 32);
        if (swap->has_secret)
            AR_BIND_BLOB(s, 6, swap->secret, 32);
        else
            AR_BIND_NULL(s, 6);
        AR_BIND_INT(s, 7, swap->amount);
        AR_BIND_INT(s, 8, (int)swap->locktime);
        AR_BIND_TEXT(s, 9, swap->my_address);
        AR_BIND_TEXT(s, 10, swap->counter_address);
        AR_BIND_BLOB(s, 11, swap->funding_txid, 32);
        AR_BIND_INT(s, 12, (int)swap->funding_vout);
        AR_BIND_BLOB(s, 13, swap->redeem_script,
                     (int)swap->redeem_script_len);
        AR_BIND_INT(s, 14, (int)swap->redeem_script_len);
        AR_BIND_TEXT(s, 15, swap->p2sh_address);
        AR_BIND_INT(s, 16, swap->created_at));
}

static bool row_to_swap(sqlite3_stmt *s, struct swap_contract *out)
{
    memset(out, 0, sizeof(*out));
    const char *str = (const char *)sqlite3_column_text(s, 0);
    if (str) snprintf(out->swap_id, sizeof(out->swap_id), "%s", str);

    out->role = (enum swap_role)sqlite3_column_int(s, 1);
    out->state = (enum swap_state)sqlite3_column_int(s, 2);
    out->chain = (enum swap_chain)sqlite3_column_int(s, 3);

    if (!read_swap_blob(s, 4, out->secret_hash, 32, "secret_hash"))
        LOG_FAIL("htlc", "zswp_contracts.secret_hash rejected");

    bool has_secret = false;
    if (!read_swap_optional_blob(s, 5, out->secret, 32, "secret", &has_secret))
        LOG_FAIL("htlc", "zswp_contracts.secret rejected");
    out->has_secret = has_secret;

    out->amount = sqlite3_column_int64(s, 6);
    out->locktime = (uint32_t)sqlite3_column_int(s, 7);

    str = (const char *)sqlite3_column_text(s, 8);
    if (str) snprintf(out->my_address, sizeof(out->my_address), "%s", str);

    str = (const char *)sqlite3_column_text(s, 9);
    if (str) snprintf(out->counter_address, sizeof(out->counter_address),
                      "%s", str);

    if (!read_swap_blob(s, 10, out->funding_txid, 32, "funding_txid"))
        LOG_FAIL("htlc", "zswp_contracts.funding_txid rejected");

    out->funding_vout = (uint32_t)sqlite3_column_int(s, 11);

    const void *blob = sqlite3_column_blob(s, 12);
    int rlen = sqlite3_column_int(s, 13);
    int rbytes = sqlite3_column_bytes(s, 12);
    if (rlen <= 0 || rlen > 256)
        LOG_FAIL("htlc",
                 "zswp_contracts.redeem_script_len invalid: got=%d "
                 "expected=1..256",
                 rlen);
    if (!blob || rbytes != rlen)
        LOG_FAIL("htlc",
                 "zswp_contracts.redeem_script blob length mismatch: "
                 "got=%d expected=%d",
                 rbytes, rlen);
    AR_READ_BLOB(s, 12, out->redeem_script, rlen);
    out->redeem_script_len = (size_t)rlen;

    str = (const char *)sqlite3_column_text(s, 14);
    if (str) snprintf(out->p2sh_address, sizeof(out->p2sh_address), "%s", str);

    out->created_at = sqlite3_column_int64(s, 15);
    return true;
}

bool db_swap_find(struct node_db *ndb, const char *swap_id,
                  struct swap_contract *out)
{
    if (!ndb || !ndb->open) return false;
    if (!swap_id || !out) return false;

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " SWAP_COLS " FROM zswp_contracts WHERE swap_id=?",
        AR_BIND_TEXT(s, 1, swap_id),
        if (!row_to_swap(s, out)) { AR_FINALIZE(s); return false; });
}

int db_swap_list(struct node_db *ndb, struct swap_contract *out,
                 size_t max, int state_filter)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "htlc", "db_swap_list: out is NULL");

    sqlite3_stmt *s = NULL;
    if (state_filter >= 0) {
        AR_QUERY_LIST(ndb, s,
            "SELECT " SWAP_COLS
            " FROM zswp_contracts WHERE state=?"
            " ORDER BY created_at DESC LIMIT ?",
            out, max,
            AR_BIND_INT(s, 1, state_filter);
            AR_BIND_INT(s, 2, (int)max),
            if (!row_to_swap(s, &out[count])) continue);
    }

    AR_QUERY_LIST(ndb, s,
        "SELECT " SWAP_COLS
        " FROM zswp_contracts ORDER BY created_at DESC LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int)max),
        if (!row_to_swap(s, &out[count])) continue);
}

bool db_swap_update_state(struct node_db *ndb, const char *swap_id,
                          enum swap_state state, const uint8_t *secret)
{
    if (!ndb || !ndb->open) return false;
    if (!swap_id) return false;

    sqlite3_stmt *s = NULL;
    if (secret) {
        AR_EXEC_BOOL(ndb, s,
            "UPDATE zswp_contracts SET state=?, secret=? WHERE swap_id=?",
            AR_BIND_INT(s, 1, state);
            AR_BIND_BLOB(s, 2, secret, 32);
            AR_BIND_TEXT(s, 3, swap_id));
    }

    AR_EXEC_BOOL(ndb, s,
        "UPDATE zswp_contracts SET state=? WHERE swap_id=?",
        AR_BIND_INT(s, 1, state);
        AR_BIND_TEXT(s, 2, swap_id));
}
