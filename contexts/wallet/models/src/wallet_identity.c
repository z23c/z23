/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: persist a random non-secret identity for one wallet database. */

#include "models/wallet_identity.h"

#include "base/hex.h"
#include "crypto/random_secret.h"
#include "models/database.h"
#include "models/model_text.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(wallet_identity)

static bool wallet_identity_before_validate(void *record, void *ctx)
{
    struct wallet_identity_row *row = record;
    (void)ctx;
    if (!row)
        return false;
    model_trim_ascii(row->wallet_instance_id);
    model_trim_ascii(row->operator_lane);
    if (row->created_at == 0)
        row->created_at = (int64_t)platform_time_wall_time_t();
    return true;
}

DEFINE_MODEL_BEFORE_VALIDATE_READY(wallet_identity,
                                   wallet_identity_before_validate)

bool wallet_identity_validate(const struct wallet_identity_row *row,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        ar_errors_add(errors, "wallet_identity", "is NULL");
        return false; /* raw-return-ok:null record cannot validate */
    }
    validates_custom(errors,
        zcl_is_hex_string(row->wallet_instance_id,
                          WALLET_INSTANCE_ID_HEX_LEN),
        "wallet_instance_id", "must be 32 lowercase/uppercase hex chars");
    validates_presence_of(errors, row, network_genesis);
    validates_string_present(errors, row->operator_lane, "operator_lane");
    validates_custom(errors,
        strlen(row->operator_lane) <= WALLET_OPERATOR_LANE_MAX &&
            model_string_is_printable(row->operator_lane),
        "operator_lane", "is invalid");
    validates_positive(errors, row, created_at);
    return !ar_errors_any(errors);
}

static void wallet_identity_read(struct wallet_identity_row *out,
                                 sqlite3_stmt *st)
{
    memset(out, 0, sizeof(*out));
    AR_READ_STR(st, 0, out->wallet_instance_id,
                sizeof(out->wallet_instance_id));
    AR_READ_BLOB(st, 1, out->network_genesis, 32);
    AR_READ_STR(st, 2, out->operator_lane, sizeof(out->operator_lane));
    out->created_at = AR_COL_INT(st, 3);
}

bool wallet_identity_find(struct node_db *ndb, struct wallet_identity_row *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !out)
        LOG_FAIL("wallet_identity", "find: invalid argument");
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT wallet_instance_id,network_genesis,operator_lane,created_at "
        "FROM wallet_identity WHERE id=1", ;,
        wallet_identity_read(out, st));
}

static bool wallet_identity_insert(struct node_db *ndb,
                                   const struct wallet_identity_row *row)
{
    sqlite3_stmt *st = NULL;
    AR_ADHOC_SAVE(ndb, st,
        "INSERT INTO wallet_identity"
        "(id,wallet_instance_id,network_genesis,operator_lane,created_at) "
        "VALUES(1,?,?,?,?)",
        wallet_identity_callbacks_ready(), "wallet_identity", row,
        wallet_identity_validate,
        AR_BIND_TEXT(st, 1, row->wallet_instance_id);
        AR_BIND_BLOB(st, 2, row->network_genesis, 32);
        AR_BIND_TEXT(st, 3, row->operator_lane);
        AR_BIND_INT(st, 4, row->created_at));
}

bool wallet_identity_ensure(struct node_db *ndb,
                            const uint8_t network_genesis[32],
                            const char *operator_lane,
                            struct wallet_identity_row *out)
{
    if (!ndb || !ndb->open || !network_genesis || !operator_lane ||
        !operator_lane[0] || !out)
        LOG_FAIL("wallet_identity", "ensure: invalid argument");

    struct wallet_identity_row existing;
    if (wallet_identity_find(ndb, &existing)) {
        if (memcmp(existing.network_genesis, network_genesis, 32) != 0 ||
            strcmp(existing.operator_lane, operator_lane) != 0)
            LOG_FAIL("wallet_identity",
                     "identity conflict: persisted lane=%s does not match "
                     "runtime lane=%s or network genesis changed",
                     existing.operator_lane, operator_lane);
        *out = existing;
        return true;
    }

    struct wallet_identity_row row;
    memset(&row, 0, sizeof(row));
    uint8_t raw[16];
    if (!zcl_random_secret_bytes(raw, sizeof(raw), "wallet_instance_id"))
        LOG_FAIL("wallet_identity", "could not draw wallet instance id");
    zcl_hex_encode(raw, sizeof(raw), row.wallet_instance_id);
    memcpy(row.network_genesis, network_genesis, 32);
    (void)snprintf(row.operator_lane, sizeof(row.operator_lane), "%s",
                   operator_lane);
    row.created_at = (int64_t)platform_time_wall_time_t();
    if (!wallet_identity_insert(ndb, &row))
        LOG_FAIL("wallet_identity", "could not persist wallet identity");
    *out = row;
    return true;
}

void wallet_identity_genesis_hex(const struct wallet_identity_row *row,
                                 char out[WALLET_GENESIS_HEX_LEN + 1])
{
    if (!out)
        return;
    if (!row) {
        out[0] = '\0';
        return;
    }
    zcl_hex_encode(row->network_genesis, 32, out);
}
