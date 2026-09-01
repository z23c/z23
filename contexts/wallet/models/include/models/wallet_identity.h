/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Persistent, non-secret identity for one initialized wallet database. */

#ifndef ZCL_MODELS_WALLET_IDENTITY_H
#define ZCL_MODELS_WALLET_IDENTITY_H

#include "models/activerecord.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;

#define WALLET_INSTANCE_ID_HEX_LEN 32
#define WALLET_GENESIS_HEX_LEN 64
#define WALLET_OPERATOR_LANE_MAX 15

struct wallet_identity_row {
    char wallet_instance_id[WALLET_INSTANCE_ID_HEX_LEN + 1];
    uint8_t network_genesis[32];
    char operator_lane[WALLET_OPERATOR_LANE_MAX + 1];
    int64_t created_at;
};

struct ar_callbacks *db_wallet_identity_callbacks(void);
bool wallet_identity_validate(const struct wallet_identity_row *row,
                              struct ar_errors *errors);
bool wallet_identity_find(struct node_db *ndb, struct wallet_identity_row *out);

/* Return the existing identity, or create it exactly once. Existing rows are
 * never rewritten: a genesis/lane mismatch is a conflict, not a migration. */
bool wallet_identity_ensure(struct node_db *ndb,
                            const uint8_t network_genesis[32],
                            const char *operator_lane,
                            struct wallet_identity_row *out);

void wallet_identity_genesis_hex(const struct wallet_identity_row *row,
                                 char out[WALLET_GENESIS_HEX_LEN + 1]);

#endif
