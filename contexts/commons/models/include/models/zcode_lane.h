/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read-only-index projection of canonical ZCODE lane receipts. */

#ifndef ZCL_MODELS_ZCODE_LANE_H
#define ZCL_MODELS_ZCODE_LANE_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct db_zcode_lane_receipt {
    char receipt_id[65];
    char source_root_sha3[65];
    char task_root_sha3[65];
    char candidate_root_sha3[65];
    char proof_policy_root_sha3[65];
    char proof_set_root_sha3[65];
    char prior_receipt_root_sha3[65];
    char signer_pubkey[65];
    int lane;
    int64_t created_at;
};

struct ar_callbacks *db_zcode_lane_receipt_callbacks(void);
bool db_zcode_lane_receipt_validate(
    const struct db_zcode_lane_receipt *row, struct ar_errors *errors);
bool db_zcode_lane_receipt_save(
    struct node_db *ndb, const struct db_zcode_lane_receipt *row);
bool db_zcode_lane_receipt_find(
    struct node_db *ndb, const char *receipt_id,
    struct db_zcode_lane_receipt *out);
bool db_zcode_lane_latest(
    struct node_db *ndb, const char *source_root_sha3,
    struct db_zcode_lane_receipt *out);

#endif /* ZCL_MODELS_ZCODE_LANE_H */
