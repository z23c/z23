/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Strict application-overlay validity for ZSLP Type-1 transactions. */
#ifndef ZCL_DB_MODEL_ZSLP_VALIDITY_H
#define ZCL_DB_MODEL_ZSLP_VALIDITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct transaction;
struct slp_message;

enum zslp_validity_status {
    ZSLP_VALIDITY_UNKNOWN = 0,
    ZSLP_VALIDITY_VALID = 1,
    ZSLP_VALIDITY_INVALID = 2,
};

enum zslp_ledger_role {
    ZSLP_LEDGER_TOKEN = 1,
    ZSLP_LEDGER_MINT_BATON = 2,
};

bool zslp_validity_apply_height(struct node_db *ndb, int32_t height,
                                const uint8_t prev_digest[32],
                                uint8_t out_digest[32]);
bool zslp_validity_apply_live(struct node_db *ndb,
                              const struct transaction *tx,
                              const struct slp_message *msg, int32_t height);
void zslp_validity_mark_live_spends(struct node_db *ndb,
                                    const struct transaction *tx,
                                    int32_t height);
enum zslp_validity_status zslp_validity_get(
    struct node_db *ndb, const uint8_t txid[32], char *reason,
    size_t reason_size);
bool zslp_validity_is_caught_up(struct node_db *ndb, int32_t provable_tip,
                                int32_t *cursor_out);
bool zslp_validity_inputs_match(struct node_db *ndb,
                                const struct transaction *tx,
                                const uint8_t token_id[32],
                                enum zslp_ledger_role required_role,
                                char *reason, size_t reason_size);
int64_t zslp_validity_count(struct node_db *ndb,
                            enum zslp_validity_status status);

struct zslp_token_validity_summary {
    int64_t total_minted;
    int64_t total_burned;
    int64_t circulating_supply;
    int32_t validated_height;
    bool baton_active;
    uint8_t baton_txid[32];
    int32_t baton_vout;
};
bool zslp_validity_token_summary(
    struct node_db *ndb, const uint8_t token_id[32],
    struct zslp_token_validity_summary *out);

#endif
