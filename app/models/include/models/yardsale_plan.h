/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ActiveRecord persistence for the yardsale wallet-glue
 *          plan/commit idempotency ledger (table yardsale_plans, schema
 *          v50).
 *
 * One row per operator request identity: the seller-arm request (one
 * wallet token outpoint + one live sign root) or the buy request (one
 * live sign root). payload_hex is the EXACT planned terms — the canonical
 * zswap accept-data serialization plus the sign root — and never carries
 * key material: keys are re-fetched from the wallet at commit time and
 * live only in process memory. */

#ifndef ZCL_MODELS_YARDSALE_PLAN_H
#define ZCL_MODELS_YARDSALE_PLAN_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Longest payload is the buy plan: ad_root (32) || canonical buyer accept
 * (16 inputs x 174 bytes + 144) — about 3.0 KB raw, hex doubles it. */
#define YARDSALE_PLAN_PAYLOAD_HEX_MAX 8192

#define YARDSALE_PLAN_KIND_ARM "arm"
#define YARDSALE_PLAN_KIND_BUY "buy"

#define YARDSALE_PLAN_STATE_PLANNED "PLANNED"
#define YARDSALE_PLAN_STATE_ARMING "ARMING"
#define YARDSALE_PLAN_STATE_COMMITTED "COMMITTED"
#define YARDSALE_PLAN_STATE_EXPIRED "EXPIRED"

enum db_yardsale_plan_claim_result {
    DB_YARDSALE_PLAN_CLAIM_ERROR = -1,
    DB_YARDSALE_PLAN_CLAIM_REFUSED = 0,
    DB_YARDSALE_PLAN_CLAIMED = 1,
};

struct db_yardsale_plan {
    char plan_root[65];
    char kind[8]; /* "arm" | "buy" */
    char request_hash[65];
    char payload_hex[YARDSALE_PLAN_PAYLOAD_HEX_MAX];
    char result[24]; /* empty until committed: "armed" | "begun" */
    char state[16];  /* PLANNED | COMMITTED | EXPIRED */
    int64_t expires_unix;
    int64_t created_at;
};

struct ar_callbacks *db_yardsale_plan_callbacks(void);

bool db_yardsale_plan_validate(
    const struct db_yardsale_plan *row, struct ar_errors *errors);

bool db_yardsale_plan_save(
    struct node_db *ndb, const struct db_yardsale_plan *row);
enum db_yardsale_plan_claim_result db_yardsale_plan_claim(
    struct node_db *ndb, struct db_yardsale_plan *row, int64_t now_unix);
bool db_yardsale_plan_find_by_request(
    struct node_db *ndb, const char *request_hash,
    struct db_yardsale_plan *out);
bool db_yardsale_plan_find(
    struct node_db *ndb, const char *plan_root,
    struct db_yardsale_plan *out);

#endif /* ZCL_MODELS_YARDSALE_PLAN_H */
