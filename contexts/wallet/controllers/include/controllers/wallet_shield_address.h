/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z_shieldaddress: move every mature coin of one public address into the
 * wallet's own newest shielded address in one transaction with no transparent
 * output. A coinbase spend may not have a transparent output on main and test
 * networks, so the sweep leaves no change by construction: the one Sapling
 * output carries total - fee.
 *
 * Params: [from|null, to, null, fee, key, input_count, total_zat]. Without a
 * key (param 4) the call only plans and changes nothing. With a key it runs
 * once through wallet_send_once_dispatch. The destination is never chosen by
 * the caller: `to` must equal the wallet's newest address for the account,
 * which the node resolves itself. Refusals are strings that start with a code
 * and a colon: NOTHING_TO_SHIELD, NO_PRIVATE_ADDRESS, PROVING_UNAVAILABLE,
 * PLAN_TOKEN_MISMATCH. */

#ifndef ZCL_CONTROLLERS_WALLET_SHIELD_ADDRESS_H
#define ZCL_CONTROLLERS_WALLET_SHIELD_ADDRESS_H

#include "models/wallet_tx.h"
#include "script/standard.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct wallet_rpc_context;
struct wallet_tx;

#define WALLET_SHIELD_MAX_INPUTS 256
#define WALLET_SHIELD_NOTHING "NOTHING_TO_SHIELD"
#define WALLET_SHIELD_NO_ADDRESS "NO_PRIVATE_ADDRESS"
#define WALLET_SHIELD_NO_PROVER "PROVING_UNAVAILABLE"
#define WALLET_SHIELD_CHANGED "PLAN_TOKEN_MISMATCH"

/* Everything one sweep is decided from. */
struct wallet_shield_plan {
    struct tx_destination from_dest;
    uint8_t from_hash[20];
    char from[128];
    char to[192];
    uint8_t to_diversifier[11];
    uint8_t to_pk_d[32];
    struct db_wallet_utxo coins[WALLET_SHIELD_MAX_INPUTS];
    size_t count;           /* coins taken, at most WALLET_SHIELD_MAX_INPUTS */
    size_t remaining;       /* mature coins beyond the cap */
    size_t coinbase_count;  /* taken coins that are coinbase outputs */
    int64_t total;          /* sum of the taken coins */
    int64_t fee;
    int64_t maturing;       /* coinbase value of the address not yet mature */
    int tip;
    int32_t floor;          /* WALLET_SPEND_NO_FLOOR unless the phone rule */
    bool have_from;
};

enum wallet_shield_load {
    WALLET_SHIELD_LOAD_OK = 0,
    WALLET_SHIELD_LOAD_NO_ADDRESS,
    WALLET_SHIELD_LOAD_ERROR      /* `result` holds the reason */
};

/* Resolve the destination and the source, then take every mature coin of the
 * source up to the cap. `from` may be NULL: the address with the largest mature
 * total is used. plan->floor must be set by the caller. */
enum wallet_shield_load wallet_shield_load(struct wallet_rpc_context *ctx,
                                           const char *from,
                                           struct wallet_shield_plan *plan,
                                           struct json_value *result);

/* The unsigned transaction: one input per coin, no transparent output,
 * value_balance = -(total - fee). No proof is made. Frees nothing on failure
 * beyond its own allocation. */
bool wallet_shield_assemble(const struct wallet_shield_plan *plan,
                            struct wallet_tx *wtx, struct json_value *result);

/* The finished, signed transaction with its Sapling output proof and binding
 * signature, ready to admit. On failure `result` holds the reason and nothing
 * is left allocated; on success the caller owns wtx->tx. */
bool wallet_shield_build(struct wallet_rpc_context *ctx,
                         const struct wallet_shield_plan *plan,
                         struct wallet_tx *wtx, struct json_value *result);

void wallet_shield_plan_free(struct wallet_shield_plan *plan);

bool rpc_z_shieldaddress(const struct json_value *params, bool help,
                         struct json_value *result);

#endif /* ZCL_CONTROLLERS_WALLET_SHIELD_ADDRESS_H */
