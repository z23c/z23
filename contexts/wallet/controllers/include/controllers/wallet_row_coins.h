/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Confirm a row of the SQLite utxos or wallet_utxos projection against the
 * coins database before it becomes wallet state. The coins database is the
 * authority; the projections are read models that can be stale. */

#ifndef ZCL_CONTROLLERS_WALLET_ROW_COINS_H
#define ZCL_CONTROLLERS_WALLET_ROW_COINS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct coins_view_cache;

enum wallet_row_verdict {
    WALLET_ROW_AGREES,    /* the coin exists and its amount and script match */
    WALLET_ROW_NO_COIN,   /* no such coin, or that output is spent */
    WALLET_ROW_AMOUNT,    /* the coin carries another amount */
    WALLET_ROW_SCRIPT,    /* the coin carries another script */
};

/* What the coin says about the row, to be used in place of the row's own. */
struct wallet_row_coin {
    int height;
    bool is_coinbase;
};

/* Look the outpoint up in `coins` and compare the row's amount and script. A
 * NULL `coins` is WALLET_ROW_NO_COIN; callers that must tell "no coins view"
 * from "no such coin" test for NULL first. `out` is filled only on
 * WALLET_ROW_AGREES. */
enum wallet_row_verdict wallet_row_check_coin(
    struct coins_view_cache *coins, const uint8_t txid[32], uint32_t vout,
    int64_t value, const uint8_t *script, size_t script_len,
    struct wallet_row_coin *out);

#endif
