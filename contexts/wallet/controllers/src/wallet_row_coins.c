/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Confirm a projection row against the coins database. See
 * controllers/wallet_row_coins.h. */

#include "controllers/wallet_row_coins.h"

#include "coins/coins.h"
#include "coins/coins_view.h"
#include "core/uint256.h"

#include <string.h>

static enum wallet_row_verdict wallet_row_compare(const struct coins *c,
    uint32_t vout, int64_t value, const uint8_t *script, size_t script_len,
    struct wallet_row_coin *out)
{
    if (!coins_is_available(c, vout))
        return WALLET_ROW_NO_COIN;
    const struct tx_out *o = &c->vout[vout];
    if (o->value != value)
        return WALLET_ROW_AMOUNT;
    if (!script || o->script_pub_key.size != script_len ||
        memcmp(o->script_pub_key.data, script, script_len) != 0)
        return WALLET_ROW_SCRIPT;
    out->height = c->height;
    out->is_coinbase = c->is_coinbase;
    return WALLET_ROW_AGREES;
}

enum wallet_row_verdict wallet_row_check_coin(
    struct coins_view_cache *coins, const uint8_t txid[32], uint32_t vout,
    int64_t value, const uint8_t *script, size_t script_len,
    struct wallet_row_coin *out)
{
    if (!coins || !txid || !out)
        return WALLET_ROW_NO_COIN;
    struct uint256 id;
    memcpy(id.data, txid, sizeof(id.data));
    struct coins c;
    coins_init(&c);
    enum wallet_row_verdict v = WALLET_ROW_NO_COIN;
    if (coins_view_cache_get_coins(coins, &id, &c))
        v = wallet_row_compare(&c, vout, value, script, script_len, out);
    coins_free(&c);
    return v;
}
