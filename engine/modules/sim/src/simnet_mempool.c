/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_mempool — deterministic FIFO holder for simulator transactions.
 */

#include "sim/simnet_mempool.h"

#include "coins/coins.h"
#include "coins/coins_view.h"
#include "consensus/consensus.h"
#include "core/amount.h"
#include "domain/consensus/locktime.h"
#include "primitives/transaction.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void mempool_result_clear(struct simnet_mempool_result *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->reason = SIMNET_MEMPOOL_OK;
    uint256_set_null(&out->txid);
}

const char *simnet_mempool_reject_name(enum simnet_mempool_reject reason)
{
    switch (reason) {
    case SIMNET_MEMPOOL_OK: return "ok";
    case SIMNET_MEMPOOL_REJECT_INVALID_ARGS: return "invalid_args";
    case SIMNET_MEMPOOL_REJECT_OOM: return "oom";
    case SIMNET_MEMPOOL_REJECT_COINBASE: return "coinbase";
    case SIMNET_MEMPOOL_REJECT_MISSING_INPUT: return "missing_input";
    case SIMNET_MEMPOOL_REJECT_CONFLICT: return "conflict";
    case SIMNET_MEMPOOL_REJECT_DUPLICATE_INPUT: return "duplicate_input";
    case SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW: return "value_overflow";
    case SIMNET_MEMPOOL_REJECT_COINBASE_IMMATURE: return "coinbase_immature";
    case SIMNET_MEMPOOL_REJECT_NONFINAL: return "nonfinal";
    }
    return "unknown";
}

static bool mempool_reject(struct simnet *s, struct simnet_mempool_result *out,
                           enum simnet_mempool_reject reason,
                           const char *detail)
{
    if (s) {
        s->mempool_last_reject = (int)reason;
        snprintf(s->mempool_last_detail, sizeof(s->mempool_last_detail),
                 "%s", detail ? detail : "");
    }
    if (out) {
        out->reason = reason;
        snprintf(out->detail, sizeof(out->detail), "%s",
                 detail ? detail : "");
    }
    LOG_FAIL("simnet.mempool", "reject %s: %s",
             simnet_mempool_reject_name(reason), detail ? detail : "");
}

static bool outpoint_seen_in_tx(const struct transaction *tx, size_t upto,
                                const struct outpoint *op)
{
    for (size_t i = 0; i < upto; i++) {
        if (outpoint_cmp(&tx->vin[i].prevout, op) == 0)
            return true;
    }
    return false;
}

static bool outpoint_seen_in_mempool(const struct simnet *s,
                                     const struct outpoint *op)
{
    for (size_t i = 0; i < s->mempool_count; i++) {
        const struct transaction *held = &s->mempool_txs[i];
        for (size_t j = 0; j < held->num_vin; j++) {
            if (outpoint_cmp(&held->vin[j].prevout, op) == 0)
                return true;
        }
    }
    return false;
}

static bool mempool_validate_values(struct simnet *s,
                                    const struct transaction *tx,
                                    struct simnet_mempool_result *out,
                                    int64_t *fee_out)
{
    int64_t value_out = transaction_get_value_out(tx);
    if (value_out < 0 || !MoneyRange(value_out))
        return mempool_reject(s, out, SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW,
                              "transaction output value is out of range");

    int64_t value_in = 0;
    int next_height = s->tip_height + 1;

    for (size_t i = 0; i < tx->num_vin; i++) {
        const struct outpoint *op = &tx->vin[i].prevout;
        if (outpoint_seen_in_tx(tx, i, op))
            return mempool_reject(s, out,
                                  SIMNET_MEMPOOL_REJECT_DUPLICATE_INPUT,
                                  "transaction spends the same input twice");
        if (outpoint_seen_in_mempool(s, op))
            return mempool_reject(s, out, SIMNET_MEMPOOL_REJECT_CONFLICT,
                                  "input conflicts with a held transaction");

        struct coins coin;
        coins_init(&coin);
        if (!coins_view_cache_get_coins(&s->view, &op->hash, &coin) ||
            !coins_is_available(&coin, op->n)) {
            coins_free(&coin);
            return mempool_reject(s, out,
                                  SIMNET_MEMPOOL_REJECT_MISSING_INPUT,
                                  "input coin is absent or already spent");
        }

        if (coin.is_coinbase &&
            next_height - coin.height < COINBASE_MATURITY) {
            coins_free(&coin);
            return mempool_reject(s, out,
                                  SIMNET_MEMPOOL_REJECT_COINBASE_IMMATURE,
                                  "coinbase input is not mature at next height");
        }

        int64_t v = coin.vout[op->n].value;
        coins_free(&coin);
        if (!MoneyRange(v) || value_in > MAX_MONEY - v)
            return mempool_reject(s, out,
                                  SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW,
                                  "input value sum is out of range");
        value_in += v;
    }

    if (value_in < value_out)
        return mempool_reject(s, out,
                              SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW,
                              "input value is below output value");

    *fee_out = value_in - value_out;
    if (!MoneyRange(*fee_out))
        return mempool_reject(s, out,
                              SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW,
                              "fee is out of range");
    return true;
}

bool simnet_mempool_add(struct simnet *s, const struct transaction *tx,
                        struct simnet_mempool_result *out)
{
    mempool_result_clear(out);
    if (!s || !s->initialized || !tx)
        return mempool_reject(s, out, SIMNET_MEMPOOL_REJECT_INVALID_ARGS,
                              "invalid simnet or transaction");
    if (transaction_is_coinbase(tx))
        return mempool_reject(s, out, SIMNET_MEMPOOL_REJECT_COINBASE,
                              "coinbase transactions cannot enter mempool");
    if (tx->num_vin == 0)
        return mempool_reject(s, out, SIMNET_MEMPOOL_REJECT_MISSING_INPUT,
                              "transaction has no inputs");

    if (!domain_consensus_tx_is_final(tx, s->tip_height + 1,
                                      (int64_t)s->next_block_time)) {
        return mempool_reject(s, out, SIMNET_MEMPOOL_REJECT_NONFINAL,
                              "transaction locktime is not final for next block");
    }

    int64_t fee = 0;
    if (!mempool_validate_values(s, tx, out, &fee))
        return false;

    if (s->mempool_count == s->mempool_cap) {
        size_t new_cap = s->mempool_cap ? s->mempool_cap * 2 : 8;
        if (new_cap < s->mempool_cap)
            return mempool_reject(s, out,
                                  SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW,
                                  "mempool capacity overflow");
        struct transaction *ntxs =
            zcl_realloc(s->mempool_txs, new_cap * sizeof(*ntxs),
                        "simnet_mempool_txs");
        if (!ntxs)
            return mempool_reject(s, out, SIMNET_MEMPOOL_REJECT_OOM,
                                  "allocating mempool tx storage failed");
        s->mempool_txs = ntxs;
        s->mempool_cap = new_cap;
    }

    struct transaction copy;
    if (!transaction_copy(&copy, tx))
        return mempool_reject(s, out, SIMNET_MEMPOOL_REJECT_OOM,
                              "copying accepted transaction failed");
    transaction_compute_hash(&copy);

    size_t tx_size = transaction_serialize_size(&copy);
    if (tx_size == 0) {
        transaction_free(&copy);
        return mempool_reject(s, out,
                              SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW,
                              "transaction serialization failed");
    }

    s->mempool_txs[s->mempool_count++] = copy;
    s->mempool_last_reject = (int)SIMNET_MEMPOOL_OK;
    s->mempool_last_detail[0] = '\0';

    if (out) {
        out->reason = SIMNET_MEMPOOL_OK;
        out->txid = copy.hash;
        out->fee = fee;
        out->tx_size = tx_size;
        out->detail[0] = '\0';
    }
    return true;
}

bool simnet_mempool_mint(struct simnet *s)
{
    if (!s || !s->initialized)
        LOG_FAIL("simnet.mempool", "uninitialized simnet");

    size_t n = s->mempool_count;
    bool ok = simnet_mint_txs(s, s->mempool_txs, n);
    s->mempool_count = 0;
    return ok;
}

size_t simnet_mempool_size(const struct simnet *s)
{
    return (s && s->initialized) ? s->mempool_count : 0;
}

enum simnet_mempool_reject simnet_mempool_last_reject(const struct simnet *s)
{
    return (s && s->initialized)
        ? (enum simnet_mempool_reject)s->mempool_last_reject
        : SIMNET_MEMPOOL_REJECT_INVALID_ARGS;
}

const char *simnet_mempool_last_reject_detail(const struct simnet *s)
{
    return (s && s->initialized) ? s->mempool_last_detail : "invalid simnet";
}
