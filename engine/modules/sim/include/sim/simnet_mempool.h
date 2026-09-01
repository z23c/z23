/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_mempool — deterministic FIFO transaction holder for simnet.
 *
 * This is a simulator admission layer, not production relay policy. It checks
 * structure against the current in-memory sim chain view, stores accepted txs
 * in FIFO order, and mints the whole held set in the next sim block.
 */

#ifndef ZCL_SIM_SIMNET_MEMPOOL_H
#define ZCL_SIM_SIMNET_MEMPOOL_H

#include "sim/simnet.h"
#include "core/uint256.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum simnet_mempool_reject {
    SIMNET_MEMPOOL_OK = 0,
    SIMNET_MEMPOOL_REJECT_INVALID_ARGS,
    SIMNET_MEMPOOL_REJECT_OOM,
    SIMNET_MEMPOOL_REJECT_COINBASE,
    SIMNET_MEMPOOL_REJECT_MISSING_INPUT,
    SIMNET_MEMPOOL_REJECT_CONFLICT,
    SIMNET_MEMPOOL_REJECT_DUPLICATE_INPUT,
    SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW,
    SIMNET_MEMPOOL_REJECT_COINBASE_IMMATURE,
    SIMNET_MEMPOOL_REJECT_NONFINAL,
};

struct simnet_mempool_result {
    enum simnet_mempool_reject reason;
    char detail[128];
    struct uint256 txid;
    int64_t fee;
    size_t tx_size;
};

/* Accept a transaction into the simulator FIFO mempool. On success the tx is
 * deep-copied; caller retains ownership of `tx`. On failure `out->reason`
 * names the structural reject and no mempool state changes. */
bool simnet_mempool_add(struct simnet *s, const struct transaction *tx,
                        struct simnet_mempool_result *out);

/* Mint the current FIFO held set in one block via simnet_mint_txs(). The held
 * set is consumed on either accept or connect failure. With an empty mempool,
 * this mints a coinbase-only block. */
bool simnet_mempool_mint(struct simnet *s);

size_t simnet_mempool_size(const struct simnet *s);
enum simnet_mempool_reject simnet_mempool_last_reject(const struct simnet *s);
const char *simnet_mempool_last_reject_detail(const struct simnet *s);
const char *simnet_mempool_reject_name(enum simnet_mempool_reject reason);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_MEMPOOL_H */
