/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_wallet — high-level transparent transaction toolkit for simnet.
 */

#ifndef ZCL_SIM_SIMNET_WALLET_H
#define ZCL_SIM_SIMNET_WALLET_H

#include "core/amount.h"
#include "core/uint256.h"
#include "script/script.h"
#include "sim/simnet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct simnet_wallet;

struct simnet_tx_result {
    struct uint256 txid;
    int64_t fee;
    size_t tx_size;
    int64_t input_value;
    int64_t output_value;
    int64_t change_value;
    uint32_t change_vout; /* UINT32_MAX when no change output was created */
};

struct simnet_wallet_recipient {
    const struct script *script;       /* used directly when non-NULL */
    struct simnet_wallet *wallet;      /* otherwise pay this wallet */
    int64_t amount;
};

struct simnet_wallet *simnet_wallet_create(struct simnet *s);
void simnet_wallet_free(struct simnet_wallet *w);

const char *simnet_wallet_address(const struct simnet_wallet *w);
const struct script *simnet_wallet_script(const struct simnet_wallet *w);
int64_t simnet_wallet_balance(struct simnet_wallet *w);
/* Size-proportional catalog rate for simnet fees, in zats per kB. This is
 * not the live wallet's flat WALLET_DEFAULT_FEE_ZAT min-relay floor. */
#define SIMNET_WALLET_DEFAULT_FEE_PER_K 10000
int64_t simnet_wallet_default_fee_per_k(void);
struct fee_rate simnet_wallet_default_fee_rate(void);

bool simnet_wallet_fund(struct simnet_wallet *w, int64_t amount,
                        struct simnet_tx_result *out);
bool simnet_wallet_send(struct simnet_wallet *from, const struct script *to,
                        int64_t amount, struct simnet_tx_result *out);
bool simnet_wallet_send_to_wallet(struct simnet_wallet *from,
                                  struct simnet_wallet *to,
                                  int64_t amount,
                                  struct simnet_tx_result *out);
bool simnet_wallet_send_many(struct simnet_wallet *from,
                             const struct simnet_wallet_recipient *recips,
                             size_t nrecips,
                             struct simnet_tx_result *out);
bool simnet_wallet_op_return(struct simnet_wallet *from,
                             const uint8_t *payload, size_t payload_len,
                             const struct simnet_wallet_recipient *value_out,
                             struct simnet_tx_result *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_WALLET_H */
