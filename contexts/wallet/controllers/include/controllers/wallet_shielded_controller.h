/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_WALLET_SHIELDED_CONTROLLER_H
#define ZCL_CONTROLLERS_WALLET_SHIELDED_CONTROLLER_H

#include <stdbool.h>

struct rpc_table;
struct json_value;
struct wallet_tx;

void register_wallet_shielded_rpc_commands(struct rpc_table *t);

/* z_sendmany, callable in-process by another RPC handler in the same node.
 * The store buyer needs this: paying an order is one step of a purchase the
 * node performs on the caller's behalf, and routing it back out through the
 * loopback socket only to re-enter the same process would put a crash window
 * between "value left the wallet" and "the purchase row knows". Same
 * contract as the dispatched call — params is the JSON array
 * [from, [{address, amount, memo|memo_hex}, ...]]; false means refused,
 * with the reason written into `result`. */
bool rpc_z_sendmany(const struct json_value *params, bool help,
                    struct json_value *result);

/* Build/sign without admitting, spending, persisting, or relaying. Ownership
 * of the initialized transaction moves to `prepared` on success. The vault
 * stores those exact bytes with its reservation before idempotent commit. */
bool z_sendmany_prepare(const struct json_value *params,
                        struct wallet_tx *prepared,
                        struct json_value *result);

/* True when `addr` is a Sapling payment address on the ACTIVE chain.
 * The human-readable part is read from chain_params_get() — mainnet
 * "zs1...", testnet "ztestsapling1...", regtest "zregtestsapling1..." —
 * because sapling_decode_payment_address() ignores the HRP, so this prefix
 * test is the only thing that routes a z_sendmany recipient to the shielded
 * branch. A hardcoded "zs1" sent every testnet/regtest z-recipient into the
 * transparent branch, where the send died on "Invalid transparent address".
 * Wallet-local routing only: no consensus effect, and a false answer can
 * only refuse a send, never mint one. Defined in wallet_shielded_send.c. */
bool wallet_addr_is_sapling(const char *addr);

#endif
