/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: register the yardsale wallet-glue RPC surface — the node-side
 * half of the yardsale.seller.arm|disarm|status and yardsale.buy native
 * commands (the CLI forwards here; the wallet, the seller profile, and
 * the pending-buy table all live in this process). The logic is
 * engine/services/src/yardsale_wallet_service*.c; these methods are the
 * wallet-context adapter only. */
#ifndef ZCL_YARDSALE_WALLET_CONTROLLER_H
#define ZCL_YARDSALE_WALLET_CONTROLLER_H

struct rpc_table;
void register_yardsale_wallet_rpc_commands(struct rpc_table *table);

#endif
