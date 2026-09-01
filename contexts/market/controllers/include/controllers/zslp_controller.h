/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZSLP token controller — create, mint, send, and track tokens.
 *
 * Integrates with the store for payment-triggered minting
 * and with the wallet for shielded payment detection. */

#ifndef ZCL_CONTROLLERS_ZSLP_H
#define ZCL_CONTROLLERS_ZSLP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct zslp_tx_receipt {
    char txid[65];
    int64_t fee_paid;
    bool broadcast;
};

/* Create a new ZSLP token (GENESIS).
 * Returns the token_id (hex) or NULL on failure. */
const char *zslp_create_token(const char *datadir,
                               const char *ticker,
                               const char *name,
                               uint8_t decimals,
                               uint64_t initial_supply);

/* Mint additional tokens (requires mint baton).
 * Sends tokens to recipient_addr (t-address). */
bool zslp_mint(const char *datadir,
                const char *token_id_hex,
                const char *recipient_addr,
                uint64_t amount);

/* Send tokens from our wallet to an address. */
bool zslp_send(const char *datadir,
                const char *token_id_hex,
                const char *to_addr,
                uint64_t amount);

/* Receipt-bearing variants used by typed native plan/commit commands. */
const char *zslp_create_token_with_receipt(
    const char *datadir, const char *ticker, const char *name,
    uint8_t decimals, uint64_t initial_supply,
    struct zslp_tx_receipt *receipt);
bool zslp_mint_with_receipt(const char *datadir, const char *token_id_hex,
                            const char *recipient_addr, uint64_t amount,
                            struct zslp_tx_receipt *receipt);
bool zslp_send_with_receipt(const char *datadir, const char *token_id_hex,
                            const char *to_addr, uint64_t amount,
                            struct zslp_tx_receipt *receipt);
bool zslp_burn_with_receipt(const char *datadir, const char *token_id_hex,
                            uint64_t amount,
                            struct zslp_tx_receipt *receipt);

/* Get token balance for an address (scans OP_RETURN outputs). */
uint64_t zslp_balance(const char *datadir,
                       const char *token_id_hex,
                       const char *addr);

/* Generate a fresh z-address for receiving shielded payment. */
bool zslp_generate_payment_address(const char *datadir,
                                    char *z_addr_out, size_t max);

/* Check if a z-address has received a payment of at least min_amount.
 * Returns the amount received, or 0 if no payment. */
int64_t zslp_check_payment(const char *datadir,
                            const char *z_addr,
                            int64_t min_amount);

/* Set the datadir for RPC commands */
void zslp_rpc_set_datadir(const char *datadir);

/* Register ZSLP RPC commands */
struct rpc_table;
void register_zslp_rpc_commands(struct rpc_table *t);
void register_zslp_transaction_rpc_commands(struct rpc_table *t);

#endif
