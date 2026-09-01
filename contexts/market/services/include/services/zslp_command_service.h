/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ZSLP command service — command-side workflow helpers. */

#ifndef ZCL_ZSLP_COMMAND_SERVICE_H
#define ZCL_ZSLP_COMMAND_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "models/zslp.h"
#include "services/zslp_service.h"
#include "util/result.h"

struct wallet;
struct wallet_tx;
struct wallet_tx_admission;

/* Add one canonical OP_RETURN as vout[0], then sign every transparent input
 * and compute the exact transaction id without admitting or relaying it.
 * Durable plan/commit workflows persist these exact bytes during plan and
 * publish the same bytes later.  No private key leaves the resident wallet. */
struct zcl_result zslp_command_prepare_with_op_return(
    struct wallet *wallet, struct wallet_tx *wtx,
    const uint8_t *op_script, size_t script_len);

/* Compatibility wrapper for direct-broadcast controllers.  New typed agent
 * mutations should call prepare during plan and publish the persisted bytes
 * during commit. */
struct zcl_result zslp_command_commit_with_op_return(struct wallet *wallet,
                                        struct wallet_tx *wtx,
                                        const struct wallet_tx_admission *admission,
                                        const uint8_t *op_script,
                                        size_t script_len);
struct zcl_result zslp_command_build_genesis_base_tx(struct wallet *wallet,
                                        struct wallet_tx *wtx,
                                        int64_t *fee_paid,
                                        const char **tx_error);
struct zcl_result zslp_command_build_send_base_tx(struct wallet *wallet,
                                     const char *to_addr,
                                     struct wallet_tx *wtx,
                                     int64_t *fee_paid,
                                     const char **tx_error);

/* Custody-correct ZSLP builders. SEND consumes confirmed wallet-owned token
 * outputs and returns token change; MINT consumes the wallet-owned mint baton
 * and recreates it. Both add ordinary, non-SLP wallet coins only when the
 * asset dust inputs do not cover dust outputs + fee. The OP_RETURN is present
 * before the one signing pass, so no signature is silently skipped. token_id
 * is in the node's internal txid byte order. */
struct zcl_result zslp_command_build_token_send_tx(
    struct wallet *wallet, const uint8_t token_id[32], const char *to_addr,
    uint64_t amount, struct wallet_tx *wtx, int64_t *fee_paid,
    const char **tx_error);
struct zcl_result zslp_command_build_token_burn_tx(
    struct wallet *wallet, const uint8_t token_id[32], uint64_t amount,
    struct wallet_tx *wtx, int64_t *fee_paid, const char **tx_error);
struct zcl_result zslp_command_build_token_genesis_tx(
    struct wallet *wallet, const char *ticker, const char *name,
    uint8_t decimals, uint64_t initial_supply, struct wallet_tx *wtx,
    int64_t *fee_paid, const char **tx_error);
struct zcl_result zslp_command_build_token_mint_tx(
    struct wallet *wallet, const uint8_t token_id[32], const char *to_addr,
    uint64_t amount, struct wallet_tx *wtx, int64_t *fee_paid,
    const char **tx_error);

/* Build a base tx whose SOLE input is a coin the wallet controls that pays
 * owner_address (P2PKH only). Used by mutation commands (UPDATE, TRANSFER,
 * RENEW, SET_RECORD, SET_TEXT) so the resulting tx's first input — the
 * signer the ZNAM projection treats as ownership proof, see
 * contexts/explorer/models/src/explorer_index.c:znam_owner_address — is provably the
 * current name owner, not an arbitrary wallet address. Fails closed if the
 * wallet does not hold the owner's private key or has no spendable coin
 * under that address. Output 0 pays 546 sat (dust) back to owner_address;
 * a second change output is added if the selected coin has excess value. */
struct zcl_result zslp_command_build_owner_base_tx(struct wallet *wallet,
                                     const char *owner_address,
                                     struct wallet_tx *wtx,
                                     int64_t *fee_paid,
                                     const char **tx_error);

struct zcl_result zslp_command_finalize_genesis(const char *datadir,
                                   const char *broadcast_txid,
                                   const struct zslp_token_create_request *req,
                                   char token_id_out[ZSLP_TOKEN_KEY_MAX + 1]);

struct zcl_result zslp_command_credit_transfer(const char *datadir,
                                  const struct zslp_token_transfer_request *req);

#endif
