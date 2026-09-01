/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store ACCESS GATE — the token-balance verdict behind /store/access.
 * Split from store_controller.c under the 800-line ceiling (E1): the
 * controller owns routing/order/payment flow; this file owns exactly one
 * question — "does this address hold enough of this token to be served?"
 * — and the balance-source policy that answers it. */

#include "controllers/store_controller_internal.h"
#include "controllers/zslp_controller.h"
/* wallet_decode_address — the t-address -> hash160 decode the ledger keys
 * on (controllers/wallet_helpers.h, same source the order reconcile
 * uses). */
#include "controllers/wallet_helpers.h"
/* store_ledger_access_balance — the chain-derived token holding behind the
 * access gate: uint256 form of the token id (core/uint256.h) and the
 * debit-correct per-(token,outpoint) balance (models/zslp_ledger.h). */
#include "core/uint256.h"
#include "models/zslp_ledger.h"

/* Chain-derived half of the access balance: the debit-correct per-
 * (token,outpoint) zslp_ledger projection. This is the ONLY balance a
 * production node has — the chain-scan path deliberately leaves
 * zslp_balances EMPTY (explorer_index.h), so a gate that reads only that
 * table denies every real, confirmed holder (the C5 collect wedge). The
 * ledger keys on the 32-byte token id in internal byte order (the
 * uint256_set_hex form, same as zslp_mint) and the 20-byte hash160 of the
 * holder's t-address; a ticker-string token key or a non-p2pkh address has
 * no ledger rows by construction and answers 0 here. */
static uint64_t store_ledger_access_balance(const char *datadir,
                                            const char *customer_addr,
                                            const char *token_id)
{
    char db_path[1024];
    struct node_db ndb;
    struct uint256 token;
    struct tx_destination dest;
    int64_t bal;

    uint256_set_hex(&token, token_id);
    if (uint256_is_null(&token))
        return 0;
    if (!wallet_decode_address(customer_addr, &dest) ||
        dest.type != DEST_KEY_ID)
        return 0;

    snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open_runtime(&ndb, db_path, "store.access_balance"))
        LOG_RETURN(0, "store", "access_balance: node_db_open failed path=%s",
                   db_path);

    bal = zslp_ledger_balance(&ndb, token.data, dest.id.key.id.data);
    node_db_close(&ndb);
    return bal < 0 ? 0 : (uint64_t)bal;
}

uint64_t store_access_token_balance(const char *datadir,
                                    const char *customer_addr,
                                    const char *token_id)
{
    uint64_t ledger, legacy;

    if (!datadir || !customer_addr || !token_id)
        return 0;

    /* Two sources, never additive: the chain-derived zslp_ledger (the only
     * production source) and the credit-only zslp_balances (written solely
     * by the no-chain fixture path). The truth is one or the other, so the
     * answer is max(), not a sum — summing could double-count a holding
     * that both paths happened to record. */
    ledger = store_ledger_access_balance(datadir, customer_addr, token_id);
    legacy = zslp_balance(datadir, token_id, customer_addr);
    return ledger > legacy ? ledger : legacy;
}

bool store_check_token_access(const char *datadir,
                               const char *customer_addr,
                               const char *token_id,
                               uint64_t required)
{
    if (!datadir ||
        !store_validate_access_addr(customer_addr) ||
        !store_validate_access_token(token_id))
        LOG_FAIL("store", "check_token_access: invalid args datadir=%p addr=%s token=%s",
                 (void *)datadir,
                 customer_addr ? customer_addr : "(null)",
                 token_id ? token_id : "(null)");

    return store_access_token_balance(datadir, customer_addr, token_id) >= required;
}
