/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: re-admit exact wallet transaction bytes after process restart. */

#include "wallet/wallet.h"

#include "validation/accept_to_mempool.h"

static const char *wallet_reaccept_result_name(enum mempool_accept_result r)
{
    switch (r) {
    case MEMPOOL_ACCEPT_OK:             return "ok";
    case MEMPOOL_ACCEPT_INVALID:        return "invalid";
    case MEMPOOL_ACCEPT_DUPLICATE:      return "duplicate";
    case MEMPOOL_ACCEPT_CONFLICT:       return "conflict";
    case MEMPOOL_ACCEPT_BELOW_FEE:      return "below_fee";
    case MEMPOOL_ACCEPT_MISSING_INPUTS: return "missing_inputs";
    case MEMPOOL_ACCEPT_NONFINAL:       return "nonfinal";
    case MEMPOOL_ACCEPT_EXPIRING_SOON:  return "expiring_soon";
    case MEMPOOL_ACCEPT_INTERNAL_ERROR: return "internal_error";
    case MEMPOOL_ACCEPT_UNVERIFIABLE:   return "unverifiable";
    }
    return "unknown";
}

struct zcl_result wallet_reaccept_transaction(
    struct wallet_tx *wtx, const struct wallet_tx_admission *admission)
{
    if (!wtx || !admission)
        return ZCL_ERR(-1,
            "wallet reaccept: NULL transaction or admission context");
    if (!admission->mempool || !admission->coins_tip ||
        !admission->main_state || !admission->params) {
        return ZCL_ERR(-2,
            "wallet reaccept: incomplete validation context");
    }
    char detail[128];
    enum mempool_accept_result accepted = accept_to_mempool_detailed(
        admission->mempool, admission->coins_tip, admission->main_state,
        admission->params, &wtx->tx, detail, sizeof(detail));
    if (accepted != MEMPOOL_ACCEPT_OK) {
        return ZCL_ERR(-100 - (int)accepted,
            "wallet reaccept: mempool admission rejected transaction "
            "(%s%s%s)", wallet_reaccept_result_name(accepted),
            detail[0] ? ": " : "", detail);
    }
    return ZCL_OK;
}
