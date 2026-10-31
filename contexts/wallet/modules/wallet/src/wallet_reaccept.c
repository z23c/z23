/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: re-admit exact wallet transaction bytes after process restart and
 * check the admission context every wallet commit and re-admission shares. */

#include "wallet/wallet.h"

#include "validation/accept_to_mempool.h"

#include <stdatomic.h>

static _Atomic(const struct tx_mempool *) g_required_admission_pool;

void wallet_require_admission_pool(const struct tx_mempool *pool)
{
    atomic_store(&g_required_admission_pool, pool);
}

struct zcl_result wallet_admission_pool_check(
    const struct wallet_tx_admission *admission)
{
    const struct tx_mempool *required =
        atomic_load(&g_required_admission_pool);
    if (required && admission && admission->mempool != required)
        return ZCL_ERR(WALLET_ADMISSION_POOL_REFUSED_CODE,
            "PRIVATE_BROADCAST_UNSUPPORTED: this transaction would enter the "
            "main mempool and be announced to every peer, which private "
            "wallet broadcast forbids. Restart without "
            "-walletbroadcast=private to use it.");
    return ZCL_OK;
}

struct zcl_result wallet_admission_check(
    const struct wallet_tx_admission *admission, const char *op)
{
    struct zcl_result pool_ok = wallet_admission_pool_check(admission);
    if (!pool_ok.ok)
        return pool_ok;
    if (!admission->mempool || !admission->coins_tip ||
        !admission->main_state || !admission->params) {
        return ZCL_ERR(-2,
            "wallet %s: incomplete validation context "
            "(mempool=%p coins_tip=%p main_state=%p params=%p)", op,
            (void *)admission->mempool, (void *)admission->coins_tip,
            (void *)admission->main_state, (const void *)admission->params);
    }
    return ZCL_OK;
}

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
    struct zcl_result ctx_ok = wallet_admission_check(admission, "reaccept");
    if (!ctx_ok.ok)
        return ctx_ok;
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
