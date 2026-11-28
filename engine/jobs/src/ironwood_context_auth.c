/* purpose: Bind private v6 authorization checks to a stable coin view. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/ironwood_context_auth.h"
#include "base/serialize_le.h"
#include "chain/chainparams.h"
#include "controllers/ironwood_bundle_auth.h"
#include "controllers/transaction_v6_transparent.h"
#include "primitives/block.h"
#include "script/script.h"
#include "script/script_flags.h"
#include "services/ironwood_checked_wire.h"
#include "services/ironwood_verification_setup.h"
#include <string.h>

static bool private_profile(void)
{
    const struct chain_research_descriptor *p = chain_research_profile_current();
    return p && p == chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD) &&
        chain_params_get() == p->chain;
}

static bool supported_view(const struct v6_wire_view *view, uint32_t branch)
{
    return view->header.size >= 20 && zcl_read_u32_le(view->header.data + 8) == branch &&
        view->inputs <= 1 && view->ironwood.count && !view->orchard.count &&
        !view->sapling_spends.count && !view->sapling_outputs.count;
}

static enum ironwood_context_auth_result resolve_input(const struct transaction *tx,
    utxo_apply_lookup_fn resolve, void *user, struct utxo_apply_lookup *coin)
{
    if (!tx->num_vin) return IRONWOOD_CONTEXT_COMPONENTS_OK;
    if (!resolve || outpoint_is_null(&tx->vin[0].prevout) ||
        !resolve(&tx->vin[0].prevout.hash, tx->vin[0].prevout.n, coin, user) || !coin->found)
        return IRONWOOD_CONTEXT_PREVOUT_UNAVAILABLE;
    if (coin->value < 0 || coin->value > MAX_MONEY || coin->script_len != 25)
        return IRONWOOD_CONTEXT_UNSUPPORTED;
    struct script script;
    script_set(&script, coin->script, coin->script_len);
    return script_is_p2pkh(&script) ? IRONWOOD_CONTEXT_COMPONENTS_OK : IRONWOOD_CONTEXT_UNSUPPORTED;
}

enum ironwood_context_auth_result ironwood_context_authenticate(
    const struct transaction *tx, uint32_t expected_branch, unsigned int script_flags,
    utxo_apply_lookup_fn resolve, void *user)
{
    const unsigned int required = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    if (!private_profile() || !tx || !expected_branch || (script_flags & required) != required)
        return IRONWOOD_CONTEXT_UNSUPPORTED;
    struct v6_wire_view view;
    if (!ironwood_checked_wire(tx, MAX_BLOCK_SIZE, &view).ok)
        return IRONWOOD_CONTEXT_CHECK_UNAVAILABLE;
    if (!supported_view(&view, expected_branch) || (tx->num_vin && !tx->vin))
        return IRONWOOD_CONTEXT_UNSUPPORTED;
    struct utxo_apply_lookup coin = {0};
    enum ironwood_context_auth_result r = resolve_input(tx, resolve, user, &coin);
    if (r != IRONWOOD_CONTEXT_COMPONENTS_OK) return r;
    struct transaction_v6_prevout transparent = {coin.value, coin.script, coin.script_len};
    size_t n = tx->num_vin;
    if (n && !v6_transparent_verify_p2pkh(tx->v6_wire.data, tx->v6_wire.size,
            &transparent, n, 0, expected_branch, script_flags).ok)
        return IRONWOOD_CONTEXT_CHECK_UNAVAILABLE;
    if (!ironwood_bundle_authenticate_checked(tx, expected_branch,
            n ? &transparent : NULL, n, ironwood_postnu63_verification_setup()).ok)
        return IRONWOOD_CONTEXT_CHECK_UNAVAILABLE;
    return IRONWOOD_CONTEXT_COMPONENTS_OK;
}
