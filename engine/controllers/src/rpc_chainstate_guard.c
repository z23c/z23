/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/rpc_chainstate_guard.h"
#include "rpc/protocol.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include <stdio.h>

bool rpc_chainstate_lookup_ready(const struct main_state *ms)
{
    if (!ms)
        return true;

    int tip_height = active_chain_height(&ms->chain_active);
    if (tip_height < 0)
        return true;

    /* "Is the tip block-index slot populated?" — read it through the single
     * tip accessor. active_chain_at(c, c->height) == active_chain_tip(c) today
     * (both return c->chain[c->height]); routing through active_chain_tip keeps
     * this guard tracking the authoritative reducer tip if the accessor body
     * derives from durable tip_finalize state. */
    return active_chain_tip(&ms->chain_active) != NULL;
}

bool rpc_require_chainstate_lookup_ready(const struct main_state *ms,
                                         struct json_value *result,
                                         const char *method,
                                         const char *operation)
{
    if (rpc_chainstate_lookup_ready(ms))
        return true;

    int tip_height = ms ? active_chain_height(&ms->chain_active) : -1;
    char msg[192];
    snprintf(msg, sizeof(msg),
             "%s unavailable: active chain tip height %d has no block index entry",
             operation ? operation : "Chainstate lookup", tip_height);
    json_rpc_error_full(result, RPC_INTERNAL_ERROR, msg, method);
    return false;
}
