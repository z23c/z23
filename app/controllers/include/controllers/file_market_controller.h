/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * File Market Controller — RPC commands for ZCL Market.
 *
 * Commands:
 *   zmarket_list    — list files available on the network
 *   zmarket_offer   — announce a file for sale
 *   zmarket_buy     — initiate purchase/download
 *   zmarket_status  — market status and active downloads */

#ifndef ZCL_CONTROLLERS_FILE_MARKET_H
#define ZCL_CONTROLLERS_FILE_MARKET_H

#include "rpc/server.h"
#include "models/database.h"

void rpc_market_set_state(struct node_db *ndb);
void register_market_rpc_commands(struct rpc_table *t);
void register_market_offer_rpc_commands(struct rpc_table *t);
/* The node's own moderation posture (serve profile + relay rule + local
 * review marks), implemented in app/controllers/src/market_moderation_rpc.c.
 * register_market_rpc_commands calls this; callers do not. */
void register_market_moderation_rpc_commands(struct rpc_table *t);

#ifdef ZCL_TESTING
/* One-shot deterministic seam after plan-token validation and before the
 * conditional review write. Tests use it to place a competing writer in the
 * former read/write race window. */
typedef void (*market_review_precommit_test_hook_fn)(void *ctx);
void market_review_set_precommit_hook_for_test(
    market_review_precommit_test_hook_fn fn, void *ctx);
#endif

#include "json/json.h"
bool api_market_list(struct json_value *result);
/* The listing view with an explicit per-request profile override
 * ("open"/"open-view"/"general"/"general-audience.v1", NULL = the node's
 * active profile). Backs zmarket_list, app market list, and /api/market. */
bool api_market_list_profile(const char *profile_override,
                             struct json_value *result);
bool api_market_content_list(struct json_value *result);

#endif
