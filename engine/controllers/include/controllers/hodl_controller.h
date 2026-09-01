/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * HODL Wave analytics: UTXO age distribution, heatmaps, charts. */

#ifndef ZCL_HODL_CONTROLLER_H
#define ZCL_HODL_CONTROLLER_H

#include "validation/main_state.h"
#include "coins/coins_view.h"
#include "models/database.h"
#include "rpc/server.h"

void rpc_hodl_set_state(struct main_state *ms,
                         struct coins_view_cache *coins_tip,
                         struct node_db *ndb, const char *datadir);

void register_hodl_rpc_commands(struct rpc_table *t);

#endif
