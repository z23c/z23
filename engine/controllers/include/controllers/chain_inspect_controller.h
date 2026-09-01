/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_CHAIN_INSPECT_CONTROLLER_H
#define ZCL_CONTROLLERS_CHAIN_INSPECT_CONTROLLER_H

#include "rpc/server.h"

struct main_state;
struct coins_view_db;
struct coins_view_cache;
struct node_db;

void rpc_chain_inspect_set_state(struct main_state *ms, const char *datadir,
                                  struct coins_view_db *cvdb,
                                  struct coins_view_cache *coins_tip,
                                  struct node_db *ndb);

void register_chain_inspect_rpc_commands(struct rpc_table *t);

#endif
