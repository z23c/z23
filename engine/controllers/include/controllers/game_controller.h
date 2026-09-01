/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Game Controller — RPC commands for the P2P game platform.
 *
 * Commands:
 *   gametypes      — list registered game types
 *   pingpeer       — measure P2P latency to a connected peer
 *   gamestatus     — show active game sessions
 *   getpeerlatency — latency measurements from game sessions */

#ifndef ZCL_CONTROLLERS_GAME_H
#define ZCL_CONTROLLERS_GAME_H

#include "rpc/server.h"
#include "net/connman.h"

void rpc_game_set_connman(struct connman *cm);
void register_game_rpc_commands(struct rpc_table *t);

/* REST API helpers — build JSON result for HTTP endpoints */
#include "json/json.h"
bool api_gametypes(struct json_value *result);
bool api_getpeerlatency(struct json_value *result);

#endif
