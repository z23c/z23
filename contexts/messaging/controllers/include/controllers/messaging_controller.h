/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Messaging Controller — RPC commands for ZCL Messaging (ZMSG).
 *
 * Commands:
 *   msg_send   — send a message to a peer
 *   msg_inbox  — list received messages
 *   msg_read   — mark a message as read */

#ifndef ZCL_CONTROLLERS_MESSAGING_H
#define ZCL_CONTROLLERS_MESSAGING_H

#include "rpc/server.h"
#include "models/database.h"
#include "net/connman.h"

void rpc_msg_set_state(struct node_db *ndb, struct connman *cm);
void register_msg_rpc_commands(struct rpc_table *t);

#include "json/json.h"
bool api_msg_inbox(struct json_value *result);
bool api_msg_inbox_index(struct json_value *result);

/* Diagnostics dump (`ops state --subsystem=messaging`).
 * See CLAUDE.md "Adding state introspection". Reentrant-safe; initializes out. */
bool messaging_dump_state_json(struct json_value *out, const char *key);

#endif
