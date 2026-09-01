/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_segment_controller — ops RPC surface + dumpstate for the sealed ROM
 * segment store. See engine/controllers/src/chain_segment_controller.c.
 */

#ifndef ZCL_CONTROLLERS_CHAIN_SEGMENT_CONTROLLER_H
#define ZCL_CONTROLLERS_CHAIN_SEGMENT_CONTROLLER_H

#include <stdbool.h>

struct json_value;
struct rpc_table;

bool rpc_sealsegments(const struct json_value *params, bool help,
                      struct json_value *result);
bool rpc_verifysegments(const struct json_value *params, bool help,
                        struct json_value *result);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool chain_segment_dump_state_json(struct json_value *out, const char *key);

void register_chain_segment_rpc_commands(struct rpc_table *t);

#endif /* ZCL_CONTROLLERS_CHAIN_SEGMENT_CONTROLLER_H */
