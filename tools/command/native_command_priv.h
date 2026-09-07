/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal wiring shared between native_command.c and its sibling
 * implementation files (native_command_bridge.c, ...). Not a public surface:
 * only the tools/command/native_command*.c translation units include this.
 * It exposes the exact seams a bridged leaf's dispatch pipeline needs on
 * both sides of the split — the direct-RPC binding table's shape and
 * lookup, and the two small "next action" reply helpers every handler
 * shares — without widening what any external caller can reach. */
#ifndef ZCL_TOOLS_NATIVE_COMMAND_PRIV_H
#define ZCL_TOOLS_NATIVE_COMMAND_PRIV_H

#include "json/json.h"

#include <stddef.h>

struct zcl_command_reply;

/* ── direct JSON-RPC leaf bindings (defined in native_command.c) ───────
 * A bridged leaf with no native body function proxies straight to one
 * JSON-RPC method. native_command_bridge.c's dispatch pipeline validates
 * the RPC's success body against the resolved binding. */
enum bridge_rpc_array_kind {
    BRIDGE_RPC_ARRAY_NONE = 0,
    BRIDGE_RPC_ARRAY_TXIDS,
    BRIDGE_RPC_ARRAY_PEERS,
    BRIDGE_RPC_ARRAY_LATENCY,
};

struct bridge_rpc_required_field {
    const char *name;
    enum json_type type;
};

struct bridge_rpc_binding {
    const char *path;
    const char *rpc_method;
    enum json_type top_type;
    struct bridge_rpc_required_field required[5];
    enum bridge_rpc_array_kind array_kind;
};

const struct bridge_rpc_binding *bridge_rpc_binding_for_path(
    const char *path);

/* ── shared "next action" reply helpers (defined in native_command_bridge.c)
 * Every handler across native_command.c and its siblings appends a bounded
 * discover.describe / typed-string next action the same way; one definition
 * keeps the encoding rules (path guard, buffer bound) in one place. */
void nc_add_describe_next(struct zcl_command_reply *reply, const char *path,
                          const char *reason);
void nc_add_string_next(struct zcl_command_reply *reply, const char *command,
                        const char *key, const char *value,
                        const char *reason);

#endif
