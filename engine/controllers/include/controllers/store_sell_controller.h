/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the merchant SELLING half of the store — the storesell_* node RPC
 * surface plus the one listing implementation that both that RPC method and
 * the `app.store.list-product` CLI leaf render.
 *
 * A running node holds a single-owner lease on <datadir>/node.db
 * (engine/models/src/database_owner_lease.c), so a short-lived CLI process
 * cannot open it to write a product. The buyer leaves already solved this by
 * proxying storebuy_* into the node; listing does the same through
 * storesell_list_product, and store_sell_list_product_apply is the body both
 * sides call so there is exactly one set of validations and refusals. */

#ifndef ZCL_STORE_SELL_CONTROLLER_H
#define ZCL_STORE_SELL_CONTROLLER_H

#include "kernel/command_registry.h"
#include "json/json.h"

#include <stdbool.h>

struct rpc_table;

/* Transport-neutral result of one listing attempt. `data` is a JSON object
 * that is only populated when ok; the caller always store_sell_outcome_free()s
 * it. `code`/`message`/`evidence` are the SAME strings on both transports —
 * the typed CLI reply and the RPC refusal envelope differ in shape, never in
 * what they say. */
struct store_sell_outcome {
    bool ok;
    bool mutated;
    enum zcl_command_exit exit_code;
    char code[64];
    char message[320];
    char evidence[512];
    struct json_value data;
};

void store_sell_outcome_init(struct store_sell_outcome *out);
void store_sell_outcome_free(struct store_sell_outcome *out);

/* Validate `in` and, if it is a complete product, write it to
 * <datadir>/node.db. MUST run in the process that owns the database: in the
 * node when a node is up, in the CLI only when no node holds the lease. */
void store_sell_list_product_apply(const struct json_value *in,
                                   const char *datadir,
                                   struct store_sell_outcome *out);

/* The node's own data directory, wired once at service registration. A
 * storesell_* call naming any other datadir is refused rather than served. */
void rpc_store_sell_set_state(const char *datadir);

void register_store_sell_rpc_commands(struct rpc_table *t);

#endif
