/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Declares the wallet rescan RPC registration and the rescan report JSON serializer.
 */

#ifndef ZCL_CONTROLLERS_WALLET_RESCAN_CONTROLLER_H
#define ZCL_CONTROLLERS_WALLET_RESCAN_CONTROLLER_H

#include "rpc/server.h"
#include "core/uint256.h"
#include <stdbool.h>

struct wallet_rpc_context;

enum wallet_witness_status {
    WALLET_WITNESS_FAILED, WALLET_WITNESS_INCOMPLETE,
    WALLET_WITNESS_ENDPOINT_CHANGED, WALLET_WITNESS_BUSY, WALLET_WITNESS_PERSIST_FAILED,
    WALLET_WITNESS_COMPLETE
};
struct wallet_witness_endpoint {
    int height;
    struct uint256 hash, root;
};
struct wallet_witness_outcome {
    enum wallet_witness_status status;
    int notes_total, witnesses_built, witnesses_saved, endpoint_height;
    struct uint256 endpoint_hash, endpoint_root;
};
/* Context and its wallet, database, chain and datadir must outlive this call. */
bool wallet_rescan_witnesses_at(struct wallet_rpc_context *ctx,
    const struct wallet_witness_endpoint *endpoint, struct wallet_witness_outcome *out);

void register_wallet_rescan_rpc_commands(struct rpc_table *t);

/* Serialize a rescan's coverage + yield accounting into `out` (set to an
 * object by this call). Lives here rather than in wallet_controller.c so the
 * rescan reply shape sits with the rest of the rescan surface.
 *
 * `blocker` is emitted only when the scan's yield must NOT be read as "you
 * have no funds" — see struct wallet_rescan_report. It is deliberately NOT
 * the JSON-RPC "error" key, so every count stays readable by the caller
 * alongside the failure; the native handler maps it to a non-zero exit. */
struct json_value;
struct wallet_rescan_report;
void wallet_rescan_report_to_json(struct json_value *out,
                                  const struct wallet_rescan_report *rep);

#endif
