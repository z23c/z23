/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.parity.sample` leaf's testable seams: one block-hash
 *          parity sample taken through an injected RPC function, rendered as
 *          one JSON line, appended under an exclusive lock.
 */

#ifndef ZCL_NATIVE_FLEET_PARITY_H
#define ZCL_NATIVE_FLEET_PARITY_H

#include "command/native_command.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_PARITY_BACK 100 /* sample this far below the lower tip */
#define ZCL_PARITY_HASH_HEX 64
#define ZCL_PARITY_LINE_MAX 512u

/* One sample. `ok` is false when either node could not answer; the hashes are
 * then empty and `match` is meaningless. `height` is -1 when unknown. */
struct zcl_parity_sample {
    int64_t ts;
    int64_t height;
    char our_hash[ZCL_PARITY_HASH_HEX + 1];
    char oracle_hash[ZCL_PARITY_HASH_HEX + 1];
    bool match;
    bool ok;
};

/* Asks node `side` (0 = ours, 1 = oracle) one JSON-RPC method. Returns the
 * malloc'd bare result or error body of the node RPC client, or NULL. */
typedef char *(*zcl_parity_rpc_fn)(void *ctx, int side, const char *method,
                                   const char *params_json);

/* height = min(tip_ours, tip_oracle) - ZCL_PARITY_BACK, then getblockhash on
 * both. Never fails: an RPC problem is a sample with ok == false. */
void zcl_parity_take(zcl_parity_rpc_fn rpc, void *ctx, int64_t ts,
                     struct zcl_parity_sample *out);

/* The ledger line, with its trailing newline. False when it does not fit. */
bool zcl_parity_line(const struct zcl_parity_sample *sample, char *buf,
                     size_t cap, size_t *len);

/* Appends `line` to <dir>/parity.jsonl under an exclusive non-blocking lock on
 * <dir>/parity.lock, creating the directory 0700. Never truncates. `why` names
 * the failure (lock held, mkdir, open, write) when false. */
bool zcl_parity_append(const char *dir, const char *line, size_t len,
                       const char **why);

/* The bound leaf: fleet.parity.sample. */
void zcl_native_handle_fleet_parity_sample(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);

#endif
