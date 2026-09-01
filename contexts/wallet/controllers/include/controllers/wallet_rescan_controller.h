/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_WALLET_RESCAN_CONTROLLER_H
#define ZCL_CONTROLLERS_WALLET_RESCAN_CONTROLLER_H

#include "rpc/server.h"

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
