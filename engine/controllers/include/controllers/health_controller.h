/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Health Controller — detailed sync progress and service health RPCs.
 *
 * Commands:
 *   getsyncdetail    — per-phase sync progress (headers, blocks, bg_validation, bg_hash)
 *   getservicehealth — which P2P services are active/disabled and why */

#ifndef ZCL_CONTROLLERS_HEALTH_H
#define ZCL_CONTROLLERS_HEALTH_H

#include "rpc/server.h"
#include "validation/main_state.h"
#include "services/bg_validation_service.h"
#include "services/bg_hash_verification_service.h"
#include "net/connman.h"

void rpc_health_set_state(struct main_state *ms,
                          struct bg_validation_service *bg_valid,
                          struct bg_hash_verification_service *bg_hash,
                          struct connman *cm);
void register_health_rpc_commands(struct rpc_table *t);

/* REST API helpers — build JSON result for HTTP endpoints */
#include "json/json.h"
bool api_getsyncdetail(struct json_value *result);
bool api_getservicehealth(struct json_value *result);

#endif
