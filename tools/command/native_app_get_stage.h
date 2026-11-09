/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Consume one freshly verified catalog carrier while it is staged. */
#ifndef ZCL_NATIVE_APP_GET_STAGE_H
#define ZCL_NATIVE_APP_GET_STAGE_H
#include "command/native_app_offer.h"
#include "command/native_app_receive_command.h"
typedef bool (*app_get_stage_consumer)(void *context, const char *staged_path,
    const struct app_receive_identity *identity, struct zcl_command_reply *reply, bool *host_original);
/* datadir must be an absolute profile accepted by Receive's first-use policy. reply is already
 * initialized. The path and identity are borrowed only during the synchronous
 * callback; report every persistent effect in reply->error.mutated, including
 * successful writes. Set host_original only after explicit owner consent to
 * pin and repeatedly advertise this original carrier. */
bool app_get_stage_consume(const struct zcl_app_offer_row *selected, const char *datadir,
    app_get_stage_consumer consumer, void *context, struct zcl_command_reply *reply);
/* Preserve any confirmed hosting identity if its owner-facing result cannot be shown. */
void app_get_host_result_unavailable(struct zcl_command_reply *reply);
#endif
