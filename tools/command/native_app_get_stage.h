/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Consume one freshly verified catalog carrier while it is staged. */
#ifndef ZCL_NATIVE_APP_GET_STAGE_H
#define ZCL_NATIVE_APP_GET_STAGE_H
#include "command/native_app_offer.h"
#include "command/native_app_receive_command.h"
/* Exclusive stage with the same retained-directory checks as Discover.
 * Windows currently refuses creation, as does Discover's existing stage. */
struct app_private_stage;
bool app_private_stage_open(const char *anchor, struct app_private_stage **out,
                            struct zcl_command_reply *reply);
const char *app_private_stage_path(const struct app_private_stage *stage);
bool app_private_stage_matches(const struct app_private_stage *stage, const char *sha256, int64_t size);
bool app_private_stage_close(struct app_private_stage *stage);
typedef bool (*app_get_stage_consumer)(void *context, const char *staged_path,
    const struct app_receive_identity *identity, struct zcl_command_reply *reply, bool *host_original);
/* datadir must be an absolute profile accepted by Receive's first-use policy. reply is already
 * initialized. The path and identity are borrowed only during the synchronous
 * callback; report every persistent effect in reply->error.mutated, including
 * successful writes. Set host_original only after explicit owner consent to
 * pin and repeatedly advertise this original carrier. */
bool app_get_stage_consume(const struct zcl_app_offer_row *selected, const char *datadir,
    app_get_stage_consumer consumer, void *context, struct zcl_command_reply *reply);
bool app_get_stage_consume_progress(const struct zcl_app_offer_row *selected, const char *datadir,
    app_get_stage_consumer consumer, void *context, struct zcl_command_reply *reply,
    app_confirm_presenter presenter, void *presenter_context);
/* Preserve any confirmed hosting identity if its owner-facing result cannot be shown. */
void app_get_host_result_unavailable(struct zcl_command_reply *reply);
enum app_get_rebuild_state { APP_GET_REBUILD_INVALID, APP_GET_REBUILD_CACHED, APP_GET_REBUILD_FRESH };
enum app_get_rebuild_state app_get_rebuild_prepare(const struct zcl_app_offer_row *row,
    const struct json_value *build_wire, const struct json_value *open_wire, struct zcl_app_rebuild *observation);
bool app_get_rebuild_publish(const struct zcl_app_rebuild *observation, struct zcl_command_reply *reply);
void app_get_rebuild_result_unavailable(struct zcl_command_reply *reply);
typedef bool (*app_get_bytes_consumer)(void *context, const char *staged_path,
    const struct app_receive_identity *identity, struct zcl_command_reply *reply);
/* Stages parent-verified bytes in an exclusively owned private directory,
 * rechecks hash and Receive identity, then synchronously calls consumer. */
bool app_get_stage_consume_bytes(const struct zcl_app_offer_row *selected, const char *datadir,
    const uint8_t *bytes, size_t len, app_get_bytes_consumer consumer, void *context,
    struct zcl_command_reply *reply);
#endif
