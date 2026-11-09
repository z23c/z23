/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Private read-only assembly of a received saved app's preview and Keep inputs.
 */
#ifndef ZCL_NATIVE_APP_RECEIVE_PREVIEW_H
#define ZCL_NATIVE_APP_RECEIVE_PREVIEW_H
#include <stdbool.h>
struct json_value;
struct zcl_command_reply;
struct app_receive_preview;
enum app_receive_preview_keep_state {
    APP_RECEIVE_PREVIEW_KEEP_NEW,
    APP_RECEIVE_PREVIEW_KEEP_SAME,
    APP_RECEIVE_PREVIEW_KEEP_REFUSED
};
/* Owner-only composition helper, not an authorization endpoint. All filesystem
 * access is read-only. Caller supplies the validated committed receive data;
 * create independently checks selected history, persisted release and trust.
 * All returned strings/identities are owned. Failure always leaves *out NULL. */
bool app_receive_preview_create(const struct json_value *receive_data,
    const char *datadir, struct app_receive_preview **out,
    struct zcl_command_reply *failure);
/* After successful native adoption/personalization only. Requires exactly
 * ADOPTED trust (never received trust), pins fork/parent/saved version, checks
 * original release package separately and derives the personal saved package
 * by readonly reconstruction and full content preparation in private scratch.
 * No make/key/publication. Closes the repository before returning. Cleanup
 * failure refuses with retained scratch path in failure evidence. The caller
 * owns the committed adoption and must retain its receipt on refusal. */
bool app_receive_preview_create_adopted(const struct json_value *adopt_data,
    const char *datadir, struct app_receive_preview **out,
    struct zcl_command_reply *failure);
/* Outputs are initialized on every call and must be json_free'd even on failure.
 * Build input deliberately omits confirm/plan_id: the worker owns that protocol. */
bool app_receive_preview_build_input(const struct app_receive_preview *p,
    struct json_value *out);
/* Bind actual successful CLI envelopes (command/ok/status/data), not booleans.
 * A failed rebind clears prior build/preview eligibility. Replies must come from
 * the trusted worker for this request; this helper does not authenticate IPC. */
/* Validates app.build success envelope and the exact plan tuple before constructing its confirm request. */
bool app_receive_preview_confirm_input(const struct app_receive_preview *p,
    const struct json_value *plan_envelope, struct json_value *out,
    struct zcl_command_reply *failure);
bool app_receive_preview_bind_build(struct app_receive_preview *p,
    const struct json_value *build_envelope, struct zcl_command_reply *failure);
bool app_receive_preview_open_input(const struct app_receive_preview *p,
    struct json_value *out);
bool app_receive_preview_bind_preview(struct app_receive_preview *p,
    const struct json_value *open_envelope, struct zcl_command_reply *failure);
/* Only after verified preview and a separate owner Keep action. NEW always
 * uses expected_revision=0. SAME emits no request (Close); all other existing
 * choices/corrupt records refuse. app.keep remains the atomic CAS authority. */
enum app_receive_preview_keep_state app_receive_preview_keep_input(
    const struct app_receive_preview *p, struct json_value *out,
    struct zcl_command_reply *failure);
void app_receive_preview_close(struct app_receive_preview *p);
#endif
