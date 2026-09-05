/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Native command adapter for exact local push-proof receipts. */

#include "command/native_command.h"
#include "command/native_dev_loop_command.h"
#include "command/native_dev_proof_command.h"

#include "dev_proof.h"
#ifdef ZCL_DEV_BUILD
#include "base/hex.h"
#include "dev_proof_signer.h"
#endif
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The enum-to-name mapping the reply below needs. It lives here, not in
 * tools/dev/dev_proof.c, because that file is DEV_ONLY_SRCS: it is not
 * linked into the release binary or the fuzz targets, while this
 * translation unit is. A pure switch over the enum has no dev-only
 * reach, so the release side can own it outright. */
const char *zcl_dev_proof_state_name(enum zcl_dev_proof_state state)
{
    switch (state) {
    case ZCL_DEV_PROOF_STATE_MISSING: return "missing";
    case ZCL_DEV_PROOF_STATE_RUNNING: return "running";
    case ZCL_DEV_PROOF_STATE_PASSED: return "passed";
    case ZCL_DEV_PROOF_STATE_FAILED: return "failed";
    case ZCL_DEV_PROOF_STATE_INVALID: return "invalid";
    }
    return "invalid";
}

/* The functions below map an already-resolved `zcl_dev_proof_status` onto a
 * `zcl_command_reply` (JSON fields, status, exit code). They read no files,
 * spawn no process, and touch no dev-only capability — the dev-only surface
 * is entirely in HOW a status gets resolved (proof_status/proof_ensure/
 * proof_wait below, each gated on `#ifdef ZCL_DEV_BUILD`), never in how a
 * resolved status is reported. Keeping them unconditional lets a
 * release-shaped test binary exercise the exact status/exit-code contract
 * directly (see zcl_dev_proof_wait_conclude and
 * test_impact_composition.c: test_ic_proof_wait_reports_settled_failure)
 * without flipping ZCL_DEV_BUILD for this translation unit — which would
 * also compile proof_ensure()'s real body and pull in the resident
 * dev-loop watcher from native_dev_command.c, an unrelated dependency this
 * mapping logic does not need. */
static void proof_emit_status(struct zcl_command_reply *reply,
                              const struct zcl_dev_proof_status *status,
                              bool add_wait_next)
{
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_proof_status.v1");
    (void)json_push_kv_str(&reply->data, "status",
                           zcl_dev_proof_state_name(status->state));
    if (status->local_commit[0])
        (void)json_push_kv_str(&reply->data, "local_commit",
                               status->local_commit);
    if (status->remote_base[0])
        (void)json_push_kv_str(&reply->data, "remote_base",
                               status->remote_base);
    if (status->receipt_path[0])
        (void)json_push_kv_str(&reply->data, "receipt_path",
                               status->receipt_path);
    if (status->log_dir[0])
        (void)json_push_kv_str(&reply->data, "log_dir", status->log_dir);
    if (status->detail[0])
        (void)json_push_kv_str(&reply->data, "detail", status->detail);
    if (status->worker_id > 1)
        (void)json_push_kv_int(&reply->data, "worker_id", status->worker_id);
    if (status->started_unix > 0)
        (void)json_push_kv_int(&reply->data, "started_unix",
                               status->started_unix);
    if (status->state == ZCL_DEV_PROOF_STATE_RUNNING)
        (void)json_push_kv_int(&reply->data, "eta_ms", status->eta_ms);
    (void)json_push_kv_bool(&reply->data, "receipt_reused",
                            status->receipt_reused);
    char input[192];
    int n = snprintf(input, sizeof(input),
                     "{\"local_commit\":\"%s\",\"remote_base\":\"%s\"}",
                     status->local_commit, status->remote_base);
    if (add_wait_next && n > 0 && (size_t)n < sizeof(input) &&
        status->state != ZCL_DEV_PROOF_STATE_PASSED &&
        status->state != ZCL_DEV_PROOF_STATE_INVALID &&
        status->local_commit[0] && status->remote_base[0])
        (void)zcl_command_reply_add_next(
            reply, "dev.proof.wait", input,
            "wait for the exact commit/base receipt without running push-time work");
}

/* Genuinely still in flight (RUNNING) or not yet requested (MISSING): the
 * caller should poll again, so this stays BLOCKED with exit 3. */
static void proof_wait_pending(struct zcl_command_reply *reply,
                               const struct zcl_dev_proof_status *status,
                               const char *code, const char *phase)
{
    proof_emit_status(reply, status, false);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        code, phase, status->state == ZCL_DEV_PROOF_STATE_RUNNING, false,
        "the exact local commit and remote base do not have an admitted receipt",
        status->detail[0] ? status->detail : "exact_receipt_missing");
}

/* The pair's `.failed` marker already settled this exact commit/base
 * identity: proving will not run again for it. This is a terminal outcome,
 * not "still proving" — it must never share BLOCKED/exit 3 with the
 * still-in-flight case above, or a caller that treats exit 3 as "keep
 * polling" will spin forever on a proof that already finished failing. */
static void proof_wait_failed(struct zcl_command_reply *reply,
                              const struct zcl_dev_proof_status *status)
{
    proof_emit_status(reply, status, false);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "PROOF_FAILED", "prove", false, false,
        "the exact local commit and remote base proof failed",
        status->detail[0] ? status->detail : "child_proof_failed");
}

/* The exact status/exit-code contract for `dev.proof.wait`, given an
 * already-resolved status: a settled `.failed` marker (FAILED) is a
 * terminal, non-BLOCKED outcome distinct from still-in-flight (RUNNING) or
 * not-yet-requested (MISSING); PASSED emits the receipt with no error.
 * Exposed (non-static, unconditional) so this mapping is directly
 * regression-testable without a dev build. */
void zcl_dev_proof_wait_conclude(struct zcl_command_reply *reply,
                                 const struct zcl_dev_proof_status *status)
{
    if (status->state == ZCL_DEV_PROOF_STATE_FAILED) {
        proof_wait_failed(reply, status);
        return;
    }
    if (status->state != ZCL_DEV_PROOF_STATE_PASSED) {
        proof_wait_pending(reply, status, "PROOF_WAIT_TIMEOUT", "wait");
        return;
    }
    proof_emit_status(reply, status, false);
}

#ifdef ZCL_DEV_BUILD
static const char *proof_source_root(const struct zcl_command_request *request)
{
    const struct json_value *root = request && request->input
        ? json_get(request->input, "root") : NULL;
    if (root && root->type == JSON_STR && json_get_str(root)[0])
        return json_get_str(root);
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *environment = getenv("ZCL_DEV_SOURCE_ROOT");
    return environment && environment[0] ? environment : ".";
}

static const char *proof_optional_text(const struct json_value *input,
                                       const char *key)
{
    if (!input || !key) return NULL;
    const struct json_value *value = json_get(input, key);
    return value && value->type == JSON_STR && json_get_str(value)[0]
        ? json_get_str(value) : NULL;
}
#endif

static void proof_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "proof receipt status requires the dev binary", "make dev-bin");
#else
    struct zcl_dev_proof_status status = {0};
    bool read = zcl_dev_proof_status_read(
            proof_source_root(request),
            proof_optional_text(request->input, "local_commit"),
            proof_optional_text(request->input, "remote_base"), &status);
    if (status.state == ZCL_DEV_PROOF_STATE_INVALID &&
        strcmp(status.detail, "windows_native_proof_worker_unavailable") == 0) {
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "PROOF_WORKER_UNAVAILABLE", "preflight", false, false,
            "exact background verification is unavailable on this platform",
            status.detail);
        return;
    }
    if (!read || status.state == ZCL_DEV_PROOF_STATE_INVALID) {
        proof_emit_status(reply, &status, true);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PROOF_STATUS_INVALID", "resolve", false, false,
            "could not resolve the exact local commit and remote base",
            status.detail);
        return;
    }
    proof_emit_status(reply, &status, true);
#endif
}

static void proof_ensure(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "background proof scheduling requires the dev binary", "make dev-bin");
#else
    struct zcl_dev_proof_status status = {0};
    if (!zcl_dev_proof_status_read(
            proof_source_root(request),
            proof_optional_text(request->input, "local_commit"),
            proof_optional_text(request->input, "remote_base"), &status) ||
        status.state == ZCL_DEV_PROOF_STATE_INVALID) {
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "PROOF_WORKER_UNAVAILABLE", "preflight", false, false,
            "exact background verification is unavailable on this platform",
            status.detail[0] ? status.detail : "proof_worker_unavailable");
        return;
    }
    struct zcl_command_reply watcher;
    struct json_value watcher_input;
    json_init(&watcher_input);
    json_set_object(&watcher_input);
    bool watcher_input_ready =
        json_push_kv_str(&watcher_input, "root", proof_source_root(request)) &&
        json_push_kv_str(&watcher_input, "mode", "verify");
    if (!watcher_input_ready) {
        json_free(&watcher_input);
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "PROOF_QUEUE_INPUT_FAILED", "schedule", true, false,
            "the resident watcher request could not be allocated",
            "retry proof enqueue");
        return;
    }
    struct zcl_command_request watcher_request = *request;
    watcher_request.input = &watcher_input;
    zcl_command_reply_init(&watcher, "zcl.dev_loop_status.v1");
    zcl_native_handle_dev_loop_start_async(&watcher_request, &watcher);
    const struct json_value *created = json_get(&watcher.data, "created");
    bool queue_ready = watcher.exit_code == ZCL_COMMAND_EXIT_OK &&
        ((created && created->type == JSON_BOOL && json_get_bool(created)) ||
         zcl_native_dev_loop_proof_queue_ready(proof_source_root(request)));
    zcl_command_reply_free(&watcher);
    json_free(&watcher_input);
    if (!queue_ready) {
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "PROOF_QUEUE_OWNER_STALE", "schedule", true, false,
            "the resident watcher does not advertise the proof queue contract",
            "restart the development watcher with the current z23-dev binary");
        return;
    }
    if (!zcl_dev_proof_ensure(
            proof_source_root(request),
            proof_optional_text(request->input, "local_commit"),
            proof_optional_text(request->input, "remote_base"), &status)) {
        proof_emit_status(reply, &status, true);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "PROOF_ENSURE_FAILED", "schedule", false, false,
            "could not schedule exact background verification", status.detail);
        return;
    }
    proof_emit_status(reply, &status, true);
#endif
}

static void proof_wait(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "proof receipt waiting requires the dev binary", "make dev-bin");
#else
    int64_t timeout_ms = 300000;
    const struct json_value *timeout = json_get(request->input, "timeout_ms");
    if (timeout && timeout->type == JSON_INT)
        timeout_ms = json_get_int(timeout);
    struct zcl_dev_proof_status status = {0};
    if (timeout_ms < 1 || timeout_ms > 300000) {
        status.state = ZCL_DEV_PROOF_STATE_INVALID;
        (void)snprintf(status.detail, sizeof(status.detail), "%s",
                       "timeout_ms_must_be_1_through_300000");
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PROOF_WAIT_INVALID", "normalize", false, false,
            "proof wait input is invalid", status.detail);
        return;
    }
    if (!zcl_dev_proof_wait(
            proof_source_root(request),
            proof_optional_text(request->input, "local_commit"),
            proof_optional_text(request->input, "remote_base"),
            (int)timeout_ms, &status)) {
        proof_emit_status(reply, &status, false);
        if (status.state == ZCL_DEV_PROOF_STATE_INVALID &&
            strcmp(status.detail,
                   "windows_native_proof_worker_unavailable") == 0) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "PROOF_WORKER_UNAVAILABLE", "preflight", false, false,
                "exact background verification is unavailable on this platform",
                status.detail);
        } else {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "PROOF_WAIT_INVALID", "resolve", false, false,
                "proof wait could not resolve its exact receipt request",
                status.detail[0] ? status.detail : "proof_wait_unavailable");
        }
        return;
    }
    zcl_dev_proof_wait_conclude(reply, &status);
#endif
}

/* Read-only: what identity this box signs its receipts with, and whose
 * receipts it will admit. Never creates a key — the first proof does that —
 * so an operator can ask this question from any lane without side effects. */
static void proof_signer(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
#ifndef ZCL_DEV_BUILD
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "push-proof signer identity requires the dev binary", "make dev-bin");
#else
    uint8_t pubkey[ZCL_DEV_PROOF_SIGNER_PUBKEY_BYTES];
    char hex[ZCL_DEV_PROOF_SIGNER_PUBKEY_HEX];
    char key_path[ZCL_DEV_PROOF_SIGNER_PATH_MAX];
    char allow_path[ZCL_DEV_PROOF_SIGNER_PATH_MAX];
    struct zcl_dev_proof_allowlist_state allowlist = {0};
    bool present = false;
    const char *why = NULL;
    if (!zcl_dev_proof_signer_paths(key_path, sizeof(key_path), allow_path,
                                    sizeof(allow_path))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "SIGNER_STATE_ROOT_UNAVAILABLE", "resolve", false, false,
            "could not resolve the owner-private development state root",
            "set HOME or XDG_STATE_HOME");
        return;
    }
    if (!zcl_dev_proof_signer_public(pubkey, &present, &why) ||
        !zcl_dev_proof_signer_allowlist_state(&allowlist, &why)) {
        (void)json_push_kv_str(&reply->data, "schema",
                               "zcl.dev_proof_signer.v1");
        (void)json_push_kv_str(&reply->data, "key_path", key_path);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "SIGNER_KEY_UNREADABLE", "resolve", false, false,
            "this box has a signing key it cannot read",
            why ? why : "signer_key_unreadable");
        return;
    }
    zcl_hex_encode(pubkey, sizeof(pubkey), hex);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.dev_proof_signer.v1");
    (void)json_push_kv_bool(&reply->data, "key_present", present);
    (void)json_push_kv_str(&reply->data, "pubkey", present ? hex : "");
    (void)json_push_kv_str(&reply->data, "key_path", key_path);
    (void)json_push_kv_str(&reply->data, "allowlist_path", allow_path);
    (void)json_push_kv_bool(&reply->data, "allowlist_present",
                            allowlist.present);
    (void)json_push_kv_int(&reply->data, "trusted_signers",
                           (int64_t)allowlist.trusted);
    (void)json_push_kv_int(&reply->data, "malformed_lines",
                           (int64_t)allowlist.malformed);
    (void)json_push_kv_bool(&reply->data, "self_listed", allowlist.self_listed);
    if (!present)
        (void)zcl_command_reply_add_next(
            reply, "dev.proof.ensure", "{}",
            "this box has no signing key yet; the first proof creates one");
#endif
}

void zcl_native_dev_proof_dispatch(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *path = request && request->spec ? request->spec->path : NULL;
    if (path && strcmp(path, "dev.proof.ensure") == 0)
        proof_ensure(request, reply);
    else if (path && strcmp(path, "dev.proof.status") == 0)
        proof_status(request, reply);
    else if (path && strcmp(path, "dev.proof.wait") == 0)
        proof_wait(request, reply);
    else if (path && strcmp(path, "dev.proof.signer") == 0)
        proof_signer(request, reply);
    else
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PROOF_COMMAND_INVALID", "dispatch", false, false,
            "proof dispatch requires an exact proof command path", "");
}
