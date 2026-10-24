/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Native command adapter for exact local push-proof receipts. */

#include "command/native_command.h"
#include "command/native_dev_loop_command.h"
#include "command/native_dev_proof_command.h"

#include "dev_proof.h"
#ifdef ZCL_DEV_BUILD
#include <errno.h>

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "dev_proof_coverage.h"
#include "dev_proof_observation_index.h"
#include "dev_proof_signer.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#endif
#include "json/json.h"
#include "platform/clock.h"

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
    case ZCL_DEV_PROOF_STATE_NO_VERDICT: return "no_verdict";
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
static void proof_emit_route(struct zcl_command_reply *reply,
                             const struct zcl_dev_proof_status *status,
                             const char *command, const char *reason)
{
    if (status->state == ZCL_DEV_PROOF_STATE_PASSED ||
        status->state == ZCL_DEV_PROOF_STATE_INVALID ||
        !status->root[0] || !status->local_commit[0] || !status->remote_base[0])
        return;
    struct json_value object = {0};
    json_set_object(&object);
    bool ready = json_push_kv_str(&object, "root", status->root) &&
        json_push_kv_str(&object, "local_commit", status->local_commit) &&
        json_push_kv_str(&object, "remote_base", status->remote_base);
    char input[sizeof(reply->next[0].input_json)];
    size_t n = ready ? json_write(&object, input, sizeof(input)) : 0;
    json_free(&object);
    /* An unrepresentable route is omitted, never shortened or redirected
     * to whichever checkout happens to execute the next command. */
    if (n == 0 || n >= sizeof(input)) return;
    (void)zcl_command_reply_add_next(reply, command, input, reason);
}

static void proof_emit_next(struct zcl_command_reply *reply,
                            const struct zcl_dev_proof_status *status)
{
    bool failed = status->state == ZCL_DEV_PROOF_STATE_FAILED ||
                  status->state == ZCL_DEV_PROOF_STATE_NO_VERDICT;
    proof_emit_route(reply, status, failed ? "dev.proof.retry" : "dev.proof.wait",
        failed
            ? "after repairing the reported prerequisite, explicitly request a new full proof"
            : "wait for the exact commit/base receipt without running push-time work");
}

static bool proof_producer_recovery(const struct zcl_dev_proof_status *status)
{
    return (status->state == ZCL_DEV_PROOF_STATE_FAILED ||
            status->state == ZCL_DEV_PROOF_STATE_NO_VERDICT) &&
        (strcmp(status->detail, "proof_producer_source_mismatch") == 0 ||
         strcmp(status->detail, "proof_producer_source_id_unavailable") == 0);
}

static void proof_emit_producer_recovery(struct zcl_command_reply *reply,
    const struct zcl_dev_proof_status *status)
{
    if (!proof_producer_recovery(status) || !status->root[0]) return;
    char executable[PATH_MAX];
    int n = snprintf(executable, sizeof(executable), "%s/build/bin/z23-dev",
                     status->root);
    if (n <= 0 || (size_t)n >= sizeof(executable)) return;
    /* This is a locator, not admission: the next producer must independently
     * qualify its own compiled source identity against the exact candidate. */
    (void)json_push_kv_str(&reply->data, "producer_executable", executable);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
        "Use producer_executable under devbuild --wait to run dev.proof.retry "
        "then dev.proof.step with this exact root, local_commit and remote_base; "
        "make dev-bin in that root first if the candidate producer is missing.");
}

static const char *proof_execution_state(const struct zcl_dev_proof_status *status)
{
    if (strcmp(status->detail, "resident_proof_request_queued") == 0)
        return "queued";
    if (strcmp(status->detail, "background_verification_running") == 0 &&
        status->worker_id > 1 && status->started_unix > 0 &&
        status->started_unix <= clock_now_wall_ms() / 1000)
        return "executing";
    return "unknown";
}

static void proof_emit_status(struct zcl_command_reply *reply,
                              const struct zcl_dev_proof_status *status,
                              bool add_wait_next)
{
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_proof_status.v1");
    (void)json_push_kv_str(&reply->data, "status",
                           zcl_dev_proof_state_name(status->state));
    if (status->root[0])
        (void)json_push_kv_str(&reply->data, "root", status->root);
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
    if (status->evidence[0])
        (void)json_push_kv_str(&reply->data, "evidence", status->evidence);
    if (status->worker_id > 1)
        (void)json_push_kv_int(&reply->data, "worker_id", status->worker_id);
    if (status->started_unix > 0)
        (void)json_push_kv_int(&reply->data, "started_unix",
                               status->started_unix);
    if (status->state == ZCL_DEV_PROOF_STATE_RUNNING) {
        (void)json_push_kv_str(&reply->data, "execution_state",
                               proof_execution_state(status));
        if (strcmp(status->detail, "resident_proof_request_queued") == 0)
            (void)json_push_kv_int(&reply->data, "request_age_s",
                                   status->request_age_s);
        /* Remaining timeout budget, not a predicted completion time. */
        (void)json_push_kv_int(&reply->data, "eta_ms", status->eta_ms);
    }
    (void)json_push_kv_bool(&reply->data, "receipt_reused",
                            status->receipt_reused);
    if (add_wait_next) proof_emit_next(reply, status);
}

void zcl_dev_proof_status_conclude(struct zcl_command_reply *reply,
                                   const struct zcl_dev_proof_status *status)
{
    proof_emit_status(reply, status, true);
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
 * identity: proving will not run again for it automatically. This is a terminal outcome,
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
    proof_emit_producer_recovery(reply, status);
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
    if (status->state == ZCL_DEV_PROOF_STATE_NO_VERDICT) {
        proof_wait_pending(reply, status, "PROOF_NO_VERDICT", "producer");
        proof_emit_producer_recovery(reply, status);
        return;
    }
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

void zcl_dev_proof_step_conclude(struct zcl_command_reply *reply, int result,
                                 const struct zcl_dev_proof_status *status)
{
    if (result < 0) {
        proof_emit_status(reply, status, false);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "PROOF_STEP_REFUSED", "execute", false,
            false, "foreground proof could not execute the exact pair", status->detail);
        return;
    }
    if (result == 0) {
        proof_emit_status(reply, status, false);
        if (strcmp(status->detail, "proof_foreground_requires_unarmed_checkout") == 0) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                ZCL_COMMAND_EXIT_BLOCKED, "PROOF_STEP_WATCHER_PRESENT", "execute", true,
                false, "foreground proof requires an unarmed checkout",
                "use an existing authorized unarmed verification checkout for this exact commit/base pair");
            return;
        }
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
            ZCL_COMMAND_EXIT_BLOCKED, "PROOF_STEP_BUSY", "execute", true,
            false, "proof execution or landing preparation is busy", status->detail);
        (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                       "%s", "retry dev.proof.step with the same root, local_commit and remote_base after the current execution finishes");
        return;
    }
    zcl_dev_proof_wait_conclude(reply, status);
    if (status->state == ZCL_DEV_PROOF_STATE_FAILED ||
        status->state == ZCL_DEV_PROOF_STATE_NO_VERDICT)
        proof_emit_next(reply, status);
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

static void proof_step(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
        ZCL_COMMAND_EXIT_BLOCKED, "DEV_BUILD_REQUIRED", "dispatch", false,
        false, "foreground proof requires the dev binary", "make dev-bin");
#else
    struct zcl_dev_proof_status status = {0};
    int result = zcl_dev_proof_step(proof_source_root(request),
        proof_optional_text(request->input, "local_commit"),
        proof_optional_text(request->input, "remote_base"), &status);
    zcl_dev_proof_step_conclude(reply, result, &status);
#endif
}

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
    zcl_dev_proof_status_conclude(reply, &status);
#endif
}

static bool proof_existing_watcher_input(const struct json_value *input,
    bool *existing_only, struct zcl_command_reply *reply)
{
    const struct json_value *value = input ?
        json_get(input, "require_existing_watcher") : NULL;
    *existing_only = false;
    if (!value) return true;
    if (value->type != JSON_BOOL) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT", "validate", false, false,
            "require_existing_watcher must be a JSON boolean",
            "input.require_existing_watcher");
        return false;
    }
    *existing_only = json_get_bool(value);
    return true;
}

#ifdef ZCL_DEV_BUILD
static bool proof_start_queue_owner(const struct zcl_command_request *request,
    const char *root, struct zcl_command_reply *reply)
{
    struct zcl_command_reply watcher;
    struct json_value watcher_input;
    json_init(&watcher_input);
    json_set_object(&watcher_input);
    bool ready = json_push_kv_str(&watcher_input, "root", root) &&
        json_push_kv_str(&watcher_input, "mode", "verify");
    if (!ready) {
        json_free(&watcher_input);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INTERNAL, "PROOF_QUEUE_INPUT_FAILED", "schedule",
            true, false, "the resident watcher request could not be allocated",
            "retry proof enqueue");
        return false;
    }
    struct zcl_command_request watcher_request = *request;
    watcher_request.input = &watcher_input;
    zcl_command_reply_init(&watcher, "zcl.dev_loop_status.v1");
    zcl_native_handle_dev_loop_start_async(&watcher_request, &watcher);
    const struct json_value *created = json_get(&watcher.data, "created");
    ready = watcher.exit_code == ZCL_COMMAND_EXIT_OK &&
        ((created && created->type == JSON_BOOL && json_get_bool(created)) ||
         zcl_native_dev_loop_proof_queue_ready(root));
    zcl_command_reply_free(&watcher);
    json_free(&watcher_input);
    if (!ready)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
            ZCL_COMMAND_EXIT_BLOCKED, "PROOF_QUEUE_OWNER_STALE", "schedule",
            true, false, "the resident watcher does not advertise the proof queue contract",
            "restart the development watcher with the current z23-dev binary");
    return ready;
}

static bool proof_existing_queue_owner(const struct zcl_dev_proof_status *status,
    struct zcl_command_reply *reply)
{
    /* Qualification observes existing kernel/session/root ownership. It never
     * starts a watcher, including when a hook's earlier cheap probe raced. */
    if (zcl_native_dev_loop_proof_queue_ready(status->root)) return true;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
        ZCL_COMMAND_EXIT_BLOCKED, "PROOF_EXISTING_WATCHER_REQUIRED", "schedule",
        false, false, "no qualified existing watcher owns this proof queue",
        "foreground verification remains available without starting a watcher");
    proof_emit_route(reply, status, "dev.proof.step",
        "run this exact pair in the foreground under devbuild --wait");
    return false;
}
#endif

static void proof_ensure(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    bool existing_only = false;
    if (!proof_existing_watcher_input(request ? request->input : NULL,
                                     &existing_only, reply)) return;
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
    bool queue_ready = existing_only ? proof_existing_queue_owner(&status, reply)
        : proof_start_queue_owner(request, status.root, reply);
    if (!queue_ready) {
        proof_emit_status(reply, &status, false);
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

static void proof_retry(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "proof retry requires the dev binary", "make dev-bin");
#else
    struct zcl_dev_proof_status status = {0};
    const char *root = proof_source_root(request);
    if (!zcl_dev_proof_status_read(
            root, proof_optional_text(request->input, "local_commit"),
            proof_optional_text(request->input, "remote_base"), &status) ||
        (status.state != ZCL_DEV_PROOF_STATE_FAILED &&
         status.state != ZCL_DEV_PROOF_STATE_NO_VERDICT)) {
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "PROOF_RETRY_REFUSED", "preflight", false, false,
            "proof retry requires a settled failed attempt",
            status.detail[0] ? status.detail : "proof_retry_requires_settled_failure");
        return;
    }
    /* Capture the resolved pair before the library overwrites status. */
    char local[65], base[65];
    (void)snprintf(local, sizeof(local), "%s", status.local_commit);
    (void)snprintf(base, sizeof(base), "%s", status.remote_base);
    if (!zcl_dev_proof_retry(root, local, base, &status)) {
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "PROOF_RETRY_REFUSED", "schedule", false, false,
            "could not queue another proof of the settled failed pair",
            status.detail);
        return;
    }
    proof_emit_status(reply, &status, false);
    proof_emit_route(reply, &status, "dev.proof.step",
                      "execute this explicitly retried pair without starting a watcher");
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

/* Read one coverage manifest file: the fixed envelope wire plus the blob
 * its header names, bounded. Returns 1 when read, 0 when absent, -1 on
 * any malformedness. */
#ifdef ZCL_DEV_BUILD
static int proof_coverage_read_manifest(const char *path,
    uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES],
    uint8_t **blob, size_t *blob_len, char *why, size_t why_len)
{
    *blob = NULL;
    *blob_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? 0 : -1;
    size_t got = fread(envelope, 1, ZCL_DEV_COVERAGE_WIRE_BYTES, f);
    if (got != ZCL_DEV_COVERAGE_WIRE_BYTES) {
        (void)fclose(f);
        (void)snprintf(why, why_len, "%s",
                       ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
        return -1;
    }
    uint32_t blen = 0;
    if (!zcl_dev_coverage_envelope_blob_len(envelope,
                                            ZCL_DEV_COVERAGE_WIRE_BYTES,
                                            &blen)) {
        (void)fclose(f);
        (void)snprintf(why, why_len, "%s", ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
        return -1;
    }
    uint8_t *buf = zcl_malloc(blen ? blen : 1u, "dev-proof-coverage-blob");
    if (!buf) {
        (void)fclose(f);
        (void)snprintf(why, why_len, "%s", "coverage_query_alloc_failed");
        return -1;
    }
    if (blen && fread(buf, 1, blen, f) != blen) {
        free(buf);
        (void)fclose(f);
        (void)snprintf(why, why_len, "%s", ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
        return -1;
    }
    int extra = fgetc(f);
    (void)fclose(f);
    if (extra != EOF) {
        free(buf);
        (void)snprintf(why, why_len, "%s", ZCL_DEV_COVERAGE_WHY_MANIFEST_INVALID);
        return -1;
    }
    *blob = buf;
    *blob_len = blen;
    return 1;
}

/* Everything the coverage query resolves before inspecting: the pair
 * identity, the admitted receipt, and the coverage/store paths. */
struct proof_coverage_resolved {
    struct zcl_dev_proof_status status;
    struct zcl_dev_acceptance_receipt_v1 receipt;
    char manifest_path[4096];
    char store[4096];
};

/* Re-reading the receipt must preserve the exact pair's admission binding. */
static bool proof_coverage_receipt_read(struct proof_coverage_resolved *out)
{
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    FILE *rf = fopen(out->status.receipt_path, "rb");
    char why[128] = {0};
    bool ok = rf && fread(wire, 1, sizeof(wire), rf) == sizeof(wire) &&
        fgetc(rf) == EOF &&
        zcl_dev_proof_receipt_parse(wire, sizeof(wire), &out->receipt) &&
        zcl_dev_proof_receipt_validate(&out->receipt, out->status.local_commit,
            out->status.remote_base, why, sizeof(why));
    if (rf) (void)fclose(rf);
    return ok;
}

/* Status, receipt and paths, or a written refusal. */
static bool proof_coverage_resolve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply,
    struct proof_coverage_resolved *out)
{
    memset(out, 0, sizeof(*out));
    (void)zcl_dev_proof_status_read(
        proof_source_root(request),
        proof_optional_text(request->input, "local_commit"),
        proof_optional_text(request->input, "remote_base"), &out->status);
    if (out->status.local_commit[0] == 0 || out->status.remote_base[0] == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "PROOF_COVERAGE_INVALID", "normalize",
            false, false,
            "coverage query needs a resolvable local commit and remote base",
            out->status.detail[0] ? out->status.detail : "pair_unresolvable");
        return false;
    }
    if (out->status.state != ZCL_DEV_PROOF_STATE_PASSED ||
        out->status.receipt_path[0] == 0) {
        proof_emit_status(reply, &out->status, false);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
            ZCL_COMMAND_EXIT_BLOCKED, "PROOF_COVERAGE_NO_RECEIPT", "receipt",
            out->status.state == ZCL_DEV_PROOF_STATE_RUNNING, false,
            "coverage binds an admitted receipt; this pair has none",
            out->status.detail[0] ? out->status.detail
                                  : "exact_receipt_missing");
        return false;
    }
    if (!proof_coverage_receipt_read(out)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "PROOF_COVERAGE_RECEIPT_UNREADABLE",
            "receipt", false, false,
            "the admitted receipt for this pair cannot be re-read",
            "exact_receipt_missing");
        return false;
    }
    /* <root>/.cache/zcl-dev-proof: strip "/receipts/<key>.receipt". */
    char state_dir[4096];
    const char *receipts_at = strstr(out->status.receipt_path, "/receipts/");
    if (!receipts_at || (size_t)(receipts_at - out->status.receipt_path) >=
            sizeof(state_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "PROOF_COVERAGE_PATH_INVALID",
            "normalize", false, false,
            "the receipt path does not name a proof state directory", "");
        return false;
    }
    (void)memcpy(state_dir, out->status.receipt_path,
                 (size_t)(receipts_at - out->status.receipt_path));
    state_dir[receipts_at - out->status.receipt_path] = 0;
    char key[160];
    (void)snprintf(key, sizeof(key), "%s-%s", out->status.local_commit,
                   out->status.remote_base);
    (void)snprintf(out->manifest_path, sizeof(out->manifest_path),
                   "%s/coverage/%s.coverage", state_dir, key);
    (void)snprintf(out->store, sizeof(out->store), "%s/observations.%s",
                   state_dir, key);
    return true;
}

static void proof_coverage_emit(struct zcl_command_reply *reply,
    const struct proof_coverage_resolved *resolved,
    const struct zcl_dev_coverage_inspect *report)
{
    const char *state = "covered";
    if (report->binding_mismatch)
        state = "binding_mismatch";
    else if (report->signer_why[0])
        state = report->signer_why;
    else if (report->conflicts)
        state = "conflict";
    else if (report->missing)
        state = "incomplete";
    else if (report->unqualified)
        state = "unqualified";
    else if (report->row_count == 0)
        state = "empty";

    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_proof_coverage.v1");
    (void)json_push_kv_str(&reply->data, "local_commit",
                           resolved->status.local_commit);
    (void)json_push_kv_str(&reply->data, "remote_base",
                           resolved->status.remote_base);
    (void)json_push_kv_int(&reply->data, "policy_version",
                           (int64_t)resolved->receipt.policy_version);
    (void)json_push_kv_str(&reply->data, "coverage_state", state);
    (void)json_push_kv_int(&reply->data, "rows", (int64_t)report->row_count);
    (void)json_push_kv_int(&reply->data, "covered", (int64_t)report->covered);
    (void)json_push_kv_int(&reply->data, "unqualified",
                           (int64_t)report->unqualified);
    (void)json_push_kv_int(&reply->data, "missing", (int64_t)report->missing);
    (void)json_push_kv_int(&reply->data, "conflicts",
                           (int64_t)report->conflicts);
    struct json_value missing_groups;
    json_init(&missing_groups);
    json_set_array(&missing_groups);
    for (uint32_t i = 0; i < report->missing_named; i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, report->missing_groups[i]);
        (void)json_push_back(&missing_groups, &item);
        json_free(&item);
    }
    (void)json_push_kv(&reply->data, "missing_groups", &missing_groups);
    json_free(&missing_groups);
    struct json_value observed;
    json_init(&observed);
    json_set_object(&observed);
    (void)json_push_kv_int(&observed, "total",
                           (int64_t)report->observed_total);
    (void)json_push_kv_int(&observed, "eligible",
                           (int64_t)report->observed_eligible);
    (void)json_push_kv_int(&observed, "oldest_observed_unix",
                           (int64_t)report->oldest_observed_unix);
    (void)json_push_kv_int(&observed, "newest_observed_unix",
                           (int64_t)report->newest_observed_unix);
    (void)json_push_kv(&reply->data, "observations", &observed);
    json_free(&observed);
    (void)json_push_kv_str(&reply->data, "signer_trust",
                           report->signer_why[0] ? report->signer_why
                                                 : "trusted");
    if (strcmp(state, "covered") != 0 && strcmp(state, "empty") != 0)
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s",
                       "complete qualified observation coverage for this exact pair; automatic proof-worker coverage integration is unavailable");
}
#endif

/* The lifecycle query over the canonical coverage object: what a pair's
 * manifest binds, what it covers, and what this box has observed.
 * Read-only; a missing manifest BLOCKED like a missing receipt. */
static void proof_coverage(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "coverage queries require the dev binary", "make dev-bin");
#else
    struct proof_coverage_resolved resolved = {0};
    if (!proof_coverage_resolve(request, reply, &resolved))
        return;

    uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    char why[128] = {0};
    int manifest = proof_coverage_read_manifest(resolved.manifest_path,
                                                envelope, &blob, &blob_len,
                                                why, sizeof(why));
    if (manifest <= 0) {
        zcl_command_reply_fail(reply,
            manifest == 0 ? ZCL_COMMAND_STATUS_BLOCKED
                          : ZCL_COMMAND_STATUS_FAILED,
            manifest == 0 ? ZCL_COMMAND_EXIT_BLOCKED
                          : ZCL_COMMAND_EXIT_FAILED,
            manifest == 0 ? "PROOF_COVERAGE_MANIFEST_MISSING"
                          : "PROOF_COVERAGE_MANIFEST_INVALID",
            "coverage", false, false,
            manifest == 0
                ? "this pair has no optional coverage manifest; receipt admission remains policy 5"
                : "the coverage manifest for this pair is malformed",
            why[0] ? why : "coverage_manifest_missing");
        if (manifest == 0)
            (void)snprintf(reply->error.next_action,
                           sizeof(reply->error.next_action), "%s",
                           "automatic manifest production is unavailable; retain the policy-5 receipt and inspect explicit observation evidence");
        return;
    }

    struct zcl_dev_coverage_binding binding = {0};
    (void)memcpy(binding.local_commit, resolved.receipt.local_commit,
                 ZCL_DEV_PROOF_OID_MAX);
    binding.local_commit_len = resolved.receipt.local_commit_len;
    (void)memcpy(binding.remote_base, resolved.receipt.remote_base,
                 ZCL_DEV_PROOF_OID_MAX);
    binding.remote_base_len = resolved.receipt.remote_base_len;
    (void)memcpy(binding.child_set_root, resolved.receipt.child_set_root,
                 ZCL_DEV_PROOF_ROOT_BYTES);
    (void)memcpy(binding.impact_policy_root,
                 resolved.receipt.impact_policy_root,
                 ZCL_DEV_PROOF_ROOT_BYTES);
    binding.policy_version = resolved.receipt.policy_version;

    struct zcl_dev_coverage_inspect report = {0};
    if (!zcl_dev_coverage_inspect(resolved.store, envelope, sizeof(envelope),
                                  blob, blob_len, &binding, &report,
                                  why, sizeof(why))) {
        free(blob);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "PROOF_COVERAGE_INSPECT_REFUSED",
            "coverage", false, false,
            "the coverage objects for this pair refuse inspection",
            why[0] ? why : "coverage_invalid");
        return;
    }
    free(blob);
    proof_coverage_emit(reply, &resolved, &report);
#endif
}

/* The box-level half of the lifecycle query: what this receiver has
 * observed across every pair, which (group, key) inputs carry evidence,
 * their newest verdicts, and where eligible contradictions are
 * preserved. Read-only; an absent index answers empty. */
static void proof_observations(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "observation queries require the dev binary", "make dev-bin");
#else
    char state_root[PATH_MAX], index_path[4096];
    if (!platform_state_root(state_root, sizeof(state_root)) ||
        snprintf(index_path, sizeof(index_path),
                 "%s/dev-observation-index/index", state_root) >=
            (int)sizeof(index_path)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "PROOF_OBSERVATIONS_STATE_UNAVAILABLE",
            "normalize", false, false,
            "this box has no resolvable state root for its observation index",
            "state_root_unavailable");
        return;
    }
    struct zcl_dev_observation_query_report report = {0};
    char why[128] = {0};
    if (!zcl_dev_observation_index_query(
            index_path, proof_optional_text(request->input, "group"),
            &report, why, sizeof(why))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "PROOF_OBSERVATIONS_INVALID", "index",
            false, false,
            "the box-level observation index refuses inspection",
            why[0] ? why : "observation_index_invalid");
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_observations.v1");
    const char *group = request ? proof_optional_text(request->input, "group")
                                : NULL;
    if (group)
        (void)json_push_kv_str(&reply->data, "group_filter", group);
    (void)json_push_kv_int(&reply->data, "observations",
                           (int64_t)report.total);
    (void)json_push_kv_int(&reply->data, "eligible",
                           (int64_t)report.eligible);
    (void)json_push_kv_int(&reply->data, "ineligible",
                           (int64_t)report.ineligible);
    (void)json_push_kv_int(&reply->data, "oldest_observed_unix",
                           (int64_t)report.oldest_observed_unix);
    (void)json_push_kv_int(&reply->data, "newest_observed_unix",
                           (int64_t)report.newest_observed_unix);
    (void)json_push_kv_int(&reply->data, "conflicted_groups",
                           (int64_t)report.conflicted_groups);
    (void)json_push_kv_bool(&reply->data, "truncated", report.truncated);
    struct json_value groups;
    json_init(&groups);
    json_set_array(&groups);
    for (uint32_t i = 0; i < report.groups_named; i++) {
        const struct zcl_dev_observation_group_summary *g = &report.groups[i];
        struct json_value item, key_hex;
        char hex[ZCL_DEV_VERDICT_LEAF_KEY_BYTES * 2 + 1];
        json_init(&item);
        json_set_object(&item);
        json_init(&key_hex);
        zcl_hex_encode(g->key, ZCL_DEV_VERDICT_LEAF_KEY_BYTES, hex);
        json_set_str(&key_hex, hex);
        (void)json_push_kv_str(&item, "group", g->group);
        (void)json_push_kv(&item, "key", &key_hex);
        (void)json_push_kv_str(&item, "verdict",
                               g->verdict == ZCL_DEV_VERDICT_LEAF_PASS
                                   ? "pass" : "fail");
        (void)json_push_kv_int(&item, "observed_unix",
                               (int64_t)g->observed_unix);
        (void)json_push_kv_int(&item, "observations",
                               (int64_t)g->observations);
        (void)json_push_kv_bool(&item, "conflict", g->conflict);
        (void)json_push_back(&groups, &item);
        json_free(&key_hex);
        json_free(&item);
    }
    (void)json_push_kv(&reply->data, "groups", &groups);
    json_free(&groups);
#endif
}

/* Receiver-side projection (canonical lifecycle item 3): fold one pair's
 * durable signed observations into the box-level index. The pair must
 * carry an admitted receipt, exactly like the coverage query; the merge
 * verifies every row it writes, preserves contradictions, refuses corrupt
 * bytes by name, and creates the index when absent. Re-folding the same
 * pair is a union, so the command is idempotent. The index stays a
 * rebuildable projection: this command writes no admission state. */
static void proof_observations_fold(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "observation folds require the dev binary", "make dev-bin");
#else
    struct proof_coverage_resolved resolved = {0};
    if (!proof_coverage_resolve(request, reply, &resolved))
        return;
    char state_root[PATH_MAX], index_path[4096];
    if (!platform_state_root(state_root, sizeof(state_root)) ||
        snprintf(index_path, sizeof(index_path),
                 "%s/dev-observation-index/index", state_root) >=
            (int)sizeof(index_path)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "PROOF_OBSERVATIONS_STATE_UNAVAILABLE",
            "normalize", false, false,
            "this box has no resolvable state root for its observation index",
            "state_root_unavailable");
        return;
    }
    char index_dir[4096];
    int directory_length = snprintf(index_dir, sizeof(index_dir),
                                    "%s/dev-observation-index", state_root);
    if (directory_length < 0 || directory_length >= (int)sizeof(index_dir) ||
        !platform_private_directory_ensure(index_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "PROOF_OBSERVATIONS_DIRECTORY_UNAVAILABLE",
            "index", false, false,
            "the box-level observation index needs an owner-private directory",
            "observation_index_directory_unavailable");
        return;
    }
    char why[128] = {0};
    if (!zcl_dev_observation_index_merge(index_path, resolved.store,
                                         why, sizeof(why))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "PROOF_OBSERVATIONS_FOLD_INVALID",
            "index", false, false,
            "the box-level observation index refuses this pair's durable store",
            why[0] ? why : "observation_index_invalid");
        return;
    }
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_observations_fold.v1");
    (void)json_push_kv_str(&reply->data, "local_commit",
                           resolved.status.local_commit);
    (void)json_push_kv_str(&reply->data, "remote_base",
                           resolved.status.remote_base);
    (void)json_push_kv_str(&reply->data, "store", resolved.store);
    (void)json_push_kv_str(&reply->data, "index_path", index_path);
#endif
}

#define PROOF_SELECT_REPLY_RESERVE 1536u
#define PROOF_SELECT_DEFAULT_BUDGET 65536u

bool zcl_dev_proof_select_reply_fits(size_t groups_len, size_t budget_bytes)
{
    size_t budget = budget_bytes ? budget_bytes : PROOF_SELECT_DEFAULT_BUDGET;
    return groups_len <= budget && budget - groups_len >= PROOF_SELECT_REPLY_RESERVE;
}

/* dev.proof.select: the test groups the land proof would select for
 * base..local, from the proof worker's own planner and selector. A lane
 * verify runs exactly this set, so it cannot miss a group the proof runs. */
static void proof_select(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "proof selection requires the dev binary", "make dev-bin");
#else
    const char *base = proof_optional_text(request->input, "base");
    const char *local = proof_optional_text(request->input, "local_commit");
    if (!base) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PROOF_SELECT_BASE_REQUIRED", "normalize", false, false,
            "base is required: the ref the proof diffs against, e.g. "
            "$(git merge-base origin/main HEAD)", "base");
        return;
    }
    if (!local) local = "HEAD";
    struct zcl_dev_proof_range_selection selection = {0};
    selection.groups_size = zcl_dev_proof_select_groups_capacity();
    selection.groups = zcl_calloc(selection.groups_size, 1,
                                  "dev.proof.select groups");
    if (!selection.groups) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "PROOF_SELECT_ALLOCATION_FAILED", "select", false, true,
            "could not allocate the group selector", "");
        return;
    }
    char why[160] = {0};
    if (!zcl_dev_proof_select_range(proof_source_root(request), base, local,
                                    &selection, why, sizeof(why))) {
        free(selection.groups);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "PROOF_SELECT_REFUSED", "select", false, false,
            "the proof selector refused this range",
            why[0] ? why : "proof_select_failed");
        return;
    }
    if (!zcl_dev_proof_select_reply_fits(
            strlen(selection.groups) + strlen(selection.gated) +
                strlen(selection.detail),
            request->spec ? request->spec->budget_bytes : 0)) {
        free(selection.groups);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "PROOF_SELECT_REPLY_TOO_LARGE", "select", false, false,
            "the selected group list exceeds this leaf's reply budget; "
            "run the groups by name instead", "budget");
        return;
    }
    (void)json_push_kv_str(&reply->data, "base", base);
    (void)json_push_kv_str(&reply->data, "local_commit", local);
    (void)json_push_kv_int(&reply->data, "files", (int64_t)selection.files);
    (void)json_push_kv_str(&reply->data, "selector",
                           selection.universal ? "universal" : "exact");
    (void)json_push_kv_str(&reply->data, "reason", selection.reason);
    (void)json_push_kv_str(&reply->data, "detail",
                           selection.detail[0] ? selection.detail : "-");
    (void)json_push_kv_int(&reply->data, "groups_selected",
                           (int64_t)selection.count);
    (void)json_push_kv_str(&reply->data, "host_gated",
                           selection.gated[0] ? selection.gated : "-");
    (void)json_push_kv_str(&reply->data, "groups", selection.groups);
    free(selection.groups);
#endif
}

void zcl_native_dev_proof_dispatch(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const struct {
        const char *path;
        void (*handler)(const struct zcl_command_request *,
                        struct zcl_command_reply *);
    } routes[] = {
        {"dev.proof.step", proof_step},
        {"dev.proof.ensure", proof_ensure},
        {"dev.proof.status", proof_status},
        {"dev.proof.wait", proof_wait},
        {"dev.proof.retry", proof_retry},
        {"dev.proof.signer", proof_signer},
        {"dev.proof.coverage", proof_coverage},
        {"dev.proof.select", proof_select},
        {"dev.proof.observations", proof_observations},
        {"dev.proof.observations.fold", proof_observations_fold},
    };
    const char *path = request && request->spec ? request->spec->path : NULL;
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        if (path && strcmp(path, routes[i].path) == 0) {
            routes[i].handler(request, reply);
            return;
        }
    }
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
        "PROOF_COMMAND_INVALID", "dispatch", false, false,
        "proof dispatch requires an exact proof command path", "");
}
