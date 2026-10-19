/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handler for `ops.recovery.utxo_mirror`: the operator repair for the
 * node.db `utxos` projection. It rebuilds the mirror wholesale from one
 * coins_kv snapshot on a private writer, verifies the staged rows against that
 * snapshot's SHA3 commitment, and commits only on a match (clearing a sticky
 * quarantine). It never writes coins_kv. Parse -> authorize (registry,
 * OPERATOR) -> call one service -> render. Every typed outcome is reported as
 * itself: the error code, the `mutated` flag and the projection's
 * current_state (in the error evidence and, on success, in the data) are
 * derived from the service result and the live mirror health, never assumed.
 *
 * Where it runs. The mirror service lives in the NODE process; the CLI runs
 * registry commands in its own process, where g_utxo_mirror_sync is NULL. The
 * handler therefore has two paths over one renderer:
 *   - inside the node (service global set): rebuild directly;
 *   - in the CLI: forward to the node RPC method `utxomirrorrebuild`, which
 *     only REQUESTS the rebuild (it outlasts the 10 s RPC deadline and would
 *     pin one of the four RPC workers) and runs it on the mirror thread; the
 *     CLI then polls that job and renders the typed result. It NEVER falls
 *     back to a local run: no answering node is NODE_UNAVAILABLE. */

#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "controllers/rpc_client.h"
#include "controllers/utxo_mirror_controller.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "services/authority_projection_audit.h"
#include "services/utxo_mirror_sync_service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Everything the renderer needs, whichever path produced it. */
struct umc_view {
    int64_t rows;            /* rows written, or a negative UTXO_MIRROR_REBUILD_* */
    char reason[96];
    bool quarantined;
    int64_t mirror_height;
    bool diff_scan_error;
    bool diff_truncated;
};

static const char *umc_state(const struct umc_view *v)
{
    return v->quarantined ? "quarantined" : "healthy";
}

/* One typed non-success outcome: error code, whether node.db may have been
 * mutated, and the message. */
struct umc_outcome {
    const char *code;
    bool retryable;
    bool mutated;
    const char *message;
};

static struct umc_outcome umc_classify(int64_t rows)
{
    switch (rows) {
    case UTXO_MIRROR_REBUILD_UNSETTLED:
        return (struct umc_outcome){"ROLLBACK_UNSETTLED", false, true,
            "rebuild rollback or writer close could not be proven; mirror "
            "restoration is unproven and remains quarantined; operator "
            "inspection required"};
    case UTXO_MIRROR_REBUILD_OVERLAY_ACTIVE:
        return (struct umc_outcome){"OVERLAY_ACTIVE", true, false,
            "the RAM coins overlay is active; refused before any write"};
    case UTXO_MIRROR_REBUILD_REFUSED:
        return (struct umc_outcome){"SOURCE_REFUSED", false, false,
            "the coins_kv source failed the authority proof; refused before "
            "any write"};
    case UTXO_MIRROR_REBUILD_VERIFY_MISMATCH:
        return (struct umc_outcome){"VERIFY_MISMATCH", false, false,
            "the staged rows did not match the snapshot commitment; rolled "
            "back, no successful repair is established"};
    case UTXO_MIRROR_REBUILD_STOPPED:
        return (struct umc_outcome){"STOPPED", true, false,
            "the rebuild was stopped and rolled back; no successful repair "
            "is established"};
    default:
        return (struct umc_outcome){"REBUILD_FAILED", false, false,
            "the rebuild did not complete; no successful repair is "
            "established"};
    }
}

#ifdef ZCL_TESTING
static bool g_umc_fail_projection;
void zcl_utxo_mirror_controller_test_fail_projection(bool fail)
{
    g_umc_fail_projection = fail;
}
static int64_t g_umc_poll_interval_ms = -1;
static int64_t g_umc_poll_max_ms = -1;
void zcl_utxo_mirror_controller_test_set_poll(int64_t interval_ms,
                                              int64_t max_wait_ms)
{
    g_umc_poll_interval_ms = interval_ms;
    g_umc_poll_max_ms = max_wait_ms;
}
#endif

/* Build the success projection AFTER the commit. False if any field cannot be
 * built (allocation/serialization failure). */
static bool umc_render_success(const struct umc_view *v,
                               struct zcl_command_reply *reply)
{
    json_set_object(&reply->data);
    bool ok = json_push_kv_int(&reply->data, "rows_written", v->rows);
    ok = ok && json_push_kv_int(&reply->data, "mirror_height",
                                v->mirror_height);
    ok = ok && json_push_kv_bool(&reply->data, "quarantined", v->quarantined);
    ok = ok && json_push_kv_bool(&reply->data, "mutated", true);
    ok = ok && json_push_kv_str(&reply->data, "current_state", umc_state(v));
    /* The audit's difference list is a separate observation; say plainly
     * whether the last one stopped on a scan error, or at its listing limit, or
     * was complete, rather than implying it is clean. */
    ok = ok && json_push_kv_bool(&reply->data, "audit_diff_scan_error",
                                 v->diff_scan_error);
    ok = ok && json_push_kv_bool(&reply->data, "audit_diff_truncated",
                                 v->diff_truncated);
#ifdef ZCL_TESTING
    if (g_umc_fail_projection)
        ok = false;
#endif
    return ok;
}

/* The one renderer: typed failure for a negative result, else the success
 * projection. Both the in-node and the forwarded path end here. */
static void umc_render(const struct umc_view *v,
                       struct zcl_command_reply *reply)
{
    if (v->rows < 0) {
        struct umc_outcome o = umc_classify(v->rows);
        char evidence[160];
        if (v->reason[0])
            snprintf(evidence, sizeof(evidence),
                     "current_state=%s;reason=%s", umc_state(v), v->reason);
        else
            snprintf(evidence, sizeof(evidence), "current_state=%s",
                     umc_state(v));
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, o.code, "handle",
                               o.retryable, o.mutated, o.message, evidence);
        return;
    }
    if (!umc_render_success(v, reply)) {
        /* The repair has COMMITTED; only the reply could not be built. Say so,
         * and never invite a blind replay. */
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "COMMITTED_REPLY_FAILED", "render",
            false, true,
            "the rebuild committed; the success reply could not be built; "
            "do not replay, inspect with the audit dumpstate",
            "current_state=committed");
    }
}

static void umc_fail_absent(struct zcl_command_reply *reply)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "MIRROR_ABSENT",
                           "handle", false, false,
                           "the utxo mirror service is not running", "");
}

/* ── In-node path ───────────────────────────────────────────── */

static void umc_run_direct(struct utxo_mirror_sync_service *svc,
                           struct zcl_command_reply *reply)
{
    struct umc_view v = {0};
    v.rows = utxo_mirror_rebuild_now_reason(svc, v.reason, sizeof(v.reason));
    v.quarantined = atomic_load(&svc->mirror_health) == UTXO_MIRROR_QUARANTINED;
    v.mirror_height = atomic_load(&svc->last_mirror_height);
    v.diff_scan_error = ap_audit_diff_scan_error();
    v.diff_truncated = ap_audit_diff_truncated();
    umc_render(&v, reply);
}

/* ── CLI path: forward to the node RPC, then poll the job ───── */

#define UMC_RPC_METHOD "utxomirrorrebuild"
#define UMC_POLL_INTERVAL_MS 1000
#define UMC_POLL_MAX_MS (30 * 60 * 1000)   /* a rebuild is seconds to minutes */
#define UMC_POLL_MAX_FAILS 30              /* consecutive unanswered polls */

static int64_t umc_poll_interval_ms(void)
{
#ifdef ZCL_TESTING
    if (g_umc_poll_interval_ms >= 0)
        return g_umc_poll_interval_ms;
#endif
    return UMC_POLL_INTERVAL_MS;
}

static int64_t umc_poll_max_ms(void)
{
#ifdef ZCL_TESTING
    if (g_umc_poll_max_ms >= 0)
        return g_umc_poll_max_ms;
#endif
    return UMC_POLL_MAX_MS;
}

/* One RPC round trip. True only when the node answered with a typed object
 * (it always does: the method never returns a JSON-RPC error). Anything else —
 * connection refused, no cookie, deadline, an error object, an old node
 * without the method — means no usable answer. */
static bool umc_call(const char *params, struct json_value *body,
                     char *why, size_t why_cap)
{
    why[0] = '\0';
    char *raw = node_rpc_call(UMC_RPC_METHOD, params);
    if (!raw) {
        snprintf(why, why_cap, "no reply");
        return false;
    }
    bool parsed = json_read(body, raw, strlen(raw));
    free(raw);
    if (!parsed || body->type != JSON_OBJ ||
        !json_get_str(json_get(body, "state"))) {
        const struct json_value *err = parsed && body->type == JSON_OBJ
            ? json_get(body, "error") : NULL;
        const char *msg = err && err->type == JSON_OBJ
            ? json_get_str(json_get(err, "message")) : NULL;
        snprintf(why, why_cap, "%s", msg && msg[0] ? msg : "untyped reply");
        json_free(body);
        return false;
    }
    return true;
}

static void umc_fail_unavailable(struct zcl_command_reply *reply,
                                 const char *why)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                           "dispatch", true, false,
                           "no node answered the utxo mirror rebuild request; "
                           "nothing was run or changed (this repair never "
                           "runs outside the node)", why);
    (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                     "confirm the node is running");
}

/* The node accepted the job and then went quiet, or the wait ran out: the
 * rebuild may have run or may still be running, so node.db may be mutated. */
static void umc_fail_unknown(struct zcl_command_reply *reply, uint64_t id,
                             const char *why)
{
    char evidence[160];
    snprintf(evidence, sizeof(evidence), "job_id=%llu;%s",
             (unsigned long long)id, why);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "REBUILD_OUTCOME_UNKNOWN",
                           "poll", false, true,
                           "the rebuild was started but its outcome could not "
                           "be read; do not replay, inspect the mirror first",
                           evidence);
    (void)zcl_command_reply_add_next(reply, "ops.debug.dash.mirror", "{}",
                                     "inspect mirror health and rebuild count");
}

static void umc_view_from_body(const struct json_value *b, struct umc_view *v)
{
    memset(v, 0, sizeof(*v));
    v->rows = json_get_int(json_get(b, "rows"));
    const char *r = json_get_str(json_get(b, "reason"));
    if (r)
        snprintf(v->reason, sizeof(v->reason), "%s", r);
    v->quarantined = json_get_bool(json_get(b, "quarantined"));
    v->mirror_height = json_get_int(json_get(b, "mirror_height"));
    v->diff_scan_error = json_get_bool(json_get(b, "audit_diff_scan_error"));
    v->diff_truncated = json_get_bool(json_get(b, "audit_diff_truncated"));
}

static void umc_poll_job(uint64_t id, struct zcl_command_reply *reply)
{
    char params[64];
    snprintf(params, sizeof(params), "[\"status\",%llu]",
             (unsigned long long)id);
    int64_t start = platform_time_monotonic_ms();
    int fails = 0;
    char why[160] = "";
    for (;;) {
        int64_t interval = umc_poll_interval_ms();
        if (interval > 0)
            platform_sleep_ms((int)interval);
        struct json_value b = {0};
        if (umc_call(params, &b, why, sizeof(why))) {
            fails = 0;
            const char *state = json_get_str(json_get(&b, "state"));
            if (strcmp(state, "done") == 0) {
                if ((uint64_t)json_get_int(json_get(&b, "job_id")) != id) {
                    json_free(&b);
                    umc_fail_unknown(reply, id, "result superseded by a "
                                                "later job");
                    return;
                }
                struct umc_view v;
                umc_view_from_body(&b, &v);
                json_free(&b);
                umc_render(&v, reply);
                return;
            }
            bool active = strcmp(state, "pending") == 0 ||
                          strcmp(state, "running") == 0;
            json_free(&b);
            if (!active) {
                umc_fail_unknown(reply, id, "the job record is gone");
                return;
            }
        } else if (++fails >= UMC_POLL_MAX_FAILS) {
            umc_fail_unknown(reply, id, why);
            return;
        }
        if (platform_time_monotonic_ms() - start >= umc_poll_max_ms()) {
            umc_fail_unknown(reply, id, "wait limit reached, job still active");
            return;
        }
    }
}

static void umc_run_forwarded(struct zcl_command_reply *reply)
{
    zcl_native_bridge_ensure_rpc();
    struct json_value b = {0};
    char why[160];
    if (!umc_call("[\"start\"]", &b, why, sizeof(why))) {
        umc_fail_unavailable(reply, why);
        return;
    }
    const char *state = json_get_str(json_get(&b, "state"));
    uint64_t id = (uint64_t)json_get_int(json_get(&b, "job_id"));
    if (strcmp(state, "started") == 0) {
        json_free(&b);
        umc_poll_job(id, reply);
        return;
    }
    if (strcmp(state, "in_progress") == 0) {
        char evidence[48];
        snprintf(evidence, sizeof(evidence), "job_id=%llu",
                 (unsigned long long)id);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
            ZCL_COMMAND_EXIT_BLOCKED, "REBUILD_IN_PROGRESS", "handle", true,
            false,
            "a rebuild is already pending or running on the node; this call "
            "queued nothing", evidence);
    } else if (strcmp(state, "not_running") == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "MIRROR_NOT_RUNNING", "handle", false,
            false, "the utxo mirror thread is not running on the node", "");
    } else if (strcmp(state, "absent") == 0) {
        umc_fail_absent(reply);
    } else {
        umc_fail_unavailable(reply, "unrecognised reply to the start request");
    }
    json_free(&b);
}

void zcl_native_handle_utxo_mirror_rebuild(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct utxo_mirror_sync_service *svc = g_utxo_mirror_sync;
    if (svc)
        umc_run_direct(svc, reply);
    else
        umc_run_forwarded(reply);
}

/* ── Node RPC: utxomirrorrebuild ["start"] | ["status", job_id] ─ */

static const char *umc_job_state_name(int s)
{
    switch (s) {
    case UTXO_MIRROR_JOB_PENDING: return "pending";
    case UTXO_MIRROR_JOB_RUNNING: return "running";
    case UTXO_MIRROR_JOB_DONE:    return "done";
    default:                      return "idle";
    }
}

static bool rpc_utxomirrorrebuild(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "utxomirrorrebuild \"start\" | \"status\" job_id\n"
            "\nOperator repair of the node.db utxos projection. start only\n"
            "QUEUES a wholesale rebuild on the mirror thread and returns the\n"
            "job id at once (state started | in_progress | not_running |\n"
            "absent); status reports state idle|pending|running|done and,\n"
            "when done, the typed result. Always a typed object, never an\n"
            "RPC error. Operator authority (RPC cookie); never remote.\n");
        return true;
    }
    json_set_object(result);
    struct utxo_mirror_sync_service *svc = g_utxo_mirror_sync;
    const struct json_value *a0 = params && json_size(params) > 0
        ? json_at(params, 0) : NULL;
    const char *action = a0 ? json_get_str(a0) : NULL;
    if (!action || (strcmp(action, "start") != 0 &&
                    strcmp(action, "status") != 0)) {
        json_push_kv_str(result, "state", "bad_request");
        return true;
    }
    if (!svc) {
        json_push_kv_str(result, "state", "absent");
        return true;
    }
    if (strcmp(action, "start") == 0) {
        uint64_t id = 0;
        int rc = utxo_mirror_rebuild_request(svc, &id);
        json_push_kv_str(result, "state", rc == 0 ? "started"
                         : rc > 0 ? "in_progress" : "not_running");
        json_push_kv_int(result, "job_id", (int64_t)id);
        return true;
    }
    struct utxo_mirror_rebuild_job j;
    utxo_mirror_rebuild_job_snapshot(svc, &j);
    json_push_kv_str(result, "state", umc_job_state_name(j.state));
    json_push_kv_int(result, "job_id", (int64_t)j.id);
    if (j.state == UTXO_MIRROR_JOB_DONE) {
        json_push_kv_int(result, "rows", j.result);
        json_push_kv_str(result, "reason", j.reason);
        json_push_kv_bool(result, "quarantined", j.quarantined);
        json_push_kv_int(result, "mirror_height", j.mirror_height);
        json_push_kv_bool(result, "audit_diff_scan_error",
                          ap_audit_diff_scan_error());
        json_push_kv_bool(result, "audit_diff_truncated",
                          ap_audit_diff_truncated());
    }
    return true;
}

void register_utxo_mirror_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmd = { "utxomirror", UMC_RPC_METHOD,
                               rpc_utxomirrorrebuild, false };
    rpc_table_must_append(t, &cmd);
}
