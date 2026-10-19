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
 * derived from the service result and the live mirror health, never assumed. */

#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "json/json.h"
#include "services/authority_projection_audit.h"
#include "services/utxo_mirror_sync_service.h"

#include <stdio.h>

static const char *umc_state(const struct utxo_mirror_sync_service *svc)
{
    return atomic_load(&svc->mirror_health) == UTXO_MIRROR_QUARANTINED
               ? "quarantined" : "healthy";
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
#endif

/* Build the success projection AFTER the commit. False if any field cannot be
 * built (allocation/serialization failure). */
static bool umc_render_success(const struct utxo_mirror_sync_service *svc,
                               int64_t rows, struct zcl_command_reply *reply)
{
    json_set_object(&reply->data);
    bool ok = json_push_kv_int(&reply->data, "rows_written", rows);
    ok = ok && json_push_kv_int(&reply->data, "mirror_height",
                                atomic_load(&svc->last_mirror_height));
    ok = ok && json_push_kv_bool(&reply->data, "quarantined",
                                 atomic_load(&svc->mirror_health) ==
                                     UTXO_MIRROR_QUARANTINED);
    ok = ok && json_push_kv_bool(&reply->data, "mutated", true);
    ok = ok && json_push_kv_str(&reply->data, "current_state", umc_state(svc));
    /* The audit's difference list is a separate observation; say plainly
     * whether the last one stopped on a scan error, or at its listing limit, or
     * was complete, rather than implying it is clean. */
    ok = ok && json_push_kv_bool(&reply->data, "audit_diff_scan_error",
                                 ap_audit_diff_scan_error());
    ok = ok && json_push_kv_bool(&reply->data, "audit_diff_truncated",
                                 ap_audit_diff_truncated());
#ifdef ZCL_TESTING
    if (g_umc_fail_projection)
        ok = false;
#endif
    return ok;
}

void zcl_native_handle_utxo_mirror_rebuild(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct utxo_mirror_sync_service *svc = g_utxo_mirror_sync;
    if (!svc) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "MIRROR_ABSENT",
                               "handle", false, false,
                               "the utxo mirror service is not running", "");
        return;
    }
    char reason[96] = "";
    int64_t rows = utxo_mirror_rebuild_now_reason(svc, reason, sizeof(reason));
    if (rows < 0) {
        struct umc_outcome o = umc_classify(rows);
        char evidence[160];
        if (reason[0])
            snprintf(evidence, sizeof(evidence),
                     "current_state=%s;reason=%s", umc_state(svc), reason);
        else
            snprintf(evidence, sizeof(evidence), "current_state=%s",
                     umc_state(svc));
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, o.code, "handle",
                               o.retryable, o.mutated, o.message, evidence);
        return;
    }
    if (!umc_render_success(svc, rows, reply)) {
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
