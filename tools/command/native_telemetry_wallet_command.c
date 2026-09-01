/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for `ops.telemetry.wallet.*`.
 *
 * THE WHOLE JOB OF THIS FILE is to pick a snapshot and a view and hand both to
 * telemetry_render(). It names no field, decides no health, formats no number
 * and builds no document. Those all belong to the two layers either side of
 * it: util/telemetry/wallet_fields.def declares the fields and their meaning,
 * services/wallet_telemetry.h collects the values, and
 * platform/modules/util/src/telemetry_render.c is the single renderer. If a change here
 * needs to know a field's name, the change belongs in one of those files.
 *
 * The two leaves differ by exactly one argument:
 *   summary   the whole domain at the caller's view
 *   security  the `security` group only, at the caller's view
 * There is no second code path, no per-leaf document assembly, and no
 * budget-stepping: the view the caller asked for is the view that is rendered,
 * and a document that does not fit its leaf budget is reported by the registry
 * as an over-budget reply rather than quietly shortened here.
 *
 * PROCESS SCOPE. A leaf whose subsystem is not wired in the process serving
 * the call renders `null` with a static reason token and is judged `unknown`,
 * never `ok` and never a plausible zero - see the provider header for which
 * facts are process-local and which are build facts.
 *
 * Bound by engine/composition/commands/telemetry/wallet.def.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/wallet_telemetry.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"

#include <stddef.h>

/* The sibling leaf each reply points at. Never the leaf being served: a
 * next[] entry naming the command currently in flight makes push_next_array
 * reject the WHOLE reply, which surfaces as an empty document and a budget
 * error rather than as the bad pointer it is. */
#define TW_SUMMARY_PATH  "ops.telemetry.wallet.summary"
#define TW_SECURITY_PATH "ops.telemetry.wallet.security"

/* Pick the snapshot, pick the view, render. `only_group` is NULL for the whole
 * domain or the one group name a leaf is scoped to. */
static void tw_render(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *only_group)
{
    struct wallet_snapshot snap = { 0 };
    if (!wallet_dump_state_fill(&snap)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "COLLECT_FAILED",
                               "execute", false, false,
                               "the wallet telemetry provider refused to fill "
                               "a snapshot", "wallet_dump_state_fill");
        return;
    }

    /* The CLI validates --view to summary|normal|full before dispatch and an
     * unrecognized value parses to normal, so no group name can arrive down
     * this path; out_group is therefore NULL and the leaf's own scope is the
     * only group filter that can apply. */
    enum telemetry_view view =
        telemetry_view_parse(request->view, NULL, NULL);

    if (!telemetry_render(&g_wallet_schema, &snap, view, only_group,
                          &reply->data)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RENDER_FAILED",
                               "render", false, false,
                               "the wallet telemetry document could not be "
                               "rendered in full; a partial reply is refused",
                               g_wallet_schema.schema_id);
        return;
    }
}

void zcl_native_handle_telemetry_wallet_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    tw_render(request, reply, NULL);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED)
        return;
    (void)zcl_command_reply_add_next(
        reply, TW_SECURITY_PATH, "{}",
        "read the key-handling posture behind these read models");
}

void zcl_native_handle_telemetry_wallet_security(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    tw_render(request, reply, "security");
    if (reply->status != ZCL_COMMAND_STATUS_PASSED)
        return;
    (void)zcl_command_reply_add_next(
        reply, TW_SUMMARY_PATH, "{}",
        "read how current the wallet read models behind these keys are");
}
