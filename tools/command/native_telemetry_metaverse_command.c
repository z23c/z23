/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `ops.telemetry.metaverse` controller. It is deliberately thin, and the
 * thinness is the contract (docs/TELEMETRY_CONTRACT.md): pick a snapshot, pick
 * the view the caller asked for, call telemetry_render(). It names no field,
 * builds no JSON, decides no health, and holds no state — every one of those
 * belongs to the field table, the provider, or the render layer.
 *
 * ONE leaf is wired here. `ops.telemetry.metaverse.market` and
 * `ops.telemetry.metaverse.services` stay PLANNED and fail closed with exit 3,
 * because nothing in this build can answer them honestly: there is no property
 * market subsystem at all, and the confined agent broker is a separate process
 * whose state lives in an operator-named directory rather than in this one.
 * See engine/composition/commands/telemetry/metaverse.def for the stated reasons.
 *
 * Bound by engine/composition/commands/telemetry/metaverse.def.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/metaverse_telemetry.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"

#include <stdbool.h>
#include <stddef.h>

void zcl_native_handle_telemetry_metaverse_properties(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;

    /* Zero-init is load-bearing: every leaf starts TELEMETRY_UNSET, so a field
     * the provider forgets renders as a counted provider defect rather than a
     * plausible zero. */
    struct metaverse_snapshot snap = {0};
    if (!metaverse_dump_state_fill(&snap)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "FILL_FAILED",
                               "handle", false, false,
                               "the metaverse telemetry collector refused to "
                               "fill its snapshot",
                               "ops.telemetry.metaverse.properties");
        return;
    }

    /* The view the caller asked for, at the tier they asked for it. Budget
     * stepping and view downgrade are the shared layer's job, not this file's:
     * six copies of that decision is how they drift. */
    const char *group = NULL;
    bool unrecognized = false;
    enum telemetry_view view =
        telemetry_view_parse(request ? request->view : NULL, &group,
                             &unrecognized);

    if (!telemetry_render(&g_metaverse_schema, &snap, view, group,
                          &reply->data)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RENDER_FAILED",
                               "handle", false, false,
                               "the metaverse telemetry document could not be "
                               "rendered in full; a partial reply is refused",
                               "ops.telemetry.metaverse.properties");
        return;
    }
    /* An unrecognized view key is reported, never guessed at silently: the
     * renderer already fell back to `normal` and said so in `view`. */
    if (unrecognized)
        (void)json_push_kv_bool(&reply->data, "view_key_unrecognized", true);
}
