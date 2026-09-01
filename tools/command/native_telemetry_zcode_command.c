/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ops.telemetry.zcode.* — the controller for the `zcode` telemetry domain.
 *
 * It is deliberately the thinnest layer in the stack: pick a snapshot, pick a
 * view, call telemetry_render(), attach the document. It names no field, sets
 * no threshold, and holds no state. Everything an agent reads in the reply —
 * the keys, the units, the health verdict, the next command — comes from
 * util/telemetry/zcode_fields.def by way of the shared renderer.
 *
 * WHY NORMAL AND NOT SUMMARY. This leaf takes no view argument, so whatever
 * tier it passes is the only tier this domain is ever rendered at. The field
 * table therefore declares nothing above TLV_NORMAL and this asks for NORMAL:
 * the alternative is rows that exist and can never be read. If a view
 * selector lands later, this is the one line that changes.
 *
 * There is no budget-stepping and no view downgrade here on purpose. If the
 * document ever outgrows the leaf's byte budget the fix belongs in the shared
 * layer, once, not in eight controllers.
 */

#include "command/native_command.h"

#include "json/json.h"
#include "services/zcode_telemetry.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"

/* Move the rendered document's top-level members onto the reply body, so the
 * reply IS the telemetry document rather than a wrapper around one. A shallow
 * copy per member; `doc` is freed by the caller either way. */
static bool zcode_tl_attach(struct zcl_command_reply *reply,
                            const struct json_value *doc)
{
    if (doc->type != JSON_OBJ)
        return false;
    for (size_t i = 0; i < doc->num_children; i++) {
        if (!json_push_kv(&reply->data, doc->keys[i], &doc->children[i]))
            return false;
    }
    return true;
}

void zcl_native_handle_ops_telemetry_zcode_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;

    /* Zero-init is load-bearing: it starts every leaf at TELEMETRY_UNSET, so
     * a field the collector forgets renders as a counted provider defect
     * instead of a believable zero. */
    struct zcode_snapshot snap = {0};
    if (!zcode_dump_state_fill(&snap)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "ZCODE_TELEMETRY_FILL_FAILED", "collect", true, false,
            "the zcode telemetry collector could not fill its snapshot",
            "contexts/commons/services/src/zcode_telemetry_fill.c");
        return;
    }

    struct json_value doc;
    json_init(&doc);
    bool rendered = telemetry_render(&g_zcode_schema, &snap, TLV_NORMAL, NULL,
                                     &doc);
    bool attached = rendered && zcode_tl_attach(reply, &doc);
    json_free(&doc);
    if (!attached) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "ZCODE_TELEMETRY_RENDER_FAILED", "render", true, false,
            "the zcode telemetry snapshot could not be rendered",
            rendered ? "attach" : "telemetry_render");
    }
}
