/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for `ops.telemetry.agents.{sessions,grants,activity}`.
 *
 * These are as thin as the telemetry contract intends. Each one does exactly
 * four things: take the caller's view, fill ONE typed agents snapshot, hand it
 * to telemetry_render() with its own group filter, and attach the two sibling
 * leaves as next steps. No handler here reads a global, decides a health
 * verdict, names a telemetry field, measures a document, or steps a view down
 * — the field table owns the names and the rules, the collector owns the
 * reads, and the renderer owns the JSON. Anything that looks like judgement
 * belongs in engine/services/src/agents_telemetry_fill.c instead.
 *
 * WHY THREE LEAVES OVER ONE SNAPSHOT. All three fill the whole domain and then
 * render one group of it. That is deliberate: health is evaluated over all 25
 * leaves on every call (telemetry_render always judges the full table and
 * prunes only the rendering), so `grants` still reports a malformed grant row
 * even though that leaf lives in the sessions group — while the document each
 * leaf emits stays small enough to fit its budget. The cost is one collection
 * per call, which is five bounded loopback reads.
 *
 * THE next[] RULE, which has already destroyed a reply in this repository: a
 * next entry naming the command currently being served makes
 * push_next_array() abandon the ENTIRE document (command_registry.c) and the
 * CLI then misreports it as a budget overrun with an empty body. Each leaf
 * below therefore points ONLY at its two siblings. Never add a self-reference
 * "for completeness". */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "base/log_macros.h"
#include "json/json.h"
#include "services/agents_telemetry.h"
#include "util/telemetry_render.h"

#include <stdbool.h>
#include <stddef.h>

#define TA_TAG "native.ops.telemetry.agents"
#define TA_DOMAIN "agents"

/* Copy a rendered telemetry document's top-level keys into the reply body.
 * The renderer builds a self-contained object (schema, domain, view, values,
 * leaves, completeness, freshness, health, _health) and the envelope wants
 * those keys AT the body root rather than nested under one more name, so the
 * merge is a shallow key-by-key push. json_push_kv deep-copies, so `doc` is
 * still the caller's to free. */
static bool ta_merge(struct json_value *dst, const struct json_value *doc)
{
    if (!dst || !doc || doc->type != JSON_OBJ)
        return false;
    for (size_t i = 0; i < doc->num_children; i++) {
        if (!doc->keys || !doc->keys[i])
            return false;
        if (!json_push_kv(dst, doc->keys[i], &doc->children[i]))
            return false;
    }
    return true;
}

/* The whole body of all three leaves. `group` is the field table's group name
 * for this leaf; `sibling_a`/`sibling_b` are the two OTHER leaf paths. */
static void ta_render_group(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply, const char *group,
                            const char *sibling_a, const char *reason_a,
                            const char *sibling_b, const char *reason_b)
{
    if (!request || !reply)
        return;

    const struct telemetry_domain_schema *schema =
        telemetry_domain_find(TA_DOMAIN);
    if (!schema) {
        LOG_ERROR(TA_TAG, "the '%s' telemetry domain is not registered",
                  TA_DOMAIN);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "TELEMETRY_DOMAIN_MISSING", "resolve", false, false,
            "the agents telemetry domain is not in the schema registry",
            TA_DOMAIN);
        return;
    }

    /* Zero IS the unset presence the renderer counts as a provider defect, so
     * this initializer is the contract's starting state, not tidiness. */
    struct agents_snapshot snap = { 0 };

    /* The collector reaches the node over loopback RPC and this is a one-shot
     * CLI process, so the client global is empty until this call. */
    zcl_native_bridge_ensure_rpc();
    agents_dump_state_fill(&snap);

    /* The view the caller asked for, rendered at that view — no measuring and
     * no stepping down. An over-budget reply is the kernel's to report. */
    enum telemetry_view view = telemetry_view_parse(request->view, NULL, NULL);

    struct json_value doc;
    json_init(&doc);
    bool ok = telemetry_render(schema, &snap, view, group, &doc) &&
              ta_merge(&reply->data, &doc);
    json_free(&doc);
    if (!ok) {
        LOG_ERROR(TA_TAG, "render failed for group '%s'", group);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "TELEMETRY_RENDER",
                               "serialize", false, false,
                               "the agents telemetry document could not be "
                               "rendered",
                               group);
        return;
    }

    (void)zcl_command_reply_add_next(reply, sibling_a, "{}", reason_a);
    (void)zcl_command_reply_add_next(reply, sibling_b, "{}", reason_b);
}

void zcl_native_handle_ops_telemetry_agents_sessions(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ta_render_group(request, reply, "sessions",
                    "ops.telemetry.agents.grants",
                    "see what those grants are permitted to move",
                    "ops.telemetry.agents.activity",
                    "see what has been done under them");
}

void zcl_native_handle_ops_telemetry_agents_grants(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ta_render_group(request, reply, "grants",
                    "ops.telemetry.agents.sessions",
                    "see how many grants exist and how many are still usable",
                    "ops.telemetry.agents.activity",
                    "see how much of those caps has been consumed");
}

void zcl_native_handle_ops_telemetry_agents_activity(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ta_render_group(request, reply, "activity",
                    "ops.telemetry.agents.grants",
                    "see the caps this spend is being measured against",
                    "ops.telemetry.agents.sessions",
                    "see the grant population the spend came from");
}
