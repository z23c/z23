/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_controller.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const struct agent_contract g_agent_contracts[] = {
#define AGENT_CONTRACT(method, capability, schema, native, rest,              \
                       api_cli_field, ops_surface, ops_rank, ops_name,        \
                       ops_purpose, purpose)                                  \
    { method, capability, schema, native, rest, api_cli_field, ops_surface,   \
      ops_rank, ops_name, ops_purpose, purpose },
#include "controllers/agent_contracts.def"
#undef AGENT_CONTRACT
};

static const size_t g_agent_contract_count =
    sizeof(g_agent_contracts) / sizeof(g_agent_contracts[0]);

struct agent_contract_command_surface {
    const char *surface;
    int rank;
    const char *name;
    const char *method;
    const char *catalog_path;
    const char *native_override;
    const char *purpose_override;
};

struct agent_contract_work_surface {
    const char *surface;
    int rank;
    const char *name;
    const char *why;
    const char *first_slice;
    const char *proof;
};

struct agent_contract_field_surface {
    const char *surface;
    int rank;
    const char *native_key;
    const char *method;
};

#define CONTRACT_COMMAND(surface, rank, name, method, purpose)               \
    { surface, rank, name, method, "", "", purpose }
#define DIRECT_COMMAND(surface, rank, name, native, purpose)                 \
    { surface, rank, name, "", "", native, purpose }
#define CATALOG_COMMAND(surface, rank, name, path, purpose)                  \
    { surface, rank, name, "", path, "", purpose }

static const struct agent_contract_command_surface g_agent_command_surfaces[] = {
    DIRECT_COMMAND("agentmap.commands.core", 1, "compact_status",
      "z23 status",
      "canonical terse zcl.core_status_brief.v1 first check"),
    CONTRACT_COMMAND("agentmap.commands.core", 2, "map", "agentmap",
      "where code, docs, and tests live"),
    CONTRACT_COMMAND("agentmap.commands.core", 3, "impact", "agentimpact",
      "changed files to recommended tests and risk flags"),
    CONTRACT_COMMAND("agentmap.commands.core", 4, "contracts", "agentcontracts",
      "versioned schemas and transport contract list"),
    CONTRACT_COMMAND("agentmap.commands.core", 5, "build", "agentbuild",
      "incremental/cache/reproducible build contract"),
    CONTRACT_COMMAND("agentmap.commands.core", 6, "dev_status",
      "agentdevstatus", "read-only worker-lane dev status and next safe action"),
    CONTRACT_COMMAND("agentmap.commands.core", 7, "anchor_status", "anchorstatus",
      "offline anchor-mint progress and next action"),
    CONTRACT_COMMAND("agentmap.commands.core", 8, "proof_bundle", "proofbundle",
      "one read-only JSON artifact for status, MVP, anchor, lanes, and dev lane"),
    CONTRACT_COMMAND("agentmap.commands.core", 9, "interface", "agentinterface",
      "preferred AI/operator transport and JSON rules"),
    CONTRACT_COMMAND("agentmap.commands.core", 10, "lanes", "agentlanes",
      "canonical/soak/dev topology and restart/deploy rules"),
    CONTRACT_COMMAND("agentmap.commands.core", 11, "liveness", "agentliveness",
      "lane/service/supervisor/background-quality liveness"),
    CONTRACT_COMMAND("agentmap.commands.core", 12, "deploy_guard", "agentdeployguard",
      "C-native deploy/restart allow-refuse decision"),
    DIRECT_COMMAND("agentmap.commands.core", 13, "full_compatibility_status",
      "z23 agent",
      "full zcl.public_status.v3 compatibility view"),
    DIRECT_COMMAND("agentmap.commands.core", 14, "background_quality",
      "make quality-linger-status",
      "latest background fuzz/coverage lane verdicts"),

    CONTRACT_COMMAND("agentmap.commands.drilldown", 1, "health", "healthcheck",
      "strict health drill-down"),
    CONTRACT_COMMAND("agentmap.commands.drilldown", 2, "logs", "getnodelog",
      "bounded server-side log search"),
    CONTRACT_COMMAND("agentmap.commands.drilldown", 3, "timeline", "timeline",
      "category-filtered event timeline with bounded filters"),
    CONTRACT_COMMAND("agentmap.commands.drilldown", 4, "state", "dumpstate",
      "generic subsystem diagnostics"),
    CONTRACT_COMMAND("agentmap.commands.drilldown", 5, "state_catalog", "statecatalog",
      "diagnostics subsystem catalog"),
    CONTRACT_COMMAND("agentmap.commands.drilldown", 6, "peer_incidents",
      "peerincidents", "bounded peer reconnect and duplicate-host incidents"),

    CATALOG_COMMAND("agentinterface.visual_instruments", 1, "qr",
      "app.qr.show",
      "show one bounded agent-supplied payload; copy or close returns no software authority"),
    CATALOG_COMMAND("agentinterface.visual_instruments", 2, "node_status",
      "app.presentation.status",
      "show target-node-owned height, gap, peers, onion, backup, and package-worker facts"),
    CATALOG_COMMAND("agentinterface.visual_instruments", 3, "code_change",
      "app.presentation.code-change",
      "show exact local ZVCS source facts while visibly separating agent behavior summaries"),
    CATALOG_COMMAND("agentinterface.visual_instruments", 4,
      "reproduction_progress",
      "app.presentation.reproduction",
      "show target-node proof-ledger progress for one exact action in one replaceable window"),
    CATALOG_COMMAND("agentinterface.visual_instruments", 5,
      "publication_confirmation",
      "app.presentation.publication-confirm",
      "ask for one exact human decision; the command performs no publication action"),
    CATALOG_COMMAND("agentinterface.visual_instruments", 6, "corpus_status",
      "app.presentation.corpus",
      "show canonical signed-checkpoint C23 corpus facts without starting another census"),
    CATALOG_COMMAND("agentinterface.visual_instruments", 7,
      "publication_status",
      "app.presentation.publication-status",
      "show local commit, pointer, provider, peer discovery, and exact peer fetch as separate evidence stages"),
    CATALOG_COMMAND("agentinterface.visual_instruments", 8,
      "bounded_display",
      "app.presentation.show",
      "show agent-supplied tables, charts, timelines, graphs, choices, or forms; use typed instruments for node-owned facts and confirmations"),
    CATALOG_COMMAND("agentinterface.visual_instruments", 9,
      "release_confirmation",
      "app.presentation.release-confirm",
      "ask for one exact proven-candidate decision after canonical proof; the visual command cannot accept or publish"),

    DIRECT_COMMAND("agentmap.telemetry", 1, "compact_status",
      "z23 status",
      "stable terse first-call status, blocker, and next action"),
    DIRECT_COMMAND("agentmap.telemetry", 2, "full_status",
      "z23 healthcheck",
      "wide health packet with peers, sync, chain, validation, and memory"),
    CONTRACT_COMMAND("agentmap.telemetry", 3, "subsystem_state", "dumpstate",
      "semantic subsystem internals through diagnostics registry"),
    CONTRACT_COMMAND("agentmap.telemetry", 4, "subsystem_catalog", "statecatalog",
      "machine catalog of diagnostics registry subsystems"),
    CONTRACT_COMMAND("agentmap.telemetry", 5, "node_log", "getnodelog",
      "server-side regex tail over node.log history"),
    CONTRACT_COMMAND("agentmap.telemetry", 6, "timeline", "timeline",
      "versioned category-filtered event timeline with bounded filters"),
    CONTRACT_COMMAND("agentmap.telemetry", 7, "peer_incidents",
      "peerincidents", "bounded peer incident and bootstrap-usefulness view"),
    CONTRACT_COMMAND("agentmap.telemetry", 8, "anchor_status", "anchorstatus",
      "read-only progress.kv status for the sovereign anchor producer"),
    CONTRACT_COMMAND("agentmap.telemetry", 9, "proof_bundle", "proofbundle",
      "capture the current operator evidence state as one JSON artifact"),
    CONTRACT_COMMAND("agentmap.telemetry", 10, "node_db", "dbquery",
      "SELECT-only node.db inspection with limits"),
    CONTRACT_COMMAND("agentmap.telemetry", 11, "events", "eventlog",
      "recent structured node events"),
    DIRECT_COMMAND("agentmap.telemetry", 12, "quality_lanes",
      "make quality-linger-status",
      "background tests/fuzz/coverage verdicts"),
};
#undef DIRECT_COMMAND
#undef CATALOG_COMMAND
#undef CONTRACT_COMMAND

static const size_t g_agent_command_surface_count =
    sizeof(g_agent_command_surfaces) / sizeof(g_agent_command_surfaces[0]);

#define FIELD_BINDING(surface, rank, native_key, method)                     \
    { surface, rank, native_key, method }

static const struct agent_contract_field_surface g_agent_field_surfaces[] = {
    FIELD_BINDING("agentops.first_call", 1, "native_command", "agentops"),
    FIELD_BINDING("agentops.first_call", 2, "live_status_command",
                  "agent"),
    FIELD_BINDING("agentops.first_call", 3, "liveness_command",
                  "agentliveness"),
    FIELD_BINDING("agentops.first_call", 4, "diagnose_command",
                  "agentdiagnose"),
    FIELD_BINDING("agentops.first_call", 5, "diagnostics_catalog_command",
                  "statecatalog"),
    FIELD_BINDING("agentops.first_call", 6, "diagnostics_drilldown_command",
                  "dumpstate"),
    FIELD_BINDING("agentops.first_call", 7, "timeline_command",
                  "timeline"),
    FIELD_BINDING("agentops.first_call", 8, "anchor_status_command",
                  "anchorstatus"),
    FIELD_BINDING("agentops.first_call", 9, "proof_bundle_command",
                  "proofbundle"),
    FIELD_BINDING("agentops.first_call", 10, "peer_incidents_command",
                  "peerincidents"),
    FIELD_BINDING("agentops.first_call", 11, "service_catalog_command",
                  "servicecatalog"),
    FIELD_BINDING("agentops.first_call", 12, "service_operations_command",
                  "serviceoperations"),
    FIELD_BINDING("agentops.first_call", 13, "dev_status_command",
                  "agentdevstatus"),
    FIELD_BINDING("agentops.first_call", 14, "deploy_guard_command",
                  "agentdeployguard"),
};

#undef FIELD_BINDING

static const size_t g_agent_field_surface_count =
    sizeof(g_agent_field_surfaces) / sizeof(g_agent_field_surfaces[0]);

static const struct agent_contract_work_surface g_agent_work_surfaces[] = {
    { "agentops.api_gaps", 1, "runtime_identity_everywhere",
      "Agents must know whether a payload came from source HEAD, dev, soak, or canonical.",
      "add build/lane identity to every first-call compact response",
      "syncdiag_rpc + native commands + api" },
    { "agentops.api_gaps", 2, "state_catalog_schema",
      "The first catalog now exists; next it should be kept rich enough for automated routing.",
      "extend catalog metadata as new dumpers need cost, freshness, key, and owner hints",
      "statecatalog RPC + native catalog tests" },
    { "agentops.api_gaps", 3, "timeline_query",
      "Agents still stitch together logs, SQL, events, and condition detail to answer what happened.",
      "ship and extend zcl.timeline.v2 before adding more bespoke log readers",
      "event + native commands + syncdiag_rpc" },

    { "agentops.workflow", 1, "first_call",
      "Agents should start from the compact operator contract instead of browsing the full API catalog.",
      "z23 status; then z23 agentops",
      "zcl.agent_ops.v2 no_jq_required=true" },
    { "agentops.workflow", 2, "decide_lane_and_safety",
      "The same source tree can talk to canonical, soak, dev, and fixture lanes; restarts and deploys need lane context first.",
      "read current_runtime_lane, runtime_build, runtime_availability, dev_status_command, and deploy_guard_command",
      "agentops.first_call fields from agent_contracts.def" },
    { "agentops.workflow", 3, "change_with_impact",
      "Changed files should map to focused tests through the shared impact rules instead of ad hoc memory.",
      "z23 agentimpact <files...>",
      "agent_impact_rules.def shared_rule_hits" },
    { "agentops.workflow", 4, "verify_fast_then_deep",
      "The inner loop proves syntax, lint, and targeted behavior; pre-push only admits the exact sealed receipt.",
      "make agent-loop; make t-fast ONLY=<group>; build/bin/z23-dev dev proof status",
      "agentbuild recommended_loop + receipt-only pre-push" },
    { "agentops.workflow", 5, "drill_down_only_when_needed",
      "Most one-off diagnostics should use primitive state/log/SQL/timeline tools before adding bespoke API routes.",
      "z23 dumpstate, getnodelog, dbquery, timeline, and statecatalog",
      "diagnostics registry + zcl.timeline.v2" },

    { "agentops.top_next_work", 1,
      "finish_self_verified_utxo_anchor_rebuild",
      "It replaces the borrowed snapshot seed with a UTXO anchor rebuilt from zclassic23's own verified block history.",
      "run anchorstatus on the producer, fix any named blocker, then copy-prove -refold-from-anchor artifact and cutover gates",
      "copy fixture, refold tests, parity checks, live H* climb" },
    { "agentops.top_next_work", 2, "harden_peer_bootstrap_lifecycle",
      "Tip-following depends on failing over slow peers, avoiding duplicate peer rows, and proving zclassic23 peers can bootstrap other nodes.",
      "promote peer lifecycle incidents, downloader failover, and bootstrapstatus into one operator proof",
      "download + peer_lifecycle + syncdiag_rpc + bootstrap harness" },
    { "agentops.top_next_work", 3, "promote_mvp_operator_proofs",
      "MRS is 4/8; cold-start sync, live store flow, 168h soak, and exact parity still need full run-pass evidence.",
      "wire the remaining full proofs into milestone and background quality verdicts",
      "mvp-verify + soak-evidence + parity service" },
    { "agentops.top_next_work", 4, "extend_semantic_timeline_durability",
      "The event-ring timeline is semantic now; longer root-cause windows need durable event_log/node.log references.",
      "extend zcl.timeline.v2 toward durable event_log/node.log references",
      "event + native commands + syncdiag_rpc" },
    { "agentops.top_next_work", 5, "shrink_boot_refold_supervised_units",
      "The largest code-health risk is still oversized boot/refold orchestration that future agents must understand before changing liveness.",
      "split one behavior-preserving boot/refold responsibility behind existing supervisor contracts",
      "make lint + boot smoke + refold tests + live H* climb" },
};

static const size_t g_agent_work_surface_count =
    sizeof(g_agent_work_surfaces) / sizeof(g_agent_work_surfaces[0]);

static void agent_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s ? s : "");
    json_push_back(arr, &v);
    json_free(&v);
}

static const char *agent_native_usage_tail(const char *native_command)
{
    const char *prefix = "zclassic23";
    size_t prefix_len = strlen(prefix);
    if (!native_command)
        return "";
    if (strncmp(native_command, prefix, prefix_len) != 0)
        return native_command;
    if (native_command[prefix_len] != '\0' &&
        native_command[prefix_len] != ' ')
        return native_command;
    const char *tail = native_command + prefix_len;
    while (*tail == ' ')
        tail++;
    return tail;
}

void agent_print_native_usage(FILE *out, const char *prog)
{
    FILE *dst = out ? out : stdout;
    const char *program = prog && prog[0] ? prog : "zclassic23";

    for (size_t i = 0; i < g_agent_contract_count; i++) {
        const struct agent_contract *c = &g_agent_contracts[i];
        if (!c->native_command || !c->native_command[0])
            continue;
        const char *tail = agent_native_usage_tail(c->native_command);
        const char *summary = c->ops_purpose && c->ops_purpose[0]
            ? c->ops_purpose : c->purpose;
        fprintf(dst, "  %s %-38s %s\n", program, tail,
                summary ? summary : "");
    }
}

static bool agent_contract_surface_has(const char *surfaces,
                                       const char *surface)
{
    if (!surfaces || !surfaces[0] || !surface || !surface[0])
        return false;

    size_t want_len = strlen(surface);
    const char *p = surfaces;
    while (*p) {
        while (*p == ',' || *p == ' ')
            p++;
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        while (len > 0 && p[len - 1] == ' ')
            len--;
        if (len == want_len && strncmp(p, surface, want_len) == 0)
            return true;
        if (!end)
            break;
        p = end + 1;
    }
    return false;
}

size_t agent_contract_count(void)
{
    return g_agent_contract_count;
}

const struct agent_contract *agent_contract_at(size_t index)
{
    if (index >= g_agent_contract_count)
        return NULL;
    return &g_agent_contracts[index];
}

const struct agent_contract *agent_contract_lookup(const char *method)
{
    if (!method || !method[0])
        return NULL;
    for (size_t i = 0; i < g_agent_contract_count; i++) {
        if (strcmp(g_agent_contracts[i].method, method) == 0)
            return &g_agent_contracts[i];
    }
    return NULL;
}

const char *agent_contract_probe_params_json(const char *method)
{
    if (!method || !method[0])
        return "[]";
    if (strcmp(method, "dbquery") == 0)
        return "[\"SELECT name FROM sqlite_master WHERE type = 'table'\",1]";
    if (strcmp(method, "eventlog") == 0)
        return "[1]";
    return "[]";
}

bool agent_push_contract_json(struct json_value *arr,
                              const struct agent_contract *contract)
{
    if (!arr || !contract)
        return false;

    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "method", contract->method);
    json_push_kv_str(&obj, "capability", contract->capability);
    json_push_kv_str(&obj, "schema", contract->schema);
    json_push_kv_str(&obj, "native", contract->native_command);
    json_push_kv_str(&obj, "rest", contract->rest_route);
    json_push_kv_str(&obj, "api_cli_field", contract->api_cli_field);
    json_push_kv_str(&obj, "ops_surface", contract->ops_surface);
    json_push_kv_int(&obj, "ops_rank", contract->ops_rank);
    json_push_kv_str(&obj, "ops_name", contract->ops_name);
    json_push_kv_str(&obj, "ops_purpose", contract->ops_purpose);
    json_push_kv_str(&obj, "probe_params_json",
                     agent_contract_probe_params_json(contract->method));
    json_push_kv_str(&obj, "purpose", contract->purpose);
    json_push_back(arr, &obj);
    json_free(&obj);
    return true;
}

void agent_push_contracts_json(struct json_value *arr)
{
    if (!arr)
        return;
    for (size_t i = 0; i < g_agent_contract_count; i++)
        agent_push_contract_json(arr, &g_agent_contracts[i]);
}

void agent_push_contract_summary_json(struct json_value *out,
                                      const char *key)
{
    if (!out || !key || !key[0])
        return;

    size_t native_count = 0;
    size_t rest_count = 0;
    for (size_t i = 0; i < g_agent_contract_count; i++) {
        const struct agent_contract *c = &g_agent_contracts[i];
        if (c->native_command && c->native_command[0])
            native_count++;
        if (c->rest_route && c->rest_route[0])
            rest_count++;
    }

    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_int(&obj, "contract_count",
                     (int64_t)g_agent_contract_count);
    json_push_kv_int(&obj, "native_declared_count",
                     (int64_t)native_count);
    json_push_kv_int(&obj, "rest_declared_count", (int64_t)rest_count);
    json_push_kv_int(&obj, "command_surface_count",
                     (int64_t)g_agent_command_surface_count);
    json_push_kv_int(&obj, "field_surface_count",
                     (int64_t)g_agent_field_surface_count);
    json_push_kv_int(&obj, "work_surface_count",
                     (int64_t)g_agent_work_surface_count);
    json_push_kv_int(&obj, "review_surface_count",
                     (int64_t)agent_contract_review_surface_total_count());
    json_push_kv_int(&obj, "schema_surface_count",
                     (int64_t)agent_contract_schema_surface_count());
    json_push_kv_str(&obj, "registry_source",
                     "agent_contracts.def + agent_contract_registry.c");
    json_push_kv_str(&obj, "review_registry_source",
                     "agent_contract_review_registry.c");
    json_push_kv_str(&obj, "schema_registry_source",
                     "agent_contract_schema_registry.c");
    json_push_kv(out, key, &obj);
    json_free(&obj);
}

void agent_push_contract_ops_surface_json(struct json_value *arr,
                                          const char *surface)
{
    if (!arr || !surface || !surface[0])
        return;

    int max_rank = 0;
    for (size_t i = 0; i < g_agent_contract_count; i++) {
        const struct agent_contract *c = &g_agent_contracts[i];
        if (agent_contract_surface_has(c->ops_surface, surface) &&
            c->ops_rank > max_rank)
            max_rank = c->ops_rank;
    }

    for (int rank = 1; rank <= max_rank; rank++) {
        for (size_t i = 0; i < g_agent_contract_count; i++) {
            const struct agent_contract *c = &g_agent_contracts[i];
            if (c->ops_rank != rank ||
                !agent_contract_surface_has(c->ops_surface, surface))
                continue;
            agent_push_contract_command_json(arr, c->ops_name, c->method,
                                             c->ops_purpose);
        }
    }
}

size_t agent_contract_command_surface_count(const char *surface)
{
    if (!surface || !surface[0])
        return 0;
    size_t n = 0;
    for (size_t i = 0; i < g_agent_command_surface_count; i++) {
        const struct agent_contract_command_surface *e =
            &g_agent_command_surfaces[i];
        if (e->surface && strcmp(e->surface, surface) == 0)
            n++;
    }
    return n;
}

static bool agent_push_command_surface_entry_json(
    struct json_value *arr, const struct agent_contract_command_surface *e)
{
    if (!arr || !e)
        return false;
    if (e->method && e->method[0]) {
        return agent_push_contract_command_json(arr, e->name, e->method,
                                                e->purpose_override);
    }

    if (e->catalog_path && e->catalog_path[0]) {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), e->catalog_path, NULL);
        if (!spec || spec->availability != ZCL_COMMAND_READY ||
            !spec->example || !spec->example[0])
            return false;

        char discover[128];
        int discover_len = snprintf(discover, sizeof(discover),
                                    "z23 discover schema %s",
                                    spec->path);
        if (discover_len <= 0 || (size_t)discover_len >= sizeof(discover))
            return false;

        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        json_push_kv_str(&obj, "name", e->name);
        json_push_kv_str(&obj, "path", spec->path);
        json_push_kv_str(&obj, "native", spec->example);
        json_push_kv_str(&obj, "input_schema", spec->input_schema);
        json_push_kv_str(&obj, "input_keys", spec->input_keys);
        json_push_kv_str(&obj, "output_schema", spec->output_schema);
        json_push_kv_str(&obj, "discover_input", discover);
        json_push_kv_str(&obj, "purpose", e->purpose_override);
        json_push_back(arr, &obj);
        json_free(&obj);
        return true;
    }

    if (!e->native_override || !e->native_override[0])
        return false;

    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "name", e->name);
    json_push_kv_str(&obj, "native", e->native_override);
    json_push_kv_str(&obj, "purpose", e->purpose_override);
    json_push_back(arr, &obj);
    json_free(&obj);
    return true;
}

size_t agent_push_contract_command_surface_json(struct json_value *arr,
                                                const char *surface)
{
    if (!arr || !surface || !surface[0])
        return 0;

    int max_rank = 0;
    for (size_t i = 0; i < g_agent_command_surface_count; i++) {
        const struct agent_contract_command_surface *e =
            &g_agent_command_surfaces[i];
        if (e->surface && strcmp(e->surface, surface) == 0 &&
            e->rank > max_rank)
            max_rank = e->rank;
    }

    size_t pushed = 0;
    for (int rank = 1; rank <= max_rank; rank++) {
        for (size_t i = 0; i < g_agent_command_surface_count; i++) {
            const struct agent_contract_command_surface *e =
                &g_agent_command_surfaces[i];
            if (e->rank != rank || !e->surface ||
                strcmp(e->surface, surface) != 0)
                continue;
            if (agent_push_command_surface_entry_json(arr, e))
                pushed++;
        }
    }
    return pushed;
}

size_t agent_contract_field_surface_count(const char *surface)
{
    if (!surface || !surface[0])
        return 0;
    size_t n = 0;
    for (size_t i = 0; i < g_agent_field_surface_count; i++) {
        const struct agent_contract_field_surface *e =
            &g_agent_field_surfaces[i];
        if (e->surface && strcmp(e->surface, surface) == 0)
            n++;
    }
    return n;
}

static size_t agent_push_field_surface_entry_json(
    struct json_value *obj, const struct agent_contract_field_surface *e)
{
    if (!obj || !e || !e->method || !e->method[0])
        return 0;

    const struct agent_contract *c = agent_contract_lookup(e->method);
    if (!c)
        return 0;

    size_t pushed = 0;
    if (e->native_key && e->native_key[0] &&
        !json_get(obj, e->native_key) &&
        c->native_command && c->native_command[0]) {
        json_push_kv_str(obj, e->native_key, c->native_command);
        pushed++;
    }
    return pushed;
}

size_t agent_push_contract_field_surface_json(struct json_value *obj,
                                              const char *surface)
{
    if (!obj || !surface || !surface[0])
        return 0;

    int max_rank = 0;
    for (size_t i = 0; i < g_agent_field_surface_count; i++) {
        const struct agent_contract_field_surface *e =
            &g_agent_field_surfaces[i];
        if (e->surface && strcmp(e->surface, surface) == 0 &&
            e->rank > max_rank)
            max_rank = e->rank;
    }

    size_t pushed = 0;
    for (int rank = 1; rank <= max_rank; rank++) {
        for (size_t i = 0; i < g_agent_field_surface_count; i++) {
            const struct agent_contract_field_surface *e =
                &g_agent_field_surfaces[i];
            if (e->rank != rank || !e->surface ||
                strcmp(e->surface, surface) != 0)
                continue;
            pushed += agent_push_field_surface_entry_json(obj, e);
        }
    }
    return pushed;
}

size_t agent_contract_work_surface_count(const char *surface)
{
    if (!surface || !surface[0])
        return 0;
    size_t n = 0;
    for (size_t i = 0; i < g_agent_work_surface_count; i++) {
        const struct agent_contract_work_surface *e =
            &g_agent_work_surfaces[i];
        if (e->surface && strcmp(e->surface, surface) == 0)
            n++;
    }
    return n;
}

static bool agent_push_work_item_json(
    struct json_value *arr, const struct agent_contract_work_surface *item)
{
    if (!arr || !item)
        return false;

    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_int(&obj, "rank", item->rank);
    json_push_kv_str(&obj, "name", item->name);
    json_push_kv_str(&obj, "why", item->why);
    json_push_kv_str(&obj, "first_slice", item->first_slice);
    json_push_kv_str(&obj, "proof", item->proof);
    json_push_back(arr, &obj);
    json_free(&obj);
    return true;
}

size_t agent_push_contract_work_surface_json(struct json_value *arr,
                                             const char *surface)
{
    if (!arr || !surface || !surface[0])
        return 0;

    int max_rank = 0;
    for (size_t i = 0; i < g_agent_work_surface_count; i++) {
        const struct agent_contract_work_surface *e =
            &g_agent_work_surfaces[i];
        if (e->surface && strcmp(e->surface, surface) == 0 &&
            e->rank > max_rank)
            max_rank = e->rank;
    }

    size_t pushed = 0;
    for (int rank = 1; rank <= max_rank; rank++) {
        for (size_t i = 0; i < g_agent_work_surface_count; i++) {
            const struct agent_contract_work_surface *e =
                &g_agent_work_surfaces[i];
            if (e->rank != rank || !e->surface ||
                strcmp(e->surface, surface) != 0)
                continue;
            if (agent_push_work_item_json(arr, e))
                pushed++;
        }
    }
    return pushed;
}

bool agent_push_contract_command_json(struct json_value *arr,
                                      const char *name,
                                      const char *method,
                                      const char *purpose_override)
{
    const struct agent_contract *c = agent_contract_lookup(method);
    if (!arr || !c)
        return false;

    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    const char *command_name = name && name[0] ? name : c->ops_name;
    json_push_kv_str(&obj, "name",
                     command_name && command_name[0]
                         ? command_name : c->capability);
    json_push_kv_str(&obj, "method", c->method);
    json_push_kv_str(&obj, "schema", c->schema);
    json_push_kv_str(&obj, "native", c->native_command);
    const char *command_purpose =
        purpose_override && purpose_override[0]
            ? purpose_override : c->ops_purpose;
    json_push_kv_str(&obj, "purpose",
                     command_purpose && command_purpose[0]
                         ? command_purpose : c->purpose);
    json_push_back(arr, &obj);
    json_free(&obj);
    return true;
}

bool agent_push_contract_native_field_json(struct json_value *obj,
                                           const char *key,
                                           const char *method)
{
    const struct agent_contract *c = agent_contract_lookup(method);
    if (!obj || !key || !c)
        return false;
    return json_push_kv_str(obj, key, c->native_command);
}

size_t agent_push_contract_identity_fields_json(struct json_value *obj,
                                                const char *method)
{
    const struct agent_contract *c = agent_contract_lookup(method);
    if (!obj || !c)
        return 0;

    size_t pushed = 0;
    if (!json_get(obj, "schema") && c->schema && c->schema[0] &&
        json_push_kv_str(obj, "schema", c->schema))
        pushed++;
    if (!json_get(obj, "method") &&
        json_push_kv_str(obj, "method", c->method))
        pushed++;
    if (!json_get(obj, "native_command") && c->native_command &&
        c->native_command[0] &&
        json_push_kv_str(obj, "native_command", c->native_command))
        pushed++;
    if (!json_get(obj, "contract_source") &&
        json_push_kv_str(obj, "contract_source", "agent_contracts.def"))
        pushed++;
    return pushed;
}

bool agent_push_contract_native_command_json(struct json_value *arr,
                                             const char *method)
{
    const struct agent_contract *c = agent_contract_lookup(method);
    if (!arr || !c || !c->native_command || !c->native_command[0])
        return false;
    agent_push_str(arr, c->native_command);
    return true;
}

void agent_push_contract_api_cli_fields_json(struct json_value *obj)
{
    if (!obj)
        return;
    for (size_t i = 0; i < g_agent_contract_count; i++) {
        const struct agent_contract *c = &g_agent_contracts[i];
        if (!c->api_cli_field || !c->api_cli_field[0])
            continue;
        json_push_kv_str(obj, c->api_cli_field, c->native_command);
    }
}
