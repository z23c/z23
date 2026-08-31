/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Project exact C23, command-registry, and proof-route facts as bounded typed relations. */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "base/hex.h"
#include "codeindex/codeindex.h"
#include "config/command_catalog.h"
#include "config/command_handler_index.h"
#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { CODE_RELATION_CAP = 24, CODE_RELATION_COMMAND_CAP = 8 };

static void relation_push_line(struct json_value *array, const char *text)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, text);
    (void)json_push_back(array, &item);
    json_free(&item);
}

static void relation_push(struct json_value *relations, int *count,
                          bool *truncated, const char *predicate,
                          const char *subject_type, const char *subject,
                          const char *object_type, const char *object,
                          const char *evidence)
{
    if (*count >= CODE_RELATION_CAP) {
        *truncated = true;
        return;
    }
    struct json_value relation;
    json_init(&relation);
    json_set_object(&relation);
    (void)json_push_kv_str(&relation, "predicate", predicate);
    (void)json_push_kv_str(&relation, "subject_type", subject_type);
    if (strcmp(subject_type, "c23.declaration") == 0)
        (void)json_push_kv_str(&relation, "subject_ref", "subject");
    else
        (void)json_push_kv_str(&relation, "subject", subject);
    (void)json_push_kv_str(&relation, "object_type", object_type);
    (void)json_push_kv_str(&relation, "object", object);
    (void)json_push_kv_str(&relation, "polarity", "positive");
    const bool registry_basis = strstr(evidence, "command_registry") ||
                                strcmp(evidence, "exact_def_handler_name") == 0;
    const bool impact_basis = strstr(evidence, "shared_rule") != NULL;
    const char *evidence_code = registry_basis
        ? (strcmp(evidence, "exact_def_handler_name") == 0
            ? "handler_index" : "catalog_row")
        : impact_basis ? "impact_route"
        : strcmp(evidence, "exact_index_kind") == 0 ? "index_kind"
        : strcmp(evidence, "exact_index_location") == 0 ? "index_location"
        : "index_group";
    (void)json_push_kv_str(&relation, "evidence", evidence_code);
    const char *basis = registry_basis ? "registry"
                        : impact_basis ? "impact" : "source";
    (void)json_push_kv_str(&relation, "basis_context", basis);
    (void)json_push_back(relations, &relation);
    json_free(&relation);
    (*count)++;
}

static const char *relation_c23_type(char kind)
{
    switch (kind) {
    case 'T': case 't': return "c23.function";
    case 'S': return "c23.tag";
    case 'Y': return "c23.typedef";
    case 'E': return "c23.enum_tag";
    case 'M': return "c23.macro";
    case 'D': return "c23.object_or_declaration";
    default: return "c23.indexed_declaration";
    }
}

static void relation_command_lanes(struct json_value *relations, int *count,
                                   bool *truncated, const char *command,
                                   uint32_t lanes)
{
    struct lane_name { uint32_t bit; const char *name; };
    static const struct lane_name names[] = {
        { ZCL_COMMAND_LANE_LOCAL, "local" },
        { ZCL_COMMAND_LANE_DEV, "dev" },
        { ZCL_COMMAND_LANE_CANONICAL, "canonical" },
        { ZCL_COMMAND_LANE_SOAK, "soak" },
        { ZCL_COMMAND_LANE_OFFLINE_COPY, "offline-copy" },
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if ((lanes & names[i].bit) != 0)
            relation_push(relations, count, truncated, "declares_allowed_lane",
                          "command", command, "execution_lane", names[i].name,
                          "exact_command_registry_row");
}

static void relation_command_transports(struct json_value *relations,
                                        int *count, bool *truncated,
                                        const char *command,
                                        uint32_t transports)
{
    if ((transports & ZCL_COMMAND_TRANSPORT_NATIVE) != 0)
        relation_push(relations, count, truncated, "declares_transport",
                      "command", command, "transport", "native",
                      "exact_command_registry_row");
    if ((transports & ZCL_COMMAND_TRANSPORT_REST) != 0)
        relation_push(relations, count, truncated, "declares_transport",
                      "command", command, "transport", "rest",
                      "exact_command_registry_row");
    if ((transports & ZCL_COMMAND_TRANSPORT_RPC) != 0)
        relation_push(relations, count, truncated, "declares_transport",
                      "command", command, "transport", "rpc",
                      "exact_command_registry_row");
}

void zcl_native_handle_code_relations(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *query = json_get_str(json_get(request->input, "name"));
    if (!query || !query[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME",
                               "normalize", false, false,
                               "code provenance relations requires a symbol name",
                               "");
        return;
    }

    const char *root = ".";
    if (request->context && request->context->source_root &&
        request->context->source_root[0])
        root = request->context->source_root;
    else {
        const char *environment_root = getenv("ZCL_DEV_SOURCE_ROOT");
        if (environment_root && environment_root[0]) root = environment_root;
    }
    struct codeindex *index = codeindex_open_source_view(root);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open or rebuild the source index", root);
        return;
    }

    struct ci_symbol symbol;
    bool found = false;
    const bool by_id = strchr(query, ':') != NULL;
    bool lookup_ok = by_id
        ? codeindex_symbol_by_id(index, query, &symbol, &found)
        : codeindex_symbol(index, query, &symbol, &found);
    if (!lookup_ok) {
        codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "SYMBOL_LOOKUP",
                               "query", false, false,
                               "source index could not evaluate the symbol lookup",
                               query);
        return;
    }
    if (!found) {
        (void)json_push_kv_str(&reply->data, "query", query);
        (void)json_push_kv_bool(&reply->data, "found", false);
        (void)json_push_kv_str(&reply->data, "status", "UNKNOWN");
        (void)json_push_kv_bool(&reply->data, "complete", false);
        struct json_value missing;
        json_init(&missing); json_set_array(&missing);
        relation_push_line(&missing, "closed_world_declaration_coverage");
        relation_push_line(&missing, "generated_and_platform_configuration_coverage");
        (void)json_push_kv(&reply->data, "missing_dimensions", &missing);
        json_free(&missing);
        (void)json_push_kv_str(&reply->data, "summary",
                               "no declaration resolved; scanner absence is not closed-world proof");
        codeindex_close(index);
        return;
    }

    char symbol_id[400] = "";
    (void)codeindex_symbol_record_id(&symbol, symbol_id, sizeof(symbol_id));
    uint8_t source_root[32];
    char source_hex[65] = "";
    if (!codeindex_source_root_sha3(index, source_root)) {
        codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "SOURCE_ROOT",
                               "derive", false, false,
                               "source relation context has no exact root", root);
        return;
    }
    zcl_hex_encode(source_root, sizeof(source_root), source_hex);

    const struct zcl_command_registry *registry =
        request->context && request->context->registry
            ? request->context->registry : zcl_command_catalog();
    char registry_digest[72];
    zcl_command_registry_digest(registry, registry_digest);

    struct json_value relations;
    json_init(&relations); json_set_array(&relations);
    int relation_count = 0;
    bool truncated = false;
    relation_push(&relations, &relation_count, &truncated, "isa",
                  "c23.declaration", symbol_id, "ontology_type",
                  relation_c23_type(symbol.kind), "exact_index_kind");
    char span[320];
    if (symbol.def_path[0]) {
        (void)snprintf(span, sizeof(span), "%s:%d", symbol.def_path,
                       symbol.def_line);
        relation_push(&relations, &relation_count, &truncated,
                      "has_definition_occurrence", "c23.declaration", symbol_id,
                      "source_span", span, "exact_index_location");
    }
    if (symbol.decl_path[0]) {
        (void)snprintf(span, sizeof(span), "%s:%d", symbol.decl_path,
                       symbol.decl_line);
        relation_push(&relations, &relation_count, &truncated,
                      "has_declaration_occurrence", "c23.declaration", symbol_id,
                      "source_span", span, "exact_index_location");
    }
    if (symbol.group[0])
        relation_push(&relations, &relation_count, &truncated,
                      "member_of_source_group", "c23.declaration", symbol_id,
                      "source_group", symbol.group, "exact_index_group");

    const struct zcl_command_handler_index *handlers =
        zcl_command_handler_index();
    int command_count = 0;
    int command_total = 0;
    const bool external_function = symbol.kind == 'T' &&
        strncmp(symbol_id, "fn:external:", 12) == 0;
    for (size_t i = 0; external_function && handlers &&
                       i < handlers->count; i++) {
        if (strcmp(handlers->entries[i].handler_name, symbol.name) != 0)
            continue;
        command_total++;
        if (command_count >= CODE_RELATION_COMMAND_CAP) {
            truncated = true;
            continue;
        }
        const char *command = handlers->entries[i].path;
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(registry, command, NULL);
        if (!spec) continue;
        command_count++;
        relation_push(&relations, &relation_count, &truncated,
                      "declared_handler_for_command", "c23.declaration", symbol_id,
                      "command", command, "exact_def_handler_name");
        relation_push(&relations, &relation_count, &truncated,
                      "declares_scope", "command", command, "command_scope",
                      zcl_command_scope_name(spec->scope),
                      "exact_command_registry_row");
        relation_push(&relations, &relation_count, &truncated,
                      "declares_authority", "command", command,
                      "authority", zcl_command_authority_name(spec->authority),
                      "exact_command_registry_row");
        relation_push(&relations, &relation_count, &truncated,
                      "declares_effect", "command", command, "effect",
                      zcl_command_effect_name(spec->effect),
                      "exact_command_registry_row");
        relation_command_lanes(&relations, &relation_count, &truncated,
                               command, spec->allowed_lanes);
        relation_command_transports(&relations, &relation_count, &truncated,
                                    command, spec->transports);
    }

    const char *path = symbol.def_path[0] ? symbol.def_path : symbol.decl_path;
    struct agent_impact_acc proof = {0};
    bool consensus_risk = false;
    const char *route = zcl_native_code_route_for_path(
        path, &proof, &consensus_risk);
    if (proof.groups_len == 0)
        relation_push(&relations, &relation_count, &truncated,
                      "routes_path_change_to_test_group", "c23.declaration", symbol_id,
                      "test_group", route, "exact_shared_rule_path_floor");
    for (size_t i = 0; i < proof.groups_len; i++)
        relation_push(&relations, &relation_count, &truncated,
                      "routes_path_change_to_test_group", "c23.declaration", symbol_id,
                      "test_group", proof.groups[i],
                      "exact_shared_rule_path_floor");

    (void)json_push_kv_bool(&reply->data, "found", true);
    (void)json_push_kv_str(&reply->data, "query", query);
    (void)json_push_kv_str(&reply->data, "resolution",
                           by_id ? "exact_stable_id" : "legacy_name_primary");
    (void)json_push_kv_str(&reply->data, "subject", symbol_id);
    (void)json_push_kv_str(&reply->data, "codeindex_source_root_sha3",
                           source_hex);
    (void)json_push_kv_str(&reply->data, "source_root_domain",
                           "zcl.codeindex.source_root.v4");
    (void)json_push_kv_str(&reply->data, "source_scope",
                           "codeindex_governed_source_path_enumeration");
    char relation_json[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t relation_bytes = json_write(&relations, relation_json,
                                       sizeof(relation_json));
    if (relation_bytes == 0 || relation_bytes >= sizeof(relation_json)) {
        json_free(&relations);
        codeindex_close(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RELATION_BUDGET",
                               "render", false, false,
                               "bounded relation set did not fit its hash buffer",
                               query);
        return;
    }
    struct sha3_256_ctx relation_sha;
    uint8_t relation_root[32];
    char relation_hex[65];
    static const char relation_domain[] = "zcl.code_relations.emitted.v1";
    sha3_256_init(&relation_sha);
    sha3_256_write(&relation_sha, (const uint8_t *)relation_domain,
                   sizeof(relation_domain));
    sha3_256_write(&relation_sha, source_root, sizeof(source_root));
    sha3_256_write(&relation_sha, (const uint8_t *)symbol_id,
                   strlen(symbol_id) + 1);
    sha3_256_write(&relation_sha, (const uint8_t *)registry_digest,
                   strlen(registry_digest) + 1);
    sha3_256_write(&relation_sha, (const uint8_t *)relation_json,
                   relation_bytes);
    sha3_256_finalize(&relation_sha, relation_root);
    zcl_hex_encode(relation_root, sizeof(relation_root), relation_hex);

    struct sha3_256_ctx route_sha;
    uint8_t route_root[32];
    char route_hex[65];
    static const char route_domain[] = "zcl.code_impact_route_projection.v1";
    sha3_256_init(&route_sha);
    sha3_256_write(&route_sha, (const uint8_t *)route_domain,
                   sizeof(route_domain));
    sha3_256_write(&route_sha, source_root, sizeof(source_root));
    sha3_256_write(&route_sha, (const uint8_t *)path, strlen(path) + 1);
    sha3_256_write(&route_sha, (const uint8_t *)route, strlen(route) + 1);
    for (size_t i = 0; i < proof.groups_len; i++)
        sha3_256_write(&route_sha, (const uint8_t *)proof.groups[i],
                       strlen(proof.groups[i]) + 1);
    sha3_256_finalize(&route_sha, route_root);
    zcl_hex_encode(route_root, sizeof(route_root), route_hex);

    (void)json_push_kv_str(&reply->data, "registry_digest", registry_digest);
    (void)json_push_kv_str(&reply->data, "registry_digest_coverage",
                           "catalog_identity_subset; relation_set_root binds emitted registry fields");
    (void)json_push_kv_str(&reply->data, "relation_set_root", relation_hex);
    struct json_value contexts, source_context, registry_context, route_context;
    json_init(&contexts); json_set_object(&contexts);
    json_init(&source_context); json_set_object(&source_context);
    (void)json_push_kv_str(&source_context, "identity", source_hex);
    (void)json_push_kv_str(&source_context, "domain",
                           "zcl.codeindex.source_root.v4");
    (void)json_push_kv_str(&source_context, "coverage",
                           "codeindex_governed_source_path_enumeration");
    (void)json_push_kv(&contexts, "source", &source_context);
    json_init(&registry_context); json_set_object(&registry_context);
    (void)json_push_kv_str(&registry_context, "catalog_digest",
                           registry_digest);
    (void)json_push_kv_str(&registry_context, "emitted_relation_set_root",
                           relation_hex);
    (void)json_push_kv_bool(&registry_context, "source_generation_join_complete",
                            false);
    (void)json_push_kv(&contexts, "registry", &registry_context);
    json_init(&route_context); json_set_object(&route_context);
    (void)json_push_kv_str(&route_context, "projection_root", route_hex);
    (void)json_push_kv_str(&route_context, "path", path);
    (void)json_push_kv_str(&route_context, "route", route);
    (void)json_push_kv_bool(&route_context, "source_generation_join_complete",
                            false);
    (void)json_push_kv(&contexts, "impact", &route_context);
    (void)json_push_kv(&reply->data, "contexts", &contexts);
    (void)json_push_kv_str(&reply->data, "status", "INCOMPLETE");
    (void)json_push_kv_bool(&reply->data, "complete", false);
    (void)json_push_kv_bool(&reply->data, "observed_positive", true);
    (void)json_push_kv_bool(&reply->data, "observed_negative", false);
    (void)json_push_kv(&reply->data, "relations", &relations);
    (void)json_push_kv_int(&reply->data, "relation_count", relation_count);
    (void)json_push_kv_int(&reply->data, "command_count", command_count);
    (void)json_push_kv_int(&reply->data, "command_total", command_total);
    (void)json_push_kv_bool(&reply->data, "truncated", truncated);
    (void)json_push_kv_str(&reply->data, "truncation_reason",
                           truncated ? (command_total > command_count
                               ? "command_cap" : "relation_cap") : "");
    (void)json_push_kv_str(&reply->data, "proof_state",
                           "REQUIRED_UNOBSERVED");
    (void)json_push_kv_bool(&reply->data, "consensus_risk", consensus_risk);

    struct json_value missing;
    json_init(&missing); json_set_array(&missing);
    relation_push_line(&missing, "runtime_process_observation");
    relation_push_line(&missing, "accepted_receipt_join");
    relation_push_line(&missing, "source_registry_generation_join");
    relation_push_line(&missing, "active_handler_override_join");
    relation_push_line(&missing, "canonical_ontology_manifest_join");
    relation_push_line(&missing, "closed_world_call_target_coverage");
    (void)json_push_kv(&reply->data, "missing_dimensions", &missing);
    (void)json_push_kv_str(&reply->data, "summary",
                           "typed static relations found; runtime and accepted proof remain unobserved");

    json_free(&relations);
    json_free(&missing);
    json_free(&contexts);
    json_free(&source_context);
    json_free(&registry_context);
    json_free(&route_context);
    codeindex_close(index);
}
