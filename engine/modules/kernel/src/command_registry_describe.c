/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * discover.help / discover.describe documents, split so each helper stays
 * under cyclomatic 15. Field names and budgets are unchanged. */

#include "kernel/command_registry.h"

#include <string.h>

bool command_registry_push_string_array_csv(struct json_value *object,
                                            const char *key, const char *csv)
{
    struct json_value array;
    json_init(&array);
    json_set_array(&array);
    const char *at = csv;
    while (at && *at) {
        const char *end = strchr(at, ',');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        char token[ZCL_COMMAND_MAX_PATH];
        if (len == 0 || len >= sizeof(token)) {
            json_free(&array);
            return false;
        }
        memcpy(token, at, len);
        token[len] = 0;
        struct json_value item;
        json_init(&item);
        json_set_str(&item, token);
        bool ok = json_push_back(&array, &item);
        json_free(&item);
        if (!ok) {
            json_free(&array);
            return false;
        }
        if (!end)
            break;
        at = end + 1;
    }
    bool ok = json_push_kv(object, key, &array);
    json_free(&array);
    return ok;
}

static bool push_child_summary(struct json_value *children,
                               const struct zcl_command_spec *spec)
{
    struct json_value child;
    json_init(&child);
    json_set_object(&child);
    bool ok = json_push_kv_str(&child, "path", spec->path) &&
              json_push_kv_str(&child, "summary", spec->summary) &&
              json_push_kv_str(&child, "risk",
                               zcl_command_risk_name(spec->risk)) &&
              json_push_kv_str(&child, "latency",
                               zcl_command_latency_name(spec->latency)) &&
              json_push_kv_str(&child, "availability",
                               zcl_command_availability_name(
                                   spec->availability)) &&
              json_push_back(children, &child);
    json_free(&child);
    return ok;
}

static const char *menu_wanted(const char *path)
{
    if (path && path[0] && strcmp(path, "root") != 0)
        return path;
    return "";
}

static bool menu_push_children(struct json_value *children,
                               const struct zcl_command_registry *registry,
                               const char *wanted)
{
    bool ok = true;
    for (size_t i = 0; ok && registry && i < registry->count; i++) {
        const char *parent = registry->commands[i].parent;
        if (strcmp(parent ? parent : "", wanted) == 0)
            ok = push_child_summary(children, &registry->commands[i]);
    }
    return ok;
}

static bool menu_push_next(struct json_value *root, struct json_value *children)
{
    if (children->num_children == 0)
        return true;
    const struct json_value *first = json_at(children, 0);
    const char *next_path = json_get_str(json_get(first, "path"));
    struct json_value next, empty;
    json_init(&next);
    json_init(&empty);
    json_set_object(&next);
    json_set_object(&empty);
    bool ok = json_push_kv_str(&next, "command", "discover.describe") &&
              json_push_kv_str(&empty, "path", next_path) &&
              json_push_kv(&next, "input", &empty) &&
              json_push_kv(root, "next", &next);
    json_free(&empty);
    json_free(&next);
    return ok;
}

static bool menu_header(struct json_value *root, const char *wanted,
                        const struct zcl_command_spec *node,
                        const char *digest)
{
    return json_push_kv_str(root, "schema", "zcl.command_menu.v1") &&
           json_push_kv_str(root, "path", wanted[0] ? wanted : "root") &&
           json_push_kv_str(root, "summary",
                            node ? node->summary
                                 : "Z23 sovereign command interface") &&
           json_push_kv_str(root, "registry_digest", digest);
}

size_t zcl_command_registry_menu_json(
    const struct zcl_command_registry *registry, const char *path, char *out,
    size_t out_size)
{
    const char *wanted = menu_wanted(path);
    const struct zcl_command_spec *node = NULL;
    if (wanted[0]) {
        node = zcl_command_registry_find(registry, wanted, NULL);
        if (!node)
            return 0;
        if (!command_registry_is_branch(node))
            return zcl_command_registry_describe_json(registry, wanted, out,
                                                      out_size);
    }

    char digest[72];
    zcl_command_registry_digest(registry, digest);
    struct json_value root, children;
    json_init(&root);
    json_init(&children);
    json_set_object(&root);
    json_set_array(&children);
    bool ok = menu_header(&root, wanted, node, digest) &&
              menu_push_children(&children, registry, wanted) &&
              json_push_kv(&root, "children", &children) &&
              menu_push_next(&root, &children);
    size_t result =
        ok ? command_registry_write_bounded_json(
                 &root, out, out_size,
                 wanted[0] ? ZCL_COMMAND_BRANCH_BUDGET : ZCL_COMMAND_ROOT_BUDGET)
           : 0;
    json_free(&children);
    json_free(&root);
    return result;
}

static bool describe_push_head(struct json_value *root,
                               const struct zcl_command_spec *spec,
                               const char *digest)
{
    bool ok = json_push_kv_str(root, "schema", "zcl.command_spec.v1") &&
              json_push_kv_str(root, "path", spec->path) &&
              json_push_kv_str(root, "summary", spec->summary) &&
              json_push_kv_str(root, "availability",
                               zcl_command_availability_name(
                                   spec->availability));
    if (spec->semantics && spec->semantics[0])
        ok = ok && json_push_kv_str(root, "semantics", spec->semantics);
    if (spec->availability_reason && spec->availability_reason[0])
        ok = ok && json_push_kv_str(root, "availability_reason",
                                    spec->availability_reason);
    return ok && json_push_kv_str(root, "registry_digest", digest);
}

static bool describe_push_input(struct json_value *root,
                                struct json_value *input,
                                const struct zcl_command_spec *spec)
{
    return json_push_kv_str(input, "id", spec->input_schema) &&
           command_registry_push_string_array_csv(input, "allowed_keys",
                                                  spec->input_keys) &&
           command_registry_push_string_array_csv(input, "positional_keys",
                                                  spec->positional_keys) &&
           json_push_kv(root, "input_schema", input) &&
           json_push_kv_str(root, "output_schema", spec->output_schema);
}

static bool describe_push_policy_names(struct json_value *policy,
                                       const struct zcl_command_spec *spec)
{
    return json_push_kv_str(policy, "layer",
                            zcl_command_layer_name(spec->layer)) &&
           json_push_kv_str(policy, "effect",
                            zcl_command_effect_name(spec->effect)) &&
           json_push_kv_str(policy, "risk",
                            zcl_command_risk_name(spec->risk)) &&
           json_push_kv_str(policy, "scope",
                            zcl_command_scope_name(spec->scope)) &&
           json_push_kv_str(policy, "authority",
                            zcl_command_authority_name(spec->authority)) &&
           json_push_kv_str(policy, "mode",
                            zcl_command_mode_name(spec->mode)) &&
           json_push_kv_str(policy, "latency",
                            zcl_command_latency_name(spec->latency)) &&
           json_push_kv_str(policy, "cost",
                            zcl_command_cost_name(spec->cost)) &&
           json_push_kv_str(policy, "confirmation",
                            zcl_command_confirmation_name(
                                spec->confirmation)) &&
           zcl_command_registry_describe_traits(policy, spec->traits);
}

static bool describe_push_policy_bounds(struct json_value *root,
                                        struct json_value *policy,
                                        const struct zcl_command_spec *spec,
                                        int64_t observed_p99_us,
                                        uint32_t observed_samples)
{
    return json_push_kv_int(policy, "allowed_lanes", spec->allowed_lanes) &&
           json_push_kv_int(policy, "required_capabilities",
                            (int64_t)spec->required_capabilities) &&
           json_push_kv_int(policy, "budget_bytes",
                            spec->budget_bytes > 0
                                ? spec->budget_bytes
                                : (int64_t)ZCL_COMMAND_RESULT_BUDGET) &&
           json_push_kv_int(policy, "budget_ms",
                            zcl_command_latency_budget_ms(spec->latency)) &&
           json_push_kv_int(policy, "observed_p99_us", observed_p99_us) &&
           json_push_kv_int(policy, "observed_samples",
                            (int64_t)observed_samples) &&
           json_push_kv(root, "policy", policy) &&
           json_push_kv_str(root, "example", spec->example);
}

size_t zcl_command_registry_describe_json(
    const struct zcl_command_registry *registry, const char *path, char *out,
    size_t out_size)
{
    bool alias = false;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(registry, path, &alias);
    if (!spec)
        return 0;
    if (command_registry_is_branch(spec))
        return zcl_command_registry_menu_json(registry, spec->path, out,
                                              out_size);

    char digest[72];
    zcl_command_registry_digest(registry, digest);
    struct json_value root, input, policy;
    json_init(&root);
    json_init(&input);
    json_init(&policy);
    json_set_object(&root);
    json_set_object(&input);
    json_set_object(&policy);
    int64_t observed_p99_us = 0;
    uint32_t observed_samples = 0;
    (void)command_registry_latency_ring_p99(registry, spec, &observed_p99_us,
                                            &observed_samples);
    bool ok = describe_push_head(&root, spec, digest) &&
              describe_push_input(&root, &input, spec) &&
              describe_push_policy_names(&policy, spec) &&
              describe_push_policy_bounds(&root, &policy, spec,
                                          observed_p99_us, observed_samples);
    if (spec->aliases && spec->aliases[0])
        ok = ok && command_registry_push_string_array_csv(&root, "aliases",
                                                          spec->aliases);
    if (alias)
        ok = ok && json_push_kv_str(&root, "canonical_path", spec->path);
    size_t result =
        ok ? command_registry_write_bounded_json(&root, out, out_size,
                                                 ZCL_COMMAND_SPEC_BUDGET)
           : 0;
    json_free(&policy);
    json_free(&input);
    json_free(&root);
    return result;
}
