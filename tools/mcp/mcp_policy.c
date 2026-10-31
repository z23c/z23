/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Exact registry-policy gate for the local MCP adapter (see mcp_policy.h). */

#include "mcp_policy.h"

#include <string.h>

static bool refuse(struct mcp_refusal *why, const char *code,
                   const char *message, const struct zcl_command_spec *spec)
{
    why->code = code;
    why->message = message;
    why->detail = spec ? spec->path : NULL;
    return false;
}

/* True when key appears as a whole item of the spec's comma-separated list. */
static bool keys_declare(const char *keys, const char *key)
{
    size_t n = strlen(key);
    for (const char *p = keys; p && *p;) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == n && memcmp(p, key, n) == 0)
            return true;
        p = end ? end + 1 : p + len;
    }
    return false;
}

static bool input_truthy(const struct json_value *input, const char *key)
{
    const struct json_value *v = json_get(input, key);
    if (!v)
        return false;
    switch (v->type) {
    case JSON_BOOL:
        return json_get_bool(v);
    case JSON_STR:
        return json_get_str(v) && json_get_str(v)[0];
    case JSON_NULL:
        return false;
    default:
        return true;
    }
}

static bool input_is_true(const struct json_value *input, const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool ends_with(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && memcmp(s + a - b, suffix, b) == 0;
}

static bool commit_attempted(const struct zcl_command_spec *spec,
                             const struct json_value *input)
{
    const struct json_value *mode = json_get(input, "mode");
    return ends_with(spec->path, ".commit") || input_truthy(input, "confirm") ||
           input_truthy(input, "plan_id") ||
           input_truthy(input, "plan_token") ||
           (mode && mode->type == JSON_STR && json_get_str(mode) &&
            strcmp(json_get_str(mode), "commit") == 0);
}

static bool flow_declared(const char *keys)
{
    return keys_declare(keys, "plan_id") || keys_declare(keys, "plan_token") ||
           keys_declare(keys, "confirm") || keys_declare(keys, "mode");
}

/* The registry has no stage attribute, so the plan stage of a plan/commit
 * pair is recognised by its pairing: the path is "<stem>.plan" and the same
 * registry holds "<stem>.commit" as a mutation. No registry, or
 * no such partner, means no exemption. */
static bool is_plan_stage(const struct zcl_command_spec *spec,
                          const struct zcl_command_registry *registry)
{
    char partner[ZCL_COMMAND_MAX_PATH];
    const struct zcl_command_spec *other;
    size_t n = strlen(spec->path);
    bool alias = false;
    if (!registry || !ends_with(spec->path, ".plan") ||
        n - 5 + 7 >= sizeof(partner))
        return false;
    memcpy(partner, spec->path, n - 5);
    memcpy(partner + n - 5, ".commit", 8);
    other = zcl_command_registry_find(registry, partner, &alias);
    return other && !alias && other != spec &&
           other->effect != ZCL_COMMAND_EFFECT_READ;
}

/* Every check is derived from what the contract declares AND what the request
 * supplies; a key the contract does not declare never waives a check. */
static bool plan_commit_allows(const struct zcl_command_spec *spec,
                               const struct zcl_command_registry *registry,
                               const struct json_value *input,
                               struct mcp_refusal *why)
{
    const char *keys = spec->input_keys ? spec->input_keys : "";
    bool has_plan = keys_declare(keys, "plan_id");
    bool has_token = keys_declare(keys, "plan_token");
    if (!commit_attempted(spec, input)) {
        if (flow_declared(keys) || is_plan_stage(spec, registry))
            return true; /* plan half: the leaf returns its plan, no commit */
        return refuse(why, "MUTATION_NO_CONFIRMATION_FLOW",
                      "mutation declares no plan or confirm input and is not a plan leaf; "
                      "use z23_describe to find a plan-first leaf", spec);
    }
    if (!has_plan && !has_token)
        return refuse(why, "MUTATION_NO_CONFIRMATION_FLOW",
                      "commit leaf declares no plan_id or plan_token input; "
                      "run its plan leaf from the CLI instead", spec);
    if (has_plan && !input_truthy(input, "plan_id"))
        return refuse(why, "PLAN_ID_REQUIRED",
                      "commit needs the plan_id returned by the plan call", spec);
    if (has_token && !input_truthy(input, "plan_token"))
        return refuse(why, "PLAN_TOKEN_REQUIRED",
                      "commit needs the plan_token returned by the plan call",
                      spec);
    if (keys_declare(keys, "confirm") && !input_is_true(input, "confirm"))
        return refuse(why, "CONFIRM_REQUIRED",
                      "commit needs confirm set to true", spec);
    return true;
}

static bool confirmation_allows(const struct zcl_command_spec *spec,
                                const struct zcl_command_registry *registry,
                                const struct json_value *input,
                                struct mcp_refusal *why)
{
    switch (spec->confirmation) {
    case ZCL_COMMAND_CONFIRM_PLAN_COMMIT:
        return plan_commit_allows(spec, registry, input, why);
    case ZCL_COMMAND_CONFIRM_IDEMPOTENCY:
        if (!spec->input_keys || !keys_declare(spec->input_keys, "idempotency_key"))
            return refuse(why, "MUTATION_NO_CONFIRMATION_FLOW",
                          "mutation declares no idempotency_key input; run it "
                          "from the CLI instead", spec);
        if (!input_truthy(input, "idempotency_key"))
            return refuse(why, "IDEMPOTENCY_KEY_REQUIRED",
                          "this mutation needs an idempotency_key", spec);
        return true;
    default:
        return refuse(why, "MUTATION_NO_CONFIRMATION_FLOW",
                      "mutating command has no confirmation flow", spec);
    }
}

bool mcp_policy_fleet_write(const struct zcl_command_spec *spec)
{
    static const char *const leaves[] = {"fleet.board.post", "fleet.wiki.write",
                                         "fleet.bundle.offer",
                                         "fleet.bundle.fetch"};
    if (!spec || spec->mode == ZCL_COMMAND_MODE_BRANCH ||
        spec->effect != ZCL_COMMAND_EFFECT_MUTATE ||
        spec->risk != ZCL_COMMAND_RISK_APP_WRITE ||
        spec->authority == ZCL_COMMAND_AUTH_OWNER ||
        spec->layer == ZCL_COMMAND_LAYER_CORE)
        return false;
    for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++)
        if (strcmp(spec->path, leaves[i]) == 0)
            return true;
    return false;
}

bool mcp_policy_allows(const struct zcl_command_spec *spec,
                       const struct zcl_command_registry *registry,
                       const struct json_value *input,
                       struct mcp_refusal *why)
{
    if (!spec || spec->mode == ZCL_COMMAND_MODE_BRANCH)
        return refuse(why, "NOT_A_LEAF",
                      "path is not a runnable command; use z23_describe", spec);
    /* Read-effect leaves are refused on the same wallet, core-recovery and
     * owner axes as mutations, so a misclassified leaf still cannot run. */
    if (spec->effect == ZCL_COMMAND_EFFECT_READ) {
        if (spec->risk == ZCL_COMMAND_RISK_WALLET)
            return refuse(why, "READ_REFUSED_WALLET_RISK",
                          "wallet-risk commands are not available here", spec);
        if (spec->risk == ZCL_COMMAND_RISK_CORE_RECOVERY)
            return refuse(why, "READ_REFUSED_CORE_RECOVERY",
                          "core-recovery commands are not available here", spec);
        if (spec->authority == ZCL_COMMAND_AUTH_OWNER)
            return refuse(why, "READ_REFUSED_OWNER_AUTHORITY",
                          "owner-authority commands are not available here", spec);
        return true;
    }
    if (spec->risk == ZCL_COMMAND_RISK_WALLET)
        return refuse(why, "MUTATION_REFUSED_WALLET_RISK",
                      "mutating wallet-risk commands are not available here",
                      spec);
    if (spec->risk == ZCL_COMMAND_RISK_CORE_RECOVERY)
        return refuse(why, "MUTATION_REFUSED_CORE_RECOVERY",
                      "mutating core-recovery commands are not available here",
                      spec);
    if (spec->authority == ZCL_COMMAND_AUTH_OWNER)
        return refuse(why, "MUTATION_REFUSED_OWNER_AUTHORITY",
                      "mutating owner-authority commands are not available here",
                      spec);
    if (spec->layer == ZCL_COMMAND_LAYER_CORE)
        return refuse(why, "MUTATION_REFUSED_CORE_LAYER",
                      "mutating core-layer commands are not available here",
                      spec);
    return confirmation_allows(spec, registry, input, why);
}
