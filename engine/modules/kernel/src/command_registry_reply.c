/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Result-envelope JSON helpers split out of command_registry.c under the
 * cyclomatic cap of 15. Envelope fields and next-command checks are
 * unchanged. */

#include "kernel/command_registry.h"

#include "command_registry_internal.h"

#include "services/agent_spend_policy.h"  // lib-layer-ok:agent-spend-policy-gate

#include <stdio.h>
#include <string.h>

size_t command_registry_write_bounded_json(struct json_value *root, char *out,
                                           size_t out_size,
                                           size_t contract_budget)
{
    if (!root || !out || out_size == 0)
        return 0;
    size_t need = json_write(root, out, out_size);
    if (need >= out_size || need > contract_budget) {
        if (out_size)
            out[0] = 0;
        return 0;
    }
    return need;
}

bool command_registry_reply_add_describe_next(
    struct zcl_command_reply *reply, const struct zcl_command_spec *spec,
    const char *reason)
{
    if (!reply || !spec || !spec->path)
        return false;
    if (strcmp(spec->path, "discover.describe") == 0)
        return zcl_command_reply_add_next(
            reply, "discover.help", "{}",
            "inspect the discovery surface and choose a valid leaf");
    char input[ZCL_COMMAND_MAX_PATH + 16];
    int n = snprintf(input, sizeof(input), "{\"path\":\"%s\"}", spec->path);
    return n > 0 && (size_t)n < sizeof(input) &&
           zcl_command_reply_add_next(reply, "discover.describe", input,
                                      reason);
}

const char *command_registry_wiki_effect(const struct zcl_command_spec *spec,
                                         const struct zcl_command_error *error)
{
    if (!spec || !spec->path || !error || strcmp(spec->path, "fleet.steer.wiki-write")) return NULL;
    static const struct { const char *state; const char *effect; } states[] = {
        {"committed", "committed"}, {"committed_receipt_unavailable", "committed"},
        {"retained_replay", "retained_replay"},
        {"retained_replay_receipt_unavailable", "retained_replay"},
        {"outcome_unknown", "unknown"}};
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
        if (!strcmp(error->current_state, states[i].state)) return states[i].effect;
    return NULL;
}

bool command_registry_effect_possible(const char *effect,
                                      const struct zcl_command_error *error)
{
    return effect ? strcmp(effect, "retained_replay") != 0 : error->mutated;
}

static bool push_error_required(struct json_value *object,
                                const struct zcl_command_error *error,
                                const char *effect)
{
    return json_push_kv_str(object, "code", error->code) &&
           json_push_kv_str(object, "error_code", error->code) &&
           json_push_kv_str(object, "message", error->message) &&
           json_push_kv_str(object, "phase", error->phase) &&
           json_push_kv_str(object, "current_state",
                            error->current_state[0] ? error->current_state
                                                    : "REQUEST_FAILED") &&
           json_push_kv_bool(object, "retryable", effect ? false : error->retryable) &&
           json_push_kv_bool(object, "human_action_required",
                             effect ? true : error->human_action_required) &&
           json_push_kv_str(object, "next_action",
                            effect ? "reconcile the same request_key; do not issue a new key" : error->next_action[0]
                                ? error->next_action
                                : "follow the first next command") &&
           json_push_kv_bool(object, "mutated", command_registry_effect_possible(effect, error));
}

static bool push_error_optional(struct json_value *object,
                                const struct zcl_command_error *error)
{
    bool ok = true;
    if (error->evidence[0])
        ok = ok && json_push_kv_str(object, "evidence", error->evidence);
    if (error->failure_id[0])
        ok = ok && json_push_kv_str(object, "failure_id", error->failure_id);
    return ok;
}

static bool error_effect_complete(const struct json_value *object,
    const struct zcl_command_error *error, const char *effect)
{
    if (!effect) return true;
    const char *state = json_get_str(json_get(object, "current_state"));
    const char *actual = json_get_str(json_get(object, "effect_outcome"));
    const char *action = json_get_str(json_get(object, "next_action"));
    const struct json_value *mutated = json_get(object, "mutated");
    return state && !strcmp(state, error->current_state) && actual && !strcmp(actual, effect) &&
        action && !strcmp(action, "reconcile the same request_key; do not issue a new key") &&
        mutated && mutated->type == JSON_BOOL &&
        json_get_bool(mutated) == command_registry_effect_possible(effect, error);
}

bool command_registry_push_error(struct json_value *root,
                                 const struct zcl_command_spec *spec,
                                 const struct zcl_command_error *error,
                                 const struct json_value *facts)
{
    /* Only explicit sanitized facts are exported. Ordinary partial handler
     * data remains private; malformed opt-in metadata refuses serialization. */
    if (facts && facts->type != JSON_OBJ) return false;
    struct json_value object, blockers;
    json_init(&object);
    json_init(&blockers);
    json_set_object(&object);
    json_set_array(&blockers);
    const char *effect = command_registry_wiki_effect(spec, error);
    bool ok = push_error_required(&object, error, effect) &&
              push_error_optional(&object, error) &&
              json_push_kv(&object, "blockers", &blockers);
    if (ok && effect) ok = json_push_kv_str(&object, "effect_outcome", effect);
    if (ok && facts) ok = json_push_kv(&object, "facts", facts);
    ok = ok && error_effect_complete(&object, error, effect) &&
        json_push_kv(root, "error", &object) &&
        error_effect_complete(json_get(root, "error"), error, effect);
    json_free(&blockers);
    json_free(&object);
    return ok;
}

static bool push_next_item_valid(const struct zcl_command_next *next,
                                 const struct zcl_command_registry *registry,
                                 const struct zcl_command_spec *current_spec,
                                 struct json_value *input)
{
    if (!json_read(input, next->input_json, strlen(next->input_json)) ||
        input->type != JSON_OBJ)
        return false;
    const struct zcl_command_spec *next_spec =
        zcl_command_registry_find(registry, next->command, NULL);
    char why[160] = {0};
    if (!next_spec || command_registry_is_branch(next_spec))
        return false;
    /* A leaf may name itself only to continue a page: the input must carry the
     * paging key that advances it, so the entry can never repeat the call. */
    if (current_spec && strcmp(next_spec->path, current_spec->path) == 0 &&
        !json_get(input, "cursor") && !json_get(input, "item_offset"))
        return false;
    return zcl_command_registry_input_validate(next_spec, input, why,
                                               sizeof(why));
}

static bool push_next_item(struct json_value *array,
                           const struct zcl_command_next *next,
                           const struct zcl_command_registry *registry,
                           const struct zcl_command_spec *current_spec)
{
    struct json_value item, input;
    json_init(&item);
    json_init(&input);
    json_set_object(&item);
    if (!push_next_item_valid(next, registry, current_spec, &input)) {
        json_free(&input);
        json_free(&item);
        return false;
    }
    bool ok = json_push_kv_str(&item, "command", next->command) &&
              json_push_kv(&item, "input", &input) &&
              json_push_kv_str(&item, "reason", next->reason) &&
              json_push_back(array, &item);
    json_free(&input);
    json_free(&item);
    return ok;
}

bool command_registry_push_next_array(
    struct json_value *root, const struct zcl_command_reply *reply,
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *current_spec)
{
    struct json_value array;
    json_init(&array);
    json_set_array(&array);
    bool ok = true;
    for (size_t i = 0; ok && i < reply->next_count; i++)
        ok = push_next_item(&array, &reply->next[i], registry, current_spec);
    ok = ok && json_push_kv(root, "next", &array);
    json_free(&array);
    return ok;
}

static bool serialize_envelope(struct json_value *root,
                               const struct zcl_command_spec *spec,
                               const struct zcl_command_reply *reply,
                               const char *request_id, int64_t elapsed_us,
                               bool successful)
{
    bool ok = json_push_kv_str(root, "schema", "zcl.result.v1") &&
              json_push_kv_str(root, "command", spec->path) &&
              json_push_kv_bool(root, "ok", successful) &&
              json_push_kv_str(root, "status",
                               zcl_command_status_name(reply->status)) &&
              json_push_kv_str(root, "request_id", request_id) &&
              json_push_kv_int(root, "elapsed_us",
                               elapsed_us < 0 ? 0 : elapsed_us);
    int64_t budget_ms = zcl_command_latency_budget_ms(spec->latency);
    int64_t elapsed_ms = elapsed_us < 0 ? 0 : elapsed_us / 1000;
    bool budget_exceeded = elapsed_us > budget_ms * 1000;
    return ok && json_push_kv_int(root, "budget_ms", budget_ms) &&
           json_push_kv_int(root, "elapsed_ms", elapsed_ms) &&
           json_push_kv_bool(root, "budget_exceeded", budget_exceeded);
}

static bool authority_labels_complete(
    const struct json_value *auth, bool presented,
    const struct agent_spend_policy_decision *policy)
{
    const char *kind = json_get_str(json_get(auth, "policy"));
    const char *session = json_get_str(json_get(auth, "agent_session"));
    const char *expected = presented && policy && policy->evidence[0]
                               ? policy->evidence : "none (local operator)";
    return kind && session &&
           !strcmp(kind, presented ? "bounded" : "exempt") &&
           !strcmp(session, expected);
}

static bool authority_complete(const struct json_value *auth,
                               bool presented,
                               const struct agent_spend_policy_decision *policy)
{
    if (!authority_labels_complete(auth, presented, policy))
        return false;
    if (!presented || !policy)
        return true;
    const struct json_value *debit = json_get(auth, "debited_zat");
    if (!debit || debit->type != JSON_INT || debit->val.i != policy->debited_zat)
        return false;
    if (policy->debited_zat <= 0)
        return true;
    const struct json_value *remaining = json_get(auth, "window_remaining_zat");
    return remaining && remaining->type == JSON_INT &&
           remaining->val.i == policy->window_remaining_zat;
}

static bool serialize_authority(
    struct json_value *root, bool agent_session_presented,
    const struct agent_spend_policy_decision *policy)
{
    struct json_value auth;
    json_init(&auth);
    json_set_object(&auth);
    bool ok = json_push_kv_str(&auth, "policy",
                              agent_session_presented ? "bounded" : "exempt") &&
        json_push_kv_str(
        &auth, "agent_session",
        (agent_session_presented && policy && policy->evidence[0])
            ? policy->evidence
            : "none (local operator)");
    if (agent_session_presented && policy) {
        ok = ok && json_push_kv_int(&auth, "debited_zat", policy->debited_zat);
        if (policy->debited_zat > 0)
            ok = ok && json_push_kv_int(&auth, "window_remaining_zat",
                                   policy->window_remaining_zat);
    }
    /* JSON copying can degrade a scalar on allocation failure while its
     * append returns true. Check both the prepared and published authority. */
    ok = ok && authority_complete(&auth, agent_session_presented, policy) &&
         json_push_kv(root, "authority", &auth) &&
         authority_complete(json_get(root, "authority"),
                            agent_session_presented, policy);
    json_free(&auth);
    return ok;
}

static bool serialize_body(struct json_value *root,
                           const struct zcl_command_registry *registry,
                           const struct zcl_command_spec *spec,
                           struct zcl_command_reply *reply, bool successful,
                           bool invoked_by_alias)
{
    bool ok = true;
    if (invoked_by_alias)
        ok = ok && json_push_kv_str(root, "canonical_path", spec->path);
    if (successful) {
        ok = ok &&
             json_push_kv_str(root, "data_schema",
                              reply->data_schema ? reply->data_schema
                                                 : spec->output_schema) &&
             json_push_kv(root, "data", &reply->data);
    } else {
        ok = ok && command_registry_push_error(root, spec, &reply->error,
                                               json_get(&reply->data, "failure_facts"));
        if (reply->next_count == 0) {
            ok = ok && command_registry_reply_add_describe_next(
                reply, spec,
                "inspect this command's contract and availability");
        }
    }
    return ok &&
           command_registry_push_next_array(root, reply, registry, spec);
}

/* Same serializer owners as the final envelope, with empty data and no next.
 * INT64_MAX reserves every possible elapsed integer width. Its true budget
 * flag is one byte shorter than false, so retain one extra byte as well. */
bool command_registry_success_data_budget(
    const struct zcl_command_spec *spec, bool invoked_by_alias,
    size_t budget_bytes, bool agent_session_presented,
    const struct agent_spend_policy_decision *policy, size_t *usable)
{
    *usable = 0;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, spec->output_schema);
    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    bool ok = serialize_envelope(&root, spec, &reply,
        "local-ffffffffffffffff", INT64_MAX, true) &&
        serialize_authority(&root, agent_session_presented, policy) &&
        serialize_body(&root, NULL, spec, &reply, true, invoked_by_alias);
    if (ok) {
        size_t cap = spec->budget_bytes > 0
            ? (size_t)spec->budget_bytes : ZCL_COMMAND_RESULT_BUDGET;
        if (budget_bytes > 0 && budget_bytes < cap) cap = budget_bytes;
        /* Empty data contributes two bytes; replace those with the caller's
         * complete data value, keeping one byte for the boolean width. */
        size_t overhead = json_write(&root, NULL, 0) - 2 + 1;
        if (overhead < cap) *usable = cap - overhead;
    }
    json_free(&root);
    zcl_command_reply_free(&reply);
    return ok;
}

#ifdef ZCL_TESTING
bool zcl_command_registry_test_success_budget(
    const struct zcl_command_spec *spec, struct zcl_command_reply *reply,
    const struct zcl_command_budget_fixture *fixture, size_t *usable,
    char *wire, size_t wire_size, size_t *wire_bytes)
{
    struct agent_spend_policy_decision policy = {.allowed = true,
        .debited_zat = fixture->debited_zat,
        .window_remaining_zat = fixture->remaining_zat};
    *wire_bytes = 0;
    const char *evidence = fixture->authority_evidence ? fixture->authority_evidence : "";
    int n = snprintf(policy.evidence, sizeof(policy.evidence), "%s", evidence);
    if (n < 0 || (size_t)n >= sizeof(policy.evidence))
        return false;
    if (!command_registry_success_data_budget(spec, fixture->alias,
            fixture->budget_bytes, fixture->presented, &policy, usable))
        return false;
    *wire_bytes = command_registry_serialize_reply(NULL, spec, reply,
        fixture->alias, UINT64_MAX, fixture->elapsed_us, fixture->budget_bytes,
        fixture->presented, &policy, wire, wire_size);
    return true;
}
#endif

size_t command_registry_serialize_reply(
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *spec, struct zcl_command_reply *reply,
    bool invoked_by_alias, uint64_t request_sequence, int64_t elapsed_us,
    size_t budget_bytes, bool agent_session_presented,
    const struct agent_spend_policy_decision *policy, char *out,
    size_t out_size)
{
    char request_id[48];
    (void)snprintf(request_id, sizeof(request_id), "local-%016llx",
                   (unsigned long long)request_sequence);
    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    bool successful = reply->status == ZCL_COMMAND_STATUS_PASSED ||
                      reply->status == ZCL_COMMAND_STATUS_ACCEPTED;
    bool ok = serialize_envelope(&root, spec, reply, request_id, elapsed_us,
                                 successful) &&
              serialize_authority(&root, agent_session_presented, policy) &&
              serialize_body(&root, registry, spec, reply, successful,
                             invoked_by_alias);
    size_t contract = successful ? (spec->budget_bytes > 0
                                        ? (size_t)spec->budget_bytes
                                        : ZCL_COMMAND_RESULT_BUDGET)
                                 : ZCL_COMMAND_ERROR_BUDGET;
    if (budget_bytes > 0 && budget_bytes < contract)
        contract = budget_bytes;
    size_t result = ok ? command_registry_write_bounded_json(&root, out,
                                                             out_size, contract)
                       : 0;
    json_free(&root);
    return result;
}
