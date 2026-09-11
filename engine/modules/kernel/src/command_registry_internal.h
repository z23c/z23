/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * command_registry_internal.h — the command registry's PRIVATE surface.
 *
 * zcl_command_registry_*() in kernel/command_registry.h is the module's
 * public contract. These names are not: they exist only because the
 * complexity and file-size ceilings split one translation unit into the
 * command_registry_*.c family, and a sibling TU still has to call across
 * the seam. Nothing outside engine/modules/kernel/src/ may include this
 * header; a caller that needs one of these needs a public entry point
 * instead.
 *
 * Declarations are grouped by the TU that DEFINES them. */

#ifndef ZCL_KERNEL_COMMAND_REGISTRY_INTERNAL_H
#define ZCL_KERNEL_COMMAND_REGISTRY_INTERNAL_H

#include "kernel/command_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── command_registry_devagent_input.c ─────────────────────────────────
 * The dev-agent arm of zcl_command_registry_input_validate()'s per-key
 * type rules. */
bool command_registry_devagent_input_extra_bool_key(const char *key);
bool command_registry_devagent_input_seq_ok(const struct json_value *value);
bool zcl_command_registry_devagent_input_ok(const char *path, const char *key,
                                            const struct json_value *value,
                                            bool *type_ok);

/* ── command_registry_input_types.c ────────────────────────────────────
 * The rest of the per-key JSON type/range rules behind
 * zcl_command_registry_input_validate(). command_registry_input_value_type_ok()
 * returns true when this arm owns `key` (even if *type_ok is false). */
bool command_registry_input_value_type_ok(const struct zcl_command_spec *spec,
                                          const char *key,
                                          const struct json_value *value,
                                          bool *type_ok);
bool command_registry_input_key_declared(const struct zcl_command_spec *spec,
                                         const struct json_value *input,
                                         size_t i, char *why, size_t why_size);
bool command_registry_input_type_why(const char *key,
                                     const struct json_value *value, char *why,
                                     size_t why_size);
bool command_registry_input_required_discovery(
    const struct zcl_command_spec *spec, const struct json_value *input,
    char *why, size_t why_size);

/* ── command_registry_path.c ───────────────────────────────────────────
 * Path/CSV/branch predicates and the word-by-word resolve walk. */
bool command_registry_copy_string(char *out, size_t out_size, const char *value);
bool command_registry_path_valid(const char *path);
bool command_registry_csv_token_equal(const char *csv, const char *value);
bool command_registry_csv_valid_paths(const char *csv);
bool command_registry_is_branch(const struct zcl_command_spec *spec);
bool command_registry_enum_values_valid(const struct zcl_command_spec *spec);
bool command_registry_resolve_word_ok(const char *word);
void command_registry_resolve_accept(
    const struct zcl_command_spec *found, bool alias, size_t count,
    const struct zcl_command_spec **best, size_t *best_count, bool *best_alias,
    char *invoked, size_t invoked_size, const char *candidate);
/* Appends ".<word>" (or "<word>" at *pos == 0) to `candidate`, which holds
 * `candidate_size` bytes. Refuses — leaving *pos unchanged — when the
 * result would not fit. */
bool command_registry_resolve_append(char *candidate, size_t candidate_size,
                                     size_t *pos, const char *word);

/* ── command_registry.c ────────────────────────────────────────────────
 * The registry's own state: the per-leaf latency ring. */
bool command_registry_latency_ring_p99(
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *spec, int64_t *p99_us, uint32_t *count);

/* ── command_registry_describe.c ───────────────────────────────────────
 * Describe/menu document assembly. */
bool command_registry_push_string_array_csv(struct json_value *object,
                                            const char *key, const char *csv);

/* ── command_registry_reply.c ──────────────────────────────────────────
 * Reply serialization and the budgeted JSON writer. */
struct agent_spend_policy_decision;

size_t command_registry_write_bounded_json(struct json_value *root, char *out,
                                           size_t out_size,
                                           size_t contract_budget);
bool command_registry_reply_add_describe_next(
    struct zcl_command_reply *reply, const struct zcl_command_spec *spec,
    const char *reason);
bool command_registry_push_error(struct json_value *root,
                                 const struct zcl_command_error *error);
bool command_registry_push_next_array(
    struct json_value *root, const struct zcl_command_reply *reply,
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *current_spec);
size_t command_registry_serialize_reply(
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *spec, struct zcl_command_reply *reply,
    bool invoked_by_alias, uint64_t request_sequence, int64_t elapsed_us,
    size_t budget_bytes, bool agent_session_presented,
    const struct agent_spend_policy_decision *policy, char *out,
    size_t out_size);

/* ── command_registry_replace.c ────────────────────────────────────────
 * Pre-publish checks for zcl_command_registry_replace_batch(). */
bool command_registry_replace_validate(
    const struct zcl_command_registry *registry,
    const struct zcl_command_handler_override *overrides, size_t count,
    char *why, size_t why_sz);

/* ── command_registry_execute.c ────────────────────────────────────────
 * The handler call itself, with its timing and spend-policy bookkeeping. */
void command_registry_execute_run(
    const struct zcl_command_spec *spec,
    const struct zcl_command_context *context, const struct json_value *input,
    zcl_command_handler_fn handler, bool invoked_by_alias,
    const char *invoked_name, const char *view, size_t budget_bytes,
    size_t max_items, const char *cursor, struct zcl_command_reply *reply,
    struct agent_spend_policy_decision *policy);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_KERNEL_COMMAND_REGISTRY_INTERNAL_H */
