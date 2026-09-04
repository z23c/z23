/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-key transport type rules for the dev.agent leaves, split out of
 * command_registry.c's zcl_command_registry_input_validate() so that file
 * stays under its recorded file-size-ceiling baseline. Behaviour is
 * unchanged: this is the same else-if chain in its own translation unit.
 *
 * `key` has already been confirmed present in the leaf's declared
 * `input_keys` CSV before either the caller or this function runs.
 *
 * The three functions below (the extra bool-key set and the seq predicate)
 * are the overflow for dev land's --json/--seq/--force and dev train:
 * two lanes each added a rule to command_registry.c's
 * zcl_command_registry_input_validate() chain at the same time, and keeping
 * both pushed that file past its recorded ceiling in
 * tools/lint/file_size_policy_baseline.txt, so the two new rules live here
 * instead. The chain in command_registry.c still owns dispatch and the
 * `why` message; these are pure predicates over one already-typed JSON
 * value or a bare key. */

#include "kernel/command_registry.h"

#include "json/json.h"

#include <string.h>

bool zcl_command_registry_devagent_input_ok(const char *key,
                                            const struct json_value *value,
                                            bool *type_ok)
{
    if (strcmp(key, "attempt") == 0) {
        /* dev.agent.queue's post attempt number: `--attempt=2` types as an
         * integer, so the default string branch would make the leaf
         * uninvokable from a shell while raw JSON worked. The handler owns
         * the default (1) and the requeue ceiling (3); the transport only
         * admits the positive integer shape. */
        *type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                   json_get_int(value) <= 1000000;
        return true;
    }
    if (strcmp(key, "max_age_days") == 0 || strcmp(key, "ceiling_lines") == 0) {
        /* dev.agent.triage staleness window and dev.agent.ceiling per-file
         * line ceiling. Both are typed as integers by the CLI
         * (`--max_age_days=14`), so the default string branch would make
         * the leaves uninvokable from a shell while raw JSON worked. Each
         * handler owns its own default; the transport only admits the
         * positive integer shape. */
        *type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                   json_get_int(value) <= 1000000;
        return true;
    }
    if (strcmp(key, "requested") == 0) {
        /* dev.agent.ceiling's declared scope: the paths the change was
         * allowed to touch. Same bounded array-of-paths shape as `files`. */
        *type_ok = value->type == JSON_ARR &&
                   value->num_children <= ZCL_COMMAND_INPUT_FILES_MAX_ITEMS;
        for (size_t j = 0; *type_ok && j < value->num_children; j++) {
            const struct json_value *item = &value->children[j];
            const char *text = json_get_str(item);
            *type_ok = item->type == JSON_STR && text && text[0] &&
                       strlen(text) <= ZCL_COMMAND_INPUT_FILES_PATH_MAX;
        }
        return true;
    }
    if (strcmp(key, "ledger") == 0 || strcmp(key, "model") == 0) {
        /* dev.agent.outcomes' ledger path and model filter are nonempty
         * bounded strings. The handler owns existence and content rules
         * (BAD_INPUT / LEDGER_NOT_FOUND / LEDGER_UNREADABLE); the transport
         * only admits the string shape so the documented `--ledger=<path>`
         * CLI form reaches it. */
        const char *text = json_get_str(value);
        *type_ok = value->type == JSON_STR && text && text[0] &&
                   strlen(text) <= zcl_command_registry_input_str_max(key);
        return true;
    }
    return false;
}

/* dev.land submit/cancel's `--json` and `--force` are booleans in their own
 * declared schema, same as the other flags in command_registry.c's bool
 * disjunction. `include_evidence_wires` and `list` were already in that
 * disjunction and are folded in here too, purely to keep the disjunction's
 * own line count from growing past the ceiling — no behavior change. */
bool command_registry_devagent_input_extra_bool_key(const char *key)
{
    return strcmp(key, "json") == 0 || strcmp(key, "force") == 0 ||
           strcmp(key, "include_evidence_wires") == 0 ||
           strcmp(key, "list") == 0;
}

/* dev.land cancel names one request by its sequence number, and `--seq=3`
 * types as an integer: without this rule the default string branch makes
 * the verb uninvokable from a shell while raw JSON works. The handler owns
 * the semantics; the transport only admits the positive integer shape. */
bool command_registry_devagent_input_seq_ok(const struct json_value *value)
{
    return value->type == JSON_INT && json_get_int(value) >= 1 &&
           json_get_int(value) <= 1000000000;
}
