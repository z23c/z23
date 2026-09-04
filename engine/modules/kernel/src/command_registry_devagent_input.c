/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Per-key transport type rules for the dev.agent leaves, split out of
 * command_registry.c's zcl_command_registry_input_validate() so that file
 * stays under its recorded file-size-ceiling baseline. Behaviour is
 * unchanged: this is the same else-if chain in its own translation unit.
 *
 * `key` has already been confirmed present in the leaf's declared
 * `input_keys` CSV before either the caller or this function runs. */

#include "kernel/command_registry.h"

#include "json/json.h"

#include <string.h>

bool zcl_command_registry_devagent_input_ok(const char *key,
                                            const struct json_value *value,
                                            bool *type_ok)
{
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
