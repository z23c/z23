/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-key transport type rules for the dev.agent leaves, split out of
 * command_registry.c's zcl_command_registry_input_validate() so that file
 * stays under its recorded file-size-ceiling baseline. Behaviour is
 * unchanged from the original else-if chain; each arm below is now its own
 * small predicate so that dispatcher — zcl_command_registry_devagent_input_ok
 * — is a flat sequence of "does this arm match" calls instead of one long
 * chain, keeping it under the shrink-only cyclomatic-complexity ceiling as
 * new leaf-specific rules (such as fleet.triggers.check's `dry-run`, added
 * as a data row rather than a new inline branch) arrive over time.
 *
 * `key` has already been confirmed present in the leaf's declared
 * `input_keys` CSV before either the caller or this function runs.
 *
 * The three public functions below (the extra bool-key set and the seq
 * predicate) are the overflow for dev land's --json/--seq/--force and dev
 * train: two lanes each added a rule to command_registry.c's
 * zcl_command_registry_input_validate() chain at the same time, and keeping
 * both pushed that file past its recorded ceiling in
 * tools/lint/file_size_policy_baseline.txt, so the two new rules live here
 * instead. The chain in command_registry.c still owns dispatch and the
 * `why` message; these are pure predicates over one already-typed JSON
 * value or a bare key. */

#include "kernel/command_registry.h"

#include "json/json.h"

#include <string.h>

/* True if `key` is one of `keys[0..count)`. The one loop every fixed-set
 * arm below shares, so a new key list is a new table, not a new loop. */
static bool devagent_key_in_set(const char *key, const char *const *keys,
                               size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(key, keys[i]) == 0)
            return true;
    return false;
}

/* fleet.ledger.add's gauge/counter fields. Gauges can be signed; counters
 * include measured zero. `value` and `limit` are scoped to this exact leaf
 * because those names are common enough to mean something else elsewhere. */
static bool devagent_ledger_add_int(const char *path, const char *key,
                                    const struct json_value *value,
                                    bool *type_ok)
{
    static const char *const keys[] = {
        "tokens_in", "tokens_out", "tokens_cached", "tokens_reasoning",
        "wall_ms", "turns", "tool_uses", "cost_micro_usd", "value", "count",
        "bytes", "limit",
    };
    if (!path || strcmp(path, "fleet.ledger.add") != 0 ||
        !devagent_key_in_set(key, keys, sizeof keys / sizeof keys[0]))
        return false;
    *type_ok = value->type == JSON_INT &&
              (strcmp(key, "value") == 0 || json_get_int(value) >= 0);
    return true;
}

/* dev.agent.queue's post attempt number: `--attempt=2` types as an integer,
 * so the default string branch would make the leaf uninvokable from a
 * shell while raw JSON worked. The handler owns the default (1) and the
 * requeue ceiling (3); the transport only admits the positive integer
 * shape, up to a generous round bound shared with the next arm. */
static bool devagent_bounded_positive_int(const char *key,
                                          const struct json_value *value,
                                          bool *type_ok)
{
    static const char *const keys[] = {
        "attempt", "max_age_days", "ceiling_lines",
    };
    if (!devagent_key_in_set(key, keys, sizeof keys / sizeof keys[0]))
        return false;
    *type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
              json_get_int(value) <= 1000000;
    return true;
}

/* dev.agent.ceiling's declared scope: the paths the change was allowed to
 * touch. Same bounded array-of-paths shape as `files`. */
static bool devagent_requested_paths(const char *key,
                                     const struct json_value *value,
                                     bool *type_ok)
{
    if (strcmp(key, "requested") != 0)
        return false;
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

/* dev.agent.outcomes' ledger path and model filter are nonempty bounded
 * strings. The handler owns existence and content rules (BAD_INPUT /
 * LEDGER_NOT_FOUND / LEDGER_UNREADABLE); the transport only admits the
 * string shape so the documented `--ledger=<path>` CLI form reaches it. */
static bool devagent_ledger_or_model_str(const char *key,
                                        const struct json_value *value,
                                        bool *type_ok)
{
    if (strcmp(key, "ledger") != 0 && strcmp(key, "model") != 0)
        return false;
    const char *text = json_get_str(value);
    *type_ok = value->type == JSON_STR && text && text[0] &&
              strlen(text) <= zcl_command_registry_input_str_max(key);
    return true;
}

/* dev.fleet.start's packet size ceiling. `--budget_bytes=2048` types as an
 * integer, so the default string branch would make the leaf uninvokable
 * from a shell while raw JSON worked. The transport admits only the
 * integer SHAPE and deliberately a wider range than the leaf accepts: the
 * handler owns the 1024..65536 contract and refuses anything else by name
 * (budget_out_of_range), so an operator who asks for 64 reads which rule
 * fired instead of a generic type error. */
static bool devagent_budget_bytes(const char *key,
                                  const struct json_value *value,
                                  bool *type_ok)
{
    if (strcmp(key, "budget_bytes") != 0)
        return false;
    *type_ok = value->type == JSON_INT && json_get_int(value) >= 0 &&
              json_get_int(value) <= 1000000000;
    return true;
}

/* fleet.experiment.predict|result measured and predicted quantities.
 * `--tokens=1200` types as an integer, so the default string branch would
 * make the leaves uninvokable from a shell. The handler owns presence
 * versus absence; the transport only admits a non-negative integer shape.
 * These names are unique to those leaves today. */
static bool devagent_experiment_quantity(const char *key,
                                        const struct json_value *value,
                                        bool *type_ok)
{
    static const char *const keys[] = {
        "tokens", "wall_s", "in", "out", "cache", "reasoning", "tool_uses",
        "turns", "added", "removed", "defects",
    };
    if (!devagent_key_in_set(key, keys, sizeof keys / sizeof keys[0]))
        return false;
    *type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
    return true;
}

/* Leaf-scoped boolean flags: a data row per (path, key), not a branch per
 * leaf. A bare flag (no `=value`) hands the CLI's value over as a JSON bool
 * with nothing after it, so the default string branch would make the leaf
 * uninvokable from a shell. Scoped by path rather than folded into
 * command_registry.c's shared bool disjunction, whose keys are NOT
 * leaf-scoped: the same key name on another leaf might mean something
 * else. Add a row here, not a new arm, for the next one of these. */
static bool devagent_scoped_bool(const char *path, const char *key,
                                 const struct json_value *value,
                                 bool *type_ok)
{
    static const struct {
        const char *path;
        const char *key;
    } rows[] = {
        /* fleet.triggers.check's `--dry-run`: performs the same actions as
         * a real run but never advances a source's cursor. */
        { "fleet.triggers.check", "dry-run" },
    };
    if (!path)
        return false;
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        if (strcmp(path, rows[i].path) == 0 && strcmp(key, rows[i].key) == 0) {
            *type_ok = value->type == JSON_BOOL;
            return true;
        }
    }
    return false;
}

bool zcl_command_registry_devagent_input_ok(const char *path, const char *key,
                                            const struct json_value *value,
                                            bool *type_ok)
{
    if (devagent_ledger_add_int(path, key, value, type_ok))
        return true;
    if (devagent_bounded_positive_int(key, value, type_ok))
        return true;
    if (devagent_requested_paths(key, value, type_ok))
        return true;
    if (devagent_ledger_or_model_str(key, value, type_ok))
        return true;
    if (devagent_budget_bytes(key, value, type_ok))
        return true;
    if (devagent_experiment_quantity(key, value, type_ok))
        return true;
    if (devagent_scoped_bool(path, key, value, type_ok))
        return true;
    return false;
}

/* dev.land submit/cancel's `--json` and `--force` are booleans in their own
 * declared schema, same as the other flags in command_registry.c's bool
 * disjunction. `include_evidence_wires` and `list` were already in that
 * disjunction and are folded in here too, purely to keep the disjunction's
 * own line count from growing past the ceiling — no behavior change.
 * `open` is `fleet board list --open`'s filter for posts nothing has
 * answered yet; it lands here rather than in command_registry.c for the
 * same reason. */
bool command_registry_devagent_input_extra_bool_key(const char *key)
{
    /* `include_units` is dev.fleet.start's "list the running executor units"
     * switch. It is deliberately NOT called `units`: the ZSLP branch of the
     * chain in command_registry.c already owns `units` as a positive token
     * amount, so a bool named `units` would be refused before any handler
     * ran — and renaming the ZSLP key would change a shipped money surface. */
    return strcmp(key, "json") == 0 || strcmp(key, "force") == 0 ||
           strcmp(key, "include_evidence_wires") == 0 ||
           strcmp(key, "include_units") == 0 ||
           strcmp(key, "list") == 0 || strcmp(key, "open") == 0 ||
           strcmp(key, "publish") == 0 || strcmp(key, "fleet") == 0;
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
