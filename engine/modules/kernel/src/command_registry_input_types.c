/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-key JSON type/range rules for zcl_command_registry_input_validate(),
 * split out of command_registry.c so that dispatcher stays under the
 * cyclomatic cap of 15. Behaviour is unchanged: each former else-if arm
 * is a table row or a small predicate. `key` is already in the leaf's
 * declared input_keys CSV before this runs. */

#include "kernel/command_registry.h"

#include "json/json.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool cr_key_in(const char *key, const char *const *keys, size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(key, keys[i]) == 0)
            return true;
    return false;
}

static bool cr_int_range(const struct json_value *value, int64_t lo, int64_t hi)
{
    return value->type == JSON_INT && json_get_int(value) >= lo &&
           json_get_int(value) <= hi;
}

static bool cr_nonempty_str(const struct json_value *value, size_t max_len)
{
    const char *text = json_get_str(value);
    return value->type == JSON_STR && text && text[0] && strlen(text) <= max_len;
}

static bool cr_str_array(const struct json_value *value, size_t max_items,
                         size_t max_len)
{
    if (value->type != JSON_ARR || value->num_children > max_items)
        return false;
    for (size_t j = 0; j < value->num_children; j++) {
        const struct json_value *item = &value->children[j];
        const char *text = json_get_str(item);
        if (item->type != JSON_STR || !text || !text[0] || strlen(text) > max_len)
            return false;
    }
    return true;
}

static bool cr_match_files(const char *key, const struct json_value *value,
                           bool *type_ok)
{
    if (strcmp(key, "files") != 0)
        return false;
    *type_ok = cr_str_array(value, ZCL_COMMAND_INPUT_FILES_MAX_ITEMS,
                            ZCL_COMMAND_INPUT_FILES_PATH_MAX);
    return true;
}

static bool cr_match_bool(const char *key, const struct json_value *value,
                          bool *type_ok)
{
    static const char *const keys[] = {
        "verbose",           "details",           "confirm",
        "enabled",           "relink_generation", "wait_for_edit",
        "all",               "allow_high_fees",   "exact",
        "restore",           "release",           "once",
        "dry_run",
    };
    if (!cr_key_in(key, keys, sizeof(keys) / sizeof(keys[0])) &&
        !command_registry_devagent_input_extra_bool_key(key))
        return false;
    *type_ok = value->type == JSON_BOOL;
    return true;
}

static bool cr_match_arrays(const char *key, const struct json_value *value,
                            bool *type_ok)
{
    static const char *const root_sets[] = {
        "read_only_verbs", "object_roots", "capability_roots",
        "service_roots",   "portal_roots", "starting_roots",
    };
    if (strcmp(key, "effects") == 0) {
        *type_ok = value->type == JSON_ARR && value->num_children >= 1u &&
                   value->num_children <= 50u;
        return true;
    }
    if (strcmp(key, "inputs") == 0 || strcmp(key, "prevtxs") == 0) {
        *type_ok = value->type == JSON_ARR && value->num_children <= 256u;
        return true;
    }
    if (strcmp(key, "outputs") == 0) {
        *type_ok = value->type == JSON_OBJ && value->num_children <= 256u;
        return true;
    }
    if (cr_key_in(key, root_sets, sizeof(root_sets) / sizeof(root_sets[0]))) {
        *type_ok = cr_str_array(value, 64u, 64u);
        return true;
    }
    return false;
}

static bool cr_match_public_keys(const char *key, const struct json_value *value,
                                 bool *type_ok)
{
    if (strcmp(key, "public_keys") != 0)
        return false;
    *type_ok = value->type == JSON_ARR && value->num_children >= 1u &&
               value->num_children <= 16u;
    for (size_t j = 0; *type_ok && j < value->num_children; j++) {
        const struct json_value *item = &value->children[j];
        const char *text = json_get_str(item);
        size_t len = text ? strlen(text) : 0;
        *type_ok = item->type == JSON_STR && (len == 66u || len == 130u);
        for (size_t k = 0; *type_ok && k < len; k++)
            *type_ok = isxdigit((unsigned char)text[k]) != 0;
    }
    return true;
}

static bool cr_match_units(const char *key, const struct json_value *value,
                           bool *type_ok)
{
    if (strcmp(key, "units") != 0 && strcmp(key, "supply") != 0)
        return false;
    const char *s = json_get_str(value);
    *type_ok = value->type == JSON_INT && json_get_int(value) > 0;
    if (*type_ok || value->type != JSON_STR || !s || !s[0] || strlen(s) > 20)
        return true;
    bool nonzero = false;
    *type_ok = true;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < '0' || *p > '9') {
            *type_ok = false;
            break;
        }
        if (*p != '0')
            nonzero = true;
    }
    *type_ok = *type_ok && nonzero;
    return true;
}

struct cr_int_bound {
    const char *key;
    int64_t lo;
    int64_t hi;
};

static bool cr_match_int_table(const char *key, const struct json_value *value,
                               bool *type_ok)
{
    static const struct cr_int_bound k_bounds[] = {
        { "decimals", 0, 8 },
        { "required_signatures", 1, 16 },
        { "action_mask", 1, 127 },
        { "raw_offset", 0, INT64_MAX },
        { "raw_bytes", 1, 1024 },
        { "slot", 1, 100 },
        { "window_hours", 1, 168 },
        { "height", 0, INT64_MAX },
        { "start_height", 0, INT64_MAX },
        { "after", 0, INT64_MAX },
        { "after_epoch", 0, INT64_MAX },
        { "day", 0, INT64_MAX },
        { "now_unix", 0, INT64_MAX },
        { "now", 0, INT64_MAX },
        { "created_at", 0, INT64_MAX },
        { "expires", 0, INT64_MAX },
        { "expires_at", 0, INT64_MAX },
        { "issued_unix", 0, INT64_MAX },
        { "expires_unix", 0, INT64_MAX },
        { "amount_zatoshi", 1, 2100000000000000LL },
        { "sequence", 1, INT64_MAX },
        { "not_before", 1, INT64_MAX },
        { "expiry", 1, INT64_MAX },
        { "observation_unix", 1, INT64_MAX },
        { "maximum_depth", 0, 8 },
        { "maximum_spaces", 1, 32 },
        { "maximum_portals", 1, 64 },
        { "deadline_ms", 1, 60000 },
        { "expires_in_seconds", 60, 3600 },
        { "challenge_block_height", 1, INT64_MAX },
        { "action_sequence", 1, INT64_MAX },
        { "result_sequence", 1, INT64_MAX },
        { "reproduction_sequence", 1, INT64_MAX },
        { "publisher_sequence", 1, INT64_MAX },
        { "max", 1, INT64_MAX },
        { "min-height", 0, INT64_MAX },
        { "seen-within", 0, 31536000 },
        { "page", 0, 1000000 },
        { "peer_id", 0, INT64_MAX },
        { "product_id", 1, INT64_MAX },
        { "purchase_id", 1, INT64_MAX },
        { "locktime_blocks", 1, 1000000 },
        { "price_per_mb_zat", 0, 2100000000000000LL },
        { "recipient_value_zat", 1, 2100000000000000LL },
        { "maximum_fee_zat", 0, 2100000000000000LL },
        { "concurrency", 1, 50 },
        { "tokens_per_purchase", 0, INT64_MAX },
        { "timeout_ms", 1, 300000 },
        { "heartbeat_ms", 100, 60000 },
        { "max_cpu_seconds", 1, 600 },
        { "verbosity", 0, 2 },
        { "max_items", 1, 100 },
        { "since_secs", 0, 31536000 },
        { "epoch", 0, INT64_MAX },
        { "rpc_port", 0, 65535 },
        { "watcher_id", 2, INT64_MAX },
        { "seconds", 1, 60 },
        { "top_n", 1, 32 },
        { "depth", 1, 1000000 },
    };
    for (size_t i = 0; i < sizeof(k_bounds) / sizeof(k_bounds[0]); i++) {
        if (strcmp(key, k_bounds[i].key) != 0)
            continue;
        *type_ok = cr_int_range(value, k_bounds[i].lo, k_bounds[i].hi);
        return true;
    }
    return false;
}

static bool cr_match_dual(const char *key, const struct json_value *value,
                          bool *type_ok)
{
    size_t str_max = zcl_command_registry_input_str_max(key);
    if (strcmp(key, "seed") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX) || cr_nonempty_str(value, 32);
        return true;
    }
    if (strcmp(key, "amount") == 0 || strcmp(key, "price_zcl") == 0 ||
        strcmp(key, "price_zatoshi") == 0) {
        *type_ok = value->type == JSON_INT || value->type == JSON_REAL ||
                   cr_nonempty_str(value, 64);
        return true;
    }
    if (strcmp(key, "cursor") == 0) {
        *type_ok = cr_int_range(value, 0, INT64_MAX) ||
                   cr_nonempty_str(value, 256);
        return true;
    }
    if (strcmp(key, "nonce") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX) ||
                   cr_nonempty_str(value, str_max);
        return true;
    }
    if (strcmp(key, "since") == 0 || strcmp(key, "since_epoch") == 0) {
        *type_ok = value->type == JSON_INT
                       ? json_get_int(value) >= 0
                       : cr_nonempty_str(value, str_max);
        return true;
    }
    return false;
}

static bool cr_match_presentation(const char *path, const char *key,
                                  const struct json_value *value, bool *type_ok)
{
    if (strcmp(path, "app.presentation.show") != 0)
        return false;
    if (strcmp(key, "items") == 0) {
        *type_ok = value->type == JSON_ARR && json_size(value) <= 64u;
        return true;
    }
    if (strcmp(key, "actions") == 0) {
        *type_ok = value->type == JSON_ARR && json_size(value) <= 4u;
        return true;
    }
    return false;
}

static bool cr_match_path_special(const struct zcl_command_spec *spec,
                                  const char *key,
                                  const struct json_value *value,
                                  bool *type_ok)
{
    const char *path = spec && spec->path ? spec->path : "";
    if (cr_match_presentation(path, key, value, type_ok))
        return true;
    if (strcmp(key, "maximum_bytes") == 0) {
        int64_t maximum = strcmp(path, "zcode.package.fetch") == 0
                              ? 256LL * 1024LL * 1024LL
                              : 8LL * 1024LL * 1024LL;
        *type_ok = cr_int_range(value, 1, maximum);
        return true;
    }
    if (strcmp(key, "days") == 0 && strcmp(path, "fleet.usage") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX);
        return true;
    }
    if (strcmp(key, "cutoff_height") == 0 || strcmp(key, "cutoff_mtp") == 0 ||
        strcmp(key, "epoch_capacity_atoms") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX);
        return true;
    }
    if (strcmp(key, "limit") == 0 && strcmp(path, "fleet.ledger.add") != 0) {
        *type_ok = cr_int_range(value, 1, 1000000);
        return true;
    }
    return false;
}

static bool cr_match_chunks_and_lines(const char *key,
                                      const struct json_value *value,
                                      bool *type_ok)
{
    if (strcmp(key, "chunk_start") == 0 || strcmp(key, "chunks_paid") == 0) {
        int64_t lo = strcmp(key, "chunks_paid") == 0 ? 1 : 0;
        *type_ok = cr_int_range(value, lo, 4294967295LL);
        return true;
    }
    if (strcmp(key, "max_lines") == 0 || strcmp(key, "line") == 0) {
        int64_t hi = strcmp(key, "line") ? 1000 : 1000000;
        *type_ok = cr_int_range(value, 1, hi);
        return true;
    }
    return false;
}

static bool cr_default_string(const char *key, const struct json_value *value)
{
    const char *text = json_get_str(value);
    bool type_ok = cr_nonempty_str(value, zcl_command_registry_input_str_max(key));
    if (type_ok && strcmp(key, "side") == 0)
        type_ok = strcmp(text, "input") == 0 || strcmp(text, "output") == 0;
    if (type_ok && strcmp(key, "view") == 0)
        type_ok = strcmp(text, "summary") == 0 || strcmp(text, "normal") == 0 ||
                  strcmp(text, "full") == 0;
    return type_ok;
}

static bool cr_csv_has(const char *csv, const char *value)
{
    if (!csv || !csv[0] || !value)
        return false;
    size_t value_len = strlen(value);
    const char *at = csv;
    while (*at) {
        const char *end = strchr(at, ',');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        if (len == value_len && memcmp(at, value, len) == 0)
            return true;
        if (!end)
            break;
        at = end + 1;
    }
    return false;
}

bool command_registry_input_key_declared(const struct zcl_command_spec *spec,
                                         const struct json_value *input,
                                         size_t i, char *why, size_t why_size)
{
    const char *key = input->keys[i];
    if (!key || !key[0] || !cr_csv_has(spec->input_keys, key)) {
        if (why)
            snprintf(why, why_size, "unknown input key '%s'", key ? key : "");
        return false;
    }
    for (size_t j = 0; j < i; j++) {
        if (input->keys[j] && strcmp(input->keys[j], key) == 0) {
            if (why)
                snprintf(why, why_size, "duplicate input key '%s'", key);
            return false;
        }
    }
    return true;
}

bool command_registry_input_type_why(const char *key,
                                     const struct json_value *value, char *why,
                                     size_t why_size)
{
    const char *text = json_get_str(value);
    size_t str_max = zcl_command_registry_input_str_max(key);
    if (why && value->type == JSON_STR && text && strlen(text) > str_max)
        snprintf(why, why_size,
                 "input key '%s' is %zu characters, over its %zu limit",
                 key, strlen(text), str_max);
    else if (why)
        snprintf(why, why_size, "invalid type or range for input key '%s'",
                 key);
    return false;
}

bool command_registry_input_required_discovery(
    const struct zcl_command_spec *spec, const struct json_value *input,
    char *why, size_t why_size)
{
    const char *required_key = NULL;
    if (strcmp(spec->path, "discover.search") == 0)
        required_key = "query";
    else if (strcmp(spec->path, "discover.describe") == 0 ||
             strcmp(spec->path, "discover.schema") == 0)
        required_key = "path";
    if (!required_key)
        return true;
    const char *value = json_get_str(json_get(input, required_key));
    if (value && value[0])
        return true;
    if (why)
        snprintf(why, why_size, "missing required input key '%s'",
                 required_key);
    return false;
}

static bool cr_match_shaped(const char *key, const struct json_value *value,
                            bool *type_ok)
{
    if (cr_match_files(key, value, type_ok))
        return true;
    if (cr_match_bool(key, value, type_ok))
        return true;
    if (cr_match_arrays(key, value, type_ok))
        return true;
    if (cr_match_public_keys(key, value, type_ok))
        return true;
    if (cr_match_units(key, value, type_ok))
        return true;
    return false;
}

bool command_registry_input_value_type_ok(const struct zcl_command_spec *spec,
                                          const char *key,
                                          const struct json_value *value,
                                          bool *type_ok)
{
    if (!type_ok || !key || !value)
        return false;
    *type_ok = false;
    if (cr_match_shaped(key, value, type_ok))
        return true;
    if (cr_match_int_table(key, value, type_ok))
        return true;
    if (cr_match_dual(key, value, type_ok))
        return true;
    if (cr_match_path_special(spec, key, value, type_ok))
        return true;
    if (cr_match_chunks_and_lines(key, value, type_ok))
        return true;
    if (zcl_command_registry_devagent_input_ok(spec ? spec->path : NULL, key,
                                               value, type_ok))
        return true;
    if (strcmp(key, "seq") == 0) {
        *type_ok = command_registry_devagent_input_seq_ok(value);
        return true;
    }
    *type_ok = cr_default_string(key, value);
    return true;
}
