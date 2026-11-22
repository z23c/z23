/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Path/CSV/branch predicates split out of command_registry.c so that file
 * stays under its recorded line-count ceiling and each helper stays under
 * the cyclomatic cap of 15. Behaviour is unchanged. */

#include "kernel/command_registry.h"

#include "command_registry_internal.h"

#include <stdio.h>
#include <string.h>

bool command_registry_copy_string(char *out, size_t out_size, const char *value)
{
    if (!out || out_size == 0)
        return false;
    int n = snprintf(out, out_size, "%s", value ? value : "");
    return n >= 0 && (size_t)n < out_size;
}

static bool path_token_char(unsigned char c, bool token_start)
{
    if (token_start)
        return c >= 'a' && c <= 'z';
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' ||
           c == '-';
}

bool command_registry_path_valid(const char *path)
{
    if (!path || !path[0] || strlen(path) >= ZCL_COMMAND_MAX_PATH)
        return false;
    bool token_start = true;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        if (*p == '.') {
            if (token_start)
                return false;
            token_start = true;
            continue;
        }
        if (!path_token_char(*p, token_start))
            return false;
        token_start = false;
    }
    return !token_start;
}

bool command_registry_csv_token_equal(const char *csv, const char *value)
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

/* '-' and '_' are one character for the fold; '.' and the rest are exact. */
bool command_registry_fold_equal(const char *a, size_t an, const char *b,
                                 size_t bn)
{
    if (an != bn)
        return false;
    for (size_t i = 0; i < an; i++) {
        char x = a[i] == '_' ? '-' : a[i];
        char y = b[i] == '_' ? '-' : b[i];
        if (x != y)
            return false;
    }
    return true;
}

/* First csv token that equals `value` under the fold, or NULL. *len is the
 * token length. */
static const char *csv_fold_token(const char *csv, const char *value,
                                  size_t *len)
{
    if (!csv || !csv[0] || !value)
        return NULL;
    const char *at = csv;
    while (*at) {
        const char *end = strchr(at, ',');
        size_t n = end ? (size_t)(end - at) : strlen(at);
        if (command_registry_fold_equal(at, n, value, strlen(value))) {
            *len = n;
            return at;
        }
        if (!end)
            break;
        at = end + 1;
    }
    return NULL;
}

bool command_registry_csv_token_fold_equal(const char *csv, const char *value)
{
    size_t len = 0;
    return csv_fold_token(csv, value, &len) != NULL;
}

bool zcl_command_registry_input_key_canonical(
    const struct zcl_command_spec *spec, const char *key, char *out,
    size_t out_size)
{
    if (!spec || !key || !key[0] || !out || out_size == 0)
        return false;
    size_t len = 0;
    const char *token = command_registry_csv_token_equal(spec->input_keys, key)
                            ? key
                            : csv_fold_token(spec->input_keys, key, &len);
    if (!token)
        return false;
    if (token == key)
        len = strlen(key);
    if (len >= out_size)
        return false;
    memcpy(out, token, len);
    out[len] = 0;
    return true;
}

bool command_registry_csv_valid_paths(const char *csv)
{
    if (!csv || !csv[0])
        return true;
    const char *at = csv;
    char token[ZCL_COMMAND_MAX_PATH];
    while (*at) {
        const char *end = strchr(at, ',');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        if (len == 0 || len >= sizeof(token))
            return false;
        memcpy(token, at, len);
        token[len] = 0;
        if (!command_registry_path_valid(token))
            return false;
        if (!end)
            break;
        at = end + 1;
    }
    return true;
}

bool command_registry_is_branch(const struct zcl_command_spec *spec)
{
    return spec && spec->mode == ZCL_COMMAND_MODE_BRANCH;
}

bool command_registry_enum_values_valid(const struct zcl_command_spec *spec)
{
    return spec->layer <= ZCL_COMMAND_LAYER_CODE &&
           spec->effect <= ZCL_COMMAND_EFFECT_DESTRUCTIVE &&
           spec->risk <= ZCL_COMMAND_RISK_DEV_MUTATION &&
           spec->scope <= ZCL_COMMAND_SCOPE_OFFLINE_COPY &&
           spec->authority <= ZCL_COMMAND_AUTH_OWNER &&
           spec->availability <= ZCL_COMMAND_PLANNED &&
           spec->mode <= ZCL_COMMAND_MODE_STREAM &&
           spec->latency <= ZCL_COMMAND_LATENCY_MAINTENANCE &&
           spec->cost <= ZCL_COMMAND_COST_STREAM &&
           spec->confirmation <= ZCL_COMMAND_CONFIRM_PLAN_COMMIT;
}

bool command_registry_resolve_word_ok(const char *word)
{
    return word && word[0] && word[0] != '-' && !strchr(word, '.') &&
           !strchr(word, '/') && !strchr(word, '\\');
}

void command_registry_resolve_accept(
    const struct zcl_command_spec *found, bool alias, size_t count,
    const struct zcl_command_spec **best, size_t *best_count, bool *best_alias,
    char *invoked, size_t invoked_size, const char *candidate)
{
    *best = found;
    *best_count = count;
    *best_alias = alias;
    if (invoked && invoked_size)
        (void)command_registry_copy_string(invoked, invoked_size, candidate);
}

bool command_registry_resolve_append(char *candidate, size_t candidate_size,
                                     size_t *pos, const char *word)
{
    int n = snprintf(candidate + *pos, candidate_size - *pos, "%s%s",
                     *pos ? "." : "", word);
    if (n <= 0 || (size_t)n >= candidate_size - *pos)
        return false;
    *pos += (size_t)n;
    return true;
}
