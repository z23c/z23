/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Validate one owner-signed public work card (zcl.work_card.v1). */
#include "command/work_card.h"

#include "json/json.h"

#include <stdbool.h>
#include <string.h>

static const char *const k_reason_codes[] = {
    [WORK_CARD_OK] = "OK",
    [WORK_CARD_TOO_LARGE] = "CARD_TOO_LARGE",
    [WORK_CARD_SCHEMA] = "CARD_SCHEMA",
    [WORK_CARD_LEVEL] = "CARD_LEVEL",
    [WORK_CARD_BASE] = "CARD_BASE",
    [WORK_CARD_ACCEPTANCE_SHELL] = "CARD_ACCEPTANCE_SHELL",
    [WORK_CARD_OWNED_EMPTY] = "CARD_OWNED_EMPTY",
    [WORK_CARD_NAME] = "CARD_NAME",
    [WORK_CARD_LAB_FILE] = "CARD_LAB_FILE",
    [WORK_CARD_LAB_CASES] = "CARD_LAB_CASES",
    [WORK_CARD_LAB_ACCEPTANCE] = "CARD_LAB_ACCEPTANCE",
    [WORK_CARD_TOKEN_BUDGET] = "CARD_TOKEN_BUDGET",
};

const char *work_card_reason_code(enum work_card_reason reason)
{
    if ((unsigned)reason >= sizeof(k_reason_codes) / sizeof(k_reason_codes[0]))
        return "CARD_SCHEMA";
    return k_reason_codes[reason];
}

const char *work_card_level_name(enum work_card_level level)
{
    switch (level) {
    case WORK_CARD_LEVEL_HAIKU: return "haiku";
    case WORK_CARD_LEVEL_SONNET: return "sonnet";
    case WORK_CARD_LEVEL_OPUS: return "opus";
    default: return "";
    }
}

enum work_card_level work_card_level_from_name(const char *name)
{
    if (!name)
        return WORK_CARD_LEVEL_NONE;
    for (enum work_card_level l = WORK_CARD_LEVEL_HAIKU;
         l <= WORK_CARD_LEVEL_OPUS; l++)
        if (strcmp(name, work_card_level_name(l)) == 0)
            return l;
    return WORK_CARD_LEVEL_NONE;
}

static const char *wc_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

/* An absent key is acceptable when `required` is false. A present key must be
 * an array of non-empty strings. */
static bool wc_string_array(const struct json_value *obj, const char *key,
                            bool required)
{
    const struct json_value *v = json_get(obj, key);
    if (!v)
        return !required;
    if (v->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < json_size(v); i++) {
        const struct json_value *item = json_at(v, i);
        const char *s = item && item->type == JSON_STR ? json_get_str(item)
                                                       : NULL;
        if (!s || !s[0])
            return false;
    }
    return true;
}

static bool wc_hex(const char *s, size_t len, size_t max_len)
{
    if (!s || strlen(s) != len || len > max_len)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool wc_kebab(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n == 0 || n > WORK_CARD_NAME_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        bool alnum = (s[i] >= 'a' && s[i] <= 'z') ||
                     (s[i] >= '0' && s[i] <= '9');
        bool dash = s[i] == '-' && i > 0 && i + 1 < n && s[i - 1] != '-';
        if (!alnum && !dash)
            return false;
    }
    return true;
}

/* Acceptance is one argv: words of [A-Za-z0-9_./=:,+-] separated by single
 * spaces, with no quoting, globbing, expansion, redirection or control byte,
 * and not a launcher that would run a string as a program. */
static bool wc_word_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || strchr("_./=:,+-", c) != NULL;
}

static bool wc_launcher(const char *s, size_t first)
{
    static const char *const launchers[] = {
        "sh", "bash", "dash", "zsh", "ksh", "env", "busybox", "exec", "eval",
    };
    for (size_t i = 0; i < sizeof(launchers) / sizeof(launchers[0]); i++)
        if (strlen(launchers[i]) == first && strncmp(s, launchers[i], first) == 0)
            return true;
    return false;
}

static bool wc_acceptance_ok(const char *s)
{
    if (s[0] == ' ' || s[strlen(s) - 1] == ' ')
        return false;
    for (size_t i = 0; s[i]; i++) {
        bool space = s[i] == ' ' && s[i + 1] != ' ';
        if (!wc_word_char(s[i]) && !space)
            return false;
    }
    return !wc_launcher(s, strcspn(s, " "));
}

/* A repeated top-level key would let two readers see different cards. */
static bool wc_has_duplicate_keys(const struct json_value *obj)
{
    for (size_t i = 0; i < obj->num_children; i++)
        for (size_t j = i + 1; j < obj->num_children; j++)
            if (obj->keys[i] && obj->keys[j] &&
                strcmp(obj->keys[i], obj->keys[j]) == 0)
                return true;
    return false;
}

/* Optional task_root: even-length lowercase hex, at most 128 characters. */
static bool wc_task_root_ok(const struct json_value *v)
{
    const char *s = v->type == JSON_STR ? json_get_str(v) : NULL;
    size_t n = s ? strlen(s) : 0;
    return n > 0 && n % 2 == 0 && wc_hex(s, n, 128);
}

/* Shape of every field that has no dedicated reason code. */
static bool wc_shape_ok(const struct json_value *root)
{
    const char *schema = wc_str(root, "schema");
    const char *outcome = wc_str(root, "outcome");
    const char *credit = wc_str(root, "credit");
    const struct json_value *task_root = json_get(root, "task_root");
    if (wc_has_duplicate_keys(root))
        return false;
    if (!schema || strcmp(schema, WORK_CARD_SCHEMA_ID) != 0)
        return false;
    if (!outcome || !outcome[0])
        return false;
    if (json_get(root, "credit") && !credit)
        return false;
    if (task_root && !wc_task_root_ok(task_root))
        return false;
    return wc_string_array(root, "forbidden", false) &&
           wc_string_array(root, "contract", false) &&
           wc_string_array(root, "stop_if", false) &&
           wc_string_array(root, "owned", false);
}

static enum work_card_reason wc_fields(const struct json_value *root,
                                       struct work_card *out)
{
    const char *base = wc_str(root, "base");
    const char *acceptance = wc_str(root, "acceptance");
    const struct json_value *owned = json_get(root, "owned");
    const char *name = wc_str(root, "name");

    out->level = work_card_level_from_name(wc_str(root, "level"));
    if (out->level == WORK_CARD_LEVEL_NONE)
        return WORK_CARD_LEVEL;
    if (!wc_hex(base, WORK_CARD_BASE_HEX, WORK_CARD_BASE_HEX))
        return WORK_CARD_BASE;
    if (!acceptance || !acceptance[0])
        return WORK_CARD_SCHEMA;
    if (!wc_acceptance_ok(acceptance))
        return WORK_CARD_ACCEPTANCE_SHELL;
    if (strlen(acceptance) > WORK_CARD_ACCEPTANCE_MAX)
        return WORK_CARD_SCHEMA;
    if (!owned || json_size(owned) == 0)
        return WORK_CARD_OWNED_EMPTY;
    if (!wc_kebab(name))
        return WORK_CARD_NAME;
    out->owned_count = json_size(owned);
    memcpy(out->base, base, WORK_CARD_BASE_HEX);
    memcpy(out->acceptance, acceptance, strlen(acceptance));
    memcpy(out->name, name, strlen(name));
    memcpy(out->outcome, wc_str(root, "outcome"),
           strlen(wc_str(root, "outcome")));
    return WORK_CARD_OK;
}

/* Repo-relative path of 1..WORK_CARD_PATH_MAX bytes ending in `suffix`: no
 * leading slash, backslash or `..` segment. */
static bool wc_repo_path_ok(const char *s, const char *suffix)
{
    size_t n = s ? strlen(s) : 0;
    size_t tail = strlen(suffix);
    if (n <= tail || n > WORK_CARD_PATH_MAX || s[0] == '/' ||
        strchr(s, '\\') != NULL || strcmp(s + n - tail, suffix) != 0)
        return false;
    for (const char *seg = s; seg;) {
        if (strncmp(seg, "..", 2) == 0 && (seg[2] == '/' || seg[2] == '\0'))
            return false;
        const char *slash = strchr(seg, '/');
        seg = slash ? slash + 1 : NULL;
    }
    return true;
}

static bool wc_owned_has(const struct json_value *owned, const char *path)
{
    for (size_t i = 0; i < json_size(owned); i++)
        if (strcmp(json_get_str(json_at(owned, i)), path) == 0)
            return true;
    return false;
}

/* An absent optional string is NULL with *bad false; a present non-string
 * sets *bad. */
static const char *wc_opt_str(const struct json_value *root, const char *key,
                              bool *bad)
{
    const struct json_value *v = json_get(root, key);
    *bad = v && v->type != JSON_STR;
    return v && !*bad ? json_get_str(v) : NULL;
}

static bool wc_budget_ok(const struct json_value *budget)
{
    return !budget || (budget->type == JSON_INT && json_get_int(budget) >= 1 &&
                       json_get_int(budget) <= WORK_CARD_TOKEN_BUDGET_MAX);
}

/* Checks lab_file and cases; `bad_*` marks a present non-string. */
static enum work_card_reason wc_lab_paths(const struct json_value *root,
                                          const char *file, bool bad_file,
                                          const char *cases, bool bad_cases)
{
    if (bad_file || (file && (!wc_repo_path_ok(file, ".c") ||
                              !wc_owned_has(json_get(root, "owned"), file))))
        return WORK_CARD_LAB_FILE;
    if (bad_cases || (cases && (!file || !wc_repo_path_ok(cases, ".json"))))
        return WORK_CARD_LAB_CASES;
    return WORK_CARD_OK;
}

static enum work_card_reason wc_lab(const struct json_value *root,
                                    struct work_card *out)
{
    bool bad_file, bad_cases;
    const char *file = wc_opt_str(root, "lab_file", &bad_file);
    const char *cases = wc_opt_str(root, "cases", &bad_cases);
    const struct json_value *budget = json_get(root, "token_budget");
    enum work_card_reason reason =
        wc_lab_paths(root, file, bad_file, cases, bad_cases);
    if (reason != WORK_CARD_OK)
        return reason;
    if (cases && strncmp(out->acceptance, "z23 lab test ", 13) != 0)
        return WORK_CARD_LAB_ACCEPTANCE;
    if (!wc_budget_ok(budget))
        return WORK_CARD_TOKEN_BUDGET;
    if (file)
        memcpy(out->lab_file, file, strlen(file));
    if (cases)
        memcpy(out->cases, cases, strlen(cases));
    out->token_budget = budget ? json_get_int(budget) : 0;
    return WORK_CARD_OK;
}

enum work_card_reason work_card_validate(const char *bytes, size_t len,
                                         struct work_card *out)
{
    if (!bytes || !out)
        return WORK_CARD_SCHEMA;
    memset(out, 0, sizeof(*out));
    if (len > WORK_CARD_BYTES_MAX)
        return WORK_CARD_TOO_LARGE;
    struct json_value root;
    json_init(&root);
    enum work_card_reason reason = WORK_CARD_SCHEMA;
    if (json_read(&root, bytes, len) && root.type == JSON_OBJ &&
        wc_shape_ok(&root))
        reason = wc_fields(&root, out);
    if (reason == WORK_CARD_OK)
        reason = wc_lab(&root, out);
    json_free(&root);
    if (reason != WORK_CARD_OK)
        memset(out, 0, sizeof(*out));
    return reason;
}

bool work_card_hex64(const char *s, char out[WORK_KEY_HEX + 1])
{
    if (!s || strlen(s) != WORK_KEY_HEX)
        return false;
    for (size_t i = 0; i < WORK_KEY_HEX; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'F')
            c = (char)(c - 'A' + 'a');
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
        out[i] = c;
    }
    out[WORK_KEY_HEX] = '\0';
    return true;
}

enum work_owner_status work_owner_resolve(const char *given, const char *pinned,
                                          char out[WORK_KEY_HEX + 1])
{
    if (given && given[0])
        return work_card_hex64(given, out) ? WORK_OWNER_OK : WORK_OWNER_BAD;
    if (pinned && pinned[0])
        return work_card_hex64(pinned, out) ? WORK_OWNER_OK : WORK_OWNER_BAD;
    return WORK_OWNER_REQUIRED;
}
