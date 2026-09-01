/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure goal tokenization and ranking over caller-owned buffers. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/zcode_goal_context_calc_service.h"

#include "hotswap/hotswap_service.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static bool stopword(const char *word)
{
    static const char *const words[] = {
        "a", "add", "an", "and", "ensure", "fix", "make", "or",
        "repair", "the", "to", "with", "without",
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++)
        if (strcmp(word, words[i]) == 0) return true;
    return false;
}

static void stem(char *word)
{
    size_t n = strlen(word);
    if (n > 5 && strcmp(word + n - 3u, "ing") == 0)
        word[n - 3u] = '\0';
    else if (n > 4 && strcmp(word + n - 2u, "ed") == 0)
        word[n - 2u] = '\0';
    else if (n > 4 && word[n - 1u] == 's')
        word[n - 1u] = '\0';
}

static bool tokenize(const char *goal, struct zcode_goal_tokens_v1 *out)
{
    if (!goal || !goal[0] || !out) return false;
    memset(out, 0, sizeof(*out));
    size_t used = 0;
    char word[ZCODE_GOAL_TOKEN_MAX + 1u];
    for (const unsigned char *p = (const unsigned char *)goal;; p++) {
        if (isalnum(*p) || *p == '_') {
            if (used < ZCODE_GOAL_TOKEN_MAX)
                word[used++] = (char)tolower(*p);
            else
                out->budget_exhausted = true;
            continue;
        }
        if (used != 0) {
            word[used] = '\0';
            stem(word);
            bool duplicate = false;
            for (size_t i = 0; i < out->count; i++)
                if (strcmp(out->values[i], word) == 0) duplicate = true;
            if (!stopword(word) && !duplicate && word[0]) {
                if (out->count < ZCODE_GOAL_MAX_TOKENS)
                    (void)snprintf(out->values[out->count++],
                                   ZCODE_GOAL_TOKEN_MAX + 1u, "%s", word);
                else
                    out->budget_exhausted = true;
            }
            used = 0;
        }
        if (*p == '\0') break;
    }
    out->valid = true;
    return true;
}

static int candidate_cmp(const struct zcode_goal_candidate *a,
                         const struct zcode_goal_candidate *b)
{
    if (a->score != b->score) return a->score > b->score ? -1 : 1;
    int by_name = strcmp(a->symbol.name, b->symbol.name);
    if (by_name) return by_name;
    int by_def = strcmp(a->symbol.def_path, b->symbol.def_path);
    return by_def ? by_def : strcmp(a->symbol.decl_path, b->symbol.decl_path);
}

static bool rank(struct zcode_goal_candidate *candidates, size_t count)
{
    if (!candidates || count == 0 || count > ZCODE_GOAL_MAX_CANDIDATES)
        return false;
    for (size_t i = 1; i < count; i++) {
        struct zcode_goal_candidate moving = candidates[i];
        size_t j = i;
        while (j > 0 && candidate_cmp(&moving, &candidates[j - 1u]) < 0) {
            candidates[j] = candidates[j - 1u];
            j--;
        }
        candidates[j] = moving;
    }
    return true;
}

static bool render_status(struct zcode_goal_context_view_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    (void)snprintf(
        out->capability, sizeof(out->capability), "%s",
        "bounded goal tokenization and candidate ranking are live-swappable");
    (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                   "zcode work start --input='<workspace and goal>'");
    out->valid = true;
    return true;
}

static const struct zcode_goal_context_calc_service_v1 k_builtin = {
    .tokenize = tokenize,
    .rank = rank,
    .render_status = render_status,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    ZCODE_GOAL_CONTEXT_CALC_SERVICE_ID, k_builtin,
    ZCODE_GOAL_CONTEXT_CALC_ABI_FINGERPRINT,
    ZCODE_GOAL_CONTEXT_CALC_SCHEMA_FINGERPRINT,
    ZCODE_GOAL_CONTEXT_CALC_WIRE_FINGERPRINT,
    ZCODE_GOAL_CONTEXT_CALC_KAT_FINGERPRINT)

const struct zcode_goal_context_calc_service_v1 *
zcode_goal_context_calc_service_builtin(void)
{
    return &k_builtin;
}
