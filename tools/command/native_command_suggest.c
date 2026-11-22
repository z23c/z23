/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unknown-command answer (see native_command_suggest.h).
 *
 * A typed word list resolves as far as it can; the first word that does not
 * resolve is the wrong one. Every registry leaf under the valid prefix whose
 * next segment is related to that word (same name, a common verb synonym, a
 * prefix of it, or one edit away) and whose remaining segments match the
 * words typed after it is a candidate; the three cheapest are suggested.
 * Nothing is suggested that is not a registered leaf, and only a leaf the
 * registry marks read-only (effect and risk READ) is ever a runnable
 * suggestion; a mutating, custody-bearing, spending or destructive match is
 * named only as a `discover describe <path>` pointer. */

#include "command/native_command_suggest.h"

#include "command/native_json_input.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define UC_MAX_WORDS 8
#define UC_SEG_MAX 48
#define UC_PATH_MAX 160
#define UC_MAX_SUGGEST 3

struct uc_synonym {
    const char *word;
    const char *target;
};

/* Common verbs an operator or agent types, mapped to the registry's verbs. */
static const struct uc_synonym k_synonyms[] = {
    {"ls", "list"},      {"all", "list"},      {"rm", "drop"},
    {"rm", "revoke"},    {"rm", "remove"},     {"rm", "uninstall"},
    {"delete", "drop"},  {"delete", "revoke"}, {"delete", "remove"},
    {"del", "drop"},     {"del", "remove"},    {"get", "show"},
    {"read", "show"},    {"cat", "show"},      {"view", "show"},
    {"info", "show"},    {"new", "create"},    {"init", "create"},
    {"add", "create"},   {"make", "create"},   {"stat", "status"},
    {"state", "status"}, {"find", "search"},   {"run", "start"},
};

struct uc_ctx {
    const char *words[UC_MAX_WORDS]; /* raw, as typed */
    char folded[UC_MAX_WORDS][UC_SEG_MAX];
    size_t nw;                       /* command-ish words, before a flag */
    size_t k0;                       /* leading words that resolve to branches */
    char prefix[UC_PATH_MAX];        /* canonical path of those branches */
};

struct uc_pick {
    int score;
    const char *path;
};

/* Lowercase, with '-' and '_' equal. False when `src` does not fit. */
static bool uc_fold(char dst[UC_SEG_MAX], const char *src, size_t len)
{
    if (len == 0 || len >= UC_SEG_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = c == '-' ? '_' : (char)tolower(c);
    }
    dst[len] = '\0';
    return true;
}

static bool uc_synonym(const char *word, const char *seg)
{
    for (size_t i = 0; i < sizeof(k_synonyms) / sizeof(k_synonyms[0]); i++)
        if (strcmp(k_synonyms[i].word, word) == 0 &&
            strcmp(k_synonyms[i].target, seg) == 0)
            return true;
    return false;
}

static unsigned uc_min3(unsigned a, unsigned b, unsigned c)
{
    unsigned m = a < b ? a : b;
    return m < c ? m : c;
}

/* Optimal-string-alignment distance (adjacent swap counts as one edit). */
static unsigned uc_distance(const char *a, const char *b)
{
    unsigned d[UC_SEG_MAX + 1][UC_SEG_MAX + 1];
    size_t la = strlen(a), lb = strlen(b);
    for (size_t i = 0; i <= la; i++)
        d[i][0] = (unsigned)i;
    for (size_t j = 0; j <= lb; j++)
        d[0][j] = (unsigned)j;
    for (size_t i = 1; i <= la; i++) {
        for (size_t j = 1; j <= lb; j++) {
            unsigned sub = a[i - 1] == b[j - 1] ? 0U : 1U;
            unsigned v = uc_min3(d[i - 1][j] + 1, d[i][j - 1] + 1,
                                 d[i - 1][j - 1] + sub);
            bool swap = i > 1 && j > 1 && a[i - 1] == b[j - 2] &&
                        a[i - 2] == b[j - 1];
            d[i][j] = swap && d[i - 2][j - 2] + 1 < v ? d[i - 2][j - 2] + 1
                                                       : v;
        }
    }
    return d[la][lb];
}

/* Relatedness of a typed (folded) word to a registry segment: -1 unrelated,
 * else a cost where lower is nearer. */
static int uc_seg_cost(const char *word, const char *seg)
{
    if (strcmp(word, seg) == 0)
        return 0;
    if (uc_synonym(word, seg))
        return 1;
    size_t lw = strlen(word);
    if (lw >= 2 && strncmp(seg, word, lw) == 0)
        return 2;
    if (lw < 3)
        return -1;
    unsigned d = uc_distance(word, seg);
    return d <= (lw >= 7 ? 2U : 1U) ? 2 + (int)d : -1;
}

/* Copy the next '.'-separated segment of *p (folded); advance past its dot. */
static bool uc_next_seg(const char **p, char seg[UC_SEG_MAX])
{
    const char *s = *p;
    const char *dot = strchr(s, '.');
    size_t len = dot ? (size_t)(dot - s) : strlen(s);
    if (!uc_fold(seg, s, len))
        return false;
    *p = dot ? dot + 1 : s + len;
    return true;
}

/* Cost of leaf `path` as a correction of the typed words, -1 when it is not
 * a candidate: under the valid prefix, no deeper than the typed words, and
 * every segment from the wrong word on related to the word typed there. */
static int uc_leaf_cost(const struct uc_ctx *c, const char *path)
{
    size_t plen = strlen(c->prefix);
    if (c->k0 > 0 &&
        (strncmp(path, c->prefix, plen) != 0 || path[plen] != '.'))
        return -1;
    const char *p = path + (c->k0 > 0 ? plen + 1 : 0);
    int total = 0;
    for (size_t i = c->k0; i < c->nw && *p; i++) {
        char seg[UC_SEG_MAX];
        if (!uc_next_seg(&p, seg))
            return -1;
        int cost = uc_seg_cost(c->folded[i], seg);
        if (cost < 0)
            return -1;
        total += cost;
    }
    return *p ? -1 : total;
}

static bool uc_pick_before(const struct uc_pick *a, const struct uc_pick *b)
{
    if (a->score != b->score)
        return a->score < b->score;
    size_t la = strlen(a->path), lb = strlen(b->path);
    return la != lb ? la < lb : strcmp(a->path, b->path) < 0;
}

static void uc_pick_insert(struct uc_pick picks[UC_MAX_SUGGEST], size_t *n,
                           struct uc_pick cand)
{
    size_t at = *n;
    while (at > 0 && uc_pick_before(&cand, &picks[at - 1]))
        at--;
    if (at >= UC_MAX_SUGGEST)
        return;
    size_t end = *n < UC_MAX_SUGGEST ? *n : UC_MAX_SUGGEST - 1;
    for (; end > at; end--)
        picks[end] = picks[end - 1];
    picks[at] = cand;
    if (*n < UC_MAX_SUGGEST)
        (*n)++;
}

/* Only a leaf the registry marks read-only may be a runnable suggestion. */
static bool uc_leaf_is_safe(const struct zcl_command_spec *s)
{
    return s->effect == ZCL_COMMAND_EFFECT_READ &&
           s->risk == ZCL_COMMAND_RISK_READ;
}

/* Safe matches fill `picks`; the nearest unsafe match (a spend, custody,
 * mutating or destructive leaf) is kept in `*risky` for a describe pointer. */
static size_t uc_collect(const struct zcl_command_registry *reg,
                         const struct uc_ctx *c,
                         struct uc_pick picks[UC_MAX_SUGGEST],
                         struct uc_pick *risky)
{
    size_t n = 0;
    *risky = (struct uc_pick){-1, NULL};
    for (size_t i = 0; i < reg->count; i++) {
        const struct zcl_command_spec *s = &reg->commands[i];
        if (s->mode == ZCL_COMMAND_MODE_BRANCH)
            continue;
        int cost = uc_leaf_cost(c, s->path);
        if (cost < 0)
            continue;
        struct uc_pick cand = {cost, s->path};
        if (uc_leaf_is_safe(s))
            uc_pick_insert(picks, &n, cand);
        else if (!risky->path || uc_pick_before(&cand, risky))
            *risky = cand;
    }
    return n;
}

/* Typed words up to the first flag / key=value / dotted word, folded; then
 * the longest leading run that names registered branches. */
static void uc_parse(const struct zcl_command_registry *reg,
                     const struct zcl_unknown_command *u, struct uc_ctx *c)
{
    memset(c, 0, sizeof(*c));
    for (size_t i = 0; i < u->count && c->nw < UC_MAX_WORDS; i++) {
        const char *w = u->words[i];
        if (!w || w[0] == '-' || strpbrk(w, "=."))
            break;
        if (!uc_fold(c->folded[c->nw], w, strlen(w)))
            break;
        c->words[c->nw++] = w;
    }
    char joined[UC_PATH_MAX] = "";
    for (size_t k = 0; k < c->nw; k++) {
        size_t have = strlen(joined);
        int w = snprintf(joined + have, sizeof(joined) - have, "%s%s",
                         k ? "." : "", c->words[k]);
        const struct zcl_command_spec *s =
            w > 0 && (size_t)w < sizeof(joined) - have
                ? zcl_command_registry_find(reg, joined, NULL)
                : NULL;
        if (!s || s->mode != ZCL_COMMAND_MODE_BRANCH)
            break;
        c->k0 = k + 1;
        snprintf(c->prefix, sizeof(c->prefix), "%s", s->path);
    }
}

/* With no valid prefix, the registry root nearest to the wrong first word. */
static void uc_nearest_root(const struct zcl_command_registry *reg,
                            struct uc_ctx *c)
{
    int best = -1;
    for (size_t i = 0; c->nw > 0 && i < reg->count; i++) {
        const char *path = reg->commands[i].path;
        const char *dot = strchr(path, '.');
        char seg[UC_SEG_MAX];
        size_t len = dot ? (size_t)(dot - path) : strlen(path);
        if (!uc_fold(seg, path, len))
            continue;
        int cost = uc_seg_cost(c->folded[0], seg);
        if (cost >= 0 && (best < 0 || cost < best)) {
            best = cost;
            snprintf(c->prefix, sizeof(c->prefix), "%.*s", (int)len, path);
        }
    }
}

static bool uc_push_next(struct json_value *next, const char *command,
                         const char *key, const char *value,
                         const char *reason)
{
    struct json_value item, input;
    json_init(&item);
    json_init(&input);
    json_set_object(&item);
    json_set_object(&input);
    bool ok = (!key || json_push_kv_str(&input, key, value)) &&
              json_push_kv_str(&item, "command", command) &&
              json_push_kv(&item, "input", &input) &&
              json_push_kv_str(&item, "reason", reason) &&
              json_push_back(next, &item);
    json_free(&input);
    json_free(&item);
    return ok;
}

static bool uc_build_next(struct json_value *next, const struct uc_ctx *c,
                          const struct uc_pick *picks, size_t n,
                          const struct uc_pick *risky, const char *query)
{
    bool ok = true;
    for (size_t i = 0; ok && i < n; i++)
        ok = uc_push_next(next, picks[i].path, NULL, NULL, "nearest command");
    if (ok && risky->path)
        ok = uc_push_next(next, "discover.describe", "path", risky->path,
                          "similar command changes state; read its contract "
                          "before running it");
    if (ok && query && query[0])
        ok = uc_push_next(next, "discover.search", "query", query,
                          "search for the intended command");
    if (!ok)
        return false;
    return c->prefix[0]
               ? uc_push_next(next, "discover.help", "path", c->prefix,
                              "list this group's commands")
               : uc_push_next(next, "discover.help", NULL, NULL,
                              "browse the command tree");
}

size_t zcl_native_unknown_command_json(const struct zcl_command_registry *reg,
                                       const struct zcl_unknown_command *u,
                                       char *out, size_t cap)
{
    if (!reg || !u || !u->command || !out || cap == 0)
        return 0;
    struct uc_ctx c;
    struct uc_pick picks[UC_MAX_SUGGEST];
    uc_parse(reg, u, &c);
    struct uc_pick risky;
    size_t n = uc_collect(reg, &c, picks, &risky);
    if (c.k0 == 0)
        uc_nearest_root(reg, &c);

    struct json_value next;
    json_init(&next);
    json_set_array(&next);
    size_t len = 0;
    if (uc_build_next(&next, &c, picks, n, &risky, u->query))
        len = zcl_native_error_json(u->command, "UNKNOWN_COMMAND", "resolve",
                                    u->message, u->evidence,
                                    "search for the intended command", &next,
                                    out, cap);
    json_free(&next);
    return len < cap ? len : 0;
}
