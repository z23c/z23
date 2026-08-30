/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pure primitives behind dev.agent.* — SUITE VERDICT parsing, the
 *          deterministic one-line source mutation, and checkout-root
 *          resolution. No process is spawned and no file is written here, so
 *          a registered test group can prove every rule in microseconds. */

#include "command/native_devagent.h"

#include "base/safe_alloc.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── SUITE VERDICT ─────────────────────────────────────────────────────── */

static const char *dva_field(const char *line, const char *key)
{
    size_t key_len = strlen(key);
    for (const char *p = line; (p = strstr(p, key)) != NULL; p += key_len) {
        /* A field name starts a token: the byte before it is start-of-line or
         * whitespace. Without this, `groups_total=` also matches inside a
         * hypothetical `sub_groups_total=`. */
        if (p != line && p[-1] != ' ' && p[-1] != '\t')
            continue;
        if (p[key_len] != '=')
            continue;
        return p + key_len + 1;
    }
    return NULL;
}

static long long dva_int_field(const char *line, const char *key)
{
    const char *v = dva_field(line, key);
    if (!v)
        return -1;
    char *end = NULL;
    long long value = strtoll(v, &end, 10);
    /* An empty or non-numeric value is a missing field, not a zero. */
    if (end == v)
        return -1;
    return value;
}

static void dva_str_field(const char *line, const char *key, char *out,
                          size_t cap)
{
    out[0] = '\0';
    const char *v = dva_field(line, key);
    if (!v)
        return;
    size_t n = 0;
    while (v[n] && v[n] != ' ' && v[n] != '\t' && v[n] != '\n' &&
           v[n] != '\r' && n + 1 < cap)
        n++;
    memcpy(out, v, n);
    out[n] = '\0';
}

bool zcl_devagent_verdict_parse(const char *text,
                                struct zcl_devagent_verdict *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->groups_total = -1;
    out->groups_ran = -1;
    out->groups_cached = -1;
    out->groups_gated = -1;
    out->groups_failed = -1;
    out->self_skips = -1;
    out->env_unobserved = -1;
    if (!text)
        return false;

    /* The LAST occurrence wins: a captured transcript can quote the runner's
     * own explanatory prose about the verdict line before printing it. */
    const char *hit = NULL;
    for (const char *p = text; (p = strstr(p, "SUITE VERDICT ")) != NULL; p++)
        hit = p;
    if (!hit)
        return false;

    char line[512];
    size_t n = 0;
    while (hit[n] && hit[n] != '\n' && hit[n] != '\r' && n + 1 < sizeof(line))
        n++;
    memcpy(line, hit, n);
    line[n] = '\0';

    out->present = true;
    dva_str_field(line, "mode", out->mode, sizeof(out->mode));
    dva_str_field(line, "toolkey", out->toolkey, sizeof(out->toolkey));
    out->groups_total = dva_int_field(line, "groups_total");
    out->groups_ran = dva_int_field(line, "groups_ran");
    out->groups_cached = dva_int_field(line, "groups_cached");
    out->groups_gated = dva_int_field(line, "groups_gated");
    out->groups_failed = dva_int_field(line, "groups_failed");
    out->self_skips = dva_int_field(line, "self_skips");
    out->env_unobserved = dva_int_field(line, "env_unobserved");
    out->hotswap = dva_field(line, "hotswap_module") != NULL;
    return true;
}

/* ── single-line mutation ──────────────────────────────────────────────── */

static bool dva_ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* Mark every byte of `line` that is real code (1) versus string/char literal
 * or trailing comment (0). One line in isolation cannot see an enclosing
 * block comment, which is why an obviously-comment line is refused by the
 * caller before this runs. */
static void dva_code_mask(const char *line, size_t len, unsigned char *mask)
{
    bool in_str = false, in_chr = false;
    for (size_t i = 0; i < len; i++) {
        char c = line[i];
        if (in_str || in_chr) {
            mask[i] = 0;
            if (c == '\\' && i + 1 < len) {
                mask[i + 1] = 0;
                i++;
                continue;
            }
            if (in_str && c == '"') in_str = false;
            else if (in_chr && c == '\'') in_chr = false;
            continue;
        }
        if (c == '"') { in_str = true; mask[i] = 0; continue; }
        if (c == '\'') { in_chr = true; mask[i] = 0; continue; }
        if (c == '/' && i + 1 < len && (line[i + 1] == '/' || line[i + 1] == '*')) {
            /* Rest of the line is comment for our purposes: a `/ * ... * /`
             * that closes and resumes code on the same line is rare enough
             * that treating it as comment only ever costs a refusal. */
            while (i < len) mask[i++] = 0;
            return;
        }
        mask[i] = 1;
    }
}

struct dva_op_rule {
    const char *from;
    const char *to;
    const char *name;
};

/* Order is priority: the first rule that matches at the leftmost code
 * position wins. Comparison and boolean-connective flips come first because
 * they are the mutations a real assertion is most likely to be asleep on. */
static const struct dva_op_rule g_op_rules[] = {
    { "==", "!=", "eq_to_ne" },
    { "!=", "==", "ne_to_eq" },
    { "&&", "||", "and_to_or" },
    { "||", "&&", "or_to_and" },
    { "<=", "<",  "le_to_lt" },
    { ">=", ">",  "ge_to_gt" },
};

/* `<=` inside `<<=` and `>=` inside `>>=` are compound assignments, not
 * comparisons; flipping them yields a syntax error rather than a behaviour
 * change, which reports as "the compiler noticed" and teaches nothing. */
static bool dva_op_applies(const char *line, size_t i, const char *from)
{
    if (from[0] == '<' && i > 0 && line[i - 1] == '<') return false;
    if (from[0] == '>' && i > 0 && line[i - 1] == '>') return false;
    if (from[0] == '=' && i > 0 &&
        (line[i - 1] == '!' || line[i - 1] == '<' || line[i - 1] == '>' ||
         line[i - 1] == '='))
        return false;
    return true;
}

static bool dva_word_at(const char *line, size_t len, size_t i, const char *w)
{
    size_t wl = strlen(w);
    if (i + wl > len || memcmp(line + i, w, wl) != 0)
        return false;
    if (i > 0 && dva_ident_char(line[i - 1]))
        return false;
    if (i + wl < len && dva_ident_char(line[i + wl]))
        return false;
    return true;
}

/* A decimal integer literal that is a token on its own: not the tail of an
 * identifier, not a hex digit run, not part of a float or a version-ish
 * dotted number. Returns its length, or 0. */
static size_t dva_int_literal_at(const char *line, size_t len, size_t i)
{
    if (line[i] < '0' || line[i] > '9')
        return 0;
    if (i > 0 && (dva_ident_char(line[i - 1]) || line[i - 1] == '.' ||
                  line[i - 1] == 'x' || line[i - 1] == 'X'))
        return 0;
    size_t n = 0;
    while (i + n < len && line[i + n] >= '0' && line[i + n] <= '9')
        n++;
    if (i + n < len && (dva_ident_char(line[i + n]) || line[i + n] == '.'))
        return 0;
    return n;
}

static bool dva_emit(const char *line, size_t at, size_t from_len,
                     const char *to, char *out, size_t out_cap)
{
    size_t tail = strlen(line + at + from_len);
    size_t need = at + strlen(to) + tail + 1;
    if (need > out_cap)
        return false;
    memcpy(out, line, at);
    memcpy(out + at, to, strlen(to));
    memcpy(out + at + strlen(to), line + at + from_len, tail + 1);
    return true;
}

bool zcl_devagent_mutate_line(const char *line, struct zcl_devagent_mutation *m,
                              char *out, size_t out_cap)
{
    if (!line || !m || !out || out_cap == 0)
        return false;
    memset(m, 0, sizeof(*m));
    out[0] = '\0';
    size_t len = strlen(line);
    if (len == 0 || len > 4096)
        return false;

    unsigned char *mask = zcl_calloc(len, 1, "devagent.code_mask");
    if (!mask)
        return false;
    dva_code_mask(line, len, mask);

    bool done = false;
    for (size_t i = 0; i < len && !done; i++) {
        if (!mask[i])
            continue;
        for (size_t r = 0; r < sizeof(g_op_rules) / sizeof(g_op_rules[0]); r++) {
            const struct dva_op_rule *rule = &g_op_rules[r];
            size_t fl = strlen(rule->from);
            if (i + fl > len || memcmp(line + i, rule->from, fl) != 0)
                continue;
            if (!mask[i + fl - 1] || !dva_op_applies(line, i, rule->from))
                continue;
            if (!dva_emit(line, i, fl, rule->to, out, out_cap))
                break;
            (void)snprintf(m->rule, sizeof(m->rule), "%s", rule->name);
            (void)snprintf(m->before, sizeof(m->before), "%s", rule->from);
            (void)snprintf(m->after, sizeof(m->after), "%s", rule->to);
            m->column = i + 1;
            done = true;
            break;
        }
        if (done)
            break;
        if (dva_word_at(line, len, i, "true")) {
            if (!dva_emit(line, i, 4, "false", out, out_cap))
                break;
            (void)snprintf(m->rule, sizeof(m->rule), "%s", "true_to_false");
            (void)snprintf(m->before, sizeof(m->before), "%s", "true");
            (void)snprintf(m->after, sizeof(m->after), "%s", "false");
            m->column = i + 1;
            done = true;
            break;
        }
        if (dva_word_at(line, len, i, "false")) {
            if (!dva_emit(line, i, 5, "true", out, out_cap))
                break;
            (void)snprintf(m->rule, sizeof(m->rule), "%s", "false_to_true");
            (void)snprintf(m->before, sizeof(m->before), "%s", "false");
            (void)snprintf(m->after, sizeof(m->after), "%s", "true");
            m->column = i + 1;
            done = true;
            break;
        }
        size_t digits = dva_int_literal_at(line, len, i);
        if (digits > 0 && digits < ZCL_DEVAGENT_TOKEN_MAX - 1) {
            char before[ZCL_DEVAGENT_TOKEN_MAX];
            char after[ZCL_DEVAGENT_TOKEN_MAX];
            memcpy(before, line + i, digits);
            before[digits] = '\0';
            long long value = strtoll(before, NULL, 10);
            if (value == LLONG_MAX)
                break;
            int n = snprintf(after, sizeof(after), "%lld", value + 1);
            if (n <= 0 || (size_t)n >= sizeof(after))
                break;
            if (!dva_emit(line, i, digits, after, out, out_cap))
                break;
            (void)snprintf(m->rule, sizeof(m->rule), "%s", "int_bump");
            (void)snprintf(m->before, sizeof(m->before), "%s", before);
            (void)snprintf(m->after, sizeof(m->after), "%s", after);
            m->column = i + 1;
            done = true;
            break;
        }
    }
    free(mask);
    if (!done) {
        memset(m, 0, sizeof(*m));
        out[0] = '\0';
    }
    return done;
}

/* ── checkout root ─────────────────────────────────────────────────────── */

static bool dva_marker_present(const char *dir, const char *rel)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, rel);
    return n > 0 && (size_t)n < sizeof(path) && access(path, R_OK) == 0;
}

bool zcl_devagent_checkout_root(const char *start, char *out, size_t out_cap)
{
    if (!out || out_cap == 0)
        return false;
    out[0] = '\0';
    char dir[PATH_MAX];
    if (start && start[0]) {
        if (snprintf(dir, sizeof(dir), "%s", start) < 0)
            return false;
    } else if (!getcwd(dir, sizeof(dir))) {
        return false;
    }
    /* Bounded walk: a checkout is never 40 directories deep inside itself,
     * and an unbounded loop on a symlinked path is how a "read" command
     * becomes a hang. */
    for (int depth = 0; depth < 40; depth++) {
        if (dva_marker_present(dir, "Makefile") &&
            dva_marker_present(dir, "config/commands/root.def") &&
            dva_marker_present(dir, "tools/dev/test_group_catalog.def")) {
            int n = snprintf(out, out_cap, "%s", dir);
            return n > 0 && (size_t)n < out_cap;
        }
        char *slash = strrchr(dir, '/');
        if (!slash || slash == dir)
            break;
        *slash = '\0';
    }
    out[0] = '\0';
    return false;
}
