/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the failure-log half of dev.batch.culprit: the path extraction of
 *          drop_culprit() in the gate-submit.sh bridge, line for line. Paths
 *          come only from the failure lines; compiler command lines and a
 *          gate's informational "shrank" and selftest lines are skipped; the
 *          shared ratchet files never count. */

#include "command/native_dev_batch_culprit.h"

#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* ── the string set ────────────────────────────────────────────────────── */

void cp_set_free(struct cp_set *s)
{
    size_t i;
    for (i = 0; i < s->n; i++)
        free(s->v[i]);
    free(s->v);
    memset(s, 0, sizeof(*s));
}

bool cp_set_has(const struct cp_set *s, const char *str)
{
    size_t i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->v[i], str) == 0)
            return true;
    return false;
}

static bool cp_set_grow(struct cp_set *s)
{
    size_t cap = s->cap ? s->cap * 2 : 64;
    char **grown;
    if (s->n < s->cap)
        return true;
    grown = zcl_realloc(s->v, cap * sizeof(*grown), "cp_set");
    if (!grown)
        return false;
    s->v = grown;
    s->cap = cap;
    return true;
}

bool cp_set_add(struct cp_set *s, const char *str, size_t len)
{
    char *copy;
    size_t i;
    for (i = 0; i < s->n; i++)
        if (strlen(s->v[i]) == len && memcmp(s->v[i], str, len) == 0)
            return true;
    if (!cp_set_grow(s))
        return false;
    copy = zcl_malloc(len + 1, "cp_set_str");
    if (!copy)
        return false;
    memcpy(copy, str, len);
    copy[len] = '\0';
    s->v[s->n++] = copy;
    return true;
}

static int cp_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void cp_set_sort(struct cp_set *s)
{
    if (s->n > 1)
        qsort(s->v, s->n, sizeof(*s->v), cp_cmp);
}

/* ── line tests ────────────────────────────────────────────────────────── */

static bool cp_has(const char *l, size_t n, const char *needle)
{
    size_t m = strlen(needle), i;
    for (i = 0; i + m <= n; i++)
        if (l[i] == needle[0] && memcmp(l + i, needle, m) == 0)
            return true;
    return false;
}

static bool cp_starts(const char *l, size_t n, const char *prefix)
{
    size_t m = strlen(prefix);
    return n >= m && memcmp(l, prefix, m) == 0;
}

/* grep 'CAP_[A-Z_]* ': a capability row the failure prints for the fixer. */
static bool cp_cap_row(const char *l, size_t n)
{
    size_t i, m;
    for (i = 0; i + 4 <= n; i++) {
        if (memcmp(l + i, "CAP_", 4) != 0)
            continue;
        m = i + 4;
        while (m < n && ((l[m] >= 'A' && l[m] <= 'Z') || l[m] == '_'))
            m++;
        if (m < n && l[m] == ' ')
            return true;
    }
    return false;
}

bool cp_log_fix_printed(const struct db_text *log)
{
    size_t pos = 0, len;
    const char *line;
    while (db_next_line(log, &pos, &line, &len))
        if (cp_has(line, len, "Delete them from") ||
            cp_has(line, len, "Shrink the row") || cp_cap_row(line, len))
            return true;
    return false;
}

/* Lines that name every file whatever failed. */
static bool cp_noise(const char *l, size_t n)
{
    static const char *const bad[] = {"zcc cc ", "clang -std", "gcc -std",
                                      "shrank", "selftest", "is expected",
                                      "scanned in"};
    size_t i;
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        if (cp_has(l, n, bad[i]))
            return true;
    return false;
}

static bool cp_preamble(const char *l, size_t n)
{
    return cp_starts(l, n, "devbuild:") || cp_starts(l, n, "gen_templates:") ||
           cp_starts(l, n, "make: ") || cp_starts(l, n, "r2gate:");
}

static bool cp_has_fail_mark(const struct db_text *log)
{
    size_t pos = 0, len;
    const char *line;
    while (db_next_line(log, &pos, &line, &len))
        if (cp_has(line, len, "FAIL log:") || cp_starts(line, len, "FAIL: "))
            return true;
    return false;
}

/* grep -A40 'FAIL log:', grep -A20 '^FAIL: ' and the three keywords. */
struct cp_sel {
    unsigned after_log, after_fail;
};

static bool cp_failure_line(struct cp_sel *s, const char *l, size_t n)
{
    bool sel = false;
    if (s->after_log) {
        sel = true;
        s->after_log--;
    }
    if (s->after_fail) {
        sel = true;
        s->after_fail--;
    }
    if (cp_has(l, n, "FAIL log:")) {
        sel = true;
        s->after_log = 40;
    }
    if (cp_starts(l, n, "FAIL: ")) {
        sel = true;
        s->after_fail = 20;
    }
    return sel || cp_has(l, n, "VIOLATION") || cp_has(l, n, "error:") ||
           cp_has(l, n, "undeclared");
}

/* ── path extraction ───────────────────────────────────────────────────── */

static bool cp_word(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static bool cp_class(char c)
{
    return cp_word(c) || c == '.' || c == '/' || c == '-';
}

/* The text ends at e with .c .h .sh .md .def or .txt, its dot after at least
 * one name character, and a word boundary after it. */
static bool cp_ext_at(const char *l, size_t n, size_t first, size_t e)
{
    static const char *const ext[] = {"c", "h", "sh", "md", "def", "txt"};
    size_t k;
    if (e < n && cp_word(l[e]))
        return false;
    for (k = 0; k < sizeof(ext) / sizeof(ext[0]); k++) {
        size_t m = strlen(ext[k]);
        if (e >= first + 2 + m && l[e - m - 1] == '.' &&
            memcmp(l + e - m, ext[k], m) == 0)
            return true;
    }
    return false;
}

/* grep -o -E '[A-Za-z0-9_][A-Za-z0-9_./-]*\.(c|h|def|txt|sh|md)\b' */
static bool cp_extract(const char *l, size_t n, struct cp_set *out)
{
    size_t i = 0, j, e;
    while (i < n) {
        if (!cp_word(l[i])) {
            i++;
            continue;
        }
        for (j = i + 1; j < n && cp_class(l[j]); j++)
            ;
        for (e = j; e >= i + 2 && !cp_ext_at(l, n, i, e); e--)
            ;
        if (e < i + 2) {
            i = j;
            continue;
        }
        if (!cp_set_add(out, l + i, e - i))
            return false;
        i = e;
    }
    return true;
}

bool cp_is_ratchet(const char *path)
{
    static const char *const word[] = {"baseline", "budget", "floor"};
    size_t n = strlen(path), k, i, m, r;
    if (n < 15 || strncmp(path, "tools/lint/", 11) != 0 ||
        strcmp(path + n - 4, ".txt") != 0)
        return false;
    for (k = 0; k < sizeof(word) / sizeof(word[0]); k++) {
        m = strlen(word[k]);
        for (i = 11; i + m + 4 <= n; i++) {
            if (memcmp(path + i, word[k], m) != 0)
                continue;
            for (r = i + m; r + 4 < n; r++)
                if (!((path[r] >= 'a' && path[r] <= 'z') || path[r] == '_'))
                    break;
            if (r + 4 == n)
                return true;
        }
    }
    return false;
}

static bool cp_keep_line(bool whole, bool marked, struct cp_sel *sel,
                         const char *l, size_t n)
{
    if (whole)
        return true;
    if (!marked)
        return !cp_preamble(l, n);
    return cp_failure_line(sel, l, n);
}

bool cp_log_paths(const struct db_text *log, bool agent_verify,
                  struct cp_set *out)
{
    bool marked = !agent_verify && cp_has_fail_mark(log);
    struct cp_sel sel = {0, 0};
    struct cp_set all = {0};
    size_t pos = 0, len, i;
    const char *line;
    bool ok = true;
    while (ok && db_next_line(log, &pos, &line, &len))
        if (cp_keep_line(agent_verify, marked, &sel, line, len) &&
            !cp_noise(line, len))
            ok = cp_extract(line, len, &all);
    for (i = 0; ok && i < all.n; i++)
        if (!cp_is_ratchet(all.v[i]))
            ok = cp_set_add(out, all.v[i], strlen(all.v[i]));
    cp_set_free(&all);
    cp_set_sort(out);
    return ok;
}
