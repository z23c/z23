/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-hidden-return-under-lock — a hidden-return macro
 * (LOG_FAIL, LOG_RETURN, GUARD_NOT_NULL, GUARD_NOT_NULL_RET_NULL,
 * GUARD_NOT_NULL_ERR; platform/modules/util/include/util/log_macros.h) must
 * not appear while a lock taken by a direct call is still held. Selftest:
 * gate_hidden_return_under_lock_selftest.c.
 *
 * WHY: those macros expand to a `return`. Written between a lock and its
 * unlock, the return leaks the lock and the next taker of it deadlocks. The
 * reader sees a log line, not an exit (zslp_command_prevouts_in_range held
 * wallet->cs across a LOG_FAIL; the fix is LOG_ERROR plus the unlock).
 *
 * HOW: one linear scan per function (brace depth 0 -> 1 starts a function and
 * depth 0 ends it), on the line with comments and literals blanked.
 *   - A lock call (zcl_mutex_lock, pthread_mutex_lock, platform_mutex_lock,
 *     zcl_rwlock_rdlock/wrlock, pthread_rwlock_rdlock/wrlock) adds its
 *     argument to the held set; the matching unlock call (same argument, else
 *     the most recent lock) removes it. Closing the block the lock was taken
 *     in drops it too.
 *   - trylock and timed or bounded locks are different identifiers and are
 *     not matched.
 *   - The failure branch of the acquire is exempt: a lock call inside an
 *     if/while condition (not followed by "== 0"), or a lock result stored in
 *     a variable that the next `if` tests, exempts the statement or block
 *     that the if guards.
 *   - Preprocessor lines (and their continuations) are skipped.
 * Scope: .c files under core engine contexts platform tools apps cognition;
 * vendor/ and tests/ directories and contexts/commons/corpus/ are skipped.
 * Zero baseline: a finding is a failure; fix the code, never the gate.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_hidden_return_under_lock_priv.h"

static const char k_hrl_gate[] = "check-hidden-return-under-lock";
static const char *const k_hrl_roots[] = {
    "core", "engine", "contexts", "platform", "tools", "apps", "cognition",
};
static const char *const k_hrl_lock[] = {
    "zcl_mutex_lock", "pthread_mutex_lock", "platform_mutex_lock",
    "zcl_rwlock_rdlock", "zcl_rwlock_wrlock",
    "pthread_rwlock_rdlock", "pthread_rwlock_wrlock",
};
static const char *const k_hrl_unlock[] = {
    "zcl_mutex_unlock", "pthread_mutex_unlock", "platform_mutex_unlock",
    "zcl_rwlock_unlock", "pthread_rwlock_unlock", "platform_rwlock_unlock",
};
static const char *const k_hrl_macro[] = {
    "LOG_FAIL", "LOG_RETURN", "GUARD_NOT_NULL", "GUARD_NOT_NULL_RET_NULL",
    "GUARD_NOT_NULL_ERR",
};

enum { HRL_HELD = 16, HRL_KEY = 96, HRL_FLOOR = 1000 };

struct hrl_held {
    char key[HRL_KEY];
    long depth; /* brace depth at the acquire */
    long line;
};

struct hrl_st {
    struct cstrip cs;
    const char *path;
    FILE *out;
    long lineno, depth, ex_base;
    int parens, nheld, cont, chk_next, ex_stmt, ex_blk, findings, bad;
    struct hrl_held held[HRL_HELD];
};

static int hrl_in(const char *const *tab, size_t n, const char *id, size_t len)
{
    for (size_t i = 0; i < n; i++)
        if (strlen(tab[i]) == len && memcmp(tab[i], id, len) == 0)
            return 1;
    return 0;
}

#define HRL_IN(tab, id, len) hrl_in(tab, sizeof tab / sizeof tab[0], id, len)

/* Copies the call argument at code[open] == '(' into key without blanks or
 * a leading '&'. Stops at the matching ')' or the end of the line. */
static void hrl_key(const char *code, size_t open, char *key)
{
    size_t o = 0;
    int d = 0;
    for (size_t i = open; code[i]; i++) {
        if (code[i] == '(')
            d++;
        else if (code[i] == ')' && --d == 0)
            break;
        if (i == open || code[i] == ' ' || code[i] == '\t')
            continue;
        if (code[i] == '&' && o == 0)
            continue;
        if (o + 1 < HRL_KEY)
            key[o++] = code[i];
    }
    key[o] = '\0';
}

/* Index just past the ')' closing the call at code[open], or the line end. */
static size_t hrl_call_end(const char *code, size_t open)
{
    int d = 0;
    size_t i = open;
    for (; code[i]; i++) {
        if (code[i] == '(')
            d++;
        else if (code[i] == ')' && --d == 0)
            return i + 1;
    }
    return i;
}

static int hrl_prefix_has_word(const char *code, size_t upto, const char *w)
{
    size_t wl = strlen(w);
    for (size_t i = 0; i + wl <= upto; i++) {
        if (memcmp(code + i, w, wl) != 0)
            continue;
        if (i > 0 && lintc_ident_char((unsigned char)code[i - 1]))
            continue;
        if (i + wl < upto && lintc_ident_char((unsigned char)code[i + wl]))
            continue;
        return 1;
    }
    return 0;
}

static int hrl_prefix_assigns(const char *code, size_t upto)
{
    for (size_t i = 0; i < upto; i++)
        if (code[i] == '=' && (i + 1 >= upto || code[i + 1] != '=')
            && (i == 0 || (code[i - 1] != '=' && code[i - 1] != '!'
                           && code[i - 1] != '<' && code[i - 1] != '>')))
            return 1;
    return 0;
}

static void hrl_release(struct hrl_st *s, const char *key)
{
    int at = s->nheld - 1;
    for (int i = s->nheld - 1; i >= 0; i--)
        if (strcmp(s->held[i].key, key) == 0) {
            at = i;
            break;
        }
    if (at < 0)
        return;
    for (int i = at; i + 1 < s->nheld; i++)
        s->held[i] = s->held[i + 1];
    s->nheld--;
}

static void hrl_acquire(struct hrl_st *s, const char *code, size_t id,
                        size_t open)
{
    struct hrl_held h;
    memset(&h, 0, sizeof h);
    hrl_key(code, open, h.key);
    h.depth = s->depth;
    h.line = s->lineno;
    if (s->nheld == HRL_HELD) {
        for (int i = 0; i + 1 < HRL_HELD; i++)
            s->held[i] = s->held[i + 1];
        s->nheld--;
    }
    s->held[s->nheld++] = h;
    if (s->parens > 0
        && (hrl_prefix_has_word(code, id, "if")
            || hrl_prefix_has_word(code, id, "while"))) {
        size_t e = hrl_call_end(code, open);
        size_t k = lc_skip_ws(code, e, strlen(code));
        if (strncmp(code + k, "== 0", 4) != 0
            && strncmp(code + k, "==0", 3) != 0) {
            s->ex_stmt = 1;
            s->ex_base = s->depth;
        }
    } else if (s->parens == 0 && hrl_prefix_assigns(code, id)) {
        s->chk_next = 1;
    }
}

static void hrl_macro(struct hrl_st *s, const char *id, size_t len)
{
    if (s->nheld == 0 || s->ex_stmt || s->ex_blk)
        return;
    const struct hrl_held *h = &s->held[s->nheld - 1];
    fprintf(s->out, "%s:%ld: %.*s returns while lock %s (taken at line %ld) "
            "is held\n", s->path, s->lineno, (int)len, id, h->key, h->line);
    s->findings++;
}

static void hrl_ident(struct hrl_st *s, const char *code, size_t i, size_t j)
{
    size_t k = lc_skip_ws(code, j, strlen(code));
    const char *id = code + i;
    size_t len = j - i;
    if (code[k] != '(' || (i > 0 && (code[i - 1] == '.' || code[i - 1] == '>')))
        return;
    if (HRL_IN(k_hrl_lock, id, len))
        hrl_acquire(s, code, i, k);
    else if (HRL_IN(k_hrl_unlock, id, len)) {
        char key[HRL_KEY];
        hrl_key(code, k, key);
        hrl_release(s, key);
    } else if (HRL_IN(k_hrl_macro, id, len))
        hrl_macro(s, id, len);
}

static void hrl_close(struct hrl_st *s)
{
    if (s->depth < 0)
        s->depth = 0;
    if (s->ex_blk && s->depth <= s->ex_base)
        s->ex_blk = 0;
    while (s->nheld > 0 && s->held[s->nheld - 1].depth > s->depth)
        s->nheld--;
    if (s->depth == 0) {
        s->nheld = 0;
        s->ex_stmt = s->ex_blk = s->chk_next = 0;
    }
}

static void hrl_punct(struct hrl_st *s, char c)
{
    if (c == '(')
        s->parens++;
    else if (c == ')' && s->parens > 0)
        s->parens--;
    else if (c == ';') {
        s->parens = 0;
        s->ex_stmt = 0;
    } else if (c == '{') {
        s->parens = 0;
        if (s->ex_stmt) {
            s->ex_stmt = 0;
            s->ex_blk = 1;
        }
        s->depth++;
    } else if (c == '}') {
        s->parens = 0;
        s->depth--;
        hrl_close(s);
    }
}

static void hrl_code(struct hrl_st *s, const char *code)
{
    size_t n = strlen(code);
    size_t first = lc_skip_ws(code, 0, n);
    if (s->chk_next && first < n) {
        if (strncmp(code + first, "if", 2) == 0 && !strstr(code, "== 0")) {
            s->ex_stmt = 1;
            s->ex_base = s->depth;
        }
        s->chk_next = 0;
    }
    for (size_t i = 0; i < n;) {
        if (lintc_ident_start((unsigned char)code[i])
            && (i == 0 || !lintc_ident_char((unsigned char)code[i - 1]))) {
            size_t j = i;
            while (j < n && lintc_ident_char((unsigned char)code[j]))
                j++;
            hrl_ident(s, code, i, j);
            i = j;
        } else {
            hrl_punct(s, code[i]);
            i++;
        }
    }
}

static int hrl_line(void *ctx, const char *line, size_t len)
{
    struct hrl_st *s = ctx;
    char code[CSTRIP_LINE_MAX];
    s->lineno++;
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        len--;
    int was_cont = s->cont;
    s->cont = len > 0 && line[len - 1] == '\\';
    size_t first = lc_skip_ws(line, 0, len);
    if (was_cont || (first < len && line[first] == '#'))
        return 0;
    if (!cstrip_line(&s->cs, line, len, code, sizeof code)) {
        fprintf(stderr, "%s: line %ld of %s exceeds %d bytes\n", k_hrl_gate,
                s->lineno, s->path, CSTRIP_LINE_MAX);
        s->bad = 1;
        return 2;
    }
    hrl_code(s, code);
    return 0;
}

int hrl_scan_file(const char *path, FILE *out, int *findings)
{
    struct hrl_st st;
    struct hrl_st *s = &st;
    memset(s, 0, sizeof *s);
    s->path = path;
    s->out = out;
    int rc = lc_each_line(path, hrl_line, s, 0);
    *findings += s->findings;
    return rc ? 2 : 0;
}

struct hrl_walk {
    FILE *out;
    int findings, files, rc;
};

static int hrl_skip_path(const char *path)
{
    return strstr(path, "/vendor/") || strstr(path, "/tests/")
        || strstr(path, "contexts/commons/corpus/");
}

static int hrl_on_file(const char *path, void *ctx)
{
    struct hrl_walk *w = ctx;
    if (hrl_skip_path(path))
        return 0;
    w->files++;
    return hrl_scan_file(path, w->out, &w->findings);
}

int hrl_check_root(const char *root, FILE *out)
{
    struct hrl_walk w = { .out = out };
    char dir[1024];
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_hrl_roots / sizeof k_hrl_roots[0];
         i++) {
        if (ovf(snprintf(dir, sizeof dir, "%s/%s", root, k_hrl_roots[i]),
                sizeof dir))
            return 2;
        rc = walk_src_root(k_hrl_gate, dir, 0, hrl_on_file, &w);
    }
    if (rc)
        return 2;
    if (gate_require_scanned(w.files, HRL_FLOOR, k_hrl_gate,
                             "expected thousands of .c files under the roots"))
        return 2;
    if (w.findings == 0) {
        fprintf(out, "%s: OK -- %d files, no hidden return under a held lock\n",
                k_hrl_gate, w.files);
        return 0;
    }
    fprintf(out,
            "%s: FAIL -- %d hidden return(s) while a lock is held\n"
            "FIX: LOG_FAIL, LOG_RETURN and the GUARD_NOT_NULL family return from the\n"
            "function. Under a lock use LOG_ERROR, unlock, then return explicitly.\n",
            k_hrl_gate, w.findings);
    return 1;
}

int check_hidden_return_under_lock_run(int argc, char **argv)
{
    const char *root = argc >= 1 ? argv[0] : ".";
    return hrl_check_root(root, stdout);
}
