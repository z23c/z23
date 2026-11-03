/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: split a gate's command text into argv steps with no shell. The
 * run_lint.sh table writes plain commands (quotes, $VAR, NAME=v prefixes,
 * `&&`); `z23-lint run` parses exactly that and refuses everything else a
 * shell would act on, so a table row it cannot run is an error, never a
 * silently different command.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "run_priv.h"

enum { LW_END, LW_WORD, LW_AND, LW_ERR };

struct lr_lex {
    const char *p;
    struct lr_plan *plan;
    char *err;
    size_t errcap;
    size_t start;
};

static int lex_fail(struct lr_lex *lx, const char *what, char c)
{
    if (c)
        (void)snprintf(lx->err, lx->errcap, "%s '%c'", what, c);
    else
        (void)snprintf(lx->err, lx->errcap, "%s", what);
    return LW_ERR;
}

static int put_char(struct lr_lex *lx, char c)
{
    if (lx->plan->used + 2 >= sizeof lx->plan->pool)
        return lex_fail(lx, "command words exceed the pool", 0);
    lx->plan->pool[lx->plan->used++] = c;
    return LW_WORD;
}

static int put_str(struct lr_lex *lx, const char *s)
{
    for (; *s; s++) {
        if (put_char(lx, *s) == LW_ERR)
            return LW_ERR;
    }
    return LW_WORD;
}

static int ident_start(int c) { return isalpha(c) || c == '_'; }
static int ident_cont(int c) { return isalnum(c) || c == '_'; }

/* At a '$': expand $NAME or ${NAME} from the environment; a bare '$' stays. */
static int expand_var(struct lr_lex *lx)
{
    const char *s = lx->p + 1;
    char name[LR_NAME];
    size_t n = 0;
    int braced = *s == '{';
    if (*s == '(')
        return lex_fail(lx, "command substitution is not supported", 0);
    if (braced)
        s++;
    if (!ident_start((unsigned char)*s)) {
        lx->p++;
        return put_char(lx, '$');
    }
    while (ident_cont((unsigned char)*s) && n + 1 < sizeof name)
        name[n++] = *s++;
    name[n] = '\0';
    if (braced) {
        if (*s != '}')
            return lex_fail(lx, "unterminated ${", 0);
        s++;
    }
    lx->p = s;
    const char *v = getenv(name);
    return v ? put_str(lx, v) : LW_WORD;
}

static int scan_single(struct lr_lex *lx)
{
    lx->p++;
    while (*lx->p && *lx->p != '\'') {
        if (put_char(lx, *lx->p++) == LW_ERR)
            return LW_ERR;
    }
    if (!*lx->p)
        return lex_fail(lx, "unterminated single quote", 0);
    lx->p++;
    return LW_WORD;
}

static int scan_double(struct lr_lex *lx)
{
    lx->p++;
    while (*lx->p && *lx->p != '"') {
        int r;
        if (*lx->p == '$') {
            r = expand_var(lx);
        } else if (*lx->p == '\\' && strchr("\"\\$`", lx->p[1]) && lx->p[1]) {
            lx->p++;
            r = put_char(lx, *lx->p++);
        } else if (*lx->p == '`') {
            return lex_fail(lx, "backtick is not supported", 0);
        } else {
            r = put_char(lx, *lx->p++);
        }
        if (r == LW_ERR)
            return LW_ERR;
    }
    if (!*lx->p)
        return lex_fail(lx, "unterminated double quote", 0);
    lx->p++;
    return LW_WORD;
}

/* One unquoted run or quoted piece appended to the current word. */
static int scan_piece(struct lr_lex *lx)
{
    char c = *lx->p;
    if (c == '\'')
        return scan_single(lx);
    if (c == '"')
        return scan_double(lx);
    if (c == '$')
        return expand_var(lx);
    if (c == '\\' && lx->p[1]) {
        lx->p++;
        return put_char(lx, *lx->p++);
    }
    if (strchr("|;<>()`&", c))
        return lex_fail(lx, "unsupported shell syntax", c);
    return put_char(lx, *lx->p++);
}

static int is_word_end(const char *p)
{
    return !*p || isspace((unsigned char)*p) || (p[0] == '&' && p[1] == '&');
}

/* Next word or operator. A word is stored NUL-terminated in the pool. */
static int next_word(struct lr_lex *lx, char **out)
{
    while (isspace((unsigned char)*lx->p))
        lx->p++;
    if (!*lx->p)
        return LW_END;
    if (lx->p[0] == '&' && lx->p[1] == '&') {
        lx->p += 2;
        return LW_AND;
    }
    lx->start = lx->plan->used;
    while (!is_word_end(lx->p)) {
        if (scan_piece(lx) == LW_ERR)
            return LW_ERR;
    }
    lx->plan->pool[lx->plan->used++] = '\0';
    *out = lx->plan->pool + lx->start;
    return LW_WORD;
}

static int is_assignment(const char *w)
{
    if (!ident_start((unsigned char)*w))
        return 0;
    while (ident_cont((unsigned char)*w))
        w++;
    return *w == '=';
}

static int add_word(struct lr_lex *lx, struct lr_step *st, char *w)
{
    if (st->argc == 0 && is_assignment(w)) {
        if (st->nenv >= LR_MAX_ENV)
            return lex_fail(lx, "too many env assignments", 0);
        st->env[st->nenv++] = w;
        return LW_WORD;
    }
    if (st->argc >= LR_MAX_ARGV)
        return lex_fail(lx, "too many words in one command", 0);
    st->argv[st->argc++] = w;
    st->argv[st->argc] = NULL;
    return LW_WORD;
}

static int close_step(struct lr_lex *lx)
{
    struct lr_plan *pl = lx->plan;
    if (pl->steps[pl->nsteps].argc == 0)
        return lex_fail(lx, "empty command around &&", 0);
    if (++pl->nsteps >= LR_MAX_STEPS)
        return lex_fail(lx, "too many && steps", 0);
    return LW_WORD;
}

/* ---- wrapper rewrite: a check_*.sh that only execs z23-lint ------------ */

static int is_wrapper_path(const char *p)
{
    size_t n = strlen(p);
    return strstr(p, "tools/scripts/check_") && n > 3 && strcmp(p + n - 3, ".sh") == 0;
}

/* Gate named by an `exec "...z23-lint" GATE "$@"` line; 0 if not that shape. */
static int exec_line_gate(const char *line, char *gate, size_t cap)
{
    const char *k = strstr(line, "z23-lint\" ");
    size_t n = 0;
    if (strncmp(line, "exec ", 5) != 0 || !k)
        return 0;
    k += strlen("z23-lint\" ");
    while ((islower((unsigned char)k[n]) || isdigit((unsigned char)k[n]) || k[n] == '-') && n + 1 < cap) {
        gate[n] = k[n];
        n++;
    }
    gate[n] = '\0';
    return n > 0 && strcmp(k + n, " \"$@\"\n") == 0;
}

/* The wrapper's gate when the file holds nothing but comments, blanks and that
 * one exec line. */
static int wrapper_gate(const char *path, char *gate, size_t cap)
{
    FILE *f = fopen(path, "r");
    char line[512];
    int found = 0, other = 0;
    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (!found && exec_line_gate(line, gate, cap))
            found = 1;
        else
            other = 1;
    }
    (void)fclose(f);
    return found && !other;
}

static int pool_dup(struct lr_plan *pl, const char *s, char **out)
{
    size_t n = strlen(s) + 1;
    if (pl->used + n >= sizeof pl->pool)
        return 1;
    memcpy(pl->pool + pl->used, s, n);
    *out = pl->pool + pl->used;
    pl->used += n;
    return 0;
}

/* Rewrite STEP in place to `LINT_BIN GATE rest...` when it runs a pure
 * wrapper (directly or through bash/sh). */
static int unwrap_step(struct lr_plan *pl, struct lr_step *st, const char *lint_bin)
{
    int s = (st->argc > 1 && (!strcmp(st->argv[0], "bash") || !strcmp(st->argv[0], "sh"))) ? 1 : 0;
    char gate[LR_NAME];
    char *argv[LR_MAX_ARGV + 1];
    int n = 0;
    if (st->argc <= s || !is_wrapper_path(st->argv[s])
        || !wrapper_gate(st->argv[s], gate, sizeof gate))
        return 0;
    if (st->argc - s + 1 > LR_MAX_ARGV)
        return 1;
    if (pool_dup(pl, lint_bin, &argv[n++]) || pool_dup(pl, gate, &argv[n++]))
        return 1;
    for (int i = s + 1; i < st->argc; i++)
        argv[n++] = st->argv[i];
    argv[n] = NULL;
    memcpy(st->argv, argv, sizeof argv);
    st->argc = n;
    return 0;
}

static int unwrap_all(struct lr_plan *pl, const char *lint_bin, char *err, size_t cap)
{
    for (int i = 0; lint_bin && i < pl->nsteps; i++) {
        if (unwrap_step(pl, &pl->steps[i], lint_bin)) {
            (void)snprintf(err, cap, "wrapper rewrite exceeds the plan limits");
            return 1;
        }
    }
    return 0;
}

int lr_parse_command(const char *cmd, const char *lint_bin,
                     struct lr_plan *plan, char *err, size_t errcap)
{
    struct lr_lex lx = { cmd, plan, err, errcap, 0 };
    char *w = NULL;
    int k;
    memset(plan, 0, sizeof *plan);
    err[0] = '\0';
    while ((k = next_word(&lx, &w)) != LW_END) {
        if (k == LW_ERR)
            return 1;
        if (k == LW_AND ? close_step(&lx) == LW_ERR
                        : add_word(&lx, &plan->steps[plan->nsteps], w) == LW_ERR)
            return 1;
    }
    if (plan->steps[plan->nsteps].argc == 0) {
        (void)snprintf(err, errcap, "empty command");
        return 1;
    }
    plan->nsteps++;
    return unwrap_all(plan, lint_bin, err, errcap);
}
