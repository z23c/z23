/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-markdown-links of the C23 lint runtime, the
 * replacement for tools/lint/check_markdown_links.sh (bash + embedded
 * Perl). Fail-loud local Markdown target gate: scans tracked Markdown as
 * it exists in the working tree; relative file and directory links must
 * resolve inside the repository. Network/mail/app URIs, page anchors,
 * site-absolute paths, images, fenced/inline-code examples and explicit
 * generated placeholders are intentionally outside this gate. A hollow
 * scan set (no tracked Markdown, none readable, or no local targets at
 * all) refuses with exit 2 instead of reading as clean.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "lintc.h"
#include "lintc_sig.h"

/* Every static name carries the ml_ prefix: the code index links test
 * closures by symbol name. */

enum { ML_TLINE = 8192, ML_PATH = 4096 };

static const char k_ml_gate[] = "check_markdown_links";

/* Output sinks; the self-test captures a run with both streams merged,
 * exactly as the script's 2>&1 did, and silences its stub runs. */
static FILE *g_ml_out = NULL, *g_ml_err = NULL;

static void ml_err_line(const char *fmt, ...)
{
    va_list ap;
    if (!g_ml_err)
        return;
    va_start(ap, fmt);
    vfprintf(g_ml_err, fmt, ap);
    va_end(ap);
    fputc('\n', g_ml_err);
}

static int ml_die(const char *msg)
{
    ml_err_line("%s: FATAL \xE2\x80\x94 %s", k_ml_gate, msg);
    return 2;
}

/* ── inline code stripping: remove every `run ... same-run` span ───────── */

static bool ml_backtick_run(const char *s, size_t *i, size_t *len)
{
    size_t start = *i;
    while (s[*i] == '`')
        (*i)++;
    *len = *i - start;
    return *len > 0;
}

/* The Perl `1 while s/(`+)[^`]*\1//g`: spans carry no backticks inside,
 * and the scan restarts after each removal. in/out are the same buffer. */
static void ml_strip_inline_code(char *line)
{
    size_t i = 0;
    while (line[i]) {
        size_t runlen = 0, j, k;
        if (line[i] != '`') {
            i++;
            continue;
        }
        j = i;
        if (!ml_backtick_run(line, &j, &runlen)) {
            i++;
            continue;
        }
        k = j;
        while (line[k] && line[k] != '`')
            k++;
        if (line[k] != '`')
            break;
        /* The closing run must be the SAME length as the opening one. */
        size_t close = 0;
        while (line[k + close] == '`')
            close++;
        if (close != runlen) {
            i = j;               /* not a span; resume after the run */
            continue;
        }
        memmove(line + i, line + k + close, strlen(line + k + close) + 1);
    }
}

/* ── inline link targets: the CommonMark-shaped hand parser ────────────── */

struct ml_targets {
    char **v;
    size_t n, cap;
};

static int ml_push_target(struct ml_targets *t, const char *start, size_t len)
{
    if (t->n == t->cap) {
        size_t ncap = t->cap ? t->cap * 2 : 32;
        char **grown = zcl_realloc(t->v, ncap * sizeof *grown,
                                   "ml_target_array");
        if (!grown)
            return -1;
        t->v = grown;
        t->cap = ncap;
    }
    char *s = zcl_malloc(len + 1, "ml_target_string");
    if (!s)
        return -1;
    memcpy(s, start, len);
    s[len] = '\0';
    t->v[t->n++] = s;
    return 0;
}

static void ml_free_targets(struct ml_targets *t)
{
    for (size_t i = 0; i < t->n; i++)
        free(t->v[i]);
    free(t->v);
    t->v = NULL;
    t->n = t->cap = 0;
}

/* One '[' at i: find the label's close honoring escapes and nesting; the
 * '(' must follow immediately; then the angle or balanced target. */
/* Depth/escape scan for the label's closing ']': returns its index or
 * (size_t)-1. */
static size_t ml_label_close(const char *line, size_t i)
{
    size_t len = strlen(line), depth = 1, j = i + 1;
    bool escaped = false;
    while (j < len) {
        char ch = line[j];
        if (escaped) {
            escaped = false;
        } else if (ch == '\\') {
            escaped = true;
        } else if (ch == '[') {
            depth++;
        } else if (ch == ']') {
            depth--;
            if (depth == 0)
                return j;
        }
        j++;
    }
    return (size_t)-1;
}

static int ml_target_at(const char *line, size_t i, size_t *next)
{
    size_t len = strlen(line), close, open, pos;
    *next = i;
    if (i > 0 && (line[i - 1] == '!' || line[i - 1] == '\\'))
        return -1;
    close = ml_label_close(line, i);
    if (close == (size_t)-1)
        return -1;
    open = close + 1;
    if (open >= len || line[open] != '(')
        return -1;               /* whitespace here is prose, not a link */
    pos = open + 1;
    while (pos < len && isspace((unsigned char)line[pos]))
        pos++;
    if (pos >= len)
        return -1;
    *next = pos;
    return 0;
}

/* The unangled target: balanced inner parens, honored escapes, ends at
 * unescaped whitespace or the closing paren. Returns the end index. */
static size_t ml_plain_target_end(const char *line, size_t pos)
{
    size_t len = strlen(line), end = pos, parens = 0;
    bool esc = false;
    while (end < len) {
        char ch = line[end];
        if (esc) {
            end++;
            esc = false;
            continue;
        }
        if (ch == '\\') {
            esc = true;
            end++;
            continue;
        }
        if (ch == '(') {
            parens++;
            end++;
            continue;
        }
        if (ch == ')') {
            if (parens == 0)
                break;
            parens--;
            end++;
            continue;
        }
        if (parens == 0 && isspace((unsigned char)ch))
            break;
        end++;
    }
    return end;
}

/* Collects every inline target in line into t (allocated strings). */
static int ml_inline_targets(const char *line, struct ml_targets *t)
{
    size_t len = strlen(line), i = 0;
    while (i < len) {
        size_t pos, end;
        if (line[i] != '[') {
            i++;
            continue;
        }
        if (ml_target_at(line, i, &pos) != 0) {
            i++;
            continue;
        }
        end = pos;
        if (line[pos] == '<') {
            const char *gt = strchr(line + pos + 1, '>');
            if (!gt) {
                i++;
                continue;
            }
            if (ml_push_target(t, line + pos + 1, (size_t)(gt - line - pos - 1)))
                return -1;
            end = (size_t)(gt - line) + 1;
        } else {
            end = ml_plain_target_end(line, pos);
            if (ml_push_target(t, line + pos, end - pos))
                return -1;
        }
        i = end > i ? end : i + 1;
    }
    return 0;
}

/* A reference definition line: up to three leading spaces, then
 * [label]: followed by an angle literal or one word. */
/* The value after "[label]:": an angle literal or one non-space run.
 * Returns 1 with *out owned, 0 when the line is not a definition. */
static int ml_refdef_value(const char *line, size_t i, char **out)
{
    size_t len = strlen(line);
    *out = NULL;
    while (i < len && (line[i] == ' ' || line[i] == '\t'))
        i++;
    if (i >= len)
        return 0;
    if (line[i] == '<') {
        const char *gt = strchr(line + i + 1, '>');
        if (!gt)
            return 0;
        *out = strndup(line + i + 1, (size_t)(gt - line - i - 1));
        return *out ? 1 : -1;
    }
    if (isspace((unsigned char)line[i]))
        return 0;
    {
        size_t start = i;
        while (i < len && !isspace((unsigned char)line[i]))
            i++;
        *out = strndup(line + start, i - start);
        return *out ? 1 : -1;
    }
}

static int ml_refdef_target(const char *line, char **out)
{
    size_t i = 0, len = strlen(line), close;
    while (i < 3 && (line[i] == ' ' || line[i] == '\t'))
        i++;
    if (line[i] != '[')
        return 0;
    close = i + 1;
    while (close < len && line[close] != ']')
        close++;
    if (close >= len || close == i + 1 || line[close + 1] != ':')
        return 0;
    return ml_refdef_value(line, close + 2, out);
}

/* ── target normalization ──────────────────────────────────────────────── */

enum { ML_IGNORED, ML_LOCAL, ML_ESCAPE };

static bool ml_has_dollar_brace(const char *t)
{
    const char *d = strstr(t, "${");
    return d && strchr(d, '}');
}

static bool ml_has_double_brace(const char *t)
{
    const char *d = strstr(t, "{{");
    return d && strchr(d, '}');
}

static bool ml_has_angle(const char *t)
{
    const char *o = strchr(t, '<');
    return o && strchr(o, '>');
}

static bool ml_has_ellipsis_segment(const char *t)
{
    size_t n = strlen(t);
    for (size_t i = 0; i + 3 <= n; i++) {
        if (strncmp(t + i, "...", 3) != 0)
            continue;
        if ((i == 0 || t[i - 1] == '/')
            && (i + 3 == n || t[i + 3] == '/'))
            return true;
        i += 2;
    }
    return false;
}

static bool ml_is_placeholder(const char *t)
{
    if (ml_has_dollar_brace(t) || ml_has_double_brace(t)
        || ml_has_angle(t) || ml_has_ellipsis_segment(t))
        return true;
    if (strchr(t, '*'))
        return true;
    for (const char *p = t; *p; p++)
        if (p[0] == '%' && isalpha((unsigned char)p[1]))
            return true;
    return false;
}

static bool ml_is_scheme(const char *t)
{
    if (!isalpha((unsigned char)t[0]))
        return false;
    size_t i = 1;
    while (isalnum((unsigned char)t[i]) || t[i] == '+' || t[i] == '-'
        || t[i] == '.')
        i++;
    return t[i] == ':';
}

/* Percent-decode (through the one hex codec) and backslash-unescape in
 * place; returns the new end. */
static size_t ml_decode(char *t)
{
    size_t r = 0, w = 0, n = strlen(t);
    while (r < n) {
        uint8_t byte = 0;
        char pair[3];
        if (t[r] == '%' && r + 2 < n) {
            pair[0] = t[r + 1];
            pair[1] = t[r + 2];
            pair[2] = '\0';
            if (zcl_hex_decode(pair, &byte, 1)) {
                t[w++] = (char)byte;
                r += 3;
                continue;
            }
        }
        t[w++] = t[r++];
    }
    t[w] = '\0';
    n = w;
    r = w = 0;
    while (r < n) {
        if (t[r] == '\\' && r + 1 < n && strchr("\\ ()#?", t[r + 1])) {
            t[w++] = t[r + 1];
            r += 2;
            continue;
        }
        t[w++] = t[r++];
    }
    t[w] = '\0';
    return w;
}

enum { ML_PARTS = 512 };

/* git rev-parse's notion of a worktree, as far as this gate observed it:
 * .git must exist and, when it is a directory, carry HEAD. A stray empty
 * .git directory is not a worktree. */
/* Whether the index file exists, through a worktree's gitdir pointer too:
 * git ls-files reads a fresh init's absent index as empty, while the
 * walker treats it as an error. */
static bool ml_index_present(void)
{
    struct stat st;
    char buf[ML_PATH], *nl, idx[ML_PATH];
    FILE *f;
    if (stat(".git", &st) != 0)
        return false;
    if (S_ISDIR(st.st_mode))
        return access(".git/index", F_OK) == 0;
    f = fopen(".git", "r");
    if (!f)
        return false;
    if (!fgets(buf, sizeof buf, f) || strncmp(buf, "gitdir: ", 8) != 0
        || !(nl = strchr(buf, '\n'))) {
        fclose(f);
        return false;
    }
    fclose(f);
    *nl = '\0';
    if (ovf(snprintf(idx, sizeof idx, "%s/index", buf + 8), sizeof idx))
        return false;
    return access(idx, F_OK) == 0;
}

static bool ml_is_worktree(void)
{
    struct stat st;
    char head[ML_PATH];
    if (stat(".git", &st) != 0)
        return false;
    if (!S_ISDIR(st.st_mode))
        return true;             /* a linked worktree's gitdir pointer */
    snprintf(head, sizeof head, "%s", ".git/HEAD");
    return access(head, F_OK) == 0;
}

/* Resolves raw against source's directory; kind is ML_ESCAPE when a '..'
 * pops an empty stack. res may come back empty, as the Perl join did. */
/* Joins the target against the source's directory and collapses the
 * path: '/' runs separate, '.' drops, '..' pops — or escapes when the
 * stack is empty. */
static int ml_join_parts(const char *joined, char *res, size_t cap)
{
    char *parts[ML_PARTS];
    size_t np = 0, used = 0;
    for (char *p = strtok((char *)joined, "/"); p; p = strtok(NULL, "/")) {
        if (strcmp(p, ".") == 0)
            continue;
        if (strcmp(p, "..") == 0) {
            if (np == 0)
                return ML_ESCAPE;
            np--;
            continue;
        }
        if (np >= ML_PARTS)
            return ML_IGNORED;
        parts[np++] = p;
    }
    res[0] = '\0';
    for (size_t i = 0; i < np; i++) {
        int k = snprintf(res + used, cap - used, "%s%s", i ? "/" : "",
                         parts[i]);
        if (ovf(k, cap - used))
            return ML_IGNORED;
        used += (size_t)k;
    }
    return ML_LOCAL;
}

/* The ignore classifications, in the script's exact order. */
static bool ml_trimmed_is_ignored(char *t, size_t n)
{
    if (n == 0 || t[0] == '#' || t[0] == '/' || ml_is_scheme(t)
        || ml_is_placeholder(t))
        return true;
    for (size_t i = 0; i < n; i++) {
        if (t[i] == '#' || t[i] == '?') {
            t[i] = '\0';
            break;
        }
    }
    return t[0] == '\0';
}

static int ml_normalize(const char *source, char *raw, char *res, size_t cap)
{
    char *t = raw;
    char joined[ML_TLINE * 2];
    size_t n = strlen(t), dn = strlen(source);
    while (n > 0 && isspace((unsigned char)t[0])) {
        t++;
        n--;
    }
    while (n > 0 && isspace((unsigned char)t[n - 1]))
        n--;
    t[n] = '\0';
    if (ml_trimmed_is_ignored(t, n))
        return ML_IGNORED;
    ml_decode(t);
    while (dn > 0 && source[dn - 1] != '/')
        dn--;
    if (ovf(snprintf(joined, sizeof joined, "%.*s/%s", (int)dn, source, t),
            sizeof joined))
        return ML_IGNORED;
    return ml_join_parts(joined, res, cap);
}

/* ── the scan itself ───────────────────────────────────────────────────── */

struct ml_broken {
    char src[ML_PATH];
    int line;
    char raw[ML_TLINE];
    char resolved[ML_TLINE * 2];
    const char *why;
};

static struct ml_broken *g_ml_broken;
static size_t g_ml_nbroken, g_ml_bcap;

static const char *k_ml_why_missing = "does not exist";
static const char *k_ml_why_escape = "escapes the repository";
static const char *k_ml_why_symlink =
    "resolves outside repository through a symlink";

static int ml_break(const char *src, int line, const char *raw,
                    const char *resolved, const char *why)
{
    if (g_ml_nbroken == g_ml_bcap) {
        size_t ncap = g_ml_bcap ? g_ml_bcap * 2 : 64;
        struct ml_broken *grown = zcl_realloc(g_ml_broken,
                                          ncap * sizeof *grown, "ml_broken_array");
        if (!grown)
            return -1;
        g_ml_broken = grown;
        g_ml_bcap = ncap;
    }
    struct ml_broken *b = &g_ml_broken[g_ml_nbroken++];
    snprintf(b->src, sizeof b->src, "%s", src);
    b->line = line;
    snprintf(b->raw, sizeof b->raw, "%s", raw);
    snprintf(b->resolved, sizeof b->resolved, "%s", resolved);
    b->why = why;
    return 0;
}

/* Containment after existence: the canonical path must be the root or
 * sit underneath it — a lexically inside link must not escape a symlink. */
static int ml_check_target(const char *source, int line, const char *raw,
                           const char *root, int *local_targets)
{
    char work[ML_TLINE];
    char resolved[ML_TLINE * 2];
    char canonical[ML_PATH];
    int kind;
    /* The Perl @_ copy kept the caller's raw intact for the FAIL row;
     * normalize works on a copy here for the same reason. */
    snprintf(work, sizeof work, "%s", raw);
    kind = ml_normalize(source, work, resolved, sizeof resolved);
    if (kind == ML_LOCAL)
        (*local_targets)++;
    if (kind == ML_ESCAPE)
        return ml_break(source, line, raw, "<outside repository>",
                        k_ml_why_escape);
    if (kind != ML_LOCAL)
        return 0;
    struct stat st;
    if (stat(resolved, &st) != 0)
        return ml_break(source, line, raw, resolved, k_ml_why_missing);
    if (!realpath(resolved, canonical)
        || !(strcmp(canonical, root) == 0
            || (strncmp(canonical, root, strlen(root)) == 0
                && canonical[strlen(root)] == '/')))
        return ml_break(source, line, raw, resolved, k_ml_why_symlink);
    return 0;
}

static bool ml_fence_update(const char *line, char *fence_char,
                            size_t *fence_len)
{
    size_t i = 0;
    char ch;
    size_t n;
    while (line[i] == ' ' || line[i] == '\t')
        i++;
    ch = line[i];
    if (ch != '`' && ch != '~')
        return false;
    n = 0;
    while (line[i + n] == ch)
        n++;
    if (n < 3)
        return false;
    if (!*fence_char) {
        *fence_char = ch;
        *fence_len = n;
    } else if (ch == *fence_char && n >= *fence_len) {
        *fence_char = 0;
        *fence_len = 0;
    }
    return true;
}

static int ml_scan_file(const char *source, const char *root,
                        int *local_targets)
{
    FILE *fh = fopen(source, "r");
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int lineno = 0;
    char fence_char = 0;
    size_t fence_len = 0;
    if (!fh)
        return ml_die("cannot read tracked Markdown");
    while ((n = getline(&line, &lcap, fh)) >= 0) {
        struct ml_targets t = { 0 };
        char *refdef = NULL;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        lineno++;
        if (ml_fence_update(line, &fence_char, &fence_len))
            continue;
        if (fence_char)
            continue;
        ml_strip_inline_code(line);
        if (ml_inline_targets(line, &t) != 0) {
            ml_free_targets(&t);
            free(line);
            fclose(fh);
            return -1;
        }
        if (ml_refdef_target(line, &refdef) < 0) {
            ml_free_targets(&t);
            free(line);
            fclose(fh);
            return -1;
        }
        for (size_t i = 0; i < t.n; i++) {
            if (ml_check_target(source, lineno, t.v[i], root,
                                local_targets) != 0) {
                ml_free_targets(&t);
                free(refdef);
                free(line);
                fclose(fh);
                return -1;
            }
        }
        if (refdef) {
            if (ml_check_target(source, lineno, refdef, root,
                                local_targets) != 0) {
                ml_free_targets(&t);
                free(refdef);
                free(line);
                fclose(fh);
                return -1;
            }
            free(refdef);
        }
        ml_free_targets(&t);
        if (lsc_pending()) {
            free(line);
            fclose(fh);
            return -2;
        }
    }
    int bad = ferror(fh);
    free(line);
    fclose(fh);
    return bad ? ml_die("cannot read tracked Markdown") : 0;
}

struct ml_files { char v[32768][ML_PATH]; int n; };

static int ml_collect_cb(const char *path, int stage, void *ctx)
{
    struct ml_files *f = ctx;
    size_t n;
    (void)stage;
    if (f->n >= (int)(sizeof f->v / sizeof f->v[0]))
        return 0;
    n = strlen(path);
    if (n < 3 || strcmp(path + n - 3, ".md") != 0 || n >= ML_PATH)
        return 0;
    memcpy(f->v[f->n++], path, n + 1);
    return 0;
}

static int ml_broken_cmp(const void *a, const void *b)
{
    const struct ml_broken *x = a, *y = b;
    int r = strcmp(x->src, y->src);
    if (r) return r;
    if (x->line != y->line) return x->line < y->line ? -1 : 1;
    return strcmp(x->raw, y->raw);
}

/* The scan phase over an entered root: enumerates, scans, refuses a
 * hollow set. Returns 0, a gate exit code, or -1 to leave with cwd kept. */
static int ml_scan_all(const char *root, int *scanned, int *local_targets)
{
    static struct ml_files files;
    char badext[8];
    struct stat st;
    /* git ls-files on a freshly initialised repository reads an absent
     * index as empty; the index walker treats it as an error. */
    if (ml_index_present()
        && lint_git_index_foreach(ml_collect_cb, &files, badext) != 0)
        return ml_die("cannot enumerate tracked Markdown");
    if (files.n < 1)
        return ml_die("tracked Markdown scan set is empty");
    for (int i = 0; i < files.n; i++) {
        int rc;
        if (stat(files.v[i], &st) != 0 || !S_ISREG(st.st_mode))
            continue;            /* an in-progress deletion, not a source */
        (*scanned)++;
        rc = ml_scan_file(files.v[i], root, local_targets);
        if (rc == -2)
            return lsc_pending();
        if (rc != 0)
            return rc;
    }
    if (*scanned < 1)
        return ml_die("readable tracked Markdown scan set is empty");
    if (*local_targets < 1)
        return ml_die("parser found zero local Markdown targets");
    return 0;
}

/* The report phase: sorted FAIL rows or the clean receipt. */
static int ml_report(int scanned, int local_targets)
{
    if (g_ml_nbroken > 0) {
        qsort(g_ml_broken, g_ml_nbroken, sizeof *g_ml_broken, ml_broken_cmp);
        for (size_t i = 0; i < g_ml_nbroken; i++)
            ml_err_line("FAIL: %s:%d local Markdown target '%s' resolves "
                        "to '%s' and %s", g_ml_broken[i].src,
                        g_ml_broken[i].line, g_ml_broken[i].raw,
                        g_ml_broken[i].resolved, g_ml_broken[i].why);
        ml_err_line("%s: FAIL \xE2\x80\x94 broken=%zu scanned=%d "
                    "local_targets=%d", k_ml_gate, g_ml_nbroken, scanned,
                    local_targets);
        return 1;
    }
    if (g_ml_out)
        fprintf(g_ml_out, "%s: clean \xE2\x80\x94 scanned=%d "
                "local_targets=%d\n", k_ml_gate, scanned, local_targets);
    return 0;
}

/* The whole gate over one repository root. Exit 0/1/2 semantics. */
static int ml_run(const char *root_arg)
{
    char root[ML_PATH], cwd[ML_PATH];
    int scanned = 0, local_targets = 0, rc;
    struct stat st;
    if (stat(root_arg, &st) != 0 || !S_ISDIR(st.st_mode)) {
        char msg[ML_PATH + 64];
        snprintf(msg, sizeof msg, "root is not a directory: %s", root_arg);
        return ml_die(msg);
    }
    if (!getcwd(cwd, sizeof cwd))
        return ml_die("cannot hold the working directory");
    if (chdir(root_arg) != 0 || !realpath(".", root))
        return ml_die("cannot enter repository root");
    if (!ml_is_worktree()) {
        char msg[ML_PATH + 64];
        snprintf(msg, sizeof msg, "not a Git worktree: %s", root);
        if (chdir(cwd) != 0)
            return 2;
        return ml_die(msg);
    }
    rc = ml_scan_all(root, &scanned, &local_targets);
    if (chdir(cwd) != 0)
        return 2;
    if (rc != 0)
        return rc;
    return ml_report(scanned, local_targets);
}

/* ── self-test ─────────────────────────────────────────────────────────── */

static char g_ml_tmp[4096];

static void ml_rm_tmp(void)
{
    if (g_ml_tmp[0]) {
        rap_rm_rf(g_ml_tmp);
        g_ml_tmp[0] = '\0';
    }
}

static void ml_cleanup_and_finish(void)
{
    int sig = lsc_pending();
    sigset_t all, old;
    sigfillset(&all);
    sigprocmask(SIG_BLOCK, &all, &old);
    ml_rm_tmp();
    if (sig) {
        lsc_finish(sig);
        _exit(128 + sig);
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
}

static int ml_selftest_fail(const char *msg)
{
    ml_err_line("%s selftest: FAIL \xE2\x80\x94 %s", k_ml_gate, msg);
    return 1;
}

static int ml_sh(const char *dir, const char *fmt, ...)
{
    char cmd[8192], path[ML_PATH];
    char dump[256];
    int code = 0;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(path, sizeof path, fmt, ap);
    va_end(ap);
    if (ovf(snprintf(cmd, sizeof cmd, "git -C '%s' %s", dir, path),
            sizeof cmd))
        return -1;
    if (capture_cmd(cmd, dump, sizeof dump, &code) != 0 || code != 0)
        return -1;
    return 0;
}

static int ml_write_file(const char *dir, const char *rel,
                         const char *text)
{
    char path[ML_PATH];
    FILE *f;
    if (snprintf(path, sizeof path, "%s/%s", dir, rel) >= (int)sizeof path)
        return -1;
    f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(text, f);
    return fclose(f) == 0 ? 0 : -1;
}

static const char k_ml_readme[] =
    "# Link fixture\n\n"
    "[file](docs/guide.md)\n" // error-doc-ref-ok: markdown fixture
    "[file fragment](docs/guide.md#heading)\n" // error-doc-ref-ok: markdown fixture
    "[directory](docs/guide/)\n"
    "[angle path](<docs/with space.md>)\n" // error-doc-ref-ok: markdown fixture
    "[title](docs/guide.md \"Guide\")\n" // error-doc-ref-ok: markdown fixture
    "[reference][guide]\n"
    "[guide]: docs/guide.md\n" // error-doc-ref-ok: markdown fixture
    "[external](https://example.invalid/missing)\n"
    "[mail](mailto:nobody@example.invalid)\n"
    "[app](app://fixture/missing)\n"
    "[anchor](#link-fixture)\n"
    "[site absolute](/docs/generated-route)\n"
    "![ignored image](docs/missing-image.png)\n"
    "[generated angle](docs/<generated-name>.md)\n" // error-doc-ref-ok: markdown fixture
    "[generated env](docs/${GENERATED_NAME}.md)\n" // error-doc-ref-ok: markdown fixture
    "[generated template](docs/{{generated_name}}.md)\n" // error-doc-ref-ok: markdown fixture
    "[generated printf](docs/%s.md)\n" // error-doc-ref-ok: markdown fixture
    "[generated glob](docs/*.md)\n"
    "[generated ellipsis](docs/.../file.md)\n" // error-doc-ref-ok: markdown fixture
    "`[inline example](docs/missing-inline.md)`\n\n" // error-doc-ref-ok: markdown fixture
    "```markdown\n"
    "[fenced example](docs/missing-fenced.md)\n" // error-doc-ref-ok: markdown fixture
    "```\n\n"
    "[![badge](https://example.invalid/badge.svg)](docs/guide.md)\n"; // error-doc-ref-ok: markdown fixture

/* Runs the gate with both streams captured into one buffer, like 2>&1. */
static int ml_capture(const char *root, char *cap, size_t capsz)
{
    FILE *saved_out = g_ml_out, *saved_err = g_ml_err;
    char *buf = NULL;
    size_t size = 0;
    FILE *m = open_memstream(&buf, &size);
    int rc;
    if (!m)
        return -1;
    g_ml_out = m;
    g_ml_err = m;
    rc = ml_run(root);
    fclose(m);
    g_ml_out = saved_out;
    g_ml_err = saved_err;
    snprintf(cap, capsz, "%s", buf ? buf : "");
    free(buf);
    return rc;
}

/* The bash fixture's mkdir -p: build every parent explicitly. */
static int ml_fixture_dirs(const char *repo, const char *empty)
{
    char sub[ML_PATH];
    if (mkdir(repo, 0755) != 0 && errno != EEXIST)
        return -1;
    if (snprintf(sub, sizeof sub, "%s/docs", repo) >= (int)sizeof sub
        || (mkdir(sub, 0755) != 0 && errno != EEXIST))
        return -1;
    if (snprintf(sub, sizeof sub, "%s/docs/guide", repo) >= (int)sizeof sub
        || (mkdir(sub, 0755) != 0 && errno != EEXIST))
        return -1;
    if (mkdir(empty, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int ml_selftest_fixtures(char *repo, size_t repocap,
                                char *empty, size_t emptycap)
{
    if (snprintf(repo, repocap, "%s/repo", g_ml_tmp) >= (int)repocap
        || snprintf(empty, emptycap, "%s/empty", g_ml_tmp)
        >= (int)emptycap)
        return -1;
    if (ml_fixture_dirs(repo, empty) != 0)
        return -1;
    if (ml_sh(repo, "init -q") != 0)
        return -1;
    if (ml_sh(empty, "init -q") != 0)
        return -1;
    if (ml_write_file(repo, "docs/guide.md", "# Guide\n") != 0 // error-doc-ref-ok: markdown fixture
        || ml_write_file(repo, "docs/guide/index.md", "# Nested guide\n") != 0 // error-doc-ref-ok: markdown fixture
        || ml_write_file(repo, "docs/with space.md", "# Space\n") != 0 // error-doc-ref-ok: markdown fixture
        || ml_write_file(repo, "README.md", k_ml_readme) != 0) // error-doc-ref-ok: markdown fixture
        return -1;
    if (ml_sh(repo, "add README.md docs/guide.md docs/guide/index.md " // error-doc-ref-ok: markdown fixture
                "'docs/with space.md'") != 0) // error-doc-ref-ok: markdown fixture
        return -1;
    return 0;
}

/* The three stub cases; each returns 0 or a fail message via ml_case. */
static const char *ml_case_positive(const char *repo)
{
    static char out[65536];
    int rc = ml_capture(repo, out, sizeof out);
    if (rc != 0 || !strstr(out, "check_markdown_links: clean"))
        return "positive fixture rejected";
    return NULL;
}

static const char *ml_case_negative(const char *repo)
{
    static char out[65536];
    int rc;
    if (ml_write_file(repo, "README.md", // error-doc-ref-ok: markdown fixture
                      "README\n[missing target](docs/missing.md)\n") != 0) // error-doc-ref-ok: markdown fixture
        return "cannot write the negative fixture";
    rc = ml_capture(repo, out, sizeof out);
    if (rc != 1 || !strstr(out, "README.md:") // error-doc-ref-ok: markdown fixture
        || !strstr(out, "docs/missing.md")) // error-doc-ref-ok: markdown fixture
        return "negative fixture did not fail as required";
    return NULL;
}

static const char *ml_case_empty(const char *empty)
{
    static char out[65536];
    int rc = ml_capture(empty, out, sizeof out);
    if (rc != 2 || !strstr(out, "FATAL"))
        return "empty scan did not fail loud";
    return NULL;
}

/* Runs the three stub cases in order; returns a fail message or NULL. */
static const char *ml_selftest_cases(const char *repo, const char *empty)
{
    const char *why;
    if ((why = ml_case_positive(repo)) != NULL)
        return why;
    if (lsc_pending())
        return "interrupted after the positive fixture";
    if ((why = ml_case_negative(repo)) != NULL)
        return why;
    if (lsc_pending())
        return "interrupted after the negative fixture";
    return ml_case_empty(empty);
}

int check_markdown_links_selftest(void)
{
    char repo[ML_PATH], empty[ML_PATH];
    const char *why = NULL;
    if (!g_ml_out) g_ml_out = stdout;
    if (!g_ml_err) g_ml_err = stderr;
    if (lsc_install() != 0)
        return ml_selftest_fail("cannot install signal handlers");
    {
        char template[4096];
        const char *tmp = env_or("TMPDIR", "/tmp");
        char *dir;
        if (snprintf(template, sizeof template,
                     "%s/zcl-markdown-links.XXXXXX", tmp)
            >= (int)sizeof template)
            return ml_selftest_fail("cannot build the scratch path");
        dir = mkdtemp(template);
        if (!dir)
            return ml_selftest_fail("cannot create the scratch directory");
        snprintf(g_ml_tmp, sizeof g_ml_tmp, "%s", dir);
    }
    lsc_unblock();
    if (ml_selftest_fixtures(repo, sizeof repo, empty, sizeof empty) != 0)
        why = "cannot build the fixture repositories";
    else if (lsc_pending())
        why = "interrupted while building fixtures";
    else
        why = ml_selftest_cases(repo, empty);
    ml_cleanup_and_finish();
    if (why)
        return ml_selftest_fail(why);
    if (g_ml_tmp[0])
        return ml_selftest_fail("cleanup left the scratch behind");
    printf("check_markdown_links selftest: PASS\n");
    return 0;
}

/* ── signal tests: once, twice, and SIGHUP over a pipe handshake ───────── */

static void ml_hold(int wfd)
{
    char dir[4096], template[4096];
    struct timespec ts = { 0, 5 * 1000 * 1000 };
    const char *tmp = env_or("TMPDIR", "/tmp");
    char *d;
    if (lsc_install() != 0)
        _exit(2);
    snprintf(template, sizeof template, "%s/zcl-markdown-hold.XXXXXX", tmp);
    d = mkdtemp(template);
    if (!d)
        _exit(2);
    lsc_unblock();
    snprintf(dir, sizeof dir, "%s", d);
    size_t n = strlen(dir);
    dir[n] = '\n';
    if (write(wfd, dir, n + 1) != (ssize_t)(n + 1))
        _exit(2);
    dir[n] = '\0';
    for (int i = 0; i < 4000 && !lsc_pending(); i++)
        nanosleep(&ts, NULL);
    int sig = lsc_pending();
    rap_rm_rf(dir);
    if (sig)
        lsc_finish(sig);
    _exit(3);
}

static int ml_read_path(int rfd, char *dir, size_t cap)
{
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = read(rfd, dir + used, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || dir[used] == '\n')
            break;
        used++;
    }
    dir[used] = '\0';
    return used ? 0 : -1;
}

static int ml_signal_case(int sig, int times)
{
    int fds[2], st = 0;
    char dir[4096];
    pid_t pid;
    if (pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        lsc_reset_in_child();
        close(fds[0]);
        ml_hold(fds[1]);
    }
    close(fds[1]);
    int ready = ml_read_path(fds[0], dir, sizeof dir);
    close(fds[0]);
    for (int i = 0; ready == 0 && i < times; i++)
        kill(pid, sig);
    if (waitpid(pid, &st, 0) != pid || ready != 0)
        return -1;
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig)
        return -1;
    return access(dir, F_OK) == 0 ? -1 : 0;
}

/* ── entry ─────────────────────────────────────────────────────────────── */

int check_markdown_links_run(int argc, char **argv)
{
    const char *selftest_env = getenv("ZCL_MARKDOWN_LINKS_SELFTEST");
    int rc;
    g_ml_out = stdout;
    g_ml_err = stderr;
    if ((argc >= 1 && strcmp(argv[0], "--self-test") == 0)
        || (selftest_env && strcmp(selftest_env, "1") == 0)) {
        if (lsc_install() != 0)
            return ml_selftest_fail("cannot install signal handlers");
        rc = check_markdown_links_selftest();
        if (rc == 0)
            rc = ml_signal_case(SIGINT, 1) == 0 && ml_signal_case(SIGINT, 2) == 0
                && ml_signal_case(SIGHUP, 1) == 0 ? 0
                : ml_selftest_fail("a signal case failed its contract");
        if (lsc_pending())
            lsc_finish(lsc_pending());
        return rc;
    }
    return ml_run(argc >= 1 ? argv[0] : ".");
}
