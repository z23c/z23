/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the scoping half of the check-no-wallclock-assertion detector:
 * which function a line belongs to (function definitions start in column 0
 * and their header ends on the closing paren) and which declared names
 * (formals and locals, by brace depth) are visible on each body line, so a
 * clock-tainted global is not confused with a same-name local. Ported from
 * the awk note_funcdef/declaration/index_bindings of the retired shell gate;
 * the detector proper is gate_no_wallclock_assertion_scan.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gate_no_wallclock_assertion_priv.h"
#include "lintc.h"

static struct wca_state *const w = &wca_g;

static int wca_declaration(const char *s, char *out, size_t cap);


/* ── function boundaries ─────────────────────────────────────────────── */

static void wca_count_braces(const char *s, int *opens, int *closes)
{
    *opens = *closes = 0;
    for (; *s; s++) {
        if (*s == '{')
            (*opens)++;
        else if (*s == '}')
            (*closes)++;
    }
}

/* First `ident [ \t]* (` in h: the function name of a definition header. */
static int wca_header_name(const char *h, char *out, size_t cap)
{
    size_t i = 0;
    while (h[i]) {
        if (!wca_idstart(h[i])) {
            i++;
            continue;
        }
        size_t j = i;
        while (wca_wordc(h[j]))
            j++;
        size_t k = j;
        while (wca_blank(h[k]))
            k++;
        if (h[k] == '(') {
            if (j - i >= cap)
                return -1;
            memcpy(out, h + i, j - i);
            out[j - i] = '\0';
            return 1;
        }
        i = j;
    }
    return 0;
}

static int wca_keyword_name(const char *id)
{
    static const char *const kw[] = { "if", "for", "while", "switch",
                                      "return", "sizeof" };
    for (size_t i = 0; i < sizeof kw / sizeof kw[0]; i++)
        if (strcmp(id, kw[i]) == 0)
            return 1;
    return 0;
}

static int wca_has_lower(const char *s)
{
    for (; *s; s++)
        if (*s >= 'a' && *s <= 'z')
            return 1;
    return 0;
}

/* Tracks the function the line belongs to. Returns 1 when the line is part of
 * a function body (including its opening line), setting w->scan_line to the
 * part of the line that is body text. A definition starts in COLUMN 0 and its
 * header ends on the closing paren. */

void wca_note_reset(void)
{
    w->curfn[0] = '\0';
    w->body_depth = 0;
    wca_buf_clear(&w->pending);
}

/* ── per-line visible declarations ───────────────────────────────────── */

void wca_shadow_clear(void)
{
    for (int i = 0; i < w->nsh; i++)
        free(w->sh[i].id);
    w->nsh = 0;
}

static int wca_shadow_add(const char *id, int depth)
{
    if (w->nsh == w->shcap) {
        int nc = w->shcap ? w->shcap * 2 : 32;
        struct wca_shadow *n = wca_grow(w->sh, (size_t)nc * sizeof *n);
        if (!n)
            return 1;
        w->sh = n;
        w->shcap = nc;
    }
    char *copy = wca_dup(id, strlen(id));
    if (!copy)
        return 1;
    w->sh[w->nsh].id = copy;
    w->sh[w->nsh].depth = depth;
    w->nsh++;
    return 0;
}

static int wca_snapshot(void)
{
    if (w->nsnaps == w->snapcap) {
        int nc = w->snapcap ? w->snapcap * 2 : 64;
        struct wca_snap *n = wca_grow(w->snaps, (size_t)nc * sizeof *n);
        if (!n)
            return -1;
        w->snaps = n;
        w->snapcap = nc;
    }
    struct wca_snap *sp = &w->snaps[w->nsnaps];
    sp->n = w->nsh;
    sp->id = wca_grow(NULL, (size_t)w->nsh * sizeof *sp->id);
    if (!sp->id)
        return -1;
    for (int i = 0; i < w->nsh; i++) {
        sp->id[i] = wca_dup(w->sh[i].id, strlen(w->sh[i].id));
        if (!sp->id[i])
            return -1;
    }
    return w->nsnaps++;
}

/* The formals of the header just entered, as depth-1 declarations. */
static int wca_shadow_params(void)
{
    const char *h = wca_buf_str(&w->entry);
    const char *open = strchr(h, '(');
    if (!open)
        return 0;
    h = open + 1;
    const char *lastbrace = strrchr(h, '{');
    const char *end = h + strlen(h);
    if (lastbrace)
        for (const char *p = h; p < lastbrace; p++)
            if (*p == ')') {
                end = p;
                break;
            }
    char *copy = wca_dup(h, (size_t)(end - h) + 1);
    if (!copy)
        return 1;
    size_t n = (size_t)(end - h);
    copy[n] = ';';
    copy[n + 1] = '\0';
    int rc = 0;
    char id[WCA_NAME];
    char *part = copy;
    for (;;) {
        char *comma = strchr(part, ',');
        size_t pl = comma ? (size_t)(comma - part) : strlen(part);
        char *one = wca_dup(part, pl + 1);
        if (!one) {
            rc = 1;
            break;
        }
        if (comma) {
            memcpy(one, part, pl);
            one[pl] = ';';
            one[pl + 1] = '\0';
        }
        if (wca_declaration(one, id, sizeof id) && wca_shadow_add(id, 1))
            rc = 1;
        free(one);
        if (rc || !comma)
            break;
        part = comma + 1;
    }
    free(copy);
    return rc;
}

static int wca_extern_line(const char *s)
{
    while (wca_blank(*s))
        s++;
    return strncmp(s, "extern", 6) == 0 && wca_blank(s[6]);
}

static int wca_stmt_keyword(const char *word, size_t n)
{
    static const char *const kw[] = { "return", "goto", "break", "continue",
                                      "case", "else" };
    for (size_t i = 0; i < sizeof kw / sizeof kw[0]; i++)
        if (strlen(kw[i]) == n && memcmp(kw[i], word, n) == 0)
            return 1;
    return 0;
}

/* Necessary conditions of a declaration line, checked before the regex. */
static int wca_decl_candidate(const char *s)
{
    const char *p = s;
    while (wca_blank(*p))
        p++;
    const char *word = p;
    while (wca_wordc(*p))
        p++;
    if (word == p || !wca_idstart(*word))
        return 0;
    if (!wca_blank(*p) && *p != '*')
        return 0;
    if (wca_blank(*p) && wca_stmt_keyword(word, (size_t)(p - word)))
        return 0;
    return strpbrk(s, "=;[,") != NULL;
}

/* The name a `TYPE name (=|;|[|,)` declaration line declares. */
static int wca_declaration(const char *s, char *out, size_t cap)
{
    regmatch_t rm;
    if (!wca_decl_candidate(s) || regexec(&w->decl, s, 1, &rm, 0) != 0)
        return 0;
    size_t e = (size_t)rm.rm_eo - 1; /* drop the delimiter */
    while (e > 0 && wca_blank(s[e - 1]))
        e--;
    size_t b = e;
    while (b > 0 && wca_wordc(s[b - 1]))
        b--;
    if (e - b == 0 || e - b >= cap)
        return 0;
    memcpy(out, s + b, e - b);
    out[e - b] = '\0';
    return 1;
}

static int wca_body_line(const char *s)
{
    int opens, closes;
    wca_count_braces(s, &opens, &closes);
    w->body_depth += opens - closes;
    if (w->body_depth < 0)
        w->body_depth = 0;
    return 1;
}

static void wca_pending_feed(const char *s, int *err)
{
    if (w->pending.n > 0) {
        if (wca_buf_put(&w->pending, " ", 1)
            || wca_buf_put(&w->pending, s, strlen(s)))
            *err = 1;
    } else if (wca_idstart(s[0]) && wca_buf_put(&w->pending, s, strlen(s))) {
        *err = 1;
    }
}

/* The pending text holds a `{`: it is a function definition when its first
 * `ident (` names something other than a keyword or an all-caps macro. */
static int wca_enter(const char *s, const char *pend, int *err)
{
    int opens, closes;
    char id[WCA_FN];
    wca_buf_clear(&w->entry);
    if (wca_buf_put(&w->entry, pend, strlen(pend)))
        *err = 1;
    int found = wca_header_name(pend, id, sizeof id);
    if (found < 0)
        *err = 1;
    if (found > 0 && !wca_keyword_name(id) && wca_has_lower(id))
        memcpy(w->curfn, id, strlen(id) + 1);
    wca_buf_clear(&w->pending);
    if (w->curfn[0] == '\0')
        return 0;
    const char *brace = strchr(s, '{');
    w->scan_line = brace ? brace + 1 : s + strlen(s);
    wca_count_braces(w->scan_line, &opens, &closes);
    w->body_depth = 1 + opens - closes;
    return 1;
}

int wca_note_funcdef(const char *s, int *err)
{
    w->scan_line = s;
    if (w->body_depth != 0)
        return wca_body_line(s);
    w->curfn[0] = '\0';
    wca_pending_feed(s, err);
    const char *pend = wca_buf_str(&w->pending);
    const char *semi = strchr(pend, ';');
    const char *brace = strchr(pend, '{');
    if (semi && (!brace || semi < brace)) {
        wca_buf_clear(&w->pending);
        return 0;
    }
    return brace ? wca_enter(s, pend, err) : 0;
}

/* Drops the declarations whose block has closed; 1 if any went. */
static int wca_shadow_prune(void)
{
    int keep = 0, dropped = 0;
    for (int k = 0; k < w->nsh; k++) {
        if (w->sh[k].depth > w->body_depth) {
            free(w->sh[k].id);
            dropped = 1;
        } else {
            w->sh[keep++] = w->sh[k];
        }
    }
    w->nsh = keep;
    return dropped;
}

static int wca_oom(void) { return die("z23-lint: out of memory\n", ""); }

static int wca_bind_line(int i, int before, int *last, int *dirty)
{
    char id[WCA_NAME];
    if (before == 0) {
        wca_shadow_clear();
        *dirty = 1;
        if (wca_shadow_params())
            return wca_oom();
    }
    if (wca_declaration(w->scan_line, id, sizeof id)
        && !wca_extern_line(w->scan_line)) {
        if (wca_shadow_add(id, before > 0 ? before : 1))
            return wca_oom();
        *dirty = 1;
    }
    if (w->nsh > 0) {
        if (*dirty || *last < 0) {
            *last = wca_snapshot();
            *dirty = 0;
        }
        if (*last < 0)
            return wca_oom();
        w->snap[i] = *last;
    }
    if (wca_shadow_prune())
        *dirty = 1;
    return 0;
}

int wca_index_bindings(void)
{
    int err = 0, last = -1, dirty = 1;
    wca_note_reset();
    wca_shadow_clear();
    for (int i = 0; i < w->nlines; i++) {
        int before = w->body_depth;
        w->snap[i] = -1;
        if (!wca_note_funcdef(w->line[i], &err)) {
            if (err)
                return wca_oom();
            continue;
        }
        int rc = wca_bind_line(i, before, &last, &dirty);
        if (rc)
            return rc;
    }
    return 0;
}
