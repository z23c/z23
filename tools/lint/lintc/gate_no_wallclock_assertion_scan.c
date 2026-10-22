/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the clock-taint detector of check-no-wallclock-assertion, ported
 * from the awk program of the retired shell gate of the same name. For one
 * source file it counts the assertion macros (ASSERT*, EXPECT*, REQUIRE*,
 * *CHECK) whose joined argument text depends on a MEASURED INTERVAL: the
 * difference of two real-clock readings. The model is the awk original's, step
 * for step, so both tools return the same count and first line on every file:
 *
 *   1. strip comments and string/char literals (block state carries over
 *      lines);
 *   2. index_bindings: which declared names (formals and locals, by brace
 *      depth) are visible on each function-body line;
 *   3. fixpoint (6 passes at most): a local helper whose body reads a clock
 *      becomes a reader; `TYPE x = <clocky>;` and `reader(..., &x)` taint or
 *      stamp x; a name also declared from a non-clock expression is ambiguous
 *      and ignored within its scope;
 *   4. find_assertions: join each assertion invocation across lines by
 *      balancing parentheses and ask whether it is an interval.
 *
 * Names are scoped "<function>\x1f<name>" when a declaration is visible on the
 * line, otherwise "@file\x1f<name>" (the conservative file-wide summary).
 * The rationale, the blind spots and the exemptions live in the header of
 * gate_no_wallclock_assertion.c.
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

enum { WCA_KEY = 1024, WCA_PASSES = 6 };

static const char k_wca_re_decl[] =
    "^[ \t]*(static[ \t]+|extern[ \t]+|const[ \t]+|volatile[ \t]+|"
    "register[ \t]+)*(((struct|union|enum)[ \t]+[A-Za-z_][A-Za-z0-9_]*|"
    "(unsigned|signed)[ \t]+long[ \t]+long|"
    "(unsigned|signed)[ \t]+(long|short|int|char)|long[ \t]+long|void|char|"
    "short|int|long|float|double|signed|unsigned|_Bool|bool)[ \t*]+|"
    "[A-Za-z_][A-Za-z0-9_]*[ \t]+)[A-Za-z_][A-Za-z0-9_]*[ \t]*(=|;|\\[|,)";
static const char k_wca_re_init[] =
    "^[ \t]*(static[ \t]+)?(const[ \t]+)?(unsigned[ \t]+)?(int64_t|uint64_t|"
    "int32_t|uint32_t|long long|long|int|double|float|time_t|clock_t|"
    "suseconds_t)[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*=";
static const char k_wca_re_assert[] =
    "(^|[^A-Za-z0-9_])(ASSERT[A-Za-z0-9_]*|EXPECT[A-Za-z0-9_]*|"
    "REQUIRE[A-Za-z0-9_]*|[A-Za-z0-9_]*CHECK)[ \t]*\\(";
static const char k_wca_re_time[] =
    "(^|[^A-Za-z0-9_])time[ \t]*\\([ \t]*(NULL|0)[ \t]*\\)";
static const char *const k_wca_readers[] = {
    "clock_now_monotonic_ns", "clock_now_wall_ms", "clock_gettime",
    "gettimeofday", "platform_time_monotonic_timespec",
    "platform_time_wall_time_t", "difftime",
};

struct wca_state wca_g;
static struct wca_state *const w = &wca_g;

void *wca_grow(void *p, size_t bytes)
{
    return realloc(p, bytes ? bytes : 1); // raw-alloc-ok:lint-runtime
}

char *wca_dup(const char *s, size_t n)
{
    char *q = wca_grow(NULL, n + 1);
    if (q) {
        memcpy(q, s, n);
        q[n] = '\0';
    }
    return q;
}

int wca_buf_put(struct wca_buf *b, const char *s, size_t n)
{
    size_t need = b->n + n + 1;
    if (need > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < need)
            nc *= 2;
        char *q = wca_grow(b->p, nc);
        if (!q)
            return 1;
        b->p = q;
        b->cap = nc;
    }
    if (n)
        memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
    return 0;
}

const char *wca_buf_str(const struct wca_buf *b) { return b->p ? b->p : ""; }

void wca_buf_clear(struct wca_buf *b)
{
    b->n = 0;
    if (b->p)
        b->p[0] = '\0';
}

static unsigned long wca_set_hash(const char *k)
{
    unsigned long h = 1469598103934665603UL;
    for (; *k; k++)
        h = (h ^ (unsigned char)*k) * 1099511628211UL;
    return h;
}

static int wca_set_has(const struct wca_set *s, const char *k)
{
    if (s->n == 0)
        return 0;
    size_t i = wca_set_hash(k) & (s->cap - 1);
    while (s->slot[i]) {
        if (strcmp(s->slot[i], k) == 0)
            return 1;
        i = (i + 1) & (s->cap - 1);
    }
    return 0;
}

static int wca_set_grow(struct wca_set *s)
{
    size_t nc = s->cap ? s->cap * 2 : 64;
    char **ns = wca_grow(NULL, nc * sizeof *ns);
    if (!ns)
        return 1;
    memset(ns, 0, nc * sizeof *ns);
    for (size_t i = 0; i < s->cap; i++) {
        if (!s->slot[i])
            continue;
        size_t j = wca_set_hash(s->slot[i]) & (nc - 1);
        while (ns[j])
            j = (j + 1) & (nc - 1);
        ns[j] = s->slot[i];
    }
    free(s->slot);
    s->slot = ns;
    s->cap = nc;
    return 0;
}

/* 1 = newly added, 0 = already present, -1 = out of memory. */
static int wca_set_add(struct wca_set *s, const char *k)
{
    if (wca_set_has(s, k))
        return 0;
    if ((s->n + 1) * 2 > s->cap && wca_set_grow(s))
        return -1;
    char *copy = wca_dup(k, strlen(k));
    if (!copy)
        return -1;
    size_t i = wca_set_hash(k) & (s->cap - 1);
    while (s->slot[i])
        i = (i + 1) & (s->cap - 1);
    s->slot[i] = copy;
    s->n++;
    return 1;
}

static void wca_set_clear(struct wca_set *s)
{
    for (size_t i = 0; i < s->cap; i++) {
        free(s->slot[i]);
        s->slot[i] = NULL;
    }
    s->n = 0;
}

int wca_wordc(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '_';
}

int wca_idstart(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

int wca_blank(char c) { return c == ' ' || c == '\t'; }

/* ── comments and literals ───────────────────────────────────────────── */

/* The index just past a string or char literal opened at s[i]. */
static size_t wca_skip_literal(const char *s, size_t n, size_t i)
{
    char q = s[i++];
    while (i < n) {
        char d = s[i];
        if (d == '\\') {
            i += 2;
            continue;
        }
        i++;
        if (d == q)
            break;
    }
    return i;
}

/* Bytes of block comment consumed at the cursor (0: not in one). */
static size_t wca_block_step(int *inblk, char c, char c2)
{
    if (!*inblk) {
        if (c != '/' || c2 != '*')
            return 0;
        *inblk = 1;
        return 2;
    }
    if (c == '*' && c2 == '/') {
        *inblk = 0;
        return 2;
    }
    return 1;
}

static int wca_strip(int *inblk, const char *s, size_t n, struct wca_buf *out)
{
    size_t i = 0;
    while (i < n) {
        char c = s[i];
        char c2 = i + 1 < n ? s[i + 1] : '\0';
        size_t adv = wca_block_step(inblk, c, c2);
        if (adv) {
            i += adv;
            continue;
        }
        if (c == '/' && c2 == '/')
            break;
        int lit = c == '"' || c == '\'';
        if (lit)
            i = wca_skip_literal(s, n, i);
        else
            i++;
        if (wca_buf_put(out, lit ? " " : &c, 1))
            return 1;
    }
    return wca_buf_put(out, "\0", 1);
}

/* ── name scoping ────────────────────────────────────────────────────── */

static int wca_is_local(const char *id, size_t n)
{
    int sn = w->snap[w->cur];
    if (sn < 0)
        return 0;
    const struct wca_snap *sp = &w->snaps[sn];
    for (int i = 0; i < sp->n; i++)
        if (strlen(sp->id[i]) == n && memcmp(sp->id[i], id, n) == 0)
            return 1;
    return 0;
}

/* Builds the scoped key of id; 0 when it cannot be a scoped identifier. */
static size_t wca_key(char *buf, const char *id, size_t n)
{
    const char *scope = wca_is_local(id, n) ? w->curfn : "@file";
    size_t sl = strlen(scope);
    if (sl + n + 2 > WCA_KEY)
        return 0;
    memcpy(buf, scope, sl);
    buf[sl] = '\x1f';
    memcpy(buf + sl + 1, id, n);
    buf[sl + 1 + n] = '\0';
    return sl + 1 + n;
}

static int wca_add_bound(struct wca_set *set, const char *id, size_t n)
{
    char key[WCA_KEY];
    if (!wca_key(key, id, n))
        return 0;
    return wca_set_add(set, key) == 1;
}

static int wca_has_bound(const struct wca_set *set, const char *id, size_t n)
{
    char key[WCA_KEY];
    return wca_key(key, id, n) && wca_set_has(set, key);
}

/* ── token and call indexes ──────────────────────────────────────────── */

static int wca_next_tok(const char *s, size_t *pos, const char **t,
                        size_t *len)
{
    size_t i = *pos;
    while (s[i] && !wca_wordc(s[i]))
        i++;
    if (!s[i])
        return 0;
    size_t b = i;
    while (wca_wordc(s[i]))
        i++;
    *t = s + b;
    *len = i - b;
    *pos = i;
    return 1;
}

/* The word run directly before each '(' (blanks between are ignored). */
static int wca_next_call(const char *s, size_t *pos, const char **name,
                         size_t *len)
{
    const char *p = s + *pos;
    while ((p = strchr(p, '(')) != NULL) {
        const char *e = p;
        while (e > s && wca_blank(e[-1]))
            e--;
        const char *b = e;
        while (b > s && wca_wordc(b[-1]))
            b--;
        p++;
        if (b < e) {
            *name = b;
            *len = (size_t)(e - b);
            *pos = (size_t)(p - s);
            return 1;
        }
    }
    return 0;
}

static int wca_call_is(const char *name, size_t len, const char *want)
{
    return strlen(want) == len && memcmp(name, want, len) == 0;
}

static int wca_tokens_hit(const char *s, int want_stamp)
{
    if (w->taint.n == 0 && (!want_stamp || w->stamp.n == 0))
        return 0;
    const char *t;
    size_t pos = 0, len;
    while (wca_next_tok(s, &pos, &t, &len)) {
        if (want_stamp) {
            if (wca_has_bound(&w->amb, t, len))
                continue;
            if (wca_has_bound(&w->stamp, t, len))
                return 1;
        } else if (wca_has_bound(&w->amb, t, len)) {
            continue;
        }
        if (wca_has_bound(&w->taint, t, len))
            return 1;
    }
    return 0;
}

/* Does this text READ a clock (call a reader, or name a variable holding a
 * reading)? rx is the text the time-of-NULL pattern is asked about. */
static int wca_is_clocky(const char *s, const char *rx)
{
    const char *name;
    size_t pos = 0, len;
    char tmp[WCA_NAME];
    while (wca_next_call(s, &pos, &name, &len)) {
        if (len >= sizeof tmp)
            continue;
        memcpy(tmp, name, len);
        tmp[len] = '\0';
        if (wca_set_has(&w->readers, tmp))
            return 1;
    }
    if (strstr(rx, "time") && regexec(&w->time_re, rx, 0, NULL, 0) == 0)
        return 1;
    return wca_tokens_hit(s, 1);
}

/* The load-sensitive shape is an INTERVAL, not a timestamp. */
static int wca_calls_difftime(const char *s)
{
    const char *name;
    size_t pos = 0, len;
    while (wca_next_call(s, &pos, &name, &len))
        if (wca_call_is(name, len, "difftime"))
            return 1;
    return 0;
}

/* A '-' that is not the arrow of a '->' member access. */
static int wca_has_minus(const char *s)
{
    for (const char *p = s; *p; p++) {
        if (p[0] == '-' && p[1] == '>')
            p++;
        else if (*p == '-')
            return 1;
    }
    return 0;
}

static int wca_is_interval(const char *s)
{
    if (wca_tokens_hit(s, 0) || wca_calls_difftime(s))
        return 1;
    if (!wca_has_minus(s))
        return 0;
    if (!strstr(s, "time") || !strstr(s, "->"))
        return wca_is_clocky(s, s);
    char *mod = wca_dup(s, strlen(s));
    if (!mod)
        return 0;
    for (char *p = mod; *p; p++)
        if (p[0] == '-' && p[1] == '>')
            p[0] = p[1] = ' ';
    int r = wca_is_clocky(s, mod);
    free(mod);
    return r;
}


/* ── harvesting clock-derived names ──────────────────────────────────── */

/* reader(..., &name): a single reading, so a stamp. Mirrors
 * `reader[ \t]*\([^)]*&[ \t]*IDENT`: within the call's text up to the first
 * ')', the identifier after the LAST '&' that has one. */
static int wca_harvest_outparam(const char *s, const char *k, size_t kl)
{
    int added = 0;
    const char *base = s, *pos = s; /* base: where the unmatched rest starts */
    while (*pos) {
        const char *p = strstr(pos, k);
        if (!p)
            break;
        const char *q = p + kl;
        int ok = (p == base || !wca_wordc(p[-1]));
        while (wca_blank(*q))
            q++;
        if (!ok || *q != '(') {
            pos = p + 1;
            continue;
        }
        q++;
        const char *idb = NULL, *ide = NULL;
        for (const char *c = q; *c && *c != ')'; c++) {
            if (*c != '&')
                continue;
            const char *d = c + 1;
            while (wca_blank(*d))
                d++;
            if (!wca_idstart(*d))
                continue;
            const char *e = d;
            while (wca_wordc(*e))
                e++;
            idb = d;
            ide = e;
        }
        if (!idb) {
            pos = p + 1;
            continue;
        }
        if (wca_add_bound(&w->stamp, idb, (size_t)(ide - idb)))
            added = 1;
        base = pos = ide;
    }
    return added;
}

static int wca_harvest_outparams(const char *s)
{
    int added = 0;
    const char *name;
    size_t pos = 0, len;
    char seen[16][WCA_NAME];
    int nseen = 0;
    char tmp[WCA_NAME];
    while (wca_next_call(s, &pos, &name, &len)) {
        if (len >= sizeof tmp)
            continue;
        memcpy(tmp, name, len);
        tmp[len] = '\0';
        if (!wca_set_has(&w->readers, tmp))
            continue;
        int dup = 0;
        for (int i = 0; i < nseen; i++)
            if (strcmp(seen[i], tmp) == 0)
                dup = 1;
        if (dup)
            continue;
        if (nseen < 16)
            memcpy(seen[nseen++], tmp, len + 1);
        if (wca_harvest_outparam(s, tmp, len))
            added = 1;
    }
    return added;
}

static int wca_init_candidate(const char *s)
{
    static const char *const first[] = {
        "static", "const", "unsigned", "int64_t", "uint64_t", "int32_t",
        "uint32_t", "long", "int", "double", "float", "time_t", "clock_t",
        "suseconds_t",
    };
    while (wca_blank(*s))
        s++;
    size_t n = 0;
    while (wca_wordc(s[n]))
        n++;
    for (size_t i = 0; i < sizeof first / sizeof first[0]; i++)
        if (strlen(first[i]) == n && memcmp(first[i], s, n) == 0)
            return 1;
    return 0;
}

/* `TYPE name = <rhs>;` Declaration form only: a bare `row.x = wall()` binds
 * a struct field and must not taint the bare name. */
static int wca_harvest_init(const char *s)
{
    regmatch_t rm;
    if (!strchr(s, '=') || !wca_init_candidate(s)
        || regexec(&w->init, s, 1, &rm, 0) != 0)
        return 0;
    const char *rhs = s + rm.rm_eo;
    size_t e = (size_t)rm.rm_eo - 1;
    while (e > 0 && wca_blank(s[e - 1]))
        e--;
    size_t b = e;
    while (b > 0 && wca_wordc(s[b - 1]))
        b--;
    if (e == b)
        return 0;
    int clocky = rhs[0] != '=' && wca_is_clocky(rhs, rhs);
    if (!clocky) {
        /* AMBIGUOUS NAME GUARD: a name also declared from a non-clock
         * expression cannot be told apart from a clock-derived one. */
        wca_add_bound(&w->amb, s + b, e - b);
        return 0;
    }
    if (wca_is_interval(rhs))
        return wca_add_bound(&w->taint, s + b, e - b);
    return wca_add_bound(&w->stamp, s + b, e - b);
}

static int wca_harvest(const char *s)
{
    int added = 0;
    if (strchr(s, '&') && wca_harvest_outparams(s))
        added = 1;
    if (wca_harvest_init(s))
        added = 1;
    return added;
}

static int wca_fixpoint(void)
{
    int err = 0;
    for (int pass = 0; pass < WCA_PASSES; pass++) {
        int changed = 0;
        wca_note_reset();
        for (int i = 0; i < w->nlines; i++) {
            w->cur = i;
            int in_body = wca_note_funcdef(w->line[i], &err);
            if (err)
                return die("z23-lint: out of memory\n", "");
            if (pass == 0) {
                w->scope[i] = -1;
                if (in_body) {
                    w->scope[i] = (int)w->names.n;
                    if (wca_buf_put(&w->names, w->curfn, strlen(w->curfn) + 1))
                        return die("z23-lint: out of memory\n", "");
                }
            }
            if (in_body && w->curfn[0] && !wca_set_has(&w->readers, w->curfn)
                && wca_is_clocky(w->scan_line, w->scan_line)) {
                if (wca_set_add(&w->readers, w->curfn) < 0)
                    return die("z23-lint: out of memory\n", "");
                changed = 1;
            }
            if (in_body && wca_harvest(w->scan_line))
                changed = 1;
        }
        if (!changed)
            break;
    }
    return 0;
}

/* ── assertions ──────────────────────────────────────────────────────── */

/* Joins the invocation whose '(' is line[i][idx] across lines by balancing
 * parentheses, so wrapping or reindenting cannot hide the expression. */
static int wca_join(int i, size_t idx, struct wca_buf *buf)
{
    int depth = 0;
    wca_buf_clear(buf);
    for (int j = i; j < w->nlines; j++) {
        const char *t = j == i ? w->line[j] + idx : w->line[j];
        int closed = 0;
        for (; *t; t++) {
            if (*t == '(') {
                depth++;
            } else if (*t == ')') {
                depth--;
                if (depth == 0) {
                    closed = 1;
                    break;
                }
            }
            if (wca_buf_put(buf, t, 1))
                return 1;
        }
        if (closed || depth <= 0)
            return 0;
        if (wca_buf_put(buf, " ", 1))
            return 1;
    }
    return 0;
}

static int wca_find_assertions(struct wca_hit *hit)
{
    struct wca_buf buf = { 0 };
    int rc = 0;
    for (int i = 0; rc == 0 && i < w->nlines; i++) {
        const char *s = w->line[i];
        if (!strchr(s, '(') || !(strstr(s, "ASSERT") || strstr(s, "EXPECT")
                                 || strstr(s, "REQUIRE")
                                 || strstr(s, "CHECK")))
            continue;
        w->cur = i;
        w->curfn[0] = '\0';
        if (w->scope[i] >= 0)
            memcpy(w->curfn, w->names.p + w->scope[i],
                   strlen(w->names.p + w->scope[i]) + 1);
        size_t pos = 0, len = strlen(s);
        while (pos <= len) {
            regmatch_t rm;
            if (regexec(&w->assertion, s + pos, 1, &rm, 0) != 0)
                break;
            size_t end = pos + (size_t)rm.rm_eo;
            if (wca_join(i, end - 1, &buf)) {
                rc = die("z23-lint: out of memory\n", "");
                break;
            }
            if (wca_is_interval(wca_buf_str(&buf))) {
                hit->count++;
                if (hit->first_line == 0)
                    hit->first_line = w->lno[i];
            }
            pos = end;
        }
    }
    free(buf.p);
    return rc;
}

/* ── per-file driver ─────────────────────────────────────────────────── */

static void wca_file_clear(void)
{
    wca_buf_clear(&w->text);
    wca_buf_clear(&w->names);
    wca_buf_clear(&w->pending);
    wca_buf_clear(&w->entry);
    wca_set_clear(&w->readers);
    wca_set_clear(&w->taint);
    wca_set_clear(&w->stamp);
    wca_set_clear(&w->amb);
    wca_shadow_clear();
    for (int i = 0; i < w->nsnaps; i++) {
        for (int k = 0; k < w->snaps[i].n; k++)
            free(w->snaps[i].id[k]);
        free(w->snaps[i].id);
    }
    w->nsnaps = 0;
    w->nlines = 0;
    w->curfn[0] = '\0';
    w->body_depth = 0;
}

static void wca_file_reset(void)
{
    wca_file_clear();
    for (size_t i = 0; i < sizeof k_wca_readers / sizeof k_wca_readers[0]; i++)
        (void)wca_set_add(&w->readers, k_wca_readers[i]);
}

static int wca_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *ln = NULL;
    size_t lcap = 0;
    ssize_t r;
    int inblk = 0, lineno = 0, rc = 0;
    while (rc == 0 && (r = getline(&ln, &lcap, f)) >= 0) {
        size_t n = (size_t)r;
        lineno++;
        if (n > 0 && ln[n - 1] == '\n')
            n--;
        if (w->nlines == w->lcap) {
            int nc = w->lcap ? w->lcap * 2 : 1024;
            size_t *no = wca_grow(w->off, (size_t)nc * sizeof *no);
            if (no)
                w->off = no;
            int *nl = wca_grow(w->lno, (size_t)nc * sizeof *nl);
            if (nl)
                w->lno = nl;
            if (!no || !nl) {
                rc = die("z23-lint: out of memory\n", "");
                break;
            }
            w->lcap = nc;
        }
        w->off[w->nlines] = w->text.n;
        w->lno[w->nlines] = lineno;
        w->nlines++;
        if (wca_strip(&inblk, ln, n, &w->text))
            rc = die("z23-lint: out of memory\n", "");
    }
    return fin(f, ln, path, rc);
}

static int wca_index_arrays(void)
{
    free(w->line);
    free(w->scope);
    free(w->snap);
    size_t n = (size_t)w->nlines + 1;
    w->line = wca_grow(NULL, n * sizeof *w->line);
    w->scope = wca_grow(NULL, n * sizeof *w->scope);
    w->snap = wca_grow(NULL, n * sizeof *w->snap);
    if (!w->line || !w->scope || !w->snap)
        return die("z23-lint: out of memory\n", "");
    for (int i = 0; i < w->nlines; i++) {
        w->line[i] = w->text.p + w->off[i];
        w->scope[i] = -1;
        w->snap[i] = -1;
    }
    return 0;
}

int wca_scan_file(const char *path, struct wca_hit *hit)
{
    hit->count = 0;
    hit->first_line = 0;
    wca_file_reset();
    int rc = wca_load(path);
    if (rc == 0)
        rc = wca_index_arrays();
    if (rc == 0)
        rc = wca_index_bindings();
    if (rc == 0)
        rc = wca_fixpoint();
    if (rc == 0)
        rc = wca_find_assertions(hit);
    return rc;
}

int wca_scan_init(void)
{
    memset(&wca_g, 0, sizeof wca_g);
    if (reg_fail(&w->decl, regcomp(&w->decl, k_wca_re_decl, REG_EXTENDED)))
        return 2;
    if (reg_fail(&w->init, regcomp(&w->init, k_wca_re_init, REG_EXTENDED))) {
        regfree(&w->decl);
        return 2;
    }
    if (reg_fail(&w->assertion,
                 regcomp(&w->assertion, k_wca_re_assert, REG_EXTENDED))) {
        drop2(&w->decl, &w->init);
        return 2;
    }
    if (reg_fail(&w->time_re,
                 regcomp(&w->time_re, k_wca_re_time, REG_EXTENDED))) {
        drop3(&w->decl, &w->init, &w->assertion);
        return 2;
    }
    w->ready = 1;
    return 0;
}

void wca_scan_fini(void)
{
    if (!w->ready)
        return;
    wca_file_clear();
    drop3(&w->decl, &w->init, &w->assertion);
    regfree(&w->time_re);
    free(w->text.p);
    free(w->pending.p);
    free(w->entry.p);
    free(w->names.p);
    free(w->off);
    free(w->lno);
    free(w->line);
    free(w->scope);
    free(w->snap);
    free(w->sh);
    free(w->snaps);
    free(w->readers.slot);
    free(w->taint.slot);
    free(w->stamp.slot);
    free(w->amb.slot);
    memset(&wca_g, 0, sizeof wca_g);
}
