/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-blocker-remedy (port of
 * tools/scripts/check_blocker_remedy.sh, now a shim). Blocker remedy
 * totality (docs/work/tenacity-roadmap.md "Hold-class doctrine"): every
 * named typed blocker a production call site can raise — a literal/macro id
 * argument to blocker_init / chain_linkage_hold_raise /
 * sentinel_raise_blocker / name_dependency_blocker, or a
 * blocker-id: <pattern> marker at a dynamic-id construction site — must be
 * an exact key in engine/conditions/include/conditions/
 * blocker_remedy_bindings.def, bound to a condition that exists in scope,
 * to a blocker_register_escape("...") action registered in scope, or to the
 * honest token OWNER.
 *
 * Port notes (parity contract with the shell original):
 *  - find walks a tree in readdir order; this port walks in
 *    scandir/alphasort order (the runtime's walk_src idiom). Verdicts,
 *    counts, and any single-violation report are byte-identical; a report
 *    listing violations from MULTIPLE files can order them differently.
 *  - The shell iterates the discovered-id set in bash associative-array
 *    hash order when printing the MISSING-from-table section; this port
 *    prints in discovery order. A single missing id is byte-identical.
 *  - The shell ran its extractors inside process substitutions, so an
 *    unreadable scanned file was silently dropped from the awk/grep input
 *    (a false-green). Per the runtime contract this port refuses instead:
 *    UNPROVEN exit 2, never a partial scan.
 *  - The call-site extractor reproduces the original awk program exactly,
 *    including its shared input cursor: lines pulled in as a call's
 *    continuation are not re-examined for new call starts, and a call
 *    still open after 60 continuation lines is abandoned.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { BRF_MAX_FILES = 8192, BRF_PATH = 384, BRF_VAL = 320, BRF_NAME = 96,
       BRF_MAX_ROWS = 16384, BRF_MAX_IDS = 8192, BRF_MAX_MACRO = 2048,
       BRF_MAX_TABLE = 2048, BRF_MAX_ARGS = 64, BRF_JOIN_MAX = 60 };

static const char k_table_rel[] =
    "engine/conditions/include/conditions/blocker_remedy_bindings.def";
static const char *const k_roots[] = {
    "core", "engine", "contexts", "cognition", "platform"
};
static const char *const k_fns[] = {
    "blocker_init", "chain_linkage_hold_raise",
    "sentinel_raise_blocker", "name_dependency_blocker"
};
static const int k_fn_idx[] = { 2, 2, 1, 1 };

enum { BRF_LIT = 0, BRF_ID = 1, BRF_EXPR = 2 };

struct brf_row { int file; long line; int fn; int kind; char val[BRF_VAL]; };
struct brf_trow { char id[BRF_VAL], remedy[BRF_VAL]; };
struct brf_pair { char k[BRF_NAME], v[BRF_VAL]; };

struct brf {
    char files[BRF_MAX_FILES][BRF_PATH];
    unsigned char marker[BRF_MAX_FILES], litwrap[BRF_MAX_FILES];
    int nfiles;
    struct brf_pair mac[BRF_MAX_MACRO];
    int nmac;
    char ids[BRF_MAX_IDS][BRF_VAL];
    int nids;
    struct brf_row rows[BRF_MAX_ROWS];
    int nrows;
    struct brf_trow tab[BRF_MAX_TABLE];
    int ntab;
    char conds[BRF_MAX_IDS][BRF_VAL];
    int ncond;
    char escs[BRF_MAX_IDS][BRF_VAL];
    int nesc;
    int dyn[BRF_MAX_ROWS];
    int ndyn;
    int missing[BRF_MAX_IDS];
    int nmissing;
    int badr[BRF_MAX_TABLE];
    int nbad;
    int escape_count;
};

static struct brf g;

struct brf_lines { char **v; int n, cap; };

/* ── small set/map helpers ────────────────────────────────────────────── */

static int brf_set_add(char (*set)[BRF_VAL], int *n, int max, const char *s)
{
    size_t len = strlen(s);
    if (len >= BRF_VAL)
        return die("z23-lint: derived buffer overflow\n", "");
    for (int i = 0; i < *n; i++)
        if (strcmp(set[i], s) == 0)
            return 0;
    if (*n >= max)
        return die("z23-lint: blocker-remedy set overflow\n", "");
    memcpy(set[*n], s, len + 1);
    (*n)++;
    return 0;
}

static int brf_set_has(char (*set)[BRF_VAL], int n, const char *s)
{
    for (int i = 0; i < n; i++)
        if (strcmp(set[i], s) == 0)
            return 1;
    return 0;
}

static int brf_mac_add(const char *k, const char *v)
{
    if (strlen(k) >= BRF_NAME || strlen(v) >= BRF_VAL)
        return die("z23-lint: derived buffer overflow\n", "");
    for (int i = 0; i < g.nmac; i++) {
        if (strcmp(g.mac[i].k, k) == 0) {
            memcpy(g.mac[i].v, v, strlen(v) + 1);
            return 0;
        }
    }
    if (g.nmac >= BRF_MAX_MACRO)
        return die("z23-lint: blocker-remedy macro overflow\n", "");
    memcpy(g.mac[g.nmac].k, k, strlen(k) + 1);
    memcpy(g.mac[g.nmac].v, v, strlen(v) + 1);
    g.nmac++;
    return 0;
}

static const char *brf_mac_get(const char *k)
{
    for (int i = 0; i < g.nmac; i++)
        if (strcmp(g.mac[i].k, k) == 0)
            return g.mac[i].v;
    return NULL;
}

static int brf_tab_has(const char *id)
{
    for (int i = 0; i < g.ntab; i++)
        if (strcmp(g.tab[i].id, id) == 0)
            return 1;
    return 0;
}

/* ── file collection ──────────────────────────────────────────────────── */

static int brf_scan_name(const char *name)
{
    size_t n = strlen(name);
    if (n >= 2 && name[n - 2] == '.'
        && (name[n - 1] == 'c' || name[n - 1] == 'h'))
        return 1;
    return n >= 4 && memcmp(name + n - 4, ".def", 4) == 0;
}

static int brf_excluded(const char *path)
{
    if (strncmp(path, "tests/harness/include/test/", 27) == 0)
        return 1;
    return strcmp(path, "platform/modules/util/src/blocker.c") == 0
        || strcmp(path, "platform/modules/util/include/util/blocker.h") == 0;
}

static int brf_add_file(const char *path)
{
    if (brf_excluded(path))
        return 0;
    if (g.nfiles >= BRF_MAX_FILES || strlen(path) >= BRF_PATH)
        return die("z23-lint: blocker-remedy file overflow\n", "");
    memcpy(g.files[g.nfiles], path, strlen(path) + 1);
    g.nfiles++;
    return 0;
}

static int brf_walk(const char *dir)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode))
                rc = brf_walk(path);
            else if (S_ISREG(st.st_mode) && brf_scan_name(name))
                rc = brf_add_file(path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int brf_collect_env(const char *e)
{
    for (const char *p = e; ;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        if (n >= sizeof line)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        int rc = brf_add_file(line);
        if (rc)
            return rc;
        if (!nl)
            break;
        p = nl + 1;
        if (!*p)
            break;
    }
    return 0;
}

static int brf_collect(void)
{
    const char *e = getenv("ZCL_BLOCKER_REMEDY_SCAN_FILES");
    if (e && e[0])
        return brf_collect_env(e);
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_roots / sizeof k_roots[0]; i++) {
        struct stat st;
        if (stat(k_roots[i], &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        rc = brf_walk(k_roots[i]);
    }
    return rc;
}

/* ── line loading ─────────────────────────────────────────────────────── */

static void brf_lines_free(struct brf_lines *l)
{
    for (int i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

static int brf_load_lines(const char *path, struct brf_lines *l, FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(err, "check_blocker_remedy: FATAL — cannot read scanned file: "
                     "%s\n", path);
        return 2;
    }
    l->v = NULL;
    l->n = l->cap = 0;
    char *line = NULL;
    size_t lc = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &lc, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (l->n == l->cap) {
            int ncap = l->cap ? l->cap * 2 : 64;
            char **nv = realloc(l->v, (size_t)ncap * sizeof *nv); // raw-alloc-ok:lint-runtime
            if (!nv) {
                rc = die("z23-lint: out of memory\n", "");
                break;
            }
            l->v = nv;
            l->cap = ncap;
        }
        l->v[l->n] = malloc((size_t)n + 1); // raw-alloc-ok:lint-runtime
        if (!l->v[l->n]) {
            rc = die("z23-lint: out of memory\n", "");
            break;
        }
        memcpy(l->v[l->n], line, (size_t)n + 1);
        l->n++;
    }
    if (rc == 0 && ferror(f)) {
        fprintf(err, "check_blocker_remedy: FATAL — read failed: %s\n", path);
        rc = 2;
    }
    free(line);
    if (fclose(f) != 0 && rc == 0) {
        fprintf(err, "check_blocker_remedy: FATAL — read failed: %s\n", path);
        rc = 2;
    }
    if (rc)
        brf_lines_free(l);
    return rc;
}

/* ── pass 0: #define <NAME>_BLOCKER_ID "literal" ──────────────────────── */

/* One logical line: trailing-backslash continuations joined with a single
 * space, the backslash and any trailing blanks removed. */
static int brf_logical_end(const struct brf_lines *l, int first,
                           size_t *total)
{
    int last = first;
    for (;;) {
        const char *s = l->v[last];
        size_t n = strlen(s);
        *total += n + 1;
        while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
            n--;
        if (!n || s[n - 1] != '\\' || last + 1 >= l->n)
            return last;
        last++;
    }
}

static void brf_join_span(const struct brf_lines *l, int first, int last,
                          char *buf)
{
    size_t used = 0;
    buf[0] = '\0';
    for (int i = first; i <= last; i++) {
        const char *s = l->v[i];
        size_t n = strlen(s);
        while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
            n--;
        if (n && s[n - 1] == '\\' && i < last)
            n--;
        if (i > first)
            buf[used++] = ' ';
        memcpy(buf + used, s, n);
        used += n;
        buf[used] = '\0';
    }
}

static char *brf_logical_line(const struct brf_lines *l, int *cursor)
{
    size_t total = 0;
    int last = brf_logical_end(l, *cursor, &total);
    char *buf = malloc(total + 1); // raw-alloc-ok:lint-runtime
    if (!buf) {
        (void)die("z23-lint: out of memory\n", "");
        return NULL;
    }
    brf_join_span(l, *cursor, last, buf);
    *cursor = last + 1;
    return buf;
}

static int brf_macros_file(const char *path, const regex_t *def,
                           const regex_t *quote, FILE *err)
{
    struct brf_lines l;
    int rc = brf_load_lines(path, &l, err);
    if (rc)
        return rc;
    int cursor = 0;
    while (rc == 0 && cursor < l.n) {
        char *line = brf_logical_line(&l, &cursor);
        if (!line) {
            rc = 2;
            break;
        }
        regmatch_t m[1];
        if (regexec(def, line, 1, m, 0) == 0) {
            const char *s = line + m[0].rm_so;
            const char *np = s + 7;
            while (*np == ' ' || *np == '\t')
                np++;
            const char *bi = strstr(np, "_BLOCKER_ID");
            char name[BRF_NAME], val[BRF_VAL];
            size_t nl = bi ? (size_t)(bi - np) + 11 : 0;
            regmatch_t q[1];
            if (nl == 0 || nl >= sizeof name
                || regexec(quote, s, 1, q, 0) != 0
                || (size_t)(q[0].rm_eo - q[0].rm_so) < 2
                || (size_t)(q[0].rm_eo - q[0].rm_so) - 2 >= sizeof val) {
                free(line);
                rc = die("z23-lint: blocker-remedy macro parse overflow\n", "");
                break;
            }
            memcpy(name, np, nl);
            name[nl] = '\0';
            size_t vl = (size_t)(q[0].rm_eo - q[0].rm_so) - 2;
            memcpy(val, s + q[0].rm_so + 1, vl);
            val[vl] = '\0';
            rc = brf_mac_add(name, val);
        }
        free(line);
    }
    brf_lines_free(&l);
    return rc;
}

/* ── markers: slash-star blocker-id: <pattern> star-slash ─────────────── */

static int brf_markers_file(const char *path, int fidx, const regex_t *mk,
                            FILE *err)
{
    struct brf_lines l;
    int rc = brf_load_lines(path, &l, err);
    if (rc)
        return rc;
    for (int i = 0; rc == 0 && i < l.n; i++) {
        const char *line = l.v[i];
        regmatch_t m[1];
        size_t off = 0;
        while (regexec(mk, line + off, 1, m, 0) == 0) {
            const char *seg = line + off + m[0].rm_so;
            size_t eo = off + (size_t)m[0].rm_eo;
            const char *p = strstr(seg, "blocker-id:");
            if (p) {
                p += 11;
                while (*p == ' ' || *p == '\t')
                    p++;
                char pat[BRF_VAL];
                size_t n = 0;
                while (n + 1 < sizeof pat
                       && (strchr("abcdefghijklmnopqrstuvwxyz"
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "0123456789_.*-", *p) != NULL)
                       && off + (size_t)(p - line) < eo)
                    pat[n++] = *p++;
                pat[n] = '\0';
                g.marker[fidx] = 1;
                rc = brf_set_add(g.ids, &g.nids, BRF_MAX_IDS, pat);
            }
            off = eo > off ? eo : off + 1;
        }
    }
    brf_lines_free(&l);
    return rc;
}

/* ── pass 1: call-site id arguments ───────────────────────────────────── */

/* Quote-aware scan for the ")" closing the "(" at (ln0, off0 - 1). The
 * window starts at logical line ln0; continuation lines are pulled from
 * the shared input cursor `cur` (awk getline semantics), at most
 * BRF_JOIN_MAX of them. Returns 1 and the close position plus how many
 * lines were pulled, or 0 (malformed/truncated) with *pulls set to what
 * the awk loop would still have consumed. */
static int brf_find_close(const struct brf_lines *l, int ln0, int off0,
                          int cur, int *cln, int *coff, int *pulls)
{
    int depth = 1, instr = 0, esc = 0, pulled = 0;
    int ln = ln0;
    for (;;) {
        const char *s = l->v[ln];
        for (int j = (ln == ln0 ? off0 : 0); s[j]; j++) {
            char c = s[j];
            if (instr) {
                if (esc)
                    esc = 0;
                else if (c == '\\')
                    esc = 1;
                else if (c == '"')
                    instr = 0;
            } else if (c == '"') {
                instr = 1;
            } else if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                *cln = ln;
                *coff = j;
                *pulls = pulled;
                return 1;
            }
        }
        if (pulled >= BRF_JOIN_MAX)
            break;
        int nxt = ln == ln0 ? cur : ln + 1;
        if (nxt >= l->n)
            break;
        ln = nxt;
        pulled++;
    }
    *pulls = pulled;
    return 0;
}

/* The argument text between (ln0, off0) and (cln, coff), lines joined by
 * '\n', following the same ln0-then-cursor sequence the awk buffer had. */
static char *brf_span_dup(const struct brf_lines *l, int ln0, int off0,
                          int cur, int cln, int coff)
{
    size_t total = 0;
    if (cln == ln0) {
        total = (size_t)(coff - off0);
    } else {
        total = strlen(l->v[ln0]) - (size_t)off0;
        for (int q = cur; q <= cln; q++)
            total += strlen(l->v[q]) + 1;
        total -= strlen(l->v[cln]) - (size_t)coff;
    }
    char *buf = malloc(total + 1); // raw-alloc-ok:lint-runtime
    if (!buf) {
        (void)die("z23-lint: out of memory\n", "");
        return NULL;
    }
    size_t used = 0;
    if (cln == ln0) {
        memcpy(buf, l->v[ln0] + off0, total);
        used = total;
    } else {
        size_t n0 = strlen(l->v[ln0]) - (size_t)off0;
        memcpy(buf, l->v[ln0] + off0, n0);
        used = n0;
        for (int q = cur; q <= cln; q++) {
            const char *s = l->v[q];
            size_t n = strlen(s);
            if (q == cln)
                n = (size_t)coff;
            buf[used++] = '\n';
            memcpy(buf + used, s, n);
            used += n;
        }
    }
    buf[used] = '\0';
    return buf;
}

/* split_top(): the 1-based `want`-th top-level comma-separated argument
 * span of s. Returns the total argument count (0 if fewer than want). */
static int brf_top_arg(const char *s, int want, int *aoff, int *alen)
{
    int depth = 0, instr = 0, esc = 0, argno = 1, start = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i <= n; i++) {
        char c = i < n ? s[i] : ',';
        int flush = i == n;
        if (!flush) {
            if (instr) {
                if (esc)
                    esc = 0;
                else if (c == '\\')
                    esc = 1;
                else if (c == '"')
                    instr = 0;
                continue;
            }
            if (c == '"') {
                instr = 1;
                continue;
            }
            if (c == '(')
                depth++;
            else if (c == ')')
                depth--;
            if (depth != 0 || c != ',')
                continue;
        }
        if (argno == want) {
            *aoff = start;
            *alen = (int)i - start;
        }
        argno++;
        start = (int)i + 1;
    }
    return argno - 1;
}

/* v with the leading quote already stripped: the length awk's
 * sub(/"[ \t]*$/, "", v) leaves — the first quote followed by blanks only,
 * or the whole thing when no such quote exists. */
static int brf_lit_len(const char *a, int alen)
{
    int n = 0;
    while (n < alen && a[n] != '"')
        n++;
    while (n < alen) {
        int j = n + 1;
        while (j < alen && (a[j] == ' ' || a[j] == '\t'))
            j++;
        if (j == alen)
            break;
        n++;
        while (n < alen && a[n] != '"')
            n++;
    }
    return n;
}

static int brf_ident(const char *a, int alen)
{
    for (int i = 0; i < alen; i++) {
        unsigned char c = (unsigned char)a[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || c == '_' || (i > 0 && c >= '0' && c <= '9')))
            return 0;
    }
    return 1;
}

static int brf_push(int fidx, int startline, int fn, int kind,
                    const char *a, int alen)
{
    char val[BRF_VAL];
    if (alen <= 0 || alen >= (int)sizeof val)
        return die("z23-lint: blocker-remedy value overflow\n", "");
    memcpy(val, a, (size_t)alen);
    val[alen] = '\0';
    if (g.nrows >= BRF_MAX_ROWS)
        return die("z23-lint: blocker-remedy row overflow\n", "");
    struct brf_row *r = &g.rows[g.nrows++];
    r->file = fidx;
    r->line = startline;
    r->fn = fn;
    r->kind = kind;
    memcpy(r->val, val, (size_t)alen + 1);
    return 0;
}

static int brf_emit(int fidx, int startline, int fn, const char *args,
                    const regex_t *decl)
{
    if (regexec(decl, args, 0, NULL, 0) == 0)
        return 0;
    int aoff = 0, alen = 0;
    int m = brf_top_arg(args, k_fn_idx[fn], &aoff, &alen);
    if (k_fn_idx[fn] > m)
        return 0;
    const char *a = args + aoff;
    while (alen > 0 && (*a == ' ' || *a == '\t' || *a == '\n'))
        a++, alen--;
    while (alen > 0 && (a[alen - 1] == ' ' || a[alen - 1] == '\t'
                        || a[alen - 1] == '\n'))
        alen--;
    if (alen == 0)
        return 0;
    int kind;
    if (*a == '"') {
        a++;
        alen = brf_lit_len(a, alen - 1);
        kind = BRF_LIT;
    } else {
        kind = brf_ident(a, alen) ? BRF_ID : BRF_EXPR;
    }
    return brf_push(fidx, startline, fn, kind, a, alen);
}

static int brf_calls_file(const char *path, int fidx, const regex_t *decl,
                          FILE *err)
{
    struct brf_lines l;
    int rc = brf_load_lines(path, &l, err);
    if (rc)
        return rc;
    int cursor = 0;
    while (rc == 0 && cursor < l.n) {
        int ln0 = cursor++;
        const char *line = l.v[ln0];
        for (int k = 0; rc == 0 && k < 4; k++) {
            char needle[80];
            if (ovf(snprintf(needle, sizeof needle, "%s(", k_fns[k]),
                    sizeof needle)) {
                rc = 2;
                break;
            }
            const char *hit = strstr(line, needle);
            if (!hit)
                continue;
            int off0 = (int)(hit - line) + (int)strlen(needle);
            int cur0 = cursor;
            int cln = 0, coff = 0, pulls = 0;
            int found = brf_find_close(&l, ln0, off0, cur0, &cln, &coff,
                                       &pulls);
            cursor += pulls;
            if (!found)
                continue;
            char *args = brf_span_dup(&l, ln0, off0, cur0, cln, coff);
            if (!args) {
                rc = 2;
                break;
            }
            rc = brf_emit(fidx, ln0 + 1, k, args, decl);
            free(args);
        }
    }
    brf_lines_free(&l);
    return rc;
}

/* ── table load ───────────────────────────────────────────────────────── */

/* sub(/\)[ \t]*(\/\*.*\*\/)?[ \t]*$/, "", s) — cut at the leftmost ")" that
 * is followed only by blanks and an optional trailing block comment. */
static void brf_strip_call_tail(char *s)
{
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        if (s[i] != ')')
            continue;
        size_t j = i + 1;
        while (s[j] == ' ' || s[j] == '\t')
            j++;
        if (s[j] == '\0') {
            s[i] = '\0';
            return;
        }
        if (s[j] == '/' && s[j + 1] == '*') {
            char *close = NULL;
            for (char *p = s + j + 2; *p; p++)
                if (p[0] == '*' && p[1] == '/')
                    close = p;
            if (close) {
                j = (size_t)(close - s) + 2;
                while (s[j] == ' ' || s[j] == '\t')
                    j++;
                if (s[j] == '\0') {
                    s[i] = '\0';
                    return;
                }
            }
        }
    }
}

static void brf_trim(char *s)
{
    char *p = s;
    while (*p == ' ' || *p == '\t')
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

/* awk sub(/[ \t]*\/\*.X/, "", remedy) with X="asterisk": cut at the first
 * block-comment opener, preceding blanks included. */
static void brf_strip_remedy_comment(char *s)
{
    char *p = strstr(s, "/*");
    if (!p)
        return;
    while (p > s && (p[-1] == ' ' || p[-1] == '\t'))
        p--;
    *p = '\0';
}

static int brf_table_row(char *s)
{
    brf_strip_call_tail(s);
    char *comma = strchr(s, ',');
    if (!comma)
        return 0;
    *comma = '\0';
    char *id = s, *remedy = comma + 1;
    brf_trim(id);
    brf_trim(remedy);
    brf_strip_remedy_comment(remedy);
    brf_trim(remedy);
    if (!id[0] || !remedy[0])
        return 0;
    if (g.ntab >= BRF_MAX_TABLE || strlen(id) >= BRF_VAL
        || strlen(remedy) >= BRF_VAL)
        return die("z23-lint: blocker-remedy table overflow\n", "");
    memcpy(g.tab[g.ntab].id, id, strlen(id) + 1);
    memcpy(g.tab[g.ntab].remedy, remedy, strlen(remedy) + 1);
    g.ntab++;
    return 0;
}

static int brf_table_load(const char *path, FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(err, "check_blocker_remedy: FATAL — cannot read scanned file: "
                     "%s\n", path);
        return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        if (strncmp(line, "ZCL_BLOCKER_REMEDY(", 19) != 0)
            continue;
        memmove(line, line + 19, n - 19 + 1);
        rc = brf_table_row(line);
    }
    if (rc == 0 && ferror(f)) {
        fprintf(err, "check_blocker_remedy: FATAL — read failed: %s\n", path);
        rc = 2;
    }
    free(line);
    if (fclose(f) != 0 && rc == 0) {
        fprintf(err, "check_blocker_remedy: FATAL — read failed: %s\n", path);
        rc = 2;
    }
    return rc;
}

/* ── condition names and registered escapes ───────────────────────────── */

static int brf_conds_file(const char *path, const regex_t *cond,
                          const regex_t *def, const regex_t *quote, FILE *err)
{
    struct brf_lines l;
    int rc = brf_load_lines(path, &l, err);
    if (rc)
        return rc;
    for (int i = 0; rc == 0 && i < l.n; i++) {
        regmatch_t m[1];
        if (regexec(cond, l.v[i], 1, m, 0) == 0) {
            char name[BRF_VAL];
            size_t n = (size_t)(m[0].rm_eo - m[0].rm_so) - 15;
            if (n == 0 || n >= sizeof name) {
                rc = die("z23-lint: blocker-remedy value overflow\n", "");
                break;
            }
            memcpy(name, l.v[i] + m[0].rm_so + 14, n);
            name[n] = '\0';
            rc = brf_set_add(g.conds, &g.ncond, BRF_MAX_IDS, name);
        }
        if (rc == 0 && regexec(def, l.v[i], 1, m, 0) == 0) {
            regmatch_t q[1];
            if (regexec(quote, l.v[i] + m[0].rm_so, 1, q, 0) == 0) {
                size_t n = (size_t)(q[0].rm_eo - q[0].rm_so);
                if (n < 2 || n - 2 >= BRF_VAL) {
                    rc = die("z23-lint: blocker-remedy value overflow\n", "");
                    break;
                }
                char name[BRF_VAL];
                memcpy(name, l.v[i] + m[0].rm_so + q[0].rm_so + 1, n - 2);
                name[n - 2] = '\0';
                rc = brf_set_add(g.conds, &g.ncond, BRF_MAX_IDS, name);
            }
        }
    }
    brf_lines_free(&l);
    return rc;
}

static int brf_escapes_file(const char *path, const regex_t *esc, FILE *err)
{
    struct brf_lines l;
    int rc = brf_load_lines(path, &l, err);
    if (rc)
        return rc;
    for (int i = 0; rc == 0 && i < l.n; i++) {
        const char *line = l.v[i];
        regmatch_t m[1];
        size_t off = 0;
        while (regexec(esc, line + off, 1, m, 0) == 0) {
            const char *seg = line + off + m[0].rm_so;
            size_t sn = (size_t)(m[0].rm_eo - m[0].rm_so);
            const char *q1 = memchr(seg, '"', sn);
            if (q1 && sn >= 2) {
                size_t inner = sn - (size_t)(q1 - seg) - 2;
                char name[BRF_VAL];
                if (inner == 0 || inner >= sizeof name) {
                    rc = die("z23-lint: blocker-remedy value overflow\n", "");
                    break;
                }
                memcpy(name, q1 + 1, inner);
                name[inner] = '\0';
                rc = brf_set_add(g.escs, &g.nesc, BRF_MAX_IDS, name);
            }
            size_t eo = off + (size_t)m[0].rm_eo;
            off = eo > off ? eo : off + 1;
        }
    }
    brf_lines_free(&l);
    return rc;
}

/* ── row classification ───────────────────────────────────────────────── */

static int brf_classify_rows(void)
{
    int fail = 0;
    for (int i = 0; i < g.nrows; i++) {
        struct brf_row *r = &g.rows[i];
        if (r->kind == BRF_LIT && r->fn != 0)
            g.litwrap[r->file] = 1;
    }
    for (int i = 0; i < g.nrows; i++) {
        struct brf_row *r = &g.rows[i];
        int rc = 0;
        if (r->kind == BRF_LIT) {
            rc = brf_set_add(g.ids, &g.nids, BRF_MAX_IDS, r->val);
        } else {
            const char *mv = r->kind == BRF_ID ? brf_mac_get(r->val) : NULL;
            if (mv)
                rc = brf_set_add(g.ids, &g.nids, BRF_MAX_IDS, mv);
            else if (!g.marker[r->file]
                     && !(r->fn == 0 && g.litwrap[r->file])) {
                if (g.ndyn >= BRF_MAX_ROWS)
                    return die("z23-lint: blocker-remedy row overflow\n", "");
                g.dyn[g.ndyn++] = i;
                fail = 1;
            }
        }
        if (rc)
            return rc;
    }
    return fail;
}

/* ── remedy validity ──────────────────────────────────────────────────── */

static int brf_check_remedies(void)
{
    int fail = 0;
    for (int i = 0; i < g.ntab; i++) {
        const char *rem = g.tab[i].remedy;
        if (strcmp(rem, "OWNER") == 0)
            continue;
        size_t n = strlen(rem);
        if (n > 8 && strncmp(rem, "ESCAPE(", 7) == 0 && rem[n - 1] == ')') {
            char action[BRF_VAL];
            size_t an = n - 8;
            if (an >= sizeof action)
                return die("z23-lint: blocker-remedy value overflow\n", "");
            memcpy(action, rem + 7, an);
            action[an] = '\0';
            if (brf_set_has(g.escs, g.nesc, action))
                g.escape_count++;
            else {
                if (g.nbad >= BRF_MAX_TABLE)
                    return die("z23-lint: blocker-remedy table overflow\n", "");
                g.badr[g.nbad++] = i;
                fail = 1;
            }
            continue;
        }
        if (!brf_set_has(g.conds, g.ncond, rem)) {
            if (g.nbad >= BRF_MAX_TABLE)
                return die("z23-lint: blocker-remedy table overflow\n", "");
            g.badr[g.nbad++] = i;
            fail = 1;
        }
    }
    return fail;
}

/* ── reporting ────────────────────────────────────────────────────────── */

static int brf_report_clean(FILE *out)
{
    int owner = 0, cond = 0;
    for (int i = 0; i < g.ntab; i++) {
        if (strcmp(g.tab[i].remedy, "OWNER") == 0)
            owner++;
        else if (strncmp(g.tab[i].remedy, "ESCAPE(", 7) != 0)
            cond++;
    }
    if (fprintf(out, "check_blocker_remedy: clean — %d bound blocker "
               "id(s)/pattern(s) (%d condition-remedied, %d escape-remedied, "
               "%d OWNER), %d discovered in source, all covered\n",
               g.ntab, cond, g.escape_count, owner, g.nids) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int brf_report_dyn(FILE *out)
{
    if (!g.ndyn)
        return 0;
    if (fprintf(out, "%d dynamic blocker-id call site(s) with no "
                "/* blocker-id: <pattern> */ marker:\n", g.ndyn) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < g.ndyn; i++) {
        struct brf_row *r = &g.rows[g.dyn[i]];
        if (fprintf(out, "  %s:%ld: %s(...) id argument \"%s\" is a bare "
                    "variable/expression with no #define macro, no "
                    "/* blocker-id: <pattern> */ marker, and no same-file "
                    "literal wrapper call to forward from\n",
                    g.files[r->file], r->line, k_fns[r->fn], r->val) < 0)
            return die("z23-lint: write failed\n", "");
    }
    return fputc('\n', out) == EOF ? die("z23-lint: write failed\n", "") : 0;
}

static int brf_report_missing(FILE *out)
{
    if (!g.nmissing)
        return 0;
    if (fprintf(out, "%d blocker id/pattern(s) discovered in source but "
                "MISSING from %s:\n", g.nmissing, k_table_rel) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < g.nmissing; i++)
        if (fprintf(out, "  %s\n", g.ids[g.missing[i]]) < 0)
            return die("z23-lint: write failed\n", "");
    return fputc('\n', out) == EOF ? die("z23-lint: write failed\n", "") : 0;
}

static int brf_report_bad(FILE *out)
{
    if (!g.nbad)
        return 0;
    if (fprintf(out, "%d table row(s) with a remedy that names no real "
                "condition:\n", g.nbad) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < g.nbad; i++) {
        struct brf_trow *t = &g.tab[g.badr[i]];
        size_t n = strlen(t->remedy);
        int k;
        if (n > 8 && strncmp(t->remedy, "ESCAPE(", 7) == 0
            && t->remedy[n - 1] == ')') {
            char action[BRF_VAL];
            if (n - 8 >= sizeof action)
                return die("z23-lint: blocker-remedy value overflow\n", "");
            memcpy(action, t->remedy + 7, n - 8);
            action[n - 8] = '\0';
            k = fprintf(out, "  %s -> \"%s\" (no blocker_register_escape("
                        "\"%s\", ...) call site found anywhere in scope)\n",
                        t->id, t->remedy, action);
        } else {
            k = fprintf(out, "  %s -> \"%s\" (no ZCL_CONDITION(%s) / "
                        "*_COND_NAME \"%s\" found anywhere in scope)\n",
                        t->id, t->remedy, t->remedy, t->remedy);
        }
        if (k < 0)
            return die("z23-lint: write failed\n", "");
    }
    return fputc('\n', out) == EOF ? die("z23-lint: write failed\n", "") : 0;
}

static int brf_report_fix(FILE *out)
{
    if (fprintf(out,
                "Fix options:\n"
                "  1. New blocker id/pattern: add\n"
                "     'ZCL_BLOCKER_REMEDY(<id_or_pattern>, <condition_name_or_OWNER>)' to\n"
                "     %s. Use a real condition name ONLY if you have verified in\n"
                "     code that it detects/clears this exact blocker (directly or by\n"
                "     driving the state its raiser self-clears on) — otherwise OWNER.\n"
                "  2. New dynamic (snprintf-built) blocker id: add a\n"
                "     '/* blocker-id: <pattern-with-*> */' marker comment at the\n"
                "     construction site (collapse each conversion specifier to a\n"
                "     single '*'), matching an existing example in\n"
                "     engine/jobs/src/stage_repair_coin_backfill_util.c.\n"
                "  3. Remedy names no condition: fix the typo, or add a\n"
                "     ZCL_CONDITION(<name>) entry to condition_registry.def if the\n"
                "     condition genuinely exists but isn't registered yet.\n",
                k_table_rel) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int brf_report_failed(FILE *out)
{
    if (fputs("\ncheck_blocker_remedy: FAILED\n\n", out) < 0)
        return die("z23-lint: write failed\n", "");
    int rc = brf_report_dyn(out);
    if (rc == 0)
        rc = brf_report_missing(out);
    if (rc == 0)
        rc = brf_report_bad(out);
    if (rc)
        return rc;
    return brf_report_fix(out);
}

/* ── the gate ─────────────────────────────────────────────────────────── */

struct brf_res {
    regex_t def, quote, marker, decl, cond, conddef, esc;
};

static int brf_compile(struct brf_res *r)
{
    int cr = reg_fail(&r->def, regcomp(&r->def,
        "#define[ \t]+[A-Za-z_][A-Za-z0-9_]*_BLOCKER_ID[ \t]+"
        "\"([^\"\\\\]|\\\\.)*\"", REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&r->quote, regcomp(&r->quote,
            "\"([^\"\\\\]|\\\\.)*\"", REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&r->marker, regcomp(&r->marker,
            "/\\*[ \t]*blocker-id:[ \t]*[A-Za-z0-9_.*-]+[ \t]*\\*/",
            REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&r->decl, regcomp(&r->decl,
            "const[ \t]+char[ \t]*\\*", REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&r->cond, regcomp(&r->cond,
            "ZCL_CONDITION\\([A-Za-z0-9_]+\\)", REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&r->conddef, regcomp(&r->conddef,
            "#define[ \t]+[A-Za-z0-9_]+_COND_NAME[ \t]+\"([^\"\\\\]|\\\\.)*\"",
            REG_EXTENDED));
    if (cr == 0)
        cr = reg_fail(&r->esc, regcomp(&r->esc,
            "blocker_register_escape\\([ \t]*\"[^\"]+\"", REG_EXTENDED));
    return cr;
}

static void brf_res_free(struct brf_res *r, int n)
{
    regex_t *re[] = { &r->def, &r->quote, &r->marker, &r->decl,
                      &r->cond, &r->conddef, &r->esc };
    for (int i = 0; i < n && i < 7; i++)
        regfree(re[i]);
}

static int brf_pass0(const struct brf_res *rs, FILE *err)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < g.nfiles; i++)
        rc = brf_macros_file(g.files[i], &rs->def, &rs->quote, err);
    return rc;
}

static int brf_passes(const struct brf_res *rs, FILE *err)
{
    int rc = brf_pass0(rs, err);
    for (int i = 0; rc == 0 && i < g.nfiles; i++)
        rc = brf_markers_file(g.files[i], i, &rs->marker, err);
    for (int i = 0; rc == 0 && i < g.nfiles; i++)
        rc = brf_calls_file(g.files[i], i, &rs->decl, err);
    for (int i = 0; rc == 0 && i < g.nfiles; i++)
        rc = brf_conds_file(g.files[i], &rs->cond, &rs->conddef, &rs->quote,
                            err);
    for (int i = 0; rc == 0 && i < g.nfiles; i++)
        rc = brf_escapes_file(g.files[i], &rs->esc, err);
    return rc;
}

/* Collect the scan set, run every extraction pass over it, and classify
 * discovered ids. On success *fail carries the pre-table failure flag. */
static int brf_scan_source(FILE *err, int *fail)
{
    int rc = brf_collect();
    if (rc == 0 && g.nfiles == 0) {
        fputs("check_blocker_remedy: no files to scan\n", err);
        rc = 1;
    }
    struct brf_res rs;
    if (rc == 0)
        rc = brf_compile(&rs);
    if (rc == 0) {
        rc = brf_passes(&rs, err);
        brf_res_free(&rs, 7);
    }
    if (rc == 0) {
        *fail = brf_classify_rows();
        if (*fail == 2)
            rc = 2;
    }
    return rc;
}

/* Load the binding table and list discovered ids with no matching row. */
static int brf_load_table(FILE *err)
{
    int rc = brf_table_load(k_table_rel, err);
    if (rc)
        return rc;
    if (g.ntab == 0) {
        fprintf(err, "check_blocker_remedy: parsed zero rows from %s — "
                     "parser or table is broken\n", k_table_rel);
        return 1;
    }
    for (int i = 0; i < g.nids; i++) {
        if (!brf_tab_has(g.ids[i])) {
            if (g.nmissing >= BRF_MAX_IDS)
                return die("z23-lint: blocker-remedy set overflow\n", "");
            g.missing[g.nmissing++] = i;
        }
    }
    return 0;
}

static int brf_impl(FILE *out, FILE *err)
{
    memset(&g, 0, sizeof g);
    struct stat st;
    if (stat(k_table_rel, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(err, "check_blocker_remedy: missing %s\n", k_table_rel);
        return 1;
    }
    int fail = 0;
    int rc = brf_scan_source(err, &fail);
    if (rc == 0)
        rc = brf_load_table(err);
    if (rc)
        return rc;
    if (brf_check_remedies() || fail || g.nmissing > 0)
        return brf_report_failed(out);
    return brf_report_clean(out);
}

int check_blocker_remedy_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return brf_impl(stdout, stderr);
}

/* ── fixture self-test ────────────────────────────────────────────────── */

static const char k_st_def[] =
    "ZCL_BLOCKER_REMEDY(utxo.demo, OWNER)\n"
    "ZCL_BLOCKER_REMEDY(coin_backfill.*, ESCAPE(rebuild))\n"
    "ZCL_BLOCKER_REMEDY(macro.id, cond_heal)\n"
    "ZCL_BLOCKER_REMEDY(split.id, OWNER)\n";
static const char k_st_a_c[] =
    "void f(void) { blocker_init(&b, \"utxo.demo\", \"why\", 1); }\n"
    "void g(void) { blocker_init(&b,\n"
    "    \"split.id\",\n"
    "    \"why\", 1); }\n";
static const char k_st_b_c[] =
    "#define DEMO_BLOCKER_ID \"macro.id\"\n"
    "void h(void) { blocker_init(&b, DEMO_BLOCKER_ID, \"r\", 2); }\n";
static const char k_st_c_c[] =
    "void e(void) { blocker_register_escape(\"rebuild\", rebuild_fn); }\n";
static const char k_st_reg[] = "ZCL_CONDITION(cond_heal)\n";

static int brf_st_plant(const char *def_text, const char *a_text)
{
    int rc = csr_write("./engine/conditions/include/conditions/"
                       "blocker_remedy_bindings.def", def_text);
    if (rc == 0 && a_text)
        rc = csr_write("./engine/jobs/src/a.c", a_text);
    return rc;
}

static int brf_st_full_fixture(void)
{
    int rc = brf_st_plant(k_st_def, k_st_a_c);
    if (rc == 0)
        rc = csr_write("./engine/jobs/src/b.c", k_st_b_c);
    if (rc == 0)
        rc = csr_write("./engine/services/src/c.c", k_st_c_c);
    if (rc == 0)
        rc = csr_write("./engine/conditions/condition_registry.def", k_st_reg);
    return rc;
}

/* Run the gate in the current (fixture) directory, capture out/err, assert
 * rc and (non-NULL) needles. */
static int brf_st_run(int want, const char *out_needle, const char *err_needle)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int rc = brf_impl(out, err);
    static char ob[16384], eb[4096];
    int bad = csr_slurp(out, ob, sizeof ob) || csr_slurp(err, eb, sizeof eb)
        || rc != want
        || (out_needle && strstr(ob, out_needle) == NULL)
        || (err_needle && strstr(eb, err_needle) == NULL);
    fclose(out);
    fclose(err);
    return bad;
}

static int brf_st_case(int step, const char *tag, int bad)
{
    if (bad)
        fprintf(stderr, "check_blocker_remedy selftest: step %d failed: %s\n",
                step, tag);
    return bad;
}

static int brf_st_clean_cases(const char *root, int *step, char *cwd)
{
    int bad = 0;
    if (chdir(root) != 0)
        return 1;
    bad |= brf_st_full_fixture();
    bad |= brf_st_case((*step)++, "clean pass",
                       brf_st_run(0, "check_blocker_remedy: clean — 4 bound "
                     "blocker id(s)/pattern(s) (1 condition-remedied, "
                     "1 escape-remedied, 2 OWNER), 3 discovered in source, "
                     "all covered", NULL));
    /* A dynamic id with a marker at its construction site is covered. */
    bad |= csr_write("./engine/jobs/src/d.c",
                     "void d(char *id) { /* blocker-id: coin_backfill.* */\n"
                     "  blocker_init(&b, id, \"r\", 1); }\n");
    bad |= brf_st_case((*step)++, "marker-covered dynamic id",
                       brf_st_run(0, "4 discovered in source", NULL));
    /* A same-file literal wrapper call forwards to a bare blocker_init. */
    bad |= unlink("./engine/jobs/src/d.c") != 0;
    bad |= csr_write("./engine/jobs/src/e.c",
                     "void w(void) { chain_linkage_hold_raise(&x, "
                     "\"utxo.demo\", \"r\"); }\n"
                     "void i(char *dyn) { blocker_init(&b, dyn, \"r\", 1); }\n");
    bad |= brf_st_case((*step)++, "wrapper-forwarded dynamic id",
                       brf_st_run(0, "3 discovered in source", NULL));
    if (chdir(cwd) != 0)
        return 1;
    return bad;
}

static int brf_st_violation_cases(const char *root, int *step, char *cwd)
{
    int bad = 0;
    if (chdir(root) != 0)
        return 1;
    bad |= brf_st_full_fixture();
    bad |= csr_write("./engine/jobs/src/d.c",
                     "void d(char *id) { blocker_init(&b, id, \"r\", 1); }\n");
    bad |= brf_st_case((*step)++, "bare-variable dynamic id",
                       brf_st_run(1, "engine/jobs/src/d.c:1: blocker_init(...) "
                     "id argument \"id\" is a bare variable/expression", NULL));
    bad |= csr_write("./engine/jobs/src/d.c",
                     "void d(int i) { blocker_init(&b, names[i], \"r\", 1); }\n");
    bad |= brf_st_case((*step)++, "expression dynamic id",
                       brf_st_run(1, "id argument \"names[i]\" is a bare "
                     "variable/expression", NULL));
    bad |= csr_write("./engine/jobs/src/d.c",
                     "void n(void) { blocker_init(&b, \"no.row\", \"r\", 1); }\n");
    bad |= brf_st_case((*step)++, "literal id missing from the table",
                       brf_st_run(1, "1 blocker id/pattern(s) discovered in "
                     "source but MISSING from", NULL));
    bad |= brf_st_case((*step)++, "missing section names the id",
                       brf_st_run(1, "  no.row\n", NULL));
    if (chdir(cwd) != 0)
        return 1;
    return bad;
}

static int brf_st_remedy_cases(const char *root, int *step, char *cwd)
{
    int bad = 0;
    if (chdir(root) != 0)
        return 1;
    bad |= brf_st_full_fixture();
    bad |= brf_st_plant("ZCL_BLOCKER_REMEDY(ghost.id, no_such_cond)\n"
                        "ZCL_BLOCKER_REMEDY(utxo.demo, OWNER)\n"
                        "ZCL_BLOCKER_REMEDY(coin_backfill.*, ESCAPE(rebuild))\n"
                        "ZCL_BLOCKER_REMEDY(macro.id, cond_heal)\n"
                        "ZCL_BLOCKER_REMEDY(split.id, OWNER)\n", NULL);
    bad |= brf_st_case((*step)++, "remedy naming no condition",
                       brf_st_run(1, "ghost.id -> \"no_such_cond\" (no "
                     "ZCL_CONDITION(no_such_cond)", NULL));
    bad |= brf_st_plant("ZCL_BLOCKER_REMEDY(esc.id, ESCAPE(no_such))\n"
                        "ZCL_BLOCKER_REMEDY(utxo.demo, OWNER)\n"
                        "ZCL_BLOCKER_REMEDY(coin_backfill.*, ESCAPE(rebuild))\n"
                        "ZCL_BLOCKER_REMEDY(macro.id, cond_heal)\n"
                        "ZCL_BLOCKER_REMEDY(split.id, OWNER)\n", NULL);
    bad |= brf_st_case((*step)++, "ESCAPE remedy with no registration",
                       brf_st_run(1, "esc.id -> \"ESCAPE(no_such)\" (no "
                     "blocker_register_escape(\"no_such\", ...)", NULL));
    if (chdir(cwd) != 0)
        return 1;
    return bad;
}

static int brf_st_structural_cases(const char *root, int *step, char *cwd)
{
    int bad = 0;
    if (chdir(root) != 0)
        return 1;
    bad |= brf_st_full_fixture();
    bad |= csr_write("./engine/conditions/include/conditions/"
                     "blocker_remedy_bindings.def", "# no rows\n");
    bad |= brf_st_case((*step)++, "zero-row table fails closed",
                       brf_st_run(1, NULL, "parsed zero rows from"));
    bad |= unlink("./engine/conditions/include/conditions/"
                  "blocker_remedy_bindings.def") != 0;
    bad |= brf_st_case((*step)++, "missing table fails closed",
                       brf_st_run(1, NULL, "check_blocker_remedy: missing "
                     "engine/conditions/include/conditions/"
                     "blocker_remedy_bindings.def"));
    bad |= csr_write("./engine/conditions/include/conditions/"
                     "blocker_remedy_bindings.def",
                     "ZCL_BLOCKER_REMEDY(utxo.demo, OWNER)\n"
                     "ZCL_BLOCKER_REMEDY(split.id, OWNER)\n");
    bad |= setenv("ZCL_BLOCKER_REMEDY_SCAN_FILES",
                  "engine/jobs/src/a.c", 1) != 0;
    bad |= brf_st_case((*step)++, "env file-list override",
                       brf_st_run(0, "2 bound blocker id(s)/pattern(s) "
                     "(0 condition-remedied, 0 escape-remedied, 2 OWNER), "
                     "2 discovered in source", NULL));
    bad |= unsetenv("ZCL_BLOCKER_REMEDY_SCAN_FILES") != 0;
    if (chdir(cwd) != 0)
        return 1;
    return bad;
}

static int brf_st_edge_cases(const char *root, int *step, char *cwd)
{
    int bad = 0;
    if (chdir(root) != 0)
        return 1;
    bad |= brf_st_full_fixture();
    bad |= chmod("./engine/jobs/src/a.c", 0) != 0;
    bad |= brf_st_case((*step)++, "unreadable scanned file is UNPROVEN",
                       brf_st_run(2, NULL, "cannot read scanned file"));
    bad |= chmod("./engine/jobs/src/a.c", 0600) != 0;
    if (chdir(cwd) != 0)
        return 1;
    return bad;
}

int check_blocker_remedy_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-brf-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    int step = 1;
    int bad = brf_st_clean_cases(root, &step, cwd)
        | brf_st_violation_cases(root, &step, cwd)
        | brf_st_remedy_cases(root, &step, cwd)
        | brf_st_structural_cases(root, &step, cwd)
        | brf_st_edge_cases(root, &step, cwd);
    (void)unsetenv("ZCL_BLOCKER_REMEDY_SCAN_FILES");
    if (chdir(cwd) != 0)
        bad = 1;
    (void)rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_blocker_remedy selftest\n", stderr);
    return st_ok(bad, "check_blocker_remedy selftest: OK\n");
}
