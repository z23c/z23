/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: scan half of the check_blocker_handoff_declared gate. Collects
 * the production .c/.h scan set under the configured roots (same scope and
 * exclusions as the shell original), then runs three passes over each file:
 * the BLOCKER_ID macro table, the blocker-id marker comments, and the raise
 * site extraction with per-function escape-arming analysis. All state lives
 * in fixed static arrays; on overflow the gate prints an "exceeds" line and
 * the caller fails with exit 2.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "lintc.h"
#include "gate_blocker_handoff_declared_priv.h"

static const char k_bhs_gate[] = "check_blocker_handoff_declared";

char bh_files[BH_FILES][BH_PATH];
int bh_nfiles;
struct bh_site bh_sites[BH_SITES];
int bh_nsites;
char bh_macros[BH_MACRO][2][BH_IDLEN];
int bh_nmacros;
char bh_fmark[BH_FILES][BH_MARKLEN];
size_t bh_got;
char bh_scratch[BH_SCRATCH];

static size_t bh_loff[BH_LINES];
static int bh_nlines;
static char bh_root_buf[BH_PATH];
static int bh_root_dot;

struct bh_fninfo { const char *name; char idx; char rec; };
static const struct bh_fninfo k_bh_fns[5] = {
    { "blocker_init", 2, 1 },
    { "blocker_name_dependency", 1, 0 },
    { "chain_linkage_hold_raise", 2, 0 },
    { "sentinel_raise_blocker", 1, 0 },
    { "name_dependency_blocker", 1, 0 },
};

static const char k_bh_ident[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
static const char k_bh_marker[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.*-";

void bh_reset(void)
{
    bh_nfiles = 0;
    bh_nsites = 0;
    bh_nmacros = 0;
    bh_nlines = 0;
}

int bh_path(char *out, size_t cap, const char *rel)
{
    if (bh_root_dot)
        return ovf(snprintf(out, cap, "%s", rel), cap) ? 2 : 0;
    return ovf(snprintf(out, cap, "%s/%s", bh_root_buf, rel), cap) ? 2 : 0;
}

static int bh_excluded(const char *rel)
{
    static const char *const k_ex[] = {
        "platform/modules/util/src/blocker.c",
        "platform/modules/util/include/util/blocker.h",
        NULL
    };
    if (strncmp(rel, "tests/harness/include/test/", 27) == 0)
        return 1;
    for (int i = 0; k_ex[i]; i++)
        if (strcmp(rel, k_ex[i]) == 0)
            return 1;
    return 0;
}

static int bh_add_file(const char *rel)
{
    size_t n = strlen(rel);
    if (n < 2 || (strcmp(rel + n - 2, ".c") != 0 && strcmp(rel + n - 2, ".h") != 0))
        return 0;
    if (bh_excluded(rel))
        return 0;
    if (bh_nfiles >= BH_FILES || n >= BH_PATH) {
        fprintf(stderr, "%s: scan set exceeds %d files or path exceeds %d\n",
                k_bhs_gate, BH_FILES, BH_PATH);
        return 2;
    }
    strcpy(bh_files[bh_nfiles], rel);
    bh_nfiles++;
    return 0;
}

static int bh_walk(const char *rel, int depth);

/* find -type f: regular files only, symlinks and directories are not
 * files. Directories are descended, the same as find's recursion. */
static int bh_walk_entry(const char *sub, int depth)
{
    char full[BH_PATH];
    struct stat st;
    if (bh_path(full, sizeof full, sub))
        return 2;
    if (lstat(full, &st) != 0)
        return 0;
    if (S_ISDIR(st.st_mode))
        return bh_walk(sub, depth + 1);
    if (S_ISREG(st.st_mode))
        return bh_add_file(sub);
    return 0;
}

static int bh_walk(const char *rel, int depth)
{
    if (depth > 24)
        return 0;
    char full[BH_PATH];
    if (bh_path(full, sizeof full, rel))
        return 2;
    DIR *d = opendir(full);
    if (!d)
        return 0; /* find silenced unreadable dirs; keep walking */
    int rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char sub[BH_PATH];
        if (ovf(snprintf(sub, sizeof sub, "%s%s%s", rel,
                         *rel ? "/" : "", e->d_name), sizeof sub)) {
            rc = 2;
            break;
        }
        rc = bh_walk_entry(sub, depth);
    }
    closedir(d);
    return rc;
}

static int bh_root_ok(const char *rel)
{
    char full[BH_PATH];
    struct stat st;
    if (bh_path(full, sizeof full, rel))
        return 0;
    return stat(full, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Records the tree root every bh_path() join is taken against. Must run
 * before any table or file path is resolved (the handoff tables are read
 * before the scan set is collected). */
int bh_set_root(const char *root)
{
    if (strlen(root) >= sizeof bh_root_buf) {
        fprintf(stderr, "%s: root path exceeds %d\n", k_bhs_gate, BH_PATH);
        return 2;
    }
    strcpy(bh_root_buf, root);
    bh_root_dot = strcmp(root, ".") == 0;
    return 0;
}

/* Walks each configured root; directories that do not exist are skipped,
 * exactly like the [ -d ] guard of the shell original. */
int bh_collect_files(const char *roots_spec)
{
    char spec[BH_ARGS];
    if (strlen(roots_spec) >= sizeof spec) {
        fprintf(stderr, "%s: scan root list exceeds %d\n", k_bhs_gate, BH_ARGS);
        return 2;
    }
    strcpy(spec, roots_spec);
    for (char *tok = strtok(spec, " \t"); tok; tok = strtok(NULL, " \t")) {
        if (!bh_root_ok(tok))
            continue;
        int rc = bh_walk(tok, 0);
        if (rc)
            return rc;
    }
    return 0;
}

/* Slurps one file whole and builds the line offset table. Returns 0 ok,
 * 1 missing (the caller decides), 2 error (fail closed, message printed). */
static int bh_slurp(const char *rel)
{
    char full[BH_PATH];
    if (bh_path(full, sizeof full, rel))
        return 2;
    FILE *f = fopen(full, "rb");
    if (!f) {
        fprintf(stderr, "%s: cannot read tracked file %s\n", k_bhs_gate, rel);
        return 2;
    }
    bh_got = fread(bh_scratch, 1, BH_SCRATCH, f);
    int bad = ferror(f);
    fclose(f);
    if (bad) {
        fprintf(stderr, "%s: read error on %s\n", k_bhs_gate, rel);
        return 2;
    }
    if (bh_got == BH_SCRATCH) {
        fprintf(stderr, "%s: %s exceeds %d bytes\n", k_bhs_gate, rel, BH_SCRATCH);
        return 2;
    }
    bh_scratch[bh_got] = '\0';
    size_t end = bh_got;
    if (end > 0 && bh_scratch[end - 1] == '\n')
        end--;
    bh_nlines = 0;
    size_t start = 0;
    for (size_t i = 0; i <= end; i++) {
        int cut = i == end || bh_scratch[i] == '\n';
        if (!cut)
            continue;
        if (i - start >= BH_LLINE || bh_nlines >= BH_LINES) {
            fprintf(stderr, "%s: %s exceeds %d bytes per line or %d lines\n",
                    k_bhs_gate, rel, BH_LLINE, BH_LINES);
            return 2;
        }
        bh_loff[bh_nlines++] = start;
        bh_scratch[i] = '\0';
        start = i + 1;
    }
    return 0;
}

static const char *bh_line(int i) /* 1-based */
{
    return &bh_scratch[bh_loff[i - 1]];
}

/* Joins backslash continuations starting at ln; *next is the following
 * unconsumed line number. */
static int bh_join(int ln, char *buf, size_t cap, int *next)
{
    *next = ln + 1;
    const char *l = bh_line(ln);
    if (strlen(l) >= cap)
        return 2;
    strcpy(buf, l);
    for (int i = ln + 1; i <= bh_nlines; i++) {
        size_t n = strlen(buf);
        while (n > 0 && (buf[n - 1] == ' ' || buf[n - 1] == '\t'))
            n--;
        if (n == 0 || buf[n - 1] != '\\')
            return 0;
        buf[n - 1] = '\0';
        const char *cont = bh_line(i);
        if (strlen(buf) + strlen(cont) + 2 >= cap)
            return 2;
        strcat(buf, " ");
        strcat(buf, cont);
        *next = i + 1;
    }
    return 0;
}

static int bh_macro_store(const char *name, size_t nlen, const char *val,
                          size_t vlen)
{
    for (int i = 0; i < bh_nmacros; i++)
        if (strlen(bh_macros[i][0]) == nlen &&
            strncmp(bh_macros[i][0], name, nlen) == 0) {
            if (vlen >= BH_IDLEN)
                return 2;
            memcpy(bh_macros[i][1], val, vlen);
            bh_macros[i][1][vlen] = '\0';
            return 0;
        }
    if (bh_nmacros >= BH_MACRO || nlen >= BH_IDLEN || vlen >= BH_IDLEN)
        return 2;
    memcpy(bh_macros[bh_nmacros][0], name, nlen);
    bh_macros[bh_nmacros][0][nlen] = '\0';
    memcpy(bh_macros[bh_nmacros][1], val, vlen);
    bh_macros[bh_nmacros][1][vlen] = '\0';
    bh_nmacros++;
    return 0;
}

/* One logical line of the macro pass: a define of an identifier ending in
 * _BLOCKER_ID with a string literal value. */
static int bh_macro_line(const char *line)
{
    const char *p = strstr(line, "#define");
    if (!p)
        return 0;
    p += 7;
    p += strspn(p, " \t");
    size_t n = strspn(p, k_bh_ident);
    if (n <= 11 || strncmp(p + n - 11, "_BLOCKER_ID", 11) != 0)
        return 0;
    const char *q = p + n;
    q += strspn(q, " \t");
    if (*q != '"')
        return 0;
    q++;
    const char *v = q;
    while (*q && *q != '"') {
        if (*q == '\\' && q[1])
            q++;
        q++;
    }
    if (*q != '"')
        return 0;
    return bh_macro_store(p, n, v, (size_t)(q - v));
}

static int bh_macro_pass(void)
{
    static char buf[BH_JOIN];
    for (int ln = 1; ln <= bh_nlines;) {
        int next;
        if (bh_join(ln, buf, sizeof buf, &next)) {
            fprintf(stderr, "%s: joined #define exceeds %d bytes\n",
                    k_bhs_gate, BH_JOIN);
            return 2;
        }
        int rc = bh_macro_line(buf);
        if (rc)
            return rc;
        ln = next;
    }
    return 0;
}

static int bh_mark_store(int fidx, const char *s, size_t n)
{
    char *dst = bh_fmark[fidx];
    size_t have = strlen(dst);
    size_t need = n + (have ? 1 : 0);
    if (have + need >= BH_MARKLEN)
        return 2;
    if (have)
        dst[have++] = ' ';
    memcpy(dst + have, s, n);
    dst[have + n] = '\0';
    return 0;
}

static int bh_marker_line(const char *line, int fidx)
{
    const char *p = line;
    while ((p = strstr(p, "/*")) != NULL) {
        const char *q = p + 2;
        q += strspn(q, " \t");
        if (strncmp(q, "blocker-id:", 11) == 0) {
            q += 11;
            q += strspn(q, " \t");
            const char *s = q;
            q += strspn(q, k_bh_marker);
            const char *e = q + strspn(q, " \t");
            if (q > s && strncmp(e, "*/", 2) == 0)
                if (bh_mark_store(fidx, s, (size_t)(q - s)))
                    return 2;
        }
        p += 2;
    }
    return 0;
}

static int bh_marker_pass(int fidx)
{
    for (int ln = 1; ln <= bh_nlines; ln++) {
        int rc = bh_marker_line(bh_line(ln), fidx);
        if (rc)
            return rc;
    }
    return 0;
}

static char *bh_trim(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n'))
        s[--n] = '\0';
    while (*s == ' ' || *s == '\t' || *s == '\n')
        s++;
    return s;
}

static int bh_is_ident(const char *s)
{
    if (!*s)
        return 0;
    /* first char: a letter or '_' (never a digit) */
    if ((*s >= '0' && *s <= '9') || !strchr(k_bh_ident, *s))
        return 0;
    for (const char *p = s + 1; *p; p++)
        if (!strchr(k_bh_ident, *p))
            return 0;
    return 1;
}

static long bh_find_close(const char *buf, size_t start)
{
    int depth = 1, instr = 0, esc = 0;
    for (size_t i = start; buf[i]; i++) {
        char c = buf[i];
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
        } else if (c == ')') {
            depth--;
            if (depth == 0)
                return (long)i;
        }
    }
    return -1;
}

static int bh_split_top(char *s, char *av[], int max)
{
    int cnt = 0, depth = 0, instr = 0, esc = 0;
    char *cur = s;
    for (char *p = s; ; p++) {
        char c = *p;
        if (c == '\0') {
            if (cnt >= max)
                return -1;
            av[cnt++] = cur;
            return cnt;
        }
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
        } else if (c == '(') {
            depth++;
        } else if (c == ')') {
            depth--;
        } else if (c == ',' && depth == 0) {
            if (cnt >= max)
                return -1;
            *p = '\0';
            av[cnt++] = cur;
            cur = p + 1;
        }
    }
}

/* True when the assignment after this escape_action token is an explicit
 * empty: 0, "" or a quoted backslash-zero. */
static int bh_empty_assign(const char *p)
{
    if (*p == '[') {
        p++;
        while (*p && *p != ']')
            p++;
        if (*p != ']')
            return 0;
        p++;
    }
    p += strspn(p, " \t");
    if (*p != '=')
        return 0;
    p++;
    p += strspn(p, " \t");
    int len = 0;
    if (p[0] == '0')
        len = 1;
    else if (p[0] == '"' && p[1] == '"')
        len = 2;
    else if (p[0] != '\0' && p[1] == '\\' && p[2] == '0' && p[3] != '\0')
        len = 4; /* awk class .\0. : any char, backslash, zero, any char */
    if (len == 0)
        return 0;
    p += len;
    p += strspn(p, " \t");
    return *p == ';';
}

static int bh_explicit_empty(const char *line)
{
    const char *p = line;
    while ((p = strstr(p, "escape_action")) != NULL) {
        if (bh_empty_assign(p + 13))
            return 1;
        p++;
    }
    return 0;
}

/* Does var get a non-empty escape action between line `from` and the end of
 * the enclosing function? An explicit empty anywhere in the window wins. */
static int bh_escape_after(const char *var, int from)
{
    char pat1[96], pat2[96], line[BH_LLINE];
    if (ovf(snprintf(pat1, sizeof pat1, "%s.escape_action", var), sizeof pat1))
        return -2;
    if (ovf(snprintf(pat2, sizeof pat2, "%s->escape_action", var), sizeof pat2))
        return -2;
    int lim = from + 200;
    if (lim > bh_nlines)
        lim = bh_nlines;
    int armed = 0;
    for (int i = from; i <= lim; i++) {
        if (i > from && bh_line(i)[0] == '}')
            break;
        strcpy(line, bh_line(i));
        if (!strstr(line, pat1) && !strstr(line, pat2))
            continue;
        if (bh_explicit_empty(line))
            return 0;
        armed = 1;
    }
    return armed;
}

/* has_esc for a blocker_init site: validate the record variable and look
 * forward. Returns 0/1, or -2 on internal overflow. */
static int bh_site_escape(char *av0, int ln)
{
    char *rec = bh_trim(av0);
    if (*rec == '&')
        rec++;
    if (!bh_is_ident(rec))
        return 0;
    return bh_escape_after(rec, ln);
}

/* Builds the call text starting at the raise line, joining up to 60 lines
 * until the parenthesis closes. */
static int bh_build_call(const char *first, int ln, size_t nameoff,
                         size_t namelen, char *buf, size_t cap, long *close)
{
    if (strlen(first) >= cap)
        return 2;
    strcpy(buf, first);
    size_t have = strlen(buf);
    int joins = 0, i = ln;
    *close = bh_find_close(buf, nameoff + namelen + 1);
    while (*close < 0 && joins < 60 && i < bh_nlines) {
        i++;
        joins++;
        const char *nl = bh_line(i);
        if (have + strlen(nl) + 2 >= cap)
            return 2;
        buf[have++] = '\n';
        strcpy(buf + have, nl);
        have += strlen(nl);
        *close = bh_find_close(buf, nameoff + namelen + 1);
    }
    return 0;
}

static int bh_proto(const char *args)
{
    const char *p = strstr(args, "const");
    if (!p)
        return 0;
    p += 5;
    p += strspn(p, " \t");
    if (strncmp(p, "char", 4) != 0)
        return 0;
    p += 4;
    p += strspn(p, " \t");
    return *p == '*';
}

/* Classifies the id argument and copies its text for the site row. */
static int bh_site_kind(char *a, char *kind, char *val)
{
    if (*a == '"') {
        char *end = a + strlen(a);
        a++;
        *kind = 'l';
        while (end > a && (end[-1] == ' ' || end[-1] == '\t'))
            end--;
        if (end > a && end[-1] == '"')
            end--;
        *end = '\0';
    } else if (bh_is_ident(a)) {
        *kind = 'i';
    } else {
        *kind = 'e';
    }
    if (strlen(a) >= BH_VAL)
        return 2;
    strcpy(val, a);
    return 0;
}

static int bh_store_site(int fidx, int ln, int k, char kind, int has_esc,
                         const char *val)
{
    if (bh_nsites >= BH_SITES)
        return 2;
    struct bh_site *st = &bh_sites[bh_nsites++];
    st->fidx = fidx;
    st->line = ln;
    st->fnk = (char)(k + 1);
    st->kind = kind;
    st->has_esc = (char)has_esc;
    strcpy(st->val, val);
    return 0;
}

/* Tries one raise form on one line; mirrors one iteration of the awk
 * flush() loop, including the first-occurrence-only rule. */
static int bh_try_raise(int fidx, int ln, int k)
{
    const char *line = bh_line(ln);
    const char *name = k_bh_fns[k].name;
    char namep[48];
    if (ovf(snprintf(namep, sizeof namep, "%s(", name), sizeof namep))
        return 2;
    const char *at = strstr(line, namep);
    if (!at)
        return 0;
    if (at > line && strchr(k_bh_ident, at[-1]))
        return 0;
    static char buf[BH_RBUF], args[BH_ARGS], *av[24];
    long close;
    size_t nameoff = (size_t)(at - line), namelen = strlen(name);
    int rc = bh_build_call(line, ln, nameoff, namelen, buf, sizeof buf, &close);
    if (rc)
        return rc;
    if (close < 0)
        return 0;
    size_t a0 = nameoff + namelen + 1;
    size_t alen = (size_t)close - a0;
    if (alen >= sizeof args)
        return 2;
    memcpy(args, buf + a0, alen);
    args[alen] = '\0';
    if (bh_proto(args))
        return 0;
    int m = bh_split_top(args, av, 24);
    if (m < 0)
        return 2;
    if (k_bh_fns[k].idx > m)
        return 0;
    char *a = bh_trim(av[k_bh_fns[k].idx - 1]);
    if (!*a)
        return 0;
    int has_esc = 0;
    if (k_bh_fns[k].rec) {
        has_esc = bh_site_escape(av[0], ln);
        if (has_esc == -2)
            return 2;
    }
    char kind, val[BH_VAL];
    if (bh_site_kind(a, &kind, val))
        return 2;
    return bh_store_site(fidx, ln, k, kind, has_esc, val);
}

static int bh_raise_pass(int fidx)
{
    for (int ln = 1; ln <= bh_nlines; ln++)
        for (int k = 0; k < 5; k++) {
            int rc = bh_try_raise(fidx, ln, k);
            if (rc)
                return rc;
        }
    return 0;
}

static int bh_scan_file(int fidx)
{
    int rc = bh_slurp(bh_files[fidx]);
    if (rc)
        return rc;
    bh_fmark[fidx][0] = '\0';
    rc = bh_macro_pass();
    if (rc == 0)
        rc = bh_marker_pass(fidx);
    if (rc == 0)
        rc = bh_raise_pass(fidx);
    return rc;
}

int bh_scan_all(void)
{
    for (int i = 0; i < bh_nfiles; i++) {
        int rc = bh_scan_file(i);
        if (rc)
            return rc;
    }
    return 0;
}
