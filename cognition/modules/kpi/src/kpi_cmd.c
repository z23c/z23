/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * kpi_cmd — the command-catalog scoreboard: how many leaves exist, how many
 * are ready with a handler, how many carry help, and how many ready leaves a
 * test names.
 *
 * It reads the authored .def files, not the compiled registry, so the numbers
 * are identical in every build flavour and need no node. A dev row counts as
 * READY when it binds a handler, which is what the dev build registers.
 * Parsing is deliberately narrow: it recognises the ZCL_COMMAND_* call shapes
 * at column zero, splits their top-level arguments around string literals,
 * comments and nested parentheses, and ignores everything else.
 */

#include "kpi/kpi.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum {
    KPI_DEF_MAX      = 1 << 20,
    KPI_INCLUDE_DEPTH = 3,
    KPI_ARGS_MAX     = 40,
    KPI_PATH_MAX     = 96,
    KPI_LEAF_MAX     = 4096,
    KPI_DIR_MAX      = 512,
    KPI_TEST_FILE_MAX = 8 << 20,
    KPI_TEST_FILES_MAX = 8192,
    KPI_KEY_TOKENS   = 10,
    KPI_ARG_PATH     = 0,
    KPI_ARG_SUMMARY  = 3,
    KPI_ARG_EXAMPLE  = 11
};

static const char k_cmd_dir[] = "engine/composition/commands";
static const char k_test_dir[] = "tests/harness/src";

struct kpi_leaf {
    char path[KPI_PATH_MAX];
    bool ready;
};

struct kpi_cat {
    struct kpi_leaf *leaf;
    size_t           n;
    uint64_t         ready;
    uint64_t         help;
};

struct kpi_args {
    const char *b[KPI_ARGS_MAX];
    const char *e[KPI_ARGS_MAX];
    int         n;
};

/* ── file reading ────────────────────────────────────────────────────── */

/* The whole file into `buf` (capacity cap + 1), NUL-terminated. False when it
 * is unreadable or larger than `cap`. */
static bool kpi_slurp(const char *path, char *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t got = fread(buf, 1, cap + 1, f);
    bool bad = ferror(f) != 0 || got > cap;
    fclose(f);
    if (bad)
        return false;
    buf[got] = '\0';
    if (len)
        *len = got;
    return true;
}

/* ── lexical helpers ─────────────────────────────────────────────────── */

/* After the string or character literal opening at `p`. */
static const char *kpi_skip_lit(const char *p)
{
    char q = *p++;
    while (*p && *p != q && *p != '\n') {
        if (*p == '\\' && p[1])
            p++;
        p++;
    }
    return *p == q ? p + 1 : p;
}

/* After the comment opening at `p`, or NULL when `p` opens none. */
static const char *kpi_skip_comment(const char *p)
{
    if (p[0] != '/')
        return NULL;
    if (p[1] == '/') {
        while (*p && *p != '\n')
            p++;
        return p;
    }
    if (p[1] != '*')
        return NULL;
    const char *end = strstr(p + 2, "*/");
    return end ? end + 2 : p + strlen(p);
}

/* Every top-level argument of the call whose '(' precedes `p`. Returns the
 * position after the closing ')', or NULL when the call never closes. */
static const char *kpi_scan_args(const char *p, struct kpi_args *a)
{
    int depth = 1;
    a->n = 0;
    a->b[0] = p;
    while (*p) {
        const char *skip = (*p == '"' || *p == '\'') ? kpi_skip_lit(p)
                                                     : kpi_skip_comment(p);
        if (skip) {
            p = skip;
            continue;
        }
        if (*p == '(') {
            depth++;
        } else if (*p == ')' && --depth == 0) {
            a->e[a->n] = p;
            a->n++;
            return p + 1;
        } else if (*p == ',' && depth == 1 && a->n + 1 < KPI_ARGS_MAX) {
            a->e[a->n] = p;
            a->b[++a->n] = p + 1;
        }
        p++;
    }
    return NULL;
}

/* The concatenated contents of the string literals in [b, e). Returns the
 * full length; `dst` receives at most cap - 1 bytes. */
static size_t kpi_arg_text(const char *b, const char *e, char *dst, size_t cap)
{
    size_t n = 0;
    while (b < e) {
        if (*b != '"') {
            b++;
            continue;
        }
        for (b++; b < e && *b != '"'; b++) {
            if (*b == '\\' && b + 1 < e && b[1] == '"')
                b++;
            if (dst && n + 1 < cap)
                dst[n] = *b;
            n++;
        }
        b++;
    }
    if (dst && cap > 0)
        dst[n < cap ? n : cap - 1] = '\0';
    return n;
}

static bool kpi_arg_is_null(const char *b, const char *e)
{
    while (b < e && isspace((unsigned char)*b))
        b++;
    while (e > b && isspace((unsigned char)e[-1]))
        e--;
    return e == b || (e - b == 4 && memcmp(b, "NULL", 4) == 0);
}

/* ── the catalog ─────────────────────────────────────────────────────── */

enum kpi_row_kind { KPI_ROW_NONE, KPI_ROW_READY, KPI_ROW_DEV, KPI_ROW_OTHER };

/* Which leaf shape the macro at `p` is. BRANCH rows and unknown macros are
 * NONE. PLANNED and COMPAT rows are OTHER: leaves, never ready. */
static enum kpi_row_kind kpi_row_kind_of(const char *p, const char **open)
{
    static const char k_pre[] = "ZCL_COMMAND_";
    if (strncmp(p, k_pre, sizeof k_pre - 1) != 0)
        return KPI_ROW_NONE;
    p += sizeof k_pre - 1;
    size_t n = strspn(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_");
    if (p[n] != '(')
        return KPI_ROW_NONE;
    *open = p + n;
    if (strncmp(p, "READY_", 6) == 0)
        return KPI_ROW_READY;
    if (strncmp(p, "DEV_", 4) == 0)
        return KPI_ROW_DEV;
    if (strncmp(p, "PLANNED_", 8) == 0 || strncmp(p, "COMPAT_", 7) == 0)
        return KPI_ROW_OTHER;
    return KPI_ROW_NONE;
}

static bool kpi_row_ready(enum kpi_row_kind kind, const struct kpi_args *a)
{
    if (kind != KPI_ROW_READY && kind != KPI_ROW_DEV)
        return false;
    int h = kind == KPI_ROW_READY ? a->n - 1 : a->n - 3;
    return h > KPI_ARG_EXAMPLE && !kpi_arg_is_null(a->b[h], a->e[h]);
}

static void kpi_cat_add(struct kpi_cat *c, enum kpi_row_kind kind,
                        const struct kpi_args *a)
{
    if (c->n >= KPI_LEAF_MAX || a->n <= KPI_ARG_EXAMPLE)
        return;
    struct kpi_leaf *l = &c->leaf[c->n];
    size_t len = kpi_arg_text(a->b[KPI_ARG_PATH], a->e[KPI_ARG_PATH], l->path,
                              sizeof l->path);
    if (len == 0 || len >= sizeof l->path)
        return;
    l->ready = kpi_row_ready(kind, a);
    c->n++;
    if (l->ready)
        c->ready++;
    if (kpi_arg_text(a->b[KPI_ARG_SUMMARY], a->e[KPI_ARG_SUMMARY], NULL, 0) &&
        kpi_arg_text(a->b[KPI_ARG_EXAMPLE], a->e[KPI_ARG_EXAMPLE], NULL, 0))
        c->help++;
}

/* The file named by an `#include "x.def"` line at `p`, into `name`. */
static bool kpi_include_name(const char *p, char *name, size_t cap)
{
    static const char k_inc[] = "#include \"";
    if (strncmp(p, k_inc, sizeof k_inc - 1) != 0)
        return false;
    p += sizeof k_inc - 1;
    size_t n = strcspn(p, "\"\n");
    if (p[n] != '"' || n == 0 || n >= cap)
        return false;
    memcpy(name, p, n);
    name[n] = '\0';
    return true;
}

static void kpi_cat_file(struct kpi_cat *c, const char *dir, const char *name,
                         int depth);

static void kpi_cat_text(struct kpi_cat *c, const char *dir, int depth,
                         const char *text)
{
    char name[KPI_DIR_MAX];
    struct kpi_args a;
    for (const char *p = text; p && *p;) {
        const char *open = NULL;
        enum kpi_row_kind kind = kpi_row_kind_of(p, &open);
        if (kind != KPI_ROW_NONE && kpi_scan_args(open + 1, &a))
            kpi_cat_add(c, kind, &a);
        else if (kpi_include_name(p, name, sizeof name) &&
                 depth < KPI_INCLUDE_DEPTH)
            kpi_cat_file(c, dir, name, depth + 1);
        p = strchr(p, '\n');
        if (p)
            p++;
    }
}

/* Read dir/name and walk it. Each file gets its own buffer so the caller.s
 * text stays intact while its includes are followed. */
static void kpi_cat_file(struct kpi_cat *c, const char *dir, const char *name,
                         int depth)
{
    char path[KPI_DIR_MAX * 2];
    if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path)
        return;
    char *text = zcl_calloc(KPI_DEF_MAX + 1, 1, "kpi_cmd_def");
    size_t len = 0;
    if (kpi_slurp(path, text, KPI_DEF_MAX, &len))
        kpi_cat_text(c, dir, depth, text);
    free(text);
}

/* ── test references ─────────────────────────────────────────────────── */

struct kpi_needles {
    char    (*key)[KPI_PATH_MAX]; /* ready leaf paths, sorted */
    uint8_t *hit;
    size_t   n;
};

static int kpi_key_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

static bool kpi_tok(char c)
{
    return isalnum((unsigned char)c) || c == '_' || c == '-';
}

static void kpi_mark(struct kpi_needles *nd, const char *key)
{
    const char *hit = bsearch(key, nd->key, nd->n, KPI_PATH_MAX, kpi_key_cmp);
    if (hit)
        nd->hit[(size_t)(hit - (const char *)nd->key) / KPI_PATH_MAX] = 1;
}

/* Match the words at `p` as a leaf path: dotted (a.b.c) or spaced (a b c).
 * A dotted run is only looked up at its end, so `dev.drive.x` never credits
 * `dev.drive`; a spaced run is looked up after every word, since what follows
 * a CLI path is an argument. */
static void kpi_try_path(struct kpi_needles *nd, const char *p)
{
    char key[KPI_PATH_MAX];
    size_t k = 0;
    for (int tok = 0; tok < KPI_KEY_TOKENS; tok++) {
        size_t w = 0;
        while (kpi_tok(p[w]))
            w++;
        if (w == 0 || k + w + 1 >= sizeof key)
            return;
        memcpy(key + k, p, w);
        k += w;
        p += w;
        key[k] = '\0';
        bool more = (*p == '.' || *p == ' ') && kpi_tok(p[1]);
        if (!(more && *p == '.'))
            kpi_mark(nd, key);
        if (!more)
            return;
        key[k++] = '.';
        p++;
    }
}

/* One pass over a source file: only text inside string literals can name a
 * command, so identifiers and comments never credit a leaf. */
static void kpi_scan_source(struct kpi_needles *nd, const char *s)
{
    bool in_str = false;
    for (const char *p = s; *p;) {
        if (in_str) {
            if (*p == '"' || *p == '\n') {
                in_str = false;
            } else if (*p == '\\' && p[1]) {
                p++;
            } else if (kpi_tok(*p) && !kpi_tok(p[-1]) && p[-1] != '.') {
                kpi_try_path(nd, p);
            }
            p++;
            continue;
        }
        const char *skip = (*p == '\'') ? kpi_skip_lit(p) : kpi_skip_comment(p);
        if (skip) {
            p = skip;
            continue;
        }
        in_str = (*p == '"');
        p++;
    }
}

/* Sorted copies of every READY leaf path. */
static void kpi_needles_build(struct kpi_needles *nd, const struct kpi_cat *c)
{
    nd->key = zcl_calloc(c->ready + 1, KPI_PATH_MAX, "kpi_cmd_keys");
    nd->hit = zcl_calloc(c->ready + 1, 1, "kpi_cmd_hits");
    nd->n = 0;
    for (size_t i = 0; i < c->n; i++)
        if (c->leaf[i].ready)
            memcpy(nd->key[nd->n++], c->leaf[i].path, KPI_PATH_MAX);
    qsort(nd->key, nd->n, KPI_PATH_MAX, kpi_key_cmp);
}

/* READY leaves named by a file in tests/harness/src. False when the
 * directory is unreadable or held no readable source. */
static bool kpi_tests_scan(const char *root, const struct kpi_cat *c,
                           uint64_t *tested)
{
    char dir[KPI_DIR_MAX], path[KPI_DIR_MAX * 2];
    if (snprintf(dir, sizeof dir, "%s/%s", root, k_test_dir) >= (int)sizeof dir)
        return false;
    DIR *d = opendir(dir);
    if (!d)
        return false;

    struct kpi_needles nd;
    kpi_needles_build(&nd, c);
    char *buf = zcl_calloc(KPI_TEST_FILE_MAX + 1, 1, "kpi_cmd_test_src");
    size_t read_ok = 0, seen = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && seen++ < KPI_TEST_FILES_MAX) {
        struct stat st;
        if (de->d_name[0] == '.' ||
            snprintf(path, sizeof path, "%s/%s", dir, de->d_name) >=
                (int)sizeof path ||
            stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (kpi_slurp(path, buf, KPI_TEST_FILE_MAX, NULL)) {
            kpi_scan_source(&nd, buf);
            read_ok++;
        }
    }
    closedir(d);
    uint64_t n = 0;
    for (size_t i = 0; i < nd.n; i++)
        n += nd.hit[i];
    free(buf);
    free(nd.key);
    free(nd.hit);
    *tested = n;
    return read_ok > 0;
}

/* ── entry point ─────────────────────────────────────────────────────── */

bool kpi_cmd_scan(const char *root, struct kpi_cmd_stats *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!root || !root[0])
        root = ".";

    char dir[KPI_DIR_MAX];
    if (snprintf(dir, sizeof dir, "%s/%s", root, k_cmd_dir) >= (int)sizeof dir)
        return false;
    struct kpi_cat cat;
    memset(&cat, 0, sizeof cat);
    cat.leaf = zcl_calloc(KPI_LEAF_MAX, sizeof *cat.leaf, "kpi_cmd_leaves");
    kpi_cat_file(&cat, dir, "catalog.def", 0);

    bool ok = cat.n > 0;
    if (ok) {
        out->leaves = cat.n;
        out->ready = cat.ready;
        out->help = cat.help;
        out->have_tested = kpi_tests_scan(root, &cat, &out->tested);
    }
    free(cat.leaf);
    return ok;
}
