/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HARD gate check_package_anatomy — contexts/commons/packages/
 * format discipline (docs/spec/c23-package-format.md section 2). Ported
 * from tools/lint/check_package_anatomy.sh (deleted). Selftest:
 * gate_package_anatomy_selftest.c.
 *
 * RULES (per contexts/commons/packages/<pkg>/):
 *   R1  zcode-package.json, LICENSE, README.md, include/, src/, tests/ exist.
 *   R2  manifest: schema 1, language c23, name "<pkg>/<pkg>", license on the
 *       frozen v1 SPDX allowlist.
 *   R3  the manifest's files[] array is exact in both directions (parsed
 *       strictly: one array, quoted entries, comma discipline, no dups).
 *   R4  exactly one public header include/<pkg>/<pkg>.h with the <PKG>_H guard.
 *   R5  zero function-like macros in the public header (comments stripped).
 *   R6  no inline function bodies in the public header.
 *   R7  src/<pkg>.c is the primary TU; other src .c and .h files are internal.
 *   R8  tests/ holds at least one .c.
 *   R9  no executable build logic (makefile, configure, cmakelists in any
 *       case, or .sh files) anywhere under a package.
 *
 * When the root is the production root the gate also compiles and runs the
 * three declared package KATs (ball, zdemo, zhello) under the bounded runner
 * build/bin/z23_bounded_run, via posix_spawn (never system/popen).
 *
 * Exit: 0 clean, 1 violations, 2 hollow scan set / fatal. Fail closed: an
 * unreadable file or directory or a failed subprocess is an error, never a
 * skip or a pass. No heap: fixed static arrays; overflow prints
 * "<gate>: <what> exceeds <N>" and returns 2.
 */
#include "gate_package_anatomy_priv.h"

const char k_pka_gate[] = "check_package_anatomy";
static const char k_pka_default_root[] = "contexts/commons/packages";
static const char k_pka_lics[] =
    " 0BSD MIT Apache-2.0 BSD-2-Clause BSD-3-Clause ISC Zlib ";

struct pka_fl g_pka_fl;
static struct pka_decl g_pka_decl;

/* Record one violation row; 0 ok, 2 fatal (row overflow / too many). */
int pka_fail(struct pka_ctx *cf, const char *fmt, ...)
{
    va_list ap;
    if (cf->nfail >= PKA_FAILS) {
        fprintf(stderr, "%s: violation count exceeds %d\n", k_pka_gate,
                PKA_FAILS);
        return 2;
    }
    va_start(ap, fmt);
    int n = vsnprintf(cf->fail[cf->nfail], PKA_FAIL, fmt, ap);
    va_end(ap);
    if (ovf(n, PKA_FAIL))
        return 2;
    cf->nfail++;
    return 0;
}

static int pka_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

size_t pka_ws(const char *s, size_t i)
{
    while (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\v'
           || s[i] == '\f')
        i++;
    return i;
}

int pka_idch(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

void pka_upper(const char *in, char *out, size_t cap)
{
    size_t i = 0;
    for (; in[i] && i + 1 < cap; i++)
        out[i] = (in[i] >= 'a' && in[i] <= 'z') ? (char)(in[i] - 32) : in[i];
    out[i] = '\0';
}

static void pka_lower(const char *in, char *out, size_t cap)
{
    size_t i = 0;
    for (; in[i] && i + 1 < cap; i++)
        out[i] = (in[i] >= 'A' && in[i] <= 'Z') ? (char)(in[i] + 32) : in[i];
    out[i] = '\0';
}

/* ---------- recursive file listing (find "$dir" -type f | sort) ---------- */

static int pka_walk(const char *dir, int depth, struct pka_fl *fl)
{
    if (depth > 64) {
        fprintf(stderr, "%s: directory depth under %s exceeds 64\n",
                k_pka_gate, dir);
        return 2;
    }
    DIR *dd = opendir(dir);
    if (!dd) {
        fprintf(stderr, "%s: cannot read directory %s\n", k_pka_gate, dir);
        return 2;
    }
    struct dirent *e;
    while ((e = readdir(dd))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char path[PKA_PATH];
        struct stat st;
        if (ovf(snprintf(path, sizeof path, "%s/%s", dir, e->d_name),
                sizeof path)) {
            closedir(dd);
            fprintf(stderr, "%s: path under %s exceeds %d\n", k_pka_gate, dir,
                    PKA_PATH);
            return 2;
        }
        if (lstat(path, &st) != 0) {
            closedir(dd);
            fprintf(stderr, "%s: cannot stat %s\n", k_pka_gate, path);
            return 2;
        }
        int r = 0;
        if (S_ISDIR(st.st_mode))
            r = pka_walk(path, depth + 1, fl);
        else if (S_ISREG(st.st_mode)) {
            if (fl->n >= PKA_FILES) {
                closedir(dd);
                fprintf(stderr, "%s: file count under %s exceeds %d\n",
                        k_pka_gate, dir, PKA_FILES);
                return 2;
            }
            memcpy(fl->p[fl->n], path, strlen(path) + 1);
            fl->n++;
        }
        if (r) {
            closedir(dd);
            return r;
        }
    }
    closedir(dd);
    return 0;
}

/* Top-level package directories, sorted. Returns count, or -1 fatal. An
 * unreadable root yields 0 so the scan floor fires (as the shell find did). */
static int pka_scan_root(const char *root, char dirs[][PKA_PATH], int max)
{
    DIR *dd = opendir(root);
    if (!dd)
        return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(dd))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char p[PKA_PATH];
        struct stat st;
        if (ovf(snprintf(p, sizeof p, "%s/%s", root, e->d_name), sizeof p)) {
            closedir(dd);
            return -1;
        }
        if (lstat(p, &st) != 0) {
            closedir(dd);
            return -1;
        }
        if (!S_ISDIR(st.st_mode))
            continue;
        if (n >= max) {
            fprintf(stderr, "%s: package count exceeds %d\n", k_pka_gate, max);
            closedir(dd);
            return -1;
        }
        memcpy(dirs[n], p, strlen(p) + 1);
        n++;
    }
    closedir(dd);
    qsort(dirs, (size_t)n, PKA_PATH, pka_cmp);
    return n;
}

static int pka_slurp(const char *path, char *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "%s: cannot read %s\n", k_pka_gate, path);
        return 2;
    }
    size_t n = fread(buf, 1, cap - 1, f);
    int bad = ferror(f) || !feof(f);
    int more = !bad && fgetc(f) != EOF;
    fclose(f);
    if (bad || more) {
        fprintf(stderr, "%s: %s exceeds %zu bytes\n", k_pka_gate, path,
                cap - 1);
        return 2;
    }
    buf[n] = '\0';
    *len = n;
    return 0;
}

/* ---------- manifest files[] strict parser (port of the awk) ---------- */

static int pka_is_files_key(const char *s)
{
    size_t i = pka_ws(s, 0);
    if (s[i] != '"')
        return 0;
    i++;
    if (strncmp(s + i, "files\"", 6) != 0)
        return 0;
    i += 6;
    i = pka_ws(s, i);
    if (s[i] != ':')
        return 0;
    i = pka_ws(s, i + 1);
    return s[i] == '[';
}

static int pka_is_close(const char *s)
{
    size_t i = pka_ws(s, 0);
    if (s[i] != ']')
        return 0;
    i = pka_ws(s, i + 1);
    if (s[i] == ',')
        i = pka_ws(s, i + 1);
    return s[i] == '\0';
}

/* 1 matched (val/comma filled), 0 not an entry line, -1 value overflow. */
static int pka_parse_entry(const char *s, char *val, size_t cap, int *comma)
{
    size_t i = pka_ws(s, 0);
    if (s[i] != '"')
        return 0;
    i++;
    size_t j = i;
    while (s[j] && s[j] != '"')
        j++;
    if (s[j] != '"' || j == i)
        return 0;
    if (j - i >= cap)
        return -1;
    memcpy(val, s + i, j - i);
    val[j - i] = '\0';
    j++;
    j = pka_ws(s, j);
    *comma = 0;
    if (s[j] == ',') {
        *comma = 1;
        j = pka_ws(s, j + 1);
    }
    return s[j] == '\0' ? 1 : 0;
}

static int pka_files_finish(const struct pka_decl *d)
{
    if (d->comma[d->n - 1])
        return 1;
    for (int i = 0; i + 1 < d->n; i++)
        if (!d->comma[i])
            return 1;
    return 0;
}

struct pka_files_st {
    int seen, inside, closed, bad;
};

static int pka_files_entry(const char *line, struct pka_decl *d, int *bad)
{
    char val[PKA_PATH];
    int comma = 0;
    int e = pka_parse_entry(line, val, sizeof val, &comma);
    if (e < 0) {
        fprintf(stderr, "%s: manifest files[] entry exceeds %d\n", k_pka_gate,
                PKA_PATH);
        return 2;
    }
    if (e == 0 || d->n >= PKA_DECL) {
        *bad = 1;
        return 0;
    }
    memcpy(d->v[d->n], val, strlen(val) + 1);
    d->comma[d->n] = comma;
    d->n++;
    return 0;
}

static int pka_files_line(const char *line, struct pka_decl *d,
                          struct pka_files_st *s)
{
    if (pka_is_files_key(line)) {
        if (s->seen)
            s->bad = 1;
        s->seen = 1;
        s->inside = 1;
        return 0;
    }
    if (s->inside && pka_is_close(line)) {
        s->inside = 0;
        s->closed = 1;
        return 0;
    }
    if (s->inside)
        return pka_files_entry(line, d, &s->bad);
    return 0;
}

/* 0 ok, 1 malformed, 2 fatal. */
static int pka_files_parse(const char *man, struct pka_decl *d)
{
    struct pka_files_st s = { 0, 0, 0, 0 };
    const char *p = man;
    char line[PKA_MLINE];
    d->n = 0;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n >= sizeof line) {
            fprintf(stderr, "%s: manifest line exceeds %d bytes\n", k_pka_gate,
                    PKA_MLINE);
            return 2;
        }
        memcpy(line, p, n);
        line[n] = '\0';
        int rc = pka_files_line(line, d, &s);
        if (rc)
            return rc;
        if (!nl)
            break;
        p = nl + 1;
    }
    if (!s.seen || s.inside || !s.closed || s.bad || d->n == 0)
        return 1;
    return pka_files_finish(d);
}

static int pka_declared(const char *rel)
{
    for (int i = 0; i < g_pka_decl.n; i++)
        if (!strcmp(g_pka_decl.v[i], rel))
            return 1;
    return 0;
}

/* ---------- per-package rules ---------- */

static int pka_r1(const char *dir, const char *pkg, struct pka_ctx *cf)
{
    static const char *const k_reqf[] = { "zcode-package.json", "LICENSE",
                                          "README.md" };
    static const char *const k_reqd[] = { "include", "src", "tests" };
    char p[PKA_PATH];
    struct stat st;
    for (size_t i = 0; i < 3; i++) {
        if (ovf(snprintf(p, sizeof p, "%s/%s", dir, k_reqf[i]), sizeof p))
            return 2;
        if (stat(p, &st) != 0 || !S_ISREG(st.st_mode))
            PKA_FAIL("%s: missing %s", pkg, k_reqf[i]);
    }
    for (size_t i = 0; i < 3; i++) {
        if (ovf(snprintf(p, sizeof p, "%s/%s", dir, k_reqd[i]), sizeof p))
            return 2;
        if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode))
            PKA_FAIL("%s: missing %s/ directory", pkg, k_reqd[i]);
    }
    return 0;
}

static void pka_license(const char *man, char *out, size_t cap)
{
    out[0] = '\0';
    const char *k = strstr(man, "\"license\": \"");
    if (!k)
        return;
    k += strlen("\"license\": \"");
    size_t i = 0;
    while (k[i] && k[i] != '"' && i + 1 < cap) {
        out[i] = k[i];
        i++;
    }
    out[i] = '\0';
}

static int pka_r2(const char *man, const char *pkg, struct pka_ctx *cf)
{
    char want[PKA_PATH], lic[256], probe[300];
    if (!strstr(man, "\"schema\": 1"))
        PKA_FAIL("%s: manifest schema is not 1", pkg);
    if (ovf(snprintf(want, sizeof want, "\"name\": \"%s/%s\"", pkg, pkg),
            sizeof want))
        return 2;
    if (!strstr(man, want))
        PKA_FAIL("%s: manifest name is not \"%s/%s\"", pkg, pkg, pkg);
    if (!strstr(man, "\"language\": \"c23\""))
        PKA_FAIL("%s: manifest language is not \"c23\"", pkg);
    pka_license(man, lic, sizeof lic);
    if (ovf(snprintf(probe, sizeof probe, " %s ", lic), sizeof probe))
        return 2;
    if (!strstr(k_pka_lics, probe))
        PKA_FAIL("%s: license '%s' is not on the frozen v1 SPDX allowlist",
                 pkg, lic);
    return 0;
}

static int pka_r3_dups(const char *pkg, struct pka_ctx *cf)
{
    for (int i = 0; i < g_pka_decl.n; i++)
        for (int j = 0; j < i; j++)
            if (!strcmp(g_pka_decl.v[i], g_pka_decl.v[j])) {
                PKA_FAIL("%s: manifest files[] lists %s more than once", pkg,
                         g_pka_decl.v[i]);
                break;
            }
    return 0;
}

static int pka_r3_unlisted(const char *dir, const char *pkg,
                           struct pka_ctx *cf)
{
    size_t dl = strlen(dir);
    for (int i = 0; i < g_pka_fl.n; i++) {
        const char *rel = g_pka_fl.p[i] + dl + 1;
        if (!pka_declared(rel))
            PKA_FAIL("%s: %s exists but is not listed in manifest files[]",
                     pkg, rel);
    }
    return 0;
}

static int pka_r3_missing(const char *dir, const char *pkg,
                          struct pka_ctx *cf)
{
    char p[PKA_PATH];
    struct stat st;
    for (int i = 0; i < g_pka_decl.n; i++) {
        if (ovf(snprintf(p, sizeof p, "%s/%s", dir, g_pka_decl.v[i]),
                sizeof p))
            return 2;
        if (stat(p, &st) != 0 || !S_ISREG(st.st_mode))
            PKA_FAIL("%s: manifest files[] lists %s but it does not exist",
                     pkg, g_pka_decl.v[i]);
    }
    return 0;
}

static int pka_r3(const char *dir, const char *pkg, const char *man,
                  struct pka_ctx *cf)
{
    int pr = pka_files_parse(man, &g_pka_decl);
    if (pr == 2)
        return 2;
    if (pr)
        PKA_FAIL("%s: manifest files[] is missing, duplicated, or malformed",
                 pkg);
    int r = pka_r3_dups(pkg, cf);
    if (r)
        return r;
    r = pka_r3_unlisted(dir, pkg, cf);
    if (r)
        return r;
    return pka_r3_missing(dir, pkg, cf);
}

static int pka_r7(const char *dir, const char *pkg, struct pka_ctx *cf)
{
    char prim[600], p[PKA_PATH], srcpfx[PKA_PATH];
    struct stat st;
    if (ovf(snprintf(prim, sizeof prim, "src/%s.c", pkg), sizeof prim))
        return 2;
    if (ovf(snprintf(p, sizeof p, "%s/%s", dir, prim), sizeof p))
        return 2;
    if (stat(p, &st) != 0 || !S_ISREG(st.st_mode))
        PKA_FAIL("%s: missing primary translation unit src/%s.c", pkg, pkg);
    if (ovf(snprintf(srcpfx, sizeof srcpfx, "%s/src/", dir), sizeof srcpfx))
        return 2;
    size_t pl = strlen(srcpfx);
    for (int i = 0; i < g_pka_fl.n; i++) {
        size_t len = strlen(g_pka_fl.p[i]);
        if (len < pl + 1 || strncmp(g_pka_fl.p[i], srcpfx, pl) != 0)
            continue;
        const char *rel = g_pka_fl.p[i] + strlen(dir) + 1;
        if (strcmp(rel, prim) == 0)
            continue;
        if (len > 2 && (strcmp(g_pka_fl.p[i] + len - 2, ".h") == 0
                        || strcmp(g_pka_fl.p[i] + len - 2, ".c") == 0))
            continue;
        PKA_FAIL("%s: unexpected file under src/: %s", pkg, rel);
    }
    return 0;
}

static int pka_r8(const char *dir, const char *pkg, struct pka_ctx *cf)
{
    char tspfx[PKA_PATH];
    if (ovf(snprintf(tspfx, sizeof tspfx, "%s/tests/", dir), sizeof tspfx))
        return 2;
    size_t pl = strlen(tspfx);
    int has = 0;
    for (int i = 0; i < g_pka_fl.n && !has; i++) {
        size_t len = strlen(g_pka_fl.p[i]);
        if (len >= pl + 2 && strncmp(g_pka_fl.p[i], tspfx, pl) == 0
            && strcmp(g_pka_fl.p[i] + len - 2, ".c") == 0)
            has = 1;
    }
    if (!has)
        PKA_FAIL("%s: tests/ holds no .c file", pkg);
    return 0;
}

static int pka_r9(const char *pkg, struct pka_ctx *cf)
{
    for (int i = 0; i < g_pka_fl.n; i++) {
        const char *bn = strrchr(g_pka_fl.p[i], '/');
        bn = bn ? bn + 1 : g_pka_fl.p[i];
        char lc[PKA_PATH];
        pka_lower(bn, lc, sizeof lc);
        size_t bl = strlen(bn);
        if (strncmp(lc, "makefile", 8) == 0 || strncmp(lc, "configure", 9) == 0
            || strncmp(lc, "cmakelists", 10) == 0
            || (bl > 3 && strcmp(bn + bl - 3, ".sh") == 0)) {
            PKA_FAIL("%s: executable build logic %s — the recipe is "
                     "declarative", pkg, g_pka_fl.p[i]);
            break;
        }
    }
    return 0;
}

static int pka_check_pkg(const char *dir, struct pka_ctx *cf)
{
    static char man[PKA_MANIFEST];
    const char *pkg = strrchr(dir, '/');
    pkg = pkg ? pkg + 1 : dir;
    int r = pka_r1(dir, pkg, cf);
    if (r)
        return r;
    char mpath[PKA_PATH];
    struct stat st;
    if (ovf(snprintf(mpath, sizeof mpath, "%s/zcode-package.json", dir),
            sizeof mpath))
        return 2;
    if (stat(mpath, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    g_pka_fl.n = 0;
    r = pka_walk(dir, 0, &g_pka_fl);
    if (r)
        return 2;
    qsort(g_pka_fl.p, (size_t)g_pka_fl.n, PKA_PATH, pka_cmp);
    size_t mlen = 0;
    r = pka_slurp(mpath, man, sizeof man, &mlen);
    if (r)
        return r;
    r = pka_r2(man, pkg, cf);
    if (r)
        return r;
    r = pka_r3(dir, pkg, man, cf);
    if (r)
        return r;
    r = pka_r4(dir, pkg, cf);
    if (r)
        return r;
    r = pka_r7(dir, pkg, cf);
    if (r)
        return r;
    r = pka_r8(dir, pkg, cf);
    if (r)
        return r;
    return pka_r9(pkg, cf);
}

/* ---------- verdict ---------- */

int pka_check_root(const char *root, int run_kats)
{
    static char dirs[PKA_PKGS][PKA_PATH];
    static struct pka_ctx cf;
    char hint[PKA_FAIL];
    memset(&cf, 0, sizeof cf);
    int n = pka_scan_root(root, dirs, PKA_PKGS);
    if (n < 0)
        return 2;
    if (ovf(snprintf(hint, sizeof hint,
                     "%s held almost no package directories; run from a real "
                     "checkout.", root), sizeof hint))
        return 2;
    if (gate_require_scanned(n, 70, k_pka_gate, hint))
        return 2;
    for (int i = 0; i < n; i++) {
        int r = pka_check_pkg(dirs[i], &cf);
        if (r == 2)
            return 2;
    }
    if (cf.nfail) {
        fprintf(stderr, "\nFAIL: %d package-anatomy violation(s):\n",
                cf.nfail);
        for (int i = 0; i < cf.nfail; i++)
            fprintf(stderr, "  %s\n", cf.fail[i]);
        fprintf(stderr, "\nRules: docs/spec/c23-package-format.md §2 "
                "(package anatomy discipline).\n");
        return 1;
    }
    if (run_kats) {
        int r = pka_run_kats();
        if (r)
            return r;
    }
    printf("check_package_anatomy: clean — %d packages conform (R1-R9)\n", n);
    return 0;
}

int check_package_anatomy_run(int argc, char **argv)
{
    const char *root = k_pka_default_root;
    if (argc == 0)
        return pka_check_root(root, 1);
    if (strcmp(argv[0], "--root") == 0) {
        if (argc != 2) {
            fprintf(stderr, "%s: --root requires exactly one directory\n",
                    k_pka_gate);
            return 2;
        }
        root = argv[1];
        return pka_check_root(root, strcmp(root, k_pka_default_root) == 0);
    }
    if (strcmp(argv[0], ".") == 0 || argv[0][0] == '\0')
        return pka_check_root(root, 1);
    if (strcmp(argv[0], "--help") == 0 || strcmp(argv[0], "-h") == 0) {
        printf("usage: check_package_anatomy [--root DIR]\n");
        return 0;
    }
    fprintf(stderr, "%s: unknown argument '%s'\n", k_pka_gate, argv[0]);
    return 2;
}
