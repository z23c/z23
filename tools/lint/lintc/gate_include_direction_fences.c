/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — include-direction fences of the C23 lint runtime
 * (check-core-include-boundary, check-shape-include-direction). Production
 * scan walks git-tracked files via lint_git_index_foreach (unread or
 * refused index = UNPROVEN 2); full/dev scan walks the filesystem directly.
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

enum { IDF_MAX = 4096, IDF_VMAX = 256, IDF_LINE = 8192, IDF_TOK = 256,
       IDF_MSG = RS_PATH + 128 };

struct idf_set { char p[IDF_MAX][RS_PATH]; int n; };
struct idf_collect {
    const char (*roots)[RS_PATH];
    int nroots, inc;
    struct idf_set *set;
};
typedef int (*idf_hit_fn)(int line, const char *raw, const char *hdr,
                          const char *tok, void *ctx);

static const char k_cib_inc[] =
    "^[[:space:]]*#include[[:space:]]+\"[^\"]+/";
static const char k_cib_ok[] =
    "//[[:space:]]*core-boundary-ok:[A-Za-z][A-Za-z0-9_-]*";
static const char k_sid_ok[] =
    "//[[:space:]]*shape-layer-ok:[A-Za-z][A-Za-z0-9_-]*";
static const char k_sid_mod[] =
    "^[[:space:]]*#include[[:space:]]+\"(services|controllers)/";
static const char k_sid_svc[] =
    "^[[:space:]]*#include[[:space:]]+\"controllers/";
static const char *const k_cib_roots[] = {
    "core/consensus", "core/params", "core/chainparams", "core/math"
};
static const char *const k_cib_allow[] = {
    "bloom", "chain", "chainparams", "coins", "consensus", "core", "crypto",
    "domain", "encoding", "json", "keys", "math", "platform", "primitives",
    "script", "support", "util"
};
static const char k_sid_base[] =
    "tools/scripts/shape_include_direction_baseline.txt";

static int idf_is_test(const char *path)
{
    return strstr(path, "/test/") != NULL || strncmp(path, "test/", 5) == 0;
}

static int idf_src(const char *path, int inc)
{
    size_t n = strlen(path);
    if (n >= 2 && path[n - 2] == '.'
        && (path[n - 1] == 'c' || path[n - 1] == 'h'))
        return 1;
    return inc && n >= 4 && memcmp(path + n - 4, ".inc", 4) == 0;
}

static int idf_under(const char *path, const char *root)
{
    size_t n = strlen(root);
    if (strncmp(path, root, n) != 0)
        return 0;
    return path[n] == '/' || path[n] == '\0';
}

static int idf_in_roots(const char *path, const char (*roots)[RS_PATH], int n)
{
    for (int i = 0; i < n; i++)
        if (idf_under(path, roots[i]))
            return 1;
    return 0;
}

static int idf_has(const struct idf_set *s, const char *path)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 1;
    return 0;
}

static int idf_add(struct idf_set *s, const char *path)
{
    size_t n;
    if (idf_has(s, path))
        return 0;
    n = strlen(path);
    if (s->n >= IDF_MAX || n >= RS_PATH)
        return die("z23-lint: include-fence path set overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int idf_on_index(const char *path, void *ctx)
{
    struct idf_collect *c = ctx;
    if (idf_is_test(path) || !idf_src(path, c->inc))
        return 0;
    if (!idf_in_roots(path, c->roots, c->nroots))
        return 0;
    if (lint_path_is_excluded(path))
        return 0;
    return idf_add(c->set, path);
}

static int idf_walk(const char *dir, struct idf_collect *c)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    int rc = 0, i;
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    for (i = 0; i < n; i++) {
        const char *nm = names[i]->d_name;
        if (rc == 0 && strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0
            && strcmp(nm, "test") != 0) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, nm);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode))
                rc = idf_walk(path, c);
            else if (S_ISREG(st.st_mode) && idf_src(path, c->inc)
                     && !idf_is_test(path) && !lint_path_is_excluded(path))
                rc = idf_add(c->set, path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

/* Production scan: git-tracked files only, via the index (fast, no directory
 * traversal) — an unread or refused index is UNPROVEN 2, same as any other
 * production-mode gate. Full/dev scan (the default, and what every fixture
 * and selftest exercises): walk the filesystem directly, exactly like the
 * original shell script always did. This gate's fixtures run inside the
 * make_lint_gates sandbox lane, a hardlink clone with .git deliberately
 * excluded (see test_make_lint_gates.c) — so the full-scan path must never
 * touch the git index. */
static int idf_collect(struct idf_collect *c)
{
    int rc, i;
    if (lint_prod_scan())
        return lint_git_index_foreach(idf_on_index, c);
    rc = 0;
    for (i = 0; rc == 0 && i < c->nroots; i++)
        rc = idf_walk(c->roots[i], c);
    return rc;
}

static void idf_strip_cmt(char *s)
{
    char *p = strstr(s, "//");
    char *a, *b;
    if (p)
        *p = '\0';
    a = strstr(s, "/*");
    if (!a)
        return;
    b = strstr(a + 2, "*/");
    if (!b)
        return;
    memmove(a, b + 2, strlen(b + 2) + 1);
}

static void idf_trim_inplace(char *s)
{
    char *p = s;
    size_t n;
    while (*p == ' ' || *p == '\t')
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static int idf_hdr_from(const char *line, char *hdr, size_t cap)
{
    const char *q = strchr(line, '"');
    const char *e;
    size_t n;
    if (!q)
        return 0;
    q++;
    e = strchr(q, '"');
    if (!e)
        return 0;
    n = (size_t)(e - q);
    if (n >= cap)
        return 0;
    memcpy(hdr, q, n);
    hdr[n] = '\0';
    return 1;
}

static int idf_one_line(const char *line, int lineno, const regex_t *inc,
                        const regex_t *ok, idf_hit_fn hit, void *ctx)
{
    char tok[IDF_TOK], hdr[RS_PATH];
    if (regexec(inc, line, 0, NULL, 0) != 0)
        return 0;
    if (regexec(ok, line, 0, NULL, 0) == 0)
        return 0;
    if (ovf(snprintf(tok, sizeof tok, "%s", line), sizeof tok))
        return 2;
    idf_strip_cmt(tok);
    idf_trim_inplace(tok);
    if (!idf_hdr_from(line, hdr, sizeof hdr))
        return 0;
    return hit(lineno, line, hdr, tok, ctx);
}

static int idf_scan_file(const char *path, const regex_t *inc,
                         const regex_t *ok, idf_hit_fn hit, void *ctx)
{
    FILE *f = fopen(path, "r");
    char buf[IDF_LINE];
    int rc = 0, lineno = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n + 1 >= sizeof buf && (n == 0 || buf[n - 1] != '\n')) {
            rc = die("z23-lint: source line too long: %s\n", path);
            break;
        }
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (n && buf[n - 1] == '\r')
            buf[n] = '\0';
        lineno++;
        rc = idf_one_line(buf, lineno, inc, ok, hit, ctx);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int idf_scan_text(const char *text, const regex_t *inc,
                         const regex_t *ok, idf_hit_fn hit, void *ctx)
{
    int rc = 0, lineno = 0;
    const char *p = text;
    while (rc == 0 && *p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[IDF_LINE];
        if (n >= sizeof line)
            return die("z23-lint: source line too long\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        lineno++;
        rc = idf_one_line(line, lineno, inc, ok, hit, ctx);
        if (!nl)
            break;
        p = nl + 1;
    }
    return rc;
}

static int cib_allowed(const char *hdr)
{
    const char *sl = strchr(hdr, '/');
    size_t n, i;
    if (!sl)
        return 1;
    n = (size_t)(sl - hdr);
    for (i = 0; i < sizeof k_cib_allow / sizeof k_cib_allow[0]; i++)
        if (strlen(k_cib_allow[i]) == n
            && strncmp(hdr, k_cib_allow[i], n) == 0)
            return 1;
    return 0;
}

struct cib_acc {
    const char *path;
    char v[IDF_VMAX][IDF_MSG];
    int n;
};

static int cib_hit(int line, const char *raw, const char *hdr, const char *tok,
                   void *ctx)
{
    struct cib_acc *a = ctx;
    (void)raw;
    (void)tok;
    if (cib_allowed(hdr))
        return 0;
    if (a->n >= IDF_VMAX)
        return die("z23-lint: core-include-boundary overflow\n", "");
    if (ovf(snprintf(a->v[a->n], sizeof a->v[0],
                     "%s:%d core may not include %s", a->path, line, hdr),
            sizeof a->v[0]))
        return 2;
    a->n++;
    return 0;
}

static int cib_unreadable(const char *d)
{
    fprintf(stderr, "check_core_include_boundary: FATAL — '%s' exists but "
                    "is unreadable.\n", d);
    return -1;
}

static int cib_any_root(void)
{
    int any = 0;
    size_t i;
    for (i = 0; i < sizeof k_cib_roots / sizeof k_cib_roots[0]; i++) {
        if (access(k_cib_roots[i], F_OK) != 0) {
            if (errno == ENOENT)
                continue;
            return cib_unreadable(k_cib_roots[i]);
        }
        if (access(k_cib_roots[i], R_OK) != 0)
            return cib_unreadable(k_cib_roots[i]);
        any = 1;
    }
    return any;
}

static int cib_fill_roots(char out[][RS_PATH], int *n)
{
    size_t i;
    *n = 0;
    for (i = 0; i < sizeof k_cib_roots / sizeof k_cib_roots[0]; i++) {
        if (ovf(snprintf(out[*n], RS_PATH, "%s", k_cib_roots[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    return 0;
}

static int cib_report(const struct cib_acc *a)
{
    int i;
    printf("\ncheck_core_include_boundary: %d forbidden include(s) in core/\n\n",
           a->n);
    for (i = 0; i < a->n; i++)
        printf("FAIL: %s\n", a->v[i]);
    fputs("\nThe four pure consensus contexts are the innermost layer. They "
          "may only\ninclude its own headers, C/system headers, bare "
          "siblings, and pure leaf\nlib subsystems — NEVER "
          "core/modules/validation (validation drives consensus, it is\n"
          "not consensus) or any app/ shape.\n\n"
          "Fix options (HARD gate — no baseline):\n"
          "  1. Delete the include if it's unused.\n"
          "  2. Move the needed predicate/constant DOWN into core/ or a "
          "pure leaf lib.\n"
          "  3. Invert the dependency: make the orchestration layer call "
          "core, not the\n     other way around.\n"
          "  4. As a deliberate, reviewed exception only, add "
          "'// core-boundary-ok:<tag>'.\n", stdout);
    return 1;
}

int check_core_include_boundary_run(int argc, char **argv)
{
    char roots[4][RS_PATH];
    int nr = 0, any, rc, i;
    static struct idf_set set;
    struct idf_collect c;
    regex_t inc, ok;
    struct cib_acc a = {0};
    (void)argc;
    (void)argv;
    any = cib_any_root();
    if (any < 0)
        return 2;
    if (!any) {
        fputs("check_core_include_boundary: clean — no core/ subdirs "
              "present yet (W0 posture)\n", stdout);
        return 0;
    }
    if (cib_fill_roots(roots, &nr))
        return 2;
    set.n = 0;
    c.roots = roots;
    c.nroots = nr;
    c.inc = 1;
    c.set = &set;
    rc = idf_collect(&c);
    if (rc)
        return rc;
    rc = gate_require_scanned(set.n, 1, "check-core-include-boundary",
                              "no tracked source under the four core "
                              "contexts");
    if (rc)
        return rc;
    rc = pair_comp(&inc, REG_EXTENDED, k_cib_inc, "", "", "",
                   &ok, REG_EXTENDED, k_cib_ok, "", "", "");
    if (rc)
        return rc;
    for (i = 0; rc == 0 && i < set.n; i++) {
        a.path = set.p[i];
        rc = idf_scan_file(set.p[i], &inc, &ok, cib_hit, &a);
    }
    drop2(&inc, &ok);
    if (rc)
        return rc;
    if (a.n == 0) {
        fputs("check_core_include_boundary: clean — four pure consensus "
              "contexts have no forbidden includes; core/modules "
              "UNMEASURED\n", stdout);
        return 0;
    }
    return cib_report(&a);
}

static int cib_st_text(const char *text, int want)
{
    regex_t inc, ok;
    struct cib_acc a = { .path = "core/consensus/src/st.c" };
    int rc = pair_comp(&inc, REG_EXTENDED, k_cib_inc, "", "", "",
                       &ok, REG_EXTENDED, k_cib_ok, "", "", "");
    if (rc)
        return rc;
    rc = idf_scan_text(text, &inc, &ok, cib_hit, &a);
    drop2(&inc, &ok);
    if (rc)
        return rc;
    if (a.n != want) {
        fprintf(stderr, "check_core_include_boundary selftest: want %d got %d\n",
                want, a.n);
        return 1;
    }
    return 0;
}

static int cib_st_planted(void)
{
    return cib_st_text("#include \"validation/sigops.h\"\n", 1);
}

static int cib_st_clean(void)
{
    return cib_st_text("#include \"crypto/sha256.h\"\n", 0);
}

int check_core_include_boundary_selftest(void)
{
    return st_ok(cib_st_planted() | cib_st_clean(),
                 "check_core_include_boundary selftest: PASS — a planted "
                 "validation include is named, a leaf crypto include is "
                 "clean\n");
}

struct sid_acc {
    const char *path;
    const struct bln_set *base;
    struct bln_set *seen;
    struct bln_set *neu;
};

static int sid_hit(int line, const char *raw, const char *hdr, const char *tok,
                   void *ctx)
{
    struct sid_acc *a = ctx;
    char key[BLN_ROW];
    (void)line;
    (void)raw;
    (void)hdr;
    if (ovf(snprintf(key, sizeof key, "%s:%s", a->path, tok), sizeof key))
        return 2;
    if (bln_has(a->base, key))
        return bln_add(a->seen, key);
    return bln_add(a->neu, key);
}

static int sid_base_skip(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return *s == '\0' || *s == '#';
}

static int sid_load(struct bln_set *s, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[BLN_ROW + 8];
    int rc = 0;
    s->count = 0;
    if (!f) {
        fprintf(stderr,
                "check_shape_include_direction: FATAL — baseline missing: "
                "%s\n", path);
        return 2;
    }
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (n && buf[n - 1] == '\r')
            buf[--n] = '\0';
        if (sid_base_skip(buf))
            continue;
        rc = bln_add(s, buf);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int sid_stale(const struct bln_set *base, const struct bln_set *seen,
                     struct bln_set *stale)
{
    int i, rc = 0;
    stale->count = 0;
    for (i = 0; rc == 0 && i < base->count; i++)
        if (!bln_has(seen, base->n[i]))
            rc = bln_add(stale, base->n[i]);
    return rc;
}

static int sid_scan_set(const struct idf_set *set, const regex_t *inc,
                        const regex_t *ok, struct sid_acc *a)
{
    int i, rc = 0;
    for (i = 0; rc == 0 && i < set->n; i++) {
        a->path = set->p[i];
        rc = idf_scan_file(set->p[i], inc, ok, sid_hit, a);
    }
    return rc;
}

static int sid_report(const struct bln_set *neu, const struct bln_set *stale,
                      const char *basepath)
{
    int i;
    printf("\ncheck_shape_include_direction: %d NEW violation(s) not in %s\n\n",
           neu->count, basepath);
    for (i = 0; i < neu->count; i++)
        printf("  %s\n", neu->n[i]);
    if (stale->count) {
        printf("\ncheck_shape_include_direction: %d stale baseline "
               "entry/entries\n", stale->count);
        for (i = 0; i < stale->count; i++)
            printf("  %s\n", stale->n[i]);
        fputs("Remove stale entries now; leaving them would let deleted "
              "debt return.\n", stdout);
    }
    fputs("\nFix options (RATCHET gate — new debt is never accepted):\n"
          "  1. Delete the include if it's unused (the symbol may already "
          "come from elsewhere).\n"
          "  2. Move the needed symbol DOWN into models/ (or lib/) where "
          "both sides\n     can reference it cleanly (e.g. a pure policy "
          "table).\n"
          "  3. Invert the dependency: pass the value in from the upstream "
          "caller,\n     or register a callback/port seam (see "
          "node_db_set_quick_check_skip_probe\n     in "
          "engine/models/include/models/database.h for the pattern).\n"
          "  4. As a deliberate, reviewed exception only, add an override "
          "marker\n     '// shape-layer-ok:<tag>' to the include line, or "
          "add a reviewed\n     baseline entry (grandfathering pre-existing "
          "debt only — never a\n     way to introduce a brand-new upward "
          "include).\n", stdout);
    return 1;
}

int check_shape_include_direction_run(int argc, char **argv)
{
    char mroots[RS_MAX][RS_PATH], sroots[RS_MAX][RS_PATH];
    int nm = 0, ns = 0, rc;
    static struct idf_set models, services;
    struct bln_set base = {0}, seen = {0}, neu = {0}, stale = {0};
    struct idf_collect cm, cs;
    regex_t minc, sinc, ok;
    struct sid_acc a;
    (void)argc;
    (void)argv;
    rc = repo_shape_room_dirs("models", mroots, RS_MAX, &nm);
    if (rc)
        return rc;
    rc = repo_shape_room_dirs("services", sroots, RS_MAX, &ns);
    if (rc)
        return rc;
    models.n = 0;
    services.n = 0;
    cm.roots = mroots;
    cm.nroots = nm;
    cm.inc = 0;
    cm.set = &models;
    cs.roots = sroots;
    cs.nroots = ns;
    cs.inc = 0;
    cs.set = &services;
    rc = idf_collect(&cm);
    if (rc)
        return rc;
    rc = idf_collect(&cs);
    if (rc)
        return rc;
    rc = gate_require_scanned(models.n, 1, "check-shape-include-direction",
                              "no tracked models/ source");
    if (rc)
        return rc;
    rc = gate_require_scanned(services.n, 1, "check-shape-include-direction",
                              "no tracked services/ source");
    if (rc)
        return rc;
    rc = sid_load(&base, k_sid_base);
    if (rc)
        return rc;
    rc = pair_comp(&minc, REG_EXTENDED, k_sid_mod, "", "", "",
                   &ok, REG_EXTENDED, k_sid_ok, "", "", "");
    if (rc)
        return rc;
    rc = compile_pat(&sinc, REG_EXTENDED, k_sid_svc, "", "", "");
    if (rc) {
        drop2(&minc, &ok);
        return rc;
    }
    a.base = &base;
    a.seen = &seen;
    a.neu = &neu;
    rc = sid_scan_set(&models, &minc, &ok, &a);
    if (rc == 0)
        rc = sid_scan_set(&services, &sinc, &ok, &a);
    regfree(&sinc);
    drop2(&minc, &ok);
    if (rc)
        return rc;
    rc = sid_stale(&base, &seen, &stale);
    if (rc)
        return rc;
    if (neu.count == 0 && stale.count == 0) {
        printf("check_shape_include_direction: clean — %d baselined "
               "(pre-existing), no NEW upward shape includes\n", base.count);
        return 0;
    }
    return sid_report(&neu, &stale, k_sid_base);
}

static int sid_st_text(const char *text, int want)
{
    regex_t inc, ok;
    struct bln_set base = {0}, seen = {0}, neu = {0};
    struct sid_acc a = { .path = "engine/models/src/st.c", .base = &base,
                         .seen = &seen, .neu = &neu };
    int rc = pair_comp(&inc, REG_EXTENDED, k_sid_mod, "", "", "",
                       &ok, REG_EXTENDED, k_sid_ok, "", "", "");
    if (rc)
        return rc;
    rc = idf_scan_text(text, &inc, &ok, sid_hit, &a);
    drop2(&inc, &ok);
    if (rc)
        return rc;
    if (neu.count != want) {
        fprintf(stderr, "check_shape_include_direction selftest: want %d got %d\n",
                want, neu.count);
        return 1;
    }
    return 0;
}

static int sid_st_planted(void)
{
    return sid_st_text("#include \"services/foo.h\"\n", 1);
}

static int sid_st_clean(void)
{
    return sid_st_text("#include \"models/database.h\"\n", 0);
}

int check_shape_include_direction_selftest(void)
{
    return st_ok(sid_st_planted() | sid_st_clean(),
                 "check_shape_include_direction selftest: PASS — a planted "
                 "models->services include is named, a downward include is "
                 "clean\n");
}
