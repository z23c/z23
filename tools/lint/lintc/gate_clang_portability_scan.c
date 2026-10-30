/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: scan-set construction for the check-clang-portability gate port:
 * the repo-shape reader (PRODUCT_CONTEXTS / APP_DIRS / LIB_MODULES /
 * module dirs with their floors), the compiler flag list, the Makefile-
 * derived source set, and the git-index coverage oracle with its
 * three-answer comparison. Ported from check_clang_portability.sh,
 * repo_shape.sh and gate_lib.sh (the script and its allowlist row are removed by the wiring; the shared shell helpers stay).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_clang_portability_priv.h"

static const char k_cp_gate[] = "check-clang-portability";

static int cp_reqscan(int count, int floor, const char *hint)
{
    int rc = gate_require_scanned(count, floor, k_cp_gate, hint);
    return rc ? rc : 0;
}

/* ── repo shape ──────────────────────────────────────────────────────── */

static int cp_parse_lib_modules(char out[][CP_PATH], int max)
{
    FILE *f = fopen("engine/composition/lib_module_order.def", "r");
    if (!f)
        return -1;
    char line[CP_LINE];
    int n = 0;
    while (fgets(line, sizeof line, f)) {
        char *q = strstr(line, "LIB_MODULE(\"");
        if (!q)
            continue;
        q += 12;
        char *e = strchr(q, '"');
        if (!e || n >= max)
            continue;
        size_t l = (size_t)(e - q);
        if (l >= CP_PATH)
            l = CP_PATH - 1;
        memcpy(out[n], q, l);
        out[n][l] = '\0';
        n++;
    }
    fclose(f);
    return n;
}

static int cp_is_module_dir(const char *rel)
{
    const char *m = strstr(rel, "/modules/");
    return m && strchr(m + 9, '/') == NULL;
}

static int cp_walk_mods(const char *dir, char out[][CP_PATH], int max, int *n)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char sub[CP_PATH];
        if (ovf(snprintf(sub, sizeof sub, "%s/%s", dir, e->d_name), sizeof sub)) {
            closedir(d);
            return -1;
        }
        struct stat st;
        if (stat(sub, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        const char *rel = sub[0] == '.' && sub[1] == '/' ? sub + 2 : sub;
        if (cp_is_module_dir(rel)) {
            if (*n >= max) {
                closedir(d);
                return -1;
            }
            if (ovf(snprintf(out[*n], CP_PATH, "%s", rel), CP_PATH)) {
                closedir(d);
                return -1;
            }
            (*n)++;
        } else if (cp_walk_mods(sub, out, max, n) < 0) {
            closedir(d);
            return -1;
        }
    }
    closedir(d);
    return 0;
}

int cp_shape_init(struct cp_ctx *c)
{
    int rc = gate_require_scanned(0, 0, "", ""); /* never used; keep lint calm */
    (void)rc;
    c->nprod = cp_makefile_list(c->makefile, "PRODUCT_CONTEXTS",
                                c->product_ctxs, CP_MAXBASE);
    int r0 = gate_require_scanned(c->nprod < 0 ? 0 : c->nprod, 1, "repo-shape",
                                  "PRODUCT_CONTEXTS parse came back empty");
    if (r0)
        return r0;
    c->nshape = cp_makefile_list(c->makefile, "APP_DIRS", c->app_shapes,
                                 CP_MAXBASE);
    int r1 = gate_require_scanned(c->nshape < 0 ? 0 : c->nshape, 1, "repo-shape",
                                  "APP_DIRS parse came back empty");
    if (r1)
        return r1;
    c->nlib = cp_parse_lib_modules(c->lib_modules, CP_MAXBASE);
    int r2 = gate_require_scanned(c->nlib < 0 ? 0 : c->nlib, 1, "repo-shape",
                                  "module declaration parse came back empty");
    if (r2)
        return r2;
    static const char *const auth[] = { "core", "engine", "cognition",
                                        "platform", "contexts" };
    c->nmod = 0;
    for (size_t i = 0; i < sizeof auth / sizeof auth[0]; i++)
        if (cp_walk_mods(auth[i], c->module_dirs, CP_MAXSRC, &c->nmod) < 0) {
            fprintf(stderr, "check-clang-portability: module dirs exceeds %d\n",
                    CP_MAXSRC);
            return 2;
        }
    cp_sort_uniq(c->module_dirs[0], CP_PATH, &c->nmod);
    int rn = c->nlib < 0 ? 0 : c->nlib;
    return gate_require_scanned(c->nmod, rn, "repo-shape",
                                "physical module directory set is incomplete");
}

/* ── flags ───────────────────────────────────────────────────────────── */

static void cp_addflag(struct cp_ctx *c, const char *fmt, ...)
{
    if (c->nflags >= CP_MAXARGS)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->flags[c->nflags], CP_PATH, fmt, ap);
    va_end(ap);
    c->nflags++;
}

static int cp_add_darwin(struct cp_ctx *c)
{
    struct utsname u;
    if (uname(&u) != 0 || strcmp(u.sysname, "Darwin") != 0)
        return 0;
    cp_addflag(c, "-D_DARWIN_C_SOURCE");
    cp_addflag(c, "-Dst_atim=st_atimespec");
    cp_addflag(c, "-Dst_mtim=st_mtimespec");
    cp_addflag(c, "-Dst_ctim=st_ctimespec");
    return 0;
}

static void cp_add_all(struct cp_ctx *c, const char *const *v, size_t n)
{
    for (size_t i = 0; i < n; i++)
        cp_addflag(c, "%s", v[i]);
}

/* Compiler-family flags: detect the family, then add warn/family/build sets. */
static int cp_family_flags(struct cp_ctx *c)
{
    static const char *const warn[] = { "-std=c23", "-Wall", "-Wextra",
        "-Werror", "-pedantic", "-Wimplicit-fallthrough", "-fsyntax-only" };
    static const char *const build[] = { "-O3", "-U_FORTIFY_SOURCE",
                                         "-D_FORTIFY_SOURCE=2" };
    static const char *const clangx[] = { "-Wno-gnu-zero-variadic-macro-arguments",
        "-fno-caret-diagnostics", "-fno-color-diagnostics",
        "-fno-diagnostics-fixit-info" };
    /* suppression-ok: mirrors the node build so the baseline measures reality */
    static const char *const gccx[] = { "-Wno-stringop-overflow",
        "-fno-diagnostics-show-caret", "-fdiagnostics-color=never" };
    char capture[CP_PATH], ver[CP_LINE];
    if (ovf(snprintf(capture, sizeof capture, "%s/ccver.txt", c->work),
            sizeof capture))
        return 2;
    cp_version_line(c, capture, ver, sizeof ver);
    snprintf(c->family, sizeof c->family, "%s",
             strcasestr(ver, "clang") ? "clang" : "gcc");
    cp_add_all(c, warn, sizeof warn / sizeof warn[0]);
    if (!strcmp(c->family, "clang"))
        cp_add_all(c, clangx, sizeof clangx / sizeof clangx[0]);
    else
        cp_add_all(c, gccx, sizeof gccx / sizeof gccx[0]);
    cp_add_all(c, build, sizeof build / sizeof build[0]);
    return 0;
}

/* Include roots found under the layer directories plus the fixed ones. */
static int cp_include_flags(struct cp_ctx *c)
{
    static char incdirs[CP_MAXINC][CP_PATH];
    static const char *const auth[] = { "core", "engine", "contexts",
                                        "cognition", "platform" };
    int ninc = cp_find_includes(auth, 5, incdirs, CP_MAXINC);
    if (ninc < 0) {
        fprintf(stderr, "check-clang-portability: include roots exceeds %d\n",
                CP_MAXINC);
        return 2;
    }
    int rc = cp_reqscan(ninc, 20, "no include/ roots found — the layer "
                                  "directory layout moved");
    if (rc)
        return rc;
    for (int i = 0; i < ninc; i++)
        cp_addflag(c, "-I%s", incdirs[i]);
    cp_addflag(c, "-Itools");
    cp_addflag(c, "-Itools/dev");
    cp_addflag(c, "-Ivendor/include");
    return 0;
}

static int cp_write_flags(struct cp_ctx *c)
{
    if (ovf(snprintf(c->baseline_rel, sizeof c->baseline_rel,
                     "tools/lint/portability_baseline.%s.txt", c->family),
            sizeof c->baseline_rel))
        return 2;
    if (ovf(snprintf(c->flags_nul, sizeof c->flags_nul, "%s/flags.nul",
                     c->work), sizeof c->flags_nul))
        return 2;
    FILE *f = fopen(c->flags_nul, "wb");
    if (!f)
        return die("z23-lint: cannot write %s\n", c->flags_nul);
    for (int i = 0; i < c->nflags; i++)
        fprintf(f, "%s%c", c->flags[i], '\0');
    fclose(f);
    return 0;
}

int cp_build_flags(struct cp_ctx *c)
{
    c->nflags = 0;
    int rc = cp_family_flags(c);
    if (rc)
        return rc;
    cp_addflag(c, "-D_POSIX_C_SOURCE=200809L");
    cp_addflag(c, "-DZCL_AR_ENFORCE");
    cp_addflag(c, "-DZCL_BUILD_SOURCE_ID=\"clang-portability-gate\"");
    cp_addflag(c, "-DZCL_BUILD_CLEAN=1");
    if (cp_add_darwin(c) != 0)
        return 2;
    rc = cp_include_flags(c);
    return rc ? rc : cp_write_flags(c);
}

/* ── source set ──────────────────────────────────────────────────────── */

static int cp_collect1(struct cp_ctx *c, const char *dir)
{
    return cp_collect_c(dir, c->srcs, CP_MAXSRC, &c->nsrc);
}

/* Format a directory name and collect its *.c files; 2 on any failure. */
static int cp_collectf(struct cp_ctx *c, const char *fmt, ...)
{
    char d[CP_PATH];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(d, sizeof d, fmt, ap);
    va_end(ap);
    if (ovf(n, sizeof d))
        return 2;
    return cp_collect1(c, d) ? 2 : 0;
}

/* Collect fmt for every word of the named Makefile variable. */
static int cp_collect_var(struct cp_ctx *c, const char *var, const char *fmt)
{
    char words[CP_MAXBASE][CP_PATH];
    int n = cp_makefile_list(c->makefile, var, words, CP_MAXBASE);
    if (n < 0)
        return 2;
    for (int i = 0; i < n; i++)
        if (cp_collectf(c, fmt, words[i]))
            return 2;
    return 0;
}

static int cp_collect_shapes(struct cp_ctx *c)
{
    for (int a = 0; a < 2; a++) /* engine, cognition */
        for (int s = 0; s < c->nshape; s++)
            if (cp_collectf(c, "%s/%s/src", a ? "cognition" : "engine",
                            c->app_shapes[s]))
                return 2;
    for (int p = 0; p < c->nprod; p++)
        for (int s = 0; s < c->nshape; s++)
            if (cp_collectf(c, "contexts/%s/%s/src", c->product_ctxs[p],
                            c->app_shapes[s]))
                return 2;
    for (int m = 0; m < c->nmod; m++)
        if (cp_collectf(c, "%s/src", c->module_dirs[m]))
            return 2;
    return 0;
}

static int cp_collect_fixed(struct cp_ctx *c)
{
    static const char *const dom[] = { "contexts/wallet/domain",
                                       "platform/domain/encoding" };
    for (size_t i = 0; i < sizeof dom / sizeof dom[0]; i++)
        if (cp_collectf(c, "%s/src", dom[i]))
            return 2;
    static const char *const fixed[] = { "engine/composition/src",
        "platform/adapters/outbound/persistence/src", "tools/dev",
        "tools/command", "engine/entry" };
    for (size_t i = 0; i < sizeof fixed / sizeof fixed[0]; i++)
        if (cp_collect1(c, fixed[i]))
            return 2;
    return 0;
}

int cp_scan_sources(struct cp_ctx *c)
{
    c->nsrc = 0;
    if (cp_collect_shapes(c) || cp_collect_var(c, "CORE_CONTEXTS", "core/%s/src"))
        return 2;
    if (cp_collect_fixed(c) ||
        cp_collect_var(c, "APPLICATION_CONTEXTS", "engine/application/%s/src"))
        return 2;
    /* filter '/_' then sort -u */
    int u = 0;
    for (int i = 0; i < c->nsrc; i++)
        if (!strstr(c->srcs[i], "/_")) {
            memcpy(c->srcs[u], c->srcs[i], CP_PATH);
            u++;
        }
    c->nsrc = u;
    cp_sort_uniq(c->srcs[0], CP_PATH, &c->nsrc);
    char hint[CP_PATH * 2];
    if (ovf(snprintf(hint, sizeof hint,
                     "parsed APP_DIRS/LIB_MODULES/CORE_CONTEXTS from %s — "
                     "a variable rename there empties this scan", c->makefile),
            sizeof hint))
        return 2;
    return cp_reqscan(c->nsrc, 900, hint);
}

/* ── coverage oracle ─────────────────────────────────────────────────── */

static const char k_cp_shape_re[] =
    "^((engine|cognition|contexts/[^/]+)/(models|controllers|views|services|"
    "supervisors|conditions|jobs)/src/[^/]+\\.c|((core|engine|cognition|"
    "platform|contexts/[^/]+)/modules/[^/]+/src/[^/]+\\.c)|core/(consensus|"
    "params|math|chainparams)/src/[^/]+\\.c|(contexts/wallet/domain|platform/"
    "domain/encoding)/src/[^/]+\\.c|engine/application/[^/]+/src/[^/]+\\.c|"
    "engine/composition/src/[^/]+\\.c|platform/adapters/outbound/persistence/"
    "src/[^/]+\\.c|tools/(dev|command)/[^/]+\\.c|engine/entry/[^/]+\\.c)$";

static int cp_oracle_raw(struct cp_ctx *c, const char *out)
{
    (void)c;
    static const char *const spec[] = { "core/**/*.c", "engine/**/*.c",
        "contexts/**/*.c", "cognition/**/*.c", "platform/**/*.c",
        "platform/adapters/outbound/persistence/src/*.c", "tools/dev/*.c",
        "tools/command/*.c" };
    char joined[CP_LINE];
    joined[0] = '\0';
    size_t jl = 0;
    for (size_t i = 0; i < sizeof spec / sizeof spec[0]; i++)
        jl += (size_t)snprintf(joined + jl, sizeof joined - jl, "%s%s",
                               i ? " " : "", spec[i]);
    if (ovf((int)jl, sizeof joined))
        return 2;
    char *av[4 + 8 + 1];
    int a = 0;
    av[a++] = (char *)"git";
    av[a++] = (char *)"ls-files";
    av[a++] = (char *)"--cached";
    av[a++] = (char *)"--";
    for (size_t i = 0; i < sizeof spec / sizeof spec[0]; i++)
        av[a++] = (char *)spec[i];
    av[a] = NULL;
    int rc = 0;
    if (cp_spawn("git", av, out, "/dev/null", &rc) != 0 || rc != 0) {
        fprintf(stderr, "%s: UNPROVEN — the coverage oracle could not run:\n"
                "  'git ls-files -- %s' exited %d.\n"
                "  Without an independent expectation this gate cannot tell a\n"
                "  complete scan from a partial one, so it refuses to grade\n"
                "  either way. Run it from inside the checkout.\n",
                k_cp_gate, joined, rc);
        return 2;
    }
    int n = cp_count_lines(out);
    if (n <= 0) {
        fprintf(stderr, "%s: UNPROVEN — the coverage oracle is empty: git "
                        "tracks no\n  file matching: %s\n"
                        "  An empty expectation would pass every scan, "
                        "including a scan\n  of nothing. Refusing to vouch "
                        "for coverage off a hollow\n  oracle. Fix the "
                        "pathspec, or drop the coverage check if the\n"
                        "  set is genuinely gone.\n", k_cp_gate, joined);
        return 2;
    }
    return 0;
}

static int cp_oracle_filter(const char *raw, const char *out)
{
    regex_t re;
    if (cp_regcomp(&re, k_cp_shape_re, REG_EXTENDED | REG_NOSUB))
        return 2;
    FILE *in = fopen(raw, "r"), *fo = fopen(out, "w");
    if (!in || !fo) {
        if (in)
            fclose(in);
        if (fo)
            fclose(fo);
        regfree(&re);
        return 2;
    }
    char line[CP_PATH];
    while (fgets(line, sizeof line, in)) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (strstr(line, "/_"))
            continue;
        if (regexec(&re, line, 0, NULL, 0) == 0)
            fprintf(fo, "%s\n", line);
    }
    fclose(in);
    fclose(fo);
    regfree(&re);
    return 0;
}

static int cp_in_set(char set[][CP_PATH], int n, const char *s)
{
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2, r = strcmp(set[mid], s);
        if (r == 0)
            return 1;
        if (r < 0)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return 0;
}

/* Read the oracle's expected-source list: sorted, unique. */
static int cp_load_expected(const char *expected, char exp[][CP_PATH])
{
    int ne = 0;
    FILE *f = fopen(expected, "r");
    if (f) {
        char line[CP_PATH];
        while (fgets(line, sizeof line, f) && ne < CP_MAXSRC) {
            char *nl = strchr(line, '\n');
            if (nl)
                *nl = '\0';
            if (line[0])
                memcpy(exp[ne++], line, CP_PATH);
        }
        fclose(f);
    }
    cp_sort_uniq(exp[0], CP_PATH, &ne);
    return ne;
}

static int cp_coverage_allowance(void)
{
    const char *a = getenv("ZCL_CLANG_PORTABILITY_COVERAGE_ALLOWANCE");
    int allow = a && *a ? atoi(a) : 0;
    return allow < 0 ? 0 : allow;
}

static int cp_cov_unproven(struct cp_ctx *c, int ne, int missing, int allow,
                           char miss[][CP_PATH], int shown)
{
    const char *var = "ZCL_CLANG_PORTABILITY_COVERAGE_ALLOWANCE";
        fprintf(stderr, "%s: UNPROVEN — the scan reached %d of the %d\n"
                "  entries an independent oracle says it should have reached;\n"
                "  %d missing, above the shrink-only allowance of\n"
                "  %d recorded in %s.\n"
                "  This is a PARTIAL scan: not a clean one, and not a "
                "violating\n  one. 'I scanned less than my subject' is a "
                "third answer — the\n  gate never ran over the code it "
                "claims to cover, so it cannot\n  report either verdict. "
                "A file-count floor cannot see this;\n  the count stayed "
                "large.\n  Not reached (first 20 of %d):\n",
                k_cp_gate, c->nsrc, ne, missing, allow, var, missing);
        for (int i = 0; i < shown && i < 20; i++)
            fprintf(stderr, "    %s\n", miss[i]);
        if (missing > 20)
            fprintf(stderr, "    ... and %d more\n", missing - 20);
        fprintf(stderr, "  A named file is a compiled source this gate never "
                        "reached. Check that its layer still appears in "
                        "APP_DIRS/LIB_MODULES/CORE_CONTEXTS/DOMAIN_CONTEXTS/"
                        "APPLICATION_CONTEXTS as %s and engine/composition/"
                        "lib_module_order.def define them — a layer that "
                        "drops out of those lists drops out of this gate "
                        "silently.\n", c->makefile);
    return 2;
}

static int cp_cov_stale(int ne, int missing, int allow)
{
    const char *var = "ZCL_CLANG_PORTABILITY_COVERAGE_ALLOWANCE";
        fprintf(stderr, "%s: VIOLATION — the coverage allowance is stale: "
                        "the scan now\n  misses only %d of %d expected "
                        "entries, below\n  %s=%d.\n"
                        "  Coverage improved without lowering the allowance. "
                        "An allowance\n  that may only ever rise stops "
                        "meaning 'what we measured' and\n  starts meaning "
                        "'whatever nobody lowered' — a ratchet that\n  rusts "
                        "shut. Lower %s to %d, with the reason, in the\n"
                        "  same commit.\n",
                k_cp_gate, missing, ne, var, allow, var, missing);
    return 1;
}

static int cp_require_coverage(struct cp_ctx *c, const char *expected)
{
    static char exp[CP_MAXSRC][CP_PATH];
    int ne = cp_load_expected(expected, exp);
    int missing = 0;
    char miss[64][CP_PATH];
    int shown = 0;
    for (int i = 0; i < ne; i++)
        if (!cp_in_set(c->srcs, c->nsrc, exp[i])) {
            missing++;
            if (shown < 64)
                memcpy(miss[shown++], exp[i], CP_PATH);
        }
    int allow = cp_coverage_allowance();
    if (missing > allow)
        return cp_cov_unproven(c, ne, missing, allow, miss, shown);
    if (missing < allow)
        return cp_cov_stale(ne, missing, allow);
    return 0;
}

int cp_coverage(struct cp_ctx *c)
{
    const char *on = getenv("ZCL_CLANG_PORTABILITY_COVERAGE");
    if (on && !strcmp(on, "0"))
        return 0;
    char raw[CP_PATH], fil[CP_PATH];
    if (ovf(snprintf(raw, sizeof raw, "%s/oracle.raw", c->work), sizeof raw))
        return 2;
    if (ovf(snprintf(fil, sizeof fil, "%s/oracle.txt", c->work), sizeof fil))
        return 2;
    int rc = cp_oracle_raw(c, raw);
    if (rc)
        return rc;
    rc = cp_oracle_filter(raw, fil);
    if (rc)
        return rc;
    return cp_require_coverage(c, fil);
}
