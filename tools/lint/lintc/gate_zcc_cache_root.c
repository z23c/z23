/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check-zcc-cache section for cross-root key portability. The same
 * compile launched from two checkout roots must share one cache entry when
 * -ffile-prefix-map proves the output is root-independent, including when the
 * include directory and source are spelled as ABSOLUTE paths under the root.
 * It must stay unshared when no map covers the root, must keep a path outside
 * the mapped root raw, and must still key on environment variables a compiler
 * reads while ignoring ones it cannot, only under the ZCC_PORTABLE_ENV=1 opt-in
 * and a stock driver name; and must decline root sharing for profiling flags.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc_text.h"
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

/* One compile of `src` from inside root `dir`, every path absolute under it.
 * map != 0 adds -ffile-prefix-map=<dir>=/zcl; `inc2` is an extra absolute -I
 * (NULL for none). */
static const char *pk_extra; /* one extra compiler flag for the next pk_cc */
static const char *pk_driver = "cc"; /* compiler argv[0] for the next pk_cc */
static int pk_portable = 1;          /* export ZCC_PORTABLE_ENV=1 to zcc */

static int pk_cc(const char *dir, const char *src, const char *obj, int map,
                 const char *inc2, const char *dep,
                 const char *const *caller_env)
{
    /* The opt-in goes first so a caller entry could still override it. */
    const char *env[8] = { pk_portable ? "ZCC_PORTABLE_ENV=1"
                                       : "ZCC_PORTABLE_ENV" };
    size_t ne = 1;
    for (; caller_env && *caller_env && ne < 7; caller_env++)
        env[ne++] = *caller_env;
    env[ne] = NULL;
    const char *av[20] = { zc.zcc, pk_driver, "-std=c23", "-O1", "-g", "-Wall", "-c" };
    size_t n = 7;
    av[n++] = zcf("%s/%s", dir, src);
    av[n++] = "-o";
    av[n++] = obj;
    av[n++] = zcf("-I%s/inc", dir);
    if (inc2)
        av[n++] = zcf("-I%s", inc2);
    if (dep) {
        av[n++] = "-MMD";
        av[n++] = "-MF";
        av[n++] = dep;
    }
    if (pk_extra)
        av[n++] = pk_extra;
    if (map)
        av[n++] = zcf("-ffile-prefix-map=%s=/zcl", dir);
    av[n] = NULL;
    struct zc_cmd c = { .cwd = dir, .argv = av, .env = env,
                        .errf = "/dev/null" };
    return zc_run(&c);
}

static int pk_put_pair(const char *name, const char *body)
{
    return zc_put(zcf("portable.a/%s", name), body) ||
           zc_put(zcf("portable.b/%s", name), body);
}

static int pk_shared(void)
{
    const char *a = zcw("portable.a"), *b = zcw("portable.b");
    /* (a) two roots, one mapped key: the second compile is a hit. */
    if (pk_cc(a, "p.c", zcw("pk.a.o"), 1, NULL, NULL, NULL) != 0)
        zc_fail("portable key (a): first compile failed");
    zc_disp("MISS", "portable key (a): first compile was not a MISS");
    if (pk_cc(b, "p.c", zcw("pk.b.o"), 1, NULL, NULL, NULL) != 0)
        zc_fail("portable key (a): second-root compile failed");
    zc_disp("HIT", "portable key (a): absolute -I and source under a mapped root "
                   "did not share a key across roots");

    /* (b) the hit is byte-identical to a fresh compile in the second root. */
    const char *const nocache[] = { "ZCC_DISABLE=1", NULL };
    if (pk_cc(b, "p.c", zcw("pk.fresh.o"), 1, NULL, NULL, nocache) != 0)
        zc_fail("portable key (b): uncached compile failed");
    zc_want(zc_same(zcw("pk.b.o"), zcw("pk.fresh.o")),
            "portable key (b): the cross-root hit differs from a fresh compile");
    return 0;
}

static int pk_unshared(void)
{
    const char *a = zcw("portable.a"), *b = zcw("portable.b");
    /* (c) no -ffile-prefix-map: the roots stay distinct. */
    if (pk_cc(a, "np.c", zcw("np.a.o"), 0, NULL, NULL, NULL) != 0 ||
        pk_cc(b, "np.c", zcw("np.b.o"), 0, NULL, NULL, NULL) != 0)
        zc_fail("portable key (c): unmapped compile failed");
    zc_disp("MISS",
                   "portable key (c): two unmapped roots shared a key");

    /* (d) an -I outside the mapped root stays raw: same header bytes under two
     * different outside directories are two keys. */
    if (pk_cc(a, "out.c", zcw("out.a.o"), 1, zcw("portable.s1/inc"), NULL, NULL) != 0 ||
        pk_cc(b, "out.c", zcw("out.b.o"), 1, zcw("portable.s2/inc"), NULL, NULL) != 0)
        zc_fail("portable key (d): outside -I compile failed");
    zc_disp("MISS",
                   "portable key (d): an -I outside the mapped root was remapped");
    return 0;
}

/* A specs file (or plugin, or -wrapper) can make the driver read anything: the
 * unrelated variable must then be part of the key. */
static int pk_env_specs(void)
{
    const char *a = zcw("portable.a"), *b = zcw("portable.b");
    if (zc_put("portable.specs", "") != 0)
        return 1;
    pk_extra = zcf("-specs=%s", zcw("portable.specs"));
    const char *const s1[] = { "ZCC_PORTABLE_NOISE=1", NULL };
    const char *const s2[] = { "ZCC_PORTABLE_NOISE=2", NULL };
    int sc = pk_cc(a, "s.c", zcw("s.1.o"), 1, NULL, NULL, s1) != 0 ||
             pk_cc(b, "s.c", zcw("s.2.o"), 1, NULL, NULL, s2) != 0;
    pk_extra = NULL;
    if (sc)
        zc_fail("portable key (e): specs compile failed");
    zc_disp("MISS", "portable key (e): a specs-extended driver was keyed on the "
                    "allowlist only");
    return 0;
}

/* (e) an allowlisted variable changes the key; an unrelated one does not. */
static int pk_env(void)
{
    const char *a = zcw("portable.a"), *b = zcw("portable.b");
    const char *const e1[] = { "SOURCE_DATE_EPOCH=1", NULL };
    const char *const e2[] = { "SOURCE_DATE_EPOCH=2", NULL };
    if (pk_cc(a, "e.c", zcw("e.1.o"), 1, NULL, NULL, e1) != 0 ||
        pk_cc(b, "e.c", zcw("e.2.o"), 1, NULL, NULL, e2) != 0)
        zc_fail("portable key (e): allowlisted-variable compile failed");
    zc_disp("MISS",
                   "portable key (e): an allowlisted variable did not change the key");
    const char *const n1[] = { "ZCC_PORTABLE_NOISE=1", "HOME=/nonexistent-a", NULL };
    const char *const n2[] = { "ZCC_PORTABLE_NOISE=2", "HOME=/nonexistent-b", NULL };
    if (pk_cc(a, "n.c", zcw("n.1.o"), 1, NULL, NULL, n1) != 0 ||
        pk_cc(b, "n.c", zcw("n.2.o"), 1, NULL, NULL, n2) != 0)
        zc_fail("portable key (e): unrelated-variable compile failed");
    zc_disp("HIT", "portable key (e): a variable no compiler reads changed the key");
    return pk_env_specs();
}

/* Locate `cc` on PATH, resolved through symlinks, into out. */
static int pk_find_cc(char out[PATH_MAX])
{
    const char *path = getenv("PATH");
    char cand[PATH_MAX];
    while (path && *path) {
        size_t n = strcspn(path, ":");
        if (n > 0 && n < sizeof cand - 4u) {
            snprintf(cand, sizeof cand, "%.*s/cc", (int)n, path);
            if (access(cand, X_OK) == 0 && realpath(cand, out))
                return 0;
        }
        path += n + (path[n] ? 1u : 0u);
    }
    return 1;
}

/* A launcher under the non-stock name x-gcc. Not a symlink, which resolves
 * back to the stock name: a launcher the name test must not trust. Elsewhere
 * it is a byte copy of the real driver, with COMPILER_PATH so the relocated
 * copy still finds cc1. On Apple, cc is an xcrun shim that dispatches on its
 * own name and fails as x-gcc, so it is a sh launcher that execs the real
 * driver (the Apple suite's own wrapper shape). */
static const char *pk_make_xgcc(const char **cpath)
{
    char real[PATH_MAX];
    if (pk_find_cc(real) || csr_mkdirs(zcw("portable.x")))
        return NULL;
    const char *dst = zcw("portable.x/x-gcc");
#ifdef __APPLE__
    (void)cpath;
    if (strchr(real, '\'') ||
        zc_put("portable.x/x-gcc",
               zcf("#!/bin/sh\nexec '%s' \"$@\"\n", real)) ||
        chmod(dst, 0755) != 0)
        return NULL;
#else
    char out[PATH_MAX] = "";
    if (zc_copy(real, dst, 0) || chmod(dst, 0755) != 0)
        return NULL;
    const char *const qa[] = { real, "-print-prog-name=cc1", NULL };
    struct zc_cmd q = { .argv = qa, .out = out, .cap = sizeof out };
    if (zc_run(&q) != 0)
        return NULL;
    out[strcspn(out, "\r\n")] = '\0';
    char *slash = strrchr(out, '/');
    if (slash) {
        *slash = '\0';
        *cpath = zcf("COMPILER_PATH=%s", out);
    }
#endif
    return dst;
}

/* (h) without the ZCC_PORTABLE_ENV opt-in the whole environment is keyed. */
static int pk_env_default(void)
{
    const char *a = zcw("portable.a"), *b = zcw("portable.b");
    const char *const h1[] = { "ZCC_PORTABLE_NOISE=1", "HOME=/nonexistent-a", NULL };
    const char *const h2[] = { "ZCC_PORTABLE_NOISE=2", "HOME=/nonexistent-b", NULL };
    pk_portable = 0;
    int rc = pk_cc(a, "h.c", zcw("h.1.o"), 1, NULL, NULL, h1) != 0 ||
             pk_cc(b, "h.c", zcw("h.2.o"), 1, NULL, NULL, h2) != 0;
    pk_portable = 1;
    if (rc)
        zc_fail("portable key (h): default-environment compile failed");
    zc_disp("MISS", "portable key (h): without ZCC_PORTABLE_ENV an unrelated "
                    "variable did not change the key");
    return 0;
}

/* (i) a driver that is not named exactly like a stock one keys everything. */
static int pk_env_nonstock(void)
{
    const char *a = zcw("portable.a"), *b = zcw("portable.b");
    const char *cpath = NULL;
    const char *drv = pk_make_xgcc(&cpath);
    if (!drv)
    {
        zc_fail("portable key (i): could not stage the x-gcc driver");
        return 0;
    }
    const char *const x1[] = { "ZCC_PORTABLE_NOISE=1", cpath, NULL };
    const char *const x2[] = { "ZCC_PORTABLE_NOISE=2", cpath, NULL };
    pk_driver = drv;
    int rc = pk_cc(a, "x.c", zcw("x.1.o"), 1, NULL, NULL, x1) != 0 ||
             pk_cc(b, "x.c", zcw("x.2.o"), 1, NULL, NULL, x2) != 0;
    pk_driver = "cc";
    if (rc)
        zc_fail("portable key (i): x-gcc compile failed");
    zc_disp("MISS", "portable key (i): a driver named x-gcc was keyed on the "
                    "allowlist only");
    return 0;
}

/* (j) profiling and side-file flags write beside the object and can name the
 * root: two roots must not share a key. -fprofile-arcs and --coverage already
 * bypass the cache outright (never a HIT); the rest reach root_map(). */
static int pk_one_flag(const char *flag, const char *src, int must_miss)
{
    const char *a = zcw("portable.a"), *b = zcw("portable.b");
    pk_extra = flag;
    int rc = pk_cc(a, src, zcw("%s.1.o", src), 1, NULL, NULL, NULL) != 0 ||
             pk_cc(b, src, zcw("%s.2.o", src), 1, NULL, NULL, NULL) != 0;
    pk_extra = NULL;
    if (rc)
        zc_fail(zcf("portable key (j): %s compile failed", flag));
    else if (must_miss)
        zc_disp("MISS", zcf("portable key (j): %s compiles from two roots "
                            "shared a key", flag));
    else
        zc_disp_not_in(zc.log, "HIT", zcf("portable key (j): %s compiles "
                                          "from two roots were a HIT", flag));
    return 0;
}

static int pk_side_flags(void)
{
    return pk_one_flag("-save-temps", "j1.c", 1) ||
           pk_one_flag("-fstack-usage", "j2.c", 1) ||
           pk_one_flag("-pg", "j3.c", 1) ||
           pk_one_flag("-fprofile-arcs", "j4.c", 0) ||
           pk_one_flag("--coverage", "j5.c", 0);
}

/* (f) a depfile or a stored warning would name this root's absolute paths, so
 * neither may be replayed into another root. */
static int pk_side_artifacts(void)
{
    const char *a = zcw("portable.a"), *b = zcw("portable.b");
    if (pk_cc(a, "d.c", zcw("d.a.o"), 1, NULL, zcw("d.a.d"), NULL) != 0 ||
        pk_cc(b, "d.c", zcw("d.b.o"), 1, NULL, zcw("d.b.d"), NULL) != 0)
        zc_fail("portable key (f): depfile compile failed");
    zc_disp("MISS", "portable key (f): a depfile compile was shared across roots");
    if (pk_cc(a, "w.c", zcw("w.a.o"), 1, NULL, NULL, NULL) != 0 ||
        pk_cc(b, "w.c", zcw("w.b.o"), 1, NULL, NULL, NULL) != 0)
        zc_fail("portable key (f): warning compile failed");
    zc_disp("MISS", "portable key (f): a warning naming the root was replayed "
                    "into another root");
    return 0;
}

static int pk_fixture(void)
{
    if (csr_mkdirs(zcw("portable.a/inc")) || csr_mkdirs(zcw("portable.b/inc")) ||
        csr_mkdirs(zcw("portable.s1/inc")) || csr_mkdirs(zcw("portable.s2/inc")))
        return 1;
    static const char *const srcs[] = { "p.c", "np.c", "out.c", "e.c", "n.c", "d.c", "s.c",
                                      "h.c", "x.c", "j1.c", "j2.c", "j3.c", "j4.c", "j5.c" };
    for (size_t i = 0; i < sizeof srcs / sizeof srcs[0]; i++)
        if (pk_put_pair(srcs[i],
                        zcf("#include \"p.h\"\nint pk_%zu(void) { return "
                            "PK_VALUE + %zu; }\n", i, i)))
            return 1;
    return pk_put_pair("w.c", "#include \"p.h\"\nint pk_w(void) { int unused_pk; "
                       "return PK_VALUE; }\n") ||
           pk_put_pair("inc/p.h", "#define PK_VALUE 7\n") ||
           zc_put("portable.s1/inc/q.h", "#define PK_Q 1\n") ||
           zc_put("portable.s2/inc/q.h", "#define PK_Q 1\n");
}

int zc_sec_portable(void)
{
    return pk_fixture() || pk_shared() || pk_unshared() || pk_env() ||
           pk_env_default() || pk_env_nonstock() || pk_side_flags() ||
           pk_side_artifacts();
}
