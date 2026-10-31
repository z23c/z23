/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check-zcc-cache section for cross-root key portability. The same
 * compile launched from two checkout roots must share one cache entry when
 * -ffile-prefix-map proves the output is root-independent, including when the
 * include directory and source are spelled as ABSOLUTE paths under the root.
 * It must stay unshared when no map covers the root, must keep a path outside
 * the mapped root raw, and must still key on environment variables a compiler
 * reads while ignoring ones it cannot.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc_text.h"
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

/* One compile of `src` from inside root `dir`, every path absolute under it.
 * map != 0 adds -ffile-prefix-map=<dir>=/zcl; `inc2` is an extra absolute -I
 * (NULL for none). */
static int pk_cc(const char *dir, const char *src, const char *obj, int map,
                 const char *inc2, const char *dep,
                 const char *const *env)
{
    const char *av[20] = { zc.zcc, "cc", "-std=c23", "-O1", "-g", "-Wall", "-c" };
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
    return 0;
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
    static const char *const srcs[] = { "p.c", "np.c", "out.c", "e.c", "n.c", "d.c" };
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
           pk_side_artifacts();
}
