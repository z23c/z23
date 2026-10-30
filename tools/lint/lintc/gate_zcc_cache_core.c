/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check-zcc-cache sections 1-5 and the probe-manifest cases: cold,
 * warm, touched and header-edit builds, filtered environment, compiler
 * identity, poisoned probe manifest, vanishing header, verified mode, and
 * absent/earlier include candidates.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

int zc_sec_basic(void)
{
    char b[ZC_SHA], c[ZC_SHA];
    if (zc_build("cold", ZC_ENV("ZCL_CAP_CLOSURE_SOURCE_RECORD=before"),
                 zc.sha_a))
        return 1;
    zc_disp("MISS", "a cold build was not a MISS");
    zc_want(zc_prog_is(zcw("prog"), "42"),
            "the cold build did not behave correctly");
    if (zc_build("warm", ZC_ENV("ZCL_CAP_CLOSURE_SOURCE_RECORD=after"), b))
        return 1;
    zc_disp("HIT", "a changed parent lint source receipt prevented a HIT");
    zc_want(strcmp(zc.sha_a, b) == 0,
            "a cache hit produced different bytes than the compile");
    zc_want(zc_file_has(zcw("stderr.cold"), "never_called"),
            "the fixture stopped producing the warning this gate depends on");
    zc_want(zc_file_has(zcw("stderr.warm"), "never_called"),
            "a cache hit did not replay the compiler's warning");
    zc_touch_now(zcw("main.c"));
    if (zc_build("touched", NULL, c))
        return 1;
    zc_disp("HIT", "a touched-but-unchanged source was not a HIT");
    zc_want(strcmp(zc.sha_a, c) == 0, "a content hit produced different bytes");
    return 0;
}

static int header_symlinks(const char *dep)
{
    char s1[ZC_SHA], s2[ZC_SHA];
    if (rename(dep, zcw("dep-one.h")) != 0 ||
        zc_put("dep-two.h", "#define ZCL_GATE_VALUE 102\n") ||
        symlink("dep-one.h", dep) != 0 || zc_build("symlink-one", NULL, s1))
        return 1;
    if (unlink(dep) != 0 || symlink("dep-two.h", dep) != 0 ||
        zc_build("symlink-two", NULL, s2))
        return 1;
    zc_disp("MISS", "retargeted header symlink was served");
    zc_want(strcmp(s1, s2) != 0, "symlink retarget did not change output");
    zc_want(zc_prog_is(zcw("prog"), "102"),
            "symlink retarget kept old behavior");
    if (unlink(dep) != 0)
        return 1;
    return zc_copy(zcw("dep-one.h"), dep, 0);
}

int zc_sec_header(void)
{
    char d[ZC_SHA], sm[ZC_SHA];
    const char *dep = zcw("dep.h");
    if (zc_put("dep.h", "#define ZCL_GATE_VALUE 100\n") ||
        zc_build("header", NULL, d))
        return 1;
    zc_disp("MISS", "a changed header was served from cache");
    zc_want(strcmp(zc.sha_a, d) != 0,
            "a changed header produced the same object bytes");
    zc_want(zc_prog_is(zcw("prog"), "100"),
            "the build after a header edit used stale code");
    if (zc_copy(dep, zcw("header-time"), 1) ||
        zc_put("dep.h", "#define ZCL_GATE_VALUE 101\n") ||
        zc_touch_ref(zcw("header-time"), dep) ||
        zc_build("same-meta", NULL, sm))
        return 1;
    zc_disp("MISS", "same-metadata header edit was served");
    zc_want(strcmp(sm, d) != 0, "same-metadata header edit kept old bytes");
    zc_want(zc_prog_is(zcw("prog"), "101"),
            "same-metadata edit kept old behavior");
    return header_symlinks(dep);
}

int zc_sec_envfilter(void)
{
    const char *eo = zcw("environment.o");
    const char *cv = zcw("compiler-environment");
    const char *const base[] = { zc_zd("environment-cache"),
        "BUILD_SOURCE_RECORD=first", "ZCC_REAL_FLAG=1", NULL };
    const char *const second[] = { base[0], "BUILD_SOURCE_RECORD=second",
        "ZCC_REAL_FLAG=1", NULL };
    const char *const third[] = { base[0], "BUILD_SOURCE_RECORD=third",
        "ZCC_REAL_FLAG=2", NULL };
    const char *const av[] = { zc.zcc, cv, "-c", zcw("environment.c"), "-o",
                               eo, NULL };
    char e1[ZC_SHA], e2[ZC_SHA];
    if (zc_put("compiler-environment",
               "#!/bin/sh\n[ -z \"${BUILD_SOURCE_RECORD+x}\" ] || exit 71\n"
               "exec cc \"-DZCC_ENV_VALUE=${ZCC_REAL_FLAG:-1}\" \"$@\"\n") ||
        chmod(cv, 0755) != 0 ||
        zc_put("environment.c",
               "int environment(void) { return ZCC_ENV_VALUE; }\n"))
        return 1;
    if (zc_x(av, base, NULL) != 0)
        zc_fail("filtered environment cold compile failed");
    zc_disp("MISS", "environment fixture did not start cold");
    int h1 = zc_sha(eo, e1);
    if (zc_x(av, second, NULL) != 0)
        zc_fail("filtered environment warm compile failed");
    zc_disp("HIT", "Make source record changed the cache key");
    if (zc_x(av, third, NULL) != 0)
        zc_fail("real environment changed compile failed");
    zc_disp("MISS", "compiler-visible environment change was served");
    int h2 = zc_sha(eo, e2);
    zc_want(!(h1 && h2) || strcmp(e1, e2) != 0,
            "compiler-visible environment changed no bytes");
    return 0;
}

int zc_sec_compilerversion(void)
{
    const char *cv = zcw("compiler-version");
    const char *const av[] = { zc.zcc, cv, "-c", zcw("version.c"), "-o",
                               zcw("version.o"), NULL };
    if (zc_put("compiler-version", "#!/usr/bin/env bash\n"
               "exec cc -DZCC_COMPILER_VERSION=1 \"$@\"\n") ||
        chmod(cv, 0755) != 0 ||
        zc_put("version.c",
               "int version(void) { return ZCC_COMPILER_VERSION; }\n"))
        return 1;
    if (zc_x(av, NULL, NULL) != 0)
        zc_fail("compiler-change cold fixture failed");
    zc_disp("MISS", "compiler-change fixture did not start cold");
    if (zc_copy(cv, zcw("compiler-time"), 1) ||
        zc_sed_first(cv, zcw("compiler-new"), "VERSION=1", "VERSION=2") ||
        zc_copy(zcw("compiler-new"), cv, 0) ||
        zc_touch_ref(zcw("compiler-time"), cv))
        return 1;
    if (zc_x(av, NULL, NULL) != 0)
        zc_fail("compiler-change fresh fixture failed");
    zc_disp("MISS", "same-metadata compiler edit was served");
    return 0;
}

int zc_sec_truncated(void)
{
    char cold[ZC_SHA], fresh[ZC_SHA];
    const char *const env[] = { zc_zd("truncated-cache"), NULL };
    struct stat sb;
    if (zc_build("poison-cold", env, cold))
        return 1;
    zc_disp("MISS", "poison fixture did not start cold");
    zc_want(stat(zcw("truncated-cache/man"), &sb) != 0 || !S_ISDIR(sb.st_mode),
            "source compile published a probe manifest");
    if (zc_put("dep.h", "#define ZCL_GATE_VALUE 777\n") ||
        zc_build("poison-fresh", env, fresh))
        return 1;
    zc_disp("MISS", "changed header served an old binary");
    zc_want(strcmp(cold, fresh) != 0, "poison fixture missed its header edit");
    zc_want(zc_prog_is(zcw("prog"), "777"),
            "header edit did not reach execution");
    return 0;
}

static const char zc_racing_cc[] =
    "#!/usr/bin/env bash\nset -euo pipefail\nhas_output=0\n"
    "for arg in \"$@\"; do\n"
    "    [ \"$arg\" = -E ] && exec \"$ZCC_RACE_CC\" \"$@\"\n"
    "    [ \"$arg\" = -o ] && has_output=1\ndone\n"
    "\"$ZCC_RACE_CC\" \"$@\"\n"
    "if [ \"$has_output\" = 1 ] && [ \"${ZCC_RACE_REMOVE:-0}\" = 1 ]; then\n"
    "    mv \"$ZCC_RACE_HEADER\" \"$ZCC_RACE_HEADER.hidden\"\nfi\n";

int zc_sec_racing(void)
{
    char cc[ZC_PATH];
    if (!zc_which("cc", cc, sizeof cc))
        return 1;
    const char *dep = zcw("dep.h");
    const char *const first[] = { zc_zd("racing-cache"),
        zcf("ZCC_RACE_CC=%s", cc), zcf("ZCC_RACE_HEADER=%s", dep),
        "ZCC_RACE_REMOVE=1", NULL };
    const char *const again[] = { first[0], first[1], first[2], NULL };
    const char *const av[] = { zc.zcc, zcw("racing-cc"), "-std=c23", "-O1",
        zcf("-I%s", zc.work), zcw("main.c"), "-o", zcw("raceprog"), NULL };
    if (zc_put("racing-cc", zc_racing_cc) || chmod(zcw("racing-cc"), 0755))
        return 1;
    if (zc_x(av, first, zcw("stderr.race-cold")) != 0)
        zc_fail("racing fixture did not compile");
    zc_disp("MISS", "racing fixture did not start cold");
    zc_want(!zc_exists(dep), "racing compiler did not remove the header");
    if (zc_put("dep.h", "#define ZCL_GATE_VALUE 888\n"))
        return 1;
    if (zc_x(av, again, zcw("stderr.race-fresh")) != 0)
        zc_fail("racing fixture did not rebuild");
    zc_disp("MISS", "partial manifest served an old binary");
    zc_want(zc_prog_is(zcw("raceprog"), "888"),
            "partial manifest hid the edited result");
    return zc_put("dep.h", "#define ZCL_GATE_VALUE 100\n");
}

int zc_sec_verified(void)
{
    char v1[ZC_SHA], v2[ZC_SHA];
    const char *const env[] = { "ZCC_VERIFIED=1", NULL };
    if (zc_copy(zcw("dep.h"), zcw("dep.saved"), 1) ||
        zc_put("dep.h", "#define ZCL_GATE_VALUE 200\n") ||
        zc_touch_ref(zcw("dep.saved"), zcw("dep.h")) ||
        zc_build("verified_first", env, v1))
        return 1;
    zc_disp("MISS", "verified compile used the same-account cache");
    zc_want(zc_prog_is(zcw("prog"), "200"),
            "verified compile executed stale cached behavior");
    if (zc_build("verified_second", env, v2))
        return 1;
    zc_disp("MISS", "verified rebuild reused a same-account object");
    zc_want(strcmp(v1, v2) == 0,
            "verified rebuild changed identical output bytes");
    return 0;
}

/* One compile of src with one or two -I flags; stderr goes to errf. */
static int probe_pair(const char *src, const char *out, const char *i1,
                      const char *i2, const char *errf)
{
    if (i2) {
        const char *const two[] = { zc.zcc, "cc", "-std=c23", "-O1", i1, i2,
                                    src, "-o", out, NULL };
        return zc_x(two, NULL, errf);
    }
    const char *const one[] = { zc.zcc, "cc", "-std=c23", "-O1", i1, src,
                                "-o", out, NULL };
    return zc_x(one, NULL, errf);
}

int zc_sec_optional(void)
{
    const char *src = zcw("optional.c"), *out = zcw("optional");
    const char *fl[2] = { zcf("-I%s", zc.work), NULL };
    if (zc_put("optional.c",
               "#if __has_include(\"optional.h\")\n#include \"optional.h\"\n"
               "#else\n#define OPTIONAL_VALUE 1\n#endif\n#include <stdio.h>\n"
               "int main(void) { printf(\"%d\\n\", OPTIONAL_VALUE); "
               "return 0; }\n"))
        return 1;
    if (probe_pair(src, out, fl[0], NULL, zcw("optional.first.err")) != 0)
        zc_fail("optional-header baseline compile failed");
    zc_want(zc_prog_is(out, "1"), "optional-header baseline behavior was wrong");
    if (zc_put("optional.h", "#define OPTIONAL_VALUE 2\n"))
        return 1;
    if (probe_pair(src, out, fl[0], NULL, zcw("optional.second.err")) != 0)
        zc_fail("optional-header changed compile failed");
    zc_disp("MISS", "new __has_include header was served from a stale probe manifest");
    zc_want(zc_prog_is(out, "2"),
            "new __has_include header did not change executed behavior");
    return 0;
}

int zc_sec_search(void)
{
    const char *out = zcw("search");
    const char *fl[2] = { zcf("-I%s", zcw("search-first")),
                          zcf("-I%s", zcw("search-second")) };
    if (csr_mkdirs(zcw("search-first")) || csr_mkdirs(zcw("search-second")) ||
        zc_put("search-second/choice.h", "#define CHOICE_VALUE 1\n") ||
        zc_put("search.c", "#include <choice.h>\n#include <stdio.h>\n"
               "int main(void) { printf(\"%d\\n\", CHOICE_VALUE); "
               "return 0; }\n"))
        return 1;
    if (probe_pair(zcw("search.c"), out, fl[0], fl[1], zcw("search.first.err")))
        zc_fail("include-search baseline compile failed");
    zc_want(zc_prog_is(out, "1"), "include-search baseline behavior was wrong");
    if (zc_put("search-first/choice.h", "#define CHOICE_VALUE 2\n"))
        return 1;
    if (probe_pair(zcw("search.c"), out, fl[0], fl[1], zcw("search.second.err")))
        zc_fail("include-search changed compile failed");
    zc_disp("MISS", "new earlier header was served from a stale probe manifest");
    zc_want(zc_prog_is(out, "2"),
            "new earlier header did not change executed behavior");
    return 0;
}
