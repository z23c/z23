/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check-zcc-cache sections for the node's compile shape: explicit
 * -x bypass, staged -o/-MF/-MT paths, corrupted and missing cache artifacts,
 * response-file links, epoch -MT keys, the unkeyable counter, and raw
 * PWD/TMPDIR keying.
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

int zc_sec_explicit(void)
{
    const char *src = zcw("explicit.txt"), *out = zcw("explicit");
    const char *const av[] = { zc.zcc, "cc", "-std=c23", "-x", "c",
        zcf("-I%s", zc.work), src, "-o", out, NULL };
    if (zc_put("explicit.txt",
               "#if __has_include(\"explicit.h\")\n#include \"explicit.h\"\n"
               "#else\n#define EXPLICIT_VALUE 1\n#endif\n#include <stdio.h>\n"
               "int main(void) { printf(\"%d\\n\", EXPLICIT_VALUE); "
               "return 0; }\n"))
        return 1;
    if (zc_x(av, NULL, zcw("explicit.first.err")) != 0)
        zc_fail("explicit-language baseline compile failed");
    zc_disp("BYPASS", "explicit language mode entered an incomplete content cache");
    zc_want(zc_prog_is(out, "1"), "explicit-language baseline behavior was wrong");
    if (zc_put("explicit.h", "#define EXPLICIT_VALUE 2\n"))
        return 1;
    if (zc_x(av, NULL, zcw("explicit.second.err")) != 0)
        zc_fail("explicit-language changed compile failed");
    zc_disp("BYPASS", "explicit language mode reused an incomplete content key");
    zc_want(zc_prog_is(out, "2"),
            "explicit-language edit did not change executed behavior");
    return 0;
}

int zc_sec_stage(void)
{
    char s1[ZC_SHA], s2[ZC_SHA];
    if (csr_mkdirs(zcw("final")))
        return 1;
    if (zc_stage_build("one", NULL, s1))
        zc_fail("staged compile failed");
    zc_disp("MISS", "the first staged compile was not a MISS");
    zc_want(zc_nonempty(zcw("stage.one/main.d")), "the compiler wrote no depfile");
    if (zc_stage_build("two", NULL, s2))
        zc_fail("second staged compile failed");
    zc_disp("HIT", "a staged rebuild missed: the random -o/-MF paths are in the key");
    zc_want(strcmp(s1, s2) == 0, "a staged cache hit produced different object bytes");
    zc_want(zc_nonempty(zcw("stage.two/main.d")),
            "a cache hit did not restore the depfile");
    zc_want(lct_file_has(zcw("stage.two/main.d"), "main.o"),
            "the restored depfile does not name its target");
    return 0;
}

/* Poison one artifact kind in an isolated cache, then delete it. */
static int artifact_kind(const char *sf)
{
    int meta = strcmp(sf, "meta") == 0;
    char clean[ZC_SHA], fresh[ZC_SHA], art[ZC_PATH], dot[16];
    const char *dir = zcw("poison-%s", sf);
    const char *const e2[] = { zcf("ZCC_DIR=%s", dir), NULL };
    zc_str(dot, sizeof dot, zcf(".%s", sf));
    if (zc_stage_build(zcf("poison-%s-cold", sf), e2, clean))
        zc_fail(zcf("%s poison fixture did not compile", sf));
    art[0] = '\0';
    if (!zc_find_suffix(zcf("%s/obj", dir), dot, art, sizeof art)) {
        zc_fail(zcf("%s poison fixture wrote no artifact", sf));
        return 0;
    }
    if (csr_write(art, "poison\n"))
        return 1;
    int start = zc_lines(zc.log);
    if (zc_stage_build(zcf("poison-%s-fresh", sf), e2, fresh))
        zc_fail(zcf("%s poison fixture did not rebuild", sf));
    zc_disp("MISS", zcf("corrupted %s was served as a HIT", sf));
    zc_want(strcmp(clean, fresh) == 0,
            zcf("%s poison repair changed the clean object bytes", sf));
    zc_want(zc_lookup_after(zc.log, start,
                            meta ? "meta-invalid" : zcf("%s-integrity", sf)),
            zcf("%s poison repair did not name its exact-key lookup failure", sf));
    if (zc_stage_build(zcf("poison-%s-warm", sf), e2, fresh))
        zc_fail(zcf("%s poison repair could not be reused", sf));
    zc_disp("HIT", zcf("%s poison repair did not restore cache reuse", sf));
    if (unlink(art) != 0)
        return 1;
    start = zc_lines(zc.log);
    if (zc_stage_build(zcf("missing-%s-fresh", sf), e2, fresh))
        zc_fail(zcf("%s missing artifact did not rebuild", sf));
    zc_disp("MISS", zcf("missing %s was served as a HIT", sf));
    zc_want(zc_lookup_after(zc.log, start,
                            meta ? "meta-missing" : zcf("%s-unavailable", sf)),
            zcf("%s missing artifact did not name its exact-key lookup failure", sf));
    return 0;
}

int zc_sec_artifacts(void)
{
    static const char *const kinds[] = { "bin", "dep", "err", "meta" };
    for (size_t i = 0; i < 4; i++)
        if (artifact_kind(kinds[i]))
            return 1;
    return 0;
}

static void rsp_obj(const char *src, const char *obj, const char *failmsg)
{
    const char *const av[] = { zc.zcc, "cc", "-std=c23", "-O1", "-c",
        zcw("%s", src), "-o", zcw("%s", obj), NULL };
    if (zc_x(av, NULL, "/dev/null") != 0)
        zc_fail(failmsg);
}

int zc_sec_rsp(void)
{
    const char *rsp = zcw("link.rsp"), *prog = zcw("rspprog");
    const char *const link[] = { zc.zcc, "cc", "-std=c23", "-O1",
        zcf("@%s", rsp), "-o", prog, NULL };
    if (zc_put("rsplib.c", "int rsp_value(void) { return 1; }\n") ||
        zc_put("rspmain.c", "#include <stdio.h>\nint rsp_value(void);\n"
               "int main(void) { printf(\"%d\\n\", rsp_value()); return 0; }\n"))
        return 1;
    rsp_obj("rsplib.c", "rsplib.o", "the response-file fixture library did not compile");
    rsp_obj("rspmain.c", "rspmain.o", "the response-file fixture main did not compile");
    if (zc_put("link.rsp", zcf("%s %s\n", zcw("rsplib.o"), zcw("rspmain.o"))))
        return 1;
    if (zc_x(link, NULL, "/dev/null") != 0)
        zc_fail("the response-file link failed");
    zc_disp("MISS", "the first response-file link was not a MISS");
    zc_want(zc_prog_is(prog, "1"), "the response-file link produced the wrong program");
    if (zc_put("rsplib.c", "int rsp_value(void) { return 2; }\n"))
        return 1;
    rsp_obj("rsplib.c", "rsplib.o", "the edited response-file fixture library did not compile");
    if (zc_x(link, NULL, "/dev/null") != 0)
        zc_fail("the relink after an object edit failed");
    zc_disp("MISS", "a link whose objects changed was served from cache");
    zc_want(zc_prog_is(prog, "2"),
            "the relinked program still runs the object bytes it was built from before");
    FILE *f = fopen(zcw("nul.rsp"), "wb");
    if (!f)
        return 1;
    fprintf(f, "%s%c%s\n", zcw("rsplib.o"), '\0', zcw("rspmain.o"));
    fclose(f);
    struct zc_cmd c = { .argv = ZC_ARGV(zc.zcc, "cc", "-std=c23", "-O1",
        zcf("@%s", zcw("nul.rsp")), "-o", zcw("nulprog")),
        .outf = zcw("nul.stdout"), .errf = zcw("nul.stderr") };
    zc_run(&c);
    zc_disp("BYPASS", "NUL response-file token entered the cache");
    return 0;
}

static int epoch_build(const char *tag, char sha[ZC_SHA])
{
    const char *dir = zcw("epoch.%s", tag);
    const char *mt = zcw("epochs/%s/main.o", tag);
    const char *obj = zcf("%s/main.o", dir);
    if (csr_mkdirs(dir) || csr_mkdirs(zcw("epochs/%s", tag)))
        return 1;
    const char *const av[] = { zc.zcc, "cc", "-std=c23", "-O1", "-Wall",
        "-DZCL_GATE_EPOCH_MT=1", zcf("-I%s", zc.work), "-MD", "-MP", "-MF",
        zcf("%s/main.d", dir), "-MT", mt, "-c", zcw("main.c"), "-o", obj, NULL };
    if (zc_x(av, NULL, "/dev/null") != 0)
        return 1;
    return zc_sha(obj, sha) ? 0 : 1;
}

int zc_sec_epoch(void)
{
    char e1[ZC_SHA], e2[ZC_SHA];
    const char *d = zcw("epoch.bbbb/main.d");
    if (epoch_build("aaaa", e1))
        zc_fail("epoch-a compile failed");
    zc_disp("MISS", "the first epoch-shaped -MT compile was not a MISS");
    if (epoch_build("bbbb", e2))
        zc_fail("epoch-b compile failed");
    zc_disp("HIT", "a rebuild whose only change was the -MT epoch path missed the cache");
    zc_want(strcmp(e1, e2) == 0, "an epoch-path cache hit produced different object bytes");
    zc_want(zc_nonempty(d), "the epoch-path hit did not restore a depfile");
    zc_want(lct_file_has(d, "epochs/bbbb/main.o"),
            "the restored depfile does not name the current -MT target");
    zc_want(!lct_file_has(d, "epochs/aaaa/main.o"),
            "the restored depfile still names the previous epoch's -MT target");
    return 0;
}

int zc_sec_unkey(void)
{
    char out[ZC_OUT], vals[ZC_LINE] = "";
    struct zc_cmd c = { .argv = ZC_ARGV(zc.zcc, "--zcc-stats"), .out = out,
                        .cap = sizeof out };
    zc_run(&c);
    for (char *save, *ln = strtok_r(out, "\n", &save); ln;
         ln = strtok_r(NULL, "\n", &save)) {
        if (!strstr(ln, "unkeyable"))
            continue;
        char *s2 = ln + strspn(ln, " \t");
        s2 += strcspn(s2, " \t");
        s2 += strspn(s2, " \t");
        size_t n = strcspn(s2, " \t");
        zc_append(vals, sizeof vals, "\n", s2, n);
    }
    zc_want(vals[0] == '\0' || strcmp(vals, "0") == 0,
            zcf("%s compile(s) could not be keyed at all", vals));
    return 0;
}

/* (cd dir && PWD=dir TMPDIR=tmp ... zcc cc -std=c23 -O1 [-g] ...) 2>/dev/null */
static int env_cc(const char *dir, const char *tmp, int full, const char *const *flags)
{
    const char *env[5] = { zcf("PWD=%s", dir), zcf("TMPDIR=%s", tmp) };
    if (full) {
        env[2] = zcf("TMP=%s", tmp);
        env[3] = zcf("TEMP=%s", tmp);
    }
    const char *av[16] = { zc.zcc, "cc", "-std=c23", "-O1" };
    size_t n = 4;
    for (size_t i = 0; flags[i] && n < 15; i++)
        av[n++] = flags[i];
    struct zc_cmd c = { .cwd = dir, .argv = av, .env = env, .errf = "/dev/null" };
    return zc_run(&c);
}

static void env_pair_ab(void)
{
    const char *ta = zcw("envtmp.a");
    for (int i = 0; i < 2; i++) {
        const char *d = zcw("envdir.%c", i ? 'b' : 'a');
        const char *const fl[] = { "-g", "-c", "nomap.c", "-o",
            zcw("nomap.%c.o", i ? 'b' : 'a'), NULL };
        if (env_cc(d, ta, 0, fl) != 0)
            zc_fail(zcf("env key (b): compile %c failed", i ? 'b' : 'a'));
    }
    zc_disp("MISS", "env key (b): two unmapped cwds shared a key though comp_dir differs");
}

static void env_tmp_pairs(void)
{
    const char *da = zcw("envdir.a");
    for (int i = 0; i < 2; i++) {
        const char t = i ? 'b' : 'a';
        const char *const fl[] = { "-save-temps=cwd", "-c", "st.c",
            "-o", zcw("st.%c.o", t), NULL };
        if (env_cc(da, zcw("envtmp.%c", t), 0, fl) != 0)
            zc_fail(zcf("env key (c): compile %c failed", t));
    }
    zc_disp_not_in(zc.log, "HIT", "env key (c): -save-temps ignored a different TMPDIR");
    for (int i = 0; i < 2; i++) {
        const char t = i ? 'b' : 'a';
        const char *const fl[] = { "-frandom-seed=seed.c", "-c", "seed.c",
            "-o", zcw("seed.%c.o", t), NULL };
        if (env_cc(da, zcw("envtmp.%c", t), 0, fl) != 0)
            zc_fail(zcf("env key (d): compile %c failed", t));
    }
    zc_disp("HIT", "env key (d): -frandom-seed re-keyed on TMPDIR");
    zc_want(zc_same(zcw("seed.a.o"), zcw("seed.b.o")), "env key (d): bytes differ");
}

int zc_sec_envkey(void)
{
    static const char *const src = "int zcl_envkey_probe(void) { return 7; }\n";
    static const char *const files[] = { "envdir.a/env.c", "envdir.b/env.c",
        "envdir.a/nomap.c", "envdir.b/nomap.c", "envdir.a/st.c",
        "envdir.a/seed.c" };
    static const char *const bodies[] = { src, src,
        "int zcl_envkey_nomap(void) { return 8; }\n",
        "int zcl_envkey_nomap(void) { return 8; }\n",
        "int zcl_envkey_st(void) { return 9; }\n",
        "int zcl_envkey_seed(void) { return 10; }\n" };
    if (csr_mkdirs(zcw("envtmp.a")) || csr_mkdirs(zcw("envtmp.b")))
        return 1;
    for (size_t i = 0; i < 6; i++)
        if (zc_put(files[i], bodies[i]))
            return 1;
    const char *a = zcw("envdir.a"), *b = zcw("envdir.b");
    const char *const fa[] = { "-g", "-c", "env.c", "-o", zcw("env.a.o"),
        zcf("-ffile-prefix-map=%s=/zcl", a), NULL };
    const char *const fb[] = { "-g", "-c", "env.c", "-o", zcw("env.b.o"),
        zcf("-ffile-prefix-map=%s=/zcl", b), NULL };
    if (env_cc(a, zcw("envtmp.a"), 1, fa) != 0)
        zc_fail("env key (a): compile failed");
    zc_disp("MISS", "env key (a): first compile was not a MISS");
    if (env_cc(b, zcw("envtmp.b"), 1, fb) != 0)
        zc_fail("env key (a): second compile failed");
    zc_disp("HIT", "env key (a): a different PWD/TMPDIR with a mapped cwd missed");
    zc_want(zc_same(zcw("env.a.o"), zcw("env.b.o")),
            "env key (a): the hit is not byte-identical to the fresh compile");
    env_pair_ab();
    env_tmp_pairs();
    for (int i = 0; i < 2; i++) {
        const char *d = i ? b : a;
        const char *const fl[] = { "-g", "-c", "env.c", "-o",
            zcw("lto.%c.o", i ? 'b' : 'a'), "-flto=auto",
            zcf("-ffile-prefix-map=%s=/zcl", d), NULL };
        if (env_cc(d, zcw("envtmp.a"), 1, fl) != 0)
            zc_fail("env key (e): compile");
    }
    zc_disp("MISS", "env key (e): -flto object crossed directories");
    return 0;
}
