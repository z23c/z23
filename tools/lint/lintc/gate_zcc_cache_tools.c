/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check-zcc-cache sections that depend on the toolchain the compiler
 * driver selects: a replaced assembler and frontend with a restored mtime
 * (Linux), the named-library search keying with fake libraries and GNU ld
 * scripts, and later -L flags. The macOS backend block of the shell original
 * is not ported (see the gate file header).
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

static int is_linux(void)
{
    struct utsname un;
    return uname(&un) == 0 && strcmp(un.sysname, "Linux") == 0;
}

static char lt_cc[ZC_PATH];

static int lt_compile(const char *cache, int disable)
{
    const char *env[4] = { zc_zd(cache),
                           zcf("ZCC_LOG=%s", zcw("linux-tool.log")) };
    if (disable)
        env[2] = "ZCC_DISABLE=1";
    const char *const av[] = { zc.zcc, lt_cc, "-std=c23", "-O1",
        zcf("-B%s/linux-tools/", zc.work), "-c", zcw("linux-tool.c"), "-o",
        zcw("linux-tool.o"), NULL };
    return zc_x(av, env, NULL);
}

static int lt_preprocess(const char *outname)
{
    struct zc_cmd c = { .argv = ZC_ARGV(lt_cc, zcf("-B%s/linux-tools/", zc.work),
        "-E", zcw("linux-tool.c")), .outf = zcw("%s", outname),
        .errf = "/dev/null" };
    return zc_run(&c);
}

static int lt_wrap(const char *tool, const char *fmt_body, const char *arg)
{
    const char *p = zcw("linux-tools/%s", tool);
    if (csr_write(p, zcf(fmt_body, arg)) != 0)
        return 1;
    return chmod(p, 0700) != 0;
}

/* Shared tail: mutate-with-restored-mtime misses, cache equals cold output. */
static int lt_mutate(const char *label, const char *tool, const char *cache,
                     int (*rewrite)(void))
{
    const char *log = zcw("linux-tool.log");
    const char *t = zcw("linux-tools/%s", tool);
    if (lt_preprocess("linux-before.i"))
        return 1;
    if (lt_compile(cache, 0))
        return 1;
    zc_disp_in(log, "MISS", zcf("Linux selected %s cold compile was not a MISS", label));
    zc_copy(zcw("linux-tool.o"), zcw("linux-first.o"), 0);
    if (lt_compile(cache, 0))
        return 1;
    zc_disp_in(log, "HIT", zcf("Linux selected %s warm compile was not a HIT", label));
    if (zc_copy(t, zcw("linux-as-before"), 1) || rewrite() ||
        zc_touch_ref(zcw("linux-as-before"), t) || lt_preprocess("linux-after.i"))
        return 1;
    zc_want(zc_same(zcw("linux-before.i"), zcw("linux-after.i")),
            zcf("Linux %s fixture unexpectedly changed preprocessing", label));
    if (lt_compile(cache, 0))
        return 1;
    zc_disp_in(log, "MISS", strcmp(tool, "as") == 0
               ? "mutated Linux assembler with restored mtime was served from cache"
               : "changed Linux frontend bytes were served from cache");
    zc_copy(zcw("linux-tool.o"), zcw("linux-cached.o"), 0);
    if (lt_compile(cache, 1))
        return 1;
    zc_want(zc_same(zcw("linux-cached.o"), zcw("linux-tool.o")),
            zcf("Linux selected %s cache differs from cold output", label));
    zc_want(!zc_same(zcw("linux-first.o"), zcw("linux-tool.o")),
            zcf("Linux %s fixture did not change object bytes", label));
    if (lt_compile(cache, 0))
        return 1;
    zc_disp_in(log, "HIT", zcf("stable Linux selected %s did not return to HIT", label));
    return 0;
}

static char lt_as_real[ZC_PATH], lt_fe_real[ZC_PATH];

static int lt_rewrite_as(void)
{
    return lt_wrap("as", "#!/bin/sh\nexec \"%s\" --defsym ZCC_BACKEND_TEST=2 \"$@\"\n",
                   lt_as_real);
}

static int lt_rewrite_fe(void)
{
    return lt_wrap("cc1", "#!/bin/sh\nexec \"%s\" \"$@\" -fleading-underscore\n",
                   lt_fe_real);
}

static int lt_prog_name(const char *prog, char *out, size_t cap)
{
    struct zc_cmd c = { .argv = ZC_ARGV(lt_cc, zcf("-print-prog-name=%s", prog)),
                        .out = out, .cap = cap };
    int rc = zc_run(&c);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return rc;
}

static int lt_query_failure(void)
{
    if (csr_mkdirs(zcw("query-scratch")) != 0 ||
        zc_put("query-fail-cc",
            "#!/bin/sh\n"
            "case \" $* \" in\n"
            "    *-print-prog-name=cc1*)\n"
            "        attempts=0\n"
            "        while [ \"$attempts\" -lt 200 ] && [ ! -f \"$QUERY_AS_CALLED\" ]; do\n"
            "            sleep 0.005\n"
            "            attempts=$((attempts + 1))\n"
            "        done\n"
            "        [ -f \"$QUERY_AS_CALLED\" ] || exit 91\n"
            "        cc \"$@\" || exit $?\n"
            "        : > \"$QUERY_CC1_DONE\"\n"
            "        ;;\n"
            "    *-print-prog-name=as*)\n"
            "        : > \"$QUERY_AS_CALLED\"\n"
            "        exit 42\n"
            "        ;;\n"
            "    *)\n"
            "        exec cc \"$@\"\n"
            "        ;;\n"
            "esac\n") != 0 || chmod(zcw("query-fail-cc"), 0700) != 0)
        return 1;
    const char *const env[] = { zc_zd("query-failure-cache"),
        zcf("ZCC_LOG=%s", zcw("query-failure.log")),
        zcf("TMPDIR=%s", zcw("query-scratch")),
        zcf("QUERY_AS_CALLED=%s", zcw("query-as-called")),
        zcf("QUERY_CC1_DONE=%s", zcw("query-cc1-done")), NULL };
    struct zc_cmd c = { .argv = ZC_ARGV(zc.zcc, zcw("query-fail-cc"),
        "-std=c23", "-O0", "-c", zcw("main.c"), "-o", zcw("query-fail.o")),
        .env = env, .errf = "/dev/null" };
    if (zc_run(&c) != 0)
        return 1;
    zc_want(zc_exists(zcw("query-as-called")),
            "Linux tool query failure skipped the assembler query");
    zc_want(zc_exists(zcw("query-cc1-done")),
            "Linux frontend query did not observe the assembler query or complete");
    zc_want(zc_line_with_prefix(zcw("query-failure.log"), "UNKEY"),
            "Linux failed tool query did not fall back to an uncached compile");
    DIR *dir = opendir(zcw("query-scratch"));
    zc_want(dir != NULL, "Linux tool query scratch directory is missing");
    if (!dir)
        return 1;
    bool leftover = false;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
        leftover |= strncmp(entry->d_name, "zcc-tool.", 9) == 0;
    closedir(dir);
    zc_want(!leftover, "Linux tool query failure left scratch files");
    return 0;
}

static int lt_preprocess_overlap(void)
{
    if (zc_put("preprocess-overlap-cc",
            "#!/bin/sh\n"
            "case \" $* \" in\n"
            "    *-print-prog-name=cc1*)\n"
            "        : > \"$OVERLAP_CC1\"\n"
            "        attempts=0\n"
            "        while [ \"$attempts\" -lt 200 ] && [ ! -f \"$OVERLAP_PP\" ]; do\n"
            "            sleep 0.005\n"
            "            attempts=$((attempts + 1))\n"
            "        done\n"
            "        [ -f \"$OVERLAP_PP\" ] || exit 91\n"
            "        exec cc \"$@\"\n"
            "        ;;\n"
            "    *-print-prog-name=as*) exec cc \"$@\" ;;\n"
            "    *-E*)\n"
            "        : > \"$OVERLAP_PP\"\n"
            "        attempts=0\n"
            "        while [ \"$attempts\" -lt 200 ] && [ ! -f \"$OVERLAP_CC1\" ]; do\n"
            "            sleep 0.005\n"
            "            attempts=$((attempts + 1))\n"
            "        done\n"
            "        [ -f \"$OVERLAP_CC1\" ] || exit 92\n"
            "        exec cc \"$@\"\n"
            "        ;;\n"
            "    *) exec cc \"$@\" ;;\n"
            "esac\n") != 0 || chmod(zcw("preprocess-overlap-cc"), 0700) != 0)
        return 1;
    const char *const env[] = { zc_zd("preprocess-overlap-cache"),
        zcf("ZCC_LOG=%s", zcw("preprocess-overlap.log")),
        zcf("OVERLAP_CC1=%s", zcw("overlap-cc1")),
        zcf("OVERLAP_PP=%s", zcw("overlap-pp")), NULL };
    struct zc_cmd c = { .argv = ZC_ARGV(zc.zcc, zcw("preprocess-overlap-cc"),
        "-std=c23", "-O0", "-c", zcw("main.c"), "-o", zcw("overlap.o")),
        .env = env, .errf = "/dev/null" };
    if (zc_run(&c) != 0)
        return 1;
    zc_disp_in(zcw("preprocess-overlap.log"), "MISS",
               "Linux overlapped preprocessing was not a cold MISS");
    if (zc_run(&c) != 0)
        return 1;
    zc_disp_in(zcw("preprocess-overlap.log"), "HIT",
               "Linux overlapped preprocessing was not a warm HIT");
    zc_want(zc_exists(zcw("overlap-cc1")) && zc_exists(zcw("overlap-pp")),
            "Linux preprocessing did not overlap toolchain hashing");
    return 0;
}

static int lt_scratch_record(const char *cwd, const char *marker, char out[ZC_OUT])
{
    struct zc_cmd c = {
        .cwd = cwd, .argv = ZC_ARGV(zc.zcc, "--zcc-compiler-scratch"),
        .env = ZC_ENV("DEVBUILD_ACTIVE=z23", zcf("TMPDIR=%s", zc.work),
                      zcf("DEVBUILD_Z23_JOB_TMPDIR=%s", marker)),
        .out = out, .cap = ZC_OUT
    };
    return zc_run(&c);
}

static int lt_compiler_scratch(void)
{
    const char *dir = zcw("scratch-case");
    const char *scratch = zcw("scratch-case/build/zcc-compiler-tmp");
    char out[ZC_OUT], first[ZC_OUT];
    if (mkdir(dir, 0700) || lt_scratch_record(dir, "", out) || out[0] ||
        zc_exists(scratch))
        return 1;
    static const char allowed[] =
        "/.-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int rc = lt_scratch_record(dir, zc.work, first);
    if (scratch[strspn(scratch, allowed)] != 0)
        return rc == 0 || first[0] != 0;
    if (rc != 0)
        return 1;
    size_t n = strlen(scratch);
    if (strncmp(first, scratch, n) || first[n] != ' ' ||
        strspn(first + n + 1, "0123456789abcdef") != 64 ||
        strcmp(first + n + 65, "\n") ||
        lt_scratch_record(dir, zc.work, out) || strcmp(first, out))
        return 1;
    return 0;
}

static int lt_scratch_refusals(void)
{
    const char *dir = zcw("scratch-case");
    const char *scratch = zcw("scratch-case/build/zcc-compiler-tmp");
    char out[ZC_OUT];
    if (chmod(scratch, 0755) || lt_scratch_record(dir, zc.work, out) == 0 || out[0])
        return 1;
    if (rmdir(scratch) || symlink(dir, scratch) ||
        lt_scratch_record(dir, zc.work, out) == 0 || out[0])
        return 1;
    const char *unsafe = zcw("scratch-case/newline\ncomponent");
    if (mkdir(unsafe, 0700) || lt_scratch_record(unsafe, zc.work, out) == 0 || out[0])
        return 1;
    return 0;
}

int zc_sec_linux(void)
{
    char as[ZC_PATH];
    if (!is_linux())
        return 0;
    zc_want(lt_compiler_scratch() == 0, "private compiler scratch selection failed");
    zc_want(lt_scratch_refusals() == 0, "unsafe compiler scratch was accepted");
    if (!zc_which("gcc-14", lt_cc, sizeof lt_cc) &&
        !zc_which("gcc", lt_cc, sizeof lt_cc))
        return 1;
    if (lt_prog_name("as", as, sizeof as) || !zc_which(as, lt_as_real, sizeof lt_as_real) ||
        csr_mkdirs(zcw("linux-tools")) ||
        zc_put("linux-tool.c", "int zcc_selected_tool(void) { return 7; }\n") ||
        lt_wrap("as", "#!/bin/sh\nexec \"%s\" --defsym ZCC_BACKEND_TEST=1 \"$@\"\n",
                lt_as_real))
        return 1;
    if (lt_mutate("assembler", "as", "linux-tool-cache", lt_rewrite_as))
        return 1;
    if (lt_prog_name("cc1", lt_fe_real, sizeof lt_fe_real))
        return 1;
    zc_want(access(lt_fe_real, X_OK) == 0, "Linux selected frontend is unavailable");
    if (lt_wrap("cc1", "#!/bin/sh\nexec \"%s\" \"$@\" -fno-leading-underscore\n",
                lt_fe_real))
        return 1;
    char sel[ZC_PATH];
    struct zc_cmd c = { .argv = ZC_ARGV(lt_cc, zcf("-B%s/linux-tools/", zc.work),
        "-print-prog-name=cc1"), .out = sel, .cap = sizeof sel };
    zc_run(&c);
    sel[strcspn(sel, "\n")] = '\0';
    zc_want(strcmp(sel, zcw("linux-tools/cc1")) == 0,
            "Linux driver did not select fixture frontend");
    if (lt_mutate("frontend", "cc1", "linux-frontend-cache", lt_rewrite_fe))
        return 1;
    if (lt_query_failure())
        return 1;
    return lt_preprocess_overlap();
}

/* ---- named libraries ---- */

static int nl_cc(const char *dir, const char *cc, const char *src,
                 const char *lib, const char *out, const char *cache,
                 const char *extra)
{
    const char *const env[] = { zcf("PWD=%s", dir), zcf("ZCC_DIR=%s", cache), NULL };
    const char *const av[] = { zc.zcc, cc, "-std=c23", "-O1",
        zcf("-ffile-prefix-map=%s=/zcl", dir), src, lib, "-o", out, extra, NULL };
    struct zc_cmd c = { .cwd = dir, .argv = av, .env = env, .errf = "/dev/null" };
    return zc_run(&c);
}

static void nl_is(const char *want, const char *why)
{
    zc_disp(want, zcf("named library: %s (wanted %s)", why, want));
}

static int nl_default_search(const char *cold, const char *warm, const char *error)
{
    const char *def = zcw("cache"), *a = zcw("nl.a"), *b = zcw("nl.b");
    char out[ZC_LINE];
    if (nl_cc(a, "cc", "named.c", "-lm", zcw("named.a"), def, NULL) != 0)
        zc_fail("named library: compile failed");
    nl_is(cold, "unexpected default-search disposition");
    zc_want(zc_prog_out(zcw("named.a"), out, sizeof out) == 7 && strcmp(out, "9") == 0,
            "named library: program behavior changed");
    if (nl_cc(b, "cc", "named.c", "-lm", zcw("named.b"), def, NULL) != 0)
        zc_fail("named library: second compile failed");
    nl_is(warm, "unexpected repeated default-search disposition");
    zc_want(zc_prog_out(zcw("named.b"), out, sizeof out) == 7 && strcmp(out, "9") == 0,
            "named library: repeated program behavior changed");
    if (strcmp(warm, "HIT") == 0)
        zc_want(zc_same(zcw("named.a"), zcw("named.b")),
                "named library: the hit is not byte-identical");
    if (nl_cc(a, "cc", "named.c", "-lm", zcw("n.lto.a"), def, "-flto=auto") ||
        nl_cc(b, "cc", "named.c", "-lm", zcw("n.lto.b"), def, "-flto=auto"))
        return 1;
    nl_is(cold, "unexpected -flto default-search disposition");
    if (zc_put("named-error.c", "#error ZCC_NAMED_LIBRARY_DIAGNOSTIC\n"))
        return 1;
    const char *src = zcw("named-error.c"), *bin = zcw("named-error");
    struct zc_cmd d = { .argv = ZC_ARGV("cc", "-std=c23", src, "-lm", "-o", bin),
        .outf = zcw("named-direct.out"), .merge = 1 };
    zc_want(zc_run(&d) != 0, "named library: error fixture compiled");
    const char *const env[] = { zc_zd("cache-unkey"), NULL };
    struct zc_cmd e = { .argv = ZC_ARGV(zc.zcc, "cc", "-std=c23", src, "-lm", "-o", bin),
        .env = env, .outf = zcw("named-cached.out"), .merge = 1 };
    zc_want(zc_run(&e) != 0, "named library: error status lost");
    zc_want(zc_same(zcw("named-direct.out"), zcw("named-cached.out")),
            "named library: compiler diagnostics changed");
    nl_is(error, "a compile error was not left to the compiler");
    return 0;
}

static int nl_fake(int value)
{
    const char *o = zcw("nlf.o"), *lib = zcw("nlfake/libzv.a");
    if (zc_put("nlf.c", zcf("int zv(void){return %d;}\n", value)))
        return 1;
    if (zc_x(ZC_ARGV("cc", "-c", zcw("nlf.c"), "-o", o), NULL, NULL) != 0)
        return 1;
    unlink(lib);
    return zc_x(ZC_ARGV("ar", "rcs", lib, o), NULL, NULL) != 0;
}

static int nl_fb(const char *lib, const char *cache)
{
    return nl_cc(zcw("nl.a"), zcw("nlcc"), "fake.c", lib, zcw("fake.out"), cache, NULL);
}

static int nl_linux_fake(void)
{
    const char *nlf = zcw("nlfake"), *cache = zcw("cache"), *unkey = zcw("cache-unkey");
    if (zc_put("nlcc", zcf("#!/usr/bin/env bash\ncase \" $* \" in *\" -print-search-dirs \"*) "
                           "printf 'programs: =/x/\\nlibraries: =%s\\n'; exit 0 ;; esac\n"
                           "exec cc \"$@\" -L\"%s\"\n", nlf, nlf)) ||
        chmod(zcw("nlcc"), 0755) != 0 || zc_put("nl.a/fake.c", "int main(void){return 0;}\n"))
        return 1;
    if (nl_fake(5) == 0 && nl_fb("-lzv", cache) == 0)
        nl_is("MISS", "fake library first build");
    if (nl_fb("-lzv", cache))
        return 1;
    nl_is("HIT", "unchanged fake library");
    if (nl_fake(6) == 0 && nl_fb("-lzv", cache))
        return 1;
    nl_is("MISS", "changed library bytes were served");
    if (zc_put("nlfake/libzs.so", zcf("/* GNU ld script */\nGROUP ( %s/libzv.a )\n", nlf)) ||
        nl_fb("-lzs", cache) || nl_fb("-lzs", cache))
        return 1;
    nl_is("HIT", "unchanged linker script");
    if (nl_fake(7) == 0 && nl_fb("-lzs", cache))
        return 1;
    nl_is("MISS", "a changed script target was served");
    if (zc_put("nlfake/libzg.so", zcf("/* GNU ld script */\nGROUP ( %s/missing.a )\n", nlf)))
        return 1;
    nl_fb("-lzg", unkey);
    nl_is("UNKEY", "a script naming a missing file was keyed");
    return 0;
}

int zc_sec_named(void)
{
    int lin = is_linux();
    if (zc_put("named.c", "#include <math.h>\n#include <stdio.h>\nint main(void)"
               "{volatile double v=81.0;printf(\"%.0f\\n\",sqrt(v));return 7;}\n") ||
        csr_mkdirs(zcw("nlfake")) || csr_mkdirs(zcw("nl.a")) || csr_mkdirs(zcw("nl.b")) ||
        zc_copy(zcw("named.c"), zcw("nl.a/named.c"), 0) ||
        zc_copy(zcw("named.c"), zcw("nl.b/named.c"), 0))
        return 1;
    if (nl_default_search(lin ? "MISS" : "BYPASS", lin ? "HIT" : "BYPASS",
                          lin ? "UNKEY" : "BYPASS"))
        return 1;
    return lin ? nl_linux_fake() : 0;
}

int zc_sec_archive(void)
{
    static const char *const style[2] = { "separated", "joined" };
    static const char *const want[2] = { "MISS", "HIT" };
    const char *lib = zcw("named-lib.o"), *a = zcw("libzccnamed.a");
    if (zc_put("named-lib.c", "int named_value(void) { return 23; }\n") ||
        zc_put("named-main.c", "#include <stdio.h>\nint named_value(void);\n"
               "int main(void) { printf(\"%d\\n\", named_value()); return 0; }\n"))
        return 1;
    if (zc_x(ZC_ARGV("cc", "-std=c23", "-c", zcw("named-lib.c"), "-o", lib), NULL, NULL))
        zc_fail("named archive fixture compile failed");
    unlink(a);
    if (zc_x(ZC_ARGV("ar", "rcs", a, lib), NULL, NULL))
        zc_fail("named archive fixture creation failed");
    for (int s = 0; s < 2; s++) {
        for (int w = 0; w < 2; w++) {
            const char *const sep[] = { zc.zcc, "cc", "-std=c23", "-O1", zcw("named-main.c"),
                "-lzccnamed", "-L", zc.work, "-o", zcw("named-archive"), NULL };
            const char *const joined[] = { zc.zcc, "cc", "-std=c23", "-O1", zcw("named-main.c"),
                "-lzccnamed", zcf("-L%s", zc.work), "-o", zcw("named-archive"), NULL };
            if (zc_x(s ? joined : sep, NULL, zcw("named-archive.err")) != 0)
                zc_fail(zcf("later %s -L compile failed", style[s]));
            zc_disp(want[w], zcf("later %s -L did not retain %s", style[s], want[w]));
            zc_want(zc_prog_is(zcw("named-archive"), "23"),
                    zcf("later %s -L produced wrong behavior", style[s]));
        }
    }
    return 0;
}
