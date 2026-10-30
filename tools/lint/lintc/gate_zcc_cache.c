/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check_zcc_cache - the in-tree compile cache serves correct
 * bytes (hits identical, warnings replayed, header/compiler/library edits
 * missed, poisoned or missing artifacts repaired, singleflight and bootstrap
 * identity). Ported from tools/lint/check_zcc_cache.sh; the sections live in
 * gate_zcc_cache_{core,stage,tools,flight,boot}.c over gate_zcc_cache_util.c.
 * The macOS backend-selection block of the original is not ported: it only
 * ran on Darwin and needs a Mac to prove. Selftest: gate_zcc_cache_selftest.c.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

static int (*const zc_sections[])(void) = {
    zc_sec_basic, zc_sec_header, zc_sec_linux, zc_sec_apple, zc_sec_envfilter,
    zc_sec_compilerversion, zc_sec_truncated, zc_sec_racing, zc_sec_verified,
    zc_sec_optional, zc_sec_search, zc_sec_named, zc_sec_archive,
    zc_sec_explicit, zc_sec_stage, zc_sec_artifacts, zc_sec_rsp, zc_sec_epoch,
    zc_sec_unkey, zc_sec_envkey, zc_sec_flight, zc_sec_boot,
};

static int zc_find_zcc(void)
{
    char out[ZC_PATH];
    struct zc_cmd c = { .argv = ZC_ARGV(zcf("%s/tools/dev/zcc_bootstrap.sh", zc.root)),
                        .out = out, .cap = sizeof out };
    int rc = zc_run(&c);
    size_t n = strlen(out);
    while (n && out[n - 1] == '\n')
        out[--n] = '\0';
    if (rc != 0 || !out[0] || access(out, X_OK) != 0) {
        fputs("check_zcc_cache: FAIL — could not build tools/zcc.c\n", stderr);
        return 1;
    }
    zc_str(zc.zcc, sizeof zc.zcc, out);
    return 0;
}

static int zc_setup(void)
{
    if (zc_mkwork("zcl-zcc-gate.XXXXXX")) {
        fputs("check_zcc_cache: FAIL — mktemp failed\n", stderr);
        return 1;
    }
    if (ovf(snprintf(zc.log, sizeof zc.log, "%s/zcc.log", zc.work), sizeof zc.log))
        return 2;
    setenv("ZCC_DIR", zcw("cache"), 1);
    setenv("ZCC_LOG", zc.log, 1);
    return zc_put("dep.h", "#define ZCL_GATE_VALUE 42\n") ||
           zc_put("main.c", "#include <stdio.h>\n#include \"dep.h\"\n"
                  "/* deliberately unused: this gate asserts the warning is replayed on a hit */\n"
                  "static int never_called(void) { return 1; }\n"
                  "int main(void)\n{\n    printf(\"%d\\n\", ZCL_GATE_VALUE);\n    return 0;\n}\n");
}

static int zc_sections_run(void)
{
    for (size_t i = 0; i < sizeof zc_sections / sizeof zc_sections[0]; i++) {
        int rc = zc_sections[i]();
        if (rc || zc.overflow)
            return rc ? rc : 2;
    }
    return 0;
}

int check_zcc_cache_run(int argc, char **argv)
{
    struct utsname un;
    (void)argc;
    (void)argv;
    unsetenv("ZCC_VERIFIED");
    if (uname(&un) == 0 && strncmp(un.sysname, "MINGW", 5) == 0) {
        puts("check_zcc_cache: SKIP — POSIX compile-cache process backend is unavailable on native Windows");
        return 0;
    }
    memset(&zc, 0, sizeof zc);
    if (!getcwd(zc.root, sizeof zc.root))
        return 1;
    if (zc_find_zcc())
        return 1;
    int rc = zc_setup();
    if (rc == 0)
        rc = zc_sections_run();
    if (zc.work[0])
        rap_rm_rf(zc.work);
    if (rc)
        return rc;
    if (zc.failures) {
        fprintf(stderr, "check_zcc_cache: %d failure(s); the compile cache is NOT trustworthy\n",
                zc.failures);
        fputs("  clear it now: make cc-cache-clear\n", stderr);
        return 1;
    }
    puts("check_zcc_cache: OK — hits are byte-identical; concurrent requests share compilation, audits remain independent, failed owners recover, changed inputs stay fresh; bootstrap bytes reproduce and retain source/flag sensitivity");
    return 0;
}
