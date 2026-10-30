/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of the check-zcc-cache helpers that need no compiler:
 * child capture and exit/signal codes, env set/unset in the child, log line
 * counting and LOOKUP matching, first-occurrence sed, recursive artifact
 * find and byte compare.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc_text.h"
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

static int zs_fail(const char *what)
{
    fprintf(stderr, "check_zcc_cache: selftest FAIL: %s\n", what);
    return 1;
}

static int zs_child(void)
{
    char out[ZC_LINE];
    struct zc_cmd c = { .argv = ZC_ARGV("sh", "-c", "printf '%s' \"$ZS_A\"; exit 3"),
        .env = ZC_ENV("ZS_A=seen", "HOME"), .out = out, .cap = sizeof out };
    if (zc_run(&c) != 3 || strcmp(out, "seen") != 0)
        return zs_fail("child capture or exit code");
    struct zc_cmd k = { .argv = ZC_ARGV("sh", "-c", "kill -KILL $$") };
    if (zc_run(&k) != 137)
        return zs_fail("signal exit code");
    struct zc_cmd tiny = { .argv = ZC_ARGV("sh", "-c", "printf 0123456789abcdef"),
                           .out = out, .cap = 5 };
    if (zc_run(&tiny) != 0 || strcmp(out, "0123") != 0)
        return zs_fail("truncating capture must not block the child");
    return 0;
}

static int zs_files(void)
{
    char found[ZC_PATH];
    const char *log = zcw("zcc.log");
    if (zc_put("zcc.log", "MISS a\nLOOKUP reason=bin-integrity key=0123456789abcdef"
               "0123456789abcdef0123456789abcdef0123456789abcdef x\nHIT b\n") ||
        zc_put("obj/ab/k.bin", "x") || zc_put("t.txt", "alpha beta\nbeta\n"))
        return zs_fail("fixture write");
    if (zc_lines(log) != 3)
        return zs_fail("line count");
    if (!zc_lookup_after(log, 1, "bin-integrity") || zc_lookup_after(log, 2, "bin-integrity") ||
        zc_lookup_after(log, 0, "bin-invalid"))
        return zs_fail("LOOKUP matching");
    if (!zc_find_suffix(zcw("obj"), ".bin", found, sizeof found) ||
        zc_find_suffix(zcw("obj"), ".dep", found, sizeof found))
        return zs_fail("recursive artifact find");
    return 0;
}

static int zs_text(void)
{
    const char *log = zcw("zcc.log");
    if (zc_sed_first(zcw("t.txt"), zcw("u.txt"), "beta", "BETA") ||
        !lct_file_has(zcw("u.txt"), "alpha BETA") || zc_same(zcw("t.txt"), zcw("u.txt")))
        return zs_fail("sed first occurrence");
    if (zc_copy(zcw("t.txt"), zcw("v.txt"), 1) || !zc_same(zcw("t.txt"), zcw("v.txt")))
        return zs_fail("copy");
    if (!zc_line_with_prefix(log, "HIT ") || zc_line_with_prefix(log, "WAIT "))
        return zs_fail("line prefix");
    return 0;
}

int check_zcc_cache_selftest(void)
{
    int rc;
    memset(&zc, 0, sizeof zc);
    if (zc_mkwork("zcl-zcc-selftest.XXXXXX"))
        return zs_fail("scratch directory");
    rc = zs_child() || zs_files() || zs_text();
    rap_rm_rf(zc.work);
    if (rc == 0)
        puts("check_zcc_cache: selftest OK (child capture, exit and signal codes, "
             "env set/unset, log counting, LOOKUP matching, sed, find, copy)");
    return rc;
}
