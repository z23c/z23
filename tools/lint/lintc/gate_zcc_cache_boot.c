/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check-zcc-cache bootstrap identity suite: the bootstrap compiler
 * rebuilds byte-identically from unchanged sources in any checkout, tracks a
 * source or flag edit, restores on revert, never launches a compiler when
 * unchanged, and its read-only freshness probe refuses incomplete inputs.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc_text.h"
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

static char bs_bin[ZC_PATH], bs_one[ZC_PATH], bs_two[ZC_PATH];

static int boot_fixture(const char *dest)
{
    FILE *f = fopen(zcf("%s/tools/dev/zcc-bootstrap-inputs.list", zc.root), "r");
    char line[ZC_PATH];
    int bad = !f;
    while (!bad && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = '\0';
        if (!line[0] || strncmp(line, "license=", 8) == 0)
            continue;
        char dir[ZC_PATH];
        const char *dst = zcf("%s/%s", dest, line);
        memcpy(dir, dst, strlen(dst) + 1);
        char *slash = strrchr(dir, '/');
        if (slash)
            *slash = '\0';
        bad = csr_mkdirs(dir) ||
              zc_copy(zcf("%s/%s", zc.root, line), dst, 0);
    }
    if (f)
        fclose(f);
    return bad;
}

static int boot_run(const char *checkout, const char *output, const char *const *extra)
{
    char built[ZC_PATH];
    const char *env[4] = { zcf("ZCL_BIN_DIR=%s", output) };
    for (int i = 0; extra && extra[i] && i < 2; i++)
        env[i + 1] = extra[i];
    struct zc_cmd c = { .argv = ZC_ARGV(zcf("%s/tools/dev/zcc_bootstrap.sh", checkout)),
        .env = env, .out = built, .cap = sizeof built };
    zc_run(&c);
    built[strcspn(built, "\n")] = '\0';
    if (strcmp(built, zcf("%s/zcc", output)) != 0 || access(built, X_OK) != 0) {
        zc_fail("isolated bootstrap did not publish its executable");
        return 1;
    }
    return 0;
}

static int boot_probe(const char *a, const char *b, int want_ok, const char *msg)
{
    const char *const env[] = { zc_zd("bootstrap-probe-cache"), NULL };
    const char *const av2[] = { bs_bin, "--zcc-bootstrap-fresh", a, b, NULL };
    const char *const av1[] = { bs_bin, "--zcc-bootstrap-fresh", a, NULL };
    struct zc_cmd c = { .argv = b ? av2 : av1, .env = env, .keep_out = 1 };
    int ok = zc_run(&c) == 0;
    return zc_want(ok == want_ok, msg);
}

static int boot_edit_cycle(char *hash)
{
    const char *zc_c = zcf("%s/tools/zcc.c", bs_one);
    const char *out = zcw("bootstrap-out-one");
    char now[ZC_SHA];
    if (zc_copy(zc_c, zcw("bootstrap-source-original"), 1) ||
        zc_sed_first(zc_c, zcw("bootstrap-source"), "usage: zcc <compiler>",
                     "usage: zcc-fixture <compiler>") ||
        rename(zcw("bootstrap-source"), zc_c) != 0 || boot_run(bs_one, out, NULL))
        return 1;
    struct zc_cmd u = { .argv = ZC_ARGV(bs_bin), .outf = zcw("bootstrap-usage"), .merge = 1 };
    zc_run(&u);
    zc_want(lct_file_has(zcw("bootstrap-usage"), "usage: zcc-fixture <compiler>"),
            "bootstrap source edit did not change the published behavior");
    zc_want(zc_sha(bs_bin, now) && strcmp(now, hash) != 0,
            "bootstrap source edit did not change compiler bytes");
    if (zc_copy(zcw("bootstrap-source-original"), zc_c, 1) || boot_run(bs_one, out, NULL))
        return 1;
    zc_want(zc_sha(bs_bin, now) && strcmp(now, hash) == 0,
            "restoring bootstrap source did not restore compiler bytes");
    u.outf = zcw("bootstrap-restored-usage");
    zc_run(&u);
    zc_want(lct_file_has(zcw("bootstrap-restored-usage"), "usage: zcc <compiler>"),
            "restoring bootstrap source mtime retained mutated compiler behavior");
    return 0;
}

static int boot_probes(void)
{
    const char *zc_c = zcf("%s/tools/zcc.c", bs_one);
    const char *tools = zcf("%s/tools", bs_one);
    boot_probe(bs_bin, zc_c, 1, "restored bootstrap inputs were not timestamp-fresh");
    boot_probe(bs_bin, zcw("bootstrap-missing"), 0,
               "bootstrap probe accepted a missing or non-regular input");
    boot_probe(bs_bin, tools, 0, "bootstrap probe accepted a missing or non-regular input");
    boot_probe(bs_bin, NULL, 0, "bootstrap probe accepted no inputs");
    boot_probe(tools, zc_c, 0, "bootstrap probe accepted a non-regular binary");
    zc_want(!zc_exists(zcw("bootstrap-probe-cache")), "bootstrap probe created cache state");
    return 0;
}

static int boot_tail(const char *hash)
{
    char now[ZC_SHA];
    const char *out_one = zcw("bootstrap-out-one");
    const char *const extra[] = { zcf("BOOTSTRAP_TEST_COUNT=%s", zcw("bootstrap-compiler.calls")),
        zcf("ZCL_BOOTSTRAP_CC=%s", zcw("bootstrap-compiler")), NULL };
    if (zc_put("bootstrap-compiler", "#!/bin/sh\nprintf 'compile\\n' >> \"$BOOTSTRAP_TEST_COUNT\"\n"
               "exec cc \"$@\"\n") || chmod(zcw("bootstrap-compiler"), 0755) ||
        zc_put("bootstrap-compiler.calls", "") || boot_run(bs_one, out_one, extra))
        return 1;
    zc_want(!zc_nonempty(zcw("bootstrap-compiler.calls")),
            "unchanged bootstrap launched a compiler");
    const char *sh = zcf("%s/tools/dev/zcc_bootstrap.sh", bs_one);
    if (zc_sed_first(sh, zcw("bootstrap-flags"), "BOOTSTRAP_FLAGS=(-std=c23 -O2 ",
                     "BOOTSTRAP_FLAGS=(-std=c23 -O0 ") ||
        zc_copy(zcw("bootstrap-flags"), sh, 0) || boot_run(bs_one, out_one, NULL))
        return 1;
    zc_want(zc_sha(bs_bin, now) && strcmp(now, hash) != 0,
            "bootstrap flag edit did not change compiler bytes");
    return 0;
}

/* Apple only: the signature identity and Mach-O UUID must not depend on the
 * staging filename. */
static int boot_line_is(const char *path, const char *want)
{
    FILE *f = fopen(path, "r");
    char line[ZC_LINE];
    int hit = 0;
    while (f && !hit && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = '\0';
        hit = strcmp(line, want) == 0;
    }
    if (f)
        fclose(f);
    return hit;
}

/* The uuid field two lines after LC_UUID in `otool -l`, or "". */
static void boot_uuid(const char *path, char *uuid, size_t cap)
{
    FILE *f = fopen(path, "r");
    char line[ZC_LINE];
    int skip = -1;
    uuid[0] = '\0';
    while (f && fgets(line, sizeof line, f)) {
        if (skip < 0 && strstr(line, "LC_UUID"))
            skip = 2;
        else if (skip > 0 && --skip == 0) {
            char key[ZC_LINE], val[ZC_LINE];
            if (sscanf(line, "%1023s %1023s", key, val) == 2)
                zc_str(uuid, cap, val);
            break;
        }
    }
    if (f)
        fclose(f);
}

static void boot_sign_one(const char *built)
{
    char uuid[ZC_LINE];
    struct zc_cmd v = { .argv = ZC_ARGV("codesign", "--verify", "--strict", built) };
    zc_want(zc_run(&v) == 0, "bootstrap signature is invalid");
    struct zc_cmd d = { .argv = ZC_ARGV("codesign", "-dvv", built),
        .outf = zcw("bootstrap-signature"), .merge = 1 };
    zc_run(&d);
    zc_want(boot_line_is(zcw("bootstrap-signature"), "Identifier=zcc"),
            "bootstrap signature identity depends on its staging filename");
    struct zc_cmd o = { .argv = ZC_ARGV("otool", "-l", built),
        .outf = zcw("bootstrap-otool") };
    zc_run(&o);
    boot_uuid(zcw("bootstrap-otool"), uuid, sizeof uuid);
    zc_want(uuid[0] && strcmp(uuid, "00000000-0000-0000-0000-000000000000") != 0,
            "bootstrap lost its nonzero content-derived UUID");
}

static void boot_sign(void)
{
    if (!zc_on("Darwin"))
        return;
    boot_sign_one(bs_bin);
    boot_sign_one(zcw("bootstrap-out-repeat/zcc"));
    boot_sign_one(zcw("bootstrap-out-two/zcc"));
}

int zc_sec_boot(void)
{
    char hash[ZC_SHA];
    const char *out_one = zcw("bootstrap-out-one");
    zc_str(bs_one, sizeof bs_one, zcw("bootstrap-one"));
    zc_str(bs_two, sizeof bs_two, zcw("bootstrap-two"));
    zc_str(bs_bin, sizeof bs_bin, zcw("bootstrap-out-one/zcc"));
    if (boot_fixture(bs_one) || boot_fixture(bs_two) || boot_run(bs_one, out_one, NULL) ||
        boot_run(bs_one, zcw("bootstrap-out-repeat"), NULL) ||
        boot_run(bs_two, zcw("bootstrap-out-two"), NULL))
        return 1;
    zc_want(zc_same(bs_bin, zcw("bootstrap-out-repeat/zcc")),
            "identical bootstrap sources rebuilt to different compiler bytes");
    zc_want(zc_same(bs_bin, zcw("bootstrap-out-two/zcc")),
            "physical checkout location changed bootstrap compiler bytes");
    boot_sign();
    if (!zc_sha(bs_bin, hash) || boot_edit_cycle(hash) || boot_probes())
        return 1;
    return boot_tail(hash);
}
