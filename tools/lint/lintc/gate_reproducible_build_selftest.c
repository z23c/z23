/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-reproducible-build
 * (gate_reproducible_build.c). Builds a scratch fixture tree with a stub
 * tools/scripts/repro_build_vars.sh and a fixture build command passed to
 * rpb_run_root() in place of make (never the real node build), and covers:
 * identical outputs PASS, differing outputs FAIL with a first-divergence
 * report, a build that exits rc 2 FAIL, a missing output binary FAIL, an
 * unresolved Make expression refused before any build runs, the child
 * environment policy and the release profile.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_reproducible_build_priv.h"

enum { RP_SP = 1100, RP_TXT = 8192 };

/* The fixture build: <cmd> <build_dir> <binary>. ZCL_REPRO_MARK, when set, is
 * touched first so a case can prove the build step ran at all. The DIFFER
 * marker lives in the parent (the shared scratch root), so build A creates it
 * and build B sees it and appends a byte. */
static const char k_rps_fixture[] =
    "#!/bin/sh\n"
    "set -e\n"
    "if [ -n \"${ZCL_REPRO_MARK:-}\" ]; then : > \"$ZCL_REPRO_MARK\"; fi\n"
    "mkdir -p \"$1/bin\"\n"
    "out=\"$1/bin/$2\"\n"
    "printf 'z23-repro-fixture-v1' > \"$out\"\n"
    "if [ \"${ZCL_REPRO_FAIL:-0}\" = 1 ]; then exit 2; fi\n"
    "if [ \"${ZCL_REPRO_NOOUT:-0}\" = 1 ]; then rm -f \"$out\"; exit 0; fi\n"
    "if [ \"${ZCL_REPRO_DIFFER:-0}\" = 1 ] && [ -f \"$1/../marker\" ]; then "
    "printf 'X' >> \"$out\"; fi\n"
    "if [ \"${ZCL_REPRO_DIFFER:-0}\" = 1 ]; then : > \"$1/../marker\"; fi\n"
    "exit 0\n";

static const char k_rps_vars[] =
    "#!/usr/bin/env bash\n"
    "export SOURCE_DATE_EPOCH=1700000000\n"
    "export REL_CFLAGS=\"-O2 -g0\"\n"
    "export REL_LDFLAGS=\"-Wl,--build-id=none\"\n";

/* A profile whose CFLAGS still holds a Make expression: must be refused. */
static const char k_rps_unresolved[] =
    "#!/usr/bin/env bash\n"
    "export SOURCE_DATE_EPOCH=1700000000\n"
    "export REL_CFLAGS='-O2 $(X)'\n"
    "export REL_LDFLAGS='-Wl,--build-id=none'\n";

/* text is what the case must print on stdout or stderr: the distinguishing
 * line of each outcome, not merely the rc. */
struct rps_case {
    const char *name;
    const char *differ;
    const char *fail;
    const char *noout;
    int want;
    const char *text;
};

static const struct rps_case k_rps_cases[] = {
    { "identical outputs pass", "0", "0", "0", 0, "BYTE-IDENTICAL" },
    { "differing outputs fail with offset", "1", "0", "0", 1,
      "first divergence" },
    { "build failing rc 2 fails", "0", "1", "0", 1, "Build A failed" },
    { "missing output fails", "0", "0", "1", 1, "Build A finished but" },
};

static int rps_fixture_write(const char *root, const char *vars_text,
                             char *cmd, size_t cap)
{
    char vars[RP_SP];
    if (ovf(snprintf(vars, sizeof vars, "%s/tools/scripts/repro_build_vars.sh",
                     root), sizeof vars) ||
        ovf(snprintf(cmd, cap, "%s/fixture-build.sh", root), cap))
        return 2;
    int rc = csr_write(vars, vars_text);
    if (rc == 0)
        rc = csr_write(cmd, k_rps_fixture);
    if (rc == 0 && chmod(cmd, 0755) != 0)
        rc = 2;
    return rc;
}

/* Run the gate with its stdout to out and its stderr to err (both captured).
 * The caller reads them back; fd 2 is restored before returning. */
static int rps_gate_quiet(const char *root, FILE *out, FILE *err,
                          const char *cmd)
{
    fflush(NULL);
    int se = dup(2);
    if (se >= 0)
        dup2(fileno(err), 2);
    int got = rpb_run_root(root, out, cmd);
    fflush(NULL);
    if (se >= 0) {
        dup2(se, 2);
        close(se);
    }
    return got;
}

static void rps_slurp(FILE *f, char *buf, size_t cap)
{
    size_t used = 0;
    rewind(f);
    while (used + 1 < cap && fgets(buf + used, (int)(cap - used), f))
        used += strlen(buf + used);
    buf[used] = '\0';
}

static int rps_run_case(const char *root, const char *cmd,
                        const struct rps_case *c)
{
    setenv("ZCL_REPRO_DIFFER", c->differ, 1);
    setenv("ZCL_REPRO_FAIL", c->fail, 1);
    setenv("ZCL_REPRO_NOOUT", c->noout, 1);
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int got = rps_gate_quiet(root, out, err, cmd);
    char outbuf[RP_TXT], errbuf[RP_TXT];
    rps_slurp(out, outbuf, sizeof outbuf);
    rps_slurp(err, errbuf, sizeof errbuf);
    fclose(out);
    fclose(err);
    if (got != c->want || (!strstr(outbuf, c->text) &&
                           !strstr(errbuf, c->text))) {
        fprintf(stderr, "check-reproducible-build selftest: %s: want "
                "rc=%d with \"%s\" got rc=%d\n", c->name, c->want, c->text,
                got);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d, \"%s\")\n", c->name, got, c->text);
    return 0;
}

/* The unresolved-expression refusal happens in rpb_run_root before any build:
 * rc 1 with the refusal text, and the fixture's first line (the run marker)
 * never executes. The stub exports REL_CFLAGS='-O2 $(X)' single-quoted. */
static int rps_unresolved_case(void)
{
    char root[RP_SP], cmd[RP_SP], mark[RP_SP];
    if (lct_scratch_dir(root, sizeof root, "reproducible-build"))
        return 1;
    int bad = 1;
    if (rps_fixture_write(root, k_rps_unresolved, cmd, sizeof cmd) ||
        ovf(snprintf(mark, sizeof mark, "%s/ran", root), sizeof mark))
        goto done;
    setenv("ZCL_REPRO_MARK", mark, 1);
    setenv("ZCL_REPRO_DIFFER", "0", 1);
    setenv("ZCL_REPRO_FAIL", "0", 1);
    setenv("ZCL_REPRO_NOOUT", "0", 1);
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err)
        goto done;
    int got = rps_gate_quiet(root, out, err, cmd);
    char errbuf[RP_TXT];
    rps_slurp(err, errbuf, sizeof errbuf);
    fclose(out);
    fclose(err);
    int ran = access(mark, F_OK) == 0;
    if (got != 1 || ran || !strstr(errbuf, "unresolved Make expression")) {
        fprintf(stderr, "check-reproducible-build selftest: unresolved Make "
                "expression: want rc=1, refusal text, no build; got rc=%d "
                "build-ran=%d\n", got, ran);
    } else {
        printf("  selftest ok: unresolved Make expression refused before "
               "any build (rc=1)\n");
        bad = 0;
    }
done:
    unsetenv("ZCL_REPRO_MARK");
    unsetenv("ZCL_REPRO_DIFFER");
    unsetenv("ZCL_REPRO_FAIL");
    unsetenv("ZCL_REPRO_NOOUT");
    rap_rm_rf(root);
    return bad;
}

static void rps_env_clear(void)
{
    unsetenv("ZCL_REPRO_DIFFER");
    unsetenv("ZCL_REPRO_FAIL");
    unsetenv("ZCL_REPRO_NOOUT");
    unsetenv("BINARY");
    unsetenv("KEEP");
}

/* The release profile the shell gate reported and refused. (a) The expanded
 * CFLAGS carry -march=x86-64-v3 and -Iexpanded/include and are reported as
 * captured. (b) A capture that still holds "$(" is refused with the shell
 * gate's "unresolved Make expression" result. The captures are fixture text in
 * the loader's record-separator form; no make runs. */
static int rps_profile_case(void)
{
    static const char expanded[] =
        "SOURCE_DATE_EPOCH=1700000000\036"
        "REL_CFLAGS=-std=c23 -O2 -march=x86-64-v3 -Iexpanded/include\036"
        "REL_LDFLAGS=-pthread -Wl,--build-id=none\036";
    static const char unresolved[] =
        "SOURCE_DATE_EPOCH=1700000000\036"
        "REL_CFLAGS=-std=c23 $(EXTRA_FLAGS) -march=x86-64-v3\036"
        "REL_LDFLAGS=-pthread\036";
    static const char want[] = "-std=c23 -O2 -march=x86-64-v3 -Iexpanded/include";
    struct rpb_vars v;
    char buf[sizeof expanded];
    int bad = 0;
    memcpy(buf, expanded, sizeof expanded);
    int rc = rpb_profile_parse(buf, &v);
    if (rc != 0 || strcmp(v.cflags, want) != 0 ||
        !strstr(v.cflags, "-march=x86-64-v3 -Iexpanded/include")) {
        fprintf(stderr, "check-reproducible-build selftest: expanded profile: "
                "want rc=0 cflags=%s got rc=%d cflags=%s\n", want, rc, v.cflags);
        bad = 1;
    } else {
        printf("  selftest ok: release profile reports expanded CFLAGS "
               "(-march=x86-64-v3 -Iexpanded/include)\n");
    }
    memset(buf, 0, sizeof buf);
    memcpy(buf, unresolved, sizeof unresolved);
    rc = rpb_profile_parse(buf, &v);
    if (rc != 3) {
        fprintf(stderr, "check-reproducible-build selftest: unresolved Make "
                "expression: want rc=3 got rc=%d\n", rc);
        bad = 1;
    } else {
        printf("  selftest ok: unresolved Make expression refused (rc=3)\n");
    }
    return bad;
}

/* The child environment policy, on a hostile caller environment passed as data
 * (no setenv): every forced key must come out exactly once with its pinned
 * value, and an unrelated caller key must survive. These are the values the
 * old shell gate asserted: offline=1 ccache=0 locale=C timezone=UTC
 * path=/usr/bin:/bin home=/nonexistent. */
static int rps_env_case(void)
{
    char *hostile[] = { (char *)"ZCL_VENDOR_OFFLINE=0",
                        (char *)"ZCL_USE_CCACHE=1",
                        (char *)"PATH=/opt/evil/bin:/usr/bin",
                        (char *)"HOME=/tmp", (char *)"LC_ALL=en_US.UTF-8",
                        (char *)"TZ=Europe/Paris", (char *)"KEEP_ME=1", NULL };
    static const struct { const char *key; const char *want; } pin[] = {
        { "ZCL_VENDOR_OFFLINE", "1" }, { "ZCL_USE_CCACHE", "0" },
        { "LC_ALL", "C" }, { "TZ", "UTC" }, { "PATH", "/usr/bin:/bin" },
        { "HOME", "/nonexistent" }, { "KEEP_ME", "1" },
    };
    struct rpb_env e;
    int bad = rpb_child_env(hostile, &e) != 0;
    for (size_t i = 0; !bad && i < sizeof pin / sizeof pin[0]; i++) {
        char got[RP_PATH];
        if (rpb_env_get(&e, pin[i].key, got, sizeof got) != 0 ||
            strcmp(got, pin[i].want) != 0) {
            fprintf(stderr, "check-reproducible-build selftest: child env: "
                    "%s want %s got %s\n", pin[i].key, pin[i].want, got);
            bad = 1;
        }
    }
    if (!bad)
        printf("  selftest ok: child env forces offline=1 ccache=0 "
               "locale=C timezone=UTC path=/usr/bin:/bin home=/nonexistent\n");
    return bad;
}

int check_reproducible_build_selftest(void)
{
    char root[RP_SP], cmd[RP_SP];
    int rc = lct_scratch_dir(root, sizeof root, "reproducible-build");
    if (rc)
        return rc;
    rc = rps_fixture_write(root, k_rps_vars, cmd, sizeof cmd);
    if (rc) {
        rap_rm_rf(root);
        return rc;
    }
    setenv("BINARY", "zfixture", 1);
    setenv("KEEP", "0", 1);
    int bad = rps_env_case() | rps_profile_case() | rps_unresolved_case();
    for (size_t i = 0; i < sizeof k_rps_cases / sizeof k_rps_cases[0]; i++) {
        if (rps_run_case(root, cmd, &k_rps_cases[i]))
            bad = 1;
    }
    rps_env_clear();
    rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_reproducible_build selftest\n", stderr);
    return st_ok(bad, "check-reproducible-build selftest: OK\n");
}
