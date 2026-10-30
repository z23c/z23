/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-agent-cli — verify the native agentdeployguard CLI
 * contract without jq or live datadirs. Ported from
 * tools/scripts/check_agentdeployguard_cli_exit.sh (deleted). The gate
 * enters the repository root first, as the script did with `cd "$ROOT"`, so
 * the default node binary resolves from any working directory. It runs two
 * scratch-HOME cases against the node binary: an allow case (clean
 * .zclassic-c23 datadir, -datadir=... agentdeployguard deploy-dev, want rc 0
 * and the schema/decision/exit_code fields) and a refuse case (a pending
 * auto_reindex_request in .zclassic-c23-dev, want rc 1 and four fields).
 * Both cases run with ZCL_DATADIR removed from the environment, so the
 * fixture HOME is the only datadir source. Each run goes through
 * `timeout <N>s`, as the script did. Field checks are fixed-substring
 * searches in the captured stdout. Fail closed: a non-executable binary, a
 * failed run, or a missing field is a FAIL (rc 1); the OK line is printed
 * only on stdout after both cases pass.
 * Knobs: ZCL_NODE_BIN (default build/bin/zclassic23) and
 * ZCL_AGENTDEPLOYGUARD_CLI_TIMEOUT (default 10, seconds). Selftest:
 * gate_agent_cli_selftest.c.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

static const char k_agc_gate[] = "check_agentdeployguard_cli_exit";
static const char k_agc_bin_def[] = "build/bin/zclassic23";
static const char k_agc_tmo_def[] = "10";
static const char *const k_agc_unset[] = { "ZCL_DATADIR", NULL };

enum { AGC_PATH = 1024, AGC_ARG = 8, AGC_NUM = 32, AGC_GRACE_MS = 500 };

static int agc_fail(const char *msg)
{
    fprintf(stderr, "%s: FAIL: %s\n", k_agc_gate, msg);
    return 1;
}

/* Fixed-substring field check in the captured stdout (memmem, so an
 * embedded NUL cannot hide a missing field). */
static int agc_field(const struct lcp_buf *out, const char *file,
                     const char *pat)
{
    if (out->data && memmem(out->data, out->len, pat, strlen(pat)))
        return 0;
    fprintf(stderr, "%s: FAIL: missing pattern %s in %s\n", k_agc_gate, pat,
            file);
    return 1;
}

/* Checks a fixed list of field patterns against the captured output. */
static int agc_fields(const struct lcp_buf *out, const char *file,
                      const char *const *pats, int n)
{
    for (int i = 0; i < n; i++) {
        if (agc_field(out, file, pats[i]))
            return 1;
    }
    return 0;
}

/* Enters the repository root, where the default node binary and the
 * ZCL_NODE_BIN relative paths resolve, as the script's `cd "$ROOT"` did. */
static int agc_enter_root(void)
{
    char root[AGC_PATH];
    if (cic_repo_root(root, sizeof root) || chdir(root) != 0) {
        fprintf(stderr, "%s: cannot enter the repository root\n", k_agc_gate);
        return 2;
    }
    return 0;
}

/* Runs av (av[0] is "timeout") with HOME=home and ZCL_DATADIR unset, stdout
 * captured and stderr passed through as the script did. Returns 0 with the
 * exit status in *code, or -1 when the run failed, the capture overflowed,
 * or a termination signal was forwarded. */
static int agc_exec(const char *home, char *const *av, struct lcp_buf *out,
                    int *code)
{
    char homeset[AGC_PATH + 8];
    const char *const envs[2] = { homeset, NULL };
    struct lcp_spec sp;
    int r;

    if (ovf(snprintf(homeset, sizeof homeset, "HOME=%s", home),
            sizeof homeset))
        return -1;
    memset(&sp, 0, sizeof sp);
    sp.argv = av;
    sp.setenv = envs;
    sp.unsetenv = k_agc_unset;
    sp.mode = LCP_OUT_ERRPASS;
    sp.grace_ms = AGC_GRACE_MS;
    fflush(stdout);
    fflush(stderr);
    r = lcp_run(&sp, out, code);
    lsc_unblock();
    return (r || out->lost) ? -1 : 0;
}

static int agc_rc_fail(const char *which, int got, int want)
{
    char msg[AGC_PATH];
    if (ovf(snprintf(msg, sizeof msg, "%s case exited %d, expected %d", which,
                     got, want), sizeof msg))
        return 2;
    return agc_fail(msg);
}

static const char *const k_agc_allow_pats[] = {
    "\"schema\":\"zcl.agent_deploy_guard.v1\"",
    "\"decision\":\"allow\"",
    "\"exit_code\":0",
};

static const char *const k_agc_refuse_pats[] = {
    "\"schema\":\"zcl.agent_deploy_guard.v1\"",
    "\"decision\":\"refuse\"",
    "\"exit_code\":1",
    "\"reason\":\"pending_auto_reindex_requires_explicit_recovery_boot\"",
};

static int agc_allow_case(const char *bin, const char *tmo, const char *root,
                          const char *home)
{
    char dd[AGC_PATH], opt[AGC_PATH], file[AGC_PATH];
    int code = 0, rc;
    struct lcp_buf out;

    if (ovf(snprintf(dd, sizeof dd, "%s/.zclassic-c23", home), sizeof dd) ||
        ovf(snprintf(opt, sizeof opt, "-datadir=%s", dd), sizeof opt) ||
        ovf(snprintf(file, sizeof file, "%s/allow.json", root), sizeof file))
        return 2;
    if (csr_mkdirs(dd))
        return agc_fail("cannot mkdir allow-home datadir");
    char *av[AGC_ARG] = { (char *)"timeout", (char *)tmo, (char *)bin, opt,
                          (char *)"agentdeployguard", (char *)"deploy-dev",
                          NULL };
    memset(&out, 0, sizeof out);
    if (agc_exec(home, av, &out, &code)) {
        lcp_buf_free(&out);
        return agc_fail("allow case subprocess failed");
    }
    if (code != 0) {
        lcp_buf_free(&out);
        return agc_rc_fail("allow", code, 0);
    }
    rc = agc_fields(&out, file, k_agc_allow_pats, 3);
    lcp_buf_free(&out);
    return rc;
}

static int agc_refuse_case(const char *bin, const char *tmo, const char *root,
                           const char *home)
{
    char dd[AGC_PATH], req[AGC_PATH], file[AGC_PATH];
    int code = 0, rc;
    struct lcp_buf out;

    if (ovf(snprintf(dd, sizeof dd, "%s/.zclassic-c23-dev", home), sizeof dd) ||
        ovf(snprintf(req, sizeof req, "%s/auto_reindex_request", dd),
            sizeof req) ||
        ovf(snprintf(file, sizeof file, "%s/refuse.json", root), sizeof file))
        return 2;
    if (csr_mkdirs(dd))
        return agc_fail("cannot mkdir refuse-home datadir");
    if (csr_write(req, "3172354 1\n"))
        return agc_fail("cannot write auto_reindex_request fixture");
    char *av[AGC_ARG] = { (char *)"timeout", (char *)tmo, (char *)bin,
                          (char *)"agentdeployguard", (char *)"deploy-dev",
                          NULL };
    memset(&out, 0, sizeof out);
    if (agc_exec(home, av, &out, &code)) {
        lcp_buf_free(&out);
        return agc_fail("refuse case subprocess failed");
    }
    if (code != 1) {
        lcp_buf_free(&out);
        return agc_rc_fail("refuse", code, 1);
    }
    rc = agc_fields(&out, file, k_agc_refuse_pats, 4);
    lcp_buf_free(&out);
    return rc;
}

/* Runs both cases under root; home directories are created below it. */
static int agc_cases(const char *bin, const char *tmo, const char *root)
{
    char allow_home[AGC_PATH], refuse_home[AGC_PATH];
    int rc;

    if (ovf(snprintf(allow_home, sizeof allow_home, "%s/allow-home", root),
            sizeof allow_home) ||
        ovf(snprintf(refuse_home, sizeof refuse_home, "%s/refuse-home", root),
            sizeof refuse_home))
        return 2;
    rc = agc_allow_case(bin, tmo, root, allow_home);
    if (rc == 0)
        rc = agc_refuse_case(bin, tmo, root, refuse_home);
    return rc;
}

/* Builds the "<N>s" timeout the script passed to `timeout`, always with the
 * suffix appended (so a value already ending in "s" stays an error, as it
 * was in the script). Returns 2 when the value does not fit. */
static int agc_timeout_arg(const char *tmo, char *tbuf, size_t cap)
{
    if (ovf(snprintf(tbuf, cap, "%ss", tmo), cap))
        return 2;
    return 0;
}

int check_agent_cli_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *bin = env_or("ZCL_NODE_BIN", k_agc_bin_def);
    const char *tmo = env_or("ZCL_AGENTDEPLOYGUARD_CLI_TIMEOUT", k_agc_tmo_def);
    char tbuf[AGC_NUM], root[AGC_PATH];
    int rc, sig;

    if (agc_enter_root())
        return 2;
    if (access(bin, X_OK) != 0) {
        char msg[AGC_PATH];
        if (ovf(snprintf(msg, sizeof msg, "node binary is not executable: %s",
                         bin), sizeof msg))
            return 2;
        return agc_fail(msg);
    }
    if (agc_timeout_arg(tmo, tbuf, sizeof tbuf))
        return 2;
    if (lsc_install() != 0) {
        fprintf(stderr, "%s: cannot install signal handlers\n", k_agc_gate);
        return 2;
    }
    if (lint_mkdtemp(root, sizeof root, "agent-cli")) {
        fprintf(stderr, "%s: cannot create scratch dir\n", k_agc_gate);
        return 2;
    }
    rc = agc_cases(bin, tbuf, root);
    lsc_block();
    rap_rm_rf(root);
    lsc_unblock();
    sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    if (rc)
        return rc;
    printf("%s: OK\n", k_agc_gate);
    return 0;
}
