/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check_package_anatomy declared KATs (ball, zdemo, zhello) compiled
 * and run under the bounded runner via posix_spawn, never system or popen.
 * Shared declarations live in gate_package_anatomy_priv.h.
 */
#include "gate_package_anatomy_priv.h"

/* ---------- declared package KATs (posix_spawn only) ---------- */

extern char **environ;

static int pka_spawn(char *const argv[], int quiet, int *code)
{
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_t *fap = NULL;
    int devnull = -1;
    if (quiet) {
        devnull = open("/dev/null", O_WRONLY);
        if (devnull < 0) {
            *code = -1;
            return -1;
        }
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_adddup2(&fa, devnull, 1);
        posix_spawn_file_actions_adddup2(&fa, devnull, 2);
        fap = &fa;
    }
    pid_t pid;
    int rc = posix_spawnp(&pid, argv[0], fap, NULL, argv, environ);
    if (quiet) {
        posix_spawn_file_actions_destroy(&fa);
        close(devnull);
    }
    if (rc) {
        *code = -1;
        return -1;
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) {
        *code = -1;
        return -1;
    }
    if (WIFEXITED(st))
        *code = WEXITSTATUS(st);
    else if (WIFSIGNALED(st))
        *code = 128 + WTERMSIG(st);
    else
        *code = -1;
    return 0;
}

static int pka_cc_argv(char cc[][PKA_CCLEN], int max)
{
    const char *c = getenv("CC");
    if (!c || !*c)
        c = "cc";
    int n = 0;
    while (*c) {
        while (*c == ' ' || *c == '\t')
            c++;
        if (!*c)
            break;
        if (n >= max)
            return -1;
        int i = 0;
        while (*c && *c != ' ' && *c != '\t') {
            if (i < PKA_CCLEN - 1)
                cc[n][i++] = *c;
            c++;
        }
        cc[n][i] = '\0';
        n++;
    }
    return n;
}

static int pka_kat_one(char cc[][PKA_CCLEN], int ncc, const char *runner,
                       const char *work, const char *pkg, const char *suf,
                       int *rc)
{
    char bin[PKA_PATH], iarg[PKA_PATH], src[PKA_PATH], tst[PKA_PATH];
    char *av[PKA_CC + 12];
    char *rv[4];
    int k = 0, code = 0;
    if (ovf(snprintf(bin, sizeof bin, "%s/test_%s%s", work, pkg, suf),
            sizeof bin))
        return 2;
    if (ovf(snprintf(iarg, sizeof iarg, "-Icontexts/commons/packages/%s/include",
                     pkg), sizeof iarg))
        return 2;
    if (ovf(snprintf(src, sizeof src, "contexts/commons/packages/%s/src/%s.c",
                     pkg, pkg), sizeof src))
        return 2;
    if (ovf(snprintf(tst, sizeof tst,
                     "contexts/commons/packages/%s/tests/test_%s.c", pkg, pkg),
            sizeof tst))
        return 2;
    for (int i = 0; i < ncc; i++)
        av[k++] = cc[i];
    av[k++] = (char *)"-std=c23";
    av[k++] = (char *)"-O2";
    av[k++] = (char *)"-Wall";
    av[k++] = (char *)"-Wextra";
    av[k++] = (char *)"-Werror";
    av[k++] = (char *)"-pedantic";
    av[k++] = iarg;
    av[k++] = src;
    av[k++] = tst;
    av[k++] = (char *)"-o";
    av[k++] = bin;
    av[k++] = NULL;
    if (pka_spawn(av, 0, &code) != 0)
        code = 127;
    if (code != 0) {
        fprintf(stderr, "%s: %s declared KAT does not compile\n", k_pka_gate,
                pkg);
        *rc = 1;
        return 0;
    }
    rv[0] = (char *)runner;
    rv[1] = (char *)"10000";
    rv[2] = bin;
    rv[3] = NULL;
    if (pka_spawn(rv, 0, &code) != 0)
        code = 127;
    if (code == 0)
        return 0;
    if (code == 124) {
        fprintf(stderr, "%s: %s declared KAT exceeded 10000ms\n", k_pka_gate,
                pkg);
        *rc = 1;
        return 0;
    }
    if (code == 125 || code == 126 || code == 127) {
        fprintf(stderr, "%s: FATAL — bounded runner could not supervise %s "
                "KAT\n", k_pka_gate, pkg);
        return 2;
    }
    fprintf(stderr, "%s: %s declared KAT failed (exit %d)\n", k_pka_gate, pkg,
            code);
    *rc = 1;
    return 0;
}

static int pka_kat_cc_ok(char cc[][PKA_CCLEN], int ncc)
{
    char ccs[PKA_CC * PKA_CCLEN];
    char *ver[PKA_CC + 2];
    int code = 0;
    size_t o = 0;
    if (ncc <= 0) {
        fprintf(stderr, "%s: FATAL — CC resolved to an empty command\n",
                k_pka_gate);
        return 2;
    }
    for (int i = 0; i < ncc; i++) {
        int w = snprintf(ccs + o, sizeof ccs - o, "%s%s", i ? " " : "", cc[i]);
        if (ovf(w, sizeof ccs - o))
            return 2;
        o += (size_t)w;
    }
    for (int i = 0; i < ncc; i++)
        ver[i] = cc[i];
    ver[ncc] = (char *)"--version";
    ver[ncc + 1] = NULL;
    if (pka_spawn(ver, 1, &code) != 0) {
        fprintf(stderr, "%s: FATAL — compiler '%s' is unavailable\n",
                k_pka_gate, cc[0]);
        return 2;
    }
    if (code != 0) {
        fprintf(stderr, "%s: FATAL — compiler '%s' cannot execute\n",
                k_pka_gate, ccs);
        return 2;
    }
    return 0;
}

static int pka_kat_runner_ok(const char *runner)
{
    char *st[3];
    int code = 0;
    if (access(runner, X_OK) != 0) {
        fprintf(stderr, "%s: FATAL — bounded KAT runner %s is unavailable\n",
                k_pka_gate, runner);
        return 2;
    }
    st[0] = (char *)runner;
    st[1] = (char *)"--selftest";
    st[2] = NULL;
    if (pka_spawn(st, 0, &code) != 0 || code != 0) {
        fprintf(stderr, "%s: FATAL — bounded KAT runner selftest failed\n",
                k_pka_gate);
        return 2;
    }
    return 0;
}

static int pka_kat_mkwork(char *work, size_t cap)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(work, cap, "%s/z23-lint-pkg-anat.XXXXXX", td), cap))
        return 2;
    if (!mkdtemp(work)) {
        fprintf(stderr, "%s: FATAL — cannot create KAT work directory\n",
                k_pka_gate);
        return 2;
    }
    return 0;
}

static const char *pka_kat_suffix(void)
{
    const char *os = getenv("OS");
    return (os && strcmp(os, "Windows_NT") == 0) ? ".exe" : "";
}

static int pka_kat_each(char cc[][PKA_CCLEN], int ncc, const char *runner,
                        const char *work)
{
    static const char *const k_pkgs[] = { "ball", "zdemo", "zhello" };
    const char *suf = pka_kat_suffix();
    int rc = 0;
    for (size_t i = 0; i < sizeof k_pkgs / sizeof k_pkgs[0]; i++) {
        int r = pka_kat_one(cc, ncc, runner, work, k_pkgs[i], suf, &rc);
        if (r)
            return r;
    }
    return rc;
}

int pka_run_kats(void)
{
    const char *runner = "build/bin/z23_bounded_run";
    char cc[PKA_CC][PKA_CCLEN];
    char work[PKA_PATH];
    int ncc = pka_cc_argv(cc, PKA_CC);
    int r = 0;
    if (pka_kat_cc_ok(cc, ncc) || pka_kat_runner_ok(runner))
        return 2;
    if (pka_kat_mkwork(work, sizeof work))
        return 2;
    r = pka_kat_each(cc, ncc, runner, work);
    rap_rm_rf(work);
    return r;
}
