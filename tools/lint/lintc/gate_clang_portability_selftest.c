/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-clang-portability. Ports the script's
 * --self-test: the flag-set probe TU must be rejected, a clean TU accepted,
 * the compiler-infrastructure classifier proven in four directions, and the
 * coverage three-answer behavior (a layer emptied from the Makefile parse is
 * UNPROVEN exit 2; a stale allowance is exit 1) via re-invocations of this
 * gate. The tu-cache soundness proofs live in
 * gate_clang_portability_selftest_cache.c.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_clang_portability_priv.h"


int cp_stub_cc_main(int argc, char **argv)
{
    /* invoked as: <exe> check-clang-portability --stub-cc <cc args...> */
    if (argc >= 2 && !strcmp(argv[1], "--version")) {
        printf("tu-cache stub compiler 1.0\n");
        return 0;
    }
    const char *src = argv[argc - 1];
    const char *runs = getenv("ZCL_TU_STUB_RUNS");
    if (runs) {
        FILE *f = fopen(runs, "a");
        if (f) {
            fprintf(f, "x\n");
            fclose(f);
        }
    }
    size_t l = strlen(src);
    if (l >= 4 && !strcmp(src + l - 4, "u7.c")) {
        fprintf(stderr, "%s:1:1: error: stub planted rejection\n", src);
        return 1;
    }
    return 0;
}

static int cps_compile(struct cp_ctx *c, const char *path)
{
    char *tail[CP_MAXARGS + 2];
    int a = 0;
    for (int i = 0; i < c->nflags; i++)
        tail[a++] = c->flags[i];
    tail[a++] = (char *)path;
    tail[a] = NULL;
    char sink[CP_PATH];
    cps_snp(sink, "%s/probe-out.txt", c->work);
    int rc = 0;
    if (cp_cc_spawn(c, tail, sink, sink, &rc) != 0)
        return -1;
    return rc;
}

static int cps_fail(const char *msg)
{
    fprintf(stderr, "FAIL: --self-test — %s\n", msg);
    return 1;
}


static int cps_cov_case(const char *self, int want, const char *msg,
                        const char *var1, const char *val1, const char *var2,
                        const char *val2)
{
    setenv("ZCL_INTERNAL_CLANG_COVERAGE_SELFTEST", "1", 1);
    if (var1)
        setenv(var1, val1, 1);
    if (var2)
        setenv(var2, val2, 1);
    char *av[4];
    av[0] = (char *)self;
    av[1] = (char *)"check-clang-portability";
    av[2] = NULL;
    int rc = 127;
    pid_t pid = fork();
    if (pid == 0) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            dup2(dn, 1);
            dup2(dn, 2);
        }
        execv(self, av);
        _exit(127);
    }
    int st;
    waitpid(pid, &st, 0);
    rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128;
    unsetenv("ZCL_INTERNAL_CLANG_COVERAGE_SELFTEST");
    if (var1)
        unsetenv(var1);
    if (var2)
        unsetenv(var2);
    if (rc != want) {
        char m[256];
        cps_snp(m, "%s (wanted exit %d, got %d)", msg, want, rc);
        return cps_fail(m);
    }
    return 0;
}

static int cps_cov_selftests(const char *self, struct cp_ctx *c)
{
    /* (a) CORE_CONTEXTS emptied in a truncated Makefile copy */
    char shortmk[CP_PATH];
    if (ovf(snprintf(shortmk, sizeof shortmk, "%s/Makefile.core_contexts_emptied",
                     c->work), sizeof shortmk))
        return 2;
    FILE *in = fopen(c->makefile, "r"), *o = fopen(shortmk, "w");
    if (!in || !o)
        return die("z23-lint: cannot build Makefile copy\n", "");
    char line[CP_LINE];
    while (fgets(line, sizeof line, in)) {
        if (!strncmp(line, "CORE_CONTEXTS", 13)) {
            size_t i = 13;
            while (line[i] == ' ' || line[i] == '\t' || line[i] == ':' ||
                   line[i] == '+' || line[i] == '=') {
                if (line[i] == '=')
                    break;
                i++;
            }
            fputs("CORE_CONTEXTS =\n", o);
        } else {
            fputs(line, o);
        }
    }
    fclose(in);
    fclose(o);
    int rc = cps_cov_case(self, 2,
            "a whole layer dropped from the Makefile parse was not UNPROVEN",
            "ZCL_CLANG_PORTABILITY_MAKEFILE", shortmk, NULL, NULL);
    if (rc)
        return rc;
    return cps_cov_case(self, 1,
            "an allowance above the true shortfall was silently tolerated",
            "ZCL_CLANG_PORTABILITY_COVERAGE_ALLOWANCE", "1", NULL, NULL);
}

static int cps_proven_cases(struct cp_ctx *c)
{
    char p[CP_PATH];
    cps_snp(p, "%s/compiler-crash.log", c->work);
    cps_static_write(p, "gcc: fatal error: cannot execute 'cc1': CreateProcess failed\n");
    if (cp_compiler_result_proven(p, 1))
        return cps_fail("a cc1 driver failure was accepted as a source "
                        "diagnostic.");
    cps_snp(p, "%s/source-error.log", c->work);
    cps_static_write(p, "fixture.c:1:2: error: planted source rejection\n");
    if (!cp_compiler_result_proven(p, 1))
        return cps_fail("an ordinary source-located rejection was "
                        "misclassified as compiler infrastructure failure.");
    cps_snp(p, "%s/mixed-compiler.log", c->work);
    cps_static_write(p, "fixture.c:1:2: error: planted source rejection\n"
                 "LLVM ERROR: out of memory\n");
    if (cp_compiler_result_proven(p, 1))
        return cps_fail("a mixed source/backend failure was accepted.");
    cps_snp(p, "%s/success-error.log", c->work);
    cps_static_write(p, "fixture.c:1:2: error: wrapper returned success\n");
    if (cp_compiler_result_proven(p, 0))
        return cps_fail("compiler rc=0 with an error was accepted.");
    return 0;
}

static int cps_probe_cases(struct cp_ctx *c)
{
    char probe[CP_PATH];
    cps_snp(probe, "%s/probe.c", c->work);
    int rc = cps_static_write(probe,
        "int zcl_gate_probe(int a);\n"
        "int zcl_gate_probe(int a)\n"
        "{\n"
        "    int unused_on_purpose = a + 1;\n"
        "    switch (a) {\n"
        "    case 1:\n"
        "        a++;\n"
        "    case 2:\n"
        "        a += 2;\n"
        "        break;\n"
        "    default:\n"
        "        break;\n"
        "    }\n"
        "    return a;\n"
        "}\n");
    if (rc)
        return 2;
    if (cps_compile(c, probe) == 0)
        return cps_fail("the flag set ACCEPTED a TU with an unused variable "
                        "and an unannotated switch fall-through. The gate is "
                        "hollow: it would report 'clean' on real violations.");
    char clean[CP_PATH];
    cps_snp(clean, "%s/clean.c", c->work);
    cps_static_write(clean, "int zcl_gate_clean(int a);\n"
                     "int zcl_gate_clean(int a) { return a + 1; }\n");
    if (cps_compile(c, clean) != 0)
        return cps_fail("the flag set REJECTED a trivially clean TU. The gate "
                        "would false-fail every contributor.");
    return 0;
}

/* The first real source other than the identity batch, for the real-compiler
 * leg of the cache proof. */
static int cps_cache_proof(struct cp_ctx *c, const char *self)
{
    int rc = cp_build_flags(c);
    if (!rc)
        rc = cp_scan_sources(c);
    if (rc)
        return rc;
    for (int i = 0; i < c->nsrc; i++)
        if (strcmp(c->srcs[i], "tools/dev/source_identity_batch.c") != 0)
            return cp_tu_cache_selftest(c, self, c->srcs[i]);
    return die("z23-lint: scan set is empty; no real source for the "
               "cache proof\n", "");
}

static int cps_run_all(struct cp_ctx *c)
{
    char self[CP_PATH];
    int rc = cp_build_flags(c);
    if (!rc)
        rc = cps_probe_cases(c);
    if (!rc)
        rc = cps_proven_cases(c);
    if (!rc && lint_self_exe(self, sizeof self) != 0)
        rc = die("z23-lint: cannot locate self\n", "");
    if (!rc)
        rc = cps_cov_selftests(self, c);
    if (rc)
        return rc;
    printf("  OK: --self-test — flag set trips on a violation, passes clean "
           "code;\n      a layer emptied from the Makefile parse is UNPROVEN "
           "exit 2 (not\n      clean, and invisible to SRC_FLOOR), a stale "
           "allowance is exit 1\n");
    rc = cp_digest_selftest(c->work);
    if (rc)
        return rc;
    return cps_cache_proof(c, self);
}

int check_clang_portability_selftest(void)
{
    static struct cp_ctx c;
    int skip = 0;
    int rc = cp_ctx_open(&c, &skip);
    if (rc || skip)
        return rc;
    rc = cp_mkscratch(c.work, sizeof c.work, "z23-lint-clang-port");
    if (rc)
        return rc;
    rc = cps_run_all(&c);
    rap_rm_rf(c.work);
    return rc;
}
