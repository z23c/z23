/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the build phase of check-standalone-tools-link. This is the one
 * lint gate that EXECUTES make, deliberately: a rule's -I paths and object
 * list are only proven by compiling and linking it. The phase runs the
 * gate-receipt helper selftest, starts the hermetic X11 regression suite
 * beside the build (skipped while its stamped inputs are unchanged), builds
 * every covered tool in one `make -k` batch and reports the verdict.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "platform/logical_cpu.h"
#include "lintc.h"
#include "gate_standalone_tools_link_priv.h"
#include "gate_standalone_tools_link_x11_suite.h"

enum { STL_ROW = 160, STL_FAILED = 4, STL_JOBS_DEFAULT = 4, STL_JOBS_MAX = 16 };

static const char k_x11_suite_files[] =
    "tools/lint/lintc/gate_standalone_tools_link_x11_suite.c"
    " tools/lint/lintc/gate_standalone_tools_link_x11_suite_fixture.c"
    " tools/lint/lintc/gate_standalone_tools_link_x11_suite.h";
static const char k_x11_stamp[] = "build/lint-stamps/standalone-x11.sha256";

struct stl_bs {
    char dir[STL_PATH], blog[STL_PATH], xlog[STL_PATH], key[128];
    pid_t xpid;
    int violations, nf;
    char failed[STL_FAILED][STL_ROW];
};

static struct stl_bs g_bs;
/* Nested-suite marker state (see stl_nested_state): 0 unset, 1 honoured, 2 refused. */
static int g_nested;

static void stl_fail_add(struct stl_bs *bs, const char *what)
{
    if (bs->nf < STL_FAILED)
        snprintf(bs->failed[bs->nf++], STL_ROW, "%s", what);
    bs->violations++;
}

static void stl_cleanup(struct stl_bs *bs)
{
    if (bs->xpid > 0) {
        kill(bs->xpid, SIGTERM);
        stl_wait(bs->xpid);
        bs->xpid = 0;
    }
    if (bs->dir[0])
        rap_rm_rf(bs->dir);
}

static int stl_open(struct stl_bs *bs)
{
    memset(bs, 0, sizeof *bs);
    if (stl_mkdtemp(bs->dir, sizeof bs->dir, "z23-lint-standalone-tools") != 0) {
        bs->dir[0] = '\0';
        fprintf(stderr, "%s: cannot create a scratch directory\n", k_stl_gate);
        return 2;
    }
    if (ovf(snprintf(bs->blog, sizeof bs->blog, "%s/build.log", bs->dir), sizeof bs->blog) ||
        ovf(snprintf(bs->xlog, sizeof bs->xlog, "%s/x11.log", bs->dir), sizeof bs->xlog))
        return 2;
    return 0;
}

/* Print a file, each line indented four spaces (sed 's/^/    /'). */
static void stl_dump(FILE *out, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    struct stl_rd r = { .f = f };
    while (stl_rd_next(&r))
        fprintf(out, "    %s\n", r.buf);
    fclose(f);
}

void stl_copy_to(FILE *out, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[4096];
    size_t n;
    if (!f)
        return;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        if (fwrite(buf, 1, n, out) != n)
            break;
    fclose(f);
}

/* The receipt wrapper owns a private build path for agent_sha3: prove that
 * ACTUAL path from an absent output, not only the sibling make rule. */
static void stl_helper_selftest(struct stl_bs *bs, int build_only)
{
    static char out[STL_TEXT];
    int code = 0;
    if (build_only) {
        puts("[check_standalone_tools_link] build-only: skipping the gate-receipt helper");
        puts("[check_standalone_tools_link] self-test — that is a verdict, and the gate");
        puts("[check_standalone_tools_link] still runs it in the lint dimension.");
        return;
    }
    if (capture_cmd("tools/agent/gate-receipt.sh --selftest-helper 2>&1", out,
                    sizeof out, &code) == 0 && code == 0) {
        printf("[check_standalone_tools_link] %s\n", out);
        return;
    }
    fputs("[check_standalone_tools_link] gate-receipt helper selftest failed:\n", stderr);
    fprintf(stderr, "    %s\n", out);
    stl_fail_add(bs, "gate-receipt fresh agent_sha3 helper");
}

/* Hash of every input the X11 selftest reads; empty (always run) on any
 * hashing failure. The lint binary contributes its digest only: sha256sum's
 * own output would add the binary's absolute path and give every worktree a
 * different key. */
void stl_x11_key_in(const char *dir, char *key, size_t cap)
{
    char exe[STL_PATH], qexe[STL_PATH * 2], kin[STL_PATH], qkin[STL_PATH * 2];
    static char cmd[STL_TEXT];
    int code = 0;
    key[0] = '\0';
    if (lint_self_exe(exe, sizeof exe) != 0 || sh_single_quote(exe, qexe, sizeof qexe) != 0 ||
        ovf(snprintf(kin, sizeof kin, "%s/key.in", dir), sizeof kin) ||
        sh_single_quote(kin, qkin, sizeof qkin) != 0)
        return;
    /* make and bash are run through PATH by the suite, so their versions are
     * inputs too; any of these tools failing leaves the key empty (always run). */
    if (ovf(snprintf(cmd, sizeof cmd,
        "{ sha256sum %s && sha256sum %s | cut -c1-64 && find vendor/x11/include -type f | LC_ALL=C sort | xargs sha256sum"
        " && cc --version && make --version && bash --version"
        " && awk '/^NATIVE_UI_DRIVER_BIN = /{a=1} a{if(/^# Crash recovery/)exit;print}'"
        " Makefile; } >%s 2>/dev/null && sha256sum %s | cut -c1-64",
        k_x11_suite_files, qexe, qkin, qkin), sizeof cmd))
        return;
    if (capture_cmd(cmd, key, cap, &code) != 0 || code != 0 || strlen(key) != 64)
        key[0] = '\0';
}

static void stl_x11_key(struct stl_bs *bs)
{
    stl_x11_key_in(bs->dir, bs->key, sizeof bs->key);
}

/* True when the file at path holds exactly key (trailing newlines ignored);
 * a read error is a miss. */
int stl_stamp_file_has(const char *path, const char *key)
{
    char have[128] = "";
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    size_t n = fread(have, 1, sizeof have - 1, f);
    int err = ferror(f);
    fclose(f);
    if (err)
        return 0;
    have[n] = '\0';
    while (n && have[n - 1] == '\n')
        have[--n] = '\0';
    return strcmp(have, key) == 0;
}

/* A fresh worktree has no build/lint-stamps, so the per-tree stamp alone made
 * every fresh stack worktree re-run the whole X11 suite. The key already
 * hashes every input (suite sources, the lint binary, vendored X11 headers,
 * the compiler, the Makefile section), so a pass recorded under the same key
 * in any tree on this host still proves the same thing. The shared stamp is
 * one file per key under the user cache dir; it is never consulted in a
 * nested fixture run, and its absence or any I/O failure is just a miss. */
int stl_shared_stamp_for(const char *key, int nested, char *out, size_t cap)
{
    const char *xdg = getenv("XDG_CACHE_HOME");
    const char *home = getenv("HOME");
    if (nested || !key[0])
        return -1;
    if (xdg && xdg[0] == '/')
        return ovf(snprintf(out, cap, "%s/z23/lint-stamps/standalone-x11.%s", xdg, key), cap)
                   ? -1 : 0;
    if (home && home[0] == '/')
        return ovf(snprintf(out, cap, "%s/.cache/z23/lint-stamps/standalone-x11.%s", home,
                            key), cap) ? -1 : 0;
    return -1;
}

static int stl_shared_stamp_path(const struct stl_bs *bs, char *out, size_t cap)
{
    return stl_shared_stamp_for(bs->key, g_nested, out, cap);
}

int stl_stamp_hit(const char *key, const char *local, int nested)
{
    char shared[STL_PATH];
    if (!key[0])
        return 0;
    if (stl_stamp_file_has(local, key))
        return 1;
    return stl_shared_stamp_for(key, nested, shared, sizeof shared) == 0 &&
           stl_stamp_file_has(shared, key);
}

static int stl_stamp_matches(const struct stl_bs *bs)
{
    return stl_stamp_hit(bs->key, k_x11_stamp, g_nested);
}

/* The suite exports its fixture root in k_stl_x11_nested so the gates it
 * launches stub the suite out. The marker counts only when it names the
 * tree this gate is checking; any other value is an inherited fake and is
 * refused, never skipped. 0 = unset, 1 = honoured, 2 = refused. */
static int stl_nested_state(void)
{
    const char *v = getenv(k_stl_x11_nested);
    char root[STL_PATH], rr[PATH_MAX], vr[PATH_MAX];
    if (!v)
        return 0;
    if (cic_repo_root(root, sizeof root) == 0 && realpath(root, rr) && realpath(v, vr) &&
        strcmp(rr, vr) == 0)
        return 1;
    fprintf(stderr, "[check_standalone_tools_link] %s is set but does not name the tree being"
            " checked; refusing to skip the X11 suite (unset it)\n", k_stl_x11_nested);
    return 2;
}

/* Hermetic X11 failure regressions run BESIDE the build. */
static void stl_x11_start(struct stl_bs *bs)
{
    stl_x11_key(bs);
    if (stl_stamp_matches(bs)) {
        puts("[check_standalone_tools_link] X11 selftest inputs unchanged since last pass; skipped");
        return;
    }
    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(bs->xlog, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
            _exit(127);
        int rc = g_nested ? (puts("fixture-x11-selftest"), 0)
                                          : stl_x11_selftest_run();
        fflush(stdout);
        fflush(stderr);
        _exit(rc);
    }
    if (pid > 0)
        bs->xpid = pid;
    else
        stl_fail_add(bs, "X11 runtime qualification selftest");
}

/* The platform helper is the existing positive-decimal uint32 parser/cap
 * contract. Four is the single native default, preserving the previously
 * effective composed width. Direct absent-override half-grant sizing is
 * deliberately replaced; explicit values still stay exact, never clamped. */
int stl_select_jobs(const char *override, const char *cap, int *out)
{
    uint32_t jobs;
    if (override) {
        jobs = platform_build_job_cap(UINT32_MAX, override);
        if (!jobs || jobs > STL_JOBS_MAX) {
            fprintf(stderr, "%s: FATAL — ZCL_TOOLS_LINK_JOBS must be decimal 1..16 (got '%.80s')\n", k_stl_gate, override);
            return 2;
        }
    } else {
        jobs = STL_JOBS_DEFAULT;
    }
    uint32_t bounded = platform_build_job_cap(jobs, cap);
    if (!bounded) {
        fprintf(stderr, "%s: FATAL — ZCL_BUILD_MAX_JOBS must be a positive decimal uint32 (got '%.80s')\n", k_stl_gate, cap ? cap : "");
        return 2;
    }
    if (override && bounded != jobs) {
        fprintf(stderr, "%s: FATAL — ZCL_TOOLS_LINK_JOBS request %.80s exceeds ZCL_BUILD_MAX_JOBS cap %.80s\n", k_stl_gate, override, cap);
        return 2;
    }
    *out = (int)bounded;
    return 0;
}

/* One -k batch keeps the original failure context in a single log. */
static int stl_run_make(const char *log, char (*targets)[STL_TGT], int nt, int jobs)
{
    if (jobs < 1 || jobs > STL_JOBS_MAX || nt < 1 || nt > STL_MAX)
        return -1;
    static char *av[STL_MAX + 8];
    char jarg[24];
    snprintf(jarg, sizeof jarg, "-j%d", jobs);
    int ac = 0;
    av[ac++] = (char *)"make";
    av[ac++] = (char *)"-k";
    av[ac++] = jarg;
    av[ac++] = (char *)"--no-print-directory";
    for (int i = 0; i < nt && ac < STL_MAX + 7; i++)
        av[ac++] = targets[i];
    av[ac] = NULL;
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
            _exit(127);
        execvp("make", av);
        _exit(127);
    }
    return stl_wait(pid);
}

static int stl_log_has(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    struct stl_rd r = { .f = f };
    int hit = 0;
    while (!hit && stl_rd_next(&r))
        hit = strstr(r.buf, needle) != NULL;
    fclose(f);
    return hit;
}

static void stl_x11_finish(struct stl_bs *bs)
{
    if (bs->xpid <= 0)
        return;
    int rc = stl_wait(bs->xpid);
    bs->xpid = 0;
    if (rc == 0) {
        stl_copy_to(stdout, bs->xlog);
        if (bs->key[0]) {
            char shared[STL_PATH];
            csr_write(k_x11_stamp, bs->key);
            if (stl_shared_stamp_path(bs, shared, sizeof shared) == 0)
                csr_write(shared, bs->key);
        }
        return;
    }
    stl_copy_to(stderr, bs->xlog);
    stl_fail_add(bs, "X11 runtime qualification selftest");
}

/* --build-only: a tool that would not link is still a hard failure, but the
 * verdict prose belongs to the run inside `make lint`, not to a pre-build. */
static int stl_build_only_verdict(const struct stl_bs *bs, int nt)
{
    if (bs->violations == 0) {
        printf("[check_standalone_tools_link] build-only: %d tool target(s) built\n", nt);
        return 0;
    }
    fputs("[check_standalone_tools_link] build-only: BUILD OUTPUT:\n", stderr);
    stl_dump(stderr, bs->blog);
    for (int i = 0; i < bs->nf; i++)
        fprintf(stderr, "    %s\n", bs->failed[i]);
    fprintf(stderr, "check-standalone-tools-link --build-only: %d check(s) failed\n",
            bs->violations);
    return 1;
}

static int stl_verdict(const struct stl_bs *bs, const char *mode)
{
    if (bs->violations > 0) {
        puts("[check_standalone_tools_link] BUILD OUTPUT:");
        stl_dump(stdout, bs->blog);
        puts("[check_standalone_tools_link] failed check(s):");
        for (int i = 0; i < bs->nf; i++)
            printf("    %s\n", bs->failed[i]);
    }
    printf("[check_standalone_tools_link] %d violation(s) found (mode: %s)\n",
           bs->violations, mode);
    puts("[check_standalone_tools_link] a Makefile tool rule that nothing else");
    puts("[check_standalone_tools_link] builds rots silently — fix the rule's -I");
    puts("[check_standalone_tools_link] paths / object list, or add the tool to the");
    puts("[check_standalone_tools_link] EXEMPT set in this script WITH a reason.");
    return bs->violations > 0 && strcmp(mode, "FAIL") == 0 ? 1 : 0;
}

static int stl_phase(struct stl_bs *bs, char (*targets)[STL_TGT], int nt,
                     int build_only, const char *mode, int host_linux, int jobs)
{
    stl_helper_selftest(bs, build_only);
    if (!build_only && host_linux)
        stl_x11_start(bs);
    if (stl_run_make(bs->blog, targets, nt, jobs) != 0) {
        if (stl_log_has(bs->blog, "exact source capture failed")) {
            stl_dump(stderr, bs->blog);
            fputs("[check_standalone_tools_link] source-identity capture refused, so make could"
                  " not parse. This is NOT a broken tool rule; re-run on a settled tree.\n",
                  stderr);
            return 2;
        }
        stl_fail_add(bs, "standalone tool build batch (see build output)");
    }
    if (build_only)
        return stl_build_only_verdict(bs, nt);
    stl_x11_finish(bs);
    return stl_verdict(bs, mode);
}

int stl_build_phase(char (*targets)[STL_TGT], int nt, int build_only,
                    const char *mode, int host_linux)
{
    int jobs = 0;
    int selected = stl_select_jobs(getenv("ZCL_TOOLS_LINK_JOBS"),
        getenv("ZCL_BUILD_MAX_JOBS"), &jobs);
    if (selected != 0) return selected;
    g_nested = stl_nested_state();
    if (g_nested == 2)
        return 2;
    if (stl_open(&g_bs) != 0) {
        stl_cleanup(&g_bs);
        return 2;
    }
    int rc = stl_phase(&g_bs, targets, nt, build_only, mode, host_linux, jobs);
    stl_cleanup(&g_bs);
    return rc;
}
