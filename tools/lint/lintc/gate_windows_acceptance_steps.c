/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the make-driving steps of the check-windows-acceptance gate:
 * the compile step (cross-link every catalog row, or UNOBSERVED without
 * mingw), the split --global mode (reconcile plus a make -n plan of the
 * whole cross-link) and --row=ID (cross-link exactly the named rows in a
 * fresh output directory), plus the fork+execvp spawn helper and the
 * cross-link job count. Ported from tools/lint/check_windows_acceptance.sh
 * (deleted). No system(), no popen(): the child always clears MAKEFLAGS
 * and names its own -j count so a dead inherited jobserver cannot force a
 * serial cross-link.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_windows_acceptance_priv.h"

static const char k_was_gate[] = "check-windows-acceptance";
static char wa_cap[WA_TEXT]; /* make -n capture for the --global fail path */

int wa_repo_root(char *buf, size_t cap)
{
    if (getcwd(buf, cap))
        return 0;
    if (ovf(snprintf(buf, cap, "."), cap))
        return 2;
    return 0;
}

/* Runs argv[0] with execvp. The child always drops MAKEFLAGS. quiet sends
 * the child's stdout and stderr to /dev/null; capture pipes them into out
 * instead. Returns 0 with the exit status in code, non-zero on failure. */
/* Reads everything from fd into out, NUL-terminated, up to cap-1 bytes. */
static void wa_drain(int fd, char *out, size_t cap)
{
    size_t got = 0;
    ssize_t r;
    while (got + 1 < cap && (r = read(fd, out + got, cap - 1 - got)) > 0)
        got += (size_t)r;
    out[got] = '\0';
}

/* Waits for pid, retrying on EINTR. Any other waitpid failure is -1. */
static int wa_wait_child(pid_t pid, int *st)
{
    for (;;) {
        pid_t w = waitpid(pid, st, 0);
        if (w == pid)
            return 0;
        if (w < 0 && errno == EINTR)
            continue;
        return -1;
    }
}

int wa_spawn(char *const argv[], int quiet, int capture, char *out, size_t cap,
             int *code)
{
    int fds[2] = { -1, -1 };
    if (capture && pipe(fds))
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        if (capture) {
            close(fds[0]);
            close(fds[1]);
        }
        return -1;
    }
    if (pid == 0) {
        unsetenv("MAKEFLAGS");
        if (capture) {
            dup2(fds[1], 1);
            dup2(fds[1], 2);
            close(fds[0]);
            close(fds[1]);
        } else if (quiet) {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) {
                dup2(dn, 1);
                dup2(dn, 2);
            }
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (capture) {
        close(fds[1]);
        wa_drain(fds[0], out, cap);
        close(fds[0]);
    }
    int st = 0;
    if (wa_wait_child(pid, &st))
        return -1;
    *code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
    return 0;
}

static int wa_in_path(const char *name)
{
    if (strchr(name, '/'))
        return access(name, X_OK) == 0;
    const char *path = getenv("PATH");
    if (!path || !path[0])
        return 0;
    static char dup[8192];
    if (ovf(snprintf(dup, sizeof dup, "%s", path), sizeof dup))
        return 0;
    char *save = NULL;
    for (char *dir = strtok_r(dup, ":", &save); dir;
         dir = strtok_r(NULL, ":", &save)) {
        char p[WA_PATH];
        if (ovf(snprintf(p, sizeof p, "%s/%s", dir, name), sizeof p))
            continue;
        if (access(p, X_OK) == 0)
            return 1;
    }
    return 0;
}

static const char *wa_cc(void)
{
    return env_or("ZCL_WINDOWS_ACCEPTANCE_CC", "x86_64-w64-mingw32-gcc");
}

static const char *wa_compile_target(void)
{
    struct utsname u;
    if (uname(&u) == 0) {
        if (!strncmp(u.sysname, "MINGW", 5) || !strncmp(u.sysname, "MSYS", 4) ||
            !strncmp(u.sysname, "CYGWIN", 6))
            return "windows-acceptance";
    }
    return "windows-acceptance-compile";
}

static int wa_num(const char *s)
{
    if (!s || !s[0])
        return 0;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return 0;
    return 1;
}

int wa_cross_link_jobs(void)
{
    const char *h = getenv("ZCL_HOST_JOBS");
    long v;
    if (wa_num(h)) {
        v = atol(h);
    } else {
        v = sysconf(_SC_NPROCESSORS_ONLN);
        if (v <= 0)
            v = 8;
    }
    v /= 2;
    if (v < 4)
        v = 4;
    if (v > 16)
        v = 16;
    return (int)v;
}

int wa_compile_step_io(FILE *out, FILE *err, int quiet)
{
    /* Child make writes to fd 1 directly: flush so the reconcile line
     * already printed lands before the cross-link output, as in the shell. */
    fflush(out);
    const char *cc = wa_cc();
    if (!wa_in_path(cc)) {
        if (!strcmp(env_or("ZCL_REQUIRE_MINGW", "0"), "1")) {
            fprintf(err,
                    "check-windows-acceptance: FAIL (required compiler %s is unavailable)\n",
                    cc);
            return 2;
        }
        fprintf(out,
                "check-windows-acceptance: UNOBSERVED (%s not installed; reconcile still ran and PASSED)\n",
                cc);
        return 0;
    }
    static char root[WA_PATH], js[16];
    if (wa_repo_root(root, sizeof root))
        return 2;
    if (ovf(snprintf(js, sizeof js, "-j%d", wa_cross_link_jobs()), sizeof js))
        return 2;
    char *av[8];
    int i = 0, code = 0;
    av[i++] = (char *)"make";
    av[i++] = (char *)"-C";
    av[i++] = root;
    av[i++] = js;
    av[i++] = (char *)"--no-print-directory";
    av[i++] = (char *)wa_compile_target();
    av[i] = NULL;
    if (wa_spawn(av, quiet, 0, NULL, 0, &code)) {
        fprintf(err, "%s: FAIL (cannot run make)\n", k_was_gate);
        return 2;
    }
    return code;
}

static void wa_print_tail(FILE *out, const char *buf, int keep)
{
    int n = 0;
    size_t pos = 0;
    char line[WA_LINE];
    while (wa_next_line(buf, &pos, line, sizeof line) == 1)
        n++;
    int start = n - keep;
    if (start < 0)
        start = 0;
    pos = 0;
    int i = 0;
    while (wa_next_line(buf, &pos, line, sizeof line) == 1)
        if (i++ >= start)
            fprintf(out, "    %s\n", line);
}

int wa_global_main_io(FILE *out)
{
    const char *env = getenv("ZCL_WINDOWS_ACCEPTANCE_ROOT");
    static char rbuf[WA_PATH], root[WA_PATH], vdir[WA_PATH + 64];
    const char *use = rbuf;
    if (env && env[0]) {
        use = env;
    } else if (wa_repo_root(rbuf, sizeof rbuf)) {
        return 2;
    }
    if (wa_reconcile_root(use, out))
        return 1;
    if (wa_repo_root(root, sizeof root))
        return 2;
    if (ovf(snprintf(vdir + 0, sizeof vdir, "ZCL_WINDOWS_ACCEPTANCE_DIR=%s/build/tests/windows-plan",
                     root), sizeof vdir))
        return 2;
    char *av[8] = { (char *)"make", (char *)"-C", root, (char *)"-n",
                    (char *)"--no-print-directory", vdir,
                    (char *)"windows-acceptance-compile", NULL };
    int code = 0;
    if (wa_spawn(av, 0, 1, wa_cap, sizeof wa_cap, &code))
        return 1;
    if (code != 0) {
        fprintf(out,
                "check-windows-acceptance: FAIL: make cannot plan the cross-link:\n");
        wa_print_tail(out, wa_cap, 20);
        return 1;
    }
    fprintf(out,
            "check-windows-acceptance: global PASS — make plans the cross-link of every catalog row\n");
    return 0;
}

static int wa_rows_check(const struct wa_ids *ids, const char *dir, FILE *err,
                         FILE *out);

static int wa_compile_rows(const struct wa_ids *ids, FILE *out, FILE *err)
{
    const char *cc = wa_cc();
    if (!wa_in_path(cc)) {
        if (!strcmp(env_or("ZCL_REQUIRE_MINGW", "0"), "1")) {
            fprintf(err,
                    "check-windows-acceptance: FAIL (required compiler %s is unavailable)\n",
                    cc);
            return 2;
        }
        fprintf(out,
                "check-windows-acceptance: UNOBSERVED (%s not installed; no row was cross-linked)\n",
                cc);
        return 0;
    }
    static char root[WA_PATH], dir[WA_PATH], js[16];
    static char vdir[WA_PATH + 64];
    static char *av[8 + WA_IDS];
    static char tgt[WA_IDS][WA_PATH + 8];
    if (wa_repo_root(root, sizeof root))
        return 2;
    if (ovf(snprintf(dir, sizeof dir, "%s/build/tests/windows-rows", root),
            sizeof dir))
        return 2;
    if (ovf(snprintf(js, sizeof js, "-j%d", wa_cross_link_jobs()), sizeof js))
        return 2;
    if (ovf(snprintf(vdir, sizeof vdir, "ZCL_WINDOWS_ACCEPTANCE_DIR=%s", dir),
            sizeof vdir))
        return 2;
    rap_rm_rf(dir);
    int i = 0, code = 0;
    av[i++] = (char *)"make";
    av[i++] = (char *)"-C";
    av[i++] = root;
    av[i++] = js;
    av[i++] = (char *)"--no-print-directory";
    av[i++] = vdir;
    for (int k = 0; k < ids->n; k++) {
        if (ovf(snprintf(tgt[k], sizeof tgt[k], "%s/%s.exe", dir, ids->v[k]),
                sizeof tgt[k]))
            return 2;
        av[i++] = tgt[k];
    }
    av[i] = NULL;
    if (wa_spawn(av, 0, 0, NULL, 0, &code)) {
        fprintf(err, "%s: FAIL (cannot run make)\n", k_was_gate);
        return 2;
    }
    if (code != 0)
        return 1;
    return wa_rows_check(ids, dir, err, out);
}

/* Verifies each produced binary is present and non-empty, then reports. */
static int wa_rows_check(const struct wa_ids *ids, const char *dir, FILE *err,
                         FILE *out)
{
    struct stat st;
    char p[WA_PATH + 64];
    for (int k = 0; k < ids->n; k++) {
        if (ovf(snprintf(p, sizeof p, "%s/%s.exe", dir, ids->v[k]), sizeof p))
            return 2;
        if (stat(p, &st) != 0 || st.st_size <= 0) {
            fprintf(err, "check-windows-acceptance: FAIL: missing/empty %s\n",
                    p);
            return 1;
        }
    }
    fprintf(out, "check-windows-acceptance: rows cross-link PASS (%d row(s))\n",
            ids->n);
    return 0;
}

int wa_rows_main_io(int argc, char **argv, FILE *out, FILE *err)
{
    static char root[WA_PATH];
    static struct wa_ids known, ids;
    memset(&known, 0, sizeof known);
    memset(&ids, 0, sizeof ids);
    if (wa_repo_root(root, sizeof root))
        return 2;
    if (wa_catalog_tests(root, &known))
        known.n = 0;
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        const char *id = strncmp(arg, "--row=", 6) ? "" : arg + 6;
        if (!id[0] || !wa_ids_has(&known, id)) {
            fprintf(err,
                    "check-windows-acceptance: REFUSE: '%s' does not name an active catalog row\n",
                    arg);
            return 2;
        }
        if (ids.n >= WA_IDS || ovf(snprintf(ids.v[ids.n], WA_ID, "%s", id), WA_ID)) {
            fprintf(err, "check-windows-acceptance: too many --row IDs\n");
            return 2;
        }
        ids.n++;
    }
    return wa_compile_rows(&ids, out, err);
}
