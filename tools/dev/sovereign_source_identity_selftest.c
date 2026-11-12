/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove the Git-free ZVCS adapter accepts one authorized root,
 *          refuses an ABA mutation, and refuses a disagreeing bootstrap. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include "sovereign_source_identity_selftest.h"

#include <stdio.h>
#include <string.h>

static int ssi_fail(const char *msg)
{
    fprintf(stderr, "sovereign-source-identity-selftest: FAIL: %s\n", msg);
    return 1;
}

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char k_ssi_root[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char k_ssi_bad[] =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static const char k_ssi_src[] = "int sovereign(void) { return 23; }\n";
static const char k_ssi_make[] = "all:\n\t@true\n";
static const char k_ssi_boot[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "printf \"{\\\"schema\\\":\\\"zcl.result.v1\\\",\\\"ok\\\":true,"
    "\\\"data\\\":{\\\"source_root\\\":\\\"%s\\\"}}\\n\" "
    "\"$FAKE_SOURCE_ROOT\"\n";
static const char k_ssi_git[] = "#!/usr/bin/env bash\nexit 97\n";

struct ssi_fx {
    char sandbox[PATH_MAX];
    char source[PATH_MAX];
    char script[PATH_MAX];
    char bootstrap[PATH_MAX];
    char identity[80];
    char complete[16];
    char mutation[80];
    char path_env[8192];
};

static int ssi_put(const char *path, const char *text)
{
    size_t n = strlen(text);
    FILE *file = fopen(path, "w");
    size_t wrote;
    if (file == NULL)
        return -1;
    wrote = fwrite(text, 1, n, file);
    if (wrote != n || fclose(file) != 0)
        return -1;
    return 0;
}

static int ssi_mkdir(const char *path)
{
    return mkdir(path, 0700) == 0 ? 0 : -1;
}

static int ssi_hex64(const char *text)
{
    size_t i;
    if (text == NULL)
        return 0;
    for (i = 0; i < 64; i++) {
        char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return text[64] == '\0';
}

static int ssi_take(const char **cursor, char *out, size_t cap)
{
    const char *s = *cursor;
    size_t n = 0;
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == '\0' || *s == '\n')
        return 0;
    while (s[n] != '\0' && s[n] != ' ' && s[n] != '\t' && s[n] != '\n')
        n++;
    if (n + 1 > cap)
        return 0;
    memcpy(out, s, n);
    out[n] = '\0';
    *cursor = s + n;
    return 1;
}

static int ssi_reap(pid_t pid)
{
    int status = 1;
    for (;;) {
        pid_t got = waitpid(pid, &status, 0);
        if (got == pid)
            break;
        if (errno != EINTR)
            return 1;
    }
    if (!WIFEXITED(status))
        return 1;
    return WEXITSTATUS(status);
}

static void ssi_slurp(int fd, char *out, size_t cap)
{
    size_t used = 0;
    if (out == NULL || cap == 0)
        return;
    for (;;) {
        char scratch[128];
        ssize_t n = read(fd, scratch, sizeof scratch);
        size_t i = 0;
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        while (i < (size_t)n && used + 1 < cap)
            out[used++] = scratch[i++];
    }
    out[used] = '\0';
}

static void ssi_child(const char *cwd, char *const argv[], const char *path_env,
                      const char *verify_bin, const char *fake, int out_fd)
{
    int sink;
    if (chdir(cwd) != 0 || dup2(out_fd, STDOUT_FILENO) < 0)
        _exit(127);
    sink = open("/dev/null", O_WRONLY);
    if (sink >= 0) {
        (void)dup2(sink, STDERR_FILENO);
        close(sink);
    }
    close(out_fd);
    if (setenv("ZCL_SOVEREIGN_SOURCE_ROOT", k_ssi_root, 1) != 0 ||
        setenv("ZCL_SOVEREIGN_VERIFY_BIN", verify_bin, 1) != 0 ||
        setenv("FAKE_SOURCE_ROOT", fake, 1) != 0 ||
        setenv("PATH", path_env, 1) != 0)
        _exit(127);
    unsetenv("ZCL_SOURCE_IDENTITY_SESSION");
    execv(argv[0], argv);
    _exit(127);
}

static int ssi_run(const struct ssi_fx *fx, char *const argv[],
                   const char *verify_bin, const char *fake, char *out,
                   size_t cap, int *status)
{
    int fds[2];
    pid_t pid;
    if (pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0)
        ssi_child(fx->source, argv, fx->path_env, verify_bin, fake, fds[1]);
    close(fds[1]);
    ssi_slurp(fds[0], out, cap);
    close(fds[0]);
    *status = ssi_reap(pid);
    return 0;
}

static int ssi_join(char *out, size_t cap, const char *dir, const char *name)
{
    return snprintf(out, cap, "%s/%s", dir, name) < (int)cap ? 0 : -1;
}

static int ssi_sandbox(struct ssi_fx *fx)
{
    const char *tmp = getenv("TMPDIR");
    char templ[PATH_MAX];
    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    if (snprintf(templ, sizeof templ,
                 "%s/zcl-sovereign-identity-selftest.XXXXXX", tmp) >=
        (int)sizeof templ)
        return ssi_fail("sandbox path is too long");
    if (mkdtemp(templ) == NULL)
        return ssi_fail("sandbox could not be created");
    memcpy(fx->sandbox, templ, strlen(templ) + 1);
    return 0;
}

static int ssi_layout(struct ssi_fx *fx, char *app, size_t app_cap, char *bin,
                      size_t bin_cap, char *git, size_t git_cap,
                      char *gitmeta, size_t gitmeta_cap)
{
    if (ssi_join(fx->source, sizeof fx->source, fx->sandbox, "source") != 0)
        return -1;
    if (ssi_join(bin, bin_cap, fx->sandbox, "bin") != 0)
        return -1;
    if (ssi_join(app, app_cap, fx->source, "app") != 0)
        return -1;
    if (ssi_join(fx->bootstrap, sizeof fx->bootstrap, bin, "bootstrap") != 0)
        return -1;
    if (ssi_join(git, git_cap, bin, "git") != 0)
        return -1;
    if (ssi_join(gitmeta, gitmeta_cap, fx->source, ".git") != 0)
        return -1;
    return 0;
}

static int ssi_write_tree(struct ssi_fx *fx, const char *app, const char *bin,
                          const char *git)
{
    char file[PATH_MAX];
    if (ssi_mkdir(fx->source) != 0 || ssi_mkdir(app) != 0 || ssi_mkdir(bin) != 0)
        return -1;
    if (ssi_join(file, sizeof file, app, "a.c") != 0)
        return -1;
    if (ssi_put(file, k_ssi_src) != 0 || ssi_put(git, k_ssi_git) != 0)
        return -1;
    if (ssi_put(fx->bootstrap, k_ssi_boot) != 0)
        return -1;
    if (ssi_join(file, sizeof file, fx->source, "Makefile") != 0)
        return -1;
    if (ssi_put(file, k_ssi_make) != 0)
        return -1;
    if (chmod(fx->bootstrap, 0755) != 0 || chmod(git, 0755) != 0)
        return -1;
    return 0;
}

static int ssi_store_path(struct ssi_fx *fx, const char *bin)
{
    const char *old_path = getenv("PATH");
    int n;
    if (old_path != NULL && old_path[0] != '\0')
        n = snprintf(fx->path_env, sizeof fx->path_env, "%s:%s", bin, old_path);
    else
        n = snprintf(fx->path_env, sizeof fx->path_env, "%s", bin);
    if (n < 0 || n >= (int)sizeof fx->path_env)
        return ssi_fail("sandbox PATH is too long");
    return 0;
}

static int ssi_prepare(struct ssi_fx *fx, const char *script_path)
{
    char app[PATH_MAX];
    char bin[PATH_MAX];
    char git[PATH_MAX];
    char gitmeta[PATH_MAX];
    if (script_path == NULL || realpath(script_path, fx->script) == NULL)
        return ssi_fail("source-identity.sh is unavailable");
    if (ssi_sandbox(fx) != 0)
        return 1;
    if (ssi_layout(fx, app, sizeof app, bin, sizeof bin, git, sizeof git,
                   gitmeta, sizeof gitmeta) != 0)
        return ssi_fail("sandbox path is too long");
    if (ssi_write_tree(fx, app, bin, git) != 0)
        return ssi_fail("sandbox fixture could not be written");
    if (access(gitmeta, F_OK) == 0)
        return ssi_fail("fixture unexpectedly has Git metadata");
    return ssi_store_path(fx, bin);
}

static void ssi_cleanup(struct ssi_fx *fx)
{
    pid_t pid;
    char *argv[4];
    if (fx->sandbox[0] == '\0')
        return;
    argv[0] = "rm";
    argv[1] = "-rf";
    argv[2] = fx->sandbox;
    argv[3] = NULL;
    pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    if (pid > 0)
        (void)ssi_reap(pid);
}

static int ssi_check_capture(struct ssi_fx *fx)
{
    char out[256];
    int status = 1;
    char *argv[] = {fx->script, "capture", NULL};
    if (ssi_run(fx, argv, fx->bootstrap, k_ssi_root, out, sizeof out,
                &status) != 0)
        return ssi_fail("capture could not run");
    if (out[0] != '\0' && out[strlen(out) - 1] == '\n')
        out[strlen(out) - 1] = '\0';
    if (status != 0 || strcmp(out, k_ssi_root) != 0)
        return ssi_fail("capture did not use ZVCS authority");
    return 0;
}

static int ssi_read_record(struct ssi_fx *fx, const char *line)
{
    const char *cursor = line;
    if (ssi_take(&cursor, fx->identity, sizeof fx->identity) == 0 ||
        ssi_take(&cursor, fx->complete, sizeof fx->complete) == 0 ||
        ssi_take(&cursor, fx->mutation, sizeof fx->mutation) == 0)
        return -1;
    if (strcmp(fx->identity, k_ssi_root) != 0 || strcmp(fx->complete, "1") != 0)
        return -1;
    return ssi_hex64(fx->mutation) ? 0 : -1;
}

static int ssi_check_record(struct ssi_fx *fx)
{
    char out[512];
    int status = 1;
    char *argv[] = {fx->script, "capture-record", NULL};
    if (ssi_run(fx, argv, fx->bootstrap, k_ssi_root, out, sizeof out,
                &status) != 0 ||
        status != 0)
        return ssi_fail("capture-record failed");
    if (ssi_read_record(fx, out) != 0)
        return ssi_fail("capture-record shape is invalid");
    return 0;
}

static int ssi_verify_record(struct ssi_fx *fx, int *status)
{
    char out[512];
    char *argv[] = {fx->script, "verify-record", fx->identity, fx->complete,
                    fx->mutation, NULL};
    return ssi_run(fx, argv, fx->bootstrap, k_ssi_root, out, sizeof out, status);
}

static int ssi_check_verify(struct ssi_fx *fx)
{
    int status = 1;
    if (ssi_verify_record(fx, &status) != 0 || status != 0)
        return ssi_fail("unchanged sovereign record did not verify");
    return 0;
}

static int ssi_rewrite(struct ssi_fx *fx)
{
    char path[PATH_MAX];
    FILE *file;
    if (ssi_join(path, sizeof path, fx->source, "app/a.c") != 0)
        return -1;
    file = fopen(path, "a");
    if (file == NULL)
        return -1;
    if (fputs("transient\n", file) < 0 || fclose(file) != 0)
        return -1;
    return ssi_put(path, k_ssi_src);
}

static int ssi_check_aba(struct ssi_fx *fx)
{
    int status = 0;
    if (ssi_rewrite(fx) != 0)
        return ssi_fail("ABA fixture could not be rewritten");
    if (ssi_verify_record(fx, &status) != 0)
        return ssi_fail("ABA verify could not run");
    if (status == 0)
        return ssi_fail("edit/revert ABA retained a stale mutation receipt");
    return 0;
}

static int ssi_check_refresh(struct ssi_fx *fx)
{
    char out[512];
    int status = 1;
    char *record_argv[] = {fx->script, "capture-record", NULL};
    char *mutation_argv[4];
    if (ssi_run(fx, record_argv, fx->bootstrap, k_ssi_root, out, sizeof out,
                &status) != 0 ||
        status != 0)
        return ssi_fail("refreshed capture-record failed");
    if (ssi_read_record(fx, out) != 0)
        return ssi_fail("refreshed capture-record shape is invalid");
    mutation_argv[0] = fx->script;
    mutation_argv[1] = "verify-mutation";
    mutation_argv[2] = fx->mutation;
    mutation_argv[3] = NULL;
    if (ssi_run(fx, mutation_argv, fx->bootstrap, k_ssi_root, out, sizeof out,
                &status) != 0 ||
        status != 0)
        return ssi_fail("current sovereign mutation did not verify");
    return 0;
}

static int ssi_check_disagree(struct ssi_fx *fx)
{
    char out[256];
    int status = 0;
    char *argv[] = {fx->script, "capture", NULL};
    if (ssi_run(fx, argv, fx->bootstrap, k_ssi_bad, out, sizeof out,
                &status) != 0)
        return ssi_fail("authority disagreement check could not run");
    if (status == 0)
        return ssi_fail("bootstrap/source authority disagreement was accepted");
    return 0;
}

static int ssi_check_missing(struct ssi_fx *fx)
{
    char missing[PATH_MAX];
    char out[256];
    int status = 0;
    char *argv[] = {fx->script, "capture", NULL};
    if (ssi_join(missing, sizeof missing, fx->sandbox, "bin/missing") != 0)
        return ssi_fail("missing bootstrap path is too long");
    if (ssi_run(fx, argv, missing, k_ssi_root, out, sizeof out, &status) != 0)
        return ssi_fail("missing bootstrap check could not run");
    if (status == 0)
        return ssi_fail("missing bootstrap verifier was accepted");
    return 0;
}

static int ssi_prove(struct ssi_fx *fx)
{
    if (ssi_check_capture(fx) != 0)
        return 1;
    if (ssi_check_record(fx) != 0)
        return 1;
    if (ssi_check_verify(fx) != 0)
        return 1;
    if (ssi_check_aba(fx) != 0)
        return 1;
    if (ssi_check_refresh(fx) != 0)
        return 1;
    if (ssi_check_disagree(fx) != 0)
        return 1;
    return ssi_check_missing(fx);
}
#endif

int zcl_sovereign_source_identity_selftest(const char *script_path)
{
#if defined(_WIN32)
    (void)script_path;
    return ssi_fail("unsupported platform");
#else
    struct ssi_fx fx;
    int rc;
    memset(&fx, 0, sizeof fx);
    rc = ssi_prepare(&fx, script_path);
    if (rc == 0)
        rc = ssi_prove(&fx);
    ssi_cleanup(&fx);
    if (rc == 0)
        printf("sovereign-source-identity-selftest: PASS root=%s "
               "git_contacted=false aba_refused=true\n",
               k_ssi_root);
    return rc;
#endif
}
