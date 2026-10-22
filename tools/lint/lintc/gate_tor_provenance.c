/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family - check-tor-provenance of the C23 lint runtime, the
 * replacement for the bash body of tools/lint/lintc/gate_tor_provenance.c. The
 * bundled Tor archives are bound to the vendor/tor commit, the archive bytes
 * and the compiler that built them (tools/tor_provenance.c). The gate
 *
 *   1. compiles tools/tor_provenance.c with -fsyntax-only twice, with and
 *      without the base include path, using the same CC command prefix Make
 *      executes, and hands both statuses and logs to z23-tor-provenance;
 *   2. runs the helper's own --selftest;
 *   3. judges the manifest against the vendor/tor commit and the compiler
 *      identity derived exactly as the writer derives it
 *      (tools/dev/build-epoch-key.sh compiler-bytes-id).
 *
 * SIGINT, SIGTERM and SIGHUP stop the running child, remove the scratch
 * directory and are re-raised. Selftest: gate_tor_provenance_selftest.c.
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "gate_tor_provenance_priv.h"
#include "lintc.h"
#include "lintc_sig.h"

struct tp_ctx {
    char root[TP_PATH];
    char work[TP_PATH + 32];
    char pos_log[TP_PATH + 64];
    char neg_log[TP_PATH + 64];
    char out[TP_PATH + 64];
    int grace_ms;
};

static void tp_sleep_ms(long ms)
{
    struct timespec ts = { 0, ms * 1000000L };
    nanosleep(&ts, NULL);
}

static int tp_code(int st)
{
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}

static void tp_child(char *const argv[], const char *out, int merge_err)
{
    lsc_reset_in_child();
    if (out) {
        int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || dup2(fd, 1) < 0 || (merge_err && dup2(fd, 2) < 0))
            _exit(127);
        close(fd);
    }
    execvp(argv[0], argv);
    static const char msg[] = "z23-lint: check-tor-provenance: cannot execute a child\n";
    (void)!write(2, msg, sizeof msg - 1);
    _exit(127);
}

/* Waits up to grace_ms for pid, then kills it; always reaps. */
static void tp_stop_child(pid_t pid, int sig, int grace_ms)
{
    int st;
    kill(pid, sig);
    for (int waited = 0; waited < grace_ms; waited += 10) {
        if (waitpid(pid, &st, WNOHANG) == pid)
            return;
        tp_sleep_ms(10);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
}

/* Returns 0 with *code set, 1 when a termination signal interrupted the
 * child, -1 when the child could not be started. Signals are blocked except
 * while sleeping, so none can arrive between the check and the wait. */
static int tp_wait(pid_t pid, int grace_ms, int *code)
{
    for (;;) {
        int st;
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) {
            *code = tp_code(st);
            return 0;
        }
        if (r < 0 && errno != EINTR)
            return -1;
        if (lsc_pending()) {
            tp_stop_child(pid, lsc_pending(), grace_ms);
            return 1;
        }
        lsc_unblock();
        tp_sleep_ms(5);
        lsc_block();
    }
}

static int tp_run(const struct tp_ctx *c, char *const argv[], const char *out,
                  int merge_err, int *code)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
        tp_child(argv, out, merge_err);
    return tp_wait(pid, c->grace_ms, code);
}

/* The POSIX default scratch parent when TMPDIR is unset. */
static const char k_tp_default_tmp[] = { '/', 't', 'm', 'p', '\0' };

static int tp_open_work(struct tp_ctx *c, const char *root, int grace_ms)
{
    const char *tmp = env_or("TMPDIR", k_tp_default_tmp);
    memset(c, 0, sizeof *c);
    c->grace_ms = grace_ms;
    if (snprintf(c->root, sizeof c->root, "%s", root) >= (int)sizeof c->root
        || snprintf(c->work, sizeof c->work, "%s/tor-compiler.XXXXXX", tmp) >= (int)sizeof c->work
        || !mkdtemp(c->work))
        return -1;
    snprintf(c->pos_log, sizeof c->pos_log, "%s/positive.log", c->work);
    snprintf(c->neg_log, sizeof c->neg_log, "%s/negative.log", c->work);
    snprintf(c->out, sizeof c->out, "%s/output.txt", c->work);
    return 0;
}

static void tp_cleanup(struct tp_ctx *c)
{
    lsc_block();
    unlink(c->pos_log);
    unlink(c->neg_log);
    unlink(c->out);
    rmdir(c->work);
}

/* The compiler command is the trusted CC prefix Make executes, including
 * wrappers and quoted paths; the fixture arguments travel separately. */
static int tp_compile(const struct tp_ctx *c, const char *extra, const char *log, int *code)
{
    static const char *const fixed[] = {
        "compiler", "-std=c23", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
        "-D_POSIX_C_SOURCE=200809L", "-D_DARWIN_C_SOURCE",
        "-Icontexts/commons/packages/zsha256/include",
        "-Iplatform/modules/platform/include", "-fsyntax-only",
        "tools/tor_provenance.c" };
    char script[8192], *argv[sizeof fixed / sizeof fixed[0] + 5];
    int n = 0;
    if (snprintf(script, sizeof script, "exec %s \"$@\"", env_or("CC", "cc")) >= (int)sizeof script)
        return -1;
    argv[n++] = (char *)"sh";
    argv[n++] = (char *)"-c";
    argv[n++] = script;
    for (size_t i = 0; i < sizeof fixed / sizeof fixed[0]; i++)
        argv[n++] = (char *)fixed[i];
    if (extra)
        argv[n++] = (char *)extra;
    argv[n] = NULL;
    return tp_run(c, argv, log, 1, code);
}

int tp_cc_from_line(const char *line, char *out, size_t cap)
{
    const char *p = line;
    if (strncmp(p, "CC", 2) != 0)
        return 0;
    p += 2;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '=')
        return 0;
    p++;
    size_t n = strcspn(p, "=");
    while (n && (*p == ' ' || *p == '\t')) {
        p++;
        n--;
    }
    if (n >= cap)
        n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static void tp_strip_newlines(char *s)
{
    size_t n = strlen(s);
    while (n && s[n - 1] == '\n')
        s[--n] = '\0';
}

/* The compiler Tor was (or would be) built with: VENDOR_CC, else the CC the
 * vendor/tor Makefile records, else CC, else cc. */
static void tp_effective_cc(const struct tp_ctx *c, char *out, size_t cap)
{
    char path[TP_PATH + 32], line[8192];
    const char *v = getenv("VENDOR_CC");
    out[0] = '\0';
    if (v && v[0]) {
        snprintf(out, cap, "%s", v);
        return;
    }
    snprintf(path, sizeof path, "%s/vendor/tor/Makefile", c->root);
    FILE *f = fopen(path, "r");
    while (f && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = '\0';
        if (tp_cc_from_line(line, out, cap))
            break;
    }
    if (f)
        fclose(f);
    if (!out[0])
        snprintf(out, cap, "%s", env_or("CC", "cc"));
    tp_strip_newlines(out);
}

static int tp_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    int bad = !f || ferror(f) || fgetc(f) != EOF;
    if (f)
        fclose(f);
    buf[n] = '\0';
    tp_strip_newlines(buf);
    return bad ? -1 : 0;
}

/* Runs argv and returns its exit code; 256 when interrupted or not started. */
static int tp_status(const struct tp_ctx *c, char *const argv[], const char *out)
{
    int code = 0;
    return tp_run(c, argv, out, 0, &code) == 0 ? code : 256;
}

static int tp_helper_steps(const struct tp_ctx *c, const char *bin)
{
    char pos[16], neg[16];
    int pc = 0, nc = 0;
    if (tp_compile(c, "-Iplatform/modules/base/include", c->pos_log, &pc) != 0
        || tp_compile(c, NULL, c->neg_log, &nc) != 0)
        return 1;
    snprintf(pos, sizeof pos, "%d", pc);
    snprintf(neg, sizeof neg, "%d", nc);
    char *const results[] = { (char *)bin, (char *)"check-compiler-results", pos, neg,
                              (char *)c->pos_log, (char *)c->neg_log, NULL };
    char *const self[] = { (char *)bin, (char *)"--selftest", NULL };
    return tp_status(c, results, NULL) != 0 || tp_status(c, self, NULL) != 0;
}

static int tp_identity(const struct tp_ctx *c, const char *cc, char *id, size_t cap)
{
    char tool[TP_PATH + 32];
    snprintf(tool, sizeof tool, "%s/tools/dev/build-epoch-key.sh", c->root);
    char *const argv[] = { tool, (char *)"compiler-bytes-id", (char *)cc, NULL };
    if (tp_status(c, argv, c->out) != 0 || tp_slurp(c->out, id, cap) != 0) {
        if (!lsc_pending())
            fprintf(stderr, "check-tor-provenance: could not derive a compiler identity for %s\n", cc);
        return -1;
    }
    return 0;
}

static int tp_commit(const struct tp_ctx *c, char *commit, size_t cap)
{
    char vendor[TP_PATH + 32];
    snprintf(vendor, sizeof vendor, "%s/vendor/tor", c->root);
    char *const argv[] = { (char *)"git", (char *)"-C", vendor, (char *)"rev-parse",
                           (char *)"--verify", (char *)"HEAD", NULL };
    return tp_status(c, argv, c->out) == 0 && tp_slurp(c->out, commit, cap) == 0 ? 0 : -1;
}

static int tp_steps(const struct tp_ctx *c)
{
    char bin[TP_PATH + 32], vendor[TP_PATH + 32], commit[512], cc[8192], id[8192];
    snprintf(bin, sizeof bin, "%s/build/bin/z23-tor-provenance", c->root);
    snprintf(vendor, sizeof vendor, "%s/vendor/tor", c->root);
    if (tp_helper_steps(c, bin) != 0 || tp_commit(c, commit, sizeof commit) != 0)
        return 1;
    tp_effective_cc(c, cc, sizeof cc);
    if (tp_identity(c, cc, id, sizeof id) != 0)
        return 1;
    char *const check[] = { bin, (char *)"check", vendor, (char *)"--tor-commit", commit,
                            (char *)"--compiler-id", id, NULL };
    int code = tp_status(c, check, NULL);
    return code > 255 ? 1 : code;
}

int tp_gate(const char *root, int grace_ms)
{
    struct tp_ctx c;
    if (lsc_install() != 0 || chdir(root) != 0 || tp_open_work(&c, root, grace_ms) != 0) {
        fprintf(stderr, "z23-lint: check-tor-provenance: cannot prepare the scratch directory\n");
        return 1;
    }
    int rc = tp_steps(&c);
    int sig = lsc_pending();
    tp_cleanup(&c);
    if (sig)
        lsc_finish(sig);
    return rc;
}

int check_tor_provenance_run(int argc, char **argv)
{
    char root[TP_PATH];
    (void)argc;
    (void)argv;
    if (cic_repo_root(root, sizeof root))
        return 1;
    return tp_gate(root, TP_GRACE_MS);
}
