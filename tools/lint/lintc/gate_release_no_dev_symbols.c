/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-release-no-dev-symbols — prove the RELEASE binary
 * contains none of the dev-only mutation entry points. Two layers, exactly
 * like the retired shell gate (deleted):
 *   1. STRUCTURAL (always): main.c has no legacy devloop dispatch, the
 *      Makefile puts the devloop executors in DEV_ONLY_SRCS and filters
 *      them out of DEVLOOP_SRCS, and every dev-activation engine source
 *      carries its dev or test compile guard.
 *   2. ARTIFACT (only when a FRESH release binary exists): the exported
 *      extern symbol set must not contain any forbidden dev-executor
 *      symbol. The read is per-host: ELF reads nm -D --defined-only;
 *      Mach-O has no dynamic symbol table, so it reads nm -gU and the
 *      probe strips the single leading underscore Mach-O adds.
 *
 * The nm read runs via fork + execvp with an argv array (never a shell).
 * A tool failure is a decision made out loud (FAIL + rc=1), never a skip.
 * Selftest: gate_release_no_dev_symbols_selftest.c.
 *
 * If the dev executor or engine file set changes shape, update the lists
 * below deliberately — never silence the gate by weakening the symbol list.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

static const char k_rnd_gate[] = "check-release-no-dev-symbols";

static const char *const k_rnd_forbidden[] = {
    "zcl_devloop_cli_main",
    "zcl_devloop_is_method",
    "zcl_devloop_run_cycle",
    "zcl_devloop_run_sim",
    "zcl_devloop_watch",
    "zcl_devloop_process_run",
    "zcl_devloop_print_status",
    "dev_activation_run",
    "dev_activation_activate_generation",
    "dev_activation_default_ops",
    "fsi_test_fault",
};

enum { RND_PATH = 1024, RND_LINE = 2048, RND_BLOCK = 4096, RND_ERR = 512,
       RND_NFORBID =
           (int)(sizeof k_rnd_forbidden / sizeof k_rnd_forbidden[0]) };

struct rnd_nmres {
    char err[RND_ERR];
    int rc;    /* nm exit status, or 128+signal, or 127 exec-fail */
    int nsyms; /* symbol lines seen on stdout */
    int seen[RND_NFORBID]; /* forbidden name i was exported (by index) */
};

/* An absolute rel (the binary argument may be one) is used as given, exactly
 * as the shell script's `[ -x "$BIN" ]` did; a relative one joins root. */
static int rnd_join(const char *root, const char *rel, char *out, size_t cap)
{
    if (rel[0] == '/')
        return ovf(snprintf(out, cap, "%s", rel), cap) ? 2 : 0;
    return ovf(snprintf(out, cap, "%s/%s", root, rel), cap) ? 2 : 0;
}

static int rnd_readable(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    fclose(f);
    return 1;
}

/* ── layer 1: structural ─────────────────────────────────────────────── */

static int rnd_main_c(const char *root, FILE *err, int *rc)
{
    char path[RND_PATH];
    regex_t re;
    int hits = 0;
    if (rnd_join(root, "engine/entry/main.c", path, sizeof path))
        return 2;
    if (!rnd_readable(path)) {
        fprintf(err, "FAIL: %s is unreadable (fail closed)\n", path);
        *rc = 1;
        return 0;
    }
    if (compile_pat(&re, REG_EXTENDED, "zcl_devloop_(cli_main|is_method)",
                    "", "", ""))
        return 2;
    int r = scan_re(path, &re, &hits, 0);
    regfree(&re);
    if (r)
        return 2;
    if (hits) {
        fprintf(err,
                "FAIL: engine/entry/main.c still bypasses the native "
                "registry for dev commands\n");
        *rc = 1;
    }
    return 0;
}

/* Collects the DEV_ONLY_SRCS assignment line plus the 2 lines after it
 * (the shell original read gate_grep -A2) into one block buffer. */
struct rnd_mk {
    char block[RND_BLOCK];
    size_t len;
    int collect;
    int left;
};

static int rnd_mk_append(struct rnd_mk *m, const char *s)
{
    size_t n = strlen(s);
    if (m->len + n + 2 > sizeof m->block) {
        fprintf(stderr, "%s: DEV_ONLY_SRCS block exceeds %d\n", k_rnd_gate,
                RND_BLOCK);
        return 2;
    }
    memcpy(m->block + m->len, s, n);
    m->len += n;
    m->block[m->len++] = '\n';
    m->block[m->len] = '\0';
    return 0;
}

static int rnd_mk_line(void *ctx, const char *line, size_t len)
{
    struct rnd_mk *m = ctx;
    char buf[RND_LINE];
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof buf) {
        fprintf(stderr, "%s: Makefile line exceeds %d\n", k_rnd_gate,
                RND_LINE);
        return 2;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';
    if (m->collect && m->left > 0) {
        m->left--;
        return rnd_mk_append(m, buf);
    }
    if (!m->collect && strncmp(buf, "DEV_ONLY_SRCS", 13) == 0) {
        m->collect = 1;
        m->left = 2;
        return rnd_mk_append(m, buf);
    }
    return 0;
}

static int rnd_makefile(const char *root, FILE *err, int *rc)
{
    static const char *const k_execs[] = { "devloop_cli.c", "devloop_cycle.c",
                                           "devloop_watch.c",
                                           "devloop_process.c" };
    char path[RND_PATH];
    struct rnd_mk m;
    regex_t re;
    int hits = 0;
    if (rnd_join(root, "Makefile", path, sizeof path))
        return 2;
    if (!rnd_readable(path)) {
        fprintf(err, "FAIL: %s is unreadable (fail closed)\n", path);
        *rc = 1;
        return 0;
    }
    memset(&m, 0, sizeof m);
    if (lc_each_line(path, rnd_mk_line, &m, 1))
        return 2;
    for (int i = 0; i < 4; i++) {
        char needle[RND_PATH];
        if (ovf(snprintf(needle, sizeof needle, "tools/dev/%s", k_execs[i]),
                sizeof needle))
            return 2;
        if (!strstr(m.block, needle)) {
            fprintf(err,
                    "FAIL: tools/dev/%s is not in the Makefile DEV_ONLY_SRCS "
                    "group\n", k_execs[i]);
            *rc = 1;
        }
    }
    if (gate_require_scanned(4, 4, k_rnd_gate,
                             "the DEV_ONLY_SRCS executor list changed shape "
                             "unexpectedly"))
        return 2;
    if (compile_pat(&re, REG_EXTENDED,
                    "^DEVLOOP_SRCS[[:space:]]*=.*filter-out.*DEV_ONLY_SRCS",
                    "", "", ""))
        return 2;
    int r = scan_re(path, &re, &hits, 0);
    regfree(&re);
    if (r)
        return 2;
    if (!hits) {
        fprintf(err, "FAIL: DEVLOOP_SRCS must filter-out DEV_ONLY_SRCS so the"
                     " release ALL_SRCS excludes them\n");
        *rc = 1;
    }
    return 0;
}

/* One file set against one guard regex; missing files fail closed. */
static int rnd_check_set(const char *root, const char *const *files, int n,
                         const regex_t *re, const char *guard_desc, FILE *err,
                         int *rc)
{
    char path[RND_PATH];
    for (int i = 0; i < n; i++) {
        if (rnd_join(root, files[i], path, sizeof path))
            return 2;
        if (!rnd_readable(path)) {
            fprintf(err, "FAIL: %s is missing (dev-activation engine file set"
                         " changed shape)\n", files[i]);
            *rc = 1;
            continue;
        }
        int hits = 0;
        if (scan_re(path, re, &hits, 0))
            return 2;
        if (!hits) {
            fprintf(err, "FAIL: %s is missing the %s compile guard\n",
                    files[i], guard_desc);
            *rc = 1;
        }
    }
    return 0;
}

static int rnd_guards(const char *root, FILE *err, int *rc)
{
    static const char *const k_or[] = {
        "tools/dev/dev_activation.c", "tools/dev/dev_activation_internal.h",
        "tools/dev/dev_activation_stage.c", "tools/dev/dev_activation_verify.c"
    };
    static const char *const k_strict[] = { "tools/dev/dev_activation_ops.c" };
    static const char k_or_pat[] =
        "#if[[:space:]]+defined\\(ZCL_DEV_BUILD\\)[[:space:]]*\\|\\|"
        "[[:space:]]*defined\\(ZCL_TESTING\\)";
    static const char k_or_desc[] =
        "'#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)'";
    regex_t re_or, re_strict;
    if (compile_pat(&re_or, REG_EXTENDED, k_or_pat, "", "", ""))
        return 2;
    if (compile_pat(&re_strict, REG_EXTENDED, "#ifdef[[:space:]]+ZCL_DEV_BUILD",
                    "", "", "")) {
        regfree(&re_or);
        return 2;
    }
    int r = rnd_check_set(root, k_or, 4, &re_or, k_or_desc, err, rc);
    if (!r)
        r = rnd_check_set(root, k_strict, 1, &re_strict,
                          "'#ifdef ZCL_DEV_BUILD'", err, rc);
    regfree(&re_or);
    regfree(&re_strict);
    if (r)
        return r;
    if (gate_require_scanned(5, 5, k_rnd_gate,
                             "the dev_activation engine source-file set "
                             "changed shape unexpectedly"))
        return 2;
    return 0;
}

/* ── layer 2: artifact (nm on a FRESH release binary) ────────────────── */

static int rnd_fresh(const char *bin, const char *mainc, const char *mk)
{
    struct stat sb, sm, sk;
    if (stat(bin, &sb) != 0 || access(bin, X_OK) != 0)
        return 0;
    if (stat(mainc, &sm) != 0 || stat(mk, &sk) != 0)
        return 0;
    return sb.st_mtime > sm.st_mtime && sb.st_mtime > sk.st_mtime;
}

/* Marks every forbidden name equal to sym as seen (by table index). */
static void rnd_mark_forbidden(const char *sym, struct rnd_nmres *res)
{
    for (int i = 0; i < RND_NFORBID; i++)
        if (strcmp(sym, k_rnd_forbidden[i]) == 0)
            res->seen[i] = 1;
}

/* Copies the last whitespace-delimited field of a symbol line into out. */
static void rnd_last_field(const char *line, char *out, size_t cap)
{
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == ' ' ||
                     line[n - 1] == '\t' || line[n - 1] == '\r'))
        n--;
    size_t e = n;
    while (e > 0 && line[e - 1] != ' ' && line[e - 1] != '\t')
        e--;
    size_t len = n - e;
    if (len >= cap)
        len = cap - 1;
    memcpy(out, line + e, len);
    out[len] = '\0';
}

static void rnd_sym_line(const char *line, int darwin, struct rnd_nmres *res)
{
    char sym[256];
    rnd_last_field(line, sym, sizeof sym);
    const char *s = sym;
    if (darwin && s[0] == '_')
        s++;
    if (!s[0])
        return;
    res->nsyms++;
    rnd_mark_forbidden(s, res);
}

/* read() that retries on EINTR, so an interrupted read cannot end the scan
 * early. Any other failure returns -1 to the caller. */
static ssize_t rnd_read(int fd, char *buf, size_t n)
{
    ssize_t r;
    do {
        r = read(fd, buf, n);
    } while (r < 0 && errno == EINTR);
    return r;
}

/* Reaps pid; EINTR retries, any other waitpid failure is an error (never a
 * clean status). */
static int rnd_wait(pid_t pid, int *st)
{
    pid_t r;
    do {
        r = waitpid(pid, st, 0);
    } while (r < 0 && errno == EINTR);
    return r == pid ? 0 : 2;
}

/* Child side of the nm spawn: wire the pipes to fds 1 and 2, then exec nm
 * with an argv array. Returns only if exec fails (exit 127). */
static void rnd_exec_nm(const char *bin, int darwin, const int outp[2],
                        const int errp[2])
{
    dup2(outp[1], 1);
    dup2(errp[1], 2);
    close(outp[0]); close(outp[1]);
    close(errp[0]); close(errp[1]);
    char *argv[6];
    int a = 0;
    argv[a++] = (char *)"nm";
    if (!darwin) {
        argv[a++] = (char *)"-D";
        argv[a++] = (char *)"--defined-only";
    } else {
        argv[a++] = (char *)"-gU";
    }
    argv[a++] = (char *)bin;
    argv[a] = NULL;
    execvp("nm", argv);
    _exit(127);
}

/* Creates both pipes and forks the nm child. Parent keeps the read ends. */
static int rnd_spawn_nm(const char *bin, int darwin, int outp[2], int errp[2],
                        pid_t *pid_out)
{
    if (pipe(outp) != 0)
        return 2;
    if (pipe(errp) != 0) {
        close(outp[0]);
        close(outp[1]);
        return 2;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(outp[0]); close(outp[1]);
        close(errp[0]); close(errp[1]);
        return 2;
    }
    if (pid == 0)
        rnd_exec_nm(bin, darwin, outp, errp);
    close(outp[1]);
    close(errp[1]);
    *pid_out = pid;
    return 0;
}

/* Streams nm's stdout through the symbol matcher. Returns the last read()
 * result: 0 at EOF, negative on a read failure. */
static ssize_t rnd_pump_stdout(int fd, int darwin, struct rnd_nmres *res)
{
    char pend[RND_LINE], chunk[4096];
    size_t pl = 0;
    ssize_t r;
    while ((r = rnd_read(fd, chunk, sizeof chunk)) > 0) {
        for (ssize_t i = 0; i < r; i++) {
            if (chunk[i] == '\n') {
                pend[pl] = '\0';
                rnd_sym_line(pend, darwin, res);
                pl = 0;
            } else if (pl + 1 < sizeof pend) {
                pend[pl++] = chunk[i];
            }
        }
    }
    return r;
}

/* Reads nm's stderr into res->err and closes fd. 2 on a read failure. */
static int rnd_drain_stderr(int fd, struct rnd_nmres *res)
{
    ssize_t r = 0;
    size_t el = 0;
    while (el + 1 < sizeof res->err &&
           (r = rnd_read(fd, res->err + el, sizeof res->err - 1 - el)) > 0)
        el += (size_t)r;
    res->err[el] = '\0';
    close(fd);
    return r < 0 ? 2 : 0;
}

/* Reaps nm and records its exit status: code, 128+signal, or 127. */
static int rnd_nm_status(pid_t pid, struct rnd_nmres *res)
{
    int st = 0;
    if (rnd_wait(pid, &st))
        return 2;
    if (WIFEXITED(st))
        res->rc = WEXITSTATUS(st);
    else if (WIFSIGNALED(st))
        res->rc = 128 + WTERMSIG(st);
    else
        res->rc = 127;
    return 0;
}

/* Runs nm with fork + execvp and an argv array (never a shell). stdout is
 * drained first and streamed through the forbidden matcher; stderr is read
 * after, so a large symbol list can never wedge the pipe. */
static int rnd_nm(const char *bin, int darwin, struct rnd_nmres *res)
{
    int outp[2], errp[2];
    pid_t pid = 0;
    if (rnd_spawn_nm(bin, darwin, outp, errp, &pid))
        return 2;
    ssize_t r = rnd_pump_stdout(outp[0], darwin, res);
    close(outp[0]);
    if (r < 0) {
        close(errp[0]);
        return 2;
    }
    if (rnd_drain_stderr(errp[0], res))
        return 2;
    return rnd_nm_status(pid, res);
}

static int rnd_layer2(const char *root, const char *bin, FILE *out, FILE *err,
                      int *rc)
{
    char bp[RND_PATH], mp[RND_PATH], kp[RND_PATH];
    if (rnd_join(root, bin, bp, sizeof bp) ||
        rnd_join(root, "engine/entry/main.c", mp, sizeof mp) ||
        rnd_join(root, "Makefile", kp, sizeof kp))
        return 2;
    if (!rnd_fresh(bp, mp, kp)) {
        fprintf(out, "NOTE: no fresh release binary at %s \342\200\224 "
                     "structural proof above is authoritative.\n", bin);
        fprintf(out, "      (build it with 'make zclassic23' for the "
                     "artifact-level nm proof.)\n");
        return 0;
    }
    struct utsname un;
    int darwin = uname(&un) == 0 && strcmp(un.sysname, "Darwin") == 0;
    const char *nm_read = darwin ? "nm -gU" : "nm -D --defined-only";
    struct rnd_nmres res;
    memset(&res, 0, sizeof res);
    if (rnd_nm(bp, darwin, &res))
        return 2;
    if (res.rc != 0) {
        fprintf(err, "FAIL: cannot read the exported symbols of %s with "
                     "'%s' (exit %d)\n", bin, nm_read, res.rc);
        char *nl = strchr(res.err, '\n');
        if (nl)
            *nl = '\0';
        if (res.err[0])
            fprintf(err, "      nm says: %s\n", res.err);
        fprintf(err, "      the artifact-level proof did NOT run; the "
                     "structural proof above\n");
        fprintf(err, "      is the only evidence this gate can offer for "
                     "this artifact.\n");
        *rc = 1;
    } else if (res.nsyms == 0) {
        fprintf(err, "NOTE: %s exported no symbols from %s (unexpected for "
                     "-rdynamic);\n", nm_read, bin);
        fprintf(err, "      relying on the structural proof above.\n");
    } else {
        /* One FAIL per forbidden name, in table order, as the shell did. */
        for (int i = 0; i < RND_NFORBID; i++) {
            if (!res.seen[i])
                continue;
            fprintf(err, "FAIL: release binary %s exports dev-only symbol "
                         "'%s'\n", bin, k_rnd_forbidden[i]);
            *rc = 1;
        }
        if (*rc == 0)
            fprintf(out, "  %s %s: all %d dev-executor symbols ABSENT "
                         "\342\234\223\n", nm_read, bin, RND_NFORBID);
    }
    return 0;
}

/* Shared with the selftest: run both layers against root, with bin relative
 * to root. Report lines are written to out and err exactly as the shell
 * original wrote them to stdout and stderr. */
int rnd_check_root(const char *root, const char *bin, FILE *out, FILE *err)
{
    int rc = 0;
    fprintf(out, "\342\225\220\342\225\220 LINT: release binary contains no "
                 "dev-only mutation symbols \342\225\220\342\225\220\n");
    int r = rnd_main_c(root, err, &rc);
    if (!r)
        r = rnd_makefile(root, err, &rc);
    if (!r)
        r = rnd_guards(root, err, &rc);
    if (!r)
        r = rnd_layer2(root, bin, out, err, &rc);
    if (r)
        return 2;
    if (rc != 0) {
        fprintf(err, "check-release-no-dev-symbols: FAIL\n");
        return 1;
    }
    fprintf(out, "check-release-no-dev-symbols: OK\n");
    return 0;
}

int check_release_no_dev_symbols_run(int argc, char **argv)
{
    const char *bin = argc >= 1 ? argv[0] : "build/bin/z23";
    struct stat sb;
    /* The shell original wrote stdout unbuffered, so its lines interleave
     * with the stderr FAIL lines in order; keep that order on a pipe. */
    if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
        return 2;
    if (argc == 0 && stat("build/bin/z23", &sb) != 0 &&
        stat("build/bin/z23.exe", &sb) == 0)
        bin = "build/bin/z23.exe";
    return rnd_check_root(".", bin, stdout, stderr);
}
