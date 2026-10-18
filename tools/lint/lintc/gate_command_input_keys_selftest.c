/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: self-test of check-command-input-keys. Writes one handler source
 * and a command-leaf .def per case into a private scratch directory, runs the
 * whole gate over them and grades the exit status and the report: a clean
 * leaf, a read key that is not declared, a baseline pin that excuses it or
 * has gone stale, two leaves of one handler that disagree or agree, grammar
 * drift, a collapsed floor, an unresolved handler, warn mode and the verbose
 * listing. It then proves the scratch directory is removed when the process
 * is stopped by SIGINT (once and twice), SIGTERM or SIGHUP.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "gate_command_input_keys_priv.h"
#include "lintc.h"
#include "lintc_sig.h"
#include "lintc_text.h"

enum { CKS_PATH = 4096, CKS_DIR = CKS_PATH + 32, CKS_FILE = 2 * CKS_DIR };

static char g_cks_dir[CKS_DIR];

/* The handler under test: keys read through an alias, a call, a forwarded
 * array and a callee, plus a prose mention and a value comparison that are
 * not reads. */
static const char k_cks_handlers[] =
    "static int cks_helper(const struct request *request)\n"
    "{\n"
    "    return json_get(request->input, \"beta\") != 0;\n"
    "}\n\n"
    "int h_alpha(struct request *request)\n"
    "{\n"
    "    const struct json_value *in = request->input;\n"
    "    const char *a = json_get_str(in, \"alpha\");\n"
    "    static const char *const fwd[] = { \"gamma\", \"delta\" };\n"
    "    /* json_get(request->input, \"ghost\") is prose, not a read */\n"
    "    forward(request->input, fwd, 2);\n"
    "    if (a && strcmp(a, \"onchain\") == 0)\n"
    "        return 0;\n"
    "    return cks_helper(request);\n"
    "}\n";

struct cks_case {
    const char *name, *leaves, *base, *mode, *verbose, *leaf_floor;
    int nargs, rc;
    const char *out, *err;
    int fault; /* CKS_F_*: baseline made unreadable after it is written */
};

enum { CKS_F_NONE, CKS_F_CHMOD, CKS_F_DIR, CKS_F_ABSENT };

#define CKS_A "p.a|S|O|alpha,beta,delta,zeta|gamma|h_alpha"
#define CKS_NOD "p.a|S|O|alpha,beta|gamma|h_alpha"

static const struct cks_case k_cks_cases[] = {
    { "clean", CKS_A, "", "FAIL", "0", "1", 22, 0,
      "PASS (1 leaf handler(s) resolved over 6 function(s); every key they"
      " read is declared; 0 leaf(s) on a shared dispatcher not attributable;"
      " 1 declared-but-unread", NULL, CKS_F_NONE },
    { "undeclared", CKS_NOD, "", "FAIL", "0", "1", 22, 1,
      "reads \"delta\" (handler h_alpha)", NULL, CKS_F_NONE },
    { "pinned", CKS_NOD, "p.a delta  # reason\n", "FAIL", "0", "1", 22, 0,
      "; 1 grandfathered;", NULL, CKS_F_NONE },
    { "stale pin", CKS_A, "p.a zzz\n", "FAIL", "0", "1", 22, 1,
      "1 STALE baseline entry(ies)", NULL, CKS_F_NONE },
    { "warn mode", CKS_NOD, "", "WARN", "0", "1", 22, 0,
      "READ by a handler but NOT declared", NULL, CKS_F_NONE },
    { "divergent", CKS_A ";p.b|S|O|alpha|gamma|h_alpha", "", "FAIL", "0", "1",
      22, 1, "(handler h_alpha, input schema S)", NULL, CKS_F_NONE },
    { "shared agree", CKS_A ";p.b|S|O|gamma,alpha|beta,delta,zeta|h_alpha",
      "", "FAIL", "0", "1", 22, 0, "2 leaf(s) on a shared dispatcher", NULL, CKS_F_NONE },
    { "grammar drift", CKS_A, "", "FAIL", "0", "1", 21, 2, NULL,
      "macro grammar drift: expected 22 arguments, parsed 21", CKS_F_NONE },
    { "leaf floor", CKS_A, "", "FAIL", "0", "99", 22, 2, NULL,
      "leaf population collapsed under floor (parsed 1)", CKS_F_NONE },
    { "unresolved", CKS_A ";p.c|S|O|||h_missing", "", "FAIL", "0", "1", 22, 0,
      "(not gated):\n\n    p.c -> h_missing\n", NULL, CKS_F_NONE },
    { "unreadable baseline", CKS_A, "", "FAIL", "0", "1", 22, 2, NULL,
      "baseline.txt: Permission denied", CKS_F_CHMOD },
    { "baseline read error", CKS_A, "", "FAIL", "0", "1", 22, 2, NULL,
      "baseline.txt: Is a directory", CKS_F_DIR },
    { "absent baseline is created", CKS_A, "", "FAIL", "0", "1", 22, 0,
      "PASS (1 leaf handler(s)", NULL, CKS_F_ABSENT },
    { "verbose", CKS_A, "", "FAIL", "1", "1", 22, 0,
      "(WARN, not gated):\n    p.a: zeta (handler h_alpha)", NULL, CKS_F_NONE }
};

static int cks_put(const char *name, const char *text)
{
    char path[CKS_FILE];
    FILE *f;
    snprintf(path, sizeof path, "%s/%s", g_cks_dir, name);
    f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(text, f);
    return fclose(f);
}

/* One leaf per ';'-separated spec: path|schema|output|input_keys|
 * positional_keys|handler, expanded into a READY_READ macro of nargs. */
static void cks_macro(struct cik_buf *b, const char *spec, size_t n, int nargs)
{
    char buf[256], *f[6];
    size_t k = 0;
    snprintf(buf, sizeof buf, "%.*s", (int)n, spec);
    for (char *p = buf; k < 6; p++) {
        f[k++] = p;
        p = strchr(p, '|');
        if (!p)
            break;
        *p = '\0';
    }
    cik_buf_puts(b, "ZCL_COMMAND_READY_READ(");
    for (int i = 1; i <= nargs; i++) {
        char arg[160] = "0";
        if (i == 1 || (i >= 8 && i <= 11))
            snprintf(arg, sizeof arg, "\"%s\"", f[i == 1 ? 0 : i - 7]);
        else if (i == 22)
            snprintf(arg, sizeof arg, "%s", f[5]);
        cik_buf_puts(b, i > 1 ? ", " : "");
        cik_buf_puts(b, arg);
    }
    cik_buf_puts(b, ")\n");
}

static int cks_write_defs(const struct cks_case *c)
{
    struct cik_buf b = { 0 };
    const char *p = c->leaves;
    int rc;
    while (*p) {
        size_t n = strcspn(p, ";");
        cks_macro(&b, p, n, c->nargs);
        p += n + (p[n] ? 1 : 0);
    }
    rc = cks_put("case.def", cik_buf_str(&b));
    cik_buf_free(&b);
    return rc;
}

static int cks_find(void *ctx, const struct cik_list *pats, struct cik_list *out)
{
    const struct cik_list *srcs = ctx;
    (void)pats;
    for (size_t i = 0; i < srcs->n; i++)
        cik_list_add(out, srcs->v[i], strlen(srcs->v[i]));
    return 0;
}

static int cks_fail(const char *name, const char *what)
{
    fprintf(stderr, "SELFTEST FAIL: %s: %s\n", name, what);
    return 1;
}

static int cks_grade(const struct cks_case *c, int rc, const char *out,
                     const char *err)
{
    if (rc != c->rc)
        return cks_fail(c->name, "unexpected exit status");
    if (c->out && !strstr(out, c->out))
        return cks_fail(c->name, "report lacks the expected line");
    if (c->err && !strstr(err, c->err))
        return cks_fail(c->name, "diagnostics lack the expected line");
    return 0;
}

/* Makes the written baseline unreadable (or absent); 0 on success. */
static int cks_fault_on(int fault, const char *base)
{
    if (fault == CKS_F_CHMOD)
        return chmod(base, 0);
    if (fault == CKS_F_ABSENT)
        return unlink(base);
    if (fault == CKS_F_DIR)
        return unlink(base) != 0 ? -1 : mkdir(base, 0755);
    return 0;
}

static void cks_fault_off(int fault, const char *base)
{
    if (fault == CKS_F_CHMOD)
        (void)chmod(base, 0644);
    else if (fault == CKS_F_DIR)
        (void)rmdir(base);
    else if (fault == CKS_F_ABSENT)
        (void)unlink(base);
}

static int cks_run_case(const struct cks_case *c, const struct cik_list *srcs)
{
    char def[CKS_FILE], base[CKS_FILE], *out = NULL, *err = NULL;
    size_t olen = 0, elen = 0;
    struct cik_list defs = { 0 };
    FILE *fo, *fe;
    int rc;
    if (c->fault == CKS_F_CHMOD && geteuid() == 0) {
        fprintf(stderr, "SELFTEST SKIP: %s: running as root, chmod 000 does not deny the read\n", c->name);
        return 0;
    }
    snprintf(def, sizeof def, "%s/case.def", g_cks_dir);
    snprintf(base, sizeof base, "%s/baseline.txt", g_cks_dir);
    if (cks_write_defs(c) != 0 || cks_put("baseline.txt", c->base) != 0)
        return cks_fail(c->name, "cannot write the case files");
    if (cks_fault_on(c->fault, base) != 0)
        return cks_fail(c->name, "cannot make the baseline unreadable");
    cik_list_add(&defs, def, strlen(def));
    fo = open_memstream(&out, &olen);
    fe = open_memstream(&err, &elen);
    struct cik_cfg cfg = { .def_dir = "defs", .baseline = base, .mode = c->mode,
        .verbose = c->verbose, .leaf_floor = c->leaf_floor, .fn_floor = "1",
        .bound_floor = "1", .resolved_floor = "1" };
    rc = fo && fe ? cik_check(&cfg, &defs, cks_find, (void *)srcs, fo, fe) : -2;
    if (fo)
        fclose(fo);
    if (fe)
        fclose(fe);
    cks_fault_off(c->fault, base);
    cik_list_free(&defs);
    rc = rc == -2 ? cks_fail(c->name, "cannot capture output")
                  : cks_grade(c, rc, out ? out : "", err ? err : "");
    free(out);
    free(err);
    return rc;
}

static int cks_write_sources(struct cik_list *srcs)
{
    static const char *const names[] = { "handlers.c", "f1.c", "f2.c", "f3.c",
                                         "f4.c" };
    char path[CKS_FILE], body[96];
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        snprintf(body, sizeof body, "int cks_filler_%zu(void)\n{\n    return 0;\n}\n", i);
        if (cks_put(names[i], i == 0 ? k_cks_handlers : body) != 0)
            return -1;
        snprintf(path, sizeof path, "%s/%s", g_cks_dir, names[i]);
        cik_list_add(srcs, path, strlen(path));
    }
    return 0;
}

static int cks_cases(void)
{
    struct cik_list srcs = { 0 };
    int rc = cks_write_sources(&srcs) ? cks_fail("setup", "cannot write sources") : 0;
    for (size_t i = 0; i < sizeof k_cks_cases / sizeof k_cks_cases[0]; i++)
        rc |= cks_run_case(&k_cks_cases[i], &srcs);
    cik_list_free(&srcs);
    return rc;
}

/* Parent of the scratch directory: TMPDIR, else build/scratch in the tree. */
static int cks_parent(char *out, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    char root[CKS_PATH], probe[CKS_FILE];
    if (tmp && tmp[0] == '/')
        return snprintf(out, cap, "%s", tmp) >= (int)cap ? -1 : 0;
    if (cic_repo_root(root, sizeof root)
        || snprintf(probe, sizeof probe, "%s/build/scratch/x", root) >= (int)sizeof probe
        || csr_mkdirs(probe) != 0)
        return -1;
    return snprintf(out, cap, "%s/build/scratch", root) >= (int)cap ? -1 : 0;
}

/* Creates the scratch directory with the termination signals blocked, so the
 * directory and its registration are never separated by a delivery. */
static int cks_open(void)
{
    char parent[CKS_PATH], tmpl[CKS_DIR];
    if (lsc_install() != 0)
        return cks_fail("setup", "cannot install signal handlers");
    if (cks_parent(parent, sizeof parent) != 0
        || snprintf(tmpl, sizeof tmpl, "%s/cik-selftest.XXXXXX", parent) >= (int)sizeof tmpl
        || !mkdtemp(tmpl))
        return cks_fail("setup", "cannot create the scratch directory");
    snprintf(g_cks_dir, sizeof g_cks_dir, "%s", tmpl);
    return 0;
}

/* Removes the scratch tree with signals blocked, then re-raises a recorded
 * signal under its default disposition. */
static void cks_cleanup(void)
{
    int sig = lsc_pending();
    lsc_block();
    if (g_cks_dir[0]) {
        rap_rm_rf(g_cks_dir);
        g_cks_dir[0] = '\0';
    }
    if (sig)
        lsc_finish(sig);
}

/* Signal-test child only: report the scratch directory over the pipe, then
 * wait for a signal. */
static void cks_announce(int ready_fd)
{
    struct timespec ts = { 0, 5 * 1000 * 1000 };
    char line[CKS_DIR + 8];
    int n = snprintf(line, sizeof line, "%s\n", g_cks_dir);
    if (write(ready_fd, line, (size_t)n) != n)
        _exit(2);
    for (int i = 0; i < 4000 && !lsc_pending(); i++)
        nanosleep(&ts, NULL);
}

/* ready_fd is -1 for the command line; the signal test passes a pipe. */
static int cks_run(int ready_fd)
{
    int failed;
    if (cks_open() != 0)
        return 1;
    lsc_unblock();
    if (ready_fd >= 0)
        cks_announce(ready_fd);
    if (lsc_pending())
        cks_cleanup();
    failed = cks_cases() != 0;
    cks_cleanup();
    if (failed)
        return 1;
    printf("check-command-input-keys self-test: PASS (%zu cases)\n",
           sizeof k_cks_cases / sizeof k_cks_cases[0]);
    return 0;
}

static int cks_signal_case(int sig, int times)
{
    int fds[2], st = 0, ready;
    char dir[CKS_DIR];
    pid_t pid;
    if (pipe(fds) != 0 || (pid = fork()) < 0)
        return cks_fail("signal", "pipe or fork failed");
    if (pid == 0) {
        close(fds[0]);
        _exit(cks_run(fds[1]) == 0 ? 3 : 2);
    }
    close(fds[1]);
    ready = lct_read_line_fd(fds[0], dir, sizeof dir);
    close(fds[0]);
    for (int i = 0; ready == 0 && i < times; i++)
        kill(pid, sig);
    if (waitpid(pid, &st, 0) != pid || ready != 0)
        return cks_fail("signal", "the child did not finish");
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig)
        return cks_fail("signal", "the stopped process did not re-raise its signal");
    return access(dir, F_OK) == 0
        ? cks_fail("signal", "the scratch directory outlived the signal") : 0;
}

int check_command_input_keys_selftest(void)
{
    int rc = cks_run(-1);
    if (rc == 0)
        rc = cks_signal_case(SIGINT, 1) || cks_signal_case(SIGINT, 2)
            || cks_signal_case(SIGTERM, 1) || cks_signal_case(SIGHUP, 1);
    return rc;
}
