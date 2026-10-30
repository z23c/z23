/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-sync-state-no-ordinal — the sync_trust_state
 * enumerators are ORTHOGONAL provenance facts, not a trust ordinal, so any
 * ordinal comparison (< <= > >=) against a SYNC_TRUST_* enumerator or the
 * enum type is a latent authorization bug. Ported from
 * tools/scripts/check_sync_state_no_ordinal.sh (deleted). Selftest:
 * gate_sync_state_no_ordinal_selftest.c.
 *
 * Scan: git grep --untracked over the source authorities (core engine
 * contexts cognition platform) plus tools, pathspecs <root>/ then any depth
 * of .c and .h files. Hits whose line mentions SYNC_TRUST_STATE_COUNT (the
 * legitimate loop bound over the count sentinel) are excluded, then the
 * shared lint_filter_excluded drop is applied (fixture/build/vendor noise
 * under production scans). A hollow scan (nothing mentioning the enum is
 * scannable) fails closed via gate_require_scanned, never a quiet pass.
 * Exit 0 clean, 1 violation, 2 fatal/unproven. Same stdout/stderr lines as
 * the shell original.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"

static const char k_sno_gate[] = "check_sync_state_no_ordinal";
static const char k_sno_hint[] =
    "no source under the architecture authorities mentions SYNC_TRUST_ — "
    "was services/sync_trust_policy.* renamed/moved?";
static const char k_sno_order[] =
    "(<=|>=|<|>)[[:space:]]*SYNC_TRUST_"
    "|SYNC_TRUST_[A-Z_]+[[:space:]]*(<=|>=|<|>)"
    "|(<=|>=|<|>)[[:space:]]*enum[[:space:]]+sync_trust_state"
    "|enum[[:space:]]+sync_trust_state[[:space:]]*(<=|>=|<|>)";
/* Universe: any source that mentions the enum at all (hollow-scan floor). */
static const char k_sno_universe[] =
    "SYNC_TRUST_|enum[[:space:]]+sync_trust_state";

enum { SNO_ROOTS = 6, SNO_PS = 2 * SNO_ROOTS, SNO_LINE = 4096,
       SNO_ROWS = 512, SNO_ROW = 1024, SNO_PSLEN = 64, SNO_AV = 8 + SNO_PS };

static const char *const k_sno_roots[SNO_ROOTS] = {
    "core", "engine", "contexts", "cognition", "platform", "tools",
};

static char sno_ps[SNO_PS][SNO_PSLEN];
static char *sno_av_hits[SNO_AV];
static char *sno_av_uni[SNO_AV];
static char sno_viol[SNO_ROWS][SNO_ROW];

struct sno_hits { int total; int stored; };

/* Child half of the git runner: wire stdout to the pipe, optionally chdir,
 * then exec. Never returns. */
static void sno_child_exec(int pfd[2], const char *cwd, char *const av[])
{
    int nul = open("/dev/null", O_WRONLY);
    if (nul >= 0)
        dup2(nul, STDERR_FILENO);
    if (dup2(pfd[1], STDOUT_FILENO) < 0)
        _exit(127);
    close(pfd[0]);
    close(pfd[1]);
    if (cwd && chdir(cwd) != 0)
        _exit(126);
    execvp(av[0], av);
    _exit(127);
}

/* waitpid that retries EINTR; any other failure is -1, never a clean status.
 * Shared with the selftest driver, which spawns git the same way. */
int sno_wait(pid_t pid, int *st)
{
    while (waitpid(pid, st, 0) < 0)
        if (errno != EINTR)
            return -1;
    return 0;
}

/* Runs git with av (av[0] is "git"), feeding each stdout line to fn (ctx).
 * Returns the child's exit status (126 chdir failed and 127 exec failed are
 * reported here, not silently), or a negative code: -1 spawn/wait failure,
 * -2 read error, -3 overlong line, -4 fn refused a line. Only the caller
 * decides which exit statuses are acceptable. A -1 from lct_read_line_fd is
 * end of input; git grep never emits an empty line, so it ends the stream. */
static int sno_git_lines(const char *cwd, char *const av[],
                         int (*fn)(char *, void *), void *ctx)
{
    int pfd[2];
    if (pipe(pfd) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0)
        sno_child_exec(pfd, cwd, av);
    close(pfd[1]);
    int bad = 0;
    for (;;) {
        char line[SNO_LINE];
        int got = lct_read_line_fd(pfd[0], line, sizeof line);
        if (got == -1)
            break;
        if (got < 0) {
            bad = got;
            break;
        }
        if (fn(line, ctx) != 0) {
            bad = -4;
            break;
        }
    }
    close(pfd[0]);
    int st = 0;
    if (sno_wait(pid, &st) != 0)
        return -1;
    if (bad)
        return bad;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* One git-grep hit line: drop the count-sentinel bound, apply the shared
 * exclusion filter, store the survivor. Returns nonzero only on row-table
 * overflow or a filter failure (fail closed: a line the filter could not
 * judge is never dropped as clean). */
static int sno_hits_cb(char *line, void *ctx)
{
    struct sno_hits *h = ctx;
    if (strstr(line, "SYNC_TRUST_STATE_COUNT"))
        return 0;
    char kept[SNO_ROW];
    if (lint_filter_excluded(line, kept, sizeof kept) != 0)
        return 1;
    if (!kept[0])
        return 0;
    h->total++;
    if (h->stored >= SNO_ROWS) {
        fprintf(stderr, "%s: violation rows exceed %d\n", k_sno_gate,
                SNO_ROWS);
        return 1;
    }
    if (ovf(snprintf(sno_viol[h->stored], SNO_ROW, "%s", kept), SNO_ROW))
        return 1;
    h->stored++;
    return 0;
}

static int sno_count_cb(char *line, void *ctx)
{
    (void)line;
    (*(int *)ctx)++;
    return 0;
}

/* Builds the two git-grep argv arrays (hits with -nE, universe with -lE)
 * over the fixed root pathspecs. Returns 0 ok, 2 on any overflow. */
static int sno_argv_init(void)
{
    for (int i = 0; i < SNO_ROOTS; i++) {
        if (ovf(snprintf(sno_ps[2 * i], SNO_PSLEN, "%s/**/*.c",
                         k_sno_roots[i]), SNO_PSLEN))
            return 2;
        if (ovf(snprintf(sno_ps[2 * i + 1], SNO_PSLEN, "%s/**/*.h",
                         k_sno_roots[i]), SNO_PSLEN))
            return 2;
    }
    char **avs[2] = { sno_av_hits, sno_av_uni };
    const char *flags[2] = { "-nE", "-lE" };
    const char *pats[2] = { k_sno_order, k_sno_universe };
    for (int a = 0; a < 2; a++) {
        char **av = avs[a];
        int i = 0;
        av[i++] = (char *)"git";
        av[i++] = (char *)"grep";
        av[i++] = (char *)"--untracked";
        av[i++] = (char *)flags[a];
        av[i++] = (char *)pats[a];
        av[i++] = (char *)"--";
        for (int p = 0; p < SNO_PS; p++)
            av[i++] = sno_ps[p];
        av[i] = NULL;
    }
    return 0;
}

static int sno_report_fail(FILE *out, const struct sno_hits *h)
{
    fputs("\ncheck_sync_state_no_ordinal: FAIL — ordinal comparison of "
          "enum sync_trust_state\n\n", out);
    for (int i = 0; i < h->stored; i++)
        fprintf(out, "  %s\n", sno_viol[i]);
    fputs("\nThe sync_trust_state enumerators are ORTHOGONAL provenance "
          "facts, not a\ntrust ordinal (EXPORT_ROOT_REDERIVED grants "
          "export-only; ARTIFACT_VERIFIED\ngrants serve/spend/mine/seed "
          "but not export — neither is a superset).\nFix: gate on the "
          "capability MASK, e.g.\n  sync_trust_cap_allowed(st, "
          "SYNC_CAP_...) / sync_capabilities_from_evidence(...)\n"
          "never a </<=/>/>= comparison against a SYNC_TRUST_* value.\n",
          out);
    return 1;
}

/* The full scan, run with cwd at cwd (NULL: current directory, the repo
 * root when invoked by the harness). Prints the verdict to out and returns
 * 0 clean, 1 violation, 2 fatal or unproven. Shared with the selftest. */
/* git grep exits 0 (matches) or 1 (no match); anything else is a failed scan.
 * The shell gate hid such a failure behind `|| true`; this one never does. */
static int sno_git_status_ok(int st, const char *which)
{
    if (st == 0 || st == 1)
        return 1;
    fprintf(stderr, "%s: FATAL — the %s git grep could not run (status %d)\n",
            k_sno_gate, which, st);
    return 0;
}

int sno_scan(const char *cwd, FILE *out, int *nfiles)
{
    if (sno_argv_init() != 0)
        return 2;
    struct sno_hits h = { 0, 0 };
    int hrc = sno_git_lines(cwd, sno_av_hits, sno_hits_cb, &h);
    if (!sno_git_status_ok(hrc, "hits"))
        return 2;
    int nuni = 0;
    int urc = sno_git_lines(cwd, sno_av_uni, sno_count_cb, &nuni);
    if (!sno_git_status_ok(urc, "universe"))
        return 2;
    *nfiles = nuni;
    int gr = gate_require_scanned(nuni, 1, k_sno_gate, k_sno_hint);
    if (gr != 0)
        return gr;
    if (h.total > 0)
        return sno_report_fail(out, &h);
    fprintf(out,
            "%s: clean — no ordinal sync_trust_state comparison "
            "(%d files scanned)\n", k_sno_gate, nuni);
    return 0;
}

int check_sync_state_no_ordinal_run(int argc, char **argv)
{
    (void)argv;
    if (argc != 0) {
        fprintf(stderr,
                "%s: FATAL — expected no arguments or --selftest\n",
                k_sno_gate);
        return 2;
    }
    char root[4096];
    if (cic_repo_root(root, sizeof root) || chdir(root) != 0) {
        fprintf(stderr, "%s: FATAL — cannot enter the repository root\n",
                k_sno_gate);
        return 2;
    }
    int nfiles = 0;
    return sno_scan(NULL, stdout, &nfiles);
}
