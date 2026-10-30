/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check_fuzz_artifact_replay, replay half. Re-runs every selected
 * artifact against its sanitizer-instrumented fuzz binary via fork+execvp
 * of timeout(1) (never a shell), asserts per-artifact accounting, runs the
 * anti-flake serial confirmation and grades the result against the ledger.
 * Ported from the same-named half of tools/lint/check_fuzz_artifact_replay.sh
 * (deleted).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_fuzz_artifact_replay_priv.h"

/* One replay: rc==0 ran (st = clean|reproduces), 2 could not run. */
static int farr_exec(struct far_ctx *c, const char *bin, const char *rel, int tmo,
                     const char *work, char *st, size_t stcap)
{
    char tmos[32], dur[32], topt[48], pfx[FAR_PATH + 24], art[FAR_PATH];
    char *av[13];
    int ai = 0, status;
    pid_t pid;
    if (ovf(snprintf(tmos, sizeof tmos, "%d", tmo), sizeof tmos) ||
        ovf(snprintf(dur, sizeof dur, "%d", tmo + 10), sizeof dur) ||
        ovf(snprintf(topt, sizeof topt, "-timeout=%d", tmo), sizeof topt) ||
        ovf(snprintf(pfx, sizeof pfx, "-artifact_prefix=%s/", work), sizeof pfx) ||
        ovf(snprintf(art, sizeof art, "%s/%s/%s", c->root, k_far_seed_root,
                     rel), sizeof art))
        return 2;
    av[ai++] = (char *)"timeout";
    av[ai++] = (char *)"-k";
    av[ai++] = (char *)"5";
    av[ai++] = dur;
    av[ai++] = (char *)bin;
    av[ai++] = topt;
    av[ai++] = (char *)"-rss_limit_mb=2048";
    av[ai++] = (char *)"-runs=1";
    av[ai++] = (char *)"-timeout_exitcode=70";
    av[ai++] = (char *)"-error_exitcode=77";
    av[ai++] = pfx;
    av[ai++] = art;
    av[ai] = NULL;
    pid = fork();
    if (pid < 0)
        return 2;
    if (pid == 0) {
        int nd;
        if (chdir(work) != 0)
            _exit(126);
        setenv("ASAN_OPTIONS", "detect_leaks=0:symbolize=0", 1);
        setenv("UBSAN_OPTIONS", "print_stacktrace=0", 1);
        nd = open("/dev/null", O_WRONLY);
        if (nd >= 0) {
            dup2(nd, STDOUT_FILENO);
            dup2(nd, STDERR_FILENO);
        }
        execvp(av[0], av);
        _exit(125);
    }
    if (waitpid(pid, &status, 0) < 0)
        return 2;
    if (!WIFEXITED(status)) {
        /* timeout(1) re-raises the fuzzer's fatal signal: a crash, not a lost result. */
        snprintf(st, stcap, "reproduces");
        return 0;
    }
    if (WEXITSTATUS(status) == 125 || WEXITSTATUS(status) == 126)
        return 2;
    snprintf(st, stcap, "%s", WEXITSTATUS(status) == 0 ? "clean" : "reproduces");
    return 0;
}

static int farr_replay_one(struct far_ctx *c, const char *work, const char *rel,
                           int tmo, char *st, size_t stcap)
{
    char bin[FAR_PATH];
    const char *sl = strchr(rel, '/');
    size_t cl = sl ? (size_t)(sl - rel) : strlen(rel);
    char corpus[FAR_KIND];
    struct stat sb;
    if (cl >= sizeof corpus)
        cl = sizeof corpus - 1;
    memcpy(corpus, rel, cl);
    corpus[cl] = '\0';
    if (ovf(snprintf(bin, sizeof bin, "%s/%s/fuzz_%s", c->root, c->bin_dir,
                     corpus), sizeof bin))
        return 2;
    if (stat(bin, &sb) != 0 || !(sb.st_mode & S_IXUSR)) {
        snprintf(st, stcap, "nobin");
        return 0;
    }
    return farr_exec(c, bin, rel, tmo, work, st, stcap);
}

static int farr_corpora_ok(struct far_ctx *c)
{
    char list[FAR_CORPORA];
    char *w, *save = NULL;
    if (!c->only_corpora[0])
        return 1;
    snprintf(list, sizeof list, "%s", c->only_corpora);
    for (w = strtok_r(list, ",", &save); w; w = strtok_r(NULL, ",", &save)) {
        if (!w[0])
            continue;
        if (far_kind_has(c, w))
            continue;
        fprintf(c->err, "%s: FATAL — --corpus='%s' names no fuzz target.\n",
                k_far_gate, w);
        fputs("  The Makefile has no $(BIN_DIR)/fuzz_", c->err);
        fprintf(c->err, "%s rule, so this run\n", w);
        fputs("  would replay nothing and report clean. A typo in a filter\n",
              c->err);
        fputs("  is not allowed to look like an audited corpus.\n", c->err);
        fputs("  Known corpora:", c->err);
        char sorted[FAR_KINDS][FAR_KIND];
        char *ptr[FAR_KINDS];
        for (int i = 0; i < c->n_kinds; i++)
            ptr[i] = sorted[i];
        for (int i = 0; i < c->n_kinds; i++)
            snprintf(sorted[i], FAR_KIND, "%s", c->kinds[i]);
        for (int i = 0; i < c->n_kinds; i++)
            for (int j = i + 1; j < c->n_kinds; j++)
                if (strcmp(ptr[i], ptr[j]) > 0) {
                    char *t = ptr[i];
                    ptr[i] = ptr[j];
                    ptr[j] = t;
                }
        for (int i = 0; i < c->n_kinds; i++)
            fprintf(c->err, " %s", ptr[i]);
        fputc('\n', c->err);
        return 0;
    }
    return 1;
}

static int farr_selected(struct far_ctx *c, int *sel, int *n_sel)
{
    *n_sel = 0;
    for (int i = 0; i < c->n_artifacts; i++) {
        const char *rel = c->artifacts[i];
        const char *sl = strchr(rel, '/');
        char corpus[FAR_KIND];
        char want[FAR_CORPORA + 3];
        size_t cl = sl ? (size_t)(sl - rel) : strlen(rel);
        if (cl >= sizeof corpus)
            cl = sizeof corpus - 1;
        memcpy(corpus, rel, cl);
        corpus[cl] = '\0';
        if (c->only_corpora[0]) {
            if (ovf(snprintf(want, sizeof want, ",%s,", c->only_corpora),
                     sizeof want))
                return 2;
            char needle[FAR_KIND + 3];
            if (ovf(snprintf(needle, sizeof needle, ",%s,", corpus),
                     sizeof needle) || !strstr(want, needle))
                continue;
        }
        if (*n_sel >= FAR_SEL) {
            fprintf(c->err, "%s: selection exceeds %d\n", k_far_gate, FAR_SEL);
            return 2;
        }
        sel[(*n_sel)++] = i;
    }
    return 0;
}

enum { FARR_MAX_JOBS = 64 };

struct farr_pool {
    pid_t pid[FARR_MAX_JOBS];
    int art[FARR_MAX_JOBS];
    int running, bad;
};

/* Child result codes: 10 clean, 11 reproduces, 12 nobin, anything else bad. */
static void farr_child(struct far_ctx *c, const char *work, int art)
{
    char s[FAR_ST] = "";
    int rc = farr_replay_one(c, work, c->artifacts[art], c->replay_timeout, s,
                             sizeof s);
    if (rc != 0)
        _exit(13);
    _exit(!strcmp(s, "clean") ? 10 : !strcmp(s, "reproduces") ? 11 : 12);
}

/* Reaps one finished child into st[]; a lost or odd result marks the pool bad. */
static void farr_reap(struct farr_pool *p, char st[][FAR_ST])
{
    int status, s;
    pid_t pid = wait(&status);
    int code = pid < 0 || !WIFEXITED(status) ? -1 : WEXITSTATUS(status);
    for (s = 0; s < FARR_MAX_JOBS; s++)
        if (pid > 0 && p->pid[s] == pid)
            break;
    if (pid < 0 || s == FARR_MAX_JOBS) {
        p->bad = 1;
        p->running = pid < 0 ? 0 : p->running;
        return;
    }
    p->pid[s] = 0;
    p->running--;
    if (code == 10)
        snprintf(st[p->art[s]], FAR_ST, "clean");
    else if (code == 11)
        snprintf(st[p->art[s]], FAR_ST, "reproduces");
    else if (code == 12)
        snprintf(st[p->art[s]], FAR_ST, "nobin");
    else
        p->bad = 1;
}

static int farr_spawn(struct far_ctx *c, struct farr_pool *p, const char *work,
                      int art)
{
    pid_t pid;
    int s = 0;
    while (p->pid[s] != 0)
        s++;
    fflush(c->out);
    fflush(c->err);
    pid = fork();
    if (pid < 0)
        return 2;
    if (pid == 0)
        farr_child(c, work, art);
    p->pid[s] = pid;
    p->art[s] = art;
    p->running++;
    return 0;
}

static int farr_stage(struct far_ctx *c, const char *work, const int *sel,
                      int n_sel, char st[][FAR_ST])
{
    struct farr_pool p;
    int jobs = c->jobs < 1 ? 1 : c->jobs > FARR_MAX_JOBS ? FARR_MAX_JOBS
                                                          : c->jobs;
    memset(&p, 0, sizeof p);
    for (int k = 0; k < n_sel && !p.bad; k++) {
        while (p.running >= jobs && p.running > 0)
            farr_reap(&p, st);
        if (!p.bad && farr_spawn(c, &p, work, sel[k]) != 0)
            p.bad = 1;
    }
    while (p.running > 0)
        farr_reap(&p, st);
    if (p.bad) {
        fprintf(c->err, "%s: FATAL — the replay stage exited 125.\n",
                k_far_gate);
        fputs("  Not one artifact's result can be trusted, so this run "
              "reports\n", c->err);
        fputs("  nothing rather than reporting clean. Check "
              "ZCL_FUZZ_REPLAY_JOBS\n", c->err);
        fprintf(c->err, "  (currently '%d'), and check the stderr above "
                        "this line.\n", c->jobs);
        return 2;
    }
    return 0;
}

static int farr_account(struct far_ctx *c, const int *sel, int n_sel,
                        char st[][FAR_ST])
{
    int miss[FAR_SEL], n_miss = 0;
    for (int k = 0; k < n_sel; k++)
        if (!st[sel[k]][0] && n_miss < FAR_SEL)
            miss[n_miss++] = sel[k];
    if (n_miss == 0)
        return 0;
    fprintf(c->err, "%s: FATAL — %d of %d selected artifact(s) came back "
                    "with no result.\n", k_far_gate, n_miss, n_sel);
    fputs("  The replay stage exited 0 but did not account for every "
          "artifact\n", c->err);
    fputs("  it was given. A missing result is not a pass: these were "
          "never\n", c->err);
    fputs("  run, so nothing is known about them.\n", c->err);
    for (int k = 0; k < n_miss; k++)
        fprintf(c->err, "    %s/%s\n", k_far_seed_root,
                c->artifacts[miss[k]]);
    return 2;
}

static int farr_confirm(struct far_ctx *c, const char *work, const int *sel,
                        int n_sel, char st[][FAR_ST])
{
    for (int k = 0; k < n_sel; k++) {
        int i = sel[k], li;
        const char *rel = c->artifacts[i];
        if (strcmp(st[i], "reproduces") != 0)
            continue;
        li = far_ledger_find(c, rel);
        if (li >= 0 && (!strcmp(c->ledger[li].verdict, "open") ||
                        !strcmp(c->ledger[li].verdict, "accepted")))
            continue;
        char cst[FAR_ST] = "";
        if (farr_replay_one(c, work, rel, c->confirm_timeout, cst,
                            FAR_ST) != 0 || !cst[0]) {
            fprintf(c->err, "%s: FATAL — the confirmation re-run of %s "
                            "produced no result.\n", k_far_gate, rel);
            fputs("  Same rule as the first pass: an artifact with no verdict "
                  "is a\n", c->err);
            fputs("  failure, not a nothing. Refusing to guess which it "
                  "was.\n", c->err);
            return 2;
        }
        snprintf(st[i], FAR_ST, "%s", cst);
        if (!strcmp(cst, "clean"))
            fprintf(c->out, "[%s] %s tripped %ds under load but is clean at "
                            "%ds serial — treated as load noise, not a "
                            "finding\n", k_far_gate, rel, c->replay_timeout,
                    c->confirm_timeout);
    }
    return 0;
}

static void farr_open_clean(struct far_ctx *c, int i, const char *work)
{
    const char *rel = c->artifacts[i];
    const char *kind = c->kind_of[i];
    const char *sl = strchr(rel, '/');
    char corpus[FAR_KIND], pi[FAR_PATH];
    struct stat sb;
    const char *pi_status = "";
    size_t cl = sl ? (size_t)(sl - rel) : strlen(rel);
    if (cl >= sizeof corpus)
        cl = sizeof corpus - 1;
    memcpy(corpus, rel, cl);
    corpus[cl] = '\0';
    if (!far_kind_needs_pi(kind)) {
        far_report(c, "%s/%s [ledger says 'open' but it no longer "
                      "reproduces]", k_far_seed_root, rel);
        far_note(c, "Fixed? Then say so — reclassify to 'regression-seed' "
                    "in");
        far_note(c, "%s with today's date and the commit that fixed it.",
                 k_far_ledger);
        far_note(c, "A stale 'open' is how a ledger rots into decoration.");
        return;
    }
    if (ovf(snprintf(pi, sizeof pi, "%s/%s/fuzz_%s", c->root, c->pi_bin_dir,
                     corpus), sizeof pi))
        return;
    if (stat(pi, &sb) == 0 && (sb.st_mode & S_IXUSR)) {
        char st[FAR_ST] = "";
        if (farr_exec(c, pi, rel, c->confirm_timeout, work, st, FAR_ST))
            return;
        pi_status = strcmp(st, "clean") == 0 ? "clean" : "reproduces";
    }
    if (!strcmp(pi_status, "reproduces")) {
        fprintf(c->out, "[%s] %s: stock replay is clean but pattern-init "
                        "still reproduces — 'open' stands, this is NOT a "
                        "stale verdict\n", k_far_gate, rel);
        return;
    }
    if (!pi_status[0]) {
        far_report(c, "%s/%s [ledger says 'open', stock replay is clean, and "
                      "there is no pattern-init binary to confirm it — cannot "
                      "tell]", k_far_seed_root, rel);
        far_note(c, "Build it:  make BUILD_DIR=%s/.. "
                    "ZCL_FUZZ_EXTRA_CFLAGS=-ftrivial-auto-var-init=pattern "
                    "fuzz_%s", c->pi_bin_dir, corpus);
        far_note(c, "then re-run. Neither reclassifying nor leaving this "
                    "stale is");
        far_note(c, "safe without that answer for a %s finding.", kind);
        return;
    }
    far_report(c, "%s/%s [ledger says 'open' but it no longer reproduces]",
               k_far_seed_root, rel);
    far_note(c, "Fixed? Then say so — reclassify to 'regression-seed' in");
    far_note(c, "%s with today's date and the commit that fixed it.",
             k_far_ledger);
    far_note(c, "A stale 'open' is how a ledger rots into decoration.");
}

static void farr_verdict_clean(struct far_ctx *c, int i, const char *work)
{
    int li = far_ledger_find(c, c->artifacts[i]);
    const char *v = li >= 0 ? c->ledger[li].verdict : "";
    if (!strcmp(v, "regression-seed"))
        return;
    if (!strcmp(v, "open")) {
        farr_open_clean(c, i, work);
        return;
    }
    if (!strcmp(v, "accepted")) {
        far_report(c, "%s/%s [ledger says 'accepted' but it no longer "
                      "reproduces]", k_far_seed_root, c->artifacts[i]);
        far_note(c, "Reclassify to 'regression-seed' — an 'accepted' entry "
                    "that");
        far_note(c, "does nothing is an exemption nobody is checking.");
    }
}

static void farr_verdict_repro(struct far_ctx *c, int i)
{
    const char *rel = c->artifacts[i];
    const char *sl = strchr(rel, '/');
    char corpus[FAR_KIND], cmd[FAR_PATH * 2];
    int li = far_ledger_find(c, rel);
    const char *v = li >= 0 ? c->ledger[li].verdict : "";
    const char *dt = li >= 0 && c->ledger[li].date[0] ? c->ledger[li].date
                                                      : "?";
    const char *rs = li >= 0 ? c->ledger[li].reason : "";
    size_t cl = sl ? (size_t)(sl - rel) : strlen(rel);
    if (cl >= sizeof corpus)
        cl = sizeof corpus - 1;
    memcpy(corpus, rel, cl);
    corpus[cl] = '\0';
    if (ovf(snprintf(cmd, sizeof cmd,
                     "ASAN_OPTIONS=detect_leaks=0:symbolize=0 timeout -k 5 %d "
                     "%s/fuzz_%s -timeout=%d -runs=1 -artifact_prefix=/tmp/ "
                     "%s/%s", c->confirm_timeout + 10, c->bin_dir, corpus,
                     c->confirm_timeout, k_far_seed_root, rel), sizeof cmd))
        return;
    if (!strcmp(v, "regression-seed")) {
        far_report(c, "%s/%s [REGRESSION — recorded clean on %s, hangs/crashes "
                      "NOW]", k_far_seed_root, rel, dt);
        far_note(c, "This artifact was audited and passed. It does not any "
                    "more.");
        far_note(c, "Reproduce it:  %s", cmd);
    } else if (!strcmp(v, "open")) {
        far_report(c, "%s/%s [LIVE — still reproduces; filed %s]",
                   k_far_seed_root, rel, dt);
        far_note(c, "%s", rs);
        far_note(c, "Reproduce it:  %s", cmd);
    }
}

/* Selection and per-state tallies of one replay phase. */
struct farr_tally {
    int sel[FAR_SEL], live[FAR_SEL];
    int n_sel, n_clean, n_repro, n_nobin, n_live;
};

static void farr_empty_selection(struct far_ctx *c)
{
    fprintf(c->err, "%s: FATAL — nothing was selected for replay.\n",
            k_far_gate);
    fprintf(c->err, "  %d artifact(s) were enumerated%s.\n",
            c->n_artifacts, c->only_corpora[0] ? ", then --corpus=" : "");
    if (c->only_corpora[0])
        fprintf(c->err, "  %s\n", c->only_corpora);
    fputs("  A replay run that replays nothing has proved nothing, so it "
          "does\n", c->err);
    fputs("  not get to exit 0. Widen or drop the --corpus filter.\n",
          c->err);
}

/* Makes the scratch dir and picks the artifacts; 0 ok, 2 error (work removed). */
static int farr_prepare(struct far_ctx *c, char *work, size_t cap,
                        struct farr_tally *t)
{
    if (ovf(snprintf(work, cap, "%s/zcl-fuzz-replay.XXXXXX",
                     env_or("TMPDIR", "/tmp")), cap))
        return 2;
    if (!mkdtemp(work)) {
        fprintf(c->err, "%s: mkdtemp failed\n", k_far_gate);
        return 2;
    }
    if (!farr_corpora_ok(c) || farr_selected(c, t->sel, &t->n_sel) != 0) {
        rap_rm_rf(work);
        return 2;
    }
    if (t->n_sel == 0) {
        farr_empty_selection(c);
        rap_rm_rf(work);
        return 2;
    }
    return 0;
}

static void farr_grade_nobin(struct far_ctx *c, const char *rel)
{
    const char *sl = strchr(rel, '/');
    char corpus[FAR_KIND];
    size_t cl = sl ? (size_t)(sl - rel) : strlen(rel);
    if (cl >= sizeof corpus)
        cl = sizeof corpus - 1;
    memcpy(corpus, rel, cl);
    corpus[cl] = '\0';
    far_report(c, "%s/%s [%s/fuzz_%s MISSING — cannot replay]",
               k_far_seed_root, rel, c->bin_dir, corpus);
    far_note(c, "Build it:  make fuzz_%s", corpus);
    far_note(c, "This is a FAILURE, not a skip: an artifact nobody "
                "replays is");
    far_note(c, "an artifact nobody reads, which is the whole "
                "incident.");
}

static void farr_grade_unaccounted(struct far_ctx *c, int i, const char *s)
{
    far_report(c, "%s/%s [UNACCOUNTED — replay state '%s' is not a "
                  "verdict]", k_far_seed_root, c->artifacts[i],
               s[0] ? s : "<empty>");
    far_note(c, "Every replayed artifact must come back clean, "
                "reproduces or");
    far_note(c, "nobin. Anything else means this file's result was "
                "lost, and a");
    far_note(c, "lost result is an unread finding — the whole "
                "incident.");
}

static void farr_grade_repro(struct far_ctx *c, int i, struct farr_tally *t)
{
    int li = far_ledger_find(c, c->artifacts[i]);
    const char *v = li >= 0 ? c->ledger[li].verdict : "";
    t->n_repro++;
    if (strcmp(v, "accepted") != 0)
        farr_verdict_repro(c, i);
    else if (t->n_live < FAR_SEL)
        t->live[t->n_live++] = i;
}

static void farr_grade(struct far_ctx *c, const char *work, struct farr_tally *t,
                       char st[][FAR_ST])
{
    for (int k = 0; k < t->n_sel; k++) {
        int i = t->sel[k];
        if (!strcmp(st[i], "nobin")) {
            t->n_nobin++;
            farr_grade_nobin(c, c->artifacts[i]);
        } else if (!strcmp(st[i], "clean")) {
            t->n_clean++;
            farr_verdict_clean(c, i, work);
        } else if (!strcmp(st[i], "reproduces")) {
            farr_grade_repro(c, i, t);
        } else {
            farr_grade_unaccounted(c, i, st[i]);
        }
    }
}

static void farr_nobin_summary(struct far_ctx *c, int n_nobin)
{
    fprintf(c->out, "[%s] %d artifact(s) had NO BINARY to replay against. "
                    "That is a\n", k_far_gate, n_nobin);
    fprintf(c->out, "[%s] failure, not a skip — an artifact nobody "
                    "replays is an artifact\n", k_far_gate);
    fprintf(c->out, "[%s] nobody reads. Build them:  make fuzz\n",
            k_far_gate);
    fprintf(c->out, "[%s] (a fresh worktree has none until you do; that "
                    "is this case)\n", k_far_gate);
}

static void farr_live_summary(struct far_ctx *c, const struct farr_tally *t)
{
    fprintf(c->out, "[%s] %d artifact(s) reproduce and are explicitly "
                    "ACCEPTED:\n", k_far_gate, t->n_live);
    for (int k = 0; k < t->n_live; k++) {
        int li = far_ledger_find(c, c->artifacts[t->live[k]]);
        const char *rs = li >= 0 ? c->ledger[li].reason : "";
        fprintf(c->out, "[%s]   %s — %s\n", k_far_gate,
                c->artifacts[t->live[k]], rs);
    }
}

static void farr_summary(struct far_ctx *c, const struct farr_tally *t)
{
    if (t->n_live > 0)
        farr_live_summary(c, t);
    fprintf(c->out, "[%s] replayed %d: %d clean, %d reproducing, %d "
                    "unreplayable\n", k_far_gate, t->n_sel, t->n_clean,
            t->n_repro, t->n_nobin);
    fprintf(c->out, "[%s] %d violation(s) found (mode: %s)\n", k_far_gate,
            c->violations, c->mode);
    if (t->n_nobin > 0)
        farr_nobin_summary(c, t->n_nobin);
    if (c->violations > t->n_nobin) {
        fprintf(c->out, "[%s] A saved fuzz finding that still reproduces is a "
                        "bug the node has\n", k_far_gate);
        fprintf(c->out, "[%s] TODAY, on a path a peer can reach. Fix it, or — "
                        "if it is genuinely\n", k_far_gate);
        fprintf(c->out, "[%s] a non-bug — add a per-file 'accepted' line to "
                        "%s\n", k_far_gate, k_far_ledger);
        fprintf(c->out, "[%s] saying why. There is no directory-wide exemption "
                        "on purpose.\n", k_far_gate);
    }
}

int far_replay_phase(struct far_ctx *c)
{
    static char work[FAR_PATH];
    static char st[FAR_ARTIFACTS][FAR_ST];
    static struct farr_tally t;
    memset(&t, 0, sizeof t);
    if (farr_prepare(c, work, sizeof work, &t) != 0)
        return 2;
    fprintf(c->out, "[%s] replaying %d artifact(s) at -timeout=%ds, %d at a "
                    "time\n", k_far_gate, t.n_sel, c->replay_timeout, c->jobs);
    for (int i = 0; i < c->n_artifacts; i++)
        st[i][0] = '\0';
    if (farr_stage(c, work, t.sel, t.n_sel, st) != 0 ||
        farr_account(c, t.sel, t.n_sel, st) != 0 ||
        farr_confirm(c, work, t.sel, t.n_sel, st) != 0) {
        rap_rm_rf(work);
        return 2;
    }
    farr_grade(c, work, &t, st);
    rap_rm_rf(work);
    farr_summary(c, &t);
    return c->violations > 0 && !strcmp(c->mode, "FAIL") ? 1 : 0;
}
