/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check_quality_lane_freshness — is the background quality lane's
 * own checkout at (or ahead of) the ref tip, or pinned behind it? Ported
 * from tools/scripts/check_quality_lane_freshness.sh (deleted). Tool modes
 * --check (default) | --refresh | --selftest, options --root=DIR --ref=REF.
 * Exit 0 at tip or ahead, 1 behind, 2 cannot determine or cannot safely
 * act. Fail closed. (The shell original documented a ZCL_LINT_MODE=WARN
 * downgrade of exit 1, but set -e made it unreachable; the port keeps the
 * real behaviour, exit 1 in every mode.)
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
#include "gate_quality_lane_freshness_priv.h"

static const char k_qf_gate[] = "check_quality_lane_freshness";

static void qf_trim(char *s, size_t n)
{
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
        n--;
    s[n] = '\0';
}
/* Drains fd into out (NUL-terminated, at most cap-1 bytes). Returns the byte
 * count, or -1 on a read error other than EINTR (caller fails closed). */
static ssize_t qf_drain(int fd, char *out, size_t cap)
{
    size_t n = 0;
    for (;;) {
        ssize_t r = read(fd, out + n, cap - 1 - n);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            out[n] = '\0';
            return -1;
        }
        if (r == 0)
            break;
        n += (size_t)r;
        if (n + 1 >= cap)
            break;
    }
    out[n] = '\0';
    return (ssize_t)n;
}


/* Runs git (optionally with -C root), child stderr silenced, stdout drained
 * into out. Returns the exit status, 128+sig, or -1 on failure to run. */
int qf_git(const char *root, char **args, char *out, size_t cap, size_t *olen)
{
    enum { MAXV = 20 };
    char *gv[MAXV];
    int pfd[2];
    size_t n = 0, ai = 1;
    gv[0] = (char *)"git";
    if (root) {
        gv[1] = (char *)"-C";
        gv[2] = (char *)root;
        ai = 3;
    }
    for (size_t i = 0; args && args[i]; i++) {
        if (ai + 1 >= MAXV)
            return -1;
        gv[ai++] = args[i];
    }
    gv[ai] = NULL;
    if (pipe(pfd) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul < 0)
            _exit(127);
        dup2(pfd[1], 1);
        dup2(nul, 2);
        execvp("git", gv);
        _exit(127);
    }
    close(pfd[1]);
    ssize_t got = qf_drain(pfd[0], out, cap);
    close(pfd[0]);
    n = got < 0 ? 0 : (size_t)got;
    int st = -1;
    if (waitpid(pid, &st, 0) != pid || got < 0)
        return -1;
    *olen = n;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return -1;
}

static int qf_sha(const char *root, const char *spec, char sha[QF_SHA])
{
    char out[QF_SHA], *args[3] = { (char *)"rev-parse", (char *)spec, NULL };
    size_t n = 0;
    sha[0] = '\0';
    if (qf_git(root, args, out, sizeof out, &n) != 0)
        return -1;
    qf_trim(out, n);
    if (out[0] == '\0')
        return -1;
    snprintf(sha, QF_SHA, "%s", out);
    return 0;
}

static int qf_ref_local(const char *root, const char *ref, char sha[QF_SHA])
{
    char spec[QF_LINE];
    if (ovf(snprintf(spec, sizeof spec, "refs/heads/%s", ref), sizeof spec))
        return -1;
    char *va[5] = { (char *)"rev-parse", (char *)"--verify", (char *)"-q",
                    NULL };
    va[3] = spec;
    char out[QF_SHA];
    size_t n = 0;
    if (qf_git(root, va, out, sizeof out, &n) != 0)
        return 0;
    return qf_sha(root, spec, sha) == 0 ? 1 : -1;
}

static int qf_ref_origin(const char *root, const char *ref, char sha[QF_SHA],
                         FILE *err)
{
    char out[QF_SHA], *fa[5] = { (char *)"fetch", (char *)"--quiet",
                                 (char *)"origin", NULL };
    fa[3] = (char *)ref;
    size_t n = 0;
    if (qf_git(root, fa, out, sizeof out, &n) != 0) {
        fprintf(err,
                "%s: FATAL — no local 'refs/heads/%s' in '%s' and "
                "'git fetch origin %s' failed\n"
                "  Refusing to report a commits-behind count without a resolved tip: that is\n"
                "  exactly the silent-stale shape this gate exists to close.\n",
                k_qf_gate, ref, root, ref);
        return -1;
    }
    if (qf_sha(root, "FETCH_HEAD", sha) != 0) {
        fprintf(err,
                "%s: FATAL — fetched origin/%s but cannot resolve FETCH_HEAD\n",
                k_qf_gate, ref);
        return -1;
    }
    return 0;
}

static int qf_ancestor(const char *root, const char *a, const char *b)
{
    char *args[5] = { (char *)"merge-base", (char *)"--is-ancestor",
                      (char *)a, (char *)b, NULL };
    char out[8];
    size_t n = 0;
    return qf_git(root, args, out, sizeof out, &n) == 0;
}

static int qf_ref_head(const char *root, const char *ref, char sha[QF_SHA],
                       const char **source, FILE *err)
{
    int rc = qf_ref_local(root, ref, sha);
    if (rc < 0)
        return -1;
    if (rc == 1) {
        *source = "local";
        return 0;
    }
    rc = qf_ref_origin(root, ref, sha, err);
    if (rc == 0)
        *source = "origin";
    return rc;
}

static int qf_line(char *line, size_t cap, const char *behind,
                   const char *root_head, const char *ref_head,
                   const char *source, const char *note)
{
    if (ovf(snprintf(line, cap, "commits_behind=%s root_head=%s "
                    "ref_head=%s ref_source=%s%s", behind, root_head,
                    ref_head, source, note),
            cap))
        return 2;
    return 0;
}

int qf_report(const char *root, const char *ref, char *line, size_t cap,
              FILE *err)
{
    char root_head[QF_SHA], ref_head[QF_SHA];
    const char *source = "local";
    line[0] = '\0';
    char *inside[3] = { (char *)"rev-parse", (char *)"--is-inside-work-tree",
                        NULL };
    char out[8];
    size_t n = 0;
    if (qf_git(root, inside, out, sizeof out, &n) != 0) {
        fprintf(err, "%s: FATAL — '%s' is not a git checkout\n", k_qf_gate,
                root);
        return 2;
    }
    if (qf_sha(root, "HEAD", root_head) != 0) {
        fprintf(err, "%s: FATAL — cannot resolve HEAD in '%s'\n", k_qf_gate,
                root);
        return 2;
    }
    if (qf_ref_head(root, ref, ref_head, &source, err) != 0)
        return 2;
    if (strcmp(root_head, ref_head) == 0)
        return qf_line(line, cap, "0", root_head, ref_head, source, "");
    if (qf_ancestor(root, root_head, ref_head)) {
        char range[2 * QF_SHA + 4], cnt[32] = "?";
        if (ovf(snprintf(range, sizeof range, "%s..%s", root_head, ref_head),
                sizeof range))
            return 2;
        char co[32], *ca[5] = { (char *)"rev-list", (char *)"--count", NULL,
                                NULL };
        ca[2] = range;
        size_t cn = 0;
        if (qf_git(root, ca, co, sizeof co, &cn) == 0) {
            qf_trim(co, cn);
            snprintf(cnt, sizeof cnt, "%s", co);
        }
        if (qf_line(line, cap, cnt, root_head, ref_head, source, ""))
            return 2;
        return 1;
    }
    if (qf_ancestor(root, ref_head, root_head))
        return qf_line(line, cap, "0", root_head, ref_head, source,
                       " note=root_is_ahead");
    fprintf(err,
            "%s: FATAL — '%s' HEAD (%s) and %s (%s) have DIVERGED\n"
            "  Neither is an ancestor of the other. A commits-behind count is not\n"
            "  meaningful here; this needs a human, not an automatic refresh.\n",
            k_qf_gate, root, root_head, ref, ref_head);
    return 2;
}

int qf_do_check(const char *root, const char *ref, FILE *out, FILE *err)
{
    char line[QF_LINE];
    int rc = qf_report(root, ref, line, sizeof line, err);
    fprintf(out, "%s\n", line);
    fflush(out);
    if (rc == 1)
        fprintf(err,
                "%s: '%s' is BEHIND %s — the quality lanes it drives are\n"
                "  fuzzing/testing OLD code. Refresh with:\n"
                "  z23-lint check-quality-lane-freshness --refresh --root=%s --ref=%s\n",
                k_qf_gate, root, ref, root, ref);
    return rc;
}

int qf_do_refresh(const char *root, const char *ref, FILE *out, FILE *err)
{
    char line[QF_LINE], buf[QF_LINE], branch[QF_LINE];
    size_t n = 0;
    int rc = qf_report(root, ref, line, sizeof line, err);
    fprintf(out, "%s\n", line);
    fflush(out);
    if (rc == 0) {
        fprintf(out,
                "%s: '%s' is already at (or ahead of) %s — nothing to refresh\n",
                k_qf_gate, root, ref);
        return 0;
    }
    if (rc == 2) {
        fprintf(err,
                "%s: FATAL — cannot refresh: freshness could not be determined (see above)\n",
                k_qf_gate);
        return 2;
    }
    char *sa[3] = { (char *)"status", (char *)"--porcelain", NULL };
    if (qf_git(root, sa, buf, sizeof buf, &n) != 0) {
        fprintf(err, "%s: FATAL — 'git status' failed in '%s'\n", k_qf_gate,
                root);
        return 2;
    }
    if (buf[0] != '\0') {
        fprintf(err,
                "%s: REFUSING to refresh — '%s' has uncommitted changes.\n"
                "  A stale pin is a visible problem; discarding someone's work to fix it\n"
                "  would be a worse one. Commit or stash by hand, then re-run.\n",
                k_qf_gate, root);
        return 2;
    }
    char *ba[5] = { (char *)"symbolic-ref", (char *)"--short", (char *)"-q",
                    (char *)"HEAD", NULL };
    qf_git(root, ba, branch, sizeof branch, &n);
    qf_trim(branch, n);
    if (branch[0] != '\0' && strcmp(branch, ref) != 0) {
        fprintf(err,
                "%s: REFUSING to refresh — '%s' is on branch '%s', not '%s'.\n"
                "  Switching branches out from under a running lane is not this gate's job.\n",
                k_qf_gate, root, branch, ref);
        return 2;
    }
    if (branch[0] == '\0') {
        char *ca[4] = { (char *)"checkout", (char *)"-q", NULL, NULL };
        ca[2] = (char *)ref;
        if (qf_git(root, ca, buf, sizeof buf, &n) != 0) {
            fprintf(err, "%s: FATAL — 'git checkout %s' failed in '%s'\n",
                    k_qf_gate, ref, root);
            return 2;
        }
    }
    char *ma[5] = { (char *)"merge", (char *)"--ff-only", (char *)"-q", NULL };
    ma[3] = (char *)ref;
    if (qf_git(root, ma, buf, sizeof buf, &n) != 0) {
        fprintf(err,
                "%s: FATAL — 'git merge --ff-only %s' failed in '%s'\n"
                "  Not forcing it. Resolve by hand.\n",
                k_qf_gate, ref, root);
        return 2;
    }
    char new_head[QF_SHA];
    if (qf_sha(root, "HEAD", new_head) != 0)
        new_head[0] = '\0';
    fprintf(out, "%s: refreshed '%s' to %s (%s)\n", k_qf_gate, root, ref,
            new_head);
    return 0;
}

int check_quality_lane_freshness_run(int argc, char **argv)
{
    const char *action = "check", *root_arg = NULL, *ref = "main";
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--check") == 0)
            action = "check";
        else if (strcmp(a, "--refresh") == 0)
            action = "refresh";
        else if (strcmp(a, "--selftest") == 0)
            action = "selftest";
        else if (strncmp(a, "--root=", 7) == 0)
            root_arg = a + 7;
        else if (strncmp(a, "--ref=", 6) == 0)
            ref = a + 6;
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            printf("usage: %s [--check|--refresh|--selftest] [--root=DIR] "
                   "[--ref=REF]\n", k_qf_gate);
            return 0;
        } else {
            fprintf(stderr, "%s: unknown arg '%s'\n", k_qf_gate, a);
            return 2;
        }
    }
    if (strcmp(action, "selftest") == 0)
        return check_quality_lane_freshness_selftest();
    char rootbuf[QF_PATH];
    if (!root_arg && cic_repo_root(rootbuf, sizeof rootbuf) != 0)
        return 2;
    const char *root = root_arg ? root_arg : rootbuf;
    if (strcmp(action, "refresh") == 0)
        return qf_do_refresh(root, ref, stdout, stderr);
    return qf_do_check(root, ref, stdout, stderr);
}
