/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check_quality_lane_freshness
 * (gate_quality_lane_freshness.c). Builds a throwaway upstream repo and
 * clone under the lint scratch dir and proves: at tip rc 0, behind rc 1
 * with the count, ahead rc 0, not a git checkout rc 2, unresolvable ref
 * rc 2, refresh fast-forwards a clean behind tree, and refresh refuses a
 * dirty tree rc 2, never discarding the change.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_quality_lane_freshness_priv.h"

static const char k_qfs_gate[] = "check_quality_lane_freshness";
static char k_up[QF_PATH], k_cl[QF_PATH], k_work[QF_PATH];
static FILE *k_quiet;

static int qfs_git(const char *root, char **args)
{
    char out[QF_LINE];
    size_t n = 0;
    return qf_git(root, args, out, sizeof out, &n);
}

static int qfs_commit(const char *root, const char *msg)
{
    char *args[10] = { (char *)"-c", (char *)"user.email=t@t",
                      (char *)"-c", (char *)"user.name=t",
                      (char *)"commit", (char *)"-q",
                      (char *)"--allow-empty", (char *)"-m", NULL, NULL };
    args[8] = (char *)msg;
    return qfs_git(root, args);
}

static int qfs_setup(void)
{
    char *init[5] = { (char *)"init", (char *)"-q", (char *)"-b",
                      (char *)"main", NULL };
    char *clone[5] = { (char *)"clone", (char *)"-q", NULL, NULL, NULL };
    char *detach[5] = { (char *)"checkout", (char *)"-q",
                        (char *)"--detach", (char *)"HEAD", NULL };
    clone[2] = k_up;
    clone[3] = k_cl;
    if (qfs_git(k_up, init) != 0)
        return 2;
    if (qfs_commit(k_up, "c1") != 0)
        return 2;
    if (qfs_git(NULL, clone) != 0)
        return 2;
    return qfs_git(k_cl, detach);
}

static int qfs_fail(const char *why, const char *out)
{
    fprintf(stderr, "%s --selftest: FAIL — %s\n", k_qfs_gate, why);
    if (out && out[0])
        fprintf(stderr, "%s\n", out);
    return 1;
}

static int qfs_report_case(const char *root, const char *ref, int want,
                           const char *needle, const char *why)
{
    char line[QF_LINE];
    int rc = qf_report(root, ref, line, sizeof line, k_quiet);
    if (rc != want || (needle && !strstr(line, needle)))
        return qfs_fail(why, line);
    return 0;
}

static int qfs_case_not_git(void)
{
    char nogit[QF_PATH];
    if (ovf(snprintf(nogit, sizeof nogit, "%s/nogit", k_work), sizeof nogit))
        return 2;
    if (csr_mkdirs(nogit) != 0)
        return 2;
    return qfs_report_case(nogit, "main", 2, NULL,
                           "non-git dir fails closed");
}

static int qfs_case_unresolvable(void)
{
    return qfs_report_case(k_cl, "no-such-ref", 2, NULL,
                           "unresolvable ref fails closed");
}

static int qfs_case_ahead(void)
{
    char *co[4] = { (char *)"checkout", (char *)"-q", (char *)"main", NULL };
    char *br[4] = { (char *)"branch", (char *)"oldmain", (char *)"main", NULL };
    if (qfs_git(k_cl, co) != 0)
        return 2;
    if (qfs_git(k_cl, br) != 0)
        return 2;
    if (qfs_commit(k_cl, "c5") != 0)
        return 2;
    return qfs_report_case(k_cl, "oldmain", 0, "note=root_is_ahead",
                           "ahead of ref reports rc 0");
}

/* Runs check or refresh on root, captures its stderr and demands rc plus a
 * distinguishing needle in it (never rc alone). */
static int qfs_err_case(const char *root, int refresh, int want,
                        const char *needle, const char *why)
{
    char buf[4096];
    FILE *cap = tmpfile(), *sink = tmpfile();
    int bad = 0;
    if (!cap || !sink) {
        if (cap)
            fclose(cap);
        if (sink)
            fclose(sink);
        return 2;
    }
    int rc = refresh ? qf_do_refresh(root, "main", sink, cap)
                     : qf_do_check(root, "main", sink, cap);
    rewind(cap);
    size_t n = fread(buf, 1, sizeof buf - 1, cap);
    buf[n] = '\0';
    if (rc != want)
        bad = qfs_fail(why, buf);
    else if (!strstr(buf, needle))
        bad = qfs_fail(why, buf);
    fclose(cap);
    fclose(sink);
    return bad;
}

static int qfs_clone(const char *name, char *path, size_t cap)
{
    char *clone[5] = { (char *)"clone", (char *)"-q", NULL, NULL, NULL };
    if (ovf(snprintf(path, cap, "%s/%s", k_work, name), cap))
        return 2;
    clone[2] = k_up;
    clone[3] = path;
    return qfs_git(NULL, clone) == 0 ? 0 : 2;
}

static int qfs_pull_main(const char *root)
{
    char *fe[5] = { (char *)"fetch", (char *)"-q", NULL, (char *)"main:main",
                    NULL };
    fe[2] = k_up;
    return qfs_git(root, fe) == 0 ? 0 : 2;
}

static int qfs_case_dirty_refresh(void)
{
    char dirt[QF_PATH];
    char *det[5] = { (char *)"checkout", (char *)"-q", (char *)"--detach",
                     (char *)"HEAD", NULL };
    if (ovf(snprintf(dirt, sizeof dirt, "%s/untracked-dirt.txt", k_cl),
            sizeof dirt))
        return 2;
    if (qfs_git(k_cl, det) != 0 || qfs_commit(k_up, "c4") != 0
        || qfs_pull_main(k_cl) != 0 || csr_write(dirt, "dirty\n") != 0)
        return 2;
    int bad = qfs_err_case(k_cl, 1, 2, "REFUSING to refresh",
                           "refresh did not refuse a DIRTY tree plainly");
    unlink(dirt);
    return bad;
}

static int qfs_case_wrong_branch(void)
{
    char p[QF_PATH];
    char *co[5] = { (char *)"checkout", (char *)"-q", (char *)"-b",
                    (char *)"other", NULL };
    if (qfs_clone("wrongbranch", p, sizeof p) != 0 || qfs_git(p, co) != 0
        || qfs_commit(k_up, "c6") != 0 || qfs_pull_main(p) != 0)
        return 2;
    return qfs_err_case(p, 1, 2, "is on branch 'other', not 'main'",
                        "refresh did not refuse a non-main branch plainly");
}

static int qfs_head(const char *root, char sha[QF_SHA])
{
    char *rp[3] = { (char *)"rev-parse", (char *)"HEAD", NULL };
    size_t n = 0;
    if (qf_git(root, rp, sha, QF_SHA, &n) != 0)
        return -1;
    while (n > 0 && sha[n - 1] == '\n')
        sha[--n] = '\0';
    return 0;
}

static int qfs_case_diverged(void)
{
    char p[QF_PATH], before[QF_SHA], after[QF_SHA];
    char *det[5] = { (char *)"checkout", (char *)"-q", (char *)"--detach",
                     (char *)"HEAD", NULL };
    if (qfs_clone("diverged", p, sizeof p) != 0 || qfs_git(p, det) != 0
        || qfs_commit(p, "local-only") != 0 || qfs_commit(k_up, "c7") != 0
        || qfs_pull_main(p) != 0)
        return 2;
    if (qfs_head(p, before) != 0)
        return 2;
    int bad = qfs_err_case(p, 0, 2, "have DIVERGED",
                           "diverged history was not reported as DIVERGED");
    bad |= qfs_err_case(p, 1, 2, "have DIVERGED",
                        "refresh on diverged history did not abort");
    if (qfs_head(p, after) != 0 || strcmp(before, after) != 0)
        bad |= qfs_fail("refresh moved HEAD on diverged history", "");
    return bad;
}

static int qfs_case_origin_down(void)
{
    char p[QF_PATH];
    char *det[5] = { (char *)"checkout", (char *)"-q", (char *)"--detach",
                     (char *)"HEAD", NULL };
    char *del[5] = { (char *)"branch", (char *)"-q", (char *)"-D",
                     (char *)"main", NULL };
    char *url[6] = { (char *)"remote", (char *)"set-url", (char *)"origin",
                     (char *)"/nonexistent/z23-origin", NULL, NULL };
    if (qfs_clone("noorigin", p, sizeof p) != 0 || qfs_git(p, det) != 0
        || qfs_git(p, del) != 0 || qfs_git(p, url) != 0)
        return 2;
    return qfs_err_case(p, 0, 2, "'git fetch origin main' failed",
                        "unreachable origin did not fail closed");
}

static int qfs_case_refresh_ok(void)
{
    char line[QF_LINE];
    int bad = 0;
    FILE *sink = tmpfile();
    if (!sink)
        return 2;
    int rrc = qf_do_refresh(k_cl, "main", sink, k_quiet);
    fclose(sink);
    if (rrc != 0)
        bad |= qfs_fail("refresh did not succeed on a safe case", "");
    int prc = qf_report(k_cl, "main", line, sizeof line, k_quiet);
    if (prc != 0 || !strstr(line, "commits_behind=0"))
        bad |= qfs_fail("refresh ran but tree is still behind", line);
    return bad;
}

static int qfs_cases(void)
{
    int bad = 0;
    char *fe[5] = { (char *)"fetch", (char *)"-q", NULL, (char *)"main:main",
                    NULL };
    bad |= qfs_report_case(k_cl, "main", 0, "commits_behind=0",
                           "fresh clone at tip reports 0 behind");
    if (qfs_commit(k_up, "c2") != 0 || qfs_commit(k_up, "c3") != 0)
        return 2;
    fe[2] = k_up;
    if (qfs_git(k_cl, fe) != 0)
        return 2;
    bad |= qfs_report_case(k_cl, "main", 1, "commits_behind=2",
                           "behind by two commits is detected");
    bad |= qfs_case_not_git();
    bad |= qfs_case_unresolvable();
    bad |= qfs_case_refresh_ok();
    bad |= qfs_case_dirty_refresh();
    bad |= qfs_case_wrong_branch();
    bad |= qfs_case_diverged();
    bad |= qfs_case_origin_down();
    bad |= qfs_case_ahead();
    return bad;
}

int check_quality_lane_freshness_selftest(void)
{
    int rc = lct_scratch_dir(k_work, sizeof k_work, "quality-lane-freshness");
    if (rc)
        return rc;
    if (ovf(snprintf(k_up, sizeof k_up, "%s/upstream", k_work), sizeof k_up)
        || ovf(snprintf(k_cl, sizeof k_cl, "%s/clone", k_work), sizeof k_cl))
        return 2;
    k_quiet = tmpfile();
    int bad = 2;
    if (k_quiet && csr_mkdirs(k_up) == 0 && qfs_setup() == 0)
        bad = qfs_cases();
    if (k_quiet)
        fclose(k_quiet);
    rap_rm_rf(k_work);
    if (bad) {
        fprintf(stderr, "FAIL: %s selftest\n", k_qfs_gate);
        return 1;
    }
    printf("[%s] selftest: 0-behind clean, N-behind detected, safe refresh "
           "fast-forwards, dirty refresh refuses\n", k_qfs_gate);
    return 0;
}
