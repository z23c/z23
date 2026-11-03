/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_batch_restack: dev.batch.restack (tools/command/native_dev_batch_
 * restack.c), the C form of the restack-failed.sh bridge, on a temp lab with
 * real git clones and fake `dev land status` and systemctl programs.
 *
 * One ledger holds stranded stacks of every kind: s5 failed its agent-verify
 * gate with no land row (its av-fail.txt names a culprit file, wraps another
 * on a tab-led line and quotes a compiler line), s6 has a failed land row
 * after an earlier landed one, s7 is live, s8 passed (rc=0), s9 has a running
 * gate unit, s10 has no log, s11 landed. Lanes: restacked, named in the gate
 * failure (left for triage), failed twice, moved since review, already
 * pending, missing, already on main, and cx-* lanes with and without
 * baseline rows. --dry-run must change nothing; the write path must keep the
 * bridge's bytes. The 11-03 case: a lane left for triage keeps its
 * stacked.tsv row and requeue clears it. */

#include "test/test_dev_batch_fixture.h"

#define DBR_MAX 4096

struct dbr {
    struct dbf f;
    char ledger[1200], pending[1200], done[1200], stamp[1200];
    char lane[16][900];
    char sha[16][41];
    char moved_old[41];
};

enum { L_A, L_N, L_W, L_G, L_M, L_P, L_ON, L_CXI, L_CXO, L_F, L_S6N, L_L, L_R, L_U, L_X, L_D };

static const char *const dbr_names[] = {
    "lane-a", "lane-n", "lane-w", "lane-g", "lane-m", "lane-p", "lane-on",
    "cx-in", "cx-out", "lane-f", "lane-s6n", "lane-l", "lane-r", "lane-u",
    "lane-x", "lane-d"};
static const char *const dbr_files[] = {
    "a1.c", "tests/harness/src/test_named.c", "tests/harness/src/test_wrapped.c",
    "g1.c", "m1.c", "p1.c", NULL, "cx_old.c", "cx_new.c", "f1.c",
    "tests/harness/src/test_named.c", "l1.c", "r1.c", "u1.c", "x1.c", "d1.c"};

static bool dbr_gate(const struct dbf *f, const char *stack, const char *run,
                     const char *extra_name, const char *extra)
{
    char dir[1500], p[1700];
    (void)snprintf(dir, sizeof(dir),
                   "%s/.cache/development-scratch/z23/gate-submit/z23-stacks%s",
                   f->home, stack);
    if (!dbf_mkdirs(dir))
        return false;
    (void)snprintf(p, sizeof(p), "%s/run.log", dir);
    if (run && !dbf_put(p, run))
        return false;
    if (!extra_name)
        return true;
    (void)snprintf(p, sizeof(p), "%s/%s", dir, extra_name);
    return dbf_put(p, extra);
}

static bool dbr_fakes(const struct dbf *f, char *devbin, char *sysctl)
{
    char path[1700];
    (void)snprintf(devbin, 1000, "%s/dev-bin", f->fakes);
    (void)snprintf(sysctl, 1000, "%s/systemctl", f->fakes);
    (void)snprintf(path, sizeof(path), "%s/.local/state/z23/dev/land", f->home);
    return dbf_exec(devbin, "#!/bin/sh\necho '{\"ok\":true,\"rows\":[\"z23-stacks7:lane-l\"]}'\n") &&
           dbf_exec(sysctl, "#!/bin/sh\necho '  z23-gate-stack-s9.service loaded active running gate'\n") &&
           dbf_mkdirs(path);
}

static bool dbr_logs(const struct dbf *f)
{
    char p[1700], o[3000];
    if (!dbr_gate(f, "5", "STOP: agent-verify\nrc=1\n", "av-fail.txt",
                  "gcc -c foo/gccline.c\n"
                  "\ttests/harness/src/test_wrapped.c:12: wrapped\n"
                  "FAIL tests/harness/src/test_named.c:197 assertion\n"
                  "devbuild: x/devbuild_line.c\n") ||
        !dbr_gate(f, "6", "rc=1\n", "lint.log", "tests/harness/src/test_named.c\n") ||
        !dbr_gate(f, "7", "rc=1\n", NULL, NULL) ||
        !dbr_gate(f, "8", "step\nrc=0\n", NULL, NULL) ||
        !dbr_gate(f, "9", "rc=1\n", NULL, NULL) ||
        !dbr_gate(f, "11", "rc=1\n", NULL, NULL))
        return false;
    (void)snprintf(p, sizeof(p), "%s/.local/state/z23/dev/land/outcomes.jsonl", f->home);
    (void)snprintf(o, sizeof(o),
        "{\"worktree\":\"%s/development/z23/z23-stacks6\",\"state\":\"landed\"}\n"
        "{\"worktree\":\"%s/development/z23/z23-stacks6\",\"state\":\"failed\"}\n"
        "{\"worktree\":\"%s/development/z23/z23-stacks11\",\"state\":\"landed\"}\n",
        f->home, f->home, f->home);
    {
        char dir[1700];
        (void)snprintf(dir, sizeof(dir), "%s/.local/state/z23/dev/land", f->home);
        if (!dbf_mkdirs(dir))
            return false;
    }
    return dbf_put(p, o);
}

/* One ledger row per lane; stack id per lane. */
static bool dbr_state(struct dbr *r)
{
    static const char *const stack[] = {"s5", "s5", "s5", "s5", "s5", "s5", "s5",
                                        "s5", "s5", "s6", "s6", "s7", "s8", "s9",
                                        "s10", "s5"};
    char rows[16384], row[2200], restacked[4096];
    size_t i;
    rows[0] = '\0';
    for (i = 0; i < 16; i++) {
        const char *head = r->sha[i];
        if (i == L_M)
            head = r->moved_old;
        (void)snprintf(row, sizeof(row), "%s\t%s\t%s\n",
                       i == L_D ? "/nonexistent/lane-d" : r->lane[i], head,
                       stack[i]);
        (void)strncat(rows, row, sizeof(rows) - strlen(rows) - 1);
    }
    (void)snprintf(restacked, sizeof(restacked),
                   "%s\t%s\ts5\t2026-10-26T15:45:36Z\n%s\t%s\ts5\t2026-10-26T16:45:36Z\n",
                   r->lane[L_G], r->sha[L_G], r->lane[L_G], r->sha[L_G]);
    (void)snprintf(row, sizeof(row), "%s\talready pending\n", r->lane[L_P]);
    return dbf_put(r->ledger, rows) && dbf_put(r->done, restacked) &&
           dbf_put(r->pending, row);
}

static bool dbr_build(struct dbr *r)
{
    size_t i;
    if (!dbf_setup(&r->f, "restack"))
        return false;
    for (i = 0; i < 16; i++)
        if (i != L_D && !dbf_lane(&r->f, dbr_names[i], dbr_files[i], r->lane[i],
                                  r->sha[i]))
            return false;
    /* lane-m moves after review: a second commit changes its tree. */
    memcpy(r->moved_old, r->sha[L_M], 41);
    if (!dbf_commit_file(r->lane[L_M], "m2.c", "int m2;\n") ||
        !dbf_rev(r->lane[L_M], "HEAD", r->sha[L_M]))
        return false;
    (void)snprintf(r->ledger, sizeof(r->ledger), "%s/stacked.tsv", r->f.state);
    (void)snprintf(r->pending, sizeof(r->pending), "%s/stack-pending.txt", r->f.state);
    (void)snprintf(r->done, sizeof(r->done), "%s/restacked.tsv", r->f.state);
    (void)snprintf(r->stamp, sizeof(r->stamp), "%s/.restack-failed.stamp", r->f.state);
    return dbr_logs(&r->f) && dbr_state(r);
}

static void dbr_restack(struct dbr *r, const char *const *flags,
                        struct zcl_command_reply *reply, char *dump, size_t cap,
                        const char *devbin)
{
    char sysctl[1000], dev[1000];
    const char *pairs[] = {"dev_bin", dev, "systemctl", sysctl, NULL};
    (void)snprintf(dev, sizeof(dev), "%s", devbin);
    (void)snprintf(sysctl, sizeof(sysctl), "%s/systemctl", r->f.fakes);
    dbf_call(zcl_native_handle_dev_batch_restack, &r->f, pairs, flags, reply,
             dump, cap);
}

static bool dbr_row_in(const char *file_text, const char *lane)
{
    char key[1000];
    (void)snprintf(key, sizeof(key), "%s\t", lane);
    return strstr(file_text, key) != NULL;
}

static int dbr_t_registered(void)
{
    int failures = 0;
    TEST("restack: the leaf is registered and declares its keys") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "dev.batch.restack", NULL);
        ASSERT(spec != NULL);
        ASSERT(strstr(spec->input_keys, "dry_run") != NULL);
        ASSERT(strstr(spec->input_keys, "now") != NULL);
        PASS();
    }
_test_next:;
    return failures;
}

static int dbr_t_unreadable(struct dbr *r, const char *l0)
{
    int failures = 0;
    char dump[DBR_MAX * 4], tmp[DBR_MAX * 4], bad[1000];
    struct zcl_command_reply reply;
    const char *now[] = {"now", NULL};
    TEST("restack: land status that is not ok restacks nothing") {
        (void)snprintf(bad, sizeof(bad), "%s/bad-dev", r->f.fakes);
        ASSERT(dbf_exec(bad, "#!/bin/sh\necho oops\n"));
        dbr_restack(r, now, &reply, dump, sizeof(dump), bad);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(dump, "restack-failed: land status unreadable; nothing restacked") != NULL);
        zcl_command_reply_free(&reply);
        ASSERT(dbf_slurp(r->ledger, tmp, sizeof(tmp)) && strcmp(tmp, l0) == 0);
        PASS();
    }
_test_next:;
    return failures;
}

static int dbr_t_spaced(struct dbr *r, const char *devbin)
{
    int failures = 0;
    char dump[DBR_MAX * 4];
    struct zcl_command_reply reply;
    const char *now[] = {"now", NULL};
    TEST("restack: the next pass without --now is spaced out; with --now it has nothing left") {
        dbr_restack(r, NULL, &reply, dump, sizeof(dump), devbin);
        ASSERT(strstr(dump, "\"spaced\":true") != NULL);
        zcl_command_reply_free(&reply);
        dbr_restack(r, now, &reply, dump, sizeof(dump), devbin);
        ASSERT(strstr(dump, "\"count\":0") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    return failures;
}

static int dbr_t_dry(struct dbr *r, const char *devbin, const char *l0,
                     const char *p0, const char *d0)
{
    int failures = 0;
    char dump[DBR_MAX * 4], tmp[DBR_MAX * 4];
    struct zcl_command_reply reply;
    const char *dry[] = {"dry_run", NULL};
    TEST("restack --dry-run: names the lanes that would go back and writes nothing") {
        dbr_restack(r, dry, &reply, dump, sizeof(dump), devbin);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(dump, "\"count\":5") != NULL);
        /* restacked: stranded, not named, not moved, new commits */
        ASSERT(strstr(dump, "lane-a\",\"head\"") != NULL);
        ASSERT(strstr(dump, "lane-w\",\"head\"") != NULL);
        ASSERT(strstr(dump, "cx-in\",\"head\"") != NULL);
        ASSERT(strstr(dump, "lane-f\",\"head\"") != NULL);
        /* a failed land row names nothing: the lane that would be named stays */
        ASSERT(strstr(dump, "lane-s6n\",\"head\"") != NULL);
        /* the bridge's exact lines */
        ASSERT(strstr(dump, "restack-failed: lane-n is named in s5's gate failure; left for triage") != NULL);
        ASSERT(strstr(dump, "restack-failed: lane-g failed twice after restacking; left for triage") != NULL);
        ASSERT(strstr(dump, "restack-failed: lane-m moved since review; skipped") != NULL);
        ASSERT(strstr(dump, "restack-failed: 5 lanes would go back (dry run)") != NULL);
        /* the tab-led wrapped line, the compiler line and the devbuild line name nobody */
        ASSERT(strstr(dump, "lane-w is named") == NULL);
        /* silent skips: pending, missing, on main, cx without rows, live, passed, running, no log */
        ASSERT(strstr(dump, "lane-p") == NULL && strstr(dump, "lane-d") == NULL);
        ASSERT(strstr(dump, "lane-on") == NULL && strstr(dump, "cx-out") == NULL);
        ASSERT(strstr(dump, "lane-l") == NULL && strstr(dump, "lane-r") == NULL);
        ASSERT(strstr(dump, "lane-u") == NULL && strstr(dump, "lane-x") == NULL);
        zcl_command_reply_free(&reply);
        ASSERT(dbf_slurp(r->ledger, tmp, sizeof(tmp)));
        ASSERT(strcmp(tmp, l0) == 0);
        ASSERT(dbf_slurp(r->pending, tmp, sizeof(tmp)) && strcmp(tmp, p0) == 0);
        ASSERT(dbf_slurp(r->done, tmp, sizeof(tmp)) && strcmp(tmp, d0) == 0);
        ASSERT(!dbf_exists(r->stamp));
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_batch_restack(void);
int test_dev_batch_restack(void)
{
    int failures = 0;
    static struct dbr r;
    char devbin[1000], sysctl[1000], dump[DBR_MAX * 4], l0[DBR_MAX * 4],
        p0[DBR_MAX], d0[DBR_MAX], l1[DBR_MAX * 4], p1[DBR_MAX * 2],
        d1[DBR_MAX * 2];
    struct zcl_command_reply reply;
    const char *now[] = {"now", NULL};

    ASSERT(dbr_build(&r));
    ASSERT(dbr_fakes(&r.f, devbin, sysctl));
    ASSERT(dbf_slurp(r.ledger, l0, sizeof(l0)));
    ASSERT(dbf_slurp(r.pending, p0, sizeof(p0)));
    ASSERT(dbf_slurp(r.done, d0, sizeof(d0)));

    failures += dbr_t_registered();

    failures += dbr_t_dry(&r, devbin, l0, p0, d0);

    failures += dbr_t_unreadable(&r, l0);

    TEST("restack --now: drops the taken ledger rows, appends pending and restacked rows in the bridge's bytes") {
        char want[1400], when[64];
        dbr_restack(&r, now, &reply, dump, sizeof(dump), devbin);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(dump, "restack-failed: 5 reviewed lanes back in stack-pending") != NULL);
        zcl_command_reply_free(&reply);
        ASSERT(dbf_slurp(r.ledger, l1, sizeof(l1)));
        ASSERT(dbf_slurp(r.pending, p1, sizeof(p1)));
        ASSERT(dbf_slurp(r.done, d1, sizeof(d1)));
        ASSERT(!dbr_row_in(l1, r.lane[L_A]) && !dbr_row_in(l1, r.lane[L_W]));
        ASSERT(!dbr_row_in(l1, r.lane[L_CXI]) && !dbr_row_in(l1, r.lane[L_F]));
        ASSERT(!dbr_row_in(l1, r.lane[L_S6N]));
        /* kept: triage, twice-failed, moved, pending, live, passed, running, no log */
        ASSERT(dbr_row_in(l1, r.lane[L_N]) && dbr_row_in(l1, r.lane[L_G]));
        ASSERT(dbr_row_in(l1, r.lane[L_M]) && dbr_row_in(l1, r.lane[L_P]));
        ASSERT(dbr_row_in(l1, r.lane[L_L]) && dbr_row_in(l1, r.lane[L_R]));
        ASSERT(dbr_row_in(l1, r.lane[L_U]) && dbr_row_in(l1, r.lane[L_X]));
        (void)snprintf(want, sizeof(want),
                       "%s\tlane-a: restacked after s5 failed (reviewed LAND at %.12s)\n",
                       r.lane[L_A], r.sha[L_A]);
        ASSERT(strstr(p1, want) != NULL);
        ASSERT(strncmp(p1, p0, strlen(p0)) == 0);
        ASSERT(!dbr_row_in(p1 + strlen(p0), r.lane[L_N]));
        (void)snprintf(want, sizeof(want), "%s\t%s\ts5\t", r.lane[L_A], r.sha[L_A]);
        ASSERT(strstr(d1, want) != NULL);
        ASSERT(strncmp(d1, d0, strlen(d0)) == 0);
        {
            const char *at = strstr(d1, want);
            (void)snprintf(when, sizeof(when), "%.20s", at + strlen(want));
            ASSERT(strlen(when) == 20 && when[19] == 'Z' && when[10] == 'T');
        }
        ASSERT(dbf_exists(r.stamp));
        PASS();
    }

    failures += dbr_t_spaced(&r, devbin);

    TEST("11-03: a lane left for triage keeps its stacked.tsv row, and requeue clears it") {
        ASSERT(dbr_row_in(l1, r.lane[L_N]));
        ASSERT(!dbr_row_in(p1, r.lane[L_N]));
        {
            const char *pairs[] = {"worktree", r.lane[L_N], "note", "lane-n: fixed after s5", NULL};
            dbf_call(zcl_native_handle_dev_batch_requeue, &r.f, pairs, NULL,
                     &reply, dump, sizeof(dump));
            ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
            zcl_command_reply_free(&reply);
        }
        ASSERT(dbf_slurp(r.ledger, l1, sizeof(l1)));
        ASSERT(dbf_slurp(r.pending, p1, sizeof(p1)));
        ASSERT(!dbr_row_in(l1, r.lane[L_N]));
        ASSERT(dbr_row_in(p1, r.lane[L_N]));
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(r.f.root);
    if (failures == 0)
        printf("test_dev_batch_restack: all passed\n");
    else
        printf("test_dev_batch_restack: %d FAILED\n", failures);
    return failures;
}
