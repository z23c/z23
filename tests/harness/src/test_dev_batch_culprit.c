/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_batch_culprit: dev.batch.culprit (tools/command/native_dev_batch_
 * culprit.c), the decision half of drop_culprit() in the gate-submit.sh
 * bridge plus lane granularity, on a fixture stack of 11 commits cut from
 * six lanes (dead-shell's shell file and its budget cut among them) and two
 * commits that belong to no lane, with a fixture stacked.tsv. A culprit
 * pulls in its whole lane (the s524 miss), the half-stack rule counts after
 * that expansion, a header, a shared file or only unmapped commits refuse,
 * a log naming only ratchet files refuses, and --dry-run changes nothing. */

#include "test/test_dev_batch_fixture.h"

#include "command/native_dev_batch_culprit.h"

enum { A1, A2, B1, C1, C2, D1, E1, F1, G1, U1, U2, NCOMMITS };

struct dbc {
    struct dbf f;
    char stack[900], stack8[900], stack7[900];
    char log[1000];
    char sha[NCOMMITS][41];
};

static bool dbc_pick(const char *stack, const char *lane, const char *rev,
                     char out[41])
{
    const char *fetch[] = {"fetch", "-q", lane, "HEAD", NULL};
    char lsha[41];
    const char *pick[] = {"cherry-pick", lsha, NULL};
    if (!dbf_rev(lane, rev, lsha) || !dbf_git(stack, fetch) ||
        !dbf_git(stack, pick))
        return false;
    return dbf_rev(stack, "HEAD", out);
}

/* The stack takes the lane's commit as it is (a fast-forward): same sha, so
 * `git cherry` cannot list it and only the sha mapping finds its lane. */
static bool dbc_ff(const char *stack, const char *lane, const char *rev,
                   char out[41])
{
    const char *fetch[] = {"fetch", "-q", lane, "HEAD", NULL};
    char lsha[41];
    const char *merge[] = {"merge", "-q", "--ff-only", lsha, NULL};
    if (!dbf_rev(lane, rev, lsha) || !dbf_git(stack, fetch) ||
        !dbf_git(stack, merge))
        return false;
    return dbf_rev(stack, "HEAD", out);
}

/* One lane of up to two commits; its path and head. */
static bool dbc_lane(const struct dbc *d, const char *name, const char *f1,
                     const char *f2, char path[900], char head[41])
{
    if (!dbf_lane(&d->f, name, f1, path, head))
        return false;
    return (!f2 || dbf_commit_file(path, f2, "1\n")) &&
           dbf_rev(path, "HEAD", head);
}

static bool dbc_row(char *tsv, size_t cap, const char *lane, const char *head,
                    const char *sid)
{
    size_t n = strlen(tsv);
    return snprintf(tsv + n, cap - n, "%s\t%s\t%s\n", lane, head, sid) <
           (int)(cap - n);
}

struct dbc_lanes {
    char a[900], b[900], c[900], dd[900], e[900], g[900], fl[900];
    char ha[41], hb[41], hc[41], hd[41], he[41], hg[41], hf[41];
};

static bool dbc_lanes_make(const struct dbc *d, struct dbc_lanes *l)
{
    return dbc_lane(d, "dead-shell", "tools/shell_a.sh",
                    "tools/lint/a_budget.txt", l->a, l->ha) &&
           dbc_lane(d, "lane-b", "src/b.c", NULL, l->b, l->hb) &&
           dbc_lane(d, "lane-c", "src/c.c", "src/c2.c", l->c, l->hc) &&
           dbc_lane(d, "lane-d", "src/d.c", NULL, l->dd, l->hd) &&
           dbc_lane(d, "lane-e", "src/e.c", NULL, l->e, l->he) &&
           dbc_lane(d, "lane-f", "src/f.c", NULL, l->fl, l->hf) &&
           dbc_lane(d, "lane-g", "src/g.h", NULL, l->g, l->hg);
}

/* The stack: lanes interleaved, a registry-style commit of no lane (U1) and
 * an autofix-style edit of F's file (U2). */
static bool dbc_stack_make(struct dbc *d, const struct dbc_lanes *l)
{
    const char *clone[] = {"clone", "-q", d->f.origin, d->stack, NULL};
    char par[900];
    (void)snprintf(par, sizeof(par), "%s/development/z23", d->f.home);
    (void)snprintf(d->stack, sizeof(d->stack), "%s/z23-stacks9", par);
    if (!dbf_git(par, clone))
        return false;
    return dbc_ff(d->stack, l->a, "HEAD~1", d->sha[A1]) &&
           dbc_pick(d->stack, l->b, "HEAD", d->sha[B1]) &&
           dbc_pick(d->stack, l->c, "HEAD~1", d->sha[C1]) &&
           dbc_pick(d->stack, l->a, "HEAD", d->sha[A2]) &&
           dbc_pick(d->stack, l->dd, "HEAD", d->sha[D1]) &&
           dbc_pick(d->stack, l->c, "HEAD", d->sha[C2]) &&
           dbf_commit_file(d->stack, "src/u.c", "int u;\n") &&
           dbf_rev(d->stack, "HEAD", d->sha[U1]) &&
           dbc_pick(d->stack, l->e, "HEAD", d->sha[E1]) &&
           dbc_pick(d->stack, l->fl, "HEAD", d->sha[F1]) &&
           dbc_pick(d->stack, l->g, "HEAD", d->sha[G1]) &&
           dbf_commit_file(d->stack, "src/f.c", "int y;\n") &&
           dbf_rev(d->stack, "HEAD", d->sha[U2]);
}

static bool dbc_ledger_make(const struct dbc *d, const struct dbc_lanes *l)
{
    char tsv[8192] = "";
    char path[1000];
    bool ok = dbc_row(tsv, sizeof(tsv), l->a, l->ha, "s9") &&
              dbc_row(tsv, sizeof(tsv), l->b, l->hb, "s9") &&
              dbc_row(tsv, sizeof(tsv), "/lanes/other", l->hb, "s3") &&
              dbc_row(tsv, sizeof(tsv), l->c, l->hc, "s9") &&
              dbc_row(tsv, sizeof(tsv), l->dd, l->hd, "s9") &&
              dbc_row(tsv, sizeof(tsv), l->e, l->he, "s9") &&
              dbc_row(tsv, sizeof(tsv), l->fl, l->hf, "s9") &&
              dbc_row(tsv, sizeof(tsv), l->g, l->hg, "s9");
    (void)snprintf(path, sizeof(path), "%s/stacked.tsv", d->f.state);
    return ok && dbf_put(path, tsv);
}

/* Two more stacks in the same lab. s8: lanes H (h1, h2) and I (h1 again, the
 * identical patch) so H's first commit is ambiguous, K (k1) and L, a lane
 * whose head is already origin/main. s7: lane K and lane M, plus a ledger row
 * whose head names no object (the lane lookup must fail closed). */
static bool dbc_extra_stack(struct dbc *d, const char *name, char out[900])
{
    const char *clone[] = {"clone", "-q", d->f.origin, out, NULL};
    char par[900];
    (void)snprintf(par, sizeof(par), "%s/development/z23", d->f.home);
    (void)snprintf(out, 900, "%s/%s", par, name);
    return dbf_git(par, clone);
}

struct dbc_extra {
    char h[900], i[900], k[900], l[900], m[900];
    char hh[41], hi[41], hk[41], hl[41], hm[41];
};

static bool dbc_extra_lanes(struct dbc *d, struct dbc_extra *e)
{
    return dbc_lane(d, "lane-h", "src/h1.c", "src/h2.c", e->h, e->hh) &&
           dbc_lane(d, "lane-i", "src/h1.c", NULL, e->i, e->hi) &&
           dbc_lane(d, "lane-k", "src/k.c", NULL, e->k, e->hk) &&
           dbc_lane(d, "lane-m", "src/m.c", NULL, e->m, e->hm) &&
           dbf_lane(&d->f, "lane-l", NULL, e->l, e->hl);
}

/* Lane I is never picked into s8, but git cherry needs its head object to
 * compare patches: fetch it so the stack sees the lane as a real lane does. */
static bool dbc_fetch(const char *stack, const char *lane)
{
    const char *fetch[] = {"fetch", "-q", lane, "HEAD", NULL};
    return dbf_git(stack, fetch);
}

static bool dbc_extra_picks(const struct dbc *d, const struct dbc_extra *e)
{
    char sha[41];
    return dbc_pick(d->stack8, e->h, "HEAD~1", sha) &&
           dbc_pick(d->stack8, e->h, "HEAD", sha) &&
           dbc_fetch(d->stack8, e->i) &&
           dbc_pick(d->stack8, e->k, "HEAD", sha) &&
           dbc_pick(d->stack7, e->k, "HEAD", sha) &&
           dbc_pick(d->stack7, e->m, "HEAD", sha);
}

static bool dbc_extra_rows(char *tsv, size_t cap, const struct dbc_extra *e)
{
    return dbc_row(tsv, cap, e->h, e->hh, "s8") &&
           dbc_row(tsv, cap, e->i, e->hi, "s8") &&
           dbc_row(tsv, cap, e->k, e->hk, "s8") &&
           dbc_row(tsv, cap, e->l, e->hl, "s8") &&
           dbc_row(tsv, cap, e->k, e->hk, "s7") &&
           dbc_row(tsv, cap, e->m, e->hm, "s7") &&
           dbc_row(tsv, cap, "/lanes/lane-bad",
                   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "s7");
}

static bool dbc_extra_make(struct dbc *d)
{
    struct dbc_extra e;
    char tsv[8192], path[1000];
    if (!dbc_extra_lanes(d, &e) ||
        !dbc_extra_stack(d, "z23-stacks8", d->stack8) ||
        !dbc_extra_stack(d, "z23-stacks7", d->stack7))
        return false;
    (void)snprintf(path, sizeof(path), "%s/stacked.tsv", d->f.state);
    return dbf_slurp(path, tsv, sizeof(tsv)) && dbc_extra_picks(d, &e) &&
           dbc_extra_rows(tsv, sizeof(tsv), &e) && dbf_put(path, tsv);
}

static bool dbc_setup(struct dbc *d)
{
    struct dbc_lanes l;
    memset(d, 0, sizeof(*d));
    return dbf_setup(&d->f, "culprit") && dbc_lanes_make(d, &l) &&
           dbc_stack_make(d, &l) && dbc_ledger_make(d, &l) &&
           dbc_extra_make(d) &&
           snprintf(d->log, sizeof(d->log), "%s/fail.log", d->f.root) > 0;
}
static void dbc_run(struct dbc *d, const char *text, const char *stage,
                    const char *const *flags, struct zcl_command_reply *reply,
                    char *dump, size_t cap)
{
    const char *pairs[] = {"stack", d->stack,   "log",    d->log,
                           "stage", stage,      "ledger", d->f.state,
                           NULL};
    (void)dbf_put(d->log, text);
    dbf_call(zcl_native_handle_dev_batch_culprit, &d->f, pairs, flags, reply,
             dump, cap);
}

static bool dbc_refused(struct dbc *d, const char *text, const char *code)
{
    struct zcl_command_reply reply;
    char dump[16384], want[64];
    bool ok;
    dbc_run(d, text, "lint", NULL, &reply, dump, sizeof(dump));
    (void)snprintf(want, sizeof(want), "\"refusal\":\"%s\"", code);
    ok = strstr(dump, "\"decision\":\"refuse\"") && strstr(dump, want) &&
         strstr(dump, "\"drop\":[]");
    zcl_command_reply_free(&reply);
    return ok;
}

static bool dbc_ratchet_names(void)
{
    return cp_is_ratchet("tools/lint/x_floor_a.txt") &&
           cp_is_ratchet("tools/lint/sub/b_baseline.txt") &&
           !cp_is_ratchet("tools/lint/budget.sh") &&
           !cp_is_ratchet("tools/lint/budget_Z.txt") &&
           !cp_is_ratchet("src/a_budget.txt");
}

static bool dbc_paths_case(void)
{
    static char text[] =
        "devbuild: building src/pre.c\nsrc/early.c noted\nFAIL: check-foo\n"
        "  src/b.c:12: bad\n  zcc cc -c src/zz.c\n"
        "  tools/lint/a_budget.txt grew\n  tools/lint/a_budget.txt shrank\n"
        "  see docs/a.md and x.cc and tools/q.def.\n";
    struct db_text t = {text, sizeof(text) - 1};
    struct cp_set s = {0};
    bool ok = cp_log_paths(&t, false, &s) && s.n == 3 &&
              cp_set_has(&s, "src/b.c") && cp_set_has(&s, "docs/a.md") &&
              cp_set_has(&s, "tools/q.def") && !cp_set_has(&s, "src/early.c");
    cp_set_free(&s);
    ok = ok && cp_log_paths(&t, true, &s) && cp_set_has(&s, "src/early.c") &&
         cp_set_has(&s, "src/pre.c") && !cp_set_has(&s, "src/zz.c") &&
         !cp_set_has(&s, "tools/lint/a_budget.txt");
    cp_set_free(&s);
    return ok && dbc_ratchet_names();
}

int test_dev_batch_culprit(void);
int test_dev_batch_culprit(void)
{
    int failures = 0;
    struct dbc d;
    struct zcl_command_reply reply;
    char dump[16384];

    ASSERT(dbc_setup(&d));

    TEST("culprit: the leaf is registered and declares its keys") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "dev.batch.culprit", NULL);
        ASSERT(spec != NULL);
        ASSERT(strstr(spec->input_keys, "ledger") != NULL);
        ASSERT(strstr(spec->input_keys, "stage") != NULL);
        PASS();
    }

    TEST("culprit: the log's path filters match the bridge's") {
        ASSERT(dbc_paths_case());
        PASS();
    }

    TEST("culprit: a named commit pulls in every commit of its lane, named or not") {
        dbc_run(&d, "FAIL: check-no-new-bash\n  tools/shell_a.sh is a shell file\n",
                "lint", NULL, &reply, dump, sizeof(dump));
        if (!strstr(dump, "\"decision\":\"drop\""))
            printf("\n  culprit reply: %.1800s\n", dump);
        ASSERT(strstr(dump, "\"decision\":\"drop\"") != NULL);
        ASSERT(strstr(dump, d.sha[A1]) != NULL);
        ASSERT(strstr(dump, d.sha[A2]) != NULL); /* the budget cut, never named */
        ASSERT(strstr(dump, "\"named\":false") != NULL);
        ASSERT(strstr(dump, "dead-shell") != NULL);
        ASSERT(strstr(dump, d.sha[B1]) == NULL && strstr(dump, d.sha[U1]) == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("culprit: a commit of no lane is never dropped beside a lane's") {
        dbc_run(&d, "FAIL: x\n  src/u.c bad\n  src/b.c bad\n", "lint", NULL,
                &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"decision\":\"drop\"") != NULL);
        ASSERT(strstr(dump, d.sha[B1]) != NULL);
        ASSERT(strstr(dump, d.sha[U1]) == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("culprit: a log naming only commits of no lane refuses as unmapped") {
        ASSERT(dbc_refused(&d, "FAIL: x\n  src/u.c bad\n", "unmapped"));
        PASS();
    }

    TEST("culprit: more than half the stack after the lane expansion refuses") {
        /* five named commits (10 of 11 passes the bare rule); lane C adds one */
        ASSERT(dbc_refused(&d,
                           "FAIL: x\n src/b.c a\n src/c.c a\n src/d.c a\n "
                           "src/e.c a\n src/f.c a\n",
                           "over_half"));
        PASS();
    }

    TEST("culprit: a dropped header refuses") {
        ASSERT(dbc_refused(&d, "FAIL: x\n  src/g.h bad\n", "header_touched"));
        PASS();
    }

    TEST("culprit: a kept commit touching a dropped file refuses") {
        ASSERT(dbc_refused(&d, "FAIL: x\n  src/f.c bad\n", "shared_file"));
        PASS();
    }

    TEST("culprit: a log naming only ratchet files refuses") {
        ASSERT(dbc_refused(&d,
                           "FAIL: x\n  tools/lint/a_budget.txt grew\n  "
                           "tools/lint/z_baseline.txt\n",
                           "no_paths"));
        PASS();
    }

    TEST("culprit: a failure that prints its own fix refuses") {
        ASSERT(dbc_refused(&d,
                           "FAIL: x\n  src/b.c bad\n  Delete them from "
                           "tools/lint/x_baseline.txt\n",
                           "fix_printed"));
        ASSERT(dbc_refused(&d, "FAIL: x\n  src/b.c bad\n  CAP_FS_READ  row\n",
                           "fix_printed"));
        PASS();
    }

    TEST("culprit: agent-verify reads the whole log") {
        dbc_run(&d, "FAILED GROUP test_x\nsrc/d.c:3:1: error: y\n", "agent-verify",
                NULL, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"decision\":\"drop\"") != NULL);
        ASSERT(strstr(dump, d.sha[D1]) != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("culprit: --dry-run decides the same and writes nothing") {
        char before[8192], after[8192], path[1000], head0[41], head1[41];
        const char *dry[] = {"dry_run", NULL};
        char list_a[8192], list_b[8192];
        (void)snprintf(path, sizeof(path), "%s/stacked.tsv", d.f.state);
        ASSERT(dbf_slurp(path, before, sizeof(before)));
        ASSERT(dbf_rev(d.stack, "HEAD", head0));
        dbc_run(&d, "FAIL: x\n  src/d.c bad\n", "lint", NULL, &reply, list_a,
                sizeof(list_a));
        zcl_command_reply_free(&reply);
        dbc_run(&d, "FAIL: x\n  src/d.c bad\n", "lint", dry, &reply, list_b,
                sizeof(list_b));
        zcl_command_reply_free(&reply);
        ASSERT(strstr(list_b, "\"dry_run\":true") != NULL);
        ASSERT(strstr(list_b, d.sha[D1]) != NULL);
        ASSERT(dbf_slurp(path, after, sizeof(after)) && strcmp(before, after) == 0);
        ASSERT(dbf_rev(d.stack, "HEAD", head1) && strcmp(head0, head1) == 0);
        (void)snprintf(path, sizeof(path), "%s/stack-pending.txt", d.f.state);
        ASSERT(!dbf_exists(path));
        PASS();
    }

    TEST("culprit: a failed lane lookup refuses instead of skipping the lane") {
        char main_stack[900];
        (void)snprintf(main_stack, sizeof(main_stack), "%s", d.stack);
        (void)snprintf(d.stack, sizeof(d.stack), "%s", d.stack7);
        dbc_run(&d, "FAIL: x\n  src/k.c bad\n", "lint", NULL, &reply, dump,
                sizeof(dump));
        (void)snprintf(d.stack, sizeof(d.stack), "%s", main_stack);
        ASSERT(strstr(dump, "\"decision\":\"refuse\"") != NULL);
        ASSERT(strstr(dump, "\"refusal\":\"lane_lookup_failed\"") != NULL);
        ASSERT(strstr(dump, "lane-bad") != NULL);
        ASSERT(strstr(dump, "\"drop\":[]") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("culprit: a lane sharing a patch with another is never dropped in part") {
        char main_stack[900];
        (void)snprintf(main_stack, sizeof(main_stack), "%s", d.stack);
        (void)snprintf(d.stack, sizeof(d.stack), "%s", d.stack8);
        ASSERT(dbc_refused(&d, "FAIL: x\n  src/h2.c bad\n", "ambiguous_lane"));
        (void)snprintf(d.stack, sizeof(d.stack), "%s", main_stack);
        PASS();
    }

    TEST("culprit: a lane head already on origin/main drops no other lane") {
        char main_stack[900];
        (void)snprintf(main_stack, sizeof(main_stack), "%s", d.stack);
        (void)snprintf(d.stack, sizeof(d.stack), "%s", d.stack8);
        dbc_run(&d, "FAIL: x\n  src/k.c bad\n", "lint", NULL, &reply, dump,
                sizeof(dump));
        (void)snprintf(d.stack, sizeof(d.stack), "%s", main_stack);
        ASSERT(strstr(dump, "\"decision\":\"drop\"") != NULL);
        ASSERT(strstr(dump, "lane-k") != NULL);
        ASSERT(strstr(dump, "lane-l") == NULL);
        ASSERT(strstr(dump, "lane-h") == NULL && strstr(dump, "lane-i") == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("culprit: a malformed git log line is BAD_STACK, not NO_MEMORY") {
        ASSERT(strcmp(dev_batch_culprit_test_parse_code("\001short\nsrc/a.c\n"), "BAD_STACK") == 0);
        ASSERT(strcmp(dev_batch_culprit_test_parse_code("\0010123456789012345678901234567890123456789 s\nsrc/a.c\n"),
                      "") == 0);
        PASS();
    }

    TEST("culprit: a stack path that is not a worktree is refused as input") {
        const char *pairs[] = {"stack", "/nonexistent/z23-stacks9", "log", d.log,
                               "stage", "lint", "ledger", d.f.state, NULL};
        dbf_call(zcl_native_handle_dev_batch_culprit, &d.f, pairs, NULL, &reply,
                 dump, sizeof(dump));
        ASSERT(strstr(dump, "\"decision\":\"refuse\"") != NULL);
        ASSERT(strstr(dump, "BAD_STACK") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(d.f.root);
    if (failures == 0)
        printf("test_dev_batch_culprit: all passed\n");
    else
        printf("test_dev_batch_culprit: %d FAILED\n", failures);
    return failures;
}
