/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: merge-tip resolution and queued-row conflict handling.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#include <dirent.h>


/* ── rebase regeneration for tips that carry merges ───────────────────────
 *
 * The shape that stranded land queue row 30: a long-lived candidate that
 * merged origin/main into itself (resolving the inventory, and sometimes
 * real source, by hand), then main moved again before it landed. A plain
 * `git rebase` replays each non-merge commit and throws those resolutions
 * away, so a later replayed commit conflicts on real source and the
 * generated-artifact auto-resolve correctly declines. The cases below pin
 * the landing path that keeps the candidate's resolved tree instead, and
 * the ones that must still refuse. */
#if !defined(_WIN32)

struct dlx_mtip {
    char m1[64];  /* main after the train the candidate merged */
    char m2[64];  /* main after the train that raced it */
    char tip[64]; /* the submitted candidate tip */
};

/* A commit signed by the clone's AMBIENT signer (dlx_sign_arm): the lander
 * refuses to queue an unsigned tip outside the unsigned fixture seam. */
static bool dlx_mtip_commit(const char *dir, const char *msg, char out[64])
{
    const char *add[] = { "add", "-A", NULL };
    const char *commit[] = { "commit", "--quiet", "--no-verify", "-m", msg,
                             NULL };
    const char *head[] = { "rev-parse", "HEAD", NULL };
    if (dlx_git(dir, add) != 0 || dlx_git(dir, commit) != 0)
        return false;
    return dlx_git_out(dir, head, out, 64) == 0 && strlen(out) == 40;
}

static bool dlx_mtip_write2(const char *dir, const char *inv_body,
                            const char *path, const char *body)
{
    return (!inv_body ||
            dlx_write_dep(dir, "docs/agent/EXECUTOR_HEURISTICS.md",
                          inv_body)) &&
           dlx_write_dep(dir, path, body);
}

static bool dlx_mtip_step(const char *dir, const char *inv_body,
                          const char *path, const char *body,
                          const char *msg, char out[64])
{
    return dlx_mtip_write2(dir, inv_body, path, body) &&
           dlx_mtip_commit(dir, msg, out);
}

/* base on main ; candidate c1 (a.txt, inventory) on branch cand ; main M1
 * (a.txt, inventory) pushed ; left on cand. */
static bool dlx_mtip_diverge(struct dlx_rig *rig, struct dlx_mtip *out)
{
    char scratch[64];
    const char *c = rig->clone;
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *to_cand[] = { "checkout", "--quiet", "-b", "cand", NULL };
    const char *to_main[] = { "checkout", "--quiet", "main", NULL };
    const char *back[] = { "checkout", "--quiet", "cand", NULL };
    return dlx_mtip_step(c, "base\n", "a.txt", "base\n", "base", scratch) &&
           dlx_git(c, push) == 0 && dlx_git(c, to_cand) == 0 &&
           dlx_mtip_step(c, "mine1\n", "a.txt", "mine1\n", "candidate one",
                         scratch) &&
           dlx_git(c, to_main) == 0 &&
           dlx_mtip_step(c, "theirs1\n", "a.txt", "theirs1\n", "train one",
                         out->m1) &&
           dlx_git(c, push) == 0 && dlx_git(c, back) == 0;
}

/* ...then the candidate merges M1 resolving a.txt and the inventory by
 * hand ; candidate c2 (c.txt, inventory, and b.txt when `source_conflict`)
 * is the submitted tip ; main M2 (b.txt, inventory) is pushed. The
 * candidate's net change against M1 meets M2 only on the inventory unless
 * `source_conflict`. */
static bool dlx_mtip_rig(struct dlx_rig *rig, bool source_conflict,
                         bool generated_conflict, struct dlx_mtip *out)
{
    char scratch[64];
    const char *c = rig->clone;
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *to_main[] = { "checkout", "--quiet", "main", NULL };
    const char *merge[] = { "-c", "user.name=land", "-c",
                            "user.email=land@z23.invalid", "merge",
                            "--quiet", "--no-edit", "--no-gpg-sign", "main",
                            NULL };
    if (!dlx_mtip_diverge(rig, out))
        return false;
    /* Conflicts on a.txt and the inventory by construction; the hand
     * resolution is exactly what a per-commit replay throws away. */
    (void)dlx_git(c, merge);
    if (!dlx_mtip_step(c, "merged\n", "a.txt", "merged\n", "integrate main",
                       scratch))
        return false;
    if (source_conflict && !dlx_write_dep(c, "b.txt", "mine2\n"))
        return false;
    return dlx_mtip_step(c, generated_conflict ? "mine2\n" : NULL, "c.txt",
                         "mine2\n", "candidate two",
                         out->tip) &&
           dlx_git(c, to_main) == 0 &&
           dlx_mtip_step(c, generated_conflict ? "theirs2\n" : NULL, "b.txt",
                         "theirs2\n", "train two",
                         out->m2) &&
           dlx_git(c, push) == 0;
}

static bool dlx_land_log_has(const char *needle)
{
    char landdir[1200], path[1300], log[65536];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/logs/land-1-a1.log", landdir);
    if (!dlx_slurp(path, log, sizeof(log) - 1, &len))
        return false;
    log[len] = '\0';
    return strstr(log, needle) != NULL;
}

static int test_dev_land_merge_tip_keeps_resolution(void)
{
    int failures = 0;
    TEST("land: a merge-bearing tip that main moved past keeps its resolved "
         "tree and lands exactly the commit that was proved") {
        struct dlx_rig rig;
        struct dlx_mtip m;
        struct dlx_call c;
        char landwt[1300], out[512], expect[256];
        const char *subject[] = { "log", "-1", "--format=%s", NULL };
        const char *sig_head[] = { "log", "-1", "--format=%G?", "HEAD",
                                   NULL };
        const char *parent[] = { "show", "-s", "--format=%P", "HEAD",
                                 NULL };
        const char *body[] = { "log", "-1", "--format=%B", "HEAD", NULL };
        const char *inv[] = { "show",
                              "HEAD:docs/agent/EXECUTOR_HEURISTICS.md",
                              NULL };
        const char *a_txt[] = { "show", "HEAD:a.txt", NULL };
        const char *b_txt[] = { "show", "HEAD:b.txt", NULL };
        const char *c_txt[] = { "show", "HEAD:c.txt", NULL };
        const char *head[] = { "rev-parse", "HEAD", NULL };
        const char *remote[] = { "rev-parse", "main", NULL };
        char prepared[64];
        dlx_isolate("mtipkeep");
        ASSERT(dlx_rig_make(&rig, "mtipkeep_rig"));
        ASSERT(dlx_sign_arm(rig.clone, "mtipkeep_key"));
        ASSERT(dlx_mtip_rig(&rig, false, false, &m));
        /* Production signing throughout the rebase step. */
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlx_submit(&c, &rig, m.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(landwt, subject, out, sizeof(out)) == 0);
        /* The merge-bearing tip was cut into ONE linear commit first, and
         * nothing was amended into it: its subject is the linearization's. */
        ASSERT_STR_EQ(out, "Prepare candidate for linear publication");
        ASSERT(dlx_git_out(landwt, inv, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "merged");
        /* The candidate's hand resolution survived; main's later train and
         * the candidate's later work are both present. */
        ASSERT(dlx_git_out(landwt, a_txt, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "merged");
        ASSERT(dlx_git_out(landwt, b_txt, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "theirs2");
        ASSERT(dlx_git_out(landwt, c_txt, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "mine2");
        /* One single-parent candidate commit on the new main, signed by
         * the lander's signer, and nothing on top of it. */
        ASSERT(dlx_git_out(landwt, parent, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, m.m2);
        ASSERT(dlx_git_out(landwt, sig_head, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "G");
        ASSERT(dlx_git_out(landwt, body, out, sizeof(out)) == 0);
        (void)snprintf(expect, sizeof(expect), "Original-Candidate: %s",
                       m.tip);
        ASSERT(strstr(out, expect) != NULL);
        (void)snprintf(expect, sizeof(expect), "Original-Base: %s", m.m1);
        ASSERT(strstr(out, expect) != NULL);
        /* A replayed candidate's own source tree is not claimed. */
        ASSERT(strstr(out, "Source-Tree:") == NULL);
        ASSERT(dlx_land_log_has("linearized merge-bearing candidate "));
        /* And it lands, as the very commit that was prepared. */
        ASSERT(dlx_git_out(landwt, head, prepared, sizeof(prepared)) == 0);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.bare, remote, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, prepared);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_merge_tip_generated_conflict(void)
{
    int failures = 0;
    TEST("land: a merge-bearing tip whose net change meets main on a "
         "generated document is refused naming the make target") {
        struct dlx_rig rig;
        struct dlx_mtip m;
        struct dlx_call c;
        char out[64];
        const char *remote[] = { "rev-parse", "main", NULL };
        dlx_isolate("mtipgen");
        ASSERT(dlx_rig_make(&rig, "mtipgen_rig"));
        ASSERT(dlx_sign_arm(rig.clone, "mtipgen_key"));
        ASSERT(dlx_mtip_rig(&rig, false, true, &m));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlx_submit(&c, &rig, m.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "conflict");
        ASSERT_STR_EQ(dlx_str(&c, "dimension"), "rebase");
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "run `make docs-executor-routing`") != NULL);
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.bare, remote, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, m.m2);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_merge_tip_source_conflict(void)
{
    int failures = 0;
    TEST("land: a merge-bearing tip with a real source conflict beside the "
         "generated one is a conflict naming both") {
        struct dlx_rig rig;
        struct dlx_mtip m;
        struct dlx_call c;
        char out[64];
        const char *remote[] = { "rev-parse", "main", NULL };
        dlx_isolate("mtipsrc");
        ASSERT(dlx_rig_make(&rig, "mtipsrc_rig"));
        ASSERT(dlx_sign_arm(rig.clone, "mtipsrc_key"));
        ASSERT(dlx_mtip_rig(&rig, true, true, &m));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlx_submit(&c, &rig, m.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "conflict");
        ASSERT_STR_EQ(dlx_str(&c, "dimension"), "rebase");
        ASSERT(strstr(dlx_str(&c, "detail"), "b.txt") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "docs/agent/EXECUTOR_HEURISTICS.md") != NULL);
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.bare, remote, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, m.m2);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A CODEBASE_MAP conflict is never merged or normalised by the queue, with
 * or without a divergent DOC-COUNTS block and with or without authored
 * prose on both sides: every shape is refused, names `make fix-doc-counts`,
 * and leaves the submitted tip untouched and origin where it was. */
int test_dev_land_rebase_count_conflicts(void)
{
    int failures = 0;
    const char *block = "<!-- DOC-COUNTS-BEGIN -->\nport_interfaces: 13\npersistence_adapters: 14\ncondition_registrations: 56\ncommand_bundles: 31\ncommand_roots: 13\ndumpstate_subsystems: 167\napp_shape_folders: 7\n<!-- DOC-COUNTS-END -->\n";
    for (int mode = 0; mode < 4; mode++) {
        TEST("land: a conflict on the codebase map is refused naming "
             "fix-doc-counts, whatever else changed in it") {
            struct dlx_rig rig;
            struct dlx_call c;
            char base[64], tip[64], upstream[64], before[64], after[64];
            static char a[4096], b[4096], p[4096], out[4096];
            const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
            const char *keep[] = { "branch", "keep-tip", NULL };
            const char *reset[] = { "reset", "--hard", base, NULL };
            const char *show[] = { "show", "keep-tip:docs/dev/CODEBASE_MAP.md", NULL };
            dlx_isolate("countsconf");
            ASSERT(dlx_rig_make(&rig, "countsconf_rig"));
            /* mode 0: prose edited on both sides, counts block shared;
             * mode 1: prose edited on one side, block edited on the other
             * (git merges it cleanly, so the row proceeds to the proof);
             * mode 2: block edited differently on both sides;
             * mode 3: no block at all, prose edited on both sides. */
            snprintf(a, sizeof(a), "Action A.\n%s", mode == 3 ? "" : block);
            snprintf(b, sizeof(b), "Action B.\n%s", mode == 3 ? "" : block);
            snprintf(p, sizeof(p), "Action C.\n%s", mode == 3 ? "" : block);
            if (mode == 1) {
                snprintf(b, sizeof(b), "Action A.\n%s", block);
                strstr(b, "port_interfaces: 13")[17] = '4';
                snprintf(p, sizeof(p), "Action C.\n%s", block);
            }
            if (mode == 2) {
                snprintf(b, sizeof(b), "Action A.\n%s", block);
                snprintf(p, sizeof(p), "Action A.\n%s", block);
                strstr(b, "port_interfaces: 13")[17] = '4';
                strstr(p, "port_interfaces: 13")[17] = '5';
            }
            ASSERT(dlx_write_dep(rig.clone, "docs/dev/CODEBASE_MAP.md", a));
            ASSERT(dlx_commit_tree(rig.clone, "base", base));
            ASSERT(dlx_git(rig.clone, push) == 0);
            ASSERT(dlx_write_dep(rig.clone, "docs/dev/CODEBASE_MAP.md", p));
            ASSERT(dlx_commit_tree(rig.clone, "proposal", tip));
            ASSERT(dlx_git(rig.clone, keep) == 0);
            ASSERT(dlx_git(rig.clone, reset) == 0);
            ASSERT(dlx_write_dep(rig.clone, "docs/dev/CODEBASE_MAP.md", b));
            ASSERT(dlx_commit_tree(rig.clone, "upstream", upstream));
            ASSERT(dlx_git(rig.clone, push) == 0);
            ASSERT(dlx_origin_main(&rig, before));
            setenv("ZCL_LAND_PROOF_STUB", "running", 1);
            setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
            dlx_submit(&c, &rig, tip);
            ASSERT(dlx_run(&c)); ASSERT(dlx_ok(&c)); dlx_end(&c);
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c)); ASSERT(dlx_ok(&c));
            if (mode == 1) {
                /* A clean three-way merge is not a conflict: the tip is
                 * proved exactly as the merge left it. */
                ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
            } else {
                ASSERT_STR_EQ(dlx_str(&c, "state"), "conflict");
                ASSERT(strstr(dlx_str(&c, "detail"),
                              "docs/dev/CODEBASE_MAP.md: generated document") != NULL);
                ASSERT(strstr(dlx_str(&c, "detail"), "run `make fix-doc-counts`") != NULL);
            }
            dlx_end(&c);
            ASSERT(dlx_origin_main(&rig, after));
            ASSERT_STR_EQ(after, before);
            ASSERT(dlx_git_out(rig.clone, show, out, sizeof(out)) == 0);
            p[strlen(p) - 1] = '\0';
            ASSERT_STR_EQ(out, p);
            dlx_restore(); PASS();
        }
    }
    failures += test_dev_land_merge_tip_keeps_resolution();
    failures += test_dev_land_merge_tip_generated_conflict();
    failures += test_dev_land_merge_tip_source_conflict();
_test_next:
    dlx_restore();
    return failures;
}


/* ── queued-row conflict precheck ─────────────────────────────────────────
 *
 * A row queued behind the in-flight proof used to learn that main had moved
 * into a conflicting state only when it reached the head of the queue (land
 * seqs 102/103: ~69 min queued, then `conflict/rebase` in under 5 s). Each
 * beat that leaves a row in flight now replays every queued row onto the
 * main it just observed, in the object store only, and ends a row that
 * cannot rebase as the same conflict outcome dl_rebase() would record. */

/* One commit on origin/main writing `path` = `body` on branch `branch`;
 * the clone goes back to its own main (the rig's tip A) afterwards. */
bool dlx_qp_branch(struct dlx_rig *rig, const char *branch,
                          const char *path, const char *body,
                          const char *path2, const char *body2, char out[64])
{
    const char *to_branch[] = { "checkout", "--quiet", "-b", branch,
                                "origin/main", NULL };
    const char *back[] = { "checkout", "--quiet", "main", NULL };
    if (dlx_git(rig->clone, to_branch) != 0 ||
        !dlx_write_dep(rig->clone, path, body))
        return false;
    if (path2 && !dlx_write_dep(rig->clone, path2, body2))
        return false;
    return dlx_commit_tree(rig->clone, branch, out) &&
           dlx_git(rig->clone, back) == 0;
}

/* A direct push to origin main that nobody queued: one commit on the
 * current origin/main writing `path` = `body`. `out` is the new main. */
bool dlx_qp_push_main(struct dlx_rig *rig, const char *path,
                             const char *body, char out[64])
{
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    const char *to_mover[] = { "checkout", "--quiet", "-B", "mover",
                               "origin/main", NULL };
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *back[] = { "checkout", "--quiet", "main", NULL };
    return dlx_git(rig->clone, fetch) == 0 &&
           dlx_git(rig->clone, to_mover) == 0 &&
           dlx_write_dep(rig->clone, path, body) &&
           dlx_commit_tree(rig->clone, "direct push", out) &&
           dlx_git(rig->clone, push) == 0 &&
           dlx_git(rig->clone, back) == 0;
}

/* Submit `tip` and require it to take land seq `seq`. */
bool dlx_qp_submit(struct dlx_rig *rig, const char *tip, int64_t seq)
{
    struct dlx_call c;
    dlx_submit(&c, rig, tip);
    bool ok = dlx_run(&c) && dlx_ok(&c) && dlx_int(&c, "seq") == seq;
    dlx_end(&c);
    return ok;
}

/* Submit `a_tip` (seq 1, the row that goes in flight) then B (seq 2). */
static bool dlx_qp_start_a(struct dlx_rig *rig, const char *a_tip,
                           const char *b_tip)
{
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    return dlx_qp_submit(rig, a_tip, 1) && dlx_qp_submit(rig, b_tip, 2);
}

/* Submit A (the rig tip) then B. */
static bool dlx_qp_start(struct dlx_rig *rig, const char *b_tip)
{
    return dlx_qp_start_a(rig, rig->tip, b_tip);
}

/* One step; `state` is what the reply must name, and `checked`,
 * `conflicts` and `uncertain` what the precheck must report (-1: not
 * asserted). */
static bool dlx_qp_beat_u(const char *state, int64_t checked,
                          int64_t conflicts, int64_t uncertain)
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              strcmp(dlx_str(&c, "state"), state) == 0 &&
              (checked < 0 || dlx_int(&c, "queued_prechecked") == checked) &&
              (conflicts < 0 ||
               dlx_int(&c, "queued_conflicts") == conflicts) &&
              (uncertain < 0 ||
               dlx_int(&c, "queued_uncertain") == uncertain);
    if (!ok)
        printf("[step state=%s prechecked=%lld conflicts=%lld "
               "uncertain=%lld detail=%s] ",
               dlx_str(&c, "state"),
               (long long)dlx_int(&c, "queued_prechecked"),
               (long long)dlx_int(&c, "queued_conflicts"),
               (long long)dlx_int(&c, "queued_uncertain"),
               dlx_str(&c, "detail"));
    dlx_end(&c);
    return ok;
}

static bool dlx_qp_beat(const char *state, int64_t checked,
                        int64_t conflicts)
{
    return dlx_qp_beat_u(state, checked, conflicts, -1);
}

/* Quiet string equality: these helpers scan every row, so a mismatch is
 * the normal case, not a failure worth printing. */
static bool dlx_qp_same(const char *got, const char *want)
{
    return got && want && strcmp(got, want) == 0;
}

/* True when `tip` is still a queued row at `attempt`. */
static bool dlx_qp_queued_has(const char *tip, int64_t attempt)
{
    struct dlx_call c;
    bool found = false;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *rows = dlx_arr(&c, "queued");
    for (size_t i = 0; rows && i < rows->num_children; i++) {
        const struct json_value *r = &rows->children[i];
        if (dlx_qp_same(dlx_jstr(r, "tip"), tip) &&
            json_get_int(json_get(r, "attempt")) == attempt)
            found = true;
    }
    dlx_end(&c);
    return found;
}

/* True when the last outcome for `tip` is `state` in the rebase dimension;
 * its detail is copied into `detail`. */
bool dlx_qp_outcome(const char *tip, const char *state,
                           char *detail, size_t cap)
{
    struct dlx_call c;
    bool found = false;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *rows = dlx_arr(&c, "outcomes");
    for (size_t i = 0; rows && i < rows->num_children; i++) {
        const struct json_value *r = &rows->children[i];
        if (!dlx_qp_same(dlx_jstr(r, "tip"), tip))
            continue;
        found = dlx_qp_same(dlx_jstr(r, "state"), state) &&
                dlx_qp_same(dlx_jstr(r, "dimension"), "rebase");
        (void)snprintf(detail, cap, "%s", dlx_jstr(r, "detail"));
    }
    dlx_end(&c);
    return found;
}

/* The in-flight row: seq 1 (A), phase prove, proving on `base`, and the
 * landing worktree's checkout still at the prepared commit it proves. */
static bool dlx_qp_a_in_flight(const char *base)
{
    struct dlx_call c;
    char landwt[1300], head[64];
    const char *head_args[] = { "rev-parse", "HEAD", NULL };
    const char *porcelain[] = { "status", "--porcelain",
                                "--untracked-files=no", NULL };
    char dirty[256];
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *f = json_get(&c.reply.data, "in_flight");
    bool ok = f && json_get_int(json_get(f, "seq")) == 1 &&
              dlx_eq_str(dlx_jstr(f, "phase"), "prove") &&
              dlx_eq_str(dlx_jstr(f, "base"), base);
    char local[64];
    (void)snprintf(local, sizeof(local), "%s", ok ? dlx_jstr(f, "local") : "");
    dlx_end(&c);
    dlx_land_wt(landwt, sizeof(landwt));
    return ok && dlx_git_out(landwt, head_args, head, sizeof(head)) == 0 &&
           strcmp(head, local) == 0 &&
           dlx_git_out(landwt, porcelain, dirty, sizeof(dirty)) == 0 &&
           dirty[0] == '\0';
}

bool dlx_qp_file_has(const char *path, const char *needle)
{
    static char text[262144];
    size_t len = 0;
    if (!dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    return strstr(text, needle) != NULL;
}

/* The last line of `path` that holds `anchor`, copied into `line`. Choice:
 * outcomes.jsonl is read raw, since the status reply carries no base or mark. */
static bool dlx_qp_last_line(const char *path, const char *anchor,
                             char *line, size_t cap)
{
    static char text[262144];
    const char *hit = NULL, *p, *start, *end;
    size_t len = 0;
    if (!dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    for (p = text; (p = strstr(p, anchor)) != NULL; p++)
        hit = p;
    if (!hit)
        return false;
    start = hit;
    while (start > text && start[-1] != '\n')
        start--;
    end = strchr(hit, '\n');
    if (!end)
        end = text + len;
    if ((size_t)(end - start) >= cap)
        return false;
    (void)snprintf(line, cap, "%.*s", (int)(end - start), start);
    return true;
}

static int test_dev_land_queued_conflict_detected(void)
{
    int failures = 0;
    TEST("land: a queued row main moved into conflict with ends as a "
         "conflict one beat later, while the in-flight row keeps proving") {
        struct dlx_rig rig;
        char b[64], m1[64], detail[512], landdir[1200], maildir[1400];
        char outbox[1500];
        dlx_isolate("qp_conflict");
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(maildir, sizeof(maildir), "%s/../mail", landdir) <
               (int)sizeof(maildir));
        ASSERT(dlx_mkdir_p(maildir));
        ASSERT(dlx_rig_make(&rig, "qp_conflict_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "seed.txt", "mine\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start(&rig, b));
        /* A starts; B is mergeable onto the main A starts on. */
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_queued_has(b, 1));
        /* Someone pushes straight to main, over the very line B edits. */
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        /* Existing behaviour: A's proof pair is for a base nobody is on
         * any more, so A is requeued and restarted on the new main. */
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 1));
        /* B learned now, not after A's proof. */
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        ASSERT(strstr(detail, "seed.txt") != NULL);
        ASSERT(strstr(detail, m1) != NULL);
        ASSERT(!dlx_qp_queued_has(b, 1));
        /* A is in flight on the new main, and the landing checkout it
         * proves was never touched by the check. */
        ASSERT(dlx_qp_a_in_flight(m1));
        ASSERT(snprintf(outbox, sizeof(outbox), "%s/outbox.jsonl", maildir) <
               (int)sizeof(outbox));
        ASSERT(dlx_qp_file_has(outbox, "state=conflict"));
        ASSERT(dlx_qp_file_has(outbox, "detected while queued"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A terminal conflict row records its base and its cleared mark together;
 * the cleared mark has no later effect because the row is terminal. */
static int test_dev_land_queued_conflict_mark_cleared(void)
{
    int failures = 0;
    TEST("land: a queued row that spent its producer recovery and is "
         "conflicted by a moved main is recorded on that main with the "
         "mark cleared") {
        struct dlx_rig rig;
        char b[64], m1[64], detail[512], landdir[1200], outcomes[1300];
        char anchor[128], base[128], line[4096];
        dlx_isolate("qp_mark");
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(dlx_rig_make(&rig, "qp_mark_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "seed.txt", "mine\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        /* Seed: B's producer recovery is spent before the precheck runs. */
        ASSERT(snprintf(anchor, sizeof(anchor), "\"tip\":\"%s\"", b) <
               (int)sizeof(anchor));
        ASSERT(dlx_queue_field_once(anchor, "\"producer_recovered\":0",
                                    "\"producer_recovered\":1"));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 1));
        /* The model's own verdict checks. */
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        ASSERT(strstr(detail, m1) != NULL);
        ASSERT(!dlx_qp_queued_has(b, 1));
        /* The terminal row B lands in outcomes.jsonl: moved base, mark 0. */
        ASSERT(snprintf(outcomes, sizeof(outcomes), "%s/outcomes.jsonl",
                        landdir) < (int)sizeof(outcomes));
        ASSERT(dlx_qp_last_line(outcomes, anchor, line, sizeof(line)));
        ASSERT(strstr(line, "\"producer_recovered\":0") != NULL);
        ASSERT(snprintf(base, sizeof(base), "\"base\":\"%s\"", m1) <
               (int)sizeof(base));
        ASSERT(strstr(line, base) != NULL);
        ASSERT(strstr(line, "detected while queued") != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_generated_conflict_ended(void)
{
    int failures = 0;
    TEST("land: a queued row whose only conflict is a generated document "
         "is ended by the check, naming the make target") {
        struct dlx_rig rig;
        char b[64], m1[64], detail[512];
        dlx_isolate("qp_regen");
        ASSERT(dlx_rig_make(&rig, "qp_regen_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "docs/agent/EXECUTOR_HEURISTICS.md",
                             "mine\n", "b.txt", "mine\n", b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_push_main(&rig, "docs/agent/EXECUTOR_HEURISTICS.md",
                                "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        /* Checked against the new main and ended as a conflict that names
         * the target an author runs; the queue settles nothing. */
        ASSERT(dlx_qp_beat("started", 1, 1));
        ASSERT(!dlx_qp_queued_has(b, 1));
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "run `make docs-executor-routing`") != NULL);
        ASSERT(dlx_qp_a_in_flight(m1));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_mergeable_lands(void)
{
    int failures = 0;
    TEST("land: a mergeable queued row is left queued by the check and "
         "later lands") {
        struct dlx_rig rig;
        char b[64], m1[64], remote[64];
        const char *show_b[] = { "show", "main:b.txt", NULL };
        const char *show_o[] = { "show", "main:other.txt", NULL };
        char out[64];
        dlx_isolate("qp_clean");
        ASSERT(dlx_rig_make(&rig, "qp_clean_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "b.txt", "mine\n", NULL, NULL, b));
        /* Main moves before anything starts, so B's check is a real
         * replay onto a main B was not cut from. */
        ASSERT(dlx_qp_push_main(&rig, "other.txt", "theirs\n", m1));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(dlx_qp_a_in_flight(m1));
        /* A lands, then B is rebased, proved and lands in order. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_qp_beat("landed", -1, -1));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(dlx_qp_beat("started", -1, -1));
        ASSERT(dlx_qp_beat("landed", -1, -1));
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT(dlx_git_out(rig.bare, show_b, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "mine");
        ASSERT(dlx_git_out(rig.bare, show_o, out, sizeof(out)) == 0);
        ASSERT_STR_EQ(out, "theirs");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Lines of logs/precheck.log that name `needle`. */
static long dlx_qp_log_count(const char *needle)
{
    static char text[262144];
    char landdir[1200], path[1400];
    size_t len = 0;
    long n = 0;
    char *save = NULL;
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(path, sizeof(path), "%s/logs/precheck.log", landdir) >=
            (int)sizeof(path) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return -1;
    text[len] = '\0';
    for (char *line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save))
        n += strstr(line, needle) != NULL;
    return n;
}

static int test_dev_land_queued_tool_failure_kept(void)
{
    int failures = 0;
    TEST("land: a precheck tool failure leaves the queued row queued and "
         "unmarked, and the next beat asks again") {
        struct dlx_rig rig;
        char b[64], m1[64], detail[512];
        dlx_isolate("qp_toolfail");
        ASSERT(dlx_rig_make(&rig, "qp_toolfail_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "seed.txt", "mine\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        /* The merge step itself fails: a real conflict, but no certainty
         * about it, so nothing is ended. */
        setenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL", "1", 1);
        ASSERT(dlx_qp_beat("started", 1, 0));
        unsetenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL");
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT_EQ(dlx_qp_log_count("uncertain: merge-tree failed"), 1);
        ASSERT(dlx_qp_a_in_flight(m1));
        /* Main has not moved, yet the row is asked again: an uncertain
         * answer never marks it checked. */
        ASSERT(dlx_qp_beat("proving", 1, 1));
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_main_moves_twice(void)
{
    int failures = 0;
    TEST("land: a queued row is checked once per observed main: clean on the "
         "first new main, ended on the second, never rechecked between") {
        struct dlx_rig rig;
        char b[64], m1[64], m2[64], detail[512];
        dlx_isolate("qp_twice");
        ASSERT(dlx_rig_make(&rig, "qp_twice_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "b.txt", "mine\n", NULL, NULL, b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        /* First new main: clean for B. */
        ASSERT(dlx_qp_push_main(&rig, "other.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT_EQ(dlx_qp_log_count(m1), 1);
        /* Unchanged main: no recheck, however many beats. */
        ASSERT(dlx_qp_beat("proving", 0, 0));
        ASSERT(dlx_qp_beat("proving", 0, 0));
        ASSERT_EQ(dlx_qp_log_count(m1), 1);
        ASSERT(dlx_qp_queued_has(b, 1));
        /* Second new main: over B's own line. */
        ASSERT(dlx_qp_push_main(&rig, "b.txt", "theirs\n", m2));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 1));
        ASSERT_EQ(dlx_qp_log_count(m2), 1);
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        ASSERT(strstr(detail, m2) != NULL);
        ASSERT(strstr(detail, "b.txt") != NULL);
        ASSERT(dlx_qp_a_in_flight(m2));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A branch `name` off origin/main with two commits, `p1` = `b1` then
 * `p2` = `b2`; the clone goes back to its own main afterwards. */
static bool dlx_qp_chain(struct dlx_rig *rig, const char *name,
                         const char *p1, const char *b1, const char *p2,
                         const char *b2, char out[64])
{
    char first[64];
    const char *to_branch[] = { "checkout", "--quiet", "-b", name,
                                "origin/main", NULL };
    const char *back[] = { "checkout", "--quiet", "main", NULL };
    return dlx_git(rig->clone, to_branch) == 0 &&
           dlx_write_dep(rig->clone, p1, b1) &&
           dlx_commit_tree(rig->clone, "first", first) &&
           dlx_write_dep(rig->clone, p2, b2) &&
           dlx_commit_tree(rig->clone, "second", out) &&
           dlx_git(rig->clone, back) == 0;
}

/* A merge-bearing branch `name` off origin/main: it and a side branch both
 * add `path` with different bodies, and the merge resolves it by hand.
 * Replayed commit by commit, the side's commit conflicts with the branch's
 * own; the resolved tree does not. */
static bool dlx_qp_merge_row(struct dlx_rig *rig, const char *name,
                             const char *path, char out[64])
{
    char side[64], scratch[64];
    const char *c = rig->clone;
    (void)snprintf(side, sizeof(side), "%s-side", name);
    const char *to_branch[] = { "checkout", "--quiet", "-b", name,
                                "origin/main", NULL };
    const char *merge[] = { "-c", "user.name=land", "-c",
                            "user.email=land@z23.invalid", "merge",
                            "--quiet", "--no-ff", "--no-edit",
                            "--no-gpg-sign", side, NULL };
    const char *back[] = { "checkout", "--quiet", "main", NULL };
    if (!dlx_qp_branch(rig, side, path, "side\n", NULL, NULL, scratch) ||
        dlx_git(c, to_branch) != 0 || !dlx_write_dep(c, path, "mine\n") ||
        !dlx_commit_tree(c, "mine", scratch))
        return false;
    /* The merge must stop on the add/add conflict it is built around. */
    if (dlx_git(c, merge) == 0)
        return false;
    return dlx_write_dep(c, path, "resolved\n") &&
           dlx_commit_tree(c, "resolve", out) && dlx_git(c, back) == 0;
}

/* Give queued row `seq` the landing priority `prio` in queue.jsonl, the
 * way a retried row keeps its original place ahead of later requests. */
static bool dlx_qp_prioritise(long long seq, long long prio)
{
    static char text[65536];
    char landdir[1200], qpath[1300], from[64], to[64];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) >=
            (int)sizeof(qpath) ||
        !dlx_slurp(qpath, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    (void)snprintf(from, sizeof(from), "\"seq\":%lld,\"priority_seq\":%lld,",
                   seq, seq);
    (void)snprintf(to, sizeof(to), "\"seq\":%lld,\"priority_seq\":%lld,",
                   seq, prio);
    char *at = strstr(text, from);
    if (!at || strlen(from) != strlen(to))
        return false;
    memcpy(at, to, strlen(to));
    return dlx_write(qpath, text);
}

/* True when the first precheck.log line naming `first` comes before the
 * first line naming `second`. */
static bool dlx_qp_log_before(const char *first, const char *second)
{
    static char text[262144];
    char landdir[1200], path[1400];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(path, sizeof(path), "%s/logs/precheck.log", landdir) >=
            (int)sizeof(path) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    const char *a = strstr(text, first), *b = strstr(text, second);
    return a && b && a < b;
}

static int test_dev_land_queued_union_attr_kept(void)
{
    int failures = 0;
    TEST("land: a queued row whose overlap main's own union merge attribute "
         "settles is not ended, whatever the landing checkout declares") {
        struct dlx_rig rig;
        char m1[64], m2[64], a[64], b[64], detail[512], landwt[1300];
        char attrs[1400];
        dlx_isolate("qp_union");
        ASSERT(dlx_rig_make(&rig, "qp_union_rig"));
        ASSERT(dlx_qp_push_main(&rig, "u.txt", "base\n", m1));
        ASSERT(dlx_qp_push_main(&rig, ".gitattributes", "u.txt merge=union\n",
                                m1));
        /* A, the row that goes in flight, drops the attribute, so the
         * landing checkout it proves declares no union merge. */
        ASSERT(dlx_qp_branch(&rig, "qp-a", ".gitattributes", "# none\n", NULL,
                             NULL, a));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "u.txt", "base\nb\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start_a(&rig, a, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        /* Main appends its own line where B appends: a conflict under the
         * default merge, clean under main's union attribute, which is
         * what a rebase onto main reads. */
        ASSERT(dlx_qp_push_main(&rig, "u.txt", "base\nm\n", m2));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT_EQ(dlx_qp_log_count(m2), 1);
        /* The premise held: A proves on the new main with no union. */
        ASSERT(dlx_qp_a_in_flight(m2));
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(snprintf(attrs, sizeof(attrs), "%s/.gitattributes", landwt) <
               (int)sizeof(attrs));
        ASSERT(dlx_qp_file_has(attrs, "# none"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_uncertain_backoff(void)
{
    int failures = 0;
    TEST("land: a queued row that stays uncertain is asked three times per "
         "main, then left for its real rebase until main moves") {
        struct dlx_rig rig;
        char b[64], m1[64], m2[64], detail[512];
        dlx_isolate("qp_backoff");
        ASSERT(dlx_rig_make(&rig, "qp_backoff_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "seed.txt", "mine\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        setenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL", "1", 1);
        ASSERT(dlx_qp_beat_u("started", 1, 0, 1));
        ASSERT(dlx_qp_beat_u("proving", 1, 0, 1));
        ASSERT(dlx_qp_beat_u("proving", 1, 0, 1));
        /* Three strikes on this main: no fourth replay, and one line says
         * so. */
        ASSERT(dlx_qp_beat_u("proving", 0, 0, 0));
        unsetenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL");
        ASSERT(dlx_qp_beat_u("proving", 0, 0, 0));
        ASSERT_EQ(dlx_qp_log_count("uncertain: merge-tree failed"), 3);
        ASSERT_EQ(dlx_qp_log_count("not rechecked until main moves"), 1);
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        /* A new main is a new question. */
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs2\n", m2));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat_u("started", 1, 1, 0));
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, m2) != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Count the .merge_file_* temp files an external merge driver left in
 * `dir`. */
static int dlx_qp_stray_merge_files(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    int n = 0;
    if (!d)
        return -1;
    while ((e = readdir(d)) != NULL)
        if (strncmp(e->d_name, ".merge_file_", 12) == 0)
            n++;
    closedir(d);
    return n;
}

static int test_dev_land_queued_driver_cwd_clean(void)
{
    int failures = 0;
    TEST("land: a precheck replay killed at its deadline inside an external "
         "merge driver leaves no .merge_file_* in the landing worktree and "
         "answers uncertain") {
        struct dlx_rig rig;
        char m1[64], b[64], landwt[1300], landdir[1200], attrs[1400];
        const char *cfg_drv[] = { "config", "merge.slow.driver",
                                  "sleep 3; cp %A %A", NULL };
        const char *cfg_attr[] = { "config", "core.attributesFile", attrs,
                                   NULL };
        dlx_isolate("qp_driver");
        ASSERT(dlx_rig_make(&rig, "qp_driver_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "seed.txt", "mine\n", NULL, NULL,
                             b));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_beat("started", 1, 0));
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        dlx_land_wt(landwt, sizeof(landwt));
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(attrs, sizeof(attrs), "%s/slow.attrs", landdir) <
               (int)sizeof(attrs));
        ASSERT(dlx_write_dep(landdir, "slow.attrs", "seed.txt merge=slow\n"));
        ASSERT(dlx_git(landwt, cfg_drv) == 0);
        ASSERT(dlx_git(landwt, cfg_attr) == 0);
        setenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS", "1200", 1);
        ASSERT(dlx_qp_beat_u("started", -1, 0, 1));
        unsetenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS");
        ASSERT_EQ(dlx_qp_stray_merge_files(landwt), 0);
        ASSERT(dlx_qp_queued_has(b, 1));
        dlx_restore();
        PASS();
    }
_test_next:;
    unsetenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS");
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_priority_order(void)
{
    int failures = 0;
    TEST("land: queued rows are checked in the order they will land, not "
         "the order they were written") {
        struct dlx_rig rig;
        char b[64], c[64];
        dlx_isolate("qp_order");
        ASSERT(dlx_rig_make(&rig, "qp_order_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "b.txt", "mine\n", NULL, NULL, b));
        ASSERT(dlx_qp_branch(&rig, "qp-c", "c.txt", "mine\n", NULL, NULL, c));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_submit(&rig, c, 3));
        /* C keeps an earlier place in line than B (a retried row does). */
        ASSERT(dlx_qp_prioritise(3, 1));
        ASSERT(dlx_qp_beat("started", 2, 0));
        ASSERT(dlx_qp_log_before("seq=3 ", "seq=2 "));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_deadline_left(void)
{
    int failures = 0;
    TEST("land: the precheck stops at its per-beat deadline and leaves the "
         "rows it did not reach unmarked for the next beat") {
        struct dlx_rig rig;
        struct dlx_call c;
        char b[64];
        dlx_isolate("qp_deadline");
        ASSERT(dlx_rig_make(&rig, "qp_deadline_rig"));
        ASSERT(dlx_qp_branch(&rig, "qp-b", "b.txt", "mine\n", NULL, NULL, b));
        ASSERT(dlx_qp_start(&rig, b));
        setenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS", "0", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        ASSERT_EQ(dlx_int(&c, "queued_prechecked"), 0);
        ASSERT_EQ(dlx_int(&c, "queued_uncertain"), 0);
        ASSERT_EQ(dlx_int(&c, "queued_unchecked"), 1);
        dlx_end(&c);
        unsetenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS");
        ASSERT_EQ(dlx_qp_log_count("deadline"), 1);
        ASSERT(dlx_qp_queued_has(b, 1));
        /* Unmarked: the next beat, on the same main, reaches it. */
        ASSERT(dlx_qp_beat_u("proving", 1, 0, 0));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_chain(void)
{
    int failures = 0;
    TEST("land: a multi-commit queued row is replayed commit on commit: a "
         "commit building on an earlier one is clean, a later commit over "
         "main's change is a conflict") {
        struct dlx_rig rig;
        char b[64], c[64], m1[64], detail[512];
        dlx_isolate("qp_chain");
        ASSERT(dlx_rig_make(&rig, "qp_chain_rig"));
        /* B's second commit edits the file its first commit adds. */
        ASSERT(dlx_qp_chain(&rig, "qp-b", "g.txt", "one\n", "g.txt", "two\n",
                            b));
        /* C's first commit is clean on any main; its second is not. */
        ASSERT(dlx_qp_chain(&rig, "qp-c", "h.txt", "h\n", "seed.txt",
                            "mine\n", c));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_submit(&rig, c, 3));
        ASSERT(dlx_qp_beat("started", 2, 0));
        ASSERT(dlx_qp_push_main(&rig, "seed.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 2, 1));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(dlx_qp_outcome(c, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        ASSERT(strstr(detail, "seed.txt") != NULL);
        ASSERT(strstr(detail, "h.txt") == NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_queued_merge_tip(void)
{
    int failures = 0;
    TEST("land: a merge-bearing queued row is judged by its resolved tree, "
         "the way the rebase that linearises it replays it") {
        struct dlx_rig rig;
        char b[64], c[64], m1[64], detail[512];
        dlx_isolate("qp_mtip");
        ASSERT(dlx_rig_make(&rig, "qp_mtip_rig"));
        /* Commit by commit, B's two sides collide on f.txt; its merge
         * settled that, and main never touches f.txt. */
        ASSERT(dlx_qp_merge_row(&rig, "qp-b", "f.txt", b));
        /* C is shaped the same on g.txt, and main adds g.txt too. */
        ASSERT(dlx_qp_merge_row(&rig, "qp-c", "g.txt", c));
        ASSERT(dlx_qp_start(&rig, b));
        ASSERT(dlx_qp_submit(&rig, c, 3));
        ASSERT(dlx_qp_beat("started", 2, 0));
        ASSERT(dlx_qp_push_main(&rig, "g.txt", "theirs\n", m1));
        ASSERT(dlx_qp_beat("rebased", -1, -1));
        ASSERT(dlx_qp_beat("started", 2, 1));
        ASSERT(dlx_qp_queued_has(b, 1));
        ASSERT(!dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(dlx_qp_outcome(c, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "g.txt") != NULL);
        ASSERT(strstr(detail, m1) != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* (a) true conflict, (b) clean then lands, (c) regenerated artifacts only,
 * (d) tool failure, (e) main moving twice; then main's merge attributes,
 * the uncertain backoff, priority order, the beat deadline, multi-commit
 * chains and merge-bearing tips. */
int test_dev_land_queued_precheck_cases(void)
{
    int failures = 0;
    failures += test_dev_land_queued_conflict_detected();
    failures += test_dev_land_queued_conflict_mark_cleared();
    failures += test_dev_land_queued_mergeable_lands();
    failures += test_dev_land_queued_generated_conflict_ended();
    failures += test_dev_land_queued_tool_failure_kept();
    failures += test_dev_land_queued_main_moves_twice();
    failures += test_dev_land_queued_union_attr_kept();
    failures += test_dev_land_queued_uncertain_backoff();
    failures += test_dev_land_queued_priority_order();
    failures += test_dev_land_queued_driver_cwd_clean();
    failures += test_dev_land_queued_deadline_left();
    failures += test_dev_land_queued_chain();
    failures += test_dev_land_queued_merge_tip();
    return failures;
}

#endif /* !defined(_WIN32) */
