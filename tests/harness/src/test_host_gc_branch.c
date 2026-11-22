/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ops.host.gc over lane worktrees that sit on a branch
 * (tools/command/host_gc_sweep.c, hg_classify_branch).
 *
 * A clean worktree on a branch is a checkout of commits the branch already
 * holds. Real `git worktree add -b` lanes in a throwaway repository, every
 * one past the age floor and, unless said otherwise, with an index idle
 * 300 h:
 *
 *   lane-old      clean, one commit only its branch holds, an old build/
 *                 -> REAPED, branch and commit untouched, checkout restorable
 *   lane-young    clean, index written just now        -> KEPT too_young
 *   lane-built    clean, build/ written just now        -> KEPT too_young
 *   lane-dirty    one untracked file                    -> KEPT, listed for review
 *   lane-ignored  clean, an ignored local.db            -> KEPT need_review
 *   lane-hidden   reads clean, but seed.txt is edited behind an
 *                 assume-unchanged index flag           -> KEPT need_review
 *   lane-nest     clean, a registered worktree inside its ignored build/
 *                 -> KEPT need_review (the inner one is too_young)
 *   lane-m0..m8   clean, one marker each of a half-done git operation or
 *                 worktree-only state in its gitdir     -> KEPT need_review
 *
 * age_days 0 keeps every lane, as it keeps a unique detached HEAD, and a
 * disposable pool keeps its old answer for a copy on a branch.
 *
 * Not covered: an unborn branch (`git worktree add --orphan` needs git 2.42).
 */

#include "test/test_core.h"

#include "command/host_gc_sweep.h"
#include "util/spawn.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum { HGB_PATH = 512, HGB_OUT = 4096, HGB_OLD_HOURS = 300, HGB_MARKS = 9 };

/* Every name hg_mid_operation() looks for, relative to a lane's gitdir. A
 * lowercase first letter is a directory, an uppercase one a file. */
static const char *const hgb_marks[HGB_MARKS] = {
    "rebase-apply", "rebase-merge", "sequencer", "MERGE_HEAD",
    "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG", "info/sparse-checkout",
    "refs/worktree" };

struct hgb_fix {
    char tmp[HGB_PATH], repo[HGB_PATH], pool[HGB_PATH], proc[HGB_PATH];
    char units[HGB_PATH];
    char old[HGB_PATH], young[HGB_PATH], built[HGB_PATH], dirty[HGB_PATH];
    char ignored[HGB_PATH], hidden[HGB_PATH], nest[HGB_PATH];
    char inner[HGB_PATH + 32];
    char mark[HGB_MARKS][HGB_PATH];
    char old_sha[HGB_OUT];
};

/* git with the hook-inherited repository variables removed, the way the
 * engine itself runs it, so a harness started from a git hook still builds
 * its fixture in the throwaway repository. */
static bool hgb_out(const char *dir, const char *const *args, char *out,
                    size_t cap)
{
    const char *argv[32] = { "env", "-u", "GIT_DIR", "-u", "GIT_WORK_TREE",
                             "-u", "GIT_INDEX_FILE", "-u", "GIT_COMMON_DIR",
                             "git", "-C", dir };
    size_t n = 12;
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out, cap, 60000) == 0;
}

static bool hgb_git(const char *dir, const char *const *args)
{
    char out[HGB_OUT];
    return hgb_out(dir, args, out, sizeof(out));
}

static bool hgb_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool hgb_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    if (fputs(text, f) == EOF) {
        (void)fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

static bool hgb_backdate(const char *path)
{
    struct timespec ts[2];
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    ts[0].tv_sec = st.st_atime;
    ts[0].tv_nsec = 0;
    ts[1].tv_sec = st.st_mtime - (time_t)HGB_OLD_HOURS * 3600;
    ts[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

static bool hgb_commit(const char *dir, const char *subject)
{
    const char *args[] = {
        "-c", "user.name=z23-test", "-c", "user.email=z23@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty",
        "-m", subject, NULL };
    return hgb_git(dir, args);
}

static bool hgb_make_repo(const char *repo)
{
    static const char *const init[] = { "init", "-q", "-b", "main", NULL };
    static const char *const add[] = { "add", "-A", NULL };
    static const char *const origin[] = { "update-ref",
                                          "refs/remotes/origin/main", "HEAD",
                                          NULL };
    char seed[HGB_PATH + 32], ignore[HGB_PATH + 32];
    if (mkdir(repo, 0700) != 0 || !hgb_git(repo, init))
        return false;
    (void)snprintf(seed, sizeof(seed), "%s/seed.txt", repo);
    (void)snprintf(ignore, sizeof(ignore), "%s/.gitignore", repo);
    return hgb_write(seed, "fixture\n") &&
           hgb_write(ignore, "build/\n*.db\n") && hgb_git(repo, add) &&
           hgb_commit(repo, "fixture") && hgb_git(repo, origin);
}

/* A lane on its own branch carrying one commit no other ref holds. */
static bool hgb_add_lane(const struct hgb_fix *f, const char *name, char *out)
{
    const char *args[] = { "worktree", "add", "-q", "-b", name, out, "HEAD",
                           NULL };
    if ((size_t)snprintf(out, HGB_PATH, "%s/%s", f->pool, name) >= HGB_PATH)
        return false;
    return hgb_git(f->repo, args) && hgb_commit(out, name);
}

/* Back-date the lane directory (the age floor) and, with `idle`, the index
 * and HEAD of its gitdir (the idle clock). */
static bool hgb_age(const struct hgb_fix *f, const char *name, const char *wt,
                    bool idle)
{
    static const char *const files[] = { "index", "HEAD" };
    char path[HGB_PATH + 64];
    if (!hgb_backdate(wt))
        return false;
    for (size_t i = 0; idle && i < 2; i++) {
        (void)snprintf(path, sizeof(path), "%s/.git/worktrees/%s/%s", f->repo,
                       name, files[i]);
        if (!hgb_backdate(path))
            return false;
    }
    return true;
}

/* An ignored build/ directory in `wt`, old when `old`. */
static bool hgb_build_dir(const char *wt, bool old)
{
    char dir[HGB_PATH + 32], obj[HGB_PATH + 64];
    (void)snprintf(dir, sizeof(dir), "%s/build", wt);
    (void)snprintf(obj, sizeof(obj), "%s/out.o", dir);
    return mkdir(dir, 0700) == 0 && hgb_write(obj, "object\n") &&
           (!old || hgb_backdate(dir));
}

/* One lane per marker, created with its parent inside the lane's gitdir. */
static bool hgb_mark_lane(struct hgb_fix *f, size_t i)
{
    static const char *const head[] = { "rev-parse", "HEAD", NULL };
    char name[32], path[HGB_PATH + 96], parent[HGB_PATH + 96], sha[HGB_OUT];
    const char *slash = strchr(hgb_marks[i], '/');
    bool is_dir = hgb_marks[i][0] >= 'a' && !strstr(hgb_marks[i], "sparse");
    (void)snprintf(name, sizeof(name), "lane-m%zu", i);
    if (!hgb_add_lane(f, name, f->mark[i]))
        return false;
    (void)snprintf(path, sizeof(path), "%s/.git/worktrees/%s/%s", f->repo,
                   name, hgb_marks[i]);
    if (slash) {
        (void)snprintf(parent, sizeof(parent), "%s/.git/worktrees/%s/%.*s",
                       f->repo, name, (int)(slash - hgb_marks[i]),
                       hgb_marks[i]);
        if (mkdir(parent, 0700) != 0 && !hgb_exists(parent))
            return false;
    }
    /* A file marker names the lane's own commit, so `git status` still
     * answers and the lane reads clean: only the marker keeps it. */
    if (!hgb_out(f->mark[i], head, sha, sizeof(sha)))
        return false;
    if (!(is_dir ? mkdir(path, 0700) == 0 : hgb_write(path, sha)))
        return false;
    return hgb_age(f, name, f->mark[i], true);
}

/* lane-nest holds a registered detached worktree inside its ignored build/. */
static bool hgb_nest(struct hgb_fix *f)
{
    const char *args[] = { "worktree", "add", "--detach", "-q", f->inner,
                           "HEAD", NULL };
    char dir[HGB_PATH + 16];
    (void)snprintf(dir, sizeof(dir), "%s/build", f->nest);
    (void)snprintf(f->inner, sizeof(f->inner), "%s/inner", dir);
    return mkdir(dir, 0700) == 0 && hgb_git(f->repo, args) &&
           hgb_backdate(dir);
}

static bool hgb_lanes(struct hgb_fix *f)
{
    char path[HGB_PATH + 64];
    static const char *const hide[] = { "update-index", "--assume-unchanged",
                                        "seed.txt", NULL };
    if (!hgb_add_lane(f, "lane-old", f->old) ||
        !hgb_add_lane(f, "lane-young", f->young) ||
        !hgb_add_lane(f, "lane-built", f->built) ||
        !hgb_add_lane(f, "lane-dirty", f->dirty) ||
        !hgb_add_lane(f, "lane-ignored", f->ignored) ||
        !hgb_add_lane(f, "lane-hidden", f->hidden) ||
        !hgb_add_lane(f, "lane-nest", f->nest))
        return false;
    (void)snprintf(path, sizeof(path), "%s/notes.txt", f->dirty);
    if (!hgb_write(path, "not committed\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/local.db", f->ignored);
    if (!hgb_write(path, "state no ref holds\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/seed.txt", f->hidden);
    if (!hgb_write(path, "edited behind the flag\n") ||
        !hgb_git(f->hidden, hide))
        return false;
    return hgb_build_dir(f->old, true) && hgb_build_dir(f->built, false) &&
           hgb_nest(f);
}

static bool hgb_build(struct hgb_fix *f)
{
    static const char *const head[] = { "rev-parse", "HEAD", NULL };
    (void)snprintf(f->repo, sizeof(f->repo), "%s/repo", f->tmp);
    (void)snprintf(f->pool, sizeof(f->pool), "%s/pool", f->tmp);
    (void)snprintf(f->proc, sizeof(f->proc), "%s/proc", f->tmp);
    (void)snprintf(f->units, sizeof(f->units), "%s/units", f->tmp);
    if (mkdir(f->pool, 0700) != 0 || mkdir(f->proc, 0700) != 0 ||
        mkdir(f->units, 0700) != 0 || !hgb_make_repo(f->repo) ||
        !hgb_lanes(f))
        return false;
    for (size_t i = 0; i < HGB_MARKS; i++)
        if (!hgb_mark_lane(f, i))
            return false;
    if (!hgb_out(f->old, head, f->old_sha, sizeof(f->old_sha)))
        return false;
    f->old_sha[strcspn(f->old_sha, "\r\n")] = '\0';
    return hgb_age(f, "lane-old", f->old, true) &&
           hgb_age(f, "lane-young", f->young, false) &&
           hgb_age(f, "lane-built", f->built, true) &&
           hgb_age(f, "lane-dirty", f->dirty, true) &&
           hgb_age(f, "lane-ignored", f->ignored, true) &&
           hgb_age(f, "lane-hidden", f->hidden, true) &&
           hgb_age(f, "lane-nest", f->nest, true);
}

/* An empty fake procfs: the process inventory is complete and names nobody,
 * and the fixture home keeps the default unit directory off the real one. */
static void hgb_request(const struct hgb_fix *f, struct host_gc_request *req,
                        int age_days, bool apply)
{
    memset(req, 0, sizeof(*req));
    req->floor_hours = HOST_GC_DEFAULT_FLOOR_HOURS;
    req->age_days = age_days;
    req->apply = apply;
    (void)snprintf(req->home, sizeof(req->home), "%s", f->tmp);
    (void)snprintf(req->proc_root, sizeof(req->proc_root), "%s", f->proc);
    (void)snprintf(req->unit_dir, sizeof(req->unit_dir), "%s", f->units);
    (void)snprintf(req->pools[0].name, sizeof(req->pools[0].name), "lanes");
    (void)snprintf(req->pools[0].path, sizeof(req->pools[0].path), "%s",
                   f->pool);
    req->npools = 1;
}

static bool hgb_listed(const struct host_gc_report *r, const char *path)
{
    for (size_t i = 0; i < r->nreviews; i++)
        if (strcmp(r->reviews[i].path, path) == 0)
            return r->reviews[i].dirty_count == 1;
    return false;
}

/* Every lane but lane-old, which only an apply at age_days > 0 may remove. */
static bool hgb_kept_stand(const struct hgb_fix *f)
{
    for (size_t i = 0; i < HGB_MARKS; i++)
        if (!hgb_exists(f->mark[i]))
            return false;
    return hgb_exists(f->young) && hgb_exists(f->built) &&
           hgb_exists(f->dirty) && hgb_exists(f->ignored) &&
           hgb_exists(f->hidden) &&
           hgb_exists(f->nest) && hgb_exists(f->inner);
}

static int hgb_dry_tests(const struct hgb_fix *f)
{
    struct host_gc_request req;
    static struct host_gc_report report;
    int failures = 0;

    TEST("host gc branch: a dry run finds the one clean idle lane and moves nothing") {
        hgb_request(f, &req, HOST_GC_DEFAULT_AGE_DAYS, false);
        ASSERT(host_gc_run(&req, &report));
        ASSERT_EQ(report.nclasses, (size_t)1);
        ASSERT_EQ(report.classes[0].registered, 8 + HGB_MARKS);
        ASSERT_EQ(report.classes[0].reapable, 1);
        ASSERT_EQ(report.classes[0].branch_kept, 1);
        ASSERT_EQ(report.classes[0].unique_archived, 0);
        /* lane-young, lane-built and the fresh inner worktree. */
        ASSERT_EQ(report.classes[0].too_young, 3);
        /* lane-dirty, lane-ignored, lane-hidden, lane-nest, one per marker. */
        ASSERT_EQ(report.classes[0].need_review, 4 + HGB_MARKS);
        ASSERT_EQ(report.nreviews, (size_t)1);
        ASSERT(hgb_listed(&report, f->dirty));
        ASSERT(hgb_exists(f->old) && hgb_kept_stand(f));
        PASS();
    }

    TEST("host gc branch: age_days 0 keeps every lane on a branch") {
        hgb_request(f, &req, 0, true);
        ASSERT(host_gc_run(&req, &report));
        ASSERT_EQ(report.classes[0].reapable, 0);
        ASSERT_EQ(report.classes[0].branch_kept, 0);
        ASSERT_EQ(report.classes[0].need_review, 7 + HGB_MARKS);
        ASSERT(hgb_exists(f->old) && hgb_kept_stand(f));
        PASS();
    }

    TEST("host gc branch: a disposable pool keeps a copy that sits on a branch") {
        hgb_request(f, &req, HOST_GC_DEFAULT_AGE_DAYS, false);
        req.pools[0].disposable = true;
        ASSERT(host_gc_run(&req, &report));
        ASSERT_EQ(report.classes[0].branch_kept, 0);
        ASSERT_EQ(report.classes[0].reapable, 0);
        ASSERT(hgb_exists(f->old) && hgb_kept_stand(f));
        PASS();
    }
_test_next:;
    return failures;
}

static int hgb_apply_tests(const struct hgb_fix *f)
{
    static const char *const branch[] = { "rev-parse", "--verify",
                                          "refs/heads/lane-old", NULL };
    static const char *const archive[] = { "for-each-ref",
                                           "--format=%(refname)",
                                           "refs/archive", NULL };
    const char *back[] = { "worktree", "add", "-q", f->old, "lane-old", NULL };
    struct host_gc_request req;
    static struct host_gc_report report;
    char got[HGB_OUT], seed[HGB_PATH + 32];
    int failures = 0;

    TEST("host gc branch: apply removes the clean idle lane and leaves its branch") {
        hgb_request(f, &req, HOST_GC_DEFAULT_AGE_DAYS, true);
        ASSERT(host_gc_run(&req, &report));
        ASSERT_EQ(report.classes[0].branch_kept, 1);
        ASSERT_EQ(report.classes[0].reapable, 1);
        ASSERT_EQ(report.nrefusals, (size_t)0);
        ASSERT(!hgb_exists(f->old));
        ASSERT(hgb_kept_stand(f));
        ASSERT(hgb_out(f->repo, branch, got, sizeof(got)));
        got[strcspn(got, "\r\n")] = '\0';
        ASSERT_STR_EQ(got, f->old_sha);
        /* The branch is the whole record: nothing was pinned beside it. */
        ASSERT(hgb_out(f->repo, archive, got, sizeof(got)));
        ASSERT_STR_EQ(got, "");
        PASS();
    }

    TEST("host gc branch: the removed lane comes back from its branch") {
        static const char *const head[] = { "rev-parse", "HEAD", NULL };
        ASSERT(hgb_git(f->repo, back));
        (void)snprintf(seed, sizeof(seed), "%s/seed.txt", f->old);
        ASSERT(hgb_exists(seed));
        ASSERT(hgb_out(f->old, head, got, sizeof(got)));
        got[strcspn(got, "\r\n")] = '\0';
        ASSERT_STR_EQ(got, f->old_sha);
        PASS();
    }
_test_next:;
    return failures;
}

int test_host_gc_branch(void)
{
    static struct hgb_fix f;
    int failures = 0;

    memset(&f, 0, sizeof(f));
    TEST("host gc branch: the fixture repository and its lanes build") {
        ASSERT(test_mkdtemp(f.tmp, sizeof(f.tmp), "host_gc_branch") != NULL);
        ASSERT(hgb_build(&f));
        PASS();
    }
    failures += hgb_dry_tests(&f);
    failures += hgb_apply_tests(&f);
_test_next:;
    if (f.tmp[0])
        (void)test_rm_rf_recursive(f.tmp);
    if (failures == 0)
        printf("test_host_gc_branch: all passed\n");
    else
        printf("test_host_gc_branch: %d FAILED\n", failures);
    return failures;
}
