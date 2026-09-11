/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for ops.host.gc (tools/command/native_ops_host_gc.c over
 * the engine in tools/command/host_gc_sweep.c).
 *
 * THE PROPERTY THIS GROUP EXISTS FOR: the janitor never deletes work.
 * Three REAL `git worktree add` generations are built in a throwaway
 * repository under the harness's own test-tmp, and each is put into exactly
 * one of the states the engine must respect:
 *
 *   gen-inuse    a live child process whose cwd is inside it   -> KEPT in_use
 *   gen-locked   `git worktree lock`                           -> KEPT locked
 *   gen-orphan   neither, and back-dated past the age floor    -> REAPED
 *
 * Both keeps are YOUNGER than the floor, so a run that reported them as
 * "too_young" would pass a count check while proving nothing about the two
 * rules that actually matter. The class labels are asserted, not just the
 * totals.
 *
 * Then: a dry run changes nothing on disk, an apply reclaims ONLY the
 * orphan, every leaf in the engine's own protected-tree table is refused
 * BY NAME under a throwaway fixture home (never created and never touched
 * by this test — including the two live datadir names, which this test
 * reaches only through the table, never as a literal), and a directory is
 * separately refused by its contents (holding blk*.dat).
 *
 * AND THE OTHER HALF OF "never deletes work": it never abandons space
 * either. `git worktree remove` unregisters a worktree whether or not it
 * managed to delete the directory, so one read-only scratch directory
 * inside a dead generation leaves a tree git no longer lists — invisible
 * to every later sweep, and on the tmpfs pool a permanent RAM leak. Two
 * more generations cover that: one git leaves behind and the sweep must
 * finish off (reported reclaimed, refusals empty), and one nothing can
 * remove because its PARENT is read-only, which must appear in refusals[]
 * by name rather than vanish from the accounting.
 */

#include "test/test_core.h"

#include "command/host_gc_sweep.h"
#include "util/spawn.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

enum { HGT_PATH = 512, HGT_OUT = 8192 };

/* git through the same bounded capture seam the engine uses: no shell
 * string anywhere in this fixture either. */
static bool hgt_git(const char *dir, const char *const *args)
{
    const char *argv[24];
    size_t n = 0;
    char out[HGT_OUT];
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out, sizeof(out), 60000) == 0;
}

static bool hgt_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool hgt_write(const char *path, const char *text)
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

/* A repository with exactly one commit. Identity and signing are pinned on
 * the command line so a maintainer's global gitconfig (commit.gpgsign is
 * on for this project) cannot decide whether the fixture builds.
 *
 * The committed .gitignore is what lets a fixture generation below carry
 * the two things a REAL dev-proof generation carries — build output and a
 * vendored dependency — and still be what git calls clean, which is the
 * precondition for the sweep to consider it at all. */
static bool hgt_make_repo(const char *repo)
{
    static const char *const init[] = { "init", "-q", "-b", "main", NULL };
    static const char *const add[] = { "add", "-A", NULL };
    static const char *const commit[] = {
        "-c", "user.name=z23-test", "-c", "user.email=z23@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty",
        "-m", "fixture", NULL };
    char seed[HGT_PATH];
    char ignore[HGT_PATH];
    if (mkdir(repo, 0700) != 0 || !hgt_git(repo, init))
        return false;
    (void)snprintf(seed, sizeof(seed), "%s/seed.txt", repo);
    (void)snprintf(ignore, sizeof(ignore), "%s/.gitignore", repo);
    if (!hgt_write(seed, "fixture\n") ||
        !hgt_write(ignore, "out/\nvendor/\n"))
        return false;
    return hgt_git(repo, add) && hgt_git(repo, commit);
}

static bool hgt_add_gen(const char *repo, const char *pool, const char *name,
                        char *out, size_t cap)
{
    const char *args[8];
    if ((size_t)snprintf(out, cap, "%s/%s", pool, name) >= cap)
        return false;
    args[0] = "worktree";
    args[1] = "add";
    args[2] = "--detach";
    args[3] = "-q";
    args[4] = out;
    args[5] = "HEAD";
    args[6] = NULL;
    return hgt_git(repo, args);
}

/* Back-date a directory past the age floor. The engine reads mtime, so
 * moving mtime is the whole fixture. */
static bool hgt_backdate(const char *path, int hours)
{
    struct timespec ts[2];
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    ts[0].tv_sec = st.st_atime;
    ts[0].tv_nsec = 0;
    ts[1].tv_sec = st.st_mtime - (time_t)hours * 3600;
    ts[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

/* A live process sitting in `dir`. It never returns into harness code: the
 * child chdirs and parks until the parent kills it by its exact pid. */
static pid_t hgt_occupy(const char *dir)
{
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    if (chdir(dir) != 0)
        _exit(2);
    for (;;)
        pause();
}

static const struct host_gc_class *hgt_class(const struct host_gc_report *r,
                                             const char *name)
{
    for (size_t i = 0; i < r->nclasses; i++)
        if (strcmp(r->classes[i].name, name) == 0)
            return &r->classes[i];
    return NULL;
}

static const char *hgt_refusal(const struct host_gc_report *r,
                               const char *path)
{
    for (size_t i = 0; i < r->nrefusals; i++)
        if (strcmp(r->refusals[i].path, path) == 0)
            return r->refusals[i].reason;
    return NULL;
}

static void hgt_seed_request(struct host_gc_request *req, const char *pool)
{
    const char *home = getenv("HOME");
    memset(req, 0, sizeof(*req));
    req->floor_hours = HOST_GC_DEFAULT_FLOOR_HOURS;
    (void)snprintf(req->home, sizeof(req->home), "%s", home ? home : "/");
    (void)snprintf(req->pools[0].name, sizeof(req->pools[0].name), "z23p");
    (void)snprintf(req->pools[0].path, sizeof(req->pools[0].path), "%s", pool);
    req->npools = 1;
}

int test_host_gc(void)
{
    int failures = 0;
    char tmp[HGT_PATH] = "", repo[HGT_PATH] = "", pool[HGT_PATH] = "";
    char fake[HGT_PATH] = "", blk[HGT_PATH] = "";
    char inuse[HGT_PATH] = "", locked[HGT_PATH] = "", orphan[HGT_PATH] = "";
    char left_pool[HGT_PATH] = "", left_gen[HGT_PATH] = "";
    char left_out[HGT_PATH] = "";
    char stuck_pool[HGT_PATH] = "", stuck_gen[HGT_PATH] = "";
    pid_t occupant = -1;

    TEST("host gc: the fixture repository and its three generations build") {
        static const char *const lock[] = { "worktree", "lock", NULL, NULL };
        const char *lock_args[4];
        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "host_gc") != NULL);
        (void)snprintf(repo, sizeof(repo), "%s/repo", tmp);
        (void)snprintf(pool, sizeof(pool), "%s/pool", tmp);
        ASSERT(hgt_make_repo(repo));
        ASSERT(mkdir(pool, 0700) == 0);
        ASSERT(hgt_add_gen(repo, pool, "gen-inuse", inuse, sizeof(inuse)));
        ASSERT(hgt_add_gen(repo, pool, "gen-locked", locked, sizeof(locked)));
        ASSERT(hgt_add_gen(repo, pool, "gen-orphan", orphan, sizeof(orphan)));
        lock_args[0] = lock[0];
        lock_args[1] = lock[1];
        lock_args[2] = locked;
        lock_args[3] = NULL;
        ASSERT(hgt_git(repo, lock_args));
        ASSERT(hgt_backdate(orphan, 48));
        occupant = hgt_occupy(inuse);
        ASSERT(occupant > 0);
        PASS();
    }

    TEST("host gc: dry run labels in_use, locked and reapable, and moves nothing") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        hgt_seed_request(&req, pool);
        /* Give the forked occupant a moment to reach its chdir before the
         * /proc pass reads its cwd. The engine reads a live link, so this
         * is a fixture ordering wait, not a timing assumption in the code
         * under test. */
        for (int i = 0; i < 200; i++) {
            ASSERT(host_gc_run(&req, &report));
            cls = hgt_class(&report, "z23p");
            ASSERT(cls != NULL);
            if (cls->in_use == 1)
                break;
            {
                struct timespec nap = { 0, 10000000 };
                (void)nanosleep(&nap, NULL); /* real-clock: fixture ordering wait for the forked occupant's chdir, not a timing assumption in the code under test */
            }
        }
        ASSERT_EQ(cls->registered, 3);
        ASSERT_EQ(cls->in_use, 1);
        ASSERT_EQ(cls->locked, 1);
        ASSERT_EQ(cls->reapable, 1);
        ASSERT_EQ(cls->too_young, 0);
        ASSERT_EQ(cls->need_review, 0);
        ASSERT(cls->bytes_reclaimable > 0);
        ASSERT_EQ(cls->bytes_reclaimed, (uint64_t)0);
        ASSERT(hgt_exists(inuse) && hgt_exists(locked) && hgt_exists(orphan));
        PASS();
    }

    TEST("host gc: a stale pool directory does not disable the whole pool") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        char stale[HGT_PATH];
        char dotgit[HGT_PATH];
        FILE *f;
        /* A generation whose administrative gitdir is already gone: git
         * answers nothing from inside it. readdir order decides whether the
         * engine meets this one first, so a pool-repo probe that gave up
         * after one child would sweep or not sweep by accident. */
        (void)snprintf(stale, sizeof(stale), "%s/gen-stale", pool);
        (void)snprintf(dotgit, sizeof(dotgit), "%s/.git", stale);
        ASSERT(mkdir(stale, 0700) == 0);
        f = fopen(dotgit, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("gitdir: /nonexistent/worktrees/gen-stale\n", f) != EOF);
        ASSERT(fclose(f) == 0);
        hgt_seed_request(&req, pool);
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_STR_EQ(cls->repo, repo);
        ASSERT_EQ(cls->registered, 3);
        ASSERT_EQ(report.nrefusals, (size_t)0);
        /* Unregistered by git, so never a candidate and never removed. */
        ASSERT(hgt_exists(stale));
        PASS();
    }

    TEST("host gc: the age floor keeps everything when nothing is old enough") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        hgt_seed_request(&req, pool);
        req.floor_hours = 96;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->registered, 3);
        ASSERT_EQ(cls->reapable, 0);
        ASSERT_EQ(cls->too_young, 1);
        ASSERT_EQ(cls->in_use, 1);
        ASSERT_EQ(cls->locked, 1);
        ASSERT(hgt_exists(orphan));
        PASS();
    }

    TEST("host gc: apply reclaims the orphan and nothing else") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        hgt_seed_request(&req, pool);
        req.apply = true;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->reapable, 1);
        ASSERT(cls->bytes_reclaimed > 0);
        ASSERT(!hgt_exists(orphan));
        ASSERT(hgt_exists(inuse));
        ASSERT(hgt_exists(locked));
        PASS();
    }

    TEST("host gc: a generation git leaves behind is finished, not abandoned") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        char frozen[HGT_PATH];
        char vendor[HGT_PATH], vendor_git[HGT_PATH], vendor_head[HGT_PATH];
        /* A generation shaped like a real one. `out/` is read-only build
         * scratch: git's own removal stops there, reports failure, and
         * unregisters the worktree anyway — leaving a tree `git worktree
         * list` will never name again. `vendor/.git` is a DIRECTORY, the
         * shape a vendored submodule checkout has and the shape a
         * nested-repo-preserving remover would refuse to cross. Both are
         * covered by the fixture repo's committed .gitignore, so git still
         * calls the generation clean and the sweep still classifies it. */
        (void)snprintf(left_pool, sizeof(left_pool), "%s/pool-left", tmp);
        ASSERT(mkdir(left_pool, 0700) == 0);
        ASSERT(hgt_add_gen(repo, left_pool, "gen-left", left_gen,
                           sizeof(left_gen)));
        (void)snprintf(vendor, sizeof(vendor), "%s/vendor", left_gen);
        (void)snprintf(vendor_git, sizeof(vendor_git), "%s/.git", vendor);
        (void)snprintf(vendor_head, sizeof(vendor_head), "%s/HEAD",
                       vendor_git);
        (void)snprintf(left_out, sizeof(left_out), "%s/out", left_gen);
        (void)snprintf(frozen, sizeof(frozen), "%s/frozen.txt", left_out);
        ASSERT(mkdir(vendor, 0700) == 0);
        ASSERT(mkdir(vendor_git, 0700) == 0);
        ASSERT(hgt_write(vendor_head, "ref: refs/heads/main\n"));
        ASSERT(mkdir(left_out, 0700) == 0);
        ASSERT(hgt_write(frozen, "build output\n"));
        ASSERT(chmod(left_out, 0500) == 0);
        ASSERT(hgt_backdate(left_gen, 48));
        hgt_seed_request(&req, left_pool);
        req.apply = true;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->registered, 1);
        ASSERT_EQ(cls->reapable, 1);
        ASSERT_EQ(cls->need_review, 0);
        ASSERT(cls->bytes_reclaimed > 0);
        ASSERT_EQ(report.nrefusals, (size_t)0);
        ASSERT(!hgt_exists(left_gen));
        PASS();
    }

    TEST("host gc: a generation nothing can remove is refused by name") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        const char *reason;
        /* The pool directory itself is read-only, so the final rmdir of
         * the generation is impossible for git and for the sweep alike.
         * The one outcome this must never produce is silence: a generation
         * git has already unregistered and nobody can delete has to be
         * named, or it is exactly the leak that started this. */
        (void)snprintf(stuck_pool, sizeof(stuck_pool), "%s/pool-stuck", tmp);
        ASSERT(mkdir(stuck_pool, 0700) == 0);
        ASSERT(hgt_add_gen(repo, stuck_pool, "gen-stuck", stuck_gen,
                           sizeof(stuck_gen)));
        ASSERT(hgt_backdate(stuck_gen, 48));
        ASSERT(chmod(stuck_pool, 0500) == 0);
        hgt_seed_request(&req, stuck_pool);
        req.apply = true;
        ASSERT(host_gc_run(&req, &report));
        ASSERT(chmod(stuck_pool, 0700) == 0);
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->registered, 1);
        ASSERT_EQ(cls->reapable, 0);
        ASSERT_EQ(cls->need_review, 1);
        ASSERT_EQ(cls->bytes_reclaimed, (uint64_t)0);
        reason = hgt_refusal(&report, stuck_gen);
        ASSERT(reason != NULL);
        ASSERT_EQ(strncmp(reason, "remove_failed:", 14), 0);
        ASSERT(hgt_exists(stuck_gen));
        PASS();
    }

    TEST("host gc: every protected leaf is refused by name, never swept") {
        struct host_gc_request req;
        char reason[HOST_GC_REASON_CAP];
        char expect[HOST_GC_REASON_CAP];
        char datadir[HGT_PATH];
        char fixture_home[HGT_PATH];
        size_t nleaves = host_gc_protected_leaf_count();
        /* This walks tools/command/host_gc_paths.c's own protected-leaf
         * table (host_gc_protected_leaf), so it proves the sweep refuses
         * EVERY tree it protects — the two live datadir names included —
         * by name and without stat()ing it, without this test ever
         * spelling one of those names as a literal of its own. The home
         * a path is built under is this test's own throwaway fixture
         * directory, never the real $HOME. */
        (void)snprintf(fixture_home, sizeof(fixture_home),
                       "%s/fixture-home", tmp);
        hgt_seed_request(&req, pool);
        (void)snprintf(req.home, sizeof(req.home), "%s", fixture_home);
        ASSERT(nleaves > 0);
        for (size_t i = 0; i < nleaves; i++) {
            const char *leaf = host_gc_protected_leaf(i);
            ASSERT(leaf != NULL);
            (void)snprintf(datadir, sizeof(datadir), "%s/%s", fixture_home,
                           leaf);
            ASSERT(host_gc_path_protected(&req, "", datadir, reason,
                                          sizeof(reason)));
            (void)snprintf(expect, sizeof(expect), "protected_tree:%s",
                           leaf);
            ASSERT_STR_EQ(reason, expect);
        }
        PASS();
    }

    TEST("host gc: a directory holding block files is refused by contents") {
        struct host_gc_request req;
        struct host_gc_report report;
        const char *reason;
        FILE *f;
        (void)snprintf(fake, sizeof(fake), "%s/looks-like-a-pool", tmp);
        (void)snprintf(blk, sizeof(blk), "%s/blk00000.dat", fake);
        ASSERT(mkdir(fake, 0700) == 0);
        f = fopen(blk, "wb");
        ASSERT(f != NULL);
        ASSERT(fclose(f) == 0);
        hgt_seed_request(&req, fake);
        ASSERT(host_gc_run(&req, &report));
        reason = hgt_refusal(&report, fake);
        ASSERT(reason != NULL);
        ASSERT_STR_EQ(reason, "holds_chain_data");
        ASSERT(hgt_exists(blk));
        PASS();
    }

_test_next:;
    /* Restore both read-only fixture directories whatever happened above,
     * or the recursive cleanup below cannot take its own scratch tree
     * down. Both are this test's own, under its own tmpdir. */
    if (stuck_pool[0])
        (void)chmod(stuck_pool, 0700);
    if (left_out[0])
        (void)chmod(left_out, 0700);
    if (occupant > 0) {
        (void)kill(occupant, SIGKILL);
        (void)waitpid(occupant, NULL, 0);
    }
    if (locked[0]) {
        static const char *const unlock[] = { "worktree", "unlock", NULL,
                                              NULL };
        const char *args[4];
        args[0] = unlock[0];
        args[1] = unlock[1];
        args[2] = locked;
        args[3] = NULL;
        (void)hgt_git(repo, args);
    }
    if (tmp[0])
        (void)test_rm_rf_recursive(tmp);
    if (failures == 0)
        printf("test_host_gc: all passed\n");
    else
        printf("test_host_gc: %d FAILED\n", failures);
    return failures;
}
