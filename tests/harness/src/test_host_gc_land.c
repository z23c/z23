/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ops.host.gc over the land receiver pool (tools/command/host_gc_landpool.c).
 *
 * `dev land receive` leaves one detached copy per lane under
 * <state root>/land-remote/<lane> with no sibling lock and no open process, so
 * the janitor keeps a copy by what the land queue says. A throwaway state root
 * (XDG_STATE_HOME) holds a pool shaped like land-remote and a queue.jsonl /
 * outcomes.jsonl beside it; every copy is back-dated past the age floor and
 * idle past age_days unless said otherwise:
 *
 *   held    row queued, tip = its HEAD            -> KEPT locked
 *   fly     row inflight, tip = its HEAD          -> KEPT locked
 *   done    row landed; .bundle/.prime.log/.lock  -> REAPED with its siblings
 *   bad     row failed                            -> REAPED
 *   young   row landed, directory just written    -> KEPT too_young
 *
 * Then held's row turns terminal and the next sweep removes it. The real
 * land-remote directory is never named: the state root is the fixture's.
 */

#include "test/test_core.h"

#include "command/host_gc_priv.h"
#include "command/host_gc_sweep.h"
#include "platform/state_root.h"
#include "util/spawn.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum { HGL_PATH = 600, HGL_OUT = 4096, HGL_OLD_HOURS = 300, HGL_COPIES = 5 };

static const char *const hgl_names[HGL_COPIES] = { "held", "fly", "done",
                                                   "bad", "young" };

struct hgl_fix {
    char tmp[HGL_PATH], repo[HGL_PATH], proc[HGL_PATH], units[HGL_PATH];
    char land[HGL_PATH], pool[HGL_PATH];
    char wt[HGL_COPIES][HGL_PATH];
    char sha[HGL_COPIES][64];
    char xdg[HGL_PATH];
};

static bool hgl_out(const char *dir, const char *const *args, char *out,
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

static bool hgl_git(const char *dir, const char *const *args)
{
    char out[HGL_OUT];
    return hgl_out(dir, args, out, sizeof(out));
}

static bool hgl_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool hgl_write(const char *path, const char *text)
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

static bool hgl_backdate(const char *path)
{
    struct timespec ts[2];
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    ts[0].tv_sec = st.st_atime;
    ts[0].tv_nsec = 0;
    ts[1].tv_sec = st.st_mtime - (time_t)HGL_OLD_HOURS * 3600;
    ts[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

static bool hgl_path(char *out, const char *dir, const char *name)
{
    return (size_t)snprintf(out, HGL_PATH, "%s/%s", dir, name) < HGL_PATH;
}

/* A repository whose copies each sit detached on a commit of their own, none
 * of them reachable from origin/main, so each HEAD is unique. */
static bool hgl_repo(struct hgl_fix *f)
{
    static const char *const init[] = { "init", "-q", "-b", "main", NULL };
    static const char *const origin[] = { "update-ref",
                                          "refs/remotes/origin/main", "HEAD",
                                          NULL };
    static const char *const head[] = { "rev-parse", "HEAD", NULL };
    const char *commit[] = { "-c", "user.name=z23-test", "-c",
                             "user.email=z23@example.invalid", "-c",
                             "commit.gpgsign=false", "commit", "-q",
                             "--allow-empty", "-m", "c", NULL };
    if (!hgl_path(f->repo, f->tmp, "repo") || mkdir(f->repo, 0700) != 0 ||
        !hgl_git(f->repo, init) || !hgl_git(f->repo, commit) ||
        !hgl_git(f->repo, origin))
        return false;
    for (size_t i = 0; i < HGL_COPIES; i++) {
        if (!hgl_git(f->repo, commit) ||
            !hgl_out(f->repo, head, f->sha[i], sizeof(f->sha[i])))
            return false;
        f->sha[i][strcspn(f->sha[i], "\r\n")] = '\0';
    }
    return true;
}

static bool hgl_copy(struct hgl_fix *f, size_t i, bool old)
{
    const char *add[] = { "worktree", "add", "--detach", "-q", f->wt[i],
                          f->sha[i], NULL };
    char gitdir[HGL_PATH + 64];
    if (!hgl_path(f->wt[i], f->pool, hgl_names[i]) || !hgl_git(f->repo, add))
        return false;
    if (!old)
        return true;
    for (size_t k = 0; k < 2; k++) {
        (void)snprintf(gitdir, sizeof(gitdir), "%s/.git/worktrees/%s/%s",
                       f->repo, hgl_names[i], k ? "HEAD" : "index");
        if (!hgl_backdate(gitdir))
            return false;
    }
    return hgl_backdate(f->wt[i]);
}

/* The row lines of the land queue: a queued and an inflight row in
 * queue.jsonl, the finished ones in outcomes.jsonl. */
static bool hgl_rows(const struct hgl_fix *f, const char *held_state)
{
    char path[HGL_PATH], text[HGL_OUT];
    (void)snprintf(text, sizeof(text),
                   "{\"seq\":1,\"tip\":\"%s\",\"state\":\"%s\",\"attempt\":1}\n"
                   "{\"seq\":2,\"tip\":\"%s\",\"state\":\"inflight\","
                   "\"attempt\":1}\n",
                   f->sha[0], held_state, f->sha[1]);
    if (!hgl_path(path, f->land, "queue.jsonl") || !hgl_write(path, text))
        return false;
    (void)snprintf(text, sizeof(text),
                   "{\"seq\":3,\"tip\":\"%s\",\"state\":\"landed\",\"attempt\":1}\n"
                   "{\"seq\":4,\"tip\":\"%s\",\"state\":\"failed\",\"attempt\":1}\n"
                   "{\"seq\":5,\"tip\":\"%s\",\"state\":\"landed\",\"attempt\":1}\n",
                   f->sha[2], f->sha[3], f->sha[4]);
    return hgl_path(path, f->land, "outcomes.jsonl") && hgl_write(path, text);
}

/* The state root is the fixture's: XDG_STATE_HOME decides it, and the pool is
 * created only after the verb's default has been shown to ignore its absence. */
static bool hgl_state(struct hgl_fix *f)
{
    char root[HGL_PATH];
    if (!hgl_path(f->xdg, f->tmp, "xdg") || mkdir(f->xdg, 0700) != 0 ||
        setenv("XDG_STATE_HOME", f->xdg, 1) != 0 ||
        !platform_state_root(root, sizeof(root)) ||
        !hgl_path(f->land, root, "land") || !hgl_path(f->pool, root, "land-remote"))
        return false;
    return mkdir(f->land, 0700) == 0 && hgl_path(f->proc, f->tmp, "proc") &&
           mkdir(f->proc, 0700) == 0 && hgl_path(f->units, f->tmp, "units") &&
           mkdir(f->units, 0700) == 0;
}

static bool hgl_build(struct hgl_fix *f)
{
    struct host_gc_request none;
    char sib[HGL_PATH + 16];
    static const char *const suffix[] = { ".bundle", ".prime.log", ".lock" };
    if (!hgl_state(f) || !hgl_repo(f) || !hgl_rows(f, "queued"))
        return false;
    /* No land-remote directory yet: the verb's default adds no pool. */
    memset(&none, 0, sizeof(none));
    if (host_gc_add_land_pool(&none) || none.npools != 0 || mkdir(f->pool, 0700) != 0)
        return false;
    for (size_t i = 0; i < HGL_COPIES; i++)
        if (!hgl_copy(f, i, i != 4))
            return false;
    for (size_t k = 0; k < 3; k++) {
        (void)snprintf(sib, sizeof(sib), "%s%s", f->wt[2], suffix[k]);
        if (!hgl_write(sib, "sibling\n"))
            return false;
    }
    return true;
}

/* The verb's own default builds the request; only the fixture's home, unit
 * directory and an empty fake procfs are set here. */
static bool hgl_request(const struct hgl_fix *f, struct host_gc_request *req,
                        bool apply)
{
    memset(req, 0, sizeof(*req));
    req->floor_hours = HOST_GC_DEFAULT_FLOOR_HOURS;
    req->age_days = HOST_GC_DEFAULT_AGE_DAYS;
    req->apply = apply;
    (void)snprintf(req->home, sizeof(req->home), "%s", f->tmp);
    (void)snprintf(req->proc_root, sizeof(req->proc_root), "%s", f->proc);
    (void)snprintf(req->unit_dir, sizeof(req->unit_dir), "%s", f->units);
    return host_gc_add_land_pool(req);
}

static int hgl_dry_tests(const struct hgl_fix *f)
{
    struct host_gc_request req;
    static struct host_gc_report report;
    int failures = 0;

    TEST("host gc land: the pool is marked disposable and queue_gated") {
        ASSERT(hgl_request(f, &req, false));
        ASSERT_EQ(req.npools, (size_t)1);
        ASSERT_STR_EQ(req.pools[0].name, "land-remote");
        ASSERT_STR_EQ(req.pools[0].path, f->pool);
        ASSERT(req.pools[0].disposable && req.pools[0].queue_gated);
        PASS();
    }

    TEST("host gc land: a dry run keeps rows' copies and young, and moves nothing") {
        ASSERT(hgl_request(f, &req, false));
        ASSERT(host_gc_run(&req, &report));
        ASSERT_EQ(report.nclasses, (size_t)1);
        ASSERT_EQ(report.classes[0].registered, HGL_COPIES);
        ASSERT_EQ(report.classes[0].locked, 2);
        ASSERT_EQ(report.classes[0].too_young, 1);
        ASSERT_EQ(report.classes[0].reapable, 2);
        for (size_t i = 0; i < HGL_COPIES; i++)
            ASSERT(hgl_exists(f->wt[i]));
        PASS();
    }
_test_next:;
    return failures;
}

static int hgl_apply_tests(const struct hgl_fix *f)
{
    struct host_gc_request req;
    static struct host_gc_report report;
    char sib[HGL_PATH + 16];
    int failures = 0;

    TEST("host gc land: apply removes the old terminal copies with their siblings") {
        ASSERT(hgl_request(f, &req, true));
        ASSERT(host_gc_run(&req, &report));
        ASSERT_EQ(report.classes[0].locked, 2);
        ASSERT(!hgl_exists(f->wt[2]) && !hgl_exists(f->wt[3]));
        for (size_t k = 0; k < 3; k++) {
            static const char *const suffix[] = { ".bundle", ".prime.log",
                                                  ".lock" };
            (void)snprintf(sib, sizeof(sib), "%s%s", f->wt[2], suffix[k]);
            ASSERT(!hgl_exists(sib));
        }
        PASS();
    }

    TEST("host gc land: a queued or inflight row's copy and the young copy stand") {
        ASSERT(hgl_exists(f->wt[0]) && hgl_exists(f->wt[1]));
        ASSERT(hgl_exists(f->wt[4]));
        PASS();
    }

    TEST("host gc land: the copy is released once its row is terminal") {
        ASSERT(hgl_rows(f, "landed"));
        ASSERT(hgl_request(f, &req, true));
        ASSERT(host_gc_run(&req, &report));
        ASSERT_EQ(report.classes[0].locked, 1);
        ASSERT(!hgl_exists(f->wt[0]));
        ASSERT(hgl_exists(f->wt[1]));
        PASS();
    }
_test_next:;
    return failures;
}

static int hgl_view_tests(const struct hgl_fix *f)
{
    struct hg_land_view *view;
    int failures = 0;

    TEST("host gc land: an unreadable queue or HEAD holds every copy") {
        ASSERT(hg_land_view_holds(NULL, f->sha[2]));
        view = hg_land_view_load();
        ASSERT(view != NULL);
        ASSERT(hg_land_view_holds(view, NULL));
        ASSERT(!hg_land_view_holds(view, f->sha[2]));
        ASSERT(hg_land_view_holds(view, f->sha[1]));
        hg_land_view_free(view);
        PASS();
    }
_test_next:;
    return failures;
}

int test_host_gc_land(void)
{
    static struct hgl_fix f;
    const char *saved = getenv("XDG_STATE_HOME");
    char keep[HGL_PATH] = "";
    int failures = 0;

    if (saved)
        (void)snprintf(keep, sizeof(keep), "%s", saved);
    memset(&f, 0, sizeof(f));
    TEST("host gc land: the fixture state root, repository and copies build") {
        ASSERT(test_mkdtemp(f.tmp, sizeof(f.tmp), "host_gc_land") != NULL);
        ASSERT(hgl_build(&f));
        PASS();
    }
    failures += hgl_dry_tests(&f);
    failures += hgl_apply_tests(&f);
    failures += hgl_view_tests(&f);
_test_next:;
    if (saved)
        (void)setenv("XDG_STATE_HOME", keep, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
    if (f.tmp[0])
        (void)test_rm_rf_recursive(f.tmp);
    if (failures == 0)
        printf("test_host_gc_land: all passed\n");
    else
        printf("test_host_gc_land: %d FAILED\n", failures);
    return failures;
}
