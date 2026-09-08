/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the host-GC worktree-pool sweep engine declared in
 *          command/host_gc_sweep.h. Read that header first: it carries the
 *          pool definition, the keep rules, and the single-deletion-path
 *          guarantee this file implements. The protection predicate and the
 *          path plumbing live in host_gc_paths.c.
 *
 * PROCESS RULE. git runs only through zcl_spawn_capture() (util/spawn.h).
 * No popen(), no system(), no shell command string, and no unlink(),
 * rmdir(), or recursive delete anywhere in this translation unit.
 */

#include "command/host_gc_priv.h"

#include "util/safe_alloc.h"
#include "util/spawn.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum {
    HG_GIT_TIMEOUT_MS = 120000,
    HG_LIST_CAP = 262144,
    HG_STATUS_CAP = 4096,
    HG_REPO_PROBE_MAX = 32
};

/* One removal candidate: a registered worktree of the pool's repository.
 * `occupied` is filled by the single /proc pass. */
struct hg_cand {
    char path[HOST_GC_PATH_CAP];
    size_t cls;
    bool detached;
    bool locked;
    bool occupied;
};

struct hg_scan {
    struct hg_cand *cands;
    size_t n;
    size_t cap;
    bool truncated;
};

static int hg_git(const char *dir, const char *const args[], char *out,
                  size_t out_cap)
{
    const char *argv[16];
    size_t n = 0;
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i] && n + 1 < sizeof(argv) / sizeof(argv[0]); i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    if (out && out_cap)
        out[0] = '\0';
    return zcl_spawn_capture(argv, out, out_cap, HG_GIT_TIMEOUT_MS);
}

static int64_t hg_now(const struct host_gc_request *req)
{
    return req->now ? req->now : (int64_t)time(NULL);
}

/* mtime age in seconds. A path that cannot be stat()ed reads as 0 — too
 * young to touch, the fail-safe direction. */
static int64_t hg_age_secs(const char *path, int64_t now)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    if (now <= (int64_t)st.st_mtime)
        return 0;
    return now - (int64_t)st.st_mtime;
}

static void hg_refuse(struct host_gc_report *report, const char *path,
                      const char *reason)
{
    struct host_gc_refusal *r;
    for (size_t i = 0; i < report->nrefusals; i++)
        if (strcmp(report->refusals[i].path, path) == 0)
            return;
    if (report->nrefusals >= HOST_GC_MAX_REFUSALS)
        return;
    r = &report->refusals[report->nrefusals];
    if (hg_copy(r->path, sizeof(r->path), path) &&
        hg_copy(r->reason, sizeof(r->reason), reason))
        report->nrefusals++;
}

/* ------------------------------------------------- worktree enumeration */

/* NUL-terminate the current line of `p` and return the next one. */
static char *hg_next_line(char *p)
{
    char *nl = strchr(p, '\n');
    if (!nl)
        return NULL;
    *nl = '\0';
    return nl + 1;
}


/* Ask git, from inside one worktree of the pool, for every worktree of the
 * repository that owns it. The FIRST porcelain entry is the main worktree,
 * so this also answers "which repository owns this pool" without a second
 * call and without the caller ever naming a repository itself — the removal
 * below can then only ever be addressed to the pool's own repo. */
static bool hg_list_worktrees(const char *child, char *buf, size_t cap,
                              char *repo, size_t repo_cap)
{
    static const char *const args[] = { "worktree", "list", "--porcelain",
                                        NULL };
    char first[HOST_GC_PATH_CAP];
    const char *end;
    size_t n;
    if (hg_git(child, args, buf, cap) != 0)
        return false;
    if (strncmp(buf, "worktree ", 9) != 0)
        return false;
    end = strchr(buf, '\n');
    n = (end ? (size_t)(end - buf) : strlen(buf)) - 9;
    if (n + 1 > sizeof(first))
        return false;
    memcpy(first, buf + 9, n);
    first[n] = '\0';
    return hg_copy(repo, repo_cap, first);
}

/* Which repository owns this pool? Ask git from inside a pool child, and
 * keep asking until one child answers.
 *
 * A single child is not enough. A pool accumulates directories whose
 * worktree registration is already gone (the administrative gitdir was
 * pruned while the checkout stayed on disk); `git worktree list` inside one
 * of those fails, and readdir order decides which child is tried first. A
 * one-child probe therefore made the entire pool report
 * `no_repo_behind_pool` — sweeping nothing — depending on nothing but
 * directory order. Bounded so a pool full of stale directories cannot turn
 * one sweep into hundreds of git invocations.
 */
static bool hg_pool_repo(const char *pool, char *buf, size_t cap, char *repo,
                         size_t repo_cap, bool *saw_child)
{
    DIR *d = opendir(pool);
    struct dirent *e;
    int tried = 0;
    bool found = false;
    *saw_child = false;
    if (!d)
        return false;
    while (!found && tried < HG_REPO_PROBE_MAX && (e = readdir(d)) != NULL) {
        struct stat st;
        char child[HOST_GC_PATH_CAP];
        if (e->d_name[0] == '.')
            continue;
        if (!hg_join(child, sizeof(child), pool, e->d_name))
            continue;
        if (stat(child, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        *saw_child = true;
        tried++;
        found = hg_list_worktrees(child, buf, cap, repo, repo_cap);
    }
    (void)closedir(d);
    return found;
}

/* git prints `locked` in the porcelain listing; the on-disk marker is read
 * as well so a git too old to print it still cannot lose a lock. Either
 * source saying "locked" keeps the worktree. */
static bool hg_locked_on_disk(const char *wt)
{
    char dotgit[HOST_GC_PATH_CAP];
    char line[HOST_GC_PATH_CAP];
    char marker[HOST_GC_PATH_CAP];
    struct stat st;
    FILE *f;
    if (!hg_join(dotgit, sizeof(dotgit), wt, ".git"))
        return false;
    f = fopen(dotgit, "r");
    if (!f)
        return false;
    if (!fgets(line, (int)sizeof(line), f))
        line[0] = '\0';
    (void)fclose(f);
    hg_strip(line);
    if (strncmp(line, "gitdir: ", 8) != 0)
        return false;
    if (!hg_join(marker, sizeof(marker), line + 8, "locked"))
        return false;
    return stat(marker, &st) == 0;
}

static void hg_push_cand(struct hg_scan *scan, size_t cls, const char *path,
                         bool detached, bool locked)
{
    struct hg_cand *c;
    if (scan->n >= scan->cap) {
        scan->truncated = true;
        return;
    }
    c = &scan->cands[scan->n];
    if (!hg_copy(c->path, sizeof(c->path), path))
        return;
    c->cls = cls;
    c->detached = detached;
    c->locked = locked || hg_locked_on_disk(path);
    c->occupied = false;
    scan->n++;
}

/* One porcelain record. Only a worktree strictly UNDER the pool is ever a
 * candidate: the pool directory itself and every worktree elsewhere in the
 * repository are invisible to this sweep. */
static void hg_take_record(struct hg_scan *scan, size_t cls, const char *pool,
                           const char *path, bool detached, bool locked,
                           int *registered)
{
    if (!path[0] || strcmp(path, pool) == 0 || !hg_under(pool, path))
        return;
    (*registered)++;
    hg_push_cand(scan, cls, path, detached, locked);
}

static void hg_parse_worktrees(struct hg_scan *scan, size_t cls,
                               const char *pool, char *buf, int *registered)
{
    char path[HOST_GC_PATH_CAP];
    bool detached = false, locked = false;
    char *line = buf;
    path[0] = '\0';
    while (line) {
        char *next = hg_next_line(line);
        if (strncmp(line, "worktree ", 9) == 0) {
            hg_take_record(scan, cls, pool, path, detached, locked, registered);
            detached = false;
            locked = false;
            if (!hg_copy(path, sizeof(path), line + 9))
                path[0] = '\0';
        } else if (strcmp(line, "detached") == 0) {
            detached = true;
        } else if (strncmp(line, "locked", 6) == 0) {
            locked = true;
        }
        line = next;
    }
    hg_take_record(scan, cls, pool, path, detached, locked, registered);
}

/* ------------------------------------------------------- occupancy pass */

static void hg_mark_target(struct hg_scan *scan, const char *target)
{
    if (!target || target[0] != '/')
        return;
    for (size_t i = 0; i < scan->n; i++)
        if (!scan->cands[i].occupied && hg_under(scan->cands[i].path, target))
            scan->cands[i].occupied = true;
}

static void hg_mark_link(struct hg_scan *scan, const char *link)
{
    char target[PATH_MAX];
    ssize_t n = readlink(link, target, sizeof(target) - 1);
    if (n <= 0)
        return;
    target[n] = '\0';
    hg_mark_target(scan, target);
}

static void hg_mark_fds(struct hg_scan *scan, const char *procdir)
{
    char fddir[HOST_GC_PATH_CAP];
    DIR *d;
    struct dirent *e;
    if (!hg_join(fddir, sizeof(fddir), procdir, "fd"))
        return;
    d = opendir(fddir);
    if (!d)
        return;
    while ((e = readdir(d)) != NULL) {
        char link[HOST_GC_PATH_CAP * 2];
        if (e->d_name[0] == '.')
            continue;
        if (hg_join(link, sizeof(link), fddir, e->d_name))
            hg_mark_link(scan, link);
    }
    (void)closedir(d);
}

/* ONE pass over /proc marks every candidate a live process is sitting in or
 * holding open — cwd and open descriptors both, because a proof runs make
 * from the generation root while its children sit in subdirectories and its
 * log fd may be the only thing left. Unreadable entries (another user, an
 * exiting process) are simply absent, which UNDER-estimates occupancy: this
 * test can only ever add a keep, never remove one. */
static void hg_mark_occupied(const struct host_gc_request *req,
                             struct hg_scan *scan)
{
    const char *root = req->proc_root[0] ? req->proc_root : "/proc";
    DIR *d = opendir(root);
    struct dirent *e;
    if (!d)
        return;
    while ((e = readdir(d)) != NULL) {
        char procdir[HOST_GC_PATH_CAP];
        char cwdlink[HOST_GC_PATH_CAP * 2];
        if (e->d_name[0] < '0' || e->d_name[0] > '9')
            continue;
        if (!hg_join(procdir, sizeof(procdir), root, e->d_name))
            continue;
        if (hg_join(cwdlink, sizeof(cwdlink), procdir, "cwd"))
            hg_mark_link(scan, cwdlink);
        hg_mark_fds(scan, procdir);
    }
    (void)closedir(d);
}

/* ------------------------------------------------------- classification */

static bool hg_worktree_clean(const char *wt)
{
    static const char *const args[] = { "status", "--porcelain", NULL };
    char out[HG_STATUS_CAP];
    if (hg_git(wt, args, out, sizeof(out)) != 0)
        return false;
    return out[0] == '\0';
}

enum hg_verdict {
    HG_KEEP_LOCKED,
    HG_KEEP_IN_USE,
    HG_KEEP_TOO_YOUNG,
    HG_KEEP_NEEDS_REVIEW,
    HG_REAPABLE
};

/* The keep rules, in the order host_gc_sweep.h documents. Lock and
 * occupancy come first because both outrank the age floor as an
 * explanation and all four verdicts below REAPABLE are keeps. */
static enum hg_verdict hg_classify(const struct host_gc_request *req,
                                   const struct hg_cand *c, int64_t now)
{
    int64_t floor_s =
        (int64_t)(req->floor_hours > 0 ? req->floor_hours : 0) * 3600;
    if (c->locked)
        return HG_KEEP_LOCKED;
    if (c->occupied)
        return HG_KEEP_IN_USE;
    if (hg_age_secs(c->path, now) < floor_s)
        return HG_KEEP_TOO_YOUNG;
    if (!c->detached)
        return HG_KEEP_NEEDS_REVIEW;
    if (!hg_worktree_clean(c->path))
        return HG_KEEP_NEEDS_REVIEW;
    return HG_REAPABLE;
}

static void hg_count(struct host_gc_class *cls, enum hg_verdict v)
{
    switch (v) {
    case HG_KEEP_LOCKED: cls->locked++; break;
    case HG_KEEP_IN_USE: cls->in_use++; break;
    case HG_KEEP_TOO_YOUNG: cls->too_young++; break;
    case HG_KEEP_NEEDS_REVIEW: cls->need_review++; break;
    case HG_REAPABLE: cls->reapable++; break;
    }
}

/* THE ONLY DELETION PATH IN THE ENGINE. git is asked to remove a worktree
 * of the pool's OWN repository, and refuses anything that is not one. */
static bool hg_reap(const char *repo, const char *wt)
{
    const char *args[] = { "worktree", "remove", "--force", "--", wt, NULL };
    char out[HG_STATUS_CAP];
    return hg_git(repo, args, out, sizeof(out)) == 0;
}

static void hg_act(const struct host_gc_request *req,
                   struct host_gc_class *cls, const struct hg_cand *c)
{
    uint64_t bytes = hg_dir_bytes(c->path);
    cls->bytes_reclaimable += bytes;
    if (!req->apply)
        return;
    if (hg_reap(cls->repo, c->path)) {
        cls->bytes_reclaimed += bytes;
        return;
    }
    /* git declined. The worktree stands; report it as needing a human
     * rather than counting a reclaim that never happened. */
    cls->reapable--;
    cls->need_review++;
}

/* ------------------------------------------------------------- per pool */

static bool hg_pool_open(const struct host_gc_request *req,
                         struct host_gc_report *report,
                         struct host_gc_class *cls, char *buf, size_t cap)
{
    char reason[HOST_GC_REASON_CAP];
    bool saw_child = false;
    struct stat st;
    if (host_gc_path_protected(req, "", cls->path, reason, sizeof(reason))) {
        hg_refuse(report, cls->path, reason);
        return false;
    }
    if (stat(cls->path, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    cls->present = true;
    /* An EMPTY pool is the normal steady state, not a refusal: there is no
     * worktree to ask which repository owns the pool, and nothing to sweep.
     * A pool that HAS children but where no child answers a git question is
     * different — something is there that this engine cannot classify, so
     * it is refused by name rather than skipped in silence. */
    if (!hg_pool_repo(cls->path, buf, cap, cls->repo, sizeof(cls->repo),
                      &saw_child)) {
        if (saw_child)
            hg_refuse(report, cls->path, "no_repo_behind_pool");
        return false;
    }
    return true;
}

static void hg_settle(const struct host_gc_request *req,
                      struct host_gc_report *report, struct hg_scan *scan,
                      int64_t now)
{
    for (size_t i = 0; i < scan->n; i++) {
        struct hg_cand *c = &scan->cands[i];
        struct host_gc_class *cls = &report->classes[c->cls];
        char reason[HOST_GC_REASON_CAP];
        enum hg_verdict v;
        if (host_gc_path_protected(req, cls->repo, c->path, reason,
                                   sizeof(reason))) {
            hg_refuse(report, c->path, reason);
            cls->need_review++;
            continue;
        }
        v = hg_classify(req, c, now);
        hg_count(cls, v);
        if (v == HG_REAPABLE)
            hg_act(req, cls, c);
    }
}

static void hg_seed_classes(const struct host_gc_request *req,
                            struct host_gc_report *report)
{
    report->nclasses =
        req->npools < HOST_GC_MAX_POOLS ? req->npools : HOST_GC_MAX_POOLS;
    for (size_t i = 0; i < report->nclasses; i++) {
        (void)hg_copy(report->classes[i].name,
                      sizeof(report->classes[i].name), req->pools[i].name);
        (void)hg_copy(report->classes[i].path,
                      sizeof(report->classes[i].path), req->pools[i].path);
    }
}

bool host_gc_run(const struct host_gc_request *req,
                 struct host_gc_report *report)
{
    struct hg_scan scan = { NULL, 0, HOST_GC_MAX_CANDIDATES, false };
    char *buf;
    int64_t now;

    if (!req || !report)
        return false;
    memset(report, 0, sizeof(*report));
    now = hg_now(req);
    scan.cands = zcl_calloc(HOST_GC_MAX_CANDIDATES, sizeof(*scan.cands),
                            "host_gc candidates");
    buf = zcl_malloc(HG_LIST_CAP, "host_gc worktree listing");
    if (!scan.cands || !buf) {
        free(scan.cands);
        free(buf);
        return false;
    }
    hg_seed_classes(req, report);
    for (size_t i = 0; i < report->nclasses; i++) {
        struct host_gc_class *cls = &report->classes[i];
        if (hg_pool_open(req, report, cls, buf, HG_LIST_CAP))
            hg_parse_worktrees(&scan, i, cls->path, buf, &cls->registered);
    }
    hg_mark_occupied(req, &scan);
    hg_settle(req, report, &scan, now);
    report->truncated = scan.truncated;
    free(scan.cands);
    free(buf);
    return true;
}

/* The RAM pool root is read straight from ZCL_RAM_SCRATCH_ROOT rather than
 * through platform_ram_scratch_root(), which refuses when the tmpfs is
 * low on free space — exactly the moment a sweep is most needed. Same
 * variable name, so a live proof and this sweep can never disagree about
 * which tmpfs holds the pool. */
bool host_gc_defaults(struct host_gc_request *req)
{
    const char *home = getenv("HOME");
    const char *ram = getenv("ZCL_RAM_SCRATCH_ROOT");
    if (!req)
        return false;
    memset(req, 0, sizeof(*req));
    req->floor_hours = HOST_GC_DEFAULT_FLOOR_HOURS;
    if (!home || home[0] != '/' ||
        !hg_copy(req->home, sizeof(req->home), home))
        return false;
    if (!hg_copy(req->pools[0].name, sizeof(req->pools[0].name), "z23p") ||
        !hg_join(req->pools[0].path, sizeof(req->pools[0].path), home,
                 "github/.z23p"))
        return false;
    if (!hg_copy(req->pools[1].name, sizeof(req->pools[1].name), "z23p-ram") ||
        !hg_join(req->pools[1].path, sizeof(req->pools[1].path),
                 (ram && ram[0] == '/') ? ram : "/dev/shm", "z23p"))
        return false;
    req->npools = 2;
    return true;
}
