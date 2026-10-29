/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: which pinned files do the worktrees of this repository change
 *          against origin/main. dev.cx.next only ever picks files with a
 *          baseline pin, so the caller hands in its pinned rows and the scan
 *          looks at those paths alone: per worktree one `git status` of the
 *          tracked files at the distinct pinned paths (literal pathspecs,
 *          chunked to a bounded command line; staged and unstaged in one
 *          pass; a pinned file is always tracked, so untracked files are not
 *          walked) plus one object-only merge-base diff of its HEAD run in the
 *          root. Every git call takes no optional locks, so the scan never
 *          refreshes or locks a lane's index under its writer. A busy host
 *          has a thousand worktrees, so they are scanned by a small pool. A
 *          worktree that cannot be read fails the whole scan, unless it
 *          vanished meanwhile (a test fixture's checkout): a directory that
 *          is gone changes nothing.
 *          Live: a worktree holds its files only while it is live, that is
 *          while the pinned-path status shows a tracked change, or its HEAD
 *          commit is under 48 hours old, or it has no HEAD; otherwise it is
 *          stale. Known edge: a lane with an old HEAD whose only uncommitted
 *          edits are to unpinned files is stale, so its committed pinned
 *          files are freed (the idle-lane policy). Index mtimes are no
 *          signal: tooling rewrites them. */

#include "command/native_dev_cx.h"

#include "base/safe_alloc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <pthread.h>
#endif

#define SC_BUF (4u * 1024u * 1024u)
#define SC_MS 300000
#define SC_THREADS 8
#define SC_ARG_BYTES (64u * 1024u) /* path bytes per git status call */

/* A worktree holds its changed files only while it is live: a pinned file has
 * an uncommitted change, or its HEAD commit was made at most this many hours
 * ago. */
#define SC_LIVE_HOURS 48

/* Distinct pinned paths, borrowed from the caller's rows. */
struct sc_paths {
    const char **v;
    size_t n;
};

struct sc_task {
    char path[ZCL_CX_PATH_MAX];
    char head[80];
    struct cx_set files;
    bool live;
    bool ok;
};

struct sc_pool {
    struct sc_task *tasks;
    size_t n;
    atomic_size_t next;
    const char *root;
    const struct sc_paths *pins; /* distinct pinned paths, NULL when none */
};

static int sc_git(const char *dir, const char *a, const char *b, const char *c,
                  const char *d, char *buf)
{
    const char *argv[] = {"git", "--no-optional-locks", "-c", "core.quotepath=off",
                          a, b, c, d, NULL};
    int rc = cx_run(dir, argv, buf, SC_BUF, SC_MS, false);
    return rc == 0 && strlen(buf) >= SC_BUF - 1 ? -1 : rc;
}

/* Adds the paths of `git status --porcelain` lines ("XY path"). */
static bool sc_add_status(struct cx_set *set, const char *text)
{
    for (const char *p = text; *p;) {
        size_t n = strcspn(p, "\n");
        const char *path = p + 3;
        size_t len = n >= 4 ? n - 3 : 0;
        if (len > 1 && path[0] == '"' && path[len - 1] == '"') {
            path++;
            len -= 2;
        }
        if (len > 0 && !cx_set_add(set, path, len))
            return false;
        p += n + (p[n] ? 1 : 0);
    }
    return true;
}

/* True when a porcelain line is not untracked ("??"): a tracked change. */
static bool sc_has_tracked(const char *text)
{
    for (const char *p = text; *p;) {
        size_t n = strcspn(p, "\n");
        if (n >= 4 && strncmp(p, "??", 2) != 0)
            return true;
        p += n + (p[n] ? 1 : 0);
    }
    return false;
}

/* `git status` of the tracked files at the pinned paths, in chunks of at most
 * SC_ARG_BYTES of path arguments so the command line stays bounded. The
 * porcelain lines of every chunk are folded into the task: the changed paths
 * into t->files, and t->live when any is a tracked change. */
static bool sc_status(struct sc_task *t, const struct sc_paths *pins, char *buf)
{
    static const char *const head[] = {
        "git", "--no-optional-locks", "--literal-pathspecs", "-c",
        "core.quotepath=off", "status", "--porcelain", "--no-renames", "-uno",
        "--"};
    enum { HEAD_N = sizeof(head) / sizeof(head[0]) };
    const char **argv =
        zcl_malloc((pins->n + HEAD_N + 1) * sizeof(*argv), "dev_cx.scan.argv");
    bool ok = argv != NULL;
    for (size_t at = 0; ok && at < pins->n;) {
        size_t k = HEAD_N, bytes = 0;
        memcpy(argv, head, sizeof(head));
        while (at < pins->n &&
               (bytes == 0 || bytes + strlen(pins->v[at]) < SC_ARG_BYTES)) {
            bytes += strlen(pins->v[at]) + 1;
            argv[k++] = pins->v[at++];
        }
        argv[k] = NULL;
        ok = cx_run(t->path, argv, buf, SC_BUF, SC_MS, false) == 0 &&
             strlen(buf) < SC_BUF - 1 && sc_add_status(&t->files, buf);
        t->live = t->live || (ok && sc_has_tracked(buf));
    }
    free(argv);
    return ok;
}

/* Is the worktree's HEAD commit within SC_LIVE_HOURS? git does the clock
 * (rev-list prints the commit only when it is that recent). -1 on error. */
static int sc_head_fresh(const char *root, const char *head, char *buf)
{
    char since[40];
    const char *argv[] = {"git", "rev-list", "--no-walk", since, head, NULL};
    snprintf(since, sizeof(since), "--since=%d.hours.ago", SC_LIVE_HOURS);
    if (cx_run(root, argv, buf, SC_BUF, SC_MS, false) != 0)
        return -1;
    return buf[0] != '\0';
}

static bool sc_scan_one(const char *root, struct sc_task *t, char *buf,
                        const struct sc_paths *pins)
{
    char range[160];
    int fresh = 1;
    if (pins && !sc_status(t, pins, buf))
        return false;
    if (!t->head[0]) {
        t->live = true;
        return true;
    }
    if (!t->live) {
        fresh = sc_head_fresh(root, t->head, buf);
        if (fresh < 0)
            return false;
        t->live = fresh == 1;
    }
    if (snprintf(range, sizeof(range), "origin/main...%s", t->head) >=
        (int)sizeof(range))
        return false;
    return sc_git(root, "diff", "--name-only", "--no-renames", range, buf) == 0 &&
           cx_set_add_lines(&t->files, buf);
}

/* A worktree removed while the pool ran changes nothing, so its failed scan
 * counts as an empty one. */
static bool sc_vanished(struct sc_task *t)
{
    if (access(t->path, F_OK) == 0)
        return false;
    cx_set_free(&t->files);
    t->live = false;
    return true;
}

static void sc_drain(struct sc_pool *pool)
{
    char *buf = zcl_malloc(SC_BUF, "dev_cx.scan.buf");
    for (;;) {
        size_t i = atomic_fetch_add(&pool->next, 1);
        if (i >= pool->n)
            break;
        pool->tasks[i].ok = buf && (sc_scan_one(pool->root, &pool->tasks[i], buf, pool->pins) ||
                                    sc_vanished(&pool->tasks[i]));
    }
    free(buf);
}

#if !defined(_WIN32)
static void *sc_worker(void *arg)
{
    sc_drain(arg);
    return NULL;
}
#endif

static void sc_run_pool(struct sc_pool *pool)
{
#if !defined(_WIN32)
    pthread_t th[SC_THREADS];
    size_t started = 0;
    size_t want = pool->n < SC_THREADS ? pool->n : SC_THREADS;
    for (; started < want; started++)
        /* raw-pthread-ok: bounded scan workers, all joined below before return */
        if (pthread_create(&th[started], NULL, sc_worker, pool) != 0)
            break;
    if (started == 0)
        sc_drain(pool);
    for (size_t i = 0; i < started; i++)
        (void)pthread_join(th[i], NULL);
#else
    sc_drain(pool);
#endif
}

/* One `worktree <path>` porcelain block: the live, non-bare ones become
 * tasks. A directory that is gone cannot change anything. */
static bool sc_block_task(const char *block, size_t len, struct sc_task *t)
{
    bool bare = false, prunable = false;
    memset(t, 0, sizeof(*t));
    for (const char *p = block; p < block + len;) {
        size_t n = strcspn(p, "\n");
        if (strncmp(p, "worktree ", 9) == 0 && n - 9 < sizeof(t->path))
            snprintf(t->path, sizeof(t->path), "%.*s", (int)(n - 9), p + 9);
        else if (strncmp(p, "HEAD ", 5) == 0 && n - 5 < sizeof(t->head))
            snprintf(t->head, sizeof(t->head), "%.*s", (int)(n - 5), p + 5);
        bare = bare || (n == 4 && strncmp(p, "bare", 4) == 0);
        prunable = prunable || strncmp(p, "prunable", 8) == 0;
        p += n + 1;
    }
    return t->path[0] && !bare && !prunable && access(t->path, F_OK) == 0;
}

/* NULL with *count == 0 is an empty list only when *ok stays true. */
static struct sc_task *sc_tasks(const char *list, size_t *count, bool *ok)
{
    struct sc_task *tasks = NULL;
    size_t n = 0, cap = 0;
    for (const char *p = list; *p;) {
        const char *end = strstr(p, "\n\n");
        size_t len = end ? (size_t)(end - p) : strlen(p);
        struct sc_task t;
        if (n == cap) {
            cap = cap ? cap * 2 : 64;
            struct sc_task *grown = zcl_realloc(tasks, cap * sizeof(*tasks),
                                                "dev_cx.scan.tasks");
            if (!grown) {
                free(tasks);
                *count = 0;
                *ok = false;
                return NULL;
            }
            tasks = grown;
        }
        if (sc_block_task(p, len, &t))
            tasks[n++] = t;
        p += len + (end ? 2 : 0);
        while (*p == '\n')
            p++;
    }
    *count = n;
    return tasks;
}

static bool sc_merge(struct sc_pool *pool, struct cx_set *out,
                     struct cx_set *stale, char *why,
                     size_t why_cap)
{
    bool ok = true;
    for (size_t i = 0; i < pool->n; i++) {
        struct sc_task *t = &pool->tasks[i];
        if (!t->ok && ok)
            snprintf(why, why_cap, "%s", t->path);
        ok = ok && t->ok;
        for (size_t k = 0; ok && k < t->files.n; k++)
            ok = cx_set_add(t->live ? out : stale, t->files.v[k],
                            strlen(t->files.v[k]));
        cx_set_free(&t->files);
    }
    return ok;
}

bool cx_changed_files(const char *root, const struct cx_row *pins, size_t npins,
                      struct cx_set *out, struct cx_set *stale, char *why,
                      size_t why_cap)
{
    struct sc_pool pool;
    struct sc_paths paths = {0};
    char *buf = zcl_malloc(SC_BUF, "dev_cx.scan.list");
    bool ok = false, have = true;
    memset(&pool, 0, sizeof(pool));
    why[0] = '\0';
    if (!buf)
        return false;
    if (npins > 0) {
        paths.v = zcl_malloc(npins * sizeof(*paths.v), "dev_cx.scan.paths");
        have = paths.v != NULL;
        for (size_t i = 0; have && i < npins; i++)
            if (i == 0 || strcmp(pins[i].file, pins[i - 1].file) != 0)
                paths.v[paths.n++] = pins[i].file;
        pool.pins = &paths;
    }
    if (have && sc_git(root, "worktree", "list", "--porcelain", NULL, buf) == 0) {
        bool listed = true;
        pool.tasks = sc_tasks(buf, &pool.n, &listed);
        pool.root = root;
        if (listed) {
            sc_run_pool(&pool);
            ok = sc_merge(&pool, out, stale, why, why_cap);
        }
    }
    if (!ok && !why[0])
        snprintf(why, why_cap, "%s", root);
    free(pool.tasks);
    free(paths.v);
    free(buf);
    return ok;
}
