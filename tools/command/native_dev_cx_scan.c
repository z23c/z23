/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: which files do the worktrees of this repository change against
 *          origin/main. Per worktree one `git status` (staged, unstaged and
 *          untracked in a single pass) plus one object-only merge-base diff
 *          of its HEAD run in the root. A busy host has hundreds of
 *          worktrees and a cold one costs seconds, so they are scanned by a
 *          small pool. A worktree that cannot be read fails the whole scan. */

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

struct sc_task {
    char path[ZCL_CX_PATH_MAX];
    char head[80];
    struct cx_set files;
    bool ok;
};

struct sc_pool {
    struct sc_task *tasks;
    size_t n;
    atomic_size_t next;
    const char *root;
};

static int sc_git(const char *dir, const char *a, const char *b, const char *c,
                  const char *d, char *buf)
{
    const char *argv[] = {"git", "-c", "core.quotepath=off", a, b, c, d, NULL};
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

static bool sc_scan_one(const char *root, struct sc_task *t, char *buf)
{
    char range[160];
    if (sc_git(t->path, "status", "--porcelain", "--no-renames", "-uall",
               buf) != 0 ||
        !sc_add_status(&t->files, buf))
        return false;
    if (!t->head[0])
        return true;
    if (snprintf(range, sizeof(range), "origin/main...%s", t->head) >=
        (int)sizeof(range))
        return false;
    return sc_git(root, "diff", "--name-only", "--no-renames", range, buf) == 0 &&
           cx_set_add_lines(&t->files, buf);
}

static void sc_drain(struct sc_pool *pool)
{
    char *buf = zcl_malloc(SC_BUF, "dev_cx.scan.buf");
    for (;;) {
        size_t i = atomic_fetch_add(&pool->next, 1);
        if (i >= pool->n)
            break;
        pool->tasks[i].ok = buf && sc_scan_one(pool->root, &pool->tasks[i], buf);
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

static bool sc_merge(struct sc_pool *pool, struct cx_set *out, char *why,
                     size_t why_cap)
{
    bool ok = true;
    for (size_t i = 0; i < pool->n; i++) {
        struct sc_task *t = &pool->tasks[i];
        if (!t->ok && ok)
            snprintf(why, why_cap, "%s", t->path);
        ok = ok && t->ok;
        for (size_t k = 0; ok && k < t->files.n; k++)
            ok = cx_set_add(out, t->files.v[k], strlen(t->files.v[k]));
        cx_set_free(&t->files);
    }
    return ok;
}

bool cx_changed_files(const char *root, struct cx_set *out, char *why,
                      size_t why_cap)
{
    struct sc_pool pool;
    char *buf = zcl_malloc(SC_BUF, "dev_cx.scan.list");
    bool ok = false;
    memset(&pool, 0, sizeof(pool));
    why[0] = '\0';
    if (!buf)
        return false;
    if (sc_git(root, "worktree", "list", "--porcelain", NULL, buf) == 0) {
        bool listed = true;
        pool.tasks = sc_tasks(buf, &pool.n, &listed);
        pool.root = root;
        if (listed) {
            sc_run_pool(&pool);
            ok = sc_merge(&pool, out, why, why_cap);
        }
    }
    if (!ok && !why[0])
        snprintf(why, why_cap, "%s", root);
    free(pool.tasks);
    free(buf);
    return ok;
}
