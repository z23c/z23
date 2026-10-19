/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The legacy seed copier: reflink first, then copy_file_range, then
 * read/write; a bounded worker pool; one fsync per file after the mtime is
 * set, so the data and the resume stamp reach disk together. */

#ifndef _WIN32

#define _GNU_SOURCE

#include "command/legacy_seed_priv.h"

#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

enum { LSEED_CHUNK = 1 << 20 };

struct pool {
    int srcroot;
    int dstroot;
    struct lseed_tree *tree;
    lseed_want_fn want;
    bool recopy_forced;
    atomic_int no_clone; /* latched by the first refused FICLONE of this phase */
    atomic_size_t next;
    atomic_int failed;
    atomic_uint_fast64_t copied, resumed, cloned, bytes, done;
    char why[256];
};

static bool lseed_rw_copy(int in, int out, uint64_t size)
{
    char *buf = zcl_malloc(LSEED_CHUNK, "lseed_chunk");
    uint64_t left = size;
    bool ok = buf != NULL;
    while (ok && left > 0) {
        ssize_t got = read(in, buf, left < LSEED_CHUNK ? left : LSEED_CHUNK);
        if (got <= 0) {
            ok = false;
            break;
        }
        for (ssize_t off = 0; ok && off < got;) {
            ssize_t put = write(out, buf + off, (size_t)(got - off));
            ok = put > 0;
            off += put > 0 ? put : 0;
        }
        left -= (uint64_t)got;
    }
    free(buf);
    return ok;
}

static bool lseed_cfr_copy(int in, int out, uint64_t size)
{
    uint64_t left = size;
    while (left > 0) {
        ssize_t n = copy_file_range(in, NULL, out, NULL, left, 0);
        if (n < 0 && (errno == EXDEV || errno == ENOSYS || errno == EINVAL ||
                      errno == EOPNOTSUPP)) {
            /* Offsets advanced with the copy; continue from there. */
            return lseed_rw_copy(in, out, left);
        }
        if (n <= 0)
            return false;
        left -= (uint64_t)n;
    }
    return true;
}

/* Returns 0 copied, 1 cloned, <0 failure. */
/* A filesystem that refuses FICLONE once refuses it for every file, so the
 * refusal is latched in no_clone and later files skip the ioctl. */
static int lseed_copy_data(int in, int out, uint64_t size, int mode,
                           atomic_int *no_clone)
{
    if (size == 0)
        return 0;
    if (mode == 0 && !atomic_load(no_clone)) {
        if (ioctl(out, FICLONE, in) == 0)
            return 1;
        if (errno == EOPNOTSUPP || errno == EXDEV || errno == EINVAL ||
            errno == ENOTTY)
            atomic_store(no_clone, 1);
    }
    if (mode == 1)
        return lseed_rw_copy(in, out, size) ? 0 : -1;
    return lseed_cfr_copy(in, out, size) ? 0 : -1;
}

static bool lseed_matches(int dstroot, const struct lseed_ent *e)
{
    struct stat st;
    return fstatat(dstroot, e->rel, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(st.st_mode) && (uint64_t)st.st_size == e->size &&
           st.st_mtim.tv_sec == e->mtime_s && st.st_mtim.tv_nsec == e->mtime_ns;
}

static bool lseed_finish_file(int out, const struct lseed_ent *e)
{
    struct timespec ts[2] = { { e->mtime_s, e->mtime_ns },
                              { e->mtime_s, e->mtime_ns } };
    return futimens(out, ts) == 0 && fsync(out) == 0;
}

static int lseed_copy_one(struct pool *p, const struct lseed_ent *e)
{
    struct lseed_hooks *h = lseed_hooks();
    if (h->fail_after_files > 0 &&
        atomic_fetch_add(&p->done, 1) >= (uint64_t)h->fail_after_files) {
        errno = EIO;
        return -1;
    }
    int in = lseed_open_beneath(p->srcroot, e->rel, O_RDONLY, 0);
    int out = in < 0 ? -1
                     : lseed_open_beneath(p->dstroot, e->rel,
                                          O_WRONLY | O_CREAT | O_TRUNC,
                                          e->mode & 0600);
    int how = -1;
    if (out >= 0)
        how = lseed_copy_data(in, out, e->size, h->copy_mode, &p->no_clone);
    bool ok = how >= 0 && lseed_finish_file(out, e);
    if (in >= 0)
        close(in);
    if (out >= 0)
        close(out);
    return ok ? how : -1;
}

static void lseed_record_fail(struct pool *p, const char *rel)
{
    int expected = 0;
    int saved = errno;
    if (atomic_compare_exchange_strong(&p->failed, &expected, 2)) {
        (void)snprintf(p->why, sizeof(p->why), "copy failed: %s (errno %d)", rel, saved);
        atomic_store(&p->failed, 1);
    }
}

static void *lseed_copy_worker(void *arg)
{
    struct pool *p = arg;
    for (;;) {
        size_t i = atomic_fetch_add(&p->next, 1);
        if (i >= p->tree->n || atomic_load(&p->failed))
            return NULL;
        const struct lseed_ent *e = &p->tree->e[i];
        if (!p->want(e))
            continue;
        if (!(p->recopy_forced && e->force) && lseed_matches(p->dstroot, e)) {
            atomic_fetch_add(&p->resumed, 1);
            continue;
        }
        int how = lseed_copy_one(p, e);
        if (how < 0) {
            lseed_record_fail(p, e->rel);
            return NULL;
        }
        atomic_fetch_add(&p->copied, 1);
        atomic_fetch_add(&p->cloned, (uint_fast64_t)how);
        atomic_fetch_add(&p->bytes, e->size);
    }
}

static bool lseed_make_dirs(int dstroot, const struct lseed_tree *t)
{
    for (size_t i = 0; i < t->n; i++) {
        if (!t->e[i].dir)
            continue;
        if (mkdirat(dstroot, t->e[i].rel, 0700) != 0 && errno != EEXIST)
            return false;
    }
    return true;
}

static int lseed_clamp_workers(int w)
{
    return w < 1 ? 1 : (w > LSEED_MAX_WORKERS ? LSEED_MAX_WORKERS : w);
}

/* Shared-memory state so forked workers and the parent see one pool. */
static void *lseed_shared_alloc(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

static void lseed_shared_free(void *p, size_t size)
{
    if (p)
        munmap(p, size);
}

/* Workers are forked processes (the tree forbids new thread sites). A child
 * that dies without finishing latches the pool failed. */
static void lseed_run_pool(void *(*fn)(void *), void *arg, atomic_int *failed,
                     int workers)
{
    pid_t kids[LSEED_MAX_WORKERS];
    int started = 0;
    for (int i = 1; i < lseed_clamp_workers(workers); i++) {
        pid_t pid = fork();
        if (pid == 0) {
            (void)fn(arg);
            _exit(0);
        }
        if (pid > 0)
            kids[started++] = pid;
    }
    (void)fn(arg);
    for (int i = 0; i < started; i++) {
        int st = 0;
        if (waitpid(kids[i], &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0)
            atomic_store(failed, 1);
    }
}

enum lseed_refusal lseed_copy_tree(int srcroot, int dstroot,
                                   struct lseed_tree *tree, lseed_want_fn want,
                                   bool recopy_forced, int workers,
                                   struct lseed_counts *counts,
                                   char *why, size_t why_cap)
{
    struct pool *p = lseed_shared_alloc(sizeof(*p));
    enum lseed_refusal rc = LSEED_OK;
    if (!p || !lseed_make_dirs(dstroot, tree)) {
        lseed_shared_free(p, sizeof(*p));
        (void)snprintf(why, why_cap, "cannot create target directories");
        return LSEED_COPY_FAILED;
    }
    p->srcroot = srcroot;
    p->dstroot = dstroot;
    p->tree = tree;
    p->want = want;
    p->recopy_forced = recopy_forced;
    lseed_run_pool(lseed_copy_worker, p, &p->failed, workers);
    counts->copied += p->copied;
    counts->resumed += p->resumed;
    counts->cloned += p->cloned;
    counts->bytes += p->bytes;
    if (p->failed) {
        (void)snprintf(why, why_cap, "%s", p->why[0] ? p->why : "a copy worker died");
        rc = LSEED_COPY_FAILED;
    }
    lseed_shared_free(p, sizeof(*p));
    return rc;
}

bool lseed_sync_dirs(int dstroot, const struct lseed_tree *tree)
{
    bool ok = fsync(dstroot) == 0;
    for (size_t i = 0; ok && i < tree->n; i++) {
        if (!tree->e[i].dir)
            continue;
        int fd = lseed_open_beneath(dstroot, tree->e[i].rel,
                                    O_RDONLY | O_DIRECTORY, 0);
        ok = fd >= 0 && fsync(fd) == 0;
        if (fd >= 0)
            close(fd);
    }
    return ok;
}

static int lseed_key_cmp(const void *key, const void *elem)
{
    return strcmp((const char *)key, ((const struct lseed_ent *)elem)->rel);
}

static bool lseed_in_tree(const struct lseed_tree *t, const char *rel)
{
    return t->n > 0 && bsearch(rel, t->e, t->n, sizeof(*t->e), lseed_key_cmp);
}

/* Unlink one target entry through its O_NOFOLLOW parent directory, so a
 * component swapped for a symlink after the walk is refused, never followed. */
static bool lseed_unlink_beneath(int dstroot, const char *rel, bool dir)
{
    char parent[LSEED_PATH_MAX];
    const char *slash = strrchr(rel, '/');
    if (!slash || (size_t)(slash - rel) >= sizeof(parent))
        return false;
    (void)snprintf(parent, sizeof(parent), "%.*s", (int)(slash - rel), rel);
    int pfd = lseed_open_beneath(dstroot, parent, O_RDONLY | O_DIRECTORY, 0);
    bool ok = pfd >= 0 && unlinkat(pfd, slash + 1, dir ? AT_REMOVEDIR : 0) == 0;
    if (pfd >= 0)
        close(pfd);
    return ok;
}

bool lseed_prune_extra(int dstroot, const struct lseed_tree *tree)
{
    /* Walk the target the same way the source was walked; an entry the
     * source no longer has (pruned or rotated since stage) is removed so the
     * seed is an exact image. Secret-named files are excluded from the
     * comparison walk too, but none were ever written. */
    struct lseed_tree have;
    char why[256];
    bool ok = true;
    if (lseed_walk(dstroot, &have, why, sizeof(why)) != LSEED_OK)
        return false;
    for (size_t i = have.n; i-- > 0;) {
        if (lseed_in_tree(tree, have.e[i].rel))
            continue;
        ok = lseed_unlink_beneath(dstroot, have.e[i].rel, have.e[i].dir) && ok;
    }
    lseed_tree_free(&have);
    return ok;
}

struct hash_pool {
    int dstroot;
    struct lseed_ent *ents;
    size_t n;
    atomic_size_t next;
    atomic_int failed;
};

static bool lseed_hash_file(int dstroot, struct lseed_ent *e)
{
    struct sha3_256_ctx ctx;
    unsigned char out[SHA3_256_OUTPUT_SIZE];
    int fd = lseed_open_beneath(dstroot, e->rel, O_RDONLY, 0);
    char *buf = zcl_malloc(LSEED_CHUNK, "lseed_chunk");
    bool ok = fd >= 0 && buf;
    sha3_256_init(&ctx);
    while (ok) {
        ssize_t got = read(fd, buf, LSEED_CHUNK);
        if (got < 0)
            ok = false;
        else if (got == 0)
            break;
        else
            sha3_256_write(&ctx, (const unsigned char *)buf, (size_t)got);
    }
    sha3_256_finalize(&ctx, out);
    for (size_t i = 0; ok && i < sizeof(out); i++)
        (void)snprintf(e->sha3 + 2 * i, 3, "%02x", out[i]);
    if (fd >= 0)
        close(fd);
    free(buf);
    return ok;
}

static void *lseed_hash_worker(void *arg)
{
    struct hash_pool *p = arg;
    for (;;) {
        size_t i = atomic_fetch_add(&p->next, 1);
        if (i >= p->n || atomic_load(&p->failed))
            return NULL;
        if (!p->ents[i].dir && !lseed_hash_file(p->dstroot, &p->ents[i]))
            atomic_store(&p->failed, 1);
    }
}

bool lseed_hash_tree(int dstroot, struct lseed_tree *tree, int workers)
{
    size_t bytes = sizeof(struct hash_pool) + tree->n * sizeof(struct lseed_ent);
    struct hash_pool *p = lseed_shared_alloc(bytes);
    bool ok = p != NULL;
    if (!ok)
        return false;
    p->ents = (struct lseed_ent *)(p + 1);
    memcpy(p->ents, tree->e, tree->n * sizeof(struct lseed_ent));
    p->n = tree->n;
    p->dstroot = dstroot;
    lseed_run_pool(lseed_hash_worker, p, &p->failed, workers);
    ok = !p->failed;
    if (ok)
        memcpy(tree->e, p->ents, tree->n * sizeof(struct lseed_ent));
    lseed_shared_free(p, bytes);
    return ok;
}

#else

typedef int lseed_posix_only_unused; /* empty on Windows */

#endif /* _WIN32 */
