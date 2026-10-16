/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Process-held, change-watched freshness verdict so a warm
 * codeindex_open skips the whole-checkout walk.
 *
 * A full walk that proves the store fresh is paired with an inotify watch
 * that was armed BEFORE that walk began over every directory the walk and the
 * depfile scan can read. A later open in the same process trusts the verdict
 * only while the watch has reported nothing, the watch is healthy, and the
 * store still carries the exact digests the walk verified. Any doubt (event,
 * overflow, ignored watch, add failure, cap, unsupported platform) falls
 * through to the existing full walk; this file never produces a fresh verdict
 * without either that walk or an unbroken watch. */

#define _GNU_SOURCE
#include "codeindex_priv.h"
#include "codeindex_merkle_internal.h"

#include "platform/file_watch_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <limits.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_TESTING
static _Atomic uint64_t g_fw_walks;
static _Atomic bool g_fw_force_fail;
uint64_t codeindex_test_freshness_walks(void)
{
    return atomic_load_explicit(&g_fw_walks, memory_order_relaxed);
}
void codeindex_test_force_watch_failure(bool fail)
{
    atomic_store_explicit(&g_fw_force_fail, fail, memory_order_relaxed);
}
void ci_test_note_freshness_walk(void)
{
    (void)atomic_fetch_add_explicit(&g_fw_walks, 1, memory_order_relaxed);
}
#endif

#if !defined(_WIN32)

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef IN_MODIFY
#define IN_MODIFY 0x00000002u
#endif

enum {
    FW_MAX_DIRS = 16384,
    FW_SLOTS = 4,
    FW_RETRY_OPENS = 16,
};

#define FW_MASK (IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | \
                 IN_CLOSE_WRITE | IN_MODIFY | IN_ATTRIB | \
                 IN_DELETE_SELF | IN_MOVE_SELF)

struct ci_fresh_watch {
    int fd;
    int root_wd;
    int dirs;
    char key[PATH_MAX];
};

struct fw_slot {
    bool used;
    bool disabled;
    int skips;
    uint8_t merkle[32];
    uint8_t dep[32];
    pid_t pid;                    /* arming process: a forked child misses */
    struct merkle_snapshot files; /* the leaves (path, stat key) the walk saw */
    struct ci_fresh_watch *watch;
    char key[PATH_MAX];
};

static pthread_mutex_t g_fw_lock = PTHREAD_MUTEX_INITIALIZER;
static struct fw_slot g_fw_slots[FW_SLOTS];
static unsigned g_fw_evict;

static bool fw_forced_failure(void)
{
#ifdef ZCL_TESTING
    return atomic_load_explicit(&g_fw_force_fail, memory_order_relaxed);
#else
    return false;
#endif
}

static void fw_free(struct ci_fresh_watch *w)
{
    if (!w) return;
    if (w->fd >= 0) close(w->fd);
    free(w);
}

/* ── arming: one directory-only pass using the walks' own prune rules ─── */

static bool fw_prune_source(const char *name)
{
    if (name[0] == '.') return true;
#define SOURCE_PRUNE_DIR(name_) if (strcmp(name, name_) == 0) return true;
#define SOURCE_INVENTORY_PRUNE_DIR(name_)
#include "codeindex/source_prune_dirs.def"
#undef SOURCE_INVENTORY_PRUNE_DIR
#undef SOURCE_PRUNE_DIR
    return strncmp(name, "test-tmp", 8) == 0;
}

static int fw_add(struct ci_fresh_watch *w, const char *path)
{
    if (w->dirs >= FW_MAX_DIRS || fw_forced_failure()) {
        errno = ENOSPC;
        return -1;
    }
    int wd = inotify_add_watch(w->fd, path, FW_MASK);
    if (wd >= 0) w->dirs++;
    return wd;
}

static bool fw_child_is_dir(const char *dir, const struct dirent *e, char *out,
                            size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", dir, e->d_name);
    if (n <= 0 || (size_t)n >= cap) return false;
    struct stat st;
    return lstat(out, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Watch `path` and every real subdirectory. `source` applies the source
 * walk's prune rules; the build tree is watched whole. */
static bool fw_tree(struct ci_fresh_watch *w, const char *path, bool source)
{
    if (fw_add(w, path) < 0) return false;
    DIR *d = opendir(path);
    if (!d) return false;
    bool ok = true;
    struct dirent *e;
    while (ok && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (source && fw_prune_source(e->d_name)) continue;
        if (e->d_type != DT_DIR && e->d_type != DT_UNKNOWN) continue;
        char child[PATH_MAX];
        if (fw_child_is_dir(path, e, child, sizeof(child)))
            ok = fw_tree(w, child, source);
    }
    closedir(d);
    return ok;
}

/* A top-level root follows a symlink exactly as the walks' opendir does. */
static bool fw_top(struct ci_fresh_watch *w, const char *root, const char *name,
                   bool source)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, name);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    struct stat st;
    if (stat(path, &st) != 0) return errno == ENOENT;
    if (!S_ISDIR(st.st_mode)) return false;
    return fw_tree(w, path, source);
}

static bool fw_arm_all(struct ci_fresh_watch *w, const char *root)
{
    w->root_wd = fw_add(w, root);
    if (w->root_wd < 0) return false;
    static const char *const roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!fw_top(w, root, roots[i], true)) return false;
    return fw_top(w, root, "build", false);
}

static bool fw_root_name_matters(const char *name)
{
    if (strcmp(name, "build") == 0) return true;
    static const char *const roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (strcmp(name, roots[i]) == 0) return true;
    return false;
}

/* ── draining ──────────────────────────────────────────────────────────── */

static bool fw_event_relevant(const struct ci_fresh_watch *w,
                              const struct inotify_event *ev)
{
    if (ev->mask & (IN_Q_OVERFLOW | IN_IGNORED)) return true;
    if (ev->wd == w->root_wd && ev->len > 0)
        return fw_root_name_matters(ev->name);
    return true;
}

static bool fw_buffer_quiet(const struct ci_fresh_watch *w, const char *buf,
                            size_t n)
{
    size_t off = 0;
    while (off + sizeof(struct inotify_event) <= n) {
        const struct inotify_event *ev =
            (const struct inotify_event *)(const void *)(buf + off);
        if (fw_event_relevant(w, ev)) return false;
        off += sizeof(*ev) + ev->len;
    }
    return true;
}

/* True only when the non-blocking fd is empty of relevant events. */
static bool fw_quiet(struct ci_fresh_watch *w)
{
    alignas(struct inotify_event) char buf[8192];
    for (;;) {
        ssize_t n = read(w->fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return errno == EAGAIN;
        if (n == 0 || !fw_buffer_quiet(w, buf, (size_t)n)) return false;
    }
}

/* ── table ─────────────────────────────────────────────────────────────── */

static struct fw_slot *fw_find(const char *key)
{
    for (int i = 0; i < FW_SLOTS; i++)
        if (g_fw_slots[i].used && strcmp(g_fw_slots[i].key, key) == 0)
            return &g_fw_slots[i];
    return NULL;
}

static void fw_clear(struct fw_slot *s)
{
    fw_free(s->watch);
    merkle_snapshot_free(&s->files);
    memset(s, 0, sizeof(*s));
}

static struct fw_slot *fw_take(const char *key)
{
    struct fw_slot *s = fw_find(key);
    if (s) return s;
    for (int i = 0; i < FW_SLOTS; i++)
        if (!g_fw_slots[i].used) return &g_fw_slots[i];
    s = &g_fw_slots[g_fw_evict++ % FW_SLOTS];
    fw_clear(s);
    return s;
}

static bool fw_stored_digests(struct codeindex *ci, uint8_t merkle[32],
                              uint8_t dep[32])
{
    char fmt[64], schema[64];
    size_t ml = 0, dl = 0, fl = 0, sl = 0;
    bool mf = false, df = false, ff = false, sf = false;
    if (!ci->store ||
        !ci_store_meta_get(ci->store, "source_merkle_root_sha3", merkle, 32,
                           &ml, &mf) ||
        !ci_store_meta_get(ci->store, "dep_stat_root_sha3", dep, 32, &dl, &df) ||
        !ci_store_meta_get(ci->store, "store_format", fmt, sizeof(fmt), &fl,
                           &ff) ||
        !ci_store_meta_get(ci->store, "ci_schema_version", schema,
                           sizeof(schema), &sl, &sf))
        return false;
    return mf && df && ml == 32 && dl == 32 && ff && sf &&
           fl == sizeof(CI_STORE_FORMAT) - 1 &&
           memcmp(fmt, CI_STORE_FORMAT, fl) == 0 &&
           sl == sizeof(CI_SCHEMA_VERSION) - 1 &&
           memcmp(schema, CI_SCHEMA_VERSION, sl) == 0;
}

/* ── per-file re-stat: what a directory watch cannot see ───────────────── */

/* A write through a hard link outside the watched tree, or through an
 * existing writable shared mapping, raises no directory event but always
 * moves the inode's size/mtime/ctime. The memo therefore also re-stats the
 * recorded leaves (no opendir/readdir) and trusts them only while each
 * (size, ino, dev, mtime ns, ctime ns) is the one the verifying walk saw. */
static bool fw_key_matches(const struct ci_merkle_stat_key *k,
                           const struct stat *st)
{
    return k->dev == (uint64_t)st->st_dev && k->ino == (uint64_t)st->st_ino &&
           k->size == (uint64_t)st->st_size &&
           k->mtime_sec == (uint64_t)st->st_mtim.tv_sec &&
           k->mtime_nsec == (uint64_t)st->st_mtim.tv_nsec &&
           k->ctime_sec == (uint64_t)st->st_ctim.tv_sec &&
           k->ctime_nsec == (uint64_t)st->st_ctim.tv_nsec;
}

/* A leaf stored with mtime_nsec == UINT64_MAX was written in the walk's own
 * second (racy-clean): its key proves nothing, so the walk re-reads its bytes
 * and so does the memo. */
static bool fw_racy_leaf_current(const char *root,
                                 const struct merkle_leaf_rec *leaf)
{
    struct ci_merkle_leaf now;
    bool found = false;
    return ci_merkle_hash_changed_leaf(root, leaf->path, &now, &found) &&
           found && memcmp(now.digest.bytes, leaf->digest.bytes, 32) == 0;
}

static bool fw_leaf_current(int dfd, const char *root,
                            const struct merkle_leaf_rec *leaf)
{
    struct stat st;
    if (fstatat(dfd, leaf->path, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(st.st_mode))
        return false;
    if (leaf->key.mtime_nsec == UINT64_MAX)
        return fw_racy_leaf_current(root, leaf);
    return fw_key_matches(&leaf->key, &st);
}

static bool fw_files_current(const char *root, const struct merkle_snapshot *f)
{
    int dfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return false;
    bool ok = f->nleaves > 0;
    for (uint32_t i = 0; ok && i < f->nleaves; i++)
        ok = fw_leaf_current(dfd, root, &f->leaves[i]);
    close(dfd);
    return ok;
}

/* Take the sealed snapshot's leaves, but only when its root is the digest
 * the walk just proved fresh; anything else is not recorded (stays a walk). */
static bool fw_capture_files(const char *key, const struct codeindex *ci,
                             struct merkle_snapshot *out)
{
    bool found = false;
    memset(out, 0, sizeof(*out));
    if (!merkle_snapshot_load(key, out, &found)) return false;
    const struct merkle_node_rec *root =
        found ? merkle_find_node(out->nodes, out->nnodes, "") : NULL;
    bool ok = root && memcmp(root->digest.bytes, ci->fresh_merkle, 32) == 0;
    free(out->nodes);
    out->nodes = NULL;
    out->nnodes = 0;
    if (!ok) merkle_snapshot_free(out);
    return ok;
}

bool ci_fresh_memo_hit(struct codeindex *ci)
{
    char key[PATH_MAX];
    uint8_t merkle[32], dep[32];
    if (!ci || !realpath(ci->root, key) || !fw_stored_digests(ci, merkle, dep))
        return false;
    pthread_mutex_lock(&g_fw_lock);
    struct fw_slot *s = fw_find(key);
    bool hit = false;
    if (s && !s->disabled) {
        if (s->pid != getpid() || !fw_quiet(s->watch) ||
            !fw_files_current(key, &s->files))
            fw_clear(s);
        else
            hit = memcmp(s->merkle, merkle, 32) == 0 &&
                  memcmp(s->dep, dep, 32) == 0;
    }
    pthread_mutex_unlock(&g_fw_lock);
    return hit;
}

static void fw_note_disabled(const char *key)
{
    pthread_mutex_lock(&g_fw_lock);
    struct fw_slot *s = fw_take(key);
    fw_clear(s);
    s->used = true;
    s->disabled = true;
    snprintf(s->key, sizeof(s->key), "%s", key);
    pthread_mutex_unlock(&g_fw_lock);
}

static bool fw_may_arm(const char *key)
{
    pthread_mutex_lock(&g_fw_lock);
    struct fw_slot *s = fw_find(key);
    bool ok = !s || !s->disabled || ++s->skips >= FW_RETRY_OPENS;
    pthread_mutex_unlock(&g_fw_lock);
    return ok;
}

struct ci_fresh_watch *ci_fresh_arm(const char *root)
{
    char key[PATH_MAX];
    if (!root || !realpath(root, key) || !fw_may_arm(key)) return NULL;
    struct ci_fresh_watch *w = zcl_calloc(1, sizeof(*w), "ci_fresh_watch");
    if (!w) return NULL;
    snprintf(w->key, sizeof(w->key), "%s", key);
    w->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    w->root_wd = -1;
    if (w->fd >= 0 && fw_arm_all(w, root)) return w;
    LOG_WARN("codeindex", "freshness watch unavailable (%s): walking every open",
             strerror(errno));
    fw_free(w);
    fw_note_disabled(key);
    return NULL;
}

void ci_fresh_finish(struct ci_fresh_watch *w, struct codeindex *ci, bool fresh)
{
    if (!w) return;
    pthread_mutex_lock(&g_fw_lock);
    struct merkle_snapshot files;
    if (fresh && fw_quiet(w) && fw_capture_files(w->key, ci, &files)) {
        struct fw_slot *s = fw_take(w->key);
        fw_clear(s);
        s->used = true;
        s->pid = getpid();
        s->files = files;
        memcpy(s->merkle, ci->fresh_merkle, 32);
        memcpy(s->dep, ci->fresh_dep, 32);
        snprintf(s->key, sizeof(s->key), "%s", w->key);
        s->watch = w;
        w = NULL;
    }
    pthread_mutex_unlock(&g_fw_lock);
    fw_free(w);
}

#endif
