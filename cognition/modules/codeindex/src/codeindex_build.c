/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_build — deterministic full rebuild + staleness.
 *
 * Enumerate the source set in a fixed sorted order, scan every file, fold in
 * include edges from build depfiles, write the group hierarchy, all into a
 * unique same-directory staging store, then atomically rename it over
 * index.kv and stamp meta.source_root_sha3. A cross-process lock coalesces
 * cold opens; an old reader keeps its already-open inode across publication.
 * A partial build never corrupts the live store. "Recompute, never repair." */

#include "codeindex_priv.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_merkle.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
/* ── source enumeration ─────────────────────────────────────────────── */
struct strvec {
    char  **v;
    size_t  n;
    size_t  cap;
};

static bool sv_push(struct strvec *s, const char *str)
{
    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 256;
        char **nv = zcl_realloc(s->v, ncap * sizeof(*nv), "ci_strvec");
        if (!nv) return false;
        s->v = nv; s->cap = ncap;
    }
    s->v[s->n] = zcl_strdup(str, "ci_relpath");
    if (!s->v[s->n]) return false;
    s->n++;
    return true;
}

static void sv_free(struct strvec *s)
{
    for (size_t i = 0; i < s->n; i++) free(s->v[i]);
    free(s->v);
    s->v = NULL; s->n = s->cap = 0;
}

static int sv_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* An X-macro registry (`*.def`) is `#include`d exactly like a header and
 * changes a translation unit's behavior exactly like one, but it holds no C
 * declarations. It is admitted here as an INCLUDE-GRAPH NODE only: it gets a
 * files row (so its content is bound into the source-tree stamp, and so a
 * reverse-include query can name it) and it is never handed to the C scanner,
 * so it contributes no symbols and no call edges. Before this it was outside
 * the enumerated universe entirely, which is why editing the file CLAUDE.md
 * tells every agent to edit — a diagnostics_dumpers_<domain>.def row — moved
 * neither the index stamp nor any impact answer. */
static bool ci_is_registry_name(const char *name)
{
    size_t n = strlen(name);
    return n >= 4 && strcmp(name + n - 4, ".def") == 0;
}

bool ci_path_is_registry(const char *relpath)
{
    return relpath && relpath[0] && ci_is_registry_name(relpath);
}

static bool is_source_name(const char *name)
{
    size_t n = strlen(name);
    if (n >= 2 && name[n - 2] == '.' && name[n - 1] == 'c') return true;
    if (n >= 2 && name[n - 2] == '.' && name[n - 1] == 'h') return true;
    return ci_is_registry_name(name);
}

/* pruned directory names — never descend these */
static bool prune_dir(const char *name)
{
#define SOURCE_PRUNE_DIR(name_) if (strcmp(name, name_) == 0) return true;
#define SOURCE_INVENTORY_PRUNE_DIR(name_)
#include "codeindex/source_prune_dirs.def"
#undef SOURCE_INVENTORY_PRUNE_DIR
#undef SOURCE_PRUNE_DIR
    return strncmp(name, "test-tmp", 8) == 0;
}

/* Recursively collect .c/.h under <root>/<reldir> into vec. Missing optional
 * roots are empty; permission, I/O, and allocation failures are hard errors. */
static bool collect_dir(const char *root, const char *reldir,
                        struct strvec *vec)
{
    char full[CI_PATH_MAX];
    if (reldir[0])
        snprintf(full, sizeof(full), "%s/%s", root, reldir);
    else
        snprintf(full, sizeof(full), "%s", root);
    DIR *d = opendir(full);
    if (!d) return errno == ENOENT;
    bool ok = true;
    struct dirent *e;
    while (ok && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char child[CI_PATH_MAX];
        int n;
        if (reldir[0])
            n = snprintf(child, sizeof(child), "%s/%s", reldir, e->d_name);
        else
            n = snprintf(child, sizeof(child), "%s", e->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            ok = false;
            break;
        }
        char cfull[CI_PATH_MAX];
        int cn = snprintf(cfull, sizeof(cfull), "%s/%s", root, child);
        if (cn <= 0 || (size_t)cn >= sizeof(cfull)) {
            ok = false;
            break;
        }
        struct stat st;
        if (lstat(cfull, &st) != 0) {
            ok = false;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            if (prune_dir(e->d_name)) continue;
            ok = collect_dir(root, child, vec);
        } else if (S_ISREG(st.st_mode) && is_source_name(e->d_name)) {
            ok = sv_push(vec, child);
        }
    }
    int saved = errno;
    if (closedir(d) != 0 && ok) {
        ok = false;
        saved = errno;
    }
    if (!ok) errno = saved ? saved : EIO;
    return ok;
}

bool ci_enumerate_sources(const char *root, ci_enum_cb cb, void *user)
{
    if (!root || !cb) LOG_FAIL("codeindex", "null arg to enumerate");

    struct strvec vec = {0};

    static const char *const roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!collect_dir(root, roots[i], &vec)) goto collect_failed;

    qsort(vec.v, vec.n, sizeof(vec.v[0]), sv_cmp);

    bool ok = true;
    for (size_t i = 0; i < vec.n && ok; i++) {
        /* de-dup exact repeats (a dir listed twice can't happen here, but be safe) */
        if (i > 0 && strcmp(vec.v[i], vec.v[i - 1]) == 0) continue;
        char full[CI_PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", root, vec.v[i]);
        struct stat st;
        if (lstat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
            ok = false;
            break;
        }
        if (!cb(vec.v[i], &st, user))
            ok = false;
    }
    sv_free(&vec);
    return ok;

collect_failed:
    sv_free(&vec);
    LOG_FAIL("codeindex", "source enumeration failed: %s", strerror(errno));
}

/* ── staleness stamp: exact content-bound source-tree digest ────────── */

struct stamp_ctx {
    const char *root;
    struct sha3_256_ctx sha;
    struct sha3_256_ctx stat_sha;
    bool include_stat;
};

static void sha_write_u64le(struct sha3_256_ctx *sha, uint64_t value)
{
    unsigned char encoded[8];
    for (unsigned int i = 0; i < sizeof(encoded); i++)
        encoded[i] = (unsigned char)((value >> (i * 8U)) & 0xffU);
    sha3_256_write(sha, encoded, sizeof(encoded));
}

static void source_stat_root_init(struct sha3_256_ctx *sha)
{
    static const char domain[] = "zcl.codeindex.source_stat_root.v1";
    sha3_256_init(sha);
    sha3_256_write(sha, (const unsigned char *)domain, sizeof(domain));
}

static void source_stat_root_add(struct sha3_256_ctx *sha,
                                 const char *relpath, const struct stat *st)
{
    sha3_256_write(sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    sha_write_u64le(sha, (uint64_t)st->st_dev);
    sha_write_u64le(sha, (uint64_t)st->st_ino);
    sha_write_u64le(sha, (uint64_t)st->st_size);
    sha_write_u64le(sha, (uint64_t)st->st_mtim.tv_sec);
    sha_write_u64le(sha, (uint64_t)st->st_mtim.tv_nsec);
    sha_write_u64le(sha, (uint64_t)st->st_ctim.tv_sec);
    sha_write_u64le(sha, (uint64_t)st->st_ctim.tv_nsec);
}

static bool source_file_sha3(const char *root, const char *relpath,
                             uint8_t out[32], struct stat *out_st)
{
    char path[CI_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, relpath);
    if (n <= 0 || (size_t)n >= sizeof(path))
        LOG_FAIL("codeindex", "source path too long: %s", relpath);

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        LOG_FAIL("codeindex", "open source for digest failed path=%s: %s",
                 relpath, strerror(errno));
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        int saved = errno;
        close(fd);
        LOG_FAIL("codeindex", "stream source for digest failed path=%s: %s",
                 relpath, strerror(saved));
    }

    struct stat before, after;
    if (fstat(fileno(f), &before) != 0 || !S_ISREG(before.st_mode)) {
        int saved = errno ? errno : EINVAL;
        fclose(f);
        LOG_FAIL("codeindex", "inspect source for digest failed path=%s: %s",
                 relpath, strerror(saved));
    }

    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    /* Match ci_scan_file()'s canonical per-file content hash exactly. */
    static const uint8_t content_tag = 0x02;
    sha3_256_write(&sha, &content_tag, 1);
    unsigned char buf[64 * 1024];
    size_t nr;
    while ((nr = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha3_256_write(&sha, buf, nr);
        ci_test_note_exact_bytes((uint64_t)nr);
    }
    bool ok = !ferror(f) && fstat(fileno(f), &after) == 0 &&
              S_ISREG(after.st_mode) && before.st_dev == after.st_dev &&
              before.st_ino == after.st_ino && before.st_size == after.st_size &&
              before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
              before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
              before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
              before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
    int close_rc = fclose(f);
    if (!ok || close_rc != 0)
        LOG_FAIL("codeindex", "read source for digest failed path=%s",
                 relpath);
    sha3_256_finalize(&sha, out);
    if (out_st) *out_st = after;
    return true;
}

static bool stamp_cb(const char *relpath, const struct stat *st, void *user)
{
    struct stamp_ctx *c = user;
    uint8_t content_sha3[32];
    struct stat opened_st;
    if (!source_file_sha3(c->root, relpath, content_sha3, &opened_st))
        return false;
    ci_source_root_add(&c->sha, relpath, content_sha3);
    if (c->include_stat)
        source_stat_root_add(&c->stat_sha, relpath, &opened_st);
    (void)st;
    return true;
}

static bool source_stat_cb(const char *relpath, const struct stat *st,
                           void *user)
{
    struct sha3_256_ctx *sha = user;
    source_stat_root_add(sha, relpath, st);
    return true;
}

bool ci_source_roots_sha3(const char *root, uint8_t exact_out[32],
                          uint8_t stat_out[32])
{
    if (!root || !exact_out || !stat_out)
        LOG_FAIL("codeindex", "null arg to source_roots_sha3");
    struct stamp_ctx c;
    memset(&c, 0, sizeof(c));
    c.root = root;
    c.include_stat = true;
    ci_source_root_init(&c.sha);
    source_stat_root_init(&c.stat_sha);
    if (!ci_enumerate_sources(root, stamp_cb, &c))
        LOG_FAIL("codeindex", "enumerate for source roots failed");
    sha3_256_finalize(&c.sha, exact_out);
    sha3_256_finalize(&c.stat_sha, stat_out);
    return true;
}

bool ci_source_stat_root_sha3(const char *root, uint8_t out[32])
{
    if (!root || !out)
        LOG_FAIL("codeindex", "null arg to source_stat_root_sha3");
    struct sha3_256_ctx sha;
    source_stat_root_init(&sha);
    if (!ci_enumerate_sources(root, source_stat_cb, &sha))
        LOG_FAIL("codeindex", "enumerate for source stat root failed");
    sha3_256_finalize(&sha, out);
    return true;
}

/* ── rebuild publication ────────────────────────────────────────────── */

static _Atomic uint64_t g_stage_sequence = 1;

struct stage_identity {
    dev_t dev;
    ino_t ino;
};

#ifdef ZCL_TESTING
static _Atomic int g_test_crash_point = CODEINDEX_TEST_CRASH_NONE;
static _Atomic int g_test_stage_tamper = CODEINDEX_TEST_STAGE_TAMPER_NONE;
static _Atomic bool g_test_remove_lock_directory = false;
static _Atomic uint64_t g_test_exact_bytes_read = 0;
static char g_test_stage_victim[CI_PATH_MAX];

void ci_test_note_exact_bytes(uint64_t bytes)
{
    (void)atomic_fetch_add_explicit(&g_test_exact_bytes_read, bytes,
                                    memory_order_relaxed);
}

void codeindex_test_reset_exact_bytes_read(void)
{
    atomic_store_explicit(&g_test_exact_bytes_read, 0, memory_order_relaxed);
}

uint64_t codeindex_test_exact_bytes_read(void)
{
    return atomic_load_explicit(&g_test_exact_bytes_read,
                                memory_order_relaxed);
}

void codeindex_test_set_crash_point(enum codeindex_test_crash_point point)
{
    atomic_store_explicit(&g_test_crash_point, (int)point,
                          memory_order_relaxed);
}

void codeindex_test_set_stage_tamper(
    enum codeindex_test_stage_tamper tamper, const char *victim_path)
{
    (void)snprintf(g_test_stage_victim, sizeof(g_test_stage_victim), "%s",
                   victim_path ? victim_path : "");
    atomic_store_explicit(&g_test_stage_tamper, (int)tamper,
                          memory_order_relaxed);
}

void codeindex_test_remove_lock_directory_once(void)
{
    atomic_store_explicit(&g_test_remove_lock_directory, true,
                          memory_order_relaxed);
}

static void codeindex_test_maybe_remove_lock_directory(const char *dir)
{
    if (atomic_exchange_explicit(&g_test_remove_lock_directory, false,
                                 memory_order_relaxed))
        (void)rmdir(dir);
}

static bool codeindex_test_maybe_tamper_stage(int dirfd, const char *name)
{
    int tamper = atomic_exchange_explicit(
        &g_test_stage_tamper, CODEINDEX_TEST_STAGE_TAMPER_NONE,
        memory_order_relaxed);
    if (tamper == CODEINDEX_TEST_STAGE_TAMPER_NONE)
        return true;
    if (!name || !name[0] || !g_test_stage_victim[0])
        return false;
    if (unlinkat(dirfd, name, 0) != 0)
        return false;
    if (tamper == CODEINDEX_TEST_STAGE_TAMPER_SYMLINK)
        return symlinkat(g_test_stage_victim, dirfd, name) == 0;
    if (tamper == CODEINDEX_TEST_STAGE_TAMPER_HARDLINK)
        return linkat(AT_FDCWD, g_test_stage_victim, dirfd, name, 0) == 0;
    return false;
}

static void codeindex_test_maybe_crash(enum codeindex_test_crash_point point)
{
    if (atomic_load_explicit(&g_test_crash_point, memory_order_relaxed) ==
        (int)point) {
        (void)kill(getpid(), SIGKILL);
        _exit(128 + SIGKILL);
    }
}
#else
#define codeindex_test_maybe_crash(...) ((void)0)
#define codeindex_test_maybe_tamper_stage(...) true
#define codeindex_test_maybe_remove_lock_directory(...) ((void)0)
#endif

static bool rebuild_lock_open(const char *root, char dir[CI_PATH_MAX],
                              int *out_dirfd, int *out_lockfd)
{
    *out_dirfd = -1;
    *out_lockfd = -1;
    int n = snprintf(dir, CI_PATH_MAX, "%s/.codeindex", root);
    if (n <= 0 || n >= CI_PATH_MAX)
        LOG_FAIL("codeindex", "index directory path too long");
    enum { LOCK_DIRECTORY_ATTEMPTS = 8 };
    for (int attempt = 0; attempt < LOCK_DIRECTORY_ATTEMPTS; attempt++) {
        if (mkdir(dir, 0755) != 0 && errno != EEXIST)
            LOG_FAIL("codeindex", "create index directory failed: %s",
                     strerror(errno));

        int dirfd = open(dir,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dirfd < 0) {
            int saved = errno;
            if (saved == ENOENT && attempt + 1 < LOCK_DIRECTORY_ATTEMPTS) {
                platform_sleep_ms(1);
                continue;
            }
            LOG_FAIL("codeindex", "open index directory failed: %s",
                     strerror(saved));
        }
        struct stat dir_st;
        if (fstat(dirfd, &dir_st) != 0 || !S_ISDIR(dir_st.st_mode) ||
            dir_st.st_uid != geteuid() ||
            (dir_st.st_mode & (S_IWGRP | S_IWOTH))) {
            close(dirfd);
            LOG_FAIL("codeindex",
                     "index directory must be owner-controlled and not writable by group/other");
        }

        codeindex_test_maybe_remove_lock_directory(dir);
        int lockfd = openat(dirfd, "rebuild.lock",
                            O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (lockfd < 0) {
            int saved = errno;
            close(dirfd);
            /* An opened directory may be unlinked before O_CREAT reaches it.
             * Reacquire by pathname, then revalidate ownership and mode; the
             * stale descriptor is never used for publication. */
            if (saved == ENOENT && attempt + 1 < LOCK_DIRECTORY_ATTEMPTS) {
                platform_sleep_ms(1);
                continue;
            }
            LOG_FAIL("codeindex", "open rebuild lock failed: %s",
                     strerror(saved));
        }
        if (flock(lockfd, LOCK_EX) != 0) {
            int saved = errno;
            close(lockfd);
            close(dirfd);
            LOG_FAIL("codeindex", "acquire rebuild lock failed: %s",
                     strerror(saved));
        }
        *out_dirfd = dirfd;
        *out_lockfd = lockfd;
        return true;
    }
    LOG_FAIL("codeindex",
             "index directory changed repeatedly during lock acquisition");
}

static bool cleanup_orphan_stages(int dirfd)
{
    int scanfd = dup(dirfd);
    if (scanfd < 0)
        LOG_FAIL("codeindex", "dup index directory failed: %s",
                 strerror(errno));
    DIR *dir = fdopendir(scanfd);
    if (!dir) {
        int saved = errno;
        close(scanfd);
        LOG_FAIL("codeindex", "scan index directory failed: %s",
                 strerror(saved));
    }

    bool ok = true;
    struct dirent *ent;
    static const char prefix[] = "index.kv.tmp.";
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, prefix, sizeof(prefix) - 1) != 0)
            continue;
        if (unlinkat(dirfd, ent->d_name, 0) != 0 && errno != ENOENT) {
            ok = false;
            break;
        }
    }
    closedir(dir);
    if (!ok)
        LOG_FAIL("codeindex", "remove orphan staging store failed: %s",
                 strerror(errno));
    return true;
}

static bool create_unique_stage(int dirfd, char name[128],
                                struct stage_identity *identity,
                                int *out_fd)
{
    if (!identity || !out_fd)
        LOG_FAIL("codeindex", "null staging identity/fd");
    *out_fd = -1;
    for (unsigned int attempt = 0; attempt < 128; attempt++) {
        uint64_t seq = atomic_fetch_add_explicit(&g_stage_sequence, 1,
                                                 memory_order_relaxed);
        int n = snprintf(name, 128, "index.kv.tmp.%ld.%llu",
                         (long)getpid(), (unsigned long long)seq);
        if (n <= 0 || n >= 128)
            LOG_FAIL("codeindex", "staging name overflow");
        int fd = openat(dirfd, name,
                        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0600);
        if (fd >= 0) {
            struct stat st;
            if (fstat(fd, &st) != 0) {
                int saved = errno;
                close(fd);
                unlinkat(dirfd, name, 0);
                LOG_FAIL("codeindex", "inspect staging inode failed: %s",
                         strerror(saved));
            }
            if (!S_ISREG(st.st_mode) || st.st_nlink != 1) {
                close(fd);
                unlinkat(dirfd, name, 0);
                LOG_FAIL("codeindex", "staging inode is not private regular");
            }
            identity->dev = st.st_dev;
            identity->ino = st.st_ino;
            *out_fd = fd;
            return true;
        }
        if (errno != EEXIST)
            LOG_FAIL("codeindex", "create staging inode failed: %s",
                     strerror(errno));
    }
    LOG_FAIL("codeindex", "could not allocate unique staging name");
}

static void rebuild_lock_close(int dirfd, int lockfd)
{
    if (lockfd >= 0) {
        (void)flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    if (dirfd >= 0) close(dirfd);
}

static bool remove_legacy_sidecars(int dirfd)
{
    static const char *const names[] = { "index.kv-wal", "index.kv-shm" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        /* unlinkat removes the directory entry itself and never follows a
         * substituted symlink. Any already-open legacy reader retains its
         * inode, while new immutable readers cannot associate the old name. */
        if (unlinkat(dirfd, names[i], 0) != 0 && errno != ENOENT)
            LOG_FAIL("codeindex", "remove legacy sidecar %s failed: %s",
                     names[i], strerror(errno));
    }
    return true;
}

static bool codeindex_rebuild_internal(struct codeindex *ci,
                                       bool coalesce_if_fresh)
{
    if (!ci) LOG_FAIL("codeindex", "null ci to rebuild");

    char dir[CI_PATH_MAX];
    int dirfd = -1, lockfd = -1;
    if (!rebuild_lock_open(ci->root, dir, &dirfd, &lockfd))
        return false;

    /* Whole-rebuild wall clock for the cold-build self-receipt; only the
     * full-build branch seals it (ci_build_store_memory). */
    const int64_t build_start_ms = platform_time_monotonic_ms();

    const char *failure = "unknown rebuild failure";
    bool success = false;
    char stage_name[128] = "";
    struct stage_identity stage_identity = {0};
    int stagefd = -1;
    struct ci_store *st = NULL;
    struct ci_merkle *merkle = NULL;
    struct ci_merkle_leaf *changed = NULL;
    struct ci_merkle_leaf *current_leaves = NULL;
    int changed_count = 0;
    bool incremental = false;
    uint8_t current_dep_stat[32] = {0};

    if (!cleanup_orphan_stages(dirfd)) {
        failure = "orphan staging cleanup failed";
        goto out;
    }

    /* A second cold opener may have waited while the first one published.
     * Reopen the pathname under the lock and adopt that exact fresh store
     * instead of redundantly rebuilding it. Explicit codeindex_rebuild()
     * passes false and remains a forced deterministic recompute. */
    if (coalesce_if_fresh && !ci->store) {
        struct ci_store *fresh = ci_store_open(ci->root);
        if (fresh) {
            bool stale = true;
            struct codeindex fresh_view = {.store = fresh};
            (void)snprintf(fresh_view.root, sizeof(fresh_view.root), "%s",
                           ci->root);
            bool checked = codeindex_is_stale(&fresh_view, &stale);
            if (checked && !stale) {
                struct ci_store *old = ci->store;
                ci->store = fresh;
                if (old) ci_store_close(old);
                success = true;
                goto out;
            }
            /* Missing/corrupt/stale derived state is rebuilt from source.
             * It is never repaired or accepted as partial authority. */
            ci_store_close(fresh);
            ci_merkle_free(fresh_view.pending_merkle);
        }
    }

    /* The Merkle snapshot is the changed-file oracle. It reads bytes only for
     * cache keys that moved. Inventory drift, an absent snapshot, depfile
     * churn, or a snapshot advanced independently of this store all take the
     * existing deterministic cold path. */
    struct ci_merkle_cost merkle_cost = {0};
    if (ci->pending_merkle) {
        merkle = ci->pending_merkle;
        merkle_cost.snapshot_used = ci->pending_merkle_snapshot_used;
        merkle_cost.full_rescan = ci->pending_merkle_full_rescan;
        merkle_cost.inventory_changed = ci->pending_merkle_inventory_changed;
        ci->pending_merkle = NULL;
        ci->pending_merkle_snapshot_used = false;
        ci->pending_merkle_full_rescan = false;
        ci->pending_merkle_inventory_changed = false;
    } else {
        merkle = ci_merkle_refresh_reconciled(ci->root, &merkle_cost);
    }
    struct ci_merkle_node merkle_root;
    if (!merkle || !ci_merkle_root(merkle, &merkle_root) ||
        !ci_deps_stat_root_sha3(ci->root, current_dep_stat)) {
        failure = "incremental inventory refresh failed";
        goto out;
    }
    size_t dep_len = 0;
    bool dep_found = false;
    uint8_t stored_dep_stat[32];
    bool dep_unchanged = ci->store &&
        ci_store_meta_get(ci->store, "dep_stat_root_sha3", stored_dep_stat,
                          sizeof(stored_dep_stat), &dep_len, &dep_found) &&
        dep_found && dep_len == sizeof(stored_dep_stat) &&
        memcmp(stored_dep_stat, current_dep_stat, 32) == 0;
    char stored_format[64], stored_schema[64];
    size_t format_len = 0, schema_len = 0;
    bool format_found = false, schema_found = false;
    bool generation_current = ci->store &&
        ci_store_meta_get(ci->store, "store_format", stored_format,
                          sizeof(stored_format), &format_len, &format_found) &&
        ci_store_meta_get(ci->store, "ci_schema_version", stored_schema,
                          sizeof(stored_schema), &schema_len, &schema_found) &&
        format_found && format_len == sizeof(CI_STORE_FORMAT) - 1 &&
        memcmp(stored_format, CI_STORE_FORMAT, sizeof(CI_STORE_FORMAT) - 1) == 0 &&
        schema_found && schema_len == sizeof(CI_SCHEMA_VERSION) - 1 &&
        memcmp(stored_schema, CI_SCHEMA_VERSION,
               sizeof(CI_SCHEMA_VERSION) - 1) == 0;
    int current_count = ci_merkle_leaves(merkle, NULL, 0);
    bool inventory_same = false;
    if (coalesce_if_fresh && current_count > 0 && generation_current &&
        merkle_cost.snapshot_used &&
        !merkle_cost.full_rescan && !merkle_cost.inventory_changed &&
        dep_unchanged) {
        current_leaves = zcl_calloc((size_t)current_count,
                                    sizeof(*current_leaves),
                                    "ci_incremental_current");
        changed = zcl_calloc((size_t)current_count, sizeof(*changed),
                             "ci_incremental_changed");
        if (!current_leaves || !changed ||
            ci_merkle_leaves(merkle, current_leaves, current_count) !=
                current_count) {
            failure = "collect changed Merkle leaves failed";
            goto out;
        }
        changed_count = ci_store_diff_merkle_leaves(
            ci->store, current_leaves, current_count, changed, current_count,
            &inventory_same);
        incremental = inventory_same;
    }

    if (!create_unique_stage(dirfd, stage_name, &stage_identity, &stagefd)) {
        failure = "unique staging allocation failed";
        goto out;
    }
    if (!codeindex_test_maybe_tamper_stage(dirfd, stage_name)) {
        failure = "test staging substitution failed";
        goto out;
    }

    uint8_t built_source_stat_root[32];
    uint8_t built_dep_stat_root[32];
    if (incremental) {
        memcpy(built_dep_stat_root, current_dep_stat, 32);
        if (!ci_store_copy_image_fd(ci->store, stagefd)) {
            failure = "clone prior generation failed";
            goto out;
        }
        st = ci_store_open_rw_fd(stagefd);
        if (!st || !ci_build_store_incremental(
                       ci->root, st, changed, changed_count,
                       built_dep_stat_root, merkle_root.digest.bytes)) {
            failure = "incremental scan or staging update failed";
            goto out;
        }
        ci_store_close(st);
        st = NULL;
    } else {
        if (!ci_build_store_memory(ci->root, build_start_ms, &st,
                                   built_source_stat_root,
                                   built_dep_stat_root)) {
            failure = "source scan or staging write failed";
            goto out;
        }
        if (!ci_store_meta_set(st, "source_merkle_root_sha3",
                               merkle_root.digest.bytes, 32)) {
            failure = "seal source Merkle root failed";
            goto out;
        }
        if (!ci_store_write_image_fd(st, stagefd)) {
            failure = "serialize staging store failed";
            goto out;
        }
        ci_store_close(st);
        st = NULL;
    }

    /* Serialization can be non-trivial for a large index. Recheck only the
     * cached metadata keys at the last boundary before fsync/publication; any
     * byte change also changes inode/size/mtime/ctime on the supported local
     * filesystems and forces a clean retry. */
    struct ci_merkle_cost final_merkle_cost = {0};
    struct ci_merkle *final_merkle = ci_merkle_refresh(
        ci->root, &final_merkle_cost);
    struct ci_merkle_node final_merkle_root;
    uint8_t final_dep_stat_root[32];
    bool final_ok = final_merkle &&
        ci_merkle_root(final_merkle, &final_merkle_root) &&
        memcmp(merkle_root.digest.bytes, final_merkle_root.digest.bytes, 32) == 0 &&
        ci_deps_stat_root_sha3(ci->root, final_dep_stat_root) &&
        memcmp(built_dep_stat_root, final_dep_stat_root, 32) == 0;
    ci_merkle_free(final_merkle);
    if (!final_ok) {
        failure = "source or depfile metadata changed during rebuild";
        goto out;
    }

    struct stat stage_st;
    struct stat stage_name_st;
    if (fstat(stagefd, &stage_st) != 0 || !S_ISREG(stage_st.st_mode) ||
        stage_st.st_nlink != 1 || stage_st.st_dev != stage_identity.dev ||
        stage_st.st_ino != stage_identity.ino ||
        fstatat(dirfd, stage_name, &stage_name_st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(stage_name_st.st_mode) || stage_name_st.st_nlink != 1 ||
        stage_name_st.st_dev != stage_st.st_dev ||
        stage_name_st.st_ino != stage_st.st_ino) {
        failure = "staging inode identity changed";
        goto out;
    }
    unsigned char journal_versions[2];
    if (pread(stagefd, journal_versions, sizeof(journal_versions), 18) !=
            (ssize_t)sizeof(journal_versions) ||
        journal_versions[0] != 1 || journal_versions[1] != 1) {
        failure = "staging image is not rollback-journal format";
        goto out;
    }
    if (fsync(stagefd) != 0) {
        failure = "fsync staging inode failed";
        goto out;
    }

    codeindex_test_maybe_crash(CODEINDEX_TEST_CRASH_BEFORE_RENAME);
    if (renameat(dirfd, stage_name, dirfd, "index.kv") != 0) {
        failure = "atomic staging publication failed";
        goto out;
    }
    stage_name[0] = '\0';
    struct stat published_st;
    if (fstatat(dirfd, "index.kv", &published_st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(published_st.st_mode) || published_st.st_nlink != 1 ||
        published_st.st_uid != geteuid() ||
        (published_st.st_mode & (S_IWGRP | S_IWOTH)) ||
        published_st.st_dev != stage_st.st_dev ||
        published_st.st_ino != stage_st.st_ino) {
        failure = "published index inode identity changed";
        goto out;
    }
    /* Make the rollback-journal main file durable before unlinking any WAL
     * that an older generation might require. A power loss may therefore
     * leave either (old main + old sidecars) or (new main + old sidecars),
     * never old main with its WAL removed. Immutable readers safely ignore
     * sidecars beside the new main. */
    if (fsync(dirfd) != 0) {
        failure = "fsync published index directory failed";
        goto out;
    }
    codeindex_test_maybe_crash(CODEINDEX_TEST_CRASH_AFTER_RENAME);
    if (!remove_legacy_sidecars(dirfd)) {
        failure = "legacy sidecar cleanup failed";
        goto out;
    }
    if (fsync(dirfd) != 0) {
        failure = "fsync legacy sidecar cleanup failed";
        goto out;
    }
    close(stagefd);
    stagefd = -1;

    struct ci_store *next = ci_store_open(ci->root);
    if (!next) {
        failure = "reopen published index failed";
        goto out;
    }
    struct ci_store *old = ci->store;
    ci->store = next;
    if (old) ci_store_close(old);
    success = true;

out:
    if (st) ci_store_close(st);
    ci_merkle_free(merkle);
    free(changed);
    free(current_leaves);
    if (stagefd >= 0) close(stagefd);
    if (stage_name[0]) {
        (void)unlinkat(dirfd, stage_name, 0);
    }
    rebuild_lock_close(dirfd, lockfd);
    if (!success)
        LOG_FAIL("codeindex", "rebuild failed: %s", failure);
    return true;
}

bool ci_codeindex_refresh(struct codeindex *ci)
{
    return codeindex_rebuild_internal(ci, true);
}

bool codeindex_rebuild(struct codeindex *ci)
{
    return codeindex_rebuild_internal(ci, false);
}

#endif
