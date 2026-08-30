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
    return strcmp(name, ".git") == 0 || strcmp(name, ".codeindex") == 0 ||
           strcmp(name, ".zvcs") == 0 || strcmp(name, "build") == 0 ||
           strcmp(name, "bin") == 0 || strcmp(name, "obj") == 0 ||
           strcmp(name, ".cache") == 0 || strcmp(name, "vendor") == 0 ||
           strncmp(name, "test-tmp", 8) == 0;
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

    /* lib/<mod>/{src,include} */
    size_t nmod = 0;
    const char *const *mods = ci_lib_modules(&nmod);
    for (size_t i = 0; i < nmod; i++) {
        char rel[CI_PATH_MAX];
        snprintf(rel, sizeof(rel), "lib/%s/src", mods[i]);
        if (!collect_dir(root, rel, &vec)) goto collect_failed;
        snprintf(rel, sizeof(rel), "lib/%s/include", mods[i]);
        if (!collect_dir(root, rel, &vec)) goto collect_failed;
    }
    /* app/<shape>/{src,include} */
    size_t nsh = 0;
    const char *const *shapes = ci_app_shapes(&nsh);
    for (size_t i = 0; i < nsh; i++) {
        char rel[CI_PATH_MAX];
        snprintf(rel, sizeof(rel), "app/%s/src", shapes[i]);
        if (!collect_dir(root, rel, &vec)) goto collect_failed;
        snprintf(rel, sizeof(rel), "app/%s/include", shapes[i]);
        if (!collect_dir(root, rel, &vec)) goto collect_failed;
    }
    /* the standalone roots */
    if (!collect_dir(root, "core", &vec) ||
        !collect_dir(root, "config/src", &vec) ||
        !collect_dir(root, "config/include", &vec) ||
        !collect_dir(root, "tools", &vec) ||
        !collect_dir(root, "domain", &vec) ||
        !collect_dir(root, "adapters", &vec) ||
        !collect_dir(root, "ports", &vec) ||
        !collect_dir(root, "src", &vec))
        goto collect_failed;

    /* Tests are not a production LIB_MODULES entry, but they are source a
     * developer must be able to navigate.  collect_dir() retains the same
     * generated-directory pruning used above; the sorted pass below de-dups
     * this root if it ever becomes a listed library module. */
    if (!collect_dir(root, "lib/test", &vec)) goto collect_failed;

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

static const char ci_store_format[] = "zcl.codeindex.store.v4";

struct stamp_ctx {
    const char *root;
    struct sha3_256_ctx sha;
    struct sha3_256_ctx stat_sha;
    bool include_stat;
};

static void source_root_init(struct sha3_256_ctx *sha)
{
    /* v3: bumped alongside CI_SCHEMA_VERSION="cg1" (refs.enclosing) so the
     * content stamp of any pre-call-graph generation misses — the second half
     * of the dual recompute-never-repair trigger.
     * v4: bumped alongside CI_SCHEMA_VERSION="rev1". The enumerated set now
     * includes `*.def` registries, so the stamp finally moves when one is
     * edited; a v3 stamp was computed over a strictly smaller file set. */
    static const char domain[] = "zcl.codeindex.source_root.v4";
    sha3_256_init(sha);
    sha3_256_write(sha, (const unsigned char *)domain, sizeof(domain));
}

static void source_root_add(struct sha3_256_ctx *sha, const char *relpath,
                            const uint8_t content_sha3[32])
{
    sha3_256_write(sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    sha3_256_write(sha, content_sha3, 32);
}

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
    source_root_add(&c->sha, relpath, content_sha3);
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
    source_root_init(&c.sha);
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

/* ── rebuild ────────────────────────────────────────────────────────── */

/* path → file_id map (sorted, bsearch) */
struct idmap_ent { char path[256]; int64_t id; };
struct build_ctx {
    struct ci_store   *store;
    bool               err;
    struct idmap_ent  *ids;
    size_t             nids, cap_ids;
    struct sha3_256_ctx source_root;
};

static void on_sym_cb(const struct ci_symbol *sym, void *user)
{
    struct build_ctx *b = user;
    if (b->err) return;
    if (!ci_store_put_symbol(b->store, sym)) b->err = true;
}

/* Discarding sinks for a registry file: ci_scan_file requires both callbacks,
 * and a registry must contribute neither a symbol nor a call edge. */
static void ci_ignore_sym_cb(const struct ci_symbol *sym, void *user)
{
    (void)sym;
    (void)user;
}

static void ci_ignore_ref_cb(const char *callee, const char *ref_file,
                             int ref_line, const char *enclosing, void *user)
{
    (void)callee;
    (void)ref_file;
    (void)ref_line;
    (void)enclosing;
    (void)user;
}

static void on_ref_cb(const char *callee, const char *ref_file, int ref_line,
                      const char *enclosing, void *user)
{
    struct build_ctx *b = user;
    if (b->err) return;
    if (!ci_store_put_ref(b->store, callee, ref_file, ref_line, enclosing))
        b->err = true;
}

static bool idmap_push(struct build_ctx *b, const char *path, int64_t id)
{
    if (b->nids == b->cap_ids) {
        size_t ncap = b->cap_ids ? b->cap_ids * 2 : 512;
        void *nb = zcl_realloc(b->ids, ncap * sizeof(*b->ids), "ci_idmap");
        if (!nb) return false;
        b->ids = nb; b->cap_ids = ncap;
    }
    snprintf(b->ids[b->nids].path, sizeof(b->ids[b->nids].path), "%s", path);
    b->ids[b->nids].id = id;
    b->nids++;
    return true;
}

static int idmap_cmp(const void *a, const void *b)
{
    return strcmp(((const struct idmap_ent *)a)->path,
                  ((const struct idmap_ent *)b)->path);
}

static int64_t idmap_find(const struct build_ctx *b, const char *path)
{
    size_t lo = 0, hi = b->nids;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(b->ids[mid].path, path);
        if (c == 0) return b->ids[mid].id;
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return -1;
}

/* the per-file enumeration callback needs root; carry it alongside build_ctx. */
struct build_file_env { struct build_ctx *b; const char *root; };

static bool build_file_cb2(const char *relpath, const struct stat *file_st,
                           void *user)
{
    struct build_file_env *env = user;
    struct build_ctx *b = env->b;
    if (b->err) return false;

    uint8_t sha[32];
    char purpose[CI_FILE_PURPOSE_MAX] = "";
    /* A registry is hashed and filed, never scanned: its `FOO(a, b)` rows are
     * macro data, and letting the C scanner read them would mint symbols and
     * call edges that do not exist. Include-graph node only (see
     * ci_is_registry_name). */
    bool registry = ci_path_is_registry(relpath);
    if (!ci_scan_file(env->root, relpath,
                      registry ? ci_ignore_sym_cb : on_sym_cb,
                      registry ? ci_ignore_ref_cb : on_ref_cb, b, sha,
                      purpose)) {
        b->err = true;
        return false;
    }
    source_root_add(&b->source_root, relpath, sha);
    struct ci_file f;
    memset(&f, 0, sizeof(f));
    snprintf(f.path, sizeof(f.path), "%s", relpath);
    ci_group_for_path(relpath, f.group);
    /* self-description derived from the file's leading comment (§1.1). */
    snprintf(f.purpose, sizeof(f.purpose), "%s", purpose);
    int64_t id = -1;
    int64_t mtime_ns = (int64_t)file_st->st_mtim.tv_sec * INT64_C(1000000000) +
                       (int64_t)file_st->st_mtim.tv_nsec;
    if (!ci_store_put_file(b->store, &f, sha, mtime_ns, &id)) {
        b->err = true;
        return false;
    }
    if (!idmap_push(b, relpath, id)) { b->err = true; return false; }
    return true;
}

static void on_dep_cb(const char *src_relpath, const char *dep_relpath,
                      void *user)
{
    struct build_ctx *b = user;
    if (b->err) return;
    int64_t id = idmap_find(b, src_relpath);
    if (id < 0) return;  /* source not in our indexed set — skip */
    if (!ci_store_put_include(b->store, id, dep_relpath)) b->err = true;
}

static _Atomic uint64_t g_stage_sequence = 1;

struct stage_identity {
    dev_t dev;
    ino_t ino;
};

#ifdef ZCL_TESTING
static _Atomic int g_test_crash_point = CODEINDEX_TEST_CRASH_NONE;
static _Atomic int g_test_stage_tamper = CODEINDEX_TEST_STAGE_TAMPER_NONE;
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
#endif

static bool rebuild_lock_open(const char *root, char dir[CI_PATH_MAX],
                              int *out_dirfd, int *out_lockfd)
{
    *out_dirfd = -1;
    *out_lockfd = -1;
    int n = snprintf(dir, CI_PATH_MAX, "%s/.codeindex", root);
    if (n <= 0 || n >= CI_PATH_MAX)
        LOG_FAIL("codeindex", "index directory path too long");
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
        LOG_FAIL("codeindex", "create index directory failed: %s",
                 strerror(errno));

    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0)
        LOG_FAIL("codeindex", "open index directory failed: %s",
                 strerror(errno));
    struct stat dir_st;
    if (fstat(dirfd, &dir_st) != 0 || !S_ISDIR(dir_st.st_mode) ||
        dir_st.st_uid != geteuid() || (dir_st.st_mode & (S_IWGRP | S_IWOTH))) {
        close(dirfd);
        LOG_FAIL("codeindex",
                 "index directory must be owner-controlled and not writable by group/other");
    }
    int lockfd = openat(dirfd, "rebuild.lock",
                        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0) {
        int saved = errno;
        close(dirfd);
        LOG_FAIL("codeindex", "open rebuild lock failed: %s", strerror(saved));
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

    const char *failure = "unknown rebuild failure";
    bool success = false;
    bool tx_open = false;
    char stage_name[128] = "";
    struct stage_identity stage_identity = {0};
    int stagefd = -1;
    struct ci_store *st = NULL;
    struct build_ctx b;
    memset(&b, 0, sizeof(b));

    if (!cleanup_orphan_stages(dirfd)) {
        failure = "orphan staging cleanup failed";
        goto out;
    }

    /* A second cold opener may have waited while the first one published.
     * Reopen the pathname under the lock and adopt that exact fresh store
     * instead of redundantly rebuilding it. Explicit codeindex_rebuild()
     * passes false and remains a forced deterministic recompute. */
    if (coalesce_if_fresh) {
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
        }
    }

    if (!create_unique_stage(dirfd, stage_name, &stage_identity, &stagefd)) {
        failure = "unique staging allocation failed";
        goto out;
    }
    if (!codeindex_test_maybe_tamper_stage(dirfd, stage_name)) {
        failure = "test staging substitution failed";
        goto out;
    }

    /* Build in memory, then serialize through the still-open O_EXCL file
     * descriptor. SQLite never receives a staging pathname, so a directory
     * entry swap cannot redirect DDL/DELETE writes outside this capability. */
    st = ci_store_open_path(":memory:");
    if (!st) {
        failure = "open staging store failed";
        goto out;
    }
    b.store = st;
    source_root_init(&b.source_root);

    if (!ci_store_begin(st)) {
        failure = "begin staging transaction failed";
        goto out;
    }
    tx_open = true;
    bool build_ok = ci_store_clear(st) && ci_group_emit_all(st);

    struct build_file_env env = { &b, ci->root };
    if (build_ok && !ci_enumerate_sources(ci->root, build_file_cb2, &env))
        build_ok = false;
    if (b.err) build_ok = false;

    if (build_ok)
        qsort(b.ids, b.nids, sizeof(b.ids[0]), idmap_cmp);

    uint8_t built_source_root[32];
    uint8_t built_dep_root[32];
    uint8_t built_source_stat_root[32];
    uint8_t built_dep_stat_root[32];
    if (build_ok) {
        sha3_256_finalize(&b.source_root, built_source_root);
        if (!ci_store_meta_set(st, "source_root_sha3", built_source_root, 32))
            build_ok = false;
    }
    if (build_ok &&
        (!ci_deps_scan(ci->root, on_dep_cb, &b, built_dep_root) || b.err))
        build_ok = false;
    if (build_ok &&
        !ci_store_meta_set(st, "dep_root_sha3", built_dep_root, 32))
        build_ok = false;

    /* Refuse a mixed source epoch and derive the metadata cache keys from the
     * same opened inodes as the exact validation pass. */
    uint8_t current_source_root[32], current_dep_root[32];
    if (build_ok &&
        (!ci_source_roots_sha3(ci->root, current_source_root,
                               built_source_stat_root) ||
         memcmp(built_source_root, current_source_root, 32) != 0 ||
         !ci_deps_scan_roots(ci->root, NULL, NULL, current_dep_root,
                             built_dep_stat_root) ||
         memcmp(built_dep_root, current_dep_root, 32) != 0))
        build_ok = false;
    if (build_ok &&
        !ci_store_meta_set(st, "source_stat_root_sha3",
                           built_source_stat_root, 32))
        build_ok = false;
    if (build_ok &&
        !ci_store_meta_set(st, "dep_stat_root_sha3",
                           built_dep_stat_root, 32))
        build_ok = false;
    if (build_ok &&
        !ci_store_meta_set(st, "store_format", ci_store_format,
                           sizeof(ci_store_format) - 1))
        build_ok = false;
    if (build_ok &&
        !ci_store_meta_set(st, "ci_schema_version", CI_SCHEMA_VERSION,
                           sizeof(CI_SCHEMA_VERSION) - 1))
        build_ok = false;
    if (!build_ok) {
        (void)ci_store_rollback(st);
        tx_open = false;
        failure = "source scan or staging write failed";
        goto out;
    }
    if (!ci_store_commit(st)) {
        tx_open = false;
        failure = "commit staging store failed";
        goto out;
    }
    tx_open = false;

    if (!ci_store_write_image_fd(st, stagefd)) {
        failure = "serialize staging store failed";
        goto out;
    }
    ci_store_close(st);
    st = NULL;

    /* Serialization can be non-trivial for a large index. Recheck only the
     * cached metadata keys at the last boundary before fsync/publication; any
     * byte change also changes inode/size/mtime/ctime on the supported local
     * filesystems and forces a clean retry. */
    uint8_t final_source_stat_root[32], final_dep_stat_root[32];
    if (!ci_source_stat_root_sha3(ci->root, final_source_stat_root) ||
        memcmp(built_source_stat_root, final_source_stat_root, 32) != 0 ||
        !ci_deps_stat_root_sha3(ci->root, final_dep_stat_root) ||
        memcmp(built_dep_stat_root, final_dep_stat_root, 32) != 0) {
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
    if (st) {
        if (tx_open) (void)ci_store_rollback(st);
        ci_store_close(st);
    }
    if (stagefd >= 0) close(stagefd);
    free(b.ids);
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
