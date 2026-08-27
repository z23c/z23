/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_merkle — the SHA3-256 Merkle tree over the indexed source tree.
 *
 * One pass over ci_enumerate_sources()' sorted repo-relative path stream builds
 * the whole tree with a small explicit frame stack: because the stream is sorted
 * by strcmp, every directory's descendants are contiguous in it, so a frame can
 * be finalized the moment the stream leaves its subtree. That is also where the
 * child order comes from — see `merkle_child_key` below, the single statement of
 * the ordering rule.
 *
 * The SHA3-sealed snapshot at <root>/.codeindex/source_tree.merkle exists for exactly one
 * reason: to let a refresh re-read only the files whose (dev,ino,size,mtime,
 * ctime) cache key moved, and to let a directory whose children are all
 * unchanged keep its digest without hashing. It is derived, content-keyed, and
 * discarded whole on any doubt. Its format version is also the source inventory
 * policy version: changing ci_enumerate_sources() must bump it and force one
 * cold pass. The files on disk remain the only authority.
 */

#include "codeindex_priv.h"
#include "codeindex/codeindex_merkle.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── domain separation ───────────────────────────────────────────────
 * codeindex_store.c already spends tag byte 0x01 on a symbol row and
 * codeindex_build.c spends 0x02 on a whole-file content hash. A Merkle leaf and
 * an internal node take 0x10 and 0x11 and additionally carry a NUL-terminated
 * domain string, so no preimage here can be confused with either of those two
 * nor with the other. */
enum {
    MERKLE_TAG_LEAF = 0x10,
    MERKLE_TAG_NODE = 0x11,
};

enum {
    MERKLE_MAX_DEPTH    = 32,
    MERKLE_NAME_MAX     = 160,
    MERKLE_SNAPSHOT_MAX = 64u * 1024u * 1024u,
};

static const char merkle_snapshot_format[] =
    "zcl.codeindex.source_tree.merkle.v2";
static const char merkle_snapshot_name[] = "source_tree.merkle";
static const char merkle_snapshot_seal_domain[] =
    "zcl.codeindex.source_tree.merkle.seal.v1";

/* ── records ─────────────────────────────────────────────────────────── */

/* The cache key that decides whether a leaf's bytes must be re-read. Same
 * fields ci_source_stat_root_sha3() binds: every local content replacement
 * moves at least one of them. A key mismatch costs one re-read, never an
 * alarm. */
struct merkle_stat_key {
    uint64_t dev, ino, size, mtime_sec, mtime_nsec, ctime_sec, ctime_nsec;
};

struct merkle_leaf_rec {
    char                   path[256];
    struct zcl_sha3_digest digest;
    uint64_t               size;
    struct merkle_stat_key key;
    bool                   dirty; /* digest differs from the snapshot's */
};

struct merkle_node_rec {
    char                   path[256];
    struct zcl_sha3_digest digest;
    uint32_t               direct_children;
    uint32_t               file_count;
    uint32_t               dir_count;
    uint64_t               total_bytes;
};

struct ci_merkle {
    struct merkle_leaf_rec *leaves;
    uint32_t                nleaves;
    struct merkle_node_rec *nodes; /* sorted by path; index 0 is the root ("") */
    uint32_t                nnodes;
    struct zcl_sha3_digest  root;
};

/* ── hashing ─────────────────────────────────────────────────────────── */

static void merkle_write_u32le(struct sha3_256_ctx *sha, uint32_t v)
{
    unsigned char b[4];
    for (unsigned i = 0; i < 4; i++) b[i] = (unsigned char)((v >> (i * 8)) & 0xff);
    sha3_256_write(sha, b, sizeof(b));
}

static void merkle_write_u64le(struct sha3_256_ctx *sha, uint64_t v)
{
    unsigned char b[8];
    for (unsigned i = 0; i < 8; i++) b[i] = (unsigned char)((v >> (i * 8)) & 0xff);
    sha3_256_write(sha, b, sizeof(b));
}

/* One direct child of a directory node. */
struct merkle_child {
    char                   name[MERKLE_NAME_MAX];
    uint8_t                kind; /* 0 = file leaf, 1 = directory */
    struct zcl_sha3_digest digest;
};

/* THE ordering rule, in one place. A directory's direct children are ordered by
 * strcmp over this key: a file's own name, a directory's name followed by '/'.
 * Because '/' (0x2f) sorts above '.' (0x2e) and above every character legal in
 * a C identifier, that key order is identical to strcmp order over the
 * children's full repo-relative paths — which is the order ci_enumerate_sources
 * already emits. The builder therefore appends children in stream order and
 * needs no sort, and the two can never disagree. */
static void merkle_child_key(const struct merkle_child *c,
                             char out[MERKLE_NAME_MAX + 2])
{
    (void)snprintf(out, MERKLE_NAME_MAX + 2, "%s%s", c->name,
                   c->kind == 1 ? "/" : "");
}

/* Is `next` strictly after `prev` in the canonical child order? Checked on
 * every append (see merkle_frame_push_child), which is what turns the rule
 * above from a comment into a property the build cannot violate silently: if a
 * future change to ci_enumerate_sources reorders the stream, the build fails
 * loudly instead of quietly minting a different root. */
static bool merkle_child_in_order(const struct merkle_child *prev,
                                  const struct merkle_child *next)
{
    char a[MERKLE_NAME_MAX + 2], bkey[MERKLE_NAME_MAX + 2];
    merkle_child_key(prev, a);
    merkle_child_key(next, bkey);
    return strcmp(a, bkey) < 0;
}

static void merkle_node_digest(const char *path, const struct merkle_child *kids,
                               uint32_t n, struct zcl_sha3_digest *out)
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t tag = MERKLE_TAG_NODE;
    static const char domain[] = "zcl.codeindex.merkle.node.v1";
    sha3_256_write(&sha, &tag, 1);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&sha, (const unsigned char *)path, strlen(path) + 1);
    merkle_write_u32le(&sha, n);
    for (uint32_t i = 0; i < n; i++) {
        sha3_256_write(&sha, &kids[i].kind, 1);
        sha3_256_write(&sha, (const unsigned char *)kids[i].name,
                       strlen(kids[i].name) + 1);
        sha3_256_write(&sha, kids[i].digest.bytes, 32);
    }
    sha3_256_finalize(&sha, out->bytes);
}

/* Read one file and hash its leaf. The before/after fstat comparison is not a
 * drift check: it says "these bytes and this cache key came from the same
 * inode state", so the key we store is the key the digest belongs to. */
static bool merkle_leaf_digest(const char *root, const char *relpath,
                               struct zcl_sha3_digest *out, uint64_t *out_size,
                               struct merkle_stat_key *out_key, bool *found)
{
    *found = false;
    char full[CI_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", root, relpath);
    if (n <= 0 || (size_t)n >= sizeof(full))
        LOG_FAIL("codeindex", "merkle leaf path too long: %s", relpath);

    int fd = open(full, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) {
        memset(out, 0, sizeof(*out));
        *out_size = 0;
        memset(out_key, 0, sizeof(*out_key));
        return true;
    }
    if (fd < 0)
        LOG_FAIL("codeindex", "merkle open leaf failed path=%s: %s", relpath,
                 strerror(errno));
    struct stat before, after;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)) {
        int saved = errno ? errno : EINVAL;
        close(fd);
        LOG_FAIL("codeindex", "merkle stat leaf failed path=%s: %s", relpath,
                 strerror(saved));
    }

    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t tag = MERKLE_TAG_LEAF;
    static const char domain[] = "zcl.codeindex.merkle.leaf.v1";
    sha3_256_write(&sha, &tag, 1);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    merkle_write_u64le(&sha, (uint64_t)before.st_size);

    unsigned char buf[64 * 1024];
    uint64_t total = 0;
    bool ok = true;
    for (;;) {
        ssize_t got = read(fd, buf, sizeof(buf));
        if (got < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        if (got == 0) break;
        sha3_256_write(&sha, buf, (size_t)got);
        total += (uint64_t)got;
    }
    if (ok && (fstat(fd, &after) != 0 || total != (uint64_t)before.st_size ||
               before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
               before.st_size != after.st_size ||
               before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
               before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
               before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
               before.st_ctim.tv_nsec != after.st_ctim.tv_nsec))
        ok = false;
    close(fd);
    if (!ok)
        LOG_FAIL("codeindex", "merkle read leaf failed path=%s", relpath);

    sha3_256_finalize(&sha, out->bytes);
    *out_size = total;
    out_key->dev = (uint64_t)after.st_dev;
    out_key->ino = (uint64_t)after.st_ino;
    out_key->size = (uint64_t)after.st_size;
    out_key->mtime_sec = (uint64_t)after.st_mtim.tv_sec;
    out_key->mtime_nsec = (uint64_t)after.st_mtim.tv_nsec;
    out_key->ctime_sec = (uint64_t)after.st_ctim.tv_sec;
    out_key->ctime_nsec = (uint64_t)after.st_ctim.tv_nsec;
    *found = true;
    return true;
}

/* ── the snapshot: a flat, sorted, self-describing byte image ─────────── */

struct merkle_snapshot {
    struct merkle_leaf_rec *leaves;
    uint32_t                nleaves;
    struct merkle_node_rec *nodes;
    uint32_t                nnodes;
};

static void merkle_snapshot_free(struct merkle_snapshot *s)
{
    if (!s) return;
    free(s->leaves);
    free(s->nodes);
    s->leaves = NULL;
    s->nodes = NULL;
    s->nleaves = s->nnodes = 0;
}

struct merkle_cursor {
    const unsigned char *p;
    size_t               left;
    bool                 bad;
};

static void merkle_snapshot_seal(const unsigned char *image, size_t len,
                                 unsigned char out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha,
                   (const unsigned char *)merkle_snapshot_seal_domain,
                   sizeof(merkle_snapshot_seal_domain));
    sha3_256_write(&sha, image, len);
    sha3_256_finalize(&sha, out);
}

static bool merkle_take(struct merkle_cursor *c, void *dst, size_t n)
{
    if (c->bad || c->left < n) { c->bad = true; return false; }
    memcpy(dst, c->p, n);
    c->p += n;
    c->left -= n;
    return true;
}

static uint32_t merkle_take_u32(struct merkle_cursor *c)
{
    unsigned char b[4] = {0};
    if (!merkle_take(c, b, 4)) return 0;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

static uint64_t merkle_take_u64(struct merkle_cursor *c)
{
    unsigned char b[8] = {0};
    if (!merkle_take(c, b, 8)) return 0;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | (uint64_t)b[i];
    return v;
}

static bool merkle_take_path(struct merkle_cursor *c, char out[256])
{
    unsigned char lb[2] = {0};
    if (!merkle_take(c, lb, 2)) return false;
    size_t len = (size_t)lb[0] | ((size_t)lb[1] << 8);
    if (len >= 256) { c->bad = true; return false; }
    if (!merkle_take(c, out, len)) return false;
    out[len] = '\0';
    return memchr(out, '\0', len) == NULL;
}

static void merkle_put(unsigned char **w, const void *src, size_t n)
{
    memcpy(*w, src, n);
    *w += n;
}

static void merkle_put_u32(unsigned char **w, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++) (*w)[i] = (unsigned char)((v >> (i * 8)) & 0xff);
    *w += 4;
}

static void merkle_put_u64(unsigned char **w, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) (*w)[i] = (unsigned char)((v >> (i * 8)) & 0xff);
    *w += 8;
}

static void merkle_put_path(unsigned char **w, const char *p)
{
    size_t len = strlen(p);
    (*w)[0] = (unsigned char)(len & 0xff);
    (*w)[1] = (unsigned char)((len >> 8) & 0xff);
    *w += 2;
    merkle_put(w, p, len);
}

/* Open <root>/.codeindex as a directory capability. `create` mkdirs it. Same
 * owner-controlled posture codeindex_build.c requires of the same directory: a
 * cache another user can write is a cache that can answer for us. */
static int merkle_open_dir(const char *root, bool create)
{
    char dir[CI_PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/.codeindex", root);
    if (n <= 0 || (size_t)n >= sizeof(dir)) return -1;
    if (create && mkdir(dir, 0755) != 0 && errno != EEXIST) return -1;
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Load the snapshot. A missing, truncated, wrong-format, or out-of-order image
 * is simply not a snapshot: *found stays false and the caller does a cold pass.
 * Never an error return, because there is nothing to reconcile. */
static bool merkle_snapshot_load(const char *root, struct merkle_snapshot *out,
                                 bool *found)
{
    *found = false;
    memset(out, 0, sizeof(*out));
    int dirfd = merkle_open_dir(root, false);
    if (dirfd < 0) return true;
    int fd = openat(dirfd, merkle_snapshot_name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(dirfd);
    if (fd < 0) return true;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        st.st_uid != geteuid() || (st.st_mode & (S_IWGRP | S_IWOTH)) ||
        (uint64_t)st.st_size > MERKLE_SNAPSHOT_MAX) {
        close(fd);
        return true;
    }
    size_t len = (size_t)st.st_size;
    unsigned char *img = zcl_malloc(len, "ci_merkle_snapshot");
    if (!img) {
        close(fd);
        LOG_FAIL("codeindex", "allocate merkle snapshot image (%zu bytes)", len);
    }
    size_t done = 0;
    bool read_ok = true;
    while (done < len) {
        ssize_t got = read(fd, img + done, len - done);
        if (got < 0) {
            if (errno == EINTR) continue;
            read_ok = false;
            break;
        }
        if (got == 0) { read_ok = false; break; }
        done += (size_t)got;
    }
    close(fd);
    if (!read_ok) {
        free(img);
        return true; /* unreadable cache == no cache */
    }

    if (len <= 32) {
        free(img);
        return true;
    }
    size_t payload_len = len - 32;
    unsigned char expected_seal[32];
    merkle_snapshot_seal(img, payload_len, expected_seal);
    if (memcmp(expected_seal, img + payload_len, 32) != 0) {
        free(img);
        return true;
    }

    struct merkle_cursor c = {
        .p = img, .left = payload_len, .bad = false
    };
    char format[256];
    if (!merkle_take_path(&c, format) ||
        strcmp(format, merkle_snapshot_format) != 0) {
        free(img);
        return true;
    }
    uint32_t nleaves = merkle_take_u32(&c);
    uint32_t nnodes = merkle_take_u32(&c);
    unsigned char root_digest[32];
    (void)merkle_take(&c, root_digest, 32);
    if (c.bad || nnodes == 0 || nleaves > (MERKLE_SNAPSHOT_MAX / 64) ||
        nnodes > (MERKLE_SNAPSHOT_MAX / 64)) {
        free(img);
        return true;
    }

    struct merkle_leaf_rec *leaves =
        nleaves ? zcl_malloc((size_t)nleaves * sizeof(*leaves),
                             "ci_merkle_snap_leaves")
                : NULL;
    struct merkle_node_rec *nodes =
        zcl_malloc((size_t)nnodes * sizeof(*nodes), "ci_merkle_snap_nodes");
    if ((nleaves && !leaves) || !nodes) {
        free(leaves);
        free(nodes);
        free(img);
        LOG_FAIL("codeindex", "allocate merkle snapshot records");
    }
    if (leaves) memset(leaves, 0, (size_t)nleaves * sizeof(*leaves));
    memset(nodes, 0, (size_t)nnodes * sizeof(*nodes));

    for (uint32_t i = 0; i < nleaves && !c.bad; i++) {
        struct merkle_leaf_rec *l = &leaves[i];
        if (!merkle_take_path(&c, l->path)) break;
        (void)merkle_take(&c, l->digest.bytes, 32);
        l->size = merkle_take_u64(&c);
        l->key.dev = merkle_take_u64(&c);
        l->key.ino = merkle_take_u64(&c);
        l->key.size = merkle_take_u64(&c);
        l->key.mtime_sec = merkle_take_u64(&c);
        l->key.mtime_nsec = merkle_take_u64(&c);
        l->key.ctime_sec = merkle_take_u64(&c);
        l->key.ctime_nsec = merkle_take_u64(&c);
        if (i > 0 && strcmp(leaves[i - 1].path, l->path) >= 0) c.bad = true;
    }
    for (uint32_t i = 0; i < nnodes && !c.bad; i++) {
        struct merkle_node_rec *nd = &nodes[i];
        if (!merkle_take_path(&c, nd->path)) break;
        (void)merkle_take(&c, nd->digest.bytes, 32);
        nd->direct_children = merkle_take_u32(&c);
        nd->file_count = merkle_take_u32(&c);
        nd->dir_count = merkle_take_u32(&c);
        nd->total_bytes = merkle_take_u64(&c);
        if (i > 0 && strcmp(nodes[i - 1].path, nd->path) >= 0) c.bad = true;
    }
    free(img);
    if (c.bad || c.left != 0 || nodes[0].path[0] != '\0' ||
        memcmp(nodes[0].digest.bytes, root_digest, 32) != 0) {
        free(leaves);
        free(nodes);
        return true;
    }
    out->leaves = leaves;
    out->nleaves = nleaves;
    out->nodes = nodes;
    out->nnodes = nnodes;
    *found = true;
    return true;
}

static _Atomic uint64_t g_merkle_tmp_seq = 1;

/* Publish a snapshot: private O_EXCL temp beside the target, fsync, atomic
 * rename. A crash mid-write leaves the previous snapshot (or none), and either
 * way the next refresh is correct — only slower. */
static bool merkle_snapshot_save(const char *root, const struct ci_merkle *m)
{
    size_t need = sizeof(merkle_snapshot_format) + 2 + 4 + 4 + 32 + 32;
    for (uint32_t i = 0; i < m->nleaves; i++)
        need += 2 + strlen(m->leaves[i].path) + 32 + 8 * 8;
    for (uint32_t i = 0; i < m->nnodes; i++)
        need += 2 + strlen(m->nodes[i].path) + 32 + 4 + 4 + 4 + 8;

    unsigned char *img = zcl_malloc(need, "ci_merkle_snapshot_out");
    if (!img) LOG_FAIL("codeindex", "allocate merkle snapshot output");
    unsigned char *w = img;
    merkle_put_path(&w, merkle_snapshot_format);
    merkle_put_u32(&w, m->nleaves);
    merkle_put_u32(&w, m->nnodes);
    merkle_put(&w, m->root.bytes, 32);
    for (uint32_t i = 0; i < m->nleaves; i++) {
        const struct merkle_leaf_rec *l = &m->leaves[i];
        merkle_put_path(&w, l->path);
        merkle_put(&w, l->digest.bytes, 32);
        merkle_put_u64(&w, l->size);
        merkle_put_u64(&w, l->key.dev);
        merkle_put_u64(&w, l->key.ino);
        merkle_put_u64(&w, l->key.size);
        merkle_put_u64(&w, l->key.mtime_sec);
        merkle_put_u64(&w, l->key.mtime_nsec);
        merkle_put_u64(&w, l->key.ctime_sec);
        merkle_put_u64(&w, l->key.ctime_nsec);
    }
    for (uint32_t i = 0; i < m->nnodes; i++) {
        const struct merkle_node_rec *nd = &m->nodes[i];
        merkle_put_path(&w, nd->path);
        merkle_put(&w, nd->digest.bytes, 32);
        merkle_put_u32(&w, nd->direct_children);
        merkle_put_u32(&w, nd->file_count);
        merkle_put_u32(&w, nd->dir_count);
        merkle_put_u64(&w, nd->total_bytes);
    }
    size_t payload_len = (size_t)(w - img);
    merkle_snapshot_seal(img, payload_len, w);
    w += 32;
    size_t total = (size_t)(w - img);

    int dirfd = merkle_open_dir(root, true);
    if (dirfd < 0) {
        free(img);
        LOG_FAIL("codeindex", "open index directory for merkle snapshot: %s",
                 strerror(errno));
    }
    char tmp[128];
    uint64_t seq = atomic_fetch_add_explicit(&g_merkle_tmp_seq, 1,
                                             memory_order_relaxed);
    (void)snprintf(tmp, sizeof(tmp), "%s.tmp.%ld.%llu", merkle_snapshot_name,
                   (long)getpid(), (unsigned long long)seq);
    int fd = openat(dirfd, tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                                    O_NOFOLLOW, 0600);
    if (fd < 0) {
        int saved = errno;
        close(dirfd);
        free(img);
        LOG_FAIL("codeindex", "create merkle snapshot temp: %s",
                 strerror(saved));
    }
    size_t done = 0;
    bool ok = true;
    while (done < total) {
        ssize_t put = write(fd, img + done, total - done);
        if (put < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        done += (size_t)put;
    }
    free(img);
    if (ok && fsync(fd) != 0) ok = false;
    close(fd);
    if (ok && renameat(dirfd, tmp, dirfd, merkle_snapshot_name) != 0) ok = false;
    if (!ok) (void)unlinkat(dirfd, tmp, 0);
    if (ok) (void)fsync(dirfd);
    close(dirfd);
    if (!ok)
        LOG_FAIL("codeindex", "publish merkle snapshot failed: %s",
                 strerror(errno));
    return true;
}

bool ci_merkle_forget(const char *root)
{
    if (!root) LOG_FAIL("codeindex", "null root to merkle_forget");
    int dirfd = merkle_open_dir(root, false);
    if (dirfd < 0) return true;
    int rc = unlinkat(dirfd, merkle_snapshot_name, 0);
    int saved = errno;
    close(dirfd);
    if (rc != 0 && saved != ENOENT)
        LOG_FAIL("codeindex", "remove merkle snapshot failed: %s",
                 strerror(saved));
    return true;
}

/* ── the build pass ──────────────────────────────────────────────────── */

static int merkle_leaf_cmp(const void *a, const void *b)
{
    return strcmp(((const struct merkle_leaf_rec *)a)->path,
                  ((const struct merkle_leaf_rec *)b)->path);
}

static int merkle_node_cmp(const void *a, const void *b)
{
    return strcmp(((const struct merkle_node_rec *)a)->path,
                  ((const struct merkle_node_rec *)b)->path);
}

static const struct merkle_leaf_rec *
merkle_find_leaf(const struct merkle_leaf_rec *v, uint32_t n, const char *path)
{
    if (!v || n == 0) return NULL;
    struct merkle_leaf_rec probe;
    ci_cpy(probe.path, sizeof(probe.path), path);
    return bsearch(&probe, v, n, sizeof(*v), merkle_leaf_cmp);
}

static const struct merkle_node_rec *
merkle_find_node(const struct merkle_node_rec *v, uint32_t n, const char *path)
{
    if (!v || n == 0) return NULL;
    struct merkle_node_rec probe;
    ci_cpy(probe.path, sizeof(probe.path), path);
    return bsearch(&probe, v, n, sizeof(*v), merkle_node_cmp);
}

struct merkle_frame {
    char                 path[256];
    struct merkle_child *kids;
    uint32_t             nkids, cap;
    bool                 dirty;
    uint32_t             file_count, dir_count;
    uint64_t             total_bytes;
};

struct merkle_build {
    const char               *root;
    bool                      err;
    /* collected leaves, in enumeration (sorted) order */
    struct merkle_leaf_rec   *leaves;
    uint32_t                  nleaves, cap_leaves;
    /* finalized directory nodes, in post-order (sorted at the end) */
    struct merkle_node_rec   *nodes;
    uint32_t                  nnodes, cap_nodes;
    /* the previous generation, or an empty one */
    struct merkle_snapshot    prev;
    bool                      use_prev;
    /* the frame stack */
    struct merkle_frame       frames[MERKLE_MAX_DEPTH];
    uint32_t                  depth;
    struct ci_merkle_cost     cost;
};

static bool merkle_frame_push_child(struct merkle_frame *f,
                                    const struct merkle_child *c)
{
    if (f->nkids > 0 && !merkle_child_in_order(&f->kids[f->nkids - 1], c))
        LOG_FAIL("codeindex",
                 "merkle child order violated in '%s': '%s' after '%s'",
                 f->path, c->name, f->kids[f->nkids - 1].name);
    if (f->nkids == f->cap) {
        uint32_t ncap = f->cap ? f->cap * 2 : 32;
        void *nb = zcl_realloc(f->kids, (size_t)ncap * sizeof(*f->kids),
                               "ci_merkle_kids");
        if (!nb) LOG_FAIL("codeindex", "grow merkle child list");
        f->kids = nb;
        f->cap = ncap;
    }
    f->kids[f->nkids++] = *c;
    return true;
}

static bool merkle_push_node(struct merkle_build *b,
                             const struct merkle_node_rec *nd)
{
    if (b->nnodes == b->cap_nodes) {
        uint32_t ncap = b->cap_nodes ? b->cap_nodes * 2 : 256;
        void *nb = zcl_realloc(b->nodes, (size_t)ncap * sizeof(*b->nodes),
                               "ci_merkle_nodes");
        if (!nb) LOG_FAIL("codeindex", "grow merkle node list");
        b->nodes = nb;
        b->cap_nodes = ncap;
    }
    b->nodes[b->nnodes++] = *nd;
    return true;
}

/* Turn the top frame into a node. Reuse is the whole point: if this directory
 * has the same number of direct children as the snapshot recorded and not one
 * of them changed digest, its digest is unchanged by construction — no hash. */
static bool merkle_finalize_frame(struct merkle_build *b,
                                  struct merkle_node_rec *out, bool *out_dirty)
{
    struct merkle_frame *f = &b->frames[b->depth - 1];
    const struct merkle_node_rec *prev =
        b->use_prev ? merkle_find_node(b->prev.nodes, b->prev.nnodes, f->path)
                    : NULL;

    memset(out, 0, sizeof(*out));
    ci_cpy(out->path, sizeof(out->path), f->path);
    out->direct_children = f->nkids;
    out->file_count = f->file_count;
    out->dir_count = f->dir_count;
    out->total_bytes = f->total_bytes;

    if (prev && prev->direct_children == f->nkids && !f->dirty) {
        out->digest = prev->digest;
        b->cost.nodes_reused++;
        *out_dirty = false;
    } else {
        merkle_node_digest(f->path, f->kids, f->nkids, &out->digest);
        b->cost.nodes_hashed++;
        *out_dirty = !(prev && memcmp(prev->digest.bytes, out->digest.bytes,
                                      32) == 0);
    }
    return true;
}

static const char *merkle_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* Finalize the top frame and fold it into its parent as a directory child. */
static bool merkle_pop_frame(struct merkle_build *b)
{
    struct merkle_node_rec nd;
    bool dirty = false;
    if (!merkle_finalize_frame(b, &nd, &dirty)) return false;
    if (!merkle_push_node(b, &nd)) return false;
    struct merkle_frame *f = &b->frames[b->depth - 1];
    free(f->kids);
    memset(f, 0, sizeof(*f));
    b->depth--;
    struct merkle_frame *parent = &b->frames[b->depth - 1];
    struct merkle_child c;
    memset(&c, 0, sizeof(c));
    ci_cpy(c.name, sizeof(c.name), merkle_basename(nd.path));
    c.kind = 1;
    c.digest = nd.digest;
    if (!merkle_frame_push_child(parent, &c)) return false;
    parent->dirty = parent->dirty || dirty;
    parent->file_count += nd.file_count;
    parent->dir_count += nd.dir_count + 1;
    parent->total_bytes += nd.total_bytes;
    return true;
}

/* Is directory `dir` inside (or equal to) frame path `base`? */
static bool merkle_within(const char *base, const char *dir)
{
    if (!base[0]) return true;
    size_t n = strlen(base);
    return strncmp(dir, base, n) == 0 && (dir[n] == '\0' || dir[n] == '/');
}

static bool merkle_push_frame(struct merkle_build *b, const char *path)
{
    if (b->depth >= MERKLE_MAX_DEPTH)
        LOG_FAIL("codeindex", "merkle directory nesting past %d: %s",
                 MERKLE_MAX_DEPTH, path);
    if (strlen(merkle_basename(path)) >= MERKLE_NAME_MAX)
        LOG_FAIL("codeindex", "merkle directory name exceeds %d bytes: %s",
                 MERKLE_NAME_MAX - 1, path);
    struct merkle_frame *f = &b->frames[b->depth];
    memset(f, 0, sizeof(*f));
    ci_cpy(f->path, sizeof(f->path), path);
    b->depth++;
    return true;
}

static bool merkle_enter_dir(struct merkle_build *b, const char *dir)
{
    while (b->depth > 1 && !merkle_within(b->frames[b->depth - 1].path, dir)) {
        if (!merkle_pop_frame(b)) return false;
    }
    while (strcmp(b->frames[b->depth - 1].path, dir) != 0) {
        const char *base = b->frames[b->depth - 1].path;
        size_t off = base[0] ? strlen(base) + 1 : 0;
        const char *seg = dir + off;
        const char *end = strchr(seg, '/');
        size_t seglen = end ? (size_t)(end - seg) : strlen(seg);
        char next[256];
        if (off + seglen >= sizeof(next))
            LOG_FAIL("codeindex", "merkle directory path too long: %s", dir);
        memcpy(next, dir, off + seglen);
        next[off + seglen] = '\0';
        if (!merkle_push_frame(b, next)) return false;
    }
    return true;
}

static bool merkle_add_leaf(struct merkle_build *b,
                            const struct merkle_leaf_rec *l)
{
    if (b->nleaves == b->cap_leaves) {
        uint32_t ncap = b->cap_leaves ? b->cap_leaves * 2 : 1024;
        void *nb = zcl_realloc(b->leaves, (size_t)ncap * sizeof(*b->leaves),
                               "ci_merkle_leaves");
        if (!nb) LOG_FAIL("codeindex", "grow merkle leaf list");
        b->leaves = nb;
        b->cap_leaves = ncap;
    }
    b->leaves[b->nleaves++] = *l;
    return true;
}

static bool merkle_file_cb(const char *relpath, const struct stat *st,
                           void *user)
{
    struct merkle_build *b = user;
    if (b->err) return false;
    if (strlen(relpath) >= 256) {
        b->err = true;
        LOG_FAIL("codeindex", "merkle path exceeds 255 bytes: %s", relpath);
    }
    /* A truncated basename would let two distinct siblings hash identically,
     * so refuse rather than silently collide. */
    if (strlen(merkle_basename(relpath)) >= MERKLE_NAME_MAX) {
        b->err = true;
        LOG_FAIL("codeindex", "merkle file name exceeds %d bytes: %s",
                 MERKLE_NAME_MAX - 1, relpath);
    }

    struct merkle_leaf_rec leaf;
    memset(&leaf, 0, sizeof(leaf));
    ci_cpy(leaf.path, sizeof(leaf.path), relpath);

    struct merkle_stat_key live = {
        .dev = (uint64_t)st->st_dev,
        .ino = (uint64_t)st->st_ino,
        .size = (uint64_t)st->st_size,
        .mtime_sec = (uint64_t)st->st_mtim.tv_sec,
        .mtime_nsec = (uint64_t)st->st_mtim.tv_nsec,
        .ctime_sec = (uint64_t)st->st_ctim.tv_sec,
        .ctime_nsec = (uint64_t)st->st_ctim.tv_nsec,
    };
    const struct merkle_leaf_rec *prev =
        b->use_prev ? merkle_find_leaf(b->prev.leaves, b->prev.nleaves, relpath)
                    : NULL;
    if (b->use_prev && !prev)
        b->cost.inventory_changed = true;
    if (prev && memcmp(&prev->key, &live, sizeof(live)) == 0) {
        leaf.digest = prev->digest;
        leaf.size = prev->size;
        leaf.key = prev->key;
        leaf.dirty = false;
        b->cost.leaves_reused++;
    } else {
        bool found = false;
        if (!merkle_leaf_digest(b->root, relpath, &leaf.digest, &leaf.size,
                                &leaf.key, &found) || !found) {
            b->err = true;
            return false;
        }
        b->cost.files_read++;
        b->cost.bytes_read += leaf.size;
        /* A re-read whose digest matches the snapshot (a bare `touch`) is not
         * a change: the leaf is clean and every ancestor keeps its digest. */
        leaf.dirty = !(prev && memcmp(prev->digest.bytes, leaf.digest.bytes,
                                      32) == 0);
    }
    char dir[256];
    const char *slash = strrchr(relpath, '/');
    if (slash) {
        size_t dlen = (size_t)(slash - relpath);
        memcpy(dir, relpath, dlen);
        dir[dlen] = '\0';
    } else {
        dir[0] = '\0';
    }
    if (!merkle_enter_dir(b, dir)) { b->err = true; return false; }

    struct merkle_frame *f = &b->frames[b->depth - 1];
    struct merkle_child c;
    memset(&c, 0, sizeof(c));
    ci_cpy(c.name, sizeof(c.name), merkle_basename(relpath));
    c.kind = 0;
    c.digest = leaf.digest;
    if (!merkle_frame_push_child(f, &c)) { b->err = true; return false; }
    f->dirty = f->dirty || leaf.dirty;
    f->file_count++;
    f->total_bytes += leaf.size;

    if (!merkle_add_leaf(b, &leaf)) { b->err = true; return false; }
    return true;
}

static void merkle_build_release(struct merkle_build *b)
{
    for (uint32_t i = 0; i < MERKLE_MAX_DEPTH; i++) free(b->frames[i].kids);
    merkle_snapshot_free(&b->prev);
}

static struct ci_merkle *merkle_run(const char *root, bool use_snapshot,
                                    struct ci_merkle_cost *cost_out)
{
    if (!root || !root[0])
        LOG_NULL("codeindex", "null root to merkle build");

    struct merkle_build b;
    memset(&b, 0, sizeof(b));
    b.root = root;

    if (use_snapshot) {
        bool found = false;
        if (!merkle_snapshot_load(root, &b.prev, &found)) {
            merkle_build_release(&b);
            LOG_NULL("codeindex", "load merkle snapshot failed");
        }
        b.use_prev = found;
        b.cost.snapshot_used = found;
    }

    if (!merkle_push_frame(&b, "")) {
        merkle_build_release(&b);
        LOG_NULL("codeindex", "seed merkle root frame");
    }
    if (!ci_enumerate_sources(root, merkle_file_cb, &b) || b.err) {
        merkle_build_release(&b);
        free(b.leaves);
        free(b.nodes);
        LOG_NULL("codeindex", "merkle source enumeration failed root=%s", root);
    }
    if (b.use_prev && b.nleaves != b.prev.nleaves)
        b.cost.inventory_changed = true;
    while (b.depth > 1) {
        if (!merkle_pop_frame(&b)) {
            merkle_build_release(&b);
            free(b.leaves);
            free(b.nodes);
            LOG_NULL("codeindex", "merkle frame finalize failed");
        }
    }
    struct merkle_node_rec root_node;
    bool root_dirty = false;
    if (!merkle_finalize_frame(&b, &root_node, &root_dirty) ||
        !merkle_push_node(&b, &root_node)) {
        merkle_build_release(&b);
        free(b.leaves);
        free(b.nodes);
        LOG_NULL("codeindex", "merkle root finalize failed");
    }

    struct ci_merkle *m = zcl_malloc(sizeof(*m), "ci_merkle");
    if (!m) {
        merkle_build_release(&b);
        free(b.leaves);
        free(b.nodes);
        LOG_NULL("codeindex", "allocate merkle handle");
    }
    memset(m, 0, sizeof(*m));
    m->leaves = b.leaves;
    m->nleaves = b.nleaves;
    m->nodes = b.nodes;
    m->nnodes = b.nnodes;
    m->root = root_node.digest;
    qsort(m->nodes, m->nnodes, sizeof(*m->nodes), merkle_node_cmp);

    b.cost.files_total = b.nleaves;
    b.cost.bytes_total = root_node.total_bytes;
    b.cost.nodes_total = b.nnodes;
    /* Persist only when something actually moved: a repeat refresh over an
     * untouched tree writes nothing. */
    if (use_snapshot &&
        (!b.use_prev || b.cost.files_read > 0 || b.cost.nodes_hashed > 0 ||
         b.nleaves != b.prev.nleaves || b.nnodes != b.prev.nnodes)) {
        if (!merkle_snapshot_save(root, m)) {
            /* A cache we could not publish is a slower next run, nothing more:
             * the tree in hand is already correct. */
            LOG_WARN("codeindex", "merkle snapshot not published for %s", root);
        } else {
            b.cost.snapshot_saved = true;
        }
    }

    if (cost_out) *cost_out = b.cost;
    merkle_build_release(&b);
    return m;
}

struct ci_merkle *ci_merkle_refresh(const char *root, struct ci_merkle_cost *cost)
{
    return merkle_run(root, true, cost);
}

struct ci_merkle *ci_merkle_refresh_reconciled(
    const char *root, struct ci_merkle_cost *cost)
{
    struct ci_merkle_cost first_cost = {0};
    struct ci_merkle *first = merkle_run(root, true, &first_cost);
    if (!first)
        return NULL;
    if (!first_cost.snapshot_used) {
        first_cost.full_rescan = true;
        if (cost) *cost = first_cost;
        return first;
    }
    if (!first_cost.inventory_changed) {
        if (cost) *cost = first_cost;
        return first;
    }

    ci_merkle_free(first);
    if (!ci_merkle_forget(root))
        return NULL;
    struct ci_merkle_cost cold_cost = {0};
    struct ci_merkle *cold = merkle_run(root, true, &cold_cost);
    if (!cold)
        return NULL;
    cold_cost.inventory_changed = true;
    cold_cost.full_rescan = true;
    if (cost) *cost = cold_cost;
    return cold;
}

struct ci_merkle *ci_merkle_build_cold(const char *root,
                                       struct ci_merkle_cost *cost)
{
    return merkle_run(root, false, cost);
}

void ci_merkle_free(struct ci_merkle *m)
{
    if (!m) return;
    free(m->leaves);
    free(m->nodes);
    free(m);
}

/* ── queries ─────────────────────────────────────────────────────────── */

static void merkle_fill_node(const struct merkle_node_rec *src,
                             struct ci_merkle_node *out)
{
    memset(out, 0, sizeof(*out));
    ci_cpy(out->path, sizeof(out->path), src->path);
    out->digest = src->digest;
    out->file_count = src->file_count;
    out->dir_count = src->dir_count;
    out->direct_children = src->direct_children;
    out->total_bytes = src->total_bytes;
}

/* "", ".", and "/" all name the whole tree; a trailing slash is trimmed. */
static void merkle_norm_dir(const char *in, char out[256])
{
    if (!in || !in[0] || strcmp(in, ".") == 0 || strcmp(in, "/") == 0 ||
        strcmp(in, "./") == 0) {
        out[0] = '\0';
        return;
    }
    ci_cpy(out, 256, in);
    size_t n = strlen(out);
    while (n > 0 && out[n - 1] == '/') out[--n] = '\0';
    if (n > 2 && out[0] == '.' && out[1] == '/') memmove(out, out + 2, n - 1);
}

bool ci_merkle_root(const struct ci_merkle *m, struct ci_merkle_node *out)
{
    if (!m || !out) LOG_FAIL("codeindex", "null arg to merkle_root");
    const struct merkle_node_rec *nd = merkle_find_node(m->nodes, m->nnodes, "");
    if (!nd) LOG_FAIL("codeindex", "merkle tree has no root node");
    merkle_fill_node(nd, out);
    return true;
}

bool ci_merkle_node(const struct ci_merkle *m, const char *dirpath,
                    struct ci_merkle_node *out, bool *found)
{
    if (!m || !out || !found) LOG_FAIL("codeindex", "null arg to merkle_node");
    *found = false;
    char norm[256];
    merkle_norm_dir(dirpath, norm);
    const struct merkle_node_rec *nd =
        merkle_find_node(m->nodes, m->nnodes, norm);
    if (!nd) return true;
    merkle_fill_node(nd, out);
    *found = true;
    return true;
}

bool ci_merkle_leaf(const struct ci_merkle *m, const char *filepath,
                    struct ci_merkle_leaf *out, bool *found)
{
    if (!m || !out || !found) LOG_FAIL("codeindex", "null arg to merkle_leaf");
    *found = false;
    if (!filepath || !filepath[0]) return true;
    char norm[256];
    merkle_norm_dir(filepath, norm);
    const struct merkle_leaf_rec *l =
        merkle_find_leaf(m->leaves, m->nleaves, norm);
    if (!l) return true;
    memset(out, 0, sizeof(*out));
    ci_cpy(out->path, sizeof(out->path), l->path);
    out->digest = l->digest;
    out->size = l->size;
    *found = true;
    return true;
}

static bool merkle_relative_path_valid(const char *path)
{
    if (!path || !path[0] || path[0] == '/' || strlen(path) >= 256)
        return false;
    const char *part = path;
    while (*part) {
        const char *slash = strchr(part, '/');
        size_t len = slash ? (size_t)(slash - part) : strlen(part);
        if (len == 0 || (len == 1 && part[0] == '.') ||
            (len == 2 && part[0] == '.' && part[1] == '.'))
            return false;
        if (!slash)
            break;
        part = slash + 1;
    }
    return true;
}

bool ci_merkle_hash_changed_leaf(const char *root, const char *filepath,
                                 struct ci_merkle_leaf *out, bool *found)
{
    if (!root || !root[0] || !merkle_relative_path_valid(filepath) || !out ||
        !found)
        LOG_FAIL("codeindex", "invalid changed-leaf hash request");
    struct merkle_stat_key key;
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->path, sizeof(out->path), "%s", filepath);
    return merkle_leaf_digest(root, filepath, &out->digest, &out->size, &key,
                              found);
}

int ci_merkle_child_dirs(const struct ci_merkle *m, const char *dirpath,
                         struct ci_merkle_node *out, int cap)
{
    if (!m || cap < 0) LOG_ERR("codeindex", "bad arg to merkle_child_dirs");
    char norm[256];
    merkle_norm_dir(dirpath, norm);
    size_t plen = strlen(norm);
    int n = 0;
    /* The node array is sorted by full path, and for two sibling directories
     * that order equals the documented child order (both keys are
     * name + '/'), so a prefix scan emits children in the canonical order. */
    for (uint32_t i = 0; i < m->nnodes; i++) {
        const char *p = m->nodes[i].path;
        if (plen) {
            if (strncmp(p, norm, plen) != 0 || p[plen] != '/') continue;
            if (strchr(p + plen + 1, '/')) continue;
        } else {
            if (!p[0] || strchr(p, '/')) continue;
        }
        if (out && n < cap) merkle_fill_node(&m->nodes[i], &out[n]);
        n++;
    }
    return n;
}

void ci_merkle_hex(const struct zcl_sha3_digest *d, char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    if (!out) return;
    if (!d) { out[0] = '\0'; return; }
    for (int i = 0; i < 32; i++) {
        out[i * 2] = hexd[(d->bytes[i] >> 4) & 0xf];
        out[i * 2 + 1] = hexd[d->bytes[i] & 0xf];
    }
    out[64] = '\0';
}
