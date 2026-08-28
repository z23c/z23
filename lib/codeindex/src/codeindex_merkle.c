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

#include "base/serialize_le.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "platform/positioned_file.h"

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#endif
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

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

#if !defined(_WIN32)
static const char merkle_snapshot_format[] =
    "zcl.codeindex.source_tree.merkle.v2";
static const char merkle_snapshot_name[] = "source_tree.merkle";
static const char merkle_snapshot_seal_domain[] =
    "zcl.codeindex.source_tree.merkle.seal.v1";
#endif

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

/* One direct child of a directory node — the unit the interior preimage below
 * consumes. It is declared in the public header (struct ci_merkle_proof_child)
 * rather than here because an inclusion proof must carry these verbatim: the
 * builder and the proof verifier hash the SAME type through the SAME function
 * (merkle_node_digest), so there is no second copy of the rule to drift. */
_Static_assert((int)CI_MERKLE_PROOF_NAME_MAX == (int)MERKLE_NAME_MAX,
               "proof child name bound must equal the builder's name bound");
_Static_assert((int)CI_MERKLE_PROOF_MAX_LEVELS == (int)MERKLE_MAX_DEPTH,
               "a proof must be able to hold every level the build can nest");
_Static_assert(CI_MERKLE_KIND_FILE == 0 && CI_MERKLE_KIND_DIR == 1,
               "kind numbering is hashed; it cannot be renumbered");
/* The wire ceiling must exceed the largest proof the other two bounds can
 * express, or encode() could refuse a legal proof. Worst case, exactly:
 *   domain + kind + (2 + 255) path
 *   + 8 (nlevels, nchildren)
 *   + LEVELS   * (2 + 255 path + 4 nchildren + 4 index)
 *   + CHILDREN * (1 kind + 2 + (NAME_MAX-1) name + 32 digest)
 * Written out rather than rounded, so raising a bound cannot quietly outgrow
 * the ceiling. */
_Static_assert(sizeof("zcl.codeindex.merkle.proof.v1") + 1 + 2 + 255 + 8 +
                       (size_t)CI_MERKLE_PROOF_MAX_LEVELS * (2 + 255 + 4 + 4) +
                       (size_t)CI_MERKLE_PROOF_MAX_CHILDREN *
                           (1 + 2 + (CI_MERKLE_PROOF_NAME_MAX - 1) + 32) <
                   (size_t)CI_MERKLE_PROOF_WIRE_MAX,
               "CI_MERKLE_PROOF_WIRE_MAX is below the largest expressible proof");

/* THE ordering rule, in one place. A directory's direct children are ordered by
 * strcmp over this key: a file's own name, a directory's name followed by '/'.
 *
 * That key order is identical to strcmp order over the children's full
 * repo-relative paths — which is the order ci_enumerate_sources already emits —
 * and the reason has nothing to do with where '/' sits in ASCII. It sits at
 * 0x2f: above '.' (0x2e), but BELOW every character legal in a C identifier
 * ('0' 0x30, 'A' 0x41, '_' 0x5f, 'a' 0x61). An earlier version of this comment
 * asserted the opposite; since this is the ONE normative statement of the rule,
 * a second implementation reasoning from that premise would have ordered
 * `ab_z.c` against a directory `ab` backwards and minted a different root.
 *
 * The real reason is a prefix property, and it holds for any character set: a
 * child's key is a PREFIX of every full path that child contributes to the
 * stream — "name" for a file, whose only path is "name", and "name/" for a
 * directory, all of whose paths begin "name/". Distinct children have distinct
 * keys, so the first position at which two children's paths differ is a
 * position both keys already cover, and strcmp decides the key comparison and
 * the path comparison identically. Concretely, `ab.c`, `ab/` and `ab_z.c` in
 * one directory give keys "ab.c" < "ab/" < "ab_z.c", and their full paths sort
 * in exactly that order — even though '/' is below '_'.
 *
 * The builder therefore appends children in stream order, needs no second
 * sort, and cannot disagree with the rule as documented. */
static void merkle_child_key(const struct ci_merkle_proof_child *c,
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
static bool merkle_child_in_order(const struct ci_merkle_proof_child *prev,
                                  const struct ci_merkle_proof_child *next)
{
    char a[MERKLE_NAME_MAX + 2], bkey[MERKLE_NAME_MAX + 2];
    merkle_child_key(prev, a);
    merkle_child_key(next, bkey);
    return strcmp(a, bkey) < 0;
}

static void merkle_node_digest(const char *path, const struct ci_merkle_proof_child *kids,
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
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(&file, root, relpath)) {
        memset(out, 0, sizeof(*out));
        *out_size = 0;
        memset(out_key, 0, sizeof(*out_key));
        return true;
    }
    if (!platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        LOG_FAIL("codeindex", "merkle stat leaf failed path=%s", relpath);
    }

    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t tag = MERKLE_TAG_LEAF;
    static const char domain[] = "zcl.codeindex.merkle.leaf.v1";
    sha3_256_write(&sha, &tag, 1);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    merkle_write_u64le(&sha, before.size);

    unsigned char buf[64 * 1024];
    uint64_t total = 0;
    bool ok = true;
    while (total < before.size) {
        size_t want = before.size - total < sizeof(buf)
            ? (size_t)(before.size - total) : sizeof(buf);
        int64_t got = platform_positioned_file_read(&file, buf, want, total);
        if (got < 0) { ok = false; break; }
        if (got == 0) break;
        sha3_256_write(&sha, buf, (size_t)got);
        total += (uint64_t)got;
    }
    if (ok && (!platform_positioned_file_snapshot(&file, &after) ||
               total != before.size || before.size != after.size ||
               before.volume != after.volume || before.file_low != after.file_low ||
               before.file_high != after.file_high ||
               before.modified_seconds != after.modified_seconds ||
               before.modified_nanoseconds != after.modified_nanoseconds ||
               before.changed_seconds != after.changed_seconds ||
               before.changed_nanoseconds != after.changed_nanoseconds))
        ok = false;
    platform_positioned_file_close(&file);
    if (!ok)
        LOG_FAIL("codeindex", "merkle read leaf failed path=%s", relpath);

    sha3_256_finalize(&sha, out->bytes);
    *out_size = total;
    out_key->dev = after.volume;
    out_key->ino = after.file_low;
    out_key->size = after.size;
    out_key->mtime_sec = (uint64_t)after.modified_seconds;
    out_key->mtime_nsec = after.modified_nanoseconds;
    out_key->ctime_sec = (uint64_t)after.changed_seconds;
    out_key->ctime_nsec = after.changed_nanoseconds;
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

#if !defined(_WIN32)
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
#endif

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

#if !defined(_WIN32)
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
#endif

/* Open <root>/.codeindex as a directory capability. `create` mkdirs it. Same
 * owner-controlled posture codeindex_build.c requires of the same directory: a
 * cache another user can write is a cache that can answer for us. */
#if defined(_WIN32)
static bool merkle_snapshot_load(const char *root, struct merkle_snapshot *out,
                                 bool *found)
{
    (void)root;
    *found = false;
    memset(out, 0, sizeof(*out));
    return true;
}

static bool merkle_snapshot_save(const char *root, const struct ci_merkle *m)
{
    (void)root;
    (void)m;
    return false;
}

bool ci_merkle_forget(const char *root)
{
    (void)root;
    return false;
}
#else
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
#endif

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
    struct ci_merkle_proof_child *kids;
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
                                    const struct ci_merkle_proof_child *c)
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
    struct ci_merkle_proof_child c;
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
#if defined(_WIN32)
        .mtime_sec = (uint64_t)st->st_mtime,
        .mtime_nsec = 0,
        .ctime_sec = (uint64_t)st->st_ctime,
        .ctime_nsec = 0,
#else
        .mtime_sec = (uint64_t)st->st_mtim.tv_sec,
        .mtime_nsec = (uint64_t)st->st_mtim.tv_nsec,
        .ctime_sec = (uint64_t)st->st_ctim.tv_sec,
        .ctime_nsec = (uint64_t)st->st_ctim.tv_nsec,
#endif
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
    struct ci_merkle_proof_child c;
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

/* ── inclusion proofs ──────────────────────────────────────────────────
 * The generator reads the tree; the verifier does not — it holds a proof, a
 * claimed digest, and a root, and nothing else. Every parent digest it
 * recomputes goes through merkle_node_digest(), the one function that states
 * the interior preimage, so builder and verifier cannot drift apart. See the
 * header for the size consequence of a non-binary tree; it is real and it is
 * bounded here rather than hidden. */

static const char merkle_proof_wire_domain[] = "zcl.codeindex.merkle.proof.v1";

struct ci_merkle_proof *ci_merkle_proof_alloc(void)
{
    struct ci_merkle_proof *p = zcl_malloc(sizeof(*p), "ci_merkle_proof");
    if (!p)
        LOG_NULL("codeindex", "allocate merkle proof (%zu bytes)", sizeof(*p));
    memset(p, 0, sizeof(*p));
    return p;
}

void ci_merkle_proof_free(struct ci_merkle_proof *p)
{
    free(p);
}

/* The parent directory of a repo-relative path; "" for a top-level entry. */
static void merkle_dirname(const char *path, char out[256])
{
    const char *slash = strrchr(path, '/');
    if (!slash) {
        out[0] = '\0';
        return;
    }
    size_t n = (size_t)(slash - path);
    if (n > 255) n = 255;
    memcpy(out, path, n);
    out[n] = '\0';
}

/* `path`'s basename iff `path` is a DIRECT child of `dir`, else NULL. */
static const char *merkle_direct_child(const char *path, const char *dir,
                                       size_t dlen)
{
    if (dlen) {
        if (strncmp(path, dir, dlen) != 0 || path[dlen] != '/') return NULL;
        const char *name = path + dlen + 1;
        if (!name[0] || strchr(name, '/')) return NULL;
        return name;
    }
    if (!path[0] || strchr(path, '/')) return NULL;
    return path;
}

static int merkle_child_key_cmp(const void *a, const void *b)
{
    char ka[MERKLE_NAME_MAX + 2], kb[MERKLE_NAME_MAX + 2];
    merkle_child_key(a, ka);
    merkle_child_key(b, kb);
    return strcmp(ka, kb);
}

/* Rebuild one directory node's direct-child list from the tree's flat leaf and
 * node arrays, then PROVE the rebuild is faithful by re-deriving that node's
 * own digest from it and comparing. A proof is worth exactly as much as this
 * step, so it is checked rather than asserted; a mismatch is a hard failure,
 * not a proof that happens not to verify. Running out of arena is likewise
 * loud — a short child list would silently describe a different directory. */
static bool merkle_collect_children(const struct ci_merkle *m, const char *dir,
                                    struct ci_merkle_proof_child *out,
                                    uint32_t cap, uint32_t *out_n)
{
    const struct merkle_node_rec *nd =
        merkle_find_node(m->nodes, m->nnodes, dir);
    if (!nd)
        LOG_FAIL("codeindex", "merkle proof: no directory node for '%s'", dir);

    size_t dlen = strlen(dir);
    uint32_t n = 0;
    for (uint32_t i = 0; i < m->nleaves; i++) {
        const char *name = merkle_direct_child(m->leaves[i].path, dir, dlen);
        if (!name) continue;
        if (n >= cap)
            LOG_FAIL("codeindex",
                     "merkle proof: '%s' needs more than %u sibling records "
                     "(budget %u); proof refused rather than truncated",
                     dir, nd->direct_children, CI_MERKLE_PROOF_MAX_CHILDREN);
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].name, sizeof(out[n].name), name);
        out[n].kind = CI_MERKLE_KIND_FILE;
        out[n].digest = m->leaves[i].digest;
        n++;
    }
    for (uint32_t i = 0; i < m->nnodes; i++) {
        const char *name = merkle_direct_child(m->nodes[i].path, dir, dlen);
        if (!name) continue;
        if (n >= cap)
            LOG_FAIL("codeindex",
                     "merkle proof: '%s' needs more than %u sibling records "
                     "(budget %u); proof refused rather than truncated",
                     dir, nd->direct_children, CI_MERKLE_PROOF_MAX_CHILDREN);
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].name, sizeof(out[n].name), name);
        out[n].kind = CI_MERKLE_KIND_DIR;
        out[n].digest = m->nodes[i].digest;
        n++;
    }
    qsort(out, n, sizeof(*out), merkle_child_key_cmp);
    for (uint32_t i = 1; i < n; i++) {
        if (!merkle_child_in_order(&out[i - 1], &out[i]))
            LOG_FAIL("codeindex",
                     "merkle proof: duplicate or unordered child key in '%s'",
                     dir);
    }
    if (n != nd->direct_children)
        LOG_FAIL("codeindex",
                 "merkle proof: rebuilt %u direct children of '%s', tree says %u",
                 n, dir, nd->direct_children);
    struct zcl_sha3_digest check;
    merkle_node_digest(dir, out, n, &check);
    if (memcmp(check.bytes, nd->digest.bytes, 32) != 0)
        LOG_FAIL("codeindex",
                 "merkle proof: rebuilt children of '%s' do not reproduce its "
                 "digest", dir);
    *out_n = n;
    return true;
}

bool ci_merkle_prove(const struct ci_merkle *m, const char *path,
                     struct ci_merkle_proof *out,
                     struct zcl_sha3_digest *out_digest, bool *found)
{
    if (!m || !out || !found) LOG_FAIL("codeindex", "null arg to merkle_prove");
    *found = false;
    memset(out, 0, sizeof(*out));

    char norm[256];
    merkle_norm_dir(path, norm);

    struct zcl_sha3_digest target;
    uint8_t kind;
    const struct merkle_leaf_rec *lf =
        norm[0] ? merkle_find_leaf(m->leaves, m->nleaves, norm) : NULL;
    if (lf) {
        target = lf->digest;
        kind = CI_MERKLE_KIND_FILE;
    } else {
        const struct merkle_node_rec *nd =
            merkle_find_node(m->nodes, m->nnodes, norm);
        if (!nd) return true; /* absent is an answer, not a failure */
        target = nd->digest;
        kind = CI_MERKLE_KIND_DIR;
    }

    ci_cpy(out->path, sizeof(out->path), norm);
    out->kind = kind;

    char cur[256];
    ci_cpy(cur, sizeof(cur), norm);
    while (cur[0]) {
        if (out->nlevels >= CI_MERKLE_PROOF_MAX_LEVELS)
            LOG_FAIL("codeindex",
                     "merkle proof for '%s' would need more than %d levels",
                     norm, CI_MERKLE_PROOF_MAX_LEVELS);
        char parent[256];
        merkle_dirname(cur, parent);
        struct ci_merkle_proof_level *lv = &out->level[out->nlevels];
        ci_cpy(lv->path, sizeof(lv->path), parent);
        lv->first_child = out->nchildren;
        uint32_t n = 0;
        if (!merkle_collect_children(
                m, parent, &out->children[out->nchildren],
                (uint32_t)(CI_MERKLE_PROOF_MAX_CHILDREN - out->nchildren), &n))
            return false;
        lv->nchildren = n;

        const char *want = merkle_basename(cur);
        uint8_t want_kind =
            out->nlevels == 0 ? kind : (uint8_t)CI_MERKLE_KIND_DIR;
        bool hit = false;
        for (uint32_t i = 0; i < n; i++) {
            const struct ci_merkle_proof_child *c =
                &out->children[lv->first_child + i];
            if (c->kind == want_kind && strcmp(c->name, want) == 0) {
                lv->index = i;
                hit = true;
                break;
            }
        }
        if (!hit)
            LOG_FAIL("codeindex", "merkle proof: '%s' is not a child of '%s'",
                     cur, parent);
        out->nchildren += n;
        out->nlevels++;
        ci_cpy(cur, sizeof(cur), parent);
    }

    /* Refuse to hand out a proof we cannot check ourselves. This is the one
     * place the generator and the verifier meet, and it runs on every proof. */
    bool self_ok = false;
    if (!ci_merkle_proof_verify(out, &target, &m->root, &self_ok)) return false;
    if (!self_ok) {
        memset(out, 0, sizeof(*out));
        LOG_FAIL("codeindex",
                 "merkle proof for '%s' failed its own verification", norm);
    }
    if (out_digest) *out_digest = target;
    *found = true;
    return true;
}

/* Is a fixed-size char field NUL-terminated inside its own storage? Everything
 * downstream uses strcmp/strlen on these, so this is checked before any of it. */
static bool merkle_field_terminated(const char *f, size_t cap)
{
    return memchr(f, '\0', cap) != NULL;
}

/* Is `p` a repo-relative path in the ONE shape the builder mints? "" is the
 * root; anything else is a '/'-separated list of non-empty segments, each
 * shorter than MERKLE_NAME_MAX, none of them "." or "..", with no leading
 * slash, no trailing slash, and no empty segment.
 *
 * This is not decoration, it closes a real hole. The verifier reconstructs the
 * proven path by walking merkle_dirname()/merkle_basename() upward, and those
 * two functions map BOTH "lib" and "/lib" to the same (parent "", basename
 * "lib") pair. Every deeper case is already closed by the digest chain — a
 * level's path is hashed verbatim, so "/lib/net" can never reproduce the digest
 * minted for "lib/net" — but the TOPMOST dirname() collapse is invisible to the
 * hash, because the parent it produces ("") is the same either way. Without
 * this check a proof for any top-level entry re-labelled with a leading slash
 * verifies against the same root with the same claimed digest: two distinct
 * wire images, two distinct reported paths, one accepted answer. That is
 * exactly the input ambiguity this API exists to remove, so the verifier
 * rejects any path that is not the canonical one.
 *
 * Applied to child names too, where it additionally means non-empty, no '/',
 * and inside the name bound — one rule instead of four scattered predicates. */
static bool merkle_path_canonical(const char *p)
{
    if (!p[0]) return true; /* the root */
    size_t seg = 0;
    for (const char *c = p;; c++) {
        if (*c != '/' && *c != '\0') {
            seg++;
            continue;
        }
        if (seg == 0 || seg >= MERKLE_NAME_MAX) return false;
        const char *s = c - seg;
        if (seg == 1 && s[0] == '.') return false;
        if (seg == 2 && s[0] == '.' && s[1] == '.') return false;
        if (*c == '\0') return true;
        seg = 0;
    }
}

bool ci_merkle_proof_verify(const struct ci_merkle_proof *p,
                            const struct zcl_sha3_digest *claimed,
                            const struct zcl_sha3_digest *root, bool *ok)
{
    if (!p || !claimed || !root || !ok)
        LOG_FAIL("codeindex", "null arg to merkle_proof_verify");
    *ok = false;

    if (p->nlevels > CI_MERKLE_PROOF_MAX_LEVELS ||
        p->nchildren > CI_MERKLE_PROOF_MAX_CHILDREN ||
        (p->kind != CI_MERKLE_KIND_FILE && p->kind != CI_MERKLE_KIND_DIR) ||
        !merkle_field_terminated(p->path, sizeof(p->path)) ||
        !merkle_path_canonical(p->path))
        return true;

    /* The root proves itself: no levels, and the claim IS the trusted root. */
    if (!p->path[0]) {
        if (p->kind != CI_MERKLE_KIND_DIR || p->nlevels != 0 ||
            p->nchildren != 0)
            return true;
        *ok = memcmp(claimed->bytes, root->bytes, 32) == 0;
        return true;
    }
    if (p->nlevels == 0) return true;

    char cur[256];
    memcpy(cur, p->path, sizeof(cur));
    struct zcl_sha3_digest acc = *claimed;
    uint8_t kind = p->kind;

    uint32_t run = 0;
    for (uint32_t i = 0; i < p->nlevels; i++) {
        const struct ci_merkle_proof_level *lv = &p->level[i];
        if (!merkle_field_terminated(lv->path, sizeof(lv->path)) ||
            !merkle_path_canonical(lv->path))
            return true;
        if (lv->nchildren == 0 || lv->index >= lv->nchildren) return true;
        /* Levels tile the arena front to back with no gap and no overlap —
         * the same shape the encoder demands and the decoder produces, so the
         * set of proofs this function accepts is exactly the set that can be
         * written down. Without it a proof could verify and then refuse to
         * serialize, which is a second, quieter kind of ambiguity. */
        if (lv->first_child != run || lv->nchildren > p->nchildren - run)
            return true;
        run += lv->nchildren;

        /* Each level must be EXACTLY the parent directory of the level below,
         * which is what pins a proof to one path and only that path. */
        char parent[256];
        merkle_dirname(cur, parent);
        if (strcmp(parent, lv->path) != 0) return true;

        const struct ci_merkle_proof_child *kids = &p->children[lv->first_child];
        for (uint32_t k = 0; k < lv->nchildren; k++) {
            if (!merkle_field_terminated(kids[k].name, sizeof(kids[k].name)) ||
                !kids[k].name[0] || !merkle_path_canonical(kids[k].name) ||
                strchr(kids[k].name, '/') ||
                (kids[k].kind != CI_MERKLE_KIND_FILE &&
                 kids[k].kind != CI_MERKLE_KIND_DIR))
                return true;
            /* Canonical order is part of the preimage. A reordered list would
             * also fail at the root; rejecting it here says WHY. */
            if (k && !merkle_child_in_order(&kids[k - 1], &kids[k])) return true;
        }

        const struct ci_merkle_proof_child *slot = &kids[lv->index];
        if (slot->kind != kind) return true;
        if (strcmp(slot->name, merkle_basename(cur)) != 0) return true;
        if (memcmp(slot->digest.bytes, acc.bytes, 32) != 0) return true;

        merkle_node_digest(lv->path, kids, lv->nchildren, &acc);
        kind = CI_MERKLE_KIND_DIR;
        memcpy(cur, lv->path, sizeof(cur));
    }
    if (cur[0]) return true; /* the last level must have been the root */
    if (run != p->nchildren) return true; /* no sibling record goes unbound */
    *ok = memcmp(acc.bytes, root->bytes, 32) == 0;
    return true;
}

/* ── the wire form ─────────────────────────────────────────────────────
 * One writer serves both encode() and wire_size(): size is what encode would
 * have written, never a second formula that could disagree with it. */

struct merkle_wire {
    unsigned char *p; /* NULL = measure only */
    size_t         cap, used;
    bool           overflow;
};

static void mw_put(struct merkle_wire *w, const void *src, size_t n)
{
    if (w->overflow) return;
    if (n > w->cap - w->used) {
        w->overflow = true;
        return;
    }
    if (w->p) memcpy(w->p + w->used, src, n);
    w->used += n;
}

static void mw_u8(struct merkle_wire *w, uint8_t v)
{
    mw_put(w, &v, 1);
}

/* The one byte-order codec (lib/base/include/base/serialize_le.h), not a
 * second shift ladder. The snapshot writer above predates the canonical
 * header; nothing new here re-states the rule. */
static void mw_u32(struct merkle_wire *w, uint32_t v)
{
    uint8_t b[4];
    zcl_write_u32_le(b, v);
    mw_put(w, b, sizeof(b));
}

static bool mw_str(struct merkle_wire *w, const char *s, size_t cap)
{
    if (!merkle_field_terminated(s, cap)) return false;
    size_t len = strlen(s);
    if (len > UINT16_MAX) return false; /* unreachable: cap is 256 */
    uint8_t lb[2];
    zcl_write_u16_le(lb, (uint16_t)len);
    mw_put(w, lb, sizeof(lb));
    if (len) mw_put(w, s, len);
    return true;
}

static size_t merkle_proof_write(const struct ci_merkle_proof *p,
                                 unsigned char *out, size_t cap)
{
    if (!p || p->nlevels > CI_MERKLE_PROOF_MAX_LEVELS ||
        p->nchildren > CI_MERKLE_PROOF_MAX_CHILDREN)
        return 0;
    struct merkle_wire w = {.p = out, .cap = cap, .used = 0, .overflow = false};
    mw_put(&w, merkle_proof_wire_domain, sizeof(merkle_proof_wire_domain));
    mw_u8(&w, p->kind);
    if (!mw_str(&w, p->path, sizeof(p->path))) return 0;
    mw_u32(&w, p->nlevels);
    mw_u32(&w, p->nchildren);

    uint32_t run = 0;
    for (uint32_t i = 0; i < p->nlevels; i++) {
        const struct ci_merkle_proof_level *lv = &p->level[i];
        if (lv->first_child != run || lv->nchildren == 0 ||
            lv->index >= lv->nchildren ||
            lv->nchildren > p->nchildren - run)
            return 0;
        if (!mw_str(&w, lv->path, sizeof(lv->path))) return 0;
        mw_u32(&w, lv->nchildren);
        mw_u32(&w, lv->index);
        for (uint32_t k = 0; k < lv->nchildren; k++) {
            const struct ci_merkle_proof_child *c = &p->children[run + k];
            mw_u8(&w, c->kind);
            if (!mw_str(&w, c->name, sizeof(c->name))) return 0;
            mw_put(&w, c->digest.bytes, 32);
        }
        run += lv->nchildren;
    }
    if (run != p->nchildren || w.overflow) return 0;
    return w.used;
}

size_t ci_merkle_proof_wire_size(const struct ci_merkle_proof *p)
{
    return merkle_proof_write(p, NULL, (size_t)-1);
}

size_t ci_merkle_proof_encode(const struct ci_merkle_proof *p,
                              unsigned char *out, size_t cap)
{
    if (!out) return 0;
    return merkle_proof_write(p, out, cap);
}

/* Length-prefixed string into a fixed field, refusing anything that would not
 * fit or that hides a NUL. */
static bool merkle_take_str(struct merkle_cursor *c, char *out, size_t outcap)
{
    uint8_t lb[2] = {0};
    if (!merkle_take(c, lb, sizeof(lb))) return false;
    size_t len = zcl_read_u16_le(lb);
    if (len >= outcap) {
        c->bad = true;
        return false;
    }
    memset(out, 0, outcap);
    if (len && !merkle_take(c, out, len)) return false;
    out[len] = '\0';
    if (memchr(out, '\0', len) != NULL) {
        c->bad = true;
        return false;
    }
    return true;
}

bool ci_merkle_proof_decode(const unsigned char *in, size_t len,
                            struct ci_merkle_proof *out)
{
    if (!in || !out) LOG_FAIL("codeindex", "null arg to merkle_proof_decode");
    memset(out, 0, sizeof(*out));
    if (len <= sizeof(merkle_proof_wire_domain) ||
        len > CI_MERKLE_PROOF_WIRE_MAX)
        return false;
    if (memcmp(in, merkle_proof_wire_domain,
               sizeof(merkle_proof_wire_domain)) != 0)
        return false;

    struct merkle_cursor c = {
        .p = in + sizeof(merkle_proof_wire_domain),
        .left = len - sizeof(merkle_proof_wire_domain),
        .bad = false,
    };
    unsigned char kind = 0;
    if (!merkle_take(&c, &kind, 1) || kind > CI_MERKLE_KIND_DIR) return false;
    out->kind = kind;
    if (!merkle_take_str(&c, out->path, sizeof(out->path))) return false;
    uint32_t nlevels = merkle_take_u32(&c);
    uint32_t nchildren = merkle_take_u32(&c);
    if (c.bad || nlevels > CI_MERKLE_PROOF_MAX_LEVELS ||
        nchildren > CI_MERKLE_PROOF_MAX_CHILDREN)
        return false;

    uint32_t run = 0;
    for (uint32_t i = 0; i < nlevels; i++) {
        struct ci_merkle_proof_level *lv = &out->level[i];
        if (!merkle_take_str(&c, lv->path, sizeof(lv->path))) return false;
        uint32_t n = merkle_take_u32(&c);
        uint32_t idx = merkle_take_u32(&c);
        if (c.bad || n == 0 || idx >= n || n > nchildren - run) return false;
        lv->first_child = run;
        lv->nchildren = n;
        lv->index = idx;
        for (uint32_t k = 0; k < n; k++) {
            struct ci_merkle_proof_child *ch = &out->children[run + k];
            unsigned char ck = 0;
            if (!merkle_take(&c, &ck, 1) || ck > CI_MERKLE_KIND_DIR) return false;
            ch->kind = ck;
            if (!merkle_take_str(&c, ch->name, sizeof(ch->name))) return false;
            if (!merkle_take(&c, ch->digest.bytes, 32)) return false;
        }
        run += n;
    }
    if (c.bad || c.left != 0 || run != nchildren) return false;
    out->nlevels = nlevels;
    out->nchildren = nchildren;
    return true;
}

bool ci_merkle_proof_verify_bytes(const unsigned char *in, size_t len,
                                  const struct zcl_sha3_digest *claimed,
                                  const struct zcl_sha3_digest *root,
                                  char out_path[256], uint8_t *out_kind,
                                  bool *ok)
{
    if (!claimed || !root || !ok)
        LOG_FAIL("codeindex", "null arg to merkle_proof_verify_bytes");
    *ok = false;
    if (out_path) out_path[0] = '\0';
    if (out_kind) *out_kind = 0;
    if (!in) return true;

    struct ci_merkle_proof *p = ci_merkle_proof_alloc();
    if (!p)
        LOG_FAIL("codeindex", "allocate merkle proof for byte verification");
    bool rc = true;
    if (ci_merkle_proof_decode(in, len, p)) {
        rc = ci_merkle_proof_verify(p, claimed, root, ok);
        if (rc) {
            if (out_path) ci_cpy(out_path, 256, p->path);
            if (out_kind) *out_kind = p->kind;
        }
    }
    ci_merkle_proof_free(p);
    return rc;
}
