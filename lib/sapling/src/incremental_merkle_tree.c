/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Incremental Merkle tree — pure C23 implementation. */

#include "sapling/incremental_merkle_tree.h"
#include "sapling/pedersen_hash.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#ifdef ZCL_TESTING
#include <stdatomic.h>
#endif

/* Local shorthand for the (de)serialize/wfcheck error paths below. Each use
 * logs function/file/line plus a field name so a corrupted tree on disk
 * leaves a breadcrumb instead of a bare `false`. */
#define IMT_FAIL(field) \
    LOG_FAIL("incremental_merkle_tree", \
             "%s: %s (truncated stream or malformed tree?)", __func__, (field))

void sha256_compress_combine(const struct uint256 *a,
                              const struct uint256 *b,
                              size_t depth,
                              struct uint256 *out)
{
    (void)depth;
    struct sha256_ctx hasher;
    sha256_init(&hasher);
    sha256_write(&hasher, a->data, 32);
    sha256_write(&hasher, b->data, 32);
    sha256_finalize_no_padding(&hasher, out->data, 0);
}

void sha256_compress_uncommitted(struct uint256 *out)
{
    memset(out->data, 0, 32);
}

/* Invalidate the runtime-only root memo. Every writer of the content
 * fields (depth/has_left/left/has_right/right/has_parent/parents/
 * num_parents) must call this BEFORE or WHILE mutating, so a stale memo
 * can never survive a content change. All such writers live in this file
 * (audited via git grep over the public struct). */
static void tree_root_invalidate(struct incremental_merkle_tree *t)
{
    t->root_cached = false;
}

static void tree_init(struct incremental_merkle_tree *t, size_t depth,
                       void (*combine)(const struct uint256 *, const struct uint256 *,
                                       size_t, struct uint256 *),
                       void (*uncommitted)(struct uint256 *))
{
    assert(depth <= MAX_TREE_DEPTH);
    t->depth = depth;
    t->has_left = false;
    t->has_right = false;
    memset(&t->left, 0, sizeof(struct uint256));
    memset(&t->right, 0, sizeof(struct uint256));
    memset(t->has_parent, 0, sizeof(t->has_parent));
    memset(t->parents, 0, sizeof(t->parents));
    t->num_parents = 0;
    t->combine = combine;
    t->uncommitted = uncommitted;
    memset(&t->cached_root, 0, sizeof(struct uint256));
    tree_root_invalidate(t);
}

void sprout_tree_init(struct incremental_merkle_tree *t)
{
    tree_init(t, INCREMENTAL_MERKLE_TREE_DEPTH,
              sha256_compress_combine, sha256_compress_uncommitted);
}

static void pedersen_combine(const struct uint256 *a,
                              const struct uint256 *b,
                              size_t depth,
                              struct uint256 *out)
{
    pedersen_merkle_hash(depth, a->data, b->data, out->data);
}

static void pedersen_uncommitted(struct uint256 *out)
{
    sapling_uncommitted(out->data);
}

void sapling_testing_tree_init(struct incremental_merkle_tree *t)
{
    tree_init(t, INCREMENTAL_MERKLE_TREE_DEPTH_TESTING,
              pedersen_combine, pedersen_uncommitted);
}

void sapling_tree_init(struct incremental_merkle_tree *t)
{
    tree_init(t, SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
              pedersen_combine, pedersen_uncommitted);
}

/* Cached empty roots for Sapling Pedersen tree (depth 0..32).
 * Computed once on first use, reused for all subsequent calls. */
static struct uint256 s_sapling_empty_roots[MAX_TREE_DEPTH + 1];
static pthread_once_t s_sapling_empty_roots_once = PTHREAD_ONCE_INIT;

#ifdef ZCL_TESTING
/* See comment in pedersen_hash.c — race observability. */
_Atomic int zcl_sapling_empty_roots_body_runs_for_test = 0;

void zcl_sapling_empty_roots_reset_for_test(void)
{
    /* Reassigning a pthread_once_t is not specified by POSIX but is
     * the canonical test-only trick on glibc. Only safe when no other
     * thread is racing — the race tests join all workers first. */
    s_sapling_empty_roots_once = (pthread_once_t)PTHREAD_ONCE_INIT;
    memset(s_sapling_empty_roots, 0, sizeof(s_sapling_empty_roots));
    atomic_store(&zcl_sapling_empty_roots_body_runs_for_test, 0);
}
#endif

static void load_sapling_empty_roots(void)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&zcl_sapling_empty_roots_body_runs_for_test, 1);
#endif
    pedersen_uncommitted(&s_sapling_empty_roots[0]);
    for (size_t d = 0; d < MAX_TREE_DEPTH; d++)
        pedersen_combine(&s_sapling_empty_roots[d], &s_sapling_empty_roots[d],
                          d, &s_sapling_empty_roots[d + 1]);
}

static void ensure_sapling_empty_roots(void)
{
    pthread_once(&s_sapling_empty_roots_once, load_sapling_empty_roots);
}

/* Compute empty root at given depth. Uses cache for Pedersen trees. */
static void empty_root_at_depth(const struct incremental_merkle_tree *t,
                                 size_t depth, struct uint256 *out)
{
    if (t->combine == pedersen_combine) {
        ensure_sapling_empty_roots();
        *out = s_sapling_empty_roots[depth];
        return;
    }
    struct uint256 current;
    t->uncommitted(&current);
    for (size_t d = 0; d < depth; d++) {
        struct uint256 next;
        t->combine(&current, &current, d, &next);
        current = next;
    }
    *out = current;
}

void incremental_tree_empty_root(const struct incremental_merkle_tree *t,
                                  struct uint256 *out)
{
    empty_root_at_depth(t, t->depth, out);
}

static void filler_next(const struct incremental_merkle_tree *t,
                         const struct uint256 *filler, size_t *filler_idx,
                         size_t filler_count, size_t depth,
                         struct uint256 *out)
{
    if (*filler_idx < filler_count) {
        *out = filler[*filler_idx];
        (*filler_idx)++;
    } else {
        empty_root_at_depth(t, depth, out);
    }
}

void incremental_tree_append(struct incremental_merkle_tree *t,
                              const struct uint256 *obj)
{
    tree_root_invalidate(t);
    if (!t->has_left) {
        t->left = *obj;
        t->has_left = true;
    } else if (!t->has_right) {
        t->right = *obj;
        t->has_right = true;
    } else {
        struct uint256 combined;
        t->combine(&t->left, &t->right, 0, &combined);

        t->left = *obj;
        t->has_right = false;

        for (size_t i = 0; i < t->depth; i++) {
            if (i < t->num_parents) {
                if (t->has_parent[i]) {
                    struct uint256 next;
                    t->combine(&t->parents[i], &combined, i + 1, &next);
                    combined = next;
                    t->has_parent[i] = false;
                } else {
                    t->parents[i] = combined;
                    t->has_parent[i] = true;
                    return;
                }
            } else {
                t->parents[i] = combined;
                t->has_parent[i] = true;
                t->num_parents = i + 1;
                return;
            }
        }
    }
}

void incremental_tree_root(const struct incremental_merkle_tree *t,
                            struct uint256 *out)
{
    if (t->root_cached) {
        *out = t->cached_root;
        return;
    }

    size_t filler_idx = 0;
    struct uint256 combine_left;
    if (t->has_left) {
        combine_left = t->left;
    } else {
        filler_next(t, NULL, &filler_idx, 0, 0, &combine_left);
    }

    struct uint256 combine_right;
    if (t->has_right) {
        combine_right = t->right;
    } else {
        filler_next(t, NULL, &filler_idx, 0, 0, &combine_right);
    }

    struct uint256 root;
    t->combine(&combine_left, &combine_right, 0, &root);

    size_t d = 1;
    for (size_t i = 0; i < t->num_parents; i++) {
        struct uint256 next;
        if (t->has_parent[i]) {
            t->combine(&t->parents[i], &root, d, &next);
        } else {
            struct uint256 empty;
            empty_root_at_depth(t, d, &empty);
            t->combine(&root, &empty, d, &next);
        }
        root = next;
        d++;
    }

    while (d < t->depth) {
        struct uint256 next;
        struct uint256 empty;
        empty_root_at_depth(t, d, &empty);
        t->combine(&root, &empty, d, &next);
        root = next;
        d++;
    }

    /* Memoize for the next caller. Trees are never truly const (stack,
     * heap, or global storage), so casting away const is safe; see the
     * struct comment for the threading discipline. */
    struct incremental_merkle_tree *m = (struct incremental_merkle_tree *)t;
    m->cached_root = root;
    m->root_cached = true;

    *out = root;
}

size_t incremental_tree_size(const struct incremental_merkle_tree *t)
{
    size_t ret = 0;
    if (t->has_left) ret++;
    if (t->has_right) ret++;
    for (size_t i = 0; i < t->num_parents; i++) {
        if (t->has_parent[i])
            ret += ((size_t)1 << (i + 1));
    }
    return ret;
}

bool incremental_tree_is_complete(const struct incremental_merkle_tree *t)
{
    /* These three return-false paths are the "tree not yet complete" signal
     * used by the witness append loop. They are NOT errors — logging each
     * would spam at every append. Left bare intentionally. */
    if (!t->has_left || !t->has_right)
        return false;
    if (t->num_parents != t->depth - 1)
        return false;
    for (size_t i = 0; i < t->num_parents; i++) {
        if (!t->has_parent[i])
            return false;
    }
    return true;
}

/* Wire format: optional<hash> left, optional<hash> right, vector<optional<hash>> parents */
bool incremental_tree_serialize(const struct incremental_merkle_tree *t,
                                 struct byte_stream *s)
{
    /* left: discriminant + hash */
    if (!stream_write_u8(s, t->has_left ? 1 : 0))
        IMT_FAIL("write left discriminant");
    if (t->has_left && !stream_write(s, t->left.data, 32))
        IMT_FAIL("write left hash");

    /* right: discriminant + hash */
    if (!stream_write_u8(s, t->has_right ? 1 : 0))
        IMT_FAIL("write right discriminant");
    if (t->has_right && !stream_write(s, t->right.data, 32))
        IMT_FAIL("write right hash");

    /* parents: compact_size + array of optional<hash> */
    if (!stream_write_compact_size(s, t->num_parents))
        IMT_FAIL("write num_parents compact_size");
    for (size_t i = 0; i < t->num_parents; i++) {
        if (!stream_write_u8(s, t->has_parent[i] ? 1 : 0))
            IMT_FAIL("write parent discriminant");
        if (t->has_parent[i] && !stream_write(s, t->parents[i].data, 32))
            IMT_FAIL("write parent hash");
    }
    return true;
}

static bool wfcheck(const struct incremental_merkle_tree *t)
{
    if (t->num_parents >= t->depth)
        LOG_FAIL("incremental_merkle_tree",
                 "wfcheck: num_parents=%zu >= depth=%zu",
                 t->num_parents, t->depth);
    if (t->num_parents > 0 && !t->has_parent[t->num_parents - 1])
        LOG_FAIL("incremental_merkle_tree",
                 "wfcheck: parent[num_parents-1] is not set (truncated or corrupt)");
    if (!t->has_left && t->has_right)
        LOG_FAIL("incremental_merkle_tree",
                 "wfcheck: has_right without has_left (invariant violated)");
    if (!t->has_left && t->num_parents > 0)
        LOG_FAIL("incremental_merkle_tree",
                 "wfcheck: num_parents>0 without has_left (invariant violated)");
    return true;
}

bool incremental_tree_deserialize(struct incremental_merkle_tree *t,
                                   struct byte_stream *s)
{
    uint8_t disc;

    /* Content may be half-overwritten on an early IMT_FAIL return below;
     * drop any memo up front so a stale root can never survive. */
    tree_root_invalidate(t);

    /* left */
    if (!stream_read(s, &disc, 1))
        IMT_FAIL("read left discriminant");
    t->has_left = (disc != 0);
    if (t->has_left) {
        if (!stream_read(s, t->left.data, 32))
            IMT_FAIL("read left hash");
    } else {
        memset(&t->left, 0, sizeof(struct uint256));
    }

    /* right */
    if (!stream_read(s, &disc, 1))
        IMT_FAIL("read right discriminant");
    t->has_right = (disc != 0);
    if (t->has_right) {
        if (!stream_read(s, t->right.data, 32))
            IMT_FAIL("read right hash");
    } else {
        memset(&t->right, 0, sizeof(struct uint256));
    }

    /* parents */
    uint64_t num;
    if (!stream_read_compact_size(s, &num))
        IMT_FAIL("read num_parents compact_size");
    if (num > MAX_TREE_DEPTH)
        LOG_FAIL("incremental_merkle_tree",
                 "deserialize: num_parents=%" PRIu64 " exceeds MAX_TREE_DEPTH=%d",
                 num, MAX_TREE_DEPTH);
    t->num_parents = (size_t)num;
    memset(t->has_parent, 0, sizeof(t->has_parent));
    memset(t->parents, 0, sizeof(t->parents));
    for (size_t i = 0; i < t->num_parents; i++) {
        if (!stream_read(s, &disc, 1))
            IMT_FAIL("read parent discriminant");
        t->has_parent[i] = (disc != 0);
        if (t->has_parent[i]) {
            if (!stream_read(s, t->parents[i].data, 32))
                IMT_FAIL("read parent hash");
        }
    }

    return wfcheck(t);
}

/* --- Flat-file checkpoint ───────────────────────────
 *
 * Replaces the 2.6M-block sapling tree replay on crash recovery
 * with a sub-second load from a dedicated on-disk checkpoint.
 * Lives outside the SQLite-backed node_state table so it is
 * immune to P14-class savepoint contention. See header for the
 * file format. */

#define SAPLING_CKPT_MAGIC     "SPLT"
#define SAPLING_CKPT_VERSION   2
/* magic + version + height + root + block_hash + tree_size + blob_len */
#define SAPLING_CKPT_HEADER_SZ (4 + 4 + 8 + 32 + 32 + 4 + 4)
#define SAPLING_CKPT_OFF_BLOCKHASH 48
#define SAPLING_CKPT_OFF_TREESIZE  80
#define SAPLING_CKPT_OFF_BLOBLEN   84
#define SAPLING_CKPT_TRAILER_SZ 32
#define SAPLING_CKPT_MAX_BLOB  (64u * 1024u)

static bool ckpt_write_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
    return true;
}

static bool ckpt_write_u64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)((v >> (i * 8)) & 0xff);
    return true;
}

static uint32_t ckpt_read_u32_le(const uint8_t *p)
{
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t ckpt_read_u64_le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= ((uint64_t)p[i]) << (i * 8);
    return v;
}

bool sapling_tree_flush_checkpoint(const struct incremental_merkle_tree *t,
                                   int64_t height,
                                   const uint8_t block_hash[32],
                                   const char *path)
{
    if (!t || !path)
        LOG_FAIL("sapling_tree",
                 "flush_checkpoint: NULL arg (t=%p path=%p)",
                 (const void *)t, (const void *)path);

    /* 1. Serialize the tree blob. */
    struct byte_stream blob;
    stream_init(&blob, 4096);
    if (!incremental_tree_serialize(t, &blob)) {
        stream_free(&blob);
        LOG_FAIL("sapling_tree",
                 "flush_checkpoint: serialize failed");
    }
    if (blob.size > SAPLING_CKPT_MAX_BLOB) {
        stream_free(&blob);
        LOG_FAIL("sapling_tree",
                 "flush_checkpoint: blob size %zu exceeds max %u",
                 blob.size, SAPLING_CKPT_MAX_BLOB);
    }

    /* 2. Compute current root. */
    struct uint256 root;
    incremental_tree_root(t, &root);

    /* 3. Build the header + body in a contiguous buffer so we can
     *    hash it in one shot for the trailer. */
    size_t body_sz = SAPLING_CKPT_HEADER_SZ + blob.size;
    uint8_t *body = (uint8_t *)zcl_malloc(body_sz, "sapling_ckpt_body");
    if (!body) {
        stream_free(&blob);
        LOG_FAIL("sapling_tree",
                 "flush_checkpoint: alloc body %zu failed", body_sz);
    }
    memcpy(body + 0, SAPLING_CKPT_MAGIC, 4);
    ckpt_write_u32_le(body + 4, SAPLING_CKPT_VERSION);
    ckpt_write_u64_le(body + 8, (uint64_t)height);
    memcpy(body + 16, root.data, 32);
    if (block_hash)
        memcpy(body + SAPLING_CKPT_OFF_BLOCKHASH, block_hash, 32);
    else
        memset(body + SAPLING_CKPT_OFF_BLOCKHASH, 0, 32);
    ckpt_write_u32_le(body + SAPLING_CKPT_OFF_TREESIZE,
                      (uint32_t)incremental_tree_size(t));
    ckpt_write_u32_le(body + SAPLING_CKPT_OFF_BLOBLEN, (uint32_t)blob.size);
    memcpy(body + SAPLING_CKPT_HEADER_SZ, blob.data, blob.size);
    stream_free(&blob);

    uint8_t trailer[SAPLING_CKPT_TRAILER_SZ];
    zcl_sha3_256(body, body_sz, trailer);

    /* 4. Resolve the existing parent, create a private staged file, flush its
     * bytes, replace atomically, then make the parent transition durable. */
    char resolved[32768];
    char parent[32768];
    if (!platform_private_destination_resolve(
            path, resolved, sizeof(resolved), parent, sizeof(parent))) {
        free(body);
        LOG_FAIL("sapling_tree",
                 "flush_checkpoint: invalid checkpoint path");
    }
    char tmp_path[32768];
    int tmp_len = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", resolved);
    struct platform_private_file staged;
    platform_private_file_init(&staged);
    if (tmp_len < 0 || (size_t)tmp_len >= sizeof(tmp_path) ||
        !platform_private_file_create(tmp_path, &staged)) {
        fprintf(stderr,  // obs-ok:helper-context-logged
                "[sapling_tree] %s:%d %s(): flush_checkpoint: "
                "private staging creation failed\n",
                __FILE__, __LINE__, __func__);
        free(body);
        return false;
    }

    bool ok = platform_private_file_write_at(&staged, body, body_sz, 0) &&
              platform_private_file_write_at(&staged, trailer,
                                              SAPLING_CKPT_TRAILER_SZ,
                                              body_sz) &&
              platform_private_file_flush(&staged) &&
              platform_private_file_replace(&staged, tmp_path, resolved) &&
              platform_private_parent_flush(parent);
    free(body);

    if (!ok) {
        if (staged.native != (uintptr_t)-1) {
            (void)platform_private_file_retire(&staged, tmp_path);
            platform_private_file_close(&staged);
        }
        fprintf(stderr,  // obs-ok:helper-context-logged
                "[sapling_tree] %s:%d %s(): flush_checkpoint: "
                "durable private replacement of %s failed\n",
                __FILE__, __LINE__, __func__, path);
        return false;
    }
    return true;
}

bool sapling_tree_load_checkpoint(struct incremental_merkle_tree *t,
                                  int64_t *height_out,
                                  uint8_t block_hash_out[32],
                                  const char *path)
{
    if (!t || !path)
        LOG_FAIL("sapling_tree",
                 "load_checkpoint: NULL arg (t=%p path=%p)",
                 (const void *)t, (const void *)path);

    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false; /* missing file is a silent not-found */

    uint64_t file_size = 0;
    if (!platform_positioned_file_size(&file, &file_size) ||
        file_size < SAPLING_CKPT_HEADER_SZ + SAPLING_CKPT_TRAILER_SZ) {
        platform_positioned_file_close(&file);
        return false; /* too small — treat as corrupt */
    }
    if (file_size >
        SAPLING_CKPT_HEADER_SZ + SAPLING_CKPT_MAX_BLOB + SAPLING_CKPT_TRAILER_SZ) {
        platform_positioned_file_close(&file);
        return false; /* too large — refuse */
    }

    uint8_t *buf = (uint8_t *)zcl_malloc((size_t)file_size,
                                         "sapling_ckpt_load");
    if (!buf) {
        platform_positioned_file_close(&file);
        return false;
    }
    int64_t read = platform_positioned_file_read(&file, buf,
                                                 (size_t)file_size, 0);
    platform_positioned_file_close(&file);
    if (read < 0 || (uint64_t)read != file_size) {
        free(buf);
        return false;
    }

    size_t body_sz = (size_t)file_size - SAPLING_CKPT_TRAILER_SZ;
    uint8_t expected_trailer[SAPLING_CKPT_TRAILER_SZ];
    zcl_sha3_256(buf, body_sz, expected_trailer);

    /* Integrity check must run before any field-level parsing so a
     * tampered magic byte can never steer the loader. */
    if (memcmp(buf + body_sz, expected_trailer,
               SAPLING_CKPT_TRAILER_SZ) != 0) {
        free(buf);
        return false;
    }

    if (memcmp(buf, SAPLING_CKPT_MAGIC, 4) != 0) {
        free(buf);
        return false;
    }
    uint32_t version = ckpt_read_u32_le(buf + 4);
    if (version != SAPLING_CKPT_VERSION) {
        free(buf);
        return false;
    }
    int64_t height = (int64_t)ckpt_read_u64_le(buf + 8);
    uint32_t blob_len = ckpt_read_u32_le(buf + SAPLING_CKPT_OFF_BLOBLEN);
    if (blob_len > SAPLING_CKPT_MAX_BLOB ||
        SAPLING_CKPT_HEADER_SZ + (size_t)blob_len != body_sz) {
        free(buf);
        return false;
    }

    /* Deserialize the tree blob into a scratch tree (preserves the
     * caller's tree on any failure below). */
    struct incremental_merkle_tree scratch;
    sapling_tree_init(&scratch);
    struct byte_stream s;
    stream_init_from_data(&s, buf + SAPLING_CKPT_HEADER_SZ, blob_len);
    if (!incremental_tree_deserialize(&scratch, &s)) {
        free(buf);
        return false;
    }

    /* Root from the loaded tree must match the root field in the file.
     * The SHA3 trailer already guarantees bit-for-bit integrity, but
     * the root check also catches pointer-mismatch bugs — e.g. a
     * future format change that ships a stale root alongside a valid
     * blob. */
    struct uint256 computed_root;
    incremental_tree_root(&scratch, &computed_root);
    if (memcmp(computed_root.data, buf + 16, 32) != 0) {
        free(buf);
        return false;
    }

    if (block_hash_out)
        memcpy(block_hash_out, buf + SAPLING_CKPT_OFF_BLOCKHASH, 32);

    free(buf);

    *t = scratch;
    if (height_out)
        *height_out = height;
    return true;
}

enum sapling_ckpt_verdict sapling_ckpt_verify_binding(
    int64_t ckpt_height, const struct uint256 *ckpt_root,
    const uint8_t ckpt_block_hash[32],
    int64_t tip_height,
    const uint8_t expected_block_hash[32], bool expected_hash_known,
    const struct uint256 *expected_root, bool expected_root_known)
{
    static const uint8_t zeros32[32] = {0};

    /* A cache above the current tip is stale by definition — a reorg or a
     * rollback dropped the chain below the checkpointed height. Never
     * "partially use" it; discard and full-replay. */
    if (ckpt_height > tip_height)
        return SAPLING_CKPT_STALE_ABOVE_TIP;

    /* Reorg guard: the block that now occupies `ckpt_height` must be the
     * same one the checkpoint was taken against. A NULL/absent or all-zero
     * expected hash means the caller could not resolve the block at H (an
     * absent body / header-only entry) — treat that as a reorg-class
     * discard rather than trusting a hash we cannot confirm. The checkpoint
     * only carries a real block hash from a v2 writer; an all-zero stored
     * hash skips this gate and relies on the stronger root binding below. */
    if (ckpt_block_hash &&
        memcmp(ckpt_block_hash, zeros32, 32) != 0) {
        if (!expected_hash_known || !expected_block_hash)
            return SAPLING_CKPT_REORG;
        if (memcmp(ckpt_block_hash, expected_block_hash, 32) != 0)
            return SAPLING_CKPT_REORG;
    }

    /* Consensus binding: the frontier root at H must equal the block
     * header's hashFinalSaplingRoot at H (the same binding P1-1 enforces).
     * When the header binding is absent we cannot verify, so we refuse to
     * trust — the caller falls back to the full, self-verifying replay. */
    if (!expected_root_known || !expected_root)
        return SAPLING_CKPT_ROOT_UNKNOWN;
    if (!ckpt_root ||
        memcmp(ckpt_root->data, expected_root->data, 32) != 0)
        return SAPLING_CKPT_ROOT_MISMATCH;

    return SAPLING_CKPT_OK;
}

const char *sapling_ckpt_verdict_str(enum sapling_ckpt_verdict v)
{
    switch (v) {
    case SAPLING_CKPT_OK:              return "ok";
    case SAPLING_CKPT_STALE_ABOVE_TIP: return "stale_above_tip";
    case SAPLING_CKPT_REORG:           return "reorg";
    case SAPLING_CKPT_ROOT_MISMATCH:   return "root_mismatch";
    case SAPLING_CKPT_ROOT_UNKNOWN:    return "root_unknown";
    }
    return "unknown";
}

/* --- Incremental Witness --- */

static size_t next_depth(const struct incremental_merkle_tree *t, size_t skip)
{
    size_t d = 0;
    size_t s = skip;
    if (!t->has_right) {
        if (s == 0) return 0;
        s--;
    }
    for (size_t i = 0; i < t->num_parents; i++) {
        if (!t->has_parent[i]) {
            if (s == 0) return d + 1;
            s--;
        }
        d++;
    }
    /* Above all existing parents */
    return d + 1 + s;
}

void incremental_witness_init(struct incremental_witness *w,
                               const struct incremental_merkle_tree *tree)
{
    w->tree = *tree;
    w->num_filled = 0;
    w->has_cursor = false;
    w->cursor_depth = next_depth(tree, 0);
}

void incremental_witness_append(struct incremental_witness *w,
                                 const struct uint256 *obj)
{
    if (w->has_cursor) {
        incremental_tree_append(&w->cursor, obj);
        if (incremental_tree_is_complete(&w->cursor)) {
            struct uint256 root;
            incremental_tree_root(&w->cursor, &root);
            if (w->num_filled < MAX_WITNESS_FILLS) {
                w->filled[w->num_filled++] = root;
            }
            w->has_cursor = false;
            w->cursor_depth = next_depth(&w->tree, w->num_filled);
        }
    } else {
        w->cursor_depth = next_depth(&w->tree, w->num_filled);
        if (w->cursor_depth == 0) {
            if (w->num_filled < MAX_WITNESS_FILLS) {
                w->filled[w->num_filled++] = *obj;
            }
            w->cursor_depth = next_depth(&w->tree, w->num_filled);
        } else {
            /* Initialize cursor subtree at cursor_depth */
            tree_init(&w->cursor, w->cursor_depth,
                      w->tree.combine, w->tree.uncommitted);
            incremental_tree_append(&w->cursor, obj);
            w->has_cursor = true;
        }
    }
}

void incremental_witness_root(const struct incremental_witness *w,
                               struct uint256 *out)
{
    /* Partial fill: combine tree's root computation with filled + cursor */
    const struct incremental_merkle_tree *t = &w->tree;

    struct uint256 combine_left;
    if (t->has_left) {
        combine_left = t->left;
    } else {
        t->uncommitted(&combine_left);
    }

    struct uint256 combine_right;
    if (t->has_right) {
        combine_right = t->right;
    } else {
        /* Use first filled or uncommitted */
        if (w->num_filled > 0 || w->has_cursor) {
            size_t fi = 0;
            if (fi < w->num_filled) {
                combine_right = w->filled[fi];
                fi++;
            } else {
                t->uncommitted(&combine_right);
            }
        } else {
            t->uncommitted(&combine_right);
        }
    }

    struct uint256 root;
    t->combine(&combine_left, &combine_right, 0, &root);

    size_t d = 1;
    size_t filled_idx = t->has_right ? 0 : (w->num_filled > 0 ? 1 : 0);

    for (size_t i = 0; i < t->num_parents || d < t->depth; i++) {
        struct uint256 next_val;
        if (i < t->num_parents && t->has_parent[i]) {
            t->combine(&t->parents[i], &root, d, &next_val);
        } else {
            struct uint256 filler;
            if (filled_idx < w->num_filled) {
                filler = w->filled[filled_idx++];
            } else if (w->has_cursor && filled_idx == w->num_filled) {
                incremental_tree_root(&w->cursor, &filler);
                filled_idx++;
            } else {
                empty_root_at_depth(t, d, &filler);
            }
            t->combine(&root, &filler, d, &next_val);
        }
        root = next_val;
        d++;
        if (d >= t->depth) break;
    }

    *out = root;
}

bool incremental_witness_serialize(const struct incremental_witness *w,
                                    struct byte_stream *s)
{
    if (!incremental_tree_serialize(&w->tree, s))
        IMT_FAIL("write underlying tree");

    /* filled: vector<hash> */
    if (!stream_write_compact_size(s, w->num_filled))
        IMT_FAIL("write num_filled compact_size");
    for (size_t i = 0; i < w->num_filled; i++) {
        if (!stream_write(s, w->filled[i].data, 32))
            IMT_FAIL("write filled[i]");
    }

    /* cursor: optional<tree> */
    if (!stream_write_u8(s, w->has_cursor ? 1 : 0))
        IMT_FAIL("write cursor discriminant");
    if (w->has_cursor) {
        if (!incremental_tree_serialize(&w->cursor, s))
            IMT_FAIL("write cursor tree");
    }

    return true;
}

bool incremental_witness_merkle_path(const struct incremental_witness *w,
                                      uint8_t *path_out, size_t *path_len)
{
    const struct incremental_merkle_tree *t = &w->tree;
    size_t depth = t->depth;

    if (incremental_tree_size(t) == 0)
        LOG_FAIL("incremental_merkle_tree",
                 "merkle_path: tree is empty (no leaves to authenticate)");

    /* Build the authentication path by collecting siblings at each level.
     * Walk the same structure as incremental_witness_root but collect
     * the "other side" at each combination step. */

    struct uint256 auth_path[MAX_TREE_DEPTH];
    uint8_t path_bits[MAX_TREE_DEPTH]; /* 0 = leaf is left child, 1 = right child */
    size_t num_levels = 0;

    /* Level 0: left/right of the tree base */
    size_t filled_idx = 0;

    if (t->has_right) {
        /* A witness tracks the LAST leaf present when it is created. If a
         * right leaf exists, that is the witnessed leaf: its sibling is the
         * left leaf and its position bit is 1. */
        auth_path[0] = t->left;
        path_bits[0] = 1;
    } else {
        /* With only a left leaf, the witnessed leaf is on the left. The first
         * later leaf replayed into this witness occupies its right-sibling
         * slot and is stored in filled[0]; only an unadvanced witness uses the
         * uncommitted leaf. Mirror incremental_witness_root's consumption so
         * higher levels start at the next filled subtree. */
        if (filled_idx < w->num_filled)
            auth_path[0] = w->filled[filled_idx++];
        else
            t->uncommitted(&auth_path[0]);
        path_bits[0] = 0;
    }
    num_levels = 1;

    /* Levels 1..depth-1: walk parents + filled + cursor */
    for (size_t i = 0; i < depth - 1 && num_levels < depth; i++) {
        size_t level = i; /* parent index */
        if (level < t->num_parents && t->has_parent[level]) {
            /* Parent exists → we came from the right side, sibling is parent */
            auth_path[num_levels] = t->parents[level];
            path_bits[num_levels] = 1;
        } else {
            /* No parent → get from filled or cursor or empty */
            if (filled_idx < w->num_filled) {
                auth_path[num_levels] = w->filled[filled_idx++];
            } else if (w->has_cursor && filled_idx == w->num_filled) {
                incremental_tree_root(&w->cursor, &auth_path[num_levels]);
                filled_idx++;
            } else {
                empty_root_at_depth(t, num_levels, &auth_path[num_levels]);
            }
            path_bits[num_levels] = 0;
        }
        num_levels++;
    }

    /* Pad remaining levels with empty roots */
    while (num_levels < depth) {
        empty_root_at_depth(t, num_levels, &auth_path[num_levels]);
        path_bits[num_levels] = 0;
        num_levels++;
    }

    /* Serialize in Sapling wire format:
     * compact_size(depth) || depth × (32-byte sibling || 1-byte position_bit) */
    size_t off = 0;
    /* compact_size for depth (always fits in 1 byte for depth <= 32) */
    path_out[off++] = (uint8_t)depth;
    for (size_t i = 0; i < depth; i++) {
        memcpy(path_out + off, auth_path[i].data, 32);
        off += 32;
        path_out[off++] = path_bits[i];
    }
    *path_len = off;
    return true;
}

bool incremental_witness_deserialize(struct incremental_witness *w,
                                      struct byte_stream *s,
                                      size_t depth,
                                      void (*combine)(const struct uint256 *,
                                                      const struct uint256 *,
                                                      size_t, struct uint256 *),
                                      void (*uncommitted)(struct uint256 *))
{
    /* This is the ONLY function that takes a depth alongside a hostile byte
     * stream, and it writes depth straight into w->tree.depth / w->cursor.depth
     * without going through tree_init — so tree_init's assert(depth <=
     * MAX_TREE_DEPTH) is bypassed here. An out-of-range depth would run the
     * root fold past the ends of the fixed parents[]/has_parent[] arrays.
     * Every current caller passes a compile-time constant
     * (SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH = 32, INCREMENTAL_MERKLE_TREE_DEPTH
     * = 29), so this refuses nothing that works today; it stops the next
     * caller from turning a stored witness blob into an overrun. */
    if (depth == 0 || depth > MAX_TREE_DEPTH)
        LOG_FAIL("incremental_merkle_tree",
                 "witness_deserialize: depth=%zu out of range (1..%d)",
                 depth, MAX_TREE_DEPTH);

    /* Initialize function pointers first. depth/combine/uncommitted are
     * root-affecting fields, so drop any memo carried over from a prior
     * use of *w (the deserializes below invalidate again, conservatively). */
    w->tree.depth = depth;
    w->tree.combine = combine;
    w->tree.uncommitted = uncommitted;
    tree_root_invalidate(&w->tree);

    if (!incremental_tree_deserialize(&w->tree, s))
        IMT_FAIL("read underlying tree");

    /* filled */
    uint64_t num;
    if (!stream_read_compact_size(s, &num))
        IMT_FAIL("read num_filled compact_size");
    if (num > MAX_WITNESS_FILLS)
        LOG_FAIL("incremental_merkle_tree",
                 "witness_deserialize: num_filled=%" PRIu64 " exceeds MAX_WITNESS_FILLS=%d",
                 num, MAX_WITNESS_FILLS);
    w->num_filled = (size_t)num;
    for (size_t i = 0; i < w->num_filled; i++) {
        if (!stream_read(s, w->filled[i].data, 32))
            IMT_FAIL("read filled[i]");
    }

    /* cursor */
    uint8_t disc;
    if (!stream_read(s, &disc, 1))
        IMT_FAIL("read cursor discriminant");
    w->has_cursor = (disc != 0);
    if (w->has_cursor) {
        w->cursor.depth = depth;
        w->cursor.combine = combine;
        w->cursor.uncommitted = uncommitted;
        tree_root_invalidate(&w->cursor);
        if (!incremental_tree_deserialize(&w->cursor, s))
            IMT_FAIL("read cursor tree");
    }

    w->cursor_depth = next_depth(&w->tree, w->num_filled);

    /* cursor.depth must match cursor_depth, NOT full tree depth.
     * The cursor is a subtree at a specific level — its root computation
     * pads empty hashes up to cursor.depth. Using the full tree depth (32)
     * instead of cursor_depth produces a wrong root with 27+ extra levels.
     * depth feeds the root fold, so the memo must not survive this fix. */
    if (w->has_cursor) {
        w->cursor.depth = w->cursor_depth;
        tree_root_invalidate(&w->cursor);
    }

    return true;
}
