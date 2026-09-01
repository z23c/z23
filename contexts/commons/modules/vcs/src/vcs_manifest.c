/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_manifest — implementation. See vcs/vcs_manifest.h. */

#include "vcs/vcs_manifest.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_object.h"

#include "vcs_priv.h"
#include "vcs_walk.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

void vcs_manifest_init(struct vcs_manifest *m)
{
    if (!m) return;
    m->entries = NULL;
    m->count = 0;
    m->cap = 0;
}

void vcs_manifest_free(struct vcs_manifest *m)
{
    if (!m) return;
    for (size_t i = 0; i < m->count; i++)
        free(m->entries[i].path);
    free(m->entries);
    m->entries = NULL;
    m->count = 0;
    m->cap = 0;
}

bool vcs_manifest_add(struct vcs_manifest *m, const char *path, uint32_t mode,
                      uint64_t size, const uint8_t blob[32])
{
    if (!m || !path || !blob)
        LOG_FAIL("vcs", "null arg to manifest_add");
    size_t plen = strlen(path);
    if (plen == 0 || plen > VCS_PATH_MAX)
        LOG_FAIL("vcs", "bad path length %zu", plen);

    if (m->count == m->cap) {
        size_t ncap = m->cap ? m->cap * 2 : 64;
        struct vcs_entry *ne =
            zcl_realloc(m->entries, ncap * sizeof(*ne), "vcs_manifest_entries");
        if (!ne)
            LOG_FAIL("vcs", "realloc %zu entries", ncap);
        m->entries = ne;
        m->cap = ncap;
    }
    struct vcs_entry *e = &m->entries[m->count];
    e->path = zcl_strdup(path, "vcs_entry_path");
    if (!e->path)
        LOG_FAIL("vcs", "strdup path");
    e->mode = mode;
    e->size = size;
    memcpy(e->blob, blob, 32);
    m->count++;
    return true;
}

static int entry_cmp(const void *a, const void *b)
{
    const struct vcs_entry *ea = a, *eb = b;
    return strcmp(ea->path, eb->path);
}

void vcs_manifest_sort(struct vcs_manifest *m)
{
    if (!m || m->count < 2) return;
    qsort(m->entries, m->count, sizeof(m->entries[0]), entry_cmp);
}

bool vcs_manifest_entry_hash(const struct vcs_entry *e, uint8_t out[32])
{
    if (!e || !e->path || !out)
        LOG_FAIL("vcs", "null arg to entry_hash");
    uint8_t tag = VCS_TAG_ENTRY;
    uint8_t nul = 0;
    uint8_t modebuf[4], sizebuf[8];
    vcs_wr_u32le(modebuf, e->mode);
    vcs_wr_u64le(sizebuf, e->size);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &tag, 1);
    sha3_256_write(&ctx, (const unsigned char *)e->path, strlen(e->path));
    sha3_256_write(&ctx, &nul, 1);
    sha3_256_write(&ctx, modebuf, 4);
    sha3_256_write(&ctx, sizebuf, 8);
    sha3_256_write(&ctx, e->blob, 32);
    sha3_256_finalize(&ctx, out);
    return true;
}

bool vcs_manifest_tree_hash(const struct vcs_manifest *m, uint8_t out[32])
{
    if (!m || !out)
        LOG_FAIL("vcs", "null arg to tree_hash");
    /* Sort a shallow copy of the pointer array so this stays const-correct
     * for callers; the entries themselves are not mutated. */
    struct vcs_manifest tmp = *m;
    struct vcs_entry *copy = NULL;
    if (m->count > 0) {
        copy = zcl_malloc(m->count * sizeof(*copy), "vcs_tree_hash_copy");
        if (!copy)
            LOG_FAIL("vcs", "malloc tree_hash copy");
        memcpy(copy, m->entries, m->count * sizeof(*copy));
        tmp.entries = copy;
        qsort(copy, tmp.count, sizeof(*copy), entry_cmp);
    }

    uint8_t tag = VCS_TAG_MANIFEST;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &tag, 1);
    bool ok = true;
    for (size_t i = 0; i < tmp.count; i++) {
        uint8_t eh[32];
        if (!vcs_manifest_entry_hash(&tmp.entries[i], eh)) {
            ok = false;
            break;
        }
        sha3_256_write(&ctx, eh, 32);
    }
    sha3_256_finalize(&ctx, out);
    free(copy);
    if (!ok)
        LOG_FAIL("vcs", "entry_hash failed in tree_hash");
    return true;
}

bool vcs_manifest_serialize(const struct vcs_manifest *m, uint8_t **out,
                            size_t *out_len)
{
    if (!m || !out || !out_len)
        LOG_FAIL("vcs", "null arg to serialize");
    *out = NULL;
    *out_len = 0;

    /* Serialize from a sorted copy (const-correct for the caller). */
    struct vcs_entry *copy = NULL;
    const struct vcs_entry *ents = m->entries;
    if (m->count > 0) {
        copy = zcl_malloc(m->count * sizeof(*copy), "vcs_serialize_copy");
        if (!copy)
            LOG_FAIL("vcs", "malloc serialize copy");
        memcpy(copy, m->entries, m->count * sizeof(*copy));
        qsort(copy, m->count, sizeof(*copy), entry_cmp);
        ents = copy;
    }

    size_t total = 1 + 8;
    for (size_t i = 0; i < m->count; i++) {
        size_t plen = strlen(ents[i].path);
        if (plen == 0 || plen > VCS_PATH_MAX) {
            free(copy);
            LOG_FAIL("vcs", "bad path length in serialize");
        }
        total += 2 + plen + 4 + 8 + 32;
    }

    uint8_t *buf = zcl_malloc(total, "vcs_manifest_serialize");
    if (!buf) {
        free(copy);
        LOG_FAIL("vcs", "malloc %zu for serialize", total);
    }
    size_t off = 0;
    buf[off++] = (uint8_t)VCS_MANIFEST_VERSION;
    vcs_wr_u64le(buf + off, (uint64_t)m->count);
    off += 8;
    for (size_t i = 0; i < m->count; i++) {
        size_t plen = strlen(ents[i].path);
        vcs_wr_u16le(buf + off, (uint16_t)plen);
        off += 2;
        memcpy(buf + off, ents[i].path, plen);
        off += plen;
        vcs_wr_u32le(buf + off, ents[i].mode);
        off += 4;
        vcs_wr_u64le(buf + off, ents[i].size);
        off += 8;
        memcpy(buf + off, ents[i].blob, 32);
        off += 32;
    }
    free(copy);
    *out = buf;
    *out_len = total;
    return true;
}

bool vcs_manifest_parse(const uint8_t *in, size_t len, struct vcs_manifest *out)
{
    if (!in || !out)
        LOG_FAIL("vcs", "null arg to parse");
    vcs_manifest_init(out);
    if (len < 9)
        LOG_FAIL("vcs", "manifest too short: %zu", len);
    size_t off = 0;
    uint8_t ver = in[off++];
    if (ver != VCS_MANIFEST_VERSION)
        LOG_FAIL("vcs", "bad manifest version %u", ver);
    uint64_t count = vcs_rd_u64le(in + off);
    off += 8;

    for (uint64_t i = 0; i < count; i++) {
        if (off + 2 > len)
            goto trunc;
        uint16_t plen = vcs_rd_u16le(in + off);
        off += 2;
        if (plen == 0 || plen > VCS_PATH_MAX)
            goto badpath;
        if (off + plen + 4 + 8 + 32 > len)
            goto trunc;
        char *path = zcl_malloc((size_t)plen + 1, "vcs_parse_path");
        if (!path) {
            vcs_manifest_free(out);
            LOG_FAIL("vcs", "malloc path in parse");
        }
        memcpy(path, in + off, plen);
        path[plen] = '\0';
        if (memchr(path, '\0', plen) != NULL ||
            (out->count > 0 &&
             strcmp(out->entries[out->count - 1u].path, path) >= 0)) {
            free(path);
            goto badpath;
        }
        off += plen;
        uint32_t mode = vcs_rd_u32le(in + off);
        off += 4;
        uint64_t size = vcs_rd_u64le(in + off);
        off += 8;
        const uint8_t *blob = in + off;
        off += 32;
        bool ok = vcs_manifest_add(out, path, mode, size, blob);
        free(path);
        if (!ok) {
            vcs_manifest_free(out);
            LOG_FAIL("vcs", "manifest_add failed in parse");
        }
    }
    if (off != len) {
        vcs_manifest_free(out);
        LOG_FAIL("vcs", "trailing manifest bytes: off=%zu len=%zu", off, len);
    }
    return true;

trunc:
    vcs_manifest_free(out);
    LOG_FAIL("vcs", "truncated manifest at off=%zu len=%zu", off, len);
badpath:
    vcs_manifest_free(out);
    LOG_FAIL("vcs", "bad path length in parse");
}

void vcs_manifest_diff(struct vcs_manifest *a, struct vcs_manifest *b,
                       vcs_diff_cb cb, void *user)
{
    if (!a || !b || !cb) return;
    vcs_manifest_sort(a);
    vcs_manifest_sort(b);
    size_t i = 0, j = 0;
    while (i < a->count && j < b->count) {
        int c = strcmp(a->entries[i].path, b->entries[j].path);
        if (c == 0) {
            const struct vcs_entry *ea = &a->entries[i];
            const struct vcs_entry *eb = &b->entries[j];
            if (memcmp(ea->blob, eb->blob, 32) != 0 || ea->mode != eb->mode)
                cb(VCS_DIFF_MODIFIED, ea, eb, user);
            i++;
            j++;
        } else if (c < 0) {
            cb(VCS_DIFF_REMOVED, &a->entries[i], NULL, user);
            i++;
        } else {
            cb(VCS_DIFF_ADDED, NULL, &b->entries[j], user);
            j++;
        }
    }
    for (; i < a->count; i++)
        cb(VCS_DIFF_REMOVED, &a->entries[i], NULL, user);
    for (; j < b->count; j++)
        cb(VCS_DIFF_ADDED, NULL, &b->entries[j], user);
}

/* ── build-from-worktree ─────────────────────────────────────────── */

struct dirty_row {
    char    *path;
    int64_t  mtime_ns;
    int64_t  size;
    int64_t  ctime_ns;
    uint8_t  blob[32];
};

struct build_ctx {
    const char             *repo_root;
    struct vcs_stat_cache  *sc;        /* NULL if no index */
    struct vcs_manifest    *out;
    struct dirty_row       *dirty;
    size_t                  dirty_count;
    size_t                  dirty_cap;
    bool                    err;
};

static bool build_cb(const char *relpath, uint32_t mode, uint64_t size,
                     int64_t mtime_ns, int64_t ctime_ns, void *user)
{
    struct build_ctx *b = user;
    uint8_t blob[32];
    bool have_blob = false;

    if (b->sc) {
        const struct vcs_stat_row *row = vcs_stat_cache_find(b->sc, relpath);
        if (row && row->mtime_ns == mtime_ns && row->size == (int64_t)size &&
            row->ctime_ns == ctime_ns) {
            memcpy(blob, row->blob, 32);
            have_blob = true;
        }
    }

    if (!have_blob) {
        if (!vcs_blob_hash_file(b->repo_root, relpath, blob)) {
            b->err = true;
            return false;
        }
        /* Record for stat-cache write-back. */
        if (b->sc) {
            if (b->dirty_count == b->dirty_cap) {
                size_t ncap = b->dirty_cap ? b->dirty_cap * 2 : 64;
                struct dirty_row *nd =
                    zcl_realloc(b->dirty, ncap * sizeof(*nd), "vcs_build_dirty");
                if (!nd) { b->err = true; return false; }
                b->dirty = nd;
                b->dirty_cap = ncap;
            }
            struct dirty_row *dr = &b->dirty[b->dirty_count];
            dr->path = zcl_strdup(relpath, "vcs_build_dirty_path");
            if (!dr->path) { b->err = true; return false; }
            dr->mtime_ns = mtime_ns;
            dr->size = (int64_t)size;
            dr->ctime_ns = ctime_ns;
            memcpy(dr->blob, blob, 32);
            b->dirty_count++;
        }
    }

    if (!vcs_manifest_add(b->out, relpath, mode, size, blob)) {
        b->err = true;
        return false;
    }
    return true;
}

bool vcs_manifest_build(const char *repo_root, struct vcs_index *idx,
                        struct vcs_manifest *out)
{
    if (!repo_root || !out)
        LOG_FAIL("vcs", "null arg to manifest_build");
    vcs_manifest_init(out);

    struct vcs_stat_cache sc = {0};
    bool have_sc = false;
    if (idx) {
        if (!vcs_stat_cache_load(idx, &sc))
            LOG_FAIL("vcs", "stat_cache_load failed");
        have_sc = true;
    }

    struct build_ctx b = {
        .repo_root = repo_root,
        .sc = have_sc ? &sc : NULL,
        .out = out,
    };

    bool walked = vcs_walk_tracked(repo_root, build_cb, &b);
    if (have_sc)
        vcs_stat_cache_free(&sc);

    if (!walked || b.err) {
        for (size_t i = 0; i < b.dirty_count; i++)
            free(b.dirty[i].path);
        free(b.dirty);
        vcs_manifest_free(out);
        LOG_FAIL("vcs", "worktree walk failed");
    }

    /* Persist recomputed rows and prune paths no longer in the tracked set in
     * one transaction. Pruning is load-bearing for the dev loop: generated
     * agent worktrees may disappear or become newly ignored, and their stale
     * cache rows must not tax every later snapshot. */
    vcs_manifest_sort(out);
    bool ok = true;
    if (idx) {
        if (vcs_index_begin(idx)) {
            ok = vcs_index_stat_prune_in_tx(idx, out);
            for (size_t i = 0; ok && i < b.dirty_count; i++) {
                struct dirty_row *dr = &b.dirty[i];
                if (!vcs_index_stat_put_in_tx(idx, dr->path, dr->mtime_ns,
                                              dr->size, dr->ctime_ns, dr->blob)) {
                    ok = false;
                    break;
                }
            }
            if (ok)
                ok = vcs_index_commit(idx);
            else
                vcs_index_rollback(idx);
        } else {
            ok = false;
        }
    }

    for (size_t i = 0; i < b.dirty_count; i++)
        free(b.dirty[i].path);
    free(b.dirty);

    if (!ok) {
        vcs_manifest_free(out);
        LOG_FAIL("vcs", "stat-cache write-back failed");
    }
    return true;
}
