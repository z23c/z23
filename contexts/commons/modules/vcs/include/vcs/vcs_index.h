/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_index — the ZVCS derived-state store: a dedicated SQLite WAL file at
 * <repo_root>/.zvcs/index.kv, one handle per repo, one writer, writes framed
 * in BEGIN IMMEDIATE.
 *
 * ── OUTSIDE the node.db ActiveRecord lifecycle by design ──
 * index.kv is NOT node.db and its rows are NOT AR models — it follows the
 * same kernel-store doctrine as progress.kv (storage/progress_store.h) and
 * seal_kv: a small dedicated single-writer WAL below the AR layer. Raw
 * sqlite3_step here carries the `// raw-sql-ok:vcs-index-kernel-store`
 * marker for the lint gate.
 *
 * The store is DERIVED: every row can be regenerated from the worktree plus
 * commits.log by vcs_index_rebuild() ("recompute, never repair"). It caches
 * per-path stat->blob mappings (stat_cache), named refs (HEAD), the pinned
 * sealset (seal_pin), per-commit anchor bindings (anchor), and free-form
 * meta.
 *
 * Tables:
 *   stat_cache(path PK, mtime_ns, size, ctime_ns, blob_hash)
 *   refs(name PK, commit_id)
 *   seal_pin(id=0, sealset_hash, updated_at)
 *   anchor(commit_id PK, generation_sha256, verdict_status, bound_at)
 *   meta(key PK, value) */

#ifndef ZCL_VCS_INDEX_H
#define ZCL_VCS_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vcs_index;
struct vcs_manifest;

/* Open (creating if needed) <repo_root>/.zvcs/index.kv in WAL mode and ensure
 * the schema. Returns NULL on failure. */
struct vcs_index *vcs_index_open(const char *repo_root);
void vcs_index_close(struct vcs_index *idx);

/* ── write transaction control (one writer) ──
 * Take the handle's writer lock + BEGIN IMMEDIATE. Between begin and
 * commit/rollback the caller may issue the *_in_tx writes below; they must
 * NOT be issued outside an open txn. commit/rollback release the lock. */
bool vcs_index_begin(struct vcs_index *idx);
bool vcs_index_commit(struct vcs_index *idx);
bool vcs_index_rollback(struct vcs_index *idx);

/* Writes — require an open txn (caller between begin/commit). */
bool vcs_index_stat_put_in_tx(struct vcs_index *idx, const char *path,
                              int64_t mtime_ns, int64_t size, int64_t ctime_ns,
                              const uint8_t blob[32]);
/* Delete cached paths absent from the current manifest. This keeps ignored,
 * removed, and renamed checkout files from making the warm path grow without
 * bound. Requires an open transaction. */
bool vcs_index_stat_prune_in_tx(struct vcs_index *idx,
                                const struct vcs_manifest *manifest);
bool vcs_index_ref_set_in_tx(struct vcs_index *idx, const char *name,
                             const uint8_t commit_id[32]);
bool vcs_index_seal_pin_set_in_tx(struct vcs_index *idx,
                                  const uint8_t sealset_hash[32]);
bool vcs_index_anchor_put_in_tx(struct vcs_index *idx, const uint8_t commit_id[32],
                                const uint8_t generation_sha256[32],
                                uint32_t verdict_status);
bool vcs_index_meta_set_in_tx(struct vcs_index *idx, const char *key,
                              const void *value, size_t value_len);
bool vcs_index_meta_delete_in_tx(struct vcs_index *idx, const char *key);
/* Rebuildable accelerator: one ZVCS blob root maps to one immutable
 * VCS_TAG_PACKAGE_BLOB_MAP object. Writes require an open transaction. */
bool vcs_index_package_map_put_in_tx(
    struct vcs_index *idx, const uint8_t blob_root[32],
    const uint8_t mapping_root[32]);

/* Reads — take the handle lock themselves; do not require an open txn. */
bool vcs_index_ref_get(struct vcs_index *idx, const char *name,
                       uint8_t commit_id[32], bool *found);
bool vcs_index_seal_pin_get(struct vcs_index *idx, uint8_t sealset_hash[32],
                            bool *found);
bool vcs_index_meta_get(struct vcs_index *idx, const char *key, void *out_buf,
                        size_t out_cap, size_t *out_len, bool *found);
bool vcs_index_package_map_get(
    struct vcs_index *idx, const uint8_t blob_root[32],
    uint8_t mapping_root[32], bool *found);

/* ── in-memory stat-cache snapshot ──
 * The whole stat_cache in one query, sorted by path for bsearch. This is the
 * warm-path primitive for status/build: N file stats + one SQL round-trip,
 * instead of one SELECT per file. */
struct vcs_stat_row {
    char    *path;
    int64_t  mtime_ns;
    int64_t  size;
    int64_t  ctime_ns;
    uint8_t  blob[32];
};
struct vcs_stat_cache {
    struct vcs_stat_row *rows;
    size_t               count;
    size_t               cap;
};
bool vcs_stat_cache_load(struct vcs_index *idx, struct vcs_stat_cache *out);
void vcs_stat_cache_free(struct vcs_stat_cache *sc);
/* bsearch by path; NULL if absent. */
const struct vcs_stat_row *vcs_stat_cache_find(const struct vcs_stat_cache *sc,
                                               const char *path);

/* Rebuild ALL derived rows from the worktree + commits.log. Clears the
 * tables, replays commits.log to rebuild HEAD / anchor / seal_pin, then
 * rehashes the worktree into stat_cache. Returns false on any hard error. */
bool vcs_index_rebuild(struct vcs_index *idx, const char *repo_root);

#endif /* ZCL_VCS_INDEX_H */
