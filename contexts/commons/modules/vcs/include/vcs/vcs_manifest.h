/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_manifest — the ZVCS snapshot manifest: a flat, path-sorted list of
 * tracked files (path -> mode/size/blob-hash). This is deliberately NOT a
 * blob/tree object DAG: a commit points at ONE manifest, and "what changed
 * since my snapshot" is a linear merge-join of two sorted manifests, the
 * O(n) primitive an agent needs.
 *
 * Canonical serialization (little-endian):
 *   [1  version]
 *   [8  entry_count]
 *   repeated entry_count times, in ascending path order:
 *     [2  path_len][path bytes (no NUL)][4 mode][8 size][32 blob]
 *
 * tree_hash = SHA3(0x22 || concat over sorted entries of
 *                  SHA3(0x21 || path || 0x00 || mode_le || size_le || blob)) */

#ifndef ZCL_VCS_MANIFEST_H
#define ZCL_VCS_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_MANIFEST_VERSION 1u
/* path_len is a 16-bit field on the wire. */
#define VCS_PATH_MAX 4096u

struct vcs_entry {
    char    *path;      /* heap, NUL-terminated, repo-relative, '/'-separated */
    uint32_t mode;      /* st_mode (type + permission bits) */
    uint64_t size;      /* file size in bytes */
    uint8_t  blob[32];  /* SHA3(0x20 || content) */
};

struct vcs_manifest {
    struct vcs_entry *entries;
    size_t            count;
    size_t            cap;
};

void vcs_manifest_init(struct vcs_manifest *m);
void vcs_manifest_free(struct vcs_manifest *m);

/* Build a manifest from the tracked worktree under repo_root. If idx is
 * non-NULL its stat_cache is consulted (a matching mtime_ns/size/ctime_ns
 * reuses the cached blob hash instead of re-reading the file) and every
 * recomputed entry is written back to the cache in one transaction. Blob
 * hashes are computed but NOT written to the object store — that is the
 * snapshot step's job. *out is init'd by this call. Returns false on a hard
 * error. */
struct vcs_index;
bool vcs_manifest_build(const char *repo_root, struct vcs_index *idx,
                        struct vcs_manifest *out);

/* Append an entry (copies path). Does NOT re-sort; call vcs_manifest_sort()
 * once after bulk adds, or use it only when adding in path order. Returns
 * false on allocation failure or an over-long path. */
bool vcs_manifest_add(struct vcs_manifest *m, const char *path, uint32_t mode,
                      uint64_t size, const uint8_t blob[32]);

/* Sort entries ascending by path (byte order). Idempotent. */
void vcs_manifest_sort(struct vcs_manifest *m);

/* Serialize m canonically (sorting first). Allocates *out (caller frees).
 * Returns false on a null arg / allocation failure / over-long path. */
bool vcs_manifest_serialize(const struct vcs_manifest *m, uint8_t **out,
                            size_t *out_len);

/* Parse a canonical manifest into *out (which is init'd by this call).
 * Returns false on truncation, a bad version, or an over-long path. */
bool vcs_manifest_parse(const uint8_t *in, size_t len, struct vcs_manifest *out);

/* Hash of a single entry: SHA3(0x21 || path || 0x00 || mode_le || size_le ||
 * blob). Exposed because the seal set is a commitment over entry hashes. */
bool vcs_manifest_entry_hash(const struct vcs_entry *e, uint8_t out[32]);

/* tree_hash over the whole manifest (sorts first). */
bool vcs_manifest_tree_hash(const struct vcs_manifest *m, uint8_t out[32]);

/* Merge-join diff of two path-sorted manifests. For each differing path the
 * callback fires with one of the change kinds below; identical entries emit
 * nothing. a/b are the entries from the old/new manifest respectively (the
 * absent side is NULL). Both manifests are sorted first. */
enum vcs_diff_kind {
    VCS_DIFF_ADDED    = 1,  /* in b, not in a */
    VCS_DIFF_REMOVED  = 2,  /* in a, not in b */
    VCS_DIFF_MODIFIED = 3,  /* same path, blob or mode differs */
};

typedef void (*vcs_diff_cb)(enum vcs_diff_kind kind, const struct vcs_entry *a,
                            const struct vcs_entry *b, void *user);

void vcs_manifest_diff(struct vcs_manifest *a, struct vcs_manifest *b,
                       vcs_diff_cb cb, void *user);

#endif /* ZCL_VCS_MANIFEST_H */
