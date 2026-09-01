/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs — the ZVCS façade: open/close a repo and the high-level verbs
 * (snapshot, status, log, revert) that compose the object store, manifest,
 * index, commit log, and seal guard.
 *
 * A ZVCS repo lives in the working copy beside .git/ as <repo_root>/.zvcs/:
 *   objects/     content-addressed blob + manifest store (vcs_object)
 *   commits.log  append-only self-verifying commit log (event_log)
 *   index.kv     derived SQLite WAL: stat-cache, refs, seal_pin, anchors
 *
 * "code fearlessly, not recklessly": a snapshot that would change a sealed
 * path (the consensus core + neighbours) is REFUSED (returns VCS_REFUSED,
 * exit 3) unless a one-shot unseal token authorises it. */

#ifndef ZCL_VCS_H
#define ZCL_VCS_H

#include "vcs/vcs_commit.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_manifest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Return codes shared by the façade verbs. */
enum vcs_result {
    VCS_OK        = 0,
    VCS_ERR       = -1,
    VCS_ENOTIMPL  = -2,
    VCS_REFUSED   = 3,   /* sealed-path change without a valid unseal token */
    VCS_EPARTIAL  = 4,   /* vcs_revert: a partial, honestly-named state. Either
                          * (a) the source revert + forward commit already
                          * landed (append-only, never undone) but a requested
                          * relink activation refused or failed, or (b) the
                          * two-phase worktree restore failed during phase 2
                          * (a near-impossible same-filesystem rename/unlink),
                          * leaving some paths flipped — the failing call names
                          * exactly which on stderr. Phase-1 failures never
                          * reach here: they leave the worktree untouched and
                          * return VCS_ERR. */
};

struct vcs_repo;

/* Metadata bound into a snapshot's commit record. String fields may be NULL
 * (=> empty); the 32-byte hash pointers may be NULL (=> all-zero). */
struct vcs_snapshot_meta {
    uint32_t       verdict_status;
    const char    *phase;
    uint64_t       elapsed_ms;
    const uint8_t *generation_sha256;  /* 32 bytes or NULL */
    const uint8_t *failure_hash;       /* 32 bytes or NULL */
    const char    *agent_id;
    const char    *session_id;
    const char    *task_ref;
};

/* Open (creating .zvcs/ if needed) the repo rooted at repo_root. NULL on
 * failure. */
struct vcs_repo *vcs_open(const char *repo_root);
void vcs_close(struct vcs_repo *r);

/* Accessors (handy for tests / seal-token grants). */
struct vcs_index *vcs_repo_index(struct vcs_repo *r);
const char       *vcs_repo_root(struct vcs_repo *r);

/* Capture the current tracked worktree as the existing path-sorted ZVCS
 * manifest plus domain-tagged blob objects, without creating a commit or
 * moving HEAD. The tree is scanned again before publication; any drift is a
 * refusal. This is the portable immutable source authority for ZCODE tasks. */
int vcs_tree_capture(struct vcs_repo *r, uint8_t out_tree_hash[32]);

/* Convenience form for task planning: opens only the object/index stores, not
 * the commit log, and therefore cannot create or advance history. */
int vcs_tree_capture_path(const char *repo_root, uint8_t out_tree_hash[32]);

/* Capture scan_root while publishing its immutable manifest and blobs into
 * object_store_root's existing ZVCS CAS.  This is the candidate-workspace
 * import primitive: source bytes may be prepared elsewhere, but all authority
 * enters through the requester's store and the same stable double scan. */
int vcs_tree_capture_into(const char *scan_root, const char *object_store_root,
                          uint8_t out_tree_hash[32]);

/* Load one captured manifest by tree hash and rederive its structural address
 * before returning it. Caller owns *out and releases it with
 * vcs_manifest_free(). */
bool vcs_tree_load(const char *repo_root, const uint8_t tree_hash[32],
                   struct vcs_manifest *out);

/* Rebuild one captured tree from verified CAS blobs into an existing empty
 * destination. Files are created with O_EXCL and either their captured mode
 * (file_mode 0) or the caller-selected 0400/0600 mode; source paths must
 * remain canonical regular files. This is the
 * shared materializer for confined builds and candidate handoff workspaces. */
int vcs_tree_materialize(const char *object_store_root,
                         const uint8_t tree_hash[32],
                         const char *destination, uint64_t maximum_bytes,
                         uint32_t file_mode);

/* Take a snapshot: build the worktree manifest, store dirty blobs + the
 * manifest, check the seal, append a commit, and advance HEAD/anchor/seal_pin.
 * On success writes the 32-byte commit id to out_commit_id. Returns VCS_OK,
 * VCS_REFUSED (sealed-path change), or VCS_ERR. */
int vcs_snapshot(struct vcs_repo *r, const struct vcs_snapshot_meta *meta,
                 uint8_t out_commit_id[32]);

/* Report working-tree changes vs HEAD (stat-cache warm path). Fires cb per
 * differing path (may be NULL to just count) and writes the change count to
 * *out_nchanges (may be NULL). Returns VCS_OK / VCS_ERR. */
int vcs_status(struct vcs_repo *r, vcs_diff_cb cb, void *user,
               size_t *out_nchanges);

/* Walk the commit log newest-first, invoking cb per commit until it returns
 * false or `limit` commits are emitted (0 = no limit). Returns VCS_OK/ERR. */
typedef bool (*vcs_log_cb)(const struct vcs_commit *c,
                           const uint8_t commit_id[32], void *user);
int vcs_log(struct vcs_repo *r, size_t limit, vcs_log_cb cb, void *user);

/* Relink callback for vcs_revert's binary-generation half. vcs.c
 * stays policy-free: it only decides WHEN to call activate_generation (the
 * target commit bound a non-zero generation_sha256) and how to interpret the
 * result, never HOW to activate a generation — that policy lives entirely in
 * the ops implementation supplied by the caller (kept out of contexts/commons/modules/vcs/ so the
 * ZVCS sovereignty lint gate stays green: this directory never spawns a
 * process or names the external version-control tool it replaces).
 *
 * activate_generation must return true on a successful activation and false
 * otherwise. For a hotswap-anchored commit — one whose generation_sha256
 * addresses a standalone .so artifact rather than a full binary-generation
 * directory — the activator is expected to REFUSE (return false) rather than
 * guess at a restore recipe; vcs_revert then reports VCS_EPARTIAL while the
 * already-landed source revert + forward commit stand untouched
 * (append-only, never undone). */
struct vcs_revert_relink_ops {
    bool (*activate_generation)(const uint8_t gen_sha256[32], void *ctx);
    void *ctx;
};

/* Restore the worktree to the manifest of target_commit (overwrite differing
 * tracked files atomically, delete files absent from the target), then record
 * the restoration as a forward commit (history stays append-only) whose id is
 * written to out_new_commit.
 *
 * relink controls the binary-generation half:
 *   - NULL: source-only revert. Returns VCS_OK once the forward commit lands
 *     (no ENOTIMPL — a plain source revert is always fully implemented).
 *   - non-NULL: after the forward commit lands, if the target commit's
 *     generation_sha256 is non-zero, relink->activate_generation() is called
 *     with it. Activation success => VCS_OK. Activation failure/refusal =>
 *     VCS_EPARTIAL (the source revert + forward commit already stand; never
 *     undone). An all-zero generation_sha256 has nothing to relink => VCS_OK
 *     without calling activate_generation.
 *
 * Returns VCS_OK, VCS_EPARTIAL, VCS_REFUSED, or VCS_ERR. */
int vcs_revert(struct vcs_repo *r, const uint8_t target_commit[32],
               const struct vcs_revert_relink_ops *relink,
               uint8_t out_new_commit[32]);

#endif /* ZCL_VCS_H */
