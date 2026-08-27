/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_merkle — a SHA3-256 Merkle tree over the indexed source tree, so
 * "what does this checkout contain" is one 32-byte answer and "did lib/net
 * change" is one 32-byte comparison instead of a rescan.
 *
 * ── Shape ──
 * LEAF        one indexed source file (exactly the set ci_enumerate_sources()
 *             walks: the .c/.h under the configured lib/app/core/config/tools/
 *             domain/adapters/ports/src roots). Digest binds the file's
 *             repo-relative path, its byte length, and its bytes.
 * INTERNAL    one directory that has at least one indexed file below it. Digest
 *             binds the directory's repo-relative path and, in one fixed order,
 *             every direct child's kind, name, and digest.
 * ROOT        the internal node whose path is "" — the identity of the entire
 *             indexed source state.
 *
 * Child order is the ONLY thing that makes two machines agree, so it is fixed
 * and documented in one place (codeindex_merkle.c, `merkle_child_key`): direct
 * children are ordered by strcmp over the child's name for a file and over the
 * child's name followed by '/' for a directory. That is exactly the order in
 * which children first appear in ci_enumerate_sources()' sorted repo-relative
 * path stream, so the builder needs no second sort and cannot disagree with the
 * documented rule. Nothing absolute-path-dependent enters any preimage: two
 * copies of the same tree in different directories produce the same root.
 *
 * ── Ground truth ──
 * The files on disk are authoritative; this is a CACHE and an IDENTITY. Nodes
 * are persisted at <root>/.codeindex/source_tree.merkle purely so a refresh
 * after editing N files re-reads N files instead of all of them. The complete
 * image is SHA3-sealed. A snapshot that is missing, truncated, of an older
 * source-policy format, or simply wrong is DISCARDED and recomputed. Every
 * refresh still enumerates and stats the live inventory before reusing bytes.
 * Deleting source_tree.merkle is always safe and costs only one full pass.
 */

#ifndef ZCL_CODEINDEX_MERKLE_H
#define ZCL_CODEINDEX_MERKLE_H

#include "core/zcl_ids.h"

#include <stdbool.h>
#include <stdint.h>

/* One directory subtree, or the whole tree when `path` is "". Counts are
 * RECURSIVE (everything below the node); `direct_children` is not. */
struct ci_merkle_node {
    char                   path[256];
    struct zcl_sha3_digest digest;
    uint32_t               file_count;      /* indexed files below, recursive */
    uint32_t               dir_count;       /* directory nodes below, exclusive */
    uint32_t               direct_children; /* immediate files + subdirectories */
    uint64_t               total_bytes;     /* sum of indexed file sizes below */
};

/* One indexed source file. */
struct ci_merkle_leaf {
    char                   path[256];
    struct zcl_sha3_digest digest;
    uint64_t               size;
};

/* What the last refresh actually cost. Derived per call, never persisted —
 * these are the numbers that make the incrementality claim checkable instead
 * of asserted. */
struct ci_merkle_cost {
    uint32_t files_total;    /* leaves in the tree */
    uint32_t files_read;     /* leaves whose bytes were re-read this refresh */
    uint32_t leaves_reused;  /* leaves served from the snapshot (files_total-read) */
    uint64_t bytes_total;    /* total bytes represented by every leaf */
    uint64_t bytes_read;     /* file bytes hashed this refresh */
    uint32_t nodes_total;    /* directory nodes incl. the root */
    uint32_t nodes_hashed;   /* directory nodes whose digest was recomputed */
    uint32_t nodes_reused;   /* directory nodes served from the snapshot */
    bool     snapshot_used;  /* a usable snapshot was found and read */
    bool     snapshot_saved; /* a new snapshot was published this refresh */
    bool     inventory_changed; /* sorted live paths differ from snapshot */
    bool     full_rescan;     /* no snapshot, invalid/policy, or inventory drift */
};

/* An immutable in-memory Merkle tree. */
struct ci_merkle;

/* Build the tree for the checkout at `root`, reusing <root>/.codeindex/
 * source_tree.merkle for every file whose (dev,ino,size,mtime,ctime) cache key
 * is unchanged, and publishing an updated snapshot when anything moved.
 * `cost` (may be NULL) receives the accounting above. NULL on hard failure
 * (unreadable source root); a bad snapshot is never a failure. */
struct ci_merkle *ci_merkle_refresh(const char *root, struct ci_merkle_cost *cost);

/* Authority path for resident source epochs. Like refresh, but an inventory
 * change discards the just-updated cache and performs one complete byte pass.
 * This makes missing/invalid/policy/inventory cases share one explicit cold
 * fallback while the normal unchanged startup reads zero source bytes. */
struct ci_merkle *ci_merkle_refresh_reconciled(
    const char *root, struct ci_merkle_cost *cost);

/* Same, but never reads or writes the snapshot: every leaf is re-read. This is
 * the from-scratch reference path — determinism and incrementality are both
 * measured against it. */
struct ci_merkle *ci_merkle_build_cold(const char *root,
                                       struct ci_merkle_cost *cost);

void ci_merkle_free(struct ci_merkle *m);

/* The whole-tree root node (path ""). */
bool ci_merkle_root(const struct ci_merkle *m, struct ci_merkle_node *out);

/* Look up one directory subtree. `dirpath` is repo-relative with no trailing
 * slash; "", ".", and "/" all mean the whole tree. Absence is not an error:
 * *found is set false and true is returned. */
bool ci_merkle_node(const struct ci_merkle *m, const char *dirpath,
                    struct ci_merkle_node *out, bool *found);

/* Look up one indexed file's leaf. Absence is not an error. */
bool ci_merkle_leaf(const struct ci_merkle *m, const char *filepath,
                    struct ci_merkle_leaf *out, bool *found);

/* Hash one known changed path with the exact leaf preimage used by this tree,
 * without enumerating or refreshing the repository. Missing is an honest
 * result (*found=false); symlinks, path escapes, type changes, and bytes that
 * mutate during the read fail closed. This is the resident edit-epoch seam. */
bool ci_merkle_hash_changed_leaf(const char *root, const char *filepath,
                                 struct ci_merkle_leaf *out, bool *found);

/* Direct subdirectories of `dirpath`, in the documented child order. Fills up
 * to `cap` rows, returns the count of direct subdirectories that EXIST (which
 * may exceed `cap`, so a caller can report truncation), -1 on error. */
int ci_merkle_child_dirs(const struct ci_merkle *m, const char *dirpath,
                         struct ci_merkle_node *out, int cap);

/* Lowercase hex of a digest; `out` must hold 65 bytes. */
void ci_merkle_hex(const struct zcl_sha3_digest *d, char out[65]);

/* Remove the persisted snapshot for `root`. Always safe (derived data); a
 * missing snapshot is success. */
bool ci_merkle_forget(const char *root);

#endif /* ZCL_CODEINDEX_MERKLE_H */
