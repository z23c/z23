/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded exact Git tree observation contract for landing and dispatch checks. */
#ifndef ZCL_DEV_GIT_TREE_H
#define ZCL_DEV_GIT_TREE_H

#include "util/result.h"
#include "vcs/vcs_manifest.h"

/* Local Git publication bridge, never source authority. Every blob (including
 * symlink target bytes) is independently hashed with the canonical blob tag.
 * No ignore policy is applied. Gitlinks have no blob bytes in this repository
 * and are counted as unresolved; they never disappear into a complete claim.
 * Git retains executable classification, not arbitrary filesystem permissions.
 * Successful observation is NOT candidate qualification or publication authority.
 */
struct zcl_dev_gitlink {
    char *path;
    char oid[65];
};

struct zcl_dev_git_tree {
    struct vcs_manifest files;
    struct zcl_dev_gitlink *links;
    size_t gitlinks;
    size_t symlinks;
    uint64_t payload_bytes;
};

void zcl_dev_git_tree_free(struct zcl_dev_git_tree *tree);

/* Fixed memory/work ceilings: 32768 entries, 8 MiB tree listing, 64 MiB per
 * blob, 512 MiB combined payload. The positive caller deadline covers the
 * complete operation. head is an exact lowercase 40/64-digit external OID.
 * out must own no prior allocation. On refusal it is empty; on success the
 * caller releases the observation with zcl_dev_git_tree_free. Private temporary Git
 * metadata is created and removed; the source repository and CAS are not
 * written. Object reads use no source configuration, hooks or remotes. */
struct zcl_result zcl_dev_git_tree_read(
    const char *repo, const char *head, int timeout_ms,
    struct zcl_dev_git_tree *out);

struct zcl_dev_git_source_check {
    uint8_t source_root[32];
    char head[65];
    size_t matched, missing, changed, unexpected, excluded;
    size_t gitlinks, symlinks, unrepresentable_modes;
    bool observed;
    bool source_projection_matches;
    bool complete_content_matches;
};

/* Load the verified canonical source manifest from repo's CAS and compare it
 * with exact committed bytes. Every canonical entry is checked regardless of
 * current exclusions. Exclusions classify only unmatched committed extras;
 * they remain unresolved coverage. Modes must match exactly, without silently
 * normalizing permissions. Success means complete content equality only,
 * never proof eligibility, target authority, or dispatch permission.
 * Admission is limited to 8 MiB of canonical manifest wire and 32,768 entries;
 * otherwise valid larger canonical manifests are refused by this comparator.
 * On an observed mismatch the bound report is retained with observed=true;
 * on unavailable/invalid input it is empty. */
struct zcl_result zcl_dev_git_tree_check_source(
    const char *repo, const char *head, const uint8_t source_root[32],
    int timeout_ms, struct zcl_dev_git_source_check *out);

#endif
