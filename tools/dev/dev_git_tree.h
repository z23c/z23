/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded exact Git tree observation contract for landing and dispatch checks. */
#ifndef ZCL_DEV_GIT_TREE_H
#define ZCL_DEV_GIT_TREE_H

#include "util/result.h"
#include "vcs/vcs_manifest.h"

/* Local Git publication bridge, never source authority. Every blob (including
 * symlink target bytes) is independently hashed with the canonical blob tag.
 * No ignore policy is applied. Gitlinks have no blob bytes in this repository
 * and remain unresolved for a content-complete claim. source_closure_root
 * identifies their exact paths and commit OIDs without claiming possession
 * or verification of the referenced submodule bytes.
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
    uint8_t file_manifest_root[32];
    uint8_t source_closure_root[32];
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

/* Receiver-owned locators are separate from the public gitlink path. One
 * entry is required for EVERY gitlink in the observed superproject tree;
 * expected_source_closure_root must come from a candidate-bound policy.
 * The verifier reads each pinned dependency commit, never executes it. */
struct zcl_dev_git_dependency_input {
    const char *path;
    const char *repo_locator;
    uint8_t expected_source_closure_root[32];
};

struct zcl_dev_git_dependency_check {
    uint8_t super_source_closure_root[32];
    uint8_t verified_dependency_root[32];
    size_t dependencies_verified;
    bool complete;
};

/* Bounded, independent exact-object observation. Nested gitlinks refuse until
 * a receiver supplies their own complete closure. No policy/signing grant or
 * publication authority follows from this read-only result. */
struct zcl_result zcl_dev_git_tree_verify_dependencies(
    const char *repo, const char *head,
    const struct zcl_dev_git_dependency_input *inputs, size_t input_count,
    int timeout_ms, struct zcl_dev_git_dependency_check *out);

/* Independently fetch one approved target ref into a fresh private Git store,
 * verify expected_base -> intended_head -> fetched_tip, and read exact source
 * bytes at head and tip. The caller binds the local locator to target_identity
 * under receiver policy. Every gitlink must have a receiver-owned locator and
 * pinned source closure; the same pinned set must cover both observed commits.
 * A changed gitlink at an advanced tip refuses until a new receiver policy is
 * supplied. This result alone cannot seal or persist a remote receipt. A
 * bounded depth may refuse a valid old ancestor rather than guess. */
struct zcl_dev_git_remote_observation {
    char fetched_tip[65];
    uint8_t intended_source_root[32];
    uint8_t fetched_source_root[32];
    uint8_t intended_closure_root[32];
    uint8_t fetched_closure_root[32];
    uint8_t intended_verified_dependency_root[32];
    uint8_t fetched_verified_dependency_root[32];
    uint8_t verified_ancestry_root[32];
    uint8_t evidence_root[32];
    bool complete;
};

struct zcl_result zcl_dev_git_remote_observe(
    const char *target_locator, const char *target_ref,
    const uint8_t target_identity_root[32],
    const char *expected_base, const char *intended_head,
    const uint8_t expected_head_source_root[32],
    const uint8_t expected_head_closure_root[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count,
    int timeout_ms, struct zcl_dev_git_remote_observation *out);

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

/* Admit a Gitlink only after independently reading every pinned dependency
 * and matching the receiver's exact superproject closure root. The ordinary
 * source check stays strict. This does not grant publication authority. */
struct zcl_result zcl_dev_git_tree_check_source_with_dependencies(
    const char *repo, const char *head, const uint8_t source_root[32],
    const uint8_t expected_closure_root[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count, int timeout_ms,
    struct zcl_dev_git_source_check *out,
    struct zcl_dev_git_dependency_check *dependency_out);

struct zcl_dev_git_publication_check {
    uint8_t publication_root[32];
    uint8_t attachment_root[32];
    uint8_t bundle_sha256[32];
    uint8_t candidate_root[32];
    uint8_t source_root[32];
    char expected_base[65];
    char head[65];
    struct zcl_dev_git_source_check source;
    bool verified;
};

/* Verify a persisted signed intent, attached actual bundle bytes and exact
 * canonical candidate against the receiver's target and committed Git bytes. Git
 * replacement objects and external configuration are disabled for ancestry.
 * This is a local admission observation, not target policy, proof-set
 * eligibility, a signing grant, or permission to push. Refusal clears out. */
struct zcl_result zcl_dev_git_publication_check(
    const char *repo, const uint8_t publication_root[32],
    const uint8_t attachment_root[32], const char *bundle_path,
    const uint8_t publisher_signer[32],
    const uint8_t expected_target_identity_root[32],
    const char *expected_target_ref, const char *expected_base,
    const char *head, uint64_t max_bundle_bytes, int timeout_ms,
    struct zcl_dev_git_publication_check *out);

struct zcl_result zcl_dev_git_publication_check_with_dependencies(
    const char *repo, const uint8_t publication_root[32],
    const uint8_t attachment_root[32], const char *bundle_path,
    const uint8_t publisher_signer[32],
    const uint8_t expected_target_identity_root[32],
    const char *expected_target_ref, const char *expected_base,
    const char *head, const uint8_t expected_closure_root[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count, uint64_t max_bundle_bytes, int timeout_ms,
    struct zcl_dev_git_publication_check *out);

#endif
