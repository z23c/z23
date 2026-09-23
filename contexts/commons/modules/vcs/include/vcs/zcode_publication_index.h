/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Rebuildable, read-only CAS projection for publication observations. */
#ifndef ZCL_VCS_ZCODE_PUBLICATION_INDEX_H
#define ZCL_VCS_ZCODE_PUBLICATION_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_PUBLICATION_INDEX_MAX_OBSERVATIONS 8192u

enum vcs_zcode_publication_observation_kind {
    VCS_ZCODE_OBSERVATION_ATTEMPT_RESULT = 1,
    VCS_ZCODE_OBSERVATION_REMOTE_RECEIPT = 2,
};

/* This is a pointer into existing CAS authority, not a lifecycle verdict.
 * A caller must reload the wire and apply current receiver policy. */
struct vcs_zcode_publication_observation_entry {
    char root_hex[65];
    char publication_root_hex[65];
    char signer_pubkey_hex[65];
    uint8_t kind;
    uint8_t outcome; /* attempt result only; never remote success */
};

struct vcs_zcode_publication_index;

/* A restart view for one immutable intent. Observations are signed CAS
 * objects, but a remote receipt still needs independent remote verification.
 * An incomplete scan refuses a decision. Even an empty complete scan only
 * permits a final recheck under the existing land/action lease; it never
 * grants dispatch authority by itself. */
enum vcs_zcode_publication_recovery_state {
    VCS_ZCODE_RECOVERY_RECHECK_UNDER_LEASE = 1,
    VCS_ZCODE_RECOVERY_RECONCILE_REMOTE = 2,
};

struct vcs_zcode_publication_recovery_view {
    enum vcs_zcode_publication_recovery_state state;
    size_t attempt_results;
    size_t remote_receipts;
    size_t unknown_attempts;
    size_t accepted_attempts;
    size_t rejected_attempts;
};

/* Rebuild from repo_root's CAS. Complete means this directory walk saw no
 * read/validation/cap error; it is not a concurrent-write snapshot. Before
 * dispatch, the existing land/action lease must fence and recheck for prior
 * results. A missing CAS is incomplete, never a complete empty history. */
struct vcs_zcode_publication_index *vcs_zcode_publication_index_build(
    const char *repo_root);
void vcs_zcode_publication_index_free(struct vcs_zcode_publication_index *index);
bool vcs_zcode_publication_index_complete(
    const struct vcs_zcode_publication_index *index);
size_t vcs_zcode_publication_index_count(
    const struct vcs_zcode_publication_index *index);
const struct vcs_zcode_publication_observation_entry *
vcs_zcode_publication_index_at(
    const struct vcs_zcode_publication_index *index, size_t i);
bool vcs_zcode_publication_index_recovery(
    const struct vcs_zcode_publication_index *index,
    const uint8_t publication_root[32],
    struct vcs_zcode_publication_recovery_view *out);

#endif /* ZCL_VCS_ZCODE_PUBLICATION_INDEX_H */
