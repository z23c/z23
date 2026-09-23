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

#endif /* ZCL_VCS_ZCODE_PUBLICATION_INDEX_H */
