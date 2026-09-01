/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Define optional mirror receipts for proven P2P source. */

#ifndef ZCL_VCS_DEVLOOP_MIRROR_H
#define ZCL_VCS_DEVLOOP_MIRROR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_DEVLOOP_MIRROR_RECEIPT_VERSION 1u
#define VCS_DEVLOOP_MIRROR_OID_MAX_BYTES 32u

/* Optional, declared mirror evidence. This object is never source,
 * publication, package, or proof authority: those roots are copied from the
 * already-verified provider publication chain before this receipt can exist. */
struct vcs_devloop_mirror_receipt {
    uint32_t version;
    uint8_t job_root[32];
    uint8_t vcs_commit_root[32];
    uint8_t source_identity_sha256[32];
    uint8_t proof_receipt_root[32];
    uint8_t release_root[32];
    uint8_t workspace_root[32];
    uint8_t provider_record_root[32];
    uint8_t git_oid_len;
    uint8_t git_oid[VCS_DEVLOOP_MIRROR_OID_MAX_BYTES];
};

/* Record one successful, operator-declared optional mirror after the provider
 * phase. git_oid is optional; when present it is a 20- or 32-byte opaque Git
 * object identifier. The function never invokes Git, a network, or an API.
 * One job has at most one immutable mirror receipt; exact retries reuse it. */
bool vcs_devloop_mirror_record(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *git_oid, size_t git_oid_len,
    uint8_t receipt_root_out[32], bool *reused_out);

enum vcs_devloop_mirror_lookup {
    VCS_DEVLOOP_MIRROR_ABSENT = 0,
    VCS_DEVLOOP_MIRROR_FOUND = 1,
    VCS_DEVLOOP_MIRROR_INVALID = 2,
};

/* Bounded, root-verifying reads. Absence is distinct from corrupt or
 * ambiguous evidence so status can say mirror_pending without laundering a
 * damaged receipt into an honest absence. */
bool vcs_devloop_mirror_receipt_load(
    const char *repo_root, const uint8_t receipt_root[32],
    struct vcs_devloop_mirror_receipt *out);
enum vcs_devloop_mirror_lookup vcs_devloop_mirror_load_for_job(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_mirror_receipt *out,
    uint8_t receipt_root_out[32]);

#endif /* ZCL_VCS_DEVLOOP_MIRROR_H */
