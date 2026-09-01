/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_commit — the ZVCS commit record: a self-hashing, fixed-layout,
 * little-endian struct that binds a source tree snapshot to its dev-cycle
 * verdict and the binary generation it produced.
 *
 * Canonical preimage (all fields except self_sha3), in order:
 *   [4   version]
 *   [32  parent]              (all-zero for the first commit)
 *   [32  tree_hash]
 *   [32  sealset_hash]
 *   [32  generation_sha256]
 *   [4   verdict_status]
 *   [24  phase]               (NUL-padded ASCII)
 *   [8   elapsed_ms]
 *   [32  failure_hash]
 *   [64  agent_id]            (NUL-padded ASCII)
 *   [64  session_id]          (NUL-padded ASCII)
 *   [128 task_ref]            (NUL-padded ASCII)
 *   [8   committed_at]        (unix seconds)
 * Serialized record = preimage || self_sha3, where
 *   self_sha3  = SHA3(preimage)                 (seal_kv self-verify discipline)
 *   commit_id  = SHA3(0x23 || preimage)         (the object-store address)
 * The record is appended to commits.log AND stored as an object whose content
 * is the preimage, so vcs_object_get(commit_id, VCS_TAG_COMMIT) round-trips. */

#ifndef ZCL_VCS_COMMIT_H
#define ZCL_VCS_COMMIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_COMMIT_VERSION   1u
#define VCS_COMMIT_PHASE_LEN 24
#define VCS_COMMIT_AGENT_LEN 64
#define VCS_COMMIT_SESSION_LEN 64
#define VCS_COMMIT_TASK_LEN  128

/* Preimage bytes (everything but self_sha3) + the 32-byte self hash. */
#define VCS_COMMIT_PREIMAGE_BYTES 464
#define VCS_COMMIT_RECORD_BYTES   (VCS_COMMIT_PREIMAGE_BYTES + 32)

struct vcs_commit {
    uint32_t version;
    uint8_t  parent[32];
    uint8_t  tree_hash[32];
    uint8_t  sealset_hash[32];
    uint8_t  generation_sha256[32];
    uint32_t verdict_status;
    char     phase[VCS_COMMIT_PHASE_LEN];
    uint64_t elapsed_ms;
    uint8_t  failure_hash[32];
    char     agent_id[VCS_COMMIT_AGENT_LEN];
    char     session_id[VCS_COMMIT_SESSION_LEN];
    char     task_ref[VCS_COMMIT_TASK_LEN];
    int64_t  committed_at;
    uint8_t  self_sha3[32];
};

/* Serialize c into out[VCS_COMMIT_RECORD_BYTES], computing + storing
 * self_sha3 (also copied back into c->self_sha3). Returns false on NULL. */
bool vcs_commit_serialize(struct vcs_commit *c,
                          uint8_t out[VCS_COMMIT_RECORD_BYTES]);

/* Deserialize in[len] (len must == VCS_COMMIT_RECORD_BYTES). *self_ok (if
 * non-NULL) reports whether the stored self_sha3 recomputes. A length/version
 * valid record with a bad self hash still returns true with *self_ok=false so
 * a reader can step past it. Returns false only on a hard parse failure. */
bool vcs_commit_deserialize(const uint8_t *in, size_t len,
                            struct vcs_commit *out, bool *self_ok);

/* Parse a bare preimage (len must == VCS_COMMIT_PREIMAGE_BYTES, e.g. the
 * commit object's content) into *out, recomputing self_sha3 from it. Returns
 * false on a bad length or version. */
bool vcs_commit_parse_preimage(const uint8_t *pre, size_t len,
                               struct vcs_commit *out);

/* commit_id = SHA3(0x23 || preimage(c)). */
bool vcs_commit_id(const struct vcs_commit *c, uint8_t out[32]);

/* The preimage alone (object-store content, addressed by commit_id). Writes
 * VCS_COMMIT_PREIMAGE_BYTES into out. Returns false on NULL. */
bool vcs_commit_preimage(const struct vcs_commit *c,
                         uint8_t out[VCS_COMMIT_PREIMAGE_BYTES]);

#endif /* ZCL_VCS_COMMIT_H */
