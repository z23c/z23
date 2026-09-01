/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm — bounded content.v2 source-swarm wire contract.
 *
 * This is a pure codec/verification layer. It grants no filesystem, network,
 * wallet, payment, install, build, execution, or publication authority. A
 * caller may announce a content.v2 package root, request either its manifest
 * or one manifest-addressed chunk, return bytes, and cancel an in-flight
 * request. Content bytes earn trust only after package_swarm_verify_data()
 * matches the DATA object to the caller's exact outstanding WANT and checks
 * it against the canonical content.v2 manifest.
 *
 * Integer fields are little-endian. Parsers reject unknown flags, noncanonical
 * coordinates, zero identities, oversized frames, truncation, and trailing
 * bytes. One response carries at most one 1 MiB content.v2 chunk, which keeps
 * memory and peer-accounting bounds explicit. */

#ifndef ZCL_VCS_PACKAGE_SWARM_H
#define ZCL_VCS_PACKAGE_SWARM_H

#include "vcs/package_manifest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_SWARM_VERSION 1u
#define VCS_PACKAGE_SWARM_HEADER_BYTES 8u
#define VCS_PACKAGE_SWARM_MAX_WIRE_BYTES \
    (VCS_PACKAGE_SWARM_HEADER_BYTES + 88u + VCS_PACKAGE_CHUNK_BYTES)

enum vcs_package_swarm_type {
    VCS_PACKAGE_SWARM_ANNOUNCE = 1,
    VCS_PACKAGE_SWARM_WANT = 2,
    VCS_PACKAGE_SWARM_DATA = 3,
    VCS_PACKAGE_SWARM_CANCEL = 4,
};

enum vcs_package_swarm_object_kind {
    VCS_PACKAGE_SWARM_OBJECT_MANIFEST = 1,
    VCS_PACKAGE_SWARM_OBJECT_CHUNK = 2,
};

struct vcs_package_swarm_announce {
    uint8_t package_root[32];
    uint32_t manifest_bytes;
    uint32_t file_count;
    uint64_t total_bytes;
    uint32_t total_chunks;
};

struct vcs_package_swarm_object {
    uint64_t request_id;
    uint8_t package_root[32];
    uint8_t object_kind;
    /* UINT32_MAX/UINT32_MAX for a manifest; bounded indexes for a chunk. */
    /* file_index is the manifest's canonical ascending path-order index, never
     * caller insertion order. package_manifest maintains this invariant. */
    uint32_t file_index;
    uint32_t chunk_index;
    /* Zero for a manifest; exact raw SHA3-256 chunk hash for a chunk. */
    uint8_t expected_hash[32];
};

struct vcs_package_swarm_data {
    struct vcs_package_swarm_object object;
    /* Borrowed view into the parsed wire buffer; never heap-owned here. */
    const uint8_t *bytes;
    uint32_t bytes_len;
};

struct vcs_package_swarm_cancel {
    uint64_t request_id;
    uint8_t package_root[32];
};

struct vcs_package_swarm_message {
    uint8_t type;
    union {
        struct vcs_package_swarm_announce announce;
        struct vcs_package_swarm_object want;
        struct vcs_package_swarm_data data;
        struct vcs_package_swarm_cancel cancel;
    } body;
};

/* Exact canonical wire size, or zero for an invalid message. */
size_t vcs_package_swarm_wire_size(
    const struct vcs_package_swarm_message *message);

/* Serialize into caller-owned storage. On a short buffer, returns false and
 * writes the required canonical size to *out_len. */
bool vcs_package_swarm_serialize(
    const struct vcs_package_swarm_message *message,
    uint8_t *out, size_t out_capacity, size_t *out_len);

/* Parse one exact frame. DATA bytes borrow from wire and remain valid only as
 * long as wire does. `out` is zeroed on every rejection. */
bool vcs_package_swarm_parse(const uint8_t *wire, size_t wire_len,
                             struct vcs_package_swarm_message *out);

/* Verify a DATA response against one exact outstanding WANT and content.v2.
 * All request/root/kind/coordinate/hash fields must match first. Manifest data
 * must parse and reproduce object.package_root. Chunk data must match the
 * manifest, exact final-chunk length, and SHA3. Callers still own request-id
 * uniqueness, peer/session scope, one-shot consumption, and replay rejection.
 * This verifies byte identity only; it does not authorize storage/execution. */
bool vcs_package_swarm_verify_data(
    const struct vcs_package_manifest *manifest,
    const struct vcs_package_swarm_object *expected_want,
    const struct vcs_package_swarm_data *data);

#endif /* ZCL_VCS_PACKAGE_SWARM_H */
