/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fastobj_carrier — move a builder's zcl.fastobj.v1 cache between nodes
 * as an ORDINARY content.v2 package (the transport-carrier pattern from
 * docs/work/WIRE_COMPILE_CACHE.md slice 2). No new CAS object, no new
 * wire frame: the package swarm sees one manifest and immutable chunks,
 * and a deterministic root commits identical object bytes.
 *
 * Inner layout (fixed, like package_transport's fixed paths):
 *   zcl-fastobj-carrier.v1/objects/<64 hex>.o      cached object bytes
 *   zcl-fastobj-carrier.v1/objects/<64 hex>.json   sidecar bytes verbatim
 *
 * Both members of every entry are verified before they are exported and
 * again before they are admitted: the sidecar must parse as
 * zcl.fastobj.sidecar.v1, its key_components must hash to the entry's own
 * filename, and SHA3-256 of the object bytes must equal the sidecar's
 * object_sha3. Admitted entries land in the receiving cache in EXACTLY
 * the format the confined build worker stores on a miss, so the worker's
 * own hit-path verification (sidecar re-check, materialize, re-hash) runs
 * unchanged over imported bytes — the carrier adds no admission path,
 * widens no policy, and nothing it writes is ever promoted evidence.
 * A fastobj key remains an INPUT identity: the output anchor stays a
 * ZCLBLD receipt's artifact hash.
 */

#ifndef ZCL_VCS_FASTOBJ_CARRIER_H
#define ZCL_VCS_FASTOBJ_CARRIER_H

#include "vcs/package_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_FASTOBJ_CARRIER_PREFIX "zcl-fastobj-carrier.v1"
#define VCS_FASTOBJ_CARRIER_DIR VCS_FASTOBJ_CARRIER_PREFIX "/objects"

/* Bound the carrier: one entry per compile action, two files each, well
 * under the manifest's 8192-file grammar limit. */
#define VCS_FASTOBJ_CARRIER_MAX_ENTRIES 2048u

struct vcs_fastobj_carrier_stats {
    uint32_t entries;      /* verified object+sidecar pairs */
    uint64_t object_bytes; /* sum of carried object sizes */
    uint32_t files;        /* manifest files (2 * entries) */
    uint32_t chunks;       /* unique-in-package chunk count */
    uint64_t total_bytes;  /* manifest total bytes */
};

/* Scan a fastobj cache directory, verify every entry (a torn pair, a
 * sidecar whose key does not match its filename, or an object that does
 * not hash to its sidecar refuses the WHOLE export), build the content.v2
 * carrier, and admit manifest + chunks into `store` through the ordinary
 * verify-before-store paths. The carrier root is deterministic: the same
 * cache contents always produce the same root. */
bool vcs_fastobj_carrier_export(const char *cache_dir,
                                struct vcs_package_store *store,
                                uint8_t root_out[32],
                                struct vcs_fastobj_carrier_stats *stats,
                                char *err, size_t err_cap);

/* Offline wire leg: copy the carrier package root from `src` to `dst`
 * store-to-store through the public store paths — every chunk read from
 * src is re-hashed, every chunk written to dst is verified against the
 * root-committed manifest before it is stored. This is the same
 * admission shape the package swarm uses; the live swarm fetch replaces
 * the src reads, nothing else. */
bool vcs_fastobj_carrier_fetch(struct vcs_package_store *dst,
                               struct vcs_package_store *src,
                               const uint8_t root[32],
                               struct vcs_fastobj_carrier_stats *stats,
                               char *err, size_t err_cap);

/* Re-derive the whole carrier from stored bytes, changing nothing: the
 * manifest wire loads, parses and roots to `root`; the files pair as
 * sidecar-at-2i / object-at-2i+1 entries under the carrier prefix; every
 * sidecar re-derives its own cache key; and every object hashes to its
 * sidecar's object_sha3. This IS the proof half of admit, so a consumer
 * and the public-shape gate that decides a carrier may be served run the
 * same verification a stranger re-runs after fetching it. */
bool vcs_fastobj_carrier_verify(struct vcs_package_store *store,
                                const uint8_t root[32],
                                char *err, size_t err_cap);

/* Reconstruct a verified carrier from `store` into `cache_dir`: verify
 * (above) plus the cache write. Every entry is re-verified (manifest
 * re-rooted, chunks re-hashed at their exact coordinates, sidecar + key +
 * object hash re-checked) before it lands in the receiving cache in the
 * worker's own store-on-miss format. An existing identical entry is
 * idempotent; a divergent one is corruption and refuses the admit. */
bool vcs_fastobj_carrier_admit(const char *cache_dir,
                               struct vcs_package_store *store,
                               const uint8_t root[32],
                               struct vcs_fastobj_carrier_stats *stats,
                               char *err, size_t err_cap);

#endif /* ZCL_VCS_FASTOBJ_CARRIER_H */
