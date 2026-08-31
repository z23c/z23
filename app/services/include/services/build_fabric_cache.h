/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact, non-executing restoration of accepted ZCODE build outputs. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_CACHE_H
#define ZCL_SERVICES_BUILD_FABRIC_CACHE_H

#include "base/result.h"
#include "models/build_fabric.h"

#include <stdint.h>

struct vcs_package_store;

enum build_fabric_cache_disposition {
    BUILD_FABRIC_CACHE_MISS = 0,
    BUILD_FABRIC_CACHE_HIT,
    BUILD_FABRIC_CACHE_CORRUPT,
};

struct build_fabric_cache_report {
    enum build_fabric_cache_disposition disposition;
    uint64_t restored_bytes;
    char action_id[BUILD_FABRIC_ID_HEX + 1];
    char output_root_sha3[BUILD_FABRIC_ID_HEX + 1];
};

const char *build_fabric_cache_disposition_string(
    enum build_fabric_cache_disposition disposition);

/* Restore one locally accepted compile output without queueing, leasing,
 * executing, minting evidence, or changing the durable lifecycle. The caller
 * supplies the immutable plan; its source manifest, canonical ids, authority,
 * exact accepted receipt, physical observation, and content.v2 carrier are
 * rechecked. Task expiry prevents new work, but does not revoke an immutable
 * output accepted while the task was valid. MISS is a successful,
 * non-mutating lookup result. */
struct zcl_result build_fabric_cache_restore(
    struct node_db *ndb, const char *workspace,
    struct vcs_package_store *store, const struct db_build_job *expected_job,
    const struct db_build_action *expected_action, const char *destination,
    struct build_fabric_cache_report *report);

#endif /* ZCL_SERVICES_BUILD_FABRIC_CACHE_H */
