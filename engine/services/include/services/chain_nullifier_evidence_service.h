/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: expose bounded read-only nullifier evidence without leaking the
 * mutable consensus-kernel handle across the engine boundary. */

#ifndef ZCL_SERVICES_CHAIN_NULLIFIER_EVIDENCE_SERVICE_H
#define ZCL_SERVICES_CHAIN_NULLIFIER_EVIDENCE_SERVICE_H

#include "base/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Service-owned vocabulary. Values are translated to the storage schema by
 * the implementation; callers do not depend on nullifier_kv or SQLite. */
enum chain_nullifier_pool {
    CHAIN_NULLIFIER_POOL_SPROUT = 0,
    CHAIN_NULLIFIER_POOL_SAPLING = 1,
};

struct chain_nullifier_query {
    const uint8_t *bytes;
};

struct chain_nullifier_set_evidence {
    bool any_found;
    bool heights_consistent;
    int64_t height;
};

/* Read a transaction's nullifiers under one kernel lock so a concurrent
 * reducer/reorg cannot make the observations come from different snapshots.
 * A successful empty set has any_found=false, heights_consistent=true, and
 * height=-1. Multiple found nullifiers at different heights are returned as
 * evidence (ok=true, heights_consistent=false), not a storage error. */
struct zcl_result chain_nullifier_evidence_lookup_set(
    const struct chain_nullifier_query *queries,
    size_t query_count,
    enum chain_nullifier_pool pool,
    struct chain_nullifier_set_evidence *out);

#endif /* ZCL_SERVICES_CHAIN_NULLIFIER_EVIDENCE_SERVICE_H */
