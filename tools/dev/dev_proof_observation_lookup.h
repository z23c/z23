/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded receiver-local projection of signed test observations. */
#ifndef ZCL_DEV_PROOF_OBSERVATION_LOOKUP_H
#define ZCL_DEV_PROOF_OBSERVATION_LOOKUP_H

#include "dev_proof_receipt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_DEV_OBSERVATION_MAX_ROOTS 256u
#define ZCL_DEV_OBSERVATION_MAX_DOMAINS 16u

/* The caller obtains the complete root set and exact wires from its local
 * CAS. A missing or incomplete enumeration must set complete=false. This
 * structure owns no network or durable authority. */
struct zcl_dev_observation_object {
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES];
    const uint8_t *wire;
    size_t wire_len;
};

/* Trust domains are assigned by receiver policy to signer keys, never taken
 * from a producer's assertion. One domain may contain several keys. */
struct zcl_dev_observation_domain {
    uint8_t producer_pubkey[ZCL_DEV_PROOF_PUBKEY_BYTES];
    uint8_t domain_root[ZCL_DEV_PROOF_ROOT_BYTES];
};

enum zcl_dev_observation_result {
    ZCL_DEV_OBSERVATION_UNAVAILABLE,
    ZCL_DEV_OBSERVATION_MISS,
    ZCL_DEV_OBSERVATION_PASS_EVIDENCE,
    ZCL_DEV_OBSERVATION_FAIL_EVIDENCE,
    ZCL_DEV_OBSERVATION_CONFLICT,
    ZCL_DEV_OBSERVATION_INSUFFICIENT_DOMAINS,
};

struct zcl_dev_observation_query {
    uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES];
    const char *group;
    uint64_t now_unix;
    uint64_t max_age_seconds;
    uint64_t max_future_seconds;
    uint32_t required_independent_domains;
};

struct zcl_dev_observation_result_detail {
    enum zcl_dev_observation_result result;
    uint32_t pass_count;
    uint32_t fail_count;
    uint32_t stale_count;
    uint32_t invalid_count;
    uint32_t independent_domains;
    uint32_t duplicate_roots;
    uint16_t pass_root_indices[ZCL_DEV_OBSERVATION_MAX_ROOTS];
    uint16_t fail_root_indices[ZCL_DEV_OBSERVATION_MAX_ROOTS];
};

/* Scan all locally enumerated roots. Each candidate's wire, CAS root, exact
 * key/group, signature, receiver trust domain and age are checked. A corrupt
 * or missing object makes the whole projection unavailable. Invalid signed
 * observations are counted but cannot create a PASS/FAIL conflict. An
 * eligible conflict is never collapsed. PASS_EVIDENCE is not acceptance:
 * callers still verify artifact bytes, complete closure/policy generation,
 * coverage and their own action binding before skipping work. */
void zcl_dev_observation_lookup(
    const struct zcl_dev_observation_query *query,
    const struct zcl_dev_observation_object *objects, size_t object_count,
    bool complete,
    const struct zcl_dev_observation_domain *domains, size_t domain_count,
    struct zcl_dev_observation_result_detail *out);

/* Read exact signed leaf wires from the existing local ZVCS addressed CAS.
 * `roots` comes from a separate complete local projection or authenticated
 * checkpoint. A root missing from local CAS refuses; there is no peer fetch. */
void zcl_dev_observation_lookup_local(
    const char *store_root, const struct zcl_dev_observation_query *query,
    const uint8_t (*roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t root_count,
    bool complete,
    const struct zcl_dev_observation_domain *domains, size_t domain_count,
    struct zcl_dev_observation_result_detail *out);

#endif
