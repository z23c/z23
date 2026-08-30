/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fixed-width local acceptance and child-receipt contract. */

#ifndef ZCL_TOOLS_DEV_PROOF_RECEIPT_H
#define ZCL_TOOLS_DEV_PROOF_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_DEV_PROOF_OID_MAX 32u
#define ZCL_DEV_PROOF_ROOT_BYTES 32u
#define ZCL_DEV_PROOF_DIMENSIONS 4u
#define ZCL_DEV_PROOF_WIRE_BYTES 664u
#define ZCL_DEV_PROOF_CHILD_WIRE_BYTES 100u

enum zcl_dev_proof_dimension_id {
    ZCL_DEV_PROOF_GENERATED = 0,
    ZCL_DEV_PROOF_COMPILE,
    ZCL_DEV_PROOF_LINT,
    ZCL_DEV_PROOF_TEST,
};

struct zcl_dev_proof_dimension {
    uint8_t receipt_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint32_t selected;
    uint32_t ran;
    uint32_t reused;
    uint32_t failed;
    uint32_t skipped;
};

struct zcl_dev_acceptance_receipt_v1 {
    uint8_t local_commit[ZCL_DEV_PROOF_OID_MAX];
    uint8_t remote_base[ZCL_DEV_PROOF_OID_MAX];
    uint8_t local_commit_len;
    uint8_t remote_base_len;

    uint8_t source_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t source_cas_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t mutation_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t changed_set_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t impact_policy_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t compiler_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t flags_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t environment_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t build_graph_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t child_set_root[ZCL_DEV_PROOF_ROOT_BYTES];

    struct zcl_dev_proof_dimension dimensions[ZCL_DEV_PROOF_DIMENSIONS];
    uint64_t created_unix;
    uint64_t elapsed_ms;
    uint32_t policy_version;
    uint32_t complete;
    uint8_t seal[ZCL_DEV_PROOF_ROOT_BYTES];
};

const char *zcl_dev_proof_dimension_name(enum zcl_dev_proof_dimension_id id);
bool zcl_dev_proof_oid_decode(const char *hex,
                              uint8_t out[ZCL_DEV_PROOF_OID_MAX],
                              uint8_t *out_len);
bool zcl_dev_proof_oid_encode(const uint8_t oid[ZCL_DEV_PROOF_OID_MAX],
                              uint8_t oid_len, char *out, size_t out_size);
bool zcl_dev_proof_receipt_seal(struct zcl_dev_acceptance_receipt_v1 *receipt);
bool zcl_dev_proof_receipt_child_set_root(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    uint8_t out[ZCL_DEV_PROOF_ROOT_BYTES]);
bool zcl_dev_proof_receipt_validate(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    const char *local_commit, const char *remote_base,
    char *why, size_t why_len);
bool zcl_dev_proof_receipt_serialize(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    uint8_t out[ZCL_DEV_PROOF_WIRE_BYTES]);
bool zcl_dev_proof_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_dev_acceptance_receipt_v1 *out);
bool zcl_dev_proof_child_receipt_create(
    enum zcl_dev_proof_dimension_id id,
    struct zcl_dev_proof_dimension *dimension,
    uint8_t out[ZCL_DEV_PROOF_CHILD_WIRE_BYTES]);
bool zcl_dev_proof_child_receipt_validate(
    const uint8_t *wire, size_t wire_len,
    enum zcl_dev_proof_dimension_id id,
    const struct zcl_dev_proof_dimension *dimension);

#endif
