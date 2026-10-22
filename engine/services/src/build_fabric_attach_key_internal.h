/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private executor-key record and field helpers for fixed compile attachment. */
#ifndef ZCL_BUILD_FABRIC_ATTACH_KEY_INTERNAL_H
#define ZCL_BUILD_FABRIC_ATTACH_KEY_INTERNAL_H

#include "base/result.h"
#include "services/build_fabric_attach.h"
#include "vcs/build_action.h"
#include "vcs/zcode_dev.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

enum {
    BFAT_RECORD_CAP = 4096,
};

/* Fixed canonical field order of the executor-key record. The serialized
 * record is exactly the hashed preimage: object id == executor key. */
struct bfat_key_fields {
    char kind[BUILD_FABRIC_KIND_MAX + 1];
    char target[BUILD_FABRIC_TARGET_MAX + 1];
    char resource_policy[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    char declared_outputs[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    uint8_t flags_root[32];
    uint8_t environment_root[32];
    uint8_t proof_policy_root[32];
    uint8_t toolchain_root[32];
    uint8_t runtime_root[32];
    uint8_t verifier_root[32];
    uint8_t input_bytes_root[32];
    uint8_t component_key[32];
    uint8_t component_preimage_root[32];
};

bool bfat_record_serialize(const struct bfat_key_fields *f,
                           uint8_t *out, size_t cap, size_t *out_len);
bool bfat_record_parse(const uint8_t *wire, size_t len,
                       struct bfat_key_fields *out);
void bfat_record_key(const uint8_t *wire, size_t len, uint8_t out[32]);
struct zcl_result bfat_fields_for_action(
    const struct db_build_action *action,
    const uint8_t toolchain_bytes_root[32],
    const struct vcs_toolchain_capsule_v1 *capsule,
    const uint8_t driver_bytes_root[32],
    const uint8_t backend_bytes_root[32],
    const uint8_t assembler_bytes_root[32],
    const uint8_t runtime_root[32],
    const uint8_t verifier_root[32],
    const uint8_t input_bytes_root[32], struct bfat_key_fields *out,
    struct vcs_component_proof_key_v1 *proof_out);

#endif
