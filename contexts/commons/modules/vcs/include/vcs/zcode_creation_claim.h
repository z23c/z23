/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical signed simulation-only ZC23 creation claim object. */
#ifndef ZCL_VCS_ZCODE_CREATION_CLAIM_H
#define ZCL_VCS_ZCODE_CREATION_CLAIM_H

#include "vcs/zcode_commons.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_CREATION_CLAIM_SIGNING_DOMAIN \
    "zcl.zcode.creation_claim.signature.v2"
#define VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES 288u
#define VCS_ZCODE_CREATION_CLAIM_UNSIGNED_BYTES 224u
#define VCS_ZCODE_CREATION_CLAIM_KAT_ROOT \
    "b71cb990297e455c68365f3c79d078877d74b0ef989002923cf1589f34fcf07f"

enum vcs_zcode_creation_claim_error {
    VCS_ZCODE_CREATION_CLAIM_OK = 0,
    VCS_ZCODE_CREATION_CLAIM_NULL,
    VCS_ZCODE_CREATION_CLAIM_WIRE_SIZE,
    VCS_ZCODE_CREATION_CLAIM_MAGIC_ERROR,
    VCS_ZCODE_CREATION_CLAIM_V2_VERSION_ERROR,
    VCS_ZCODE_CREATION_CLAIM_FLAGS,
    VCS_ZCODE_CREATION_CLAIM_ENUM,
    VCS_ZCODE_CREATION_CLAIM_ROOT,
    VCS_ZCODE_CREATION_CLAIM_TIME,
    VCS_ZCODE_CREATION_CLAIM_SIGNATURE,
};

/* claim_root is the CAS root of these signed bytes and is populated only in
 * the selection projection. It is deliberately not self-serialized here. */
struct vcs_zcode_creation_claim_wire_v2 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t category;
    uint16_t reserved;
    uint8_t recipient_binding_root[32];
    uint8_t workspace_lineage_root[32];
    uint8_t semantic_lineage_root[32];
    uint8_t evidence_root[32];
    uint8_t commons_admission_root[32];
    uint64_t maturity_height;
    int64_t maturity_mtp;
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_validate(
    const struct vcs_zcode_creation_claim_wire_v2 *claim);
enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_sign(
    struct vcs_zcode_creation_claim_wire_v2 *claim,
    const uint8_t signer_seed[32]);
enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_encode(
    const struct vcs_zcode_creation_claim_wire_v2 *claim,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_decode(
    struct vcs_zcode_creation_claim_wire_v2 *out,
    const uint8_t *wire, size_t wire_len);
enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_root(
    const struct vcs_zcode_creation_claim_wire_v2 *claim,
    uint8_t out[32]);
void vcs_zcode_creation_claim_wire_v2_selection(
    const struct vcs_zcode_creation_claim_wire_v2 *claim,
    const uint8_t claim_root[32],
    struct vcs_zcode_creation_claim_v2 *out);

#endif /* ZCL_VCS_ZCODE_CREATION_CLAIM_H */
