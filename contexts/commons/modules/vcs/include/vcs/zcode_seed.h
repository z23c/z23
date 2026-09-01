/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical dual-signed c23.seed.v1 credential and maturity gate. */
#ifndef ZCL_VCS_ZCODE_SEED_H
#define ZCL_VCS_ZCODE_SEED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_C23_SEED_VERSION 1u
#define VCS_C23_SEED_DOMAIN "zcl.zcode.c23.seed.v1"
#define VCS_C23_SEED_BODY_DOMAIN "zcl.zcode.c23.seed.body.v1"
#define VCS_C23_SEED_BODY_BYTES 593u
#define VCS_C23_SEED_WIRE_BYTES 721u
#define VCS_C23_SEED_CHALLENGE_BLOCKS UINT64_C(8064)
#define VCS_C23_SEED_CHALLENGE_SECONDS INT64_C(604800)

enum vcs_c23_seed_flag {
    VCS_C23_SEED_PERMISSIVE_LICENSE = 1u << 0,
    VCS_C23_SEED_TWO_COMPILERS = 1u << 1,
    VCS_C23_SEED_WARNINGS_FATAL = 1u << 2,
    VCS_C23_SEED_NETWORK_DISABLED = 1u << 3,
    VCS_C23_SEED_COMPILE_LINK_PASS = 1u << 4,
    VCS_C23_SEED_DURABLE_REPLICATION = 1u << 5,
    VCS_C23_SEED_POW_ANCHORED = 1u << 6,
    VCS_C23_SEED_SIMULATION_ONLY = 1u << 7,
    VCS_C23_SEED_NO_AUTHORITY = 1u << 8,
};

#define VCS_C23_SEED_REQUIRED_FLAGS UINT16_C(0x01ff)

enum vcs_c23_seed_source_flag {
    VCS_C23_SEED_SOURCE_GENERATED = 1u << 0,
    VCS_C23_SEED_SOURCE_VENDORED = 1u << 1,
    VCS_C23_SEED_SOURCE_COPIED = 1u << 2,
};

enum vcs_c23_seed_error {
    VCS_C23_SEED_OK = 0,
    VCS_C23_SEED_ERR_NULL,
    VCS_C23_SEED_ERR_VERSION,
    VCS_C23_SEED_ERR_FLAGS,
    VCS_C23_SEED_ERR_SOURCE_CLASSIFICATION,
    VCS_C23_SEED_ERR_ROOT,
    VCS_C23_SEED_ERR_PUBKEY,
    VCS_C23_SEED_ERR_ORDER,
    VCS_C23_SEED_ERR_TIME,
    VCS_C23_SEED_ERR_SEQUENCE,
    VCS_C23_SEED_ERR_WIRE_SIZE,
    VCS_C23_SEED_ERR_MAGIC,
    VCS_C23_SEED_ERR_RESERVED,
    VCS_C23_SEED_ERR_SIGNATURE,
    VCS_C23_SEED_ERR_KEY_MISMATCH,
    VCS_C23_SEED_ERR_OVERFLOW,
    VCS_C23_SEED_ERR_IMMATURE,
    VCS_C23_SEED_ERR_REORG,
};

struct vcs_c23_seed_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t source_flags;
    uint8_t network_genesis_root[32];
    uint8_t contributor_binding_root[32];
    uint8_t zid_pubkey[32];
    uint8_t zcl_pubkey[33];
    uint8_t package_root[32];
    uint8_t release_root[32];
    uint8_t dependency_lock_root[32];
    uint8_t license_evidence_root[32];
    uint8_t semantic_fingerprint_root[32];
    uint8_t novelty_evidence_root[32];
    uint8_t target_capsule_root[32];
    uint8_t compiler_capsule_roots[2][32];
    uint8_t build_report_roots[2][32];
    uint8_t dht_replication_root[32];
    uint64_t challenge_opening_height;
    uint8_t challenge_opening_hash[32];
    int64_t challenge_opening_mtp;
    int64_t created_unix;
    uint64_t sequence;
    uint8_t zid_signature[64];
    uint8_t zcl_signature[64];
};

typedef bool (*vcs_c23_seed_anchor_active_fn)(
    void *opaque, uint64_t height, const uint8_t hash[32]);

const char *vcs_c23_seed_error_string(enum vcs_c23_seed_error error);
enum vcs_c23_seed_error vcs_c23_seed_validate(
    const struct vcs_c23_seed_v1 *seed);
enum vcs_c23_seed_error vcs_c23_seed_serialize(
    const struct vcs_c23_seed_v1 *seed,
    uint8_t out[VCS_C23_SEED_WIRE_BYTES]);
enum vcs_c23_seed_error vcs_c23_seed_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_c23_seed_v1 *out);
enum vcs_c23_seed_error vcs_c23_seed_body_root(
    const struct vcs_c23_seed_v1 *seed, uint8_t out[32]);
enum vcs_c23_seed_error vcs_c23_seed_root(
    const struct vcs_c23_seed_v1 *seed, uint8_t out[32]);
enum vcs_c23_seed_error vcs_c23_seed_seal(
    struct vcs_c23_seed_v1 *seed, const uint8_t zid_secret[32],
    const uint8_t zid_pubkey[32], const uint8_t zcl_secret[32]);
enum vcs_c23_seed_error vcs_c23_seed_verify(
    const struct vcs_c23_seed_v1 *seed);
enum vcs_c23_seed_error vcs_c23_seed_maturity(
    const struct vcs_c23_seed_v1 *seed, uint64_t active_height,
    int64_t active_mtp, vcs_c23_seed_anchor_active_fn anchor_is_active,
    void *opaque, uint64_t *maturity_height_out,
    int64_t *maturity_mtp_out);

#endif /* ZCL_VCS_ZCODE_SEED_H */
