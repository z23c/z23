/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only portable reproduction challenges. */
#ifndef ZCL_VCS_ZCODE_REPRODUCTION_REQUEST_H
#define ZCL_VCS_ZCODE_REPRODUCTION_REQUEST_H

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_REPRODUCTION_REQUEST_DOMAIN \
    "zcl.zcode.reproduction_request.v1"
#define VCS_ZCODE_REPRODUCTION_REQUEST_VERSION 1u
#define VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES 512u
#define VCS_ZCODE_REPRODUCTION_MAX_TTL_SECONDS INT64_C(604800)
#define VCS_ZCODE_REPRODUCTION_MAX_CPU_SECONDS UINT32_C(86400)
#define VCS_ZCODE_REPRODUCTION_MAX_PROCESSES UINT32_C(256)
#define VCS_ZCODE_REPRODUCTION_MAX_MEMORY_BYTES \
    (UINT64_C(16) * 1024u * 1024u * 1024u)
#define VCS_ZCODE_REPRODUCTION_MAX_OUTPUT_BYTES \
    (UINT64_C(4) * 1024u * 1024u * 1024u)

enum vcs_zcode_reproduction_flag {
    VCS_ZCODE_REPRODUCTION_SIMULATION_ONLY = 1u << 0,
    VCS_ZCODE_REPRODUCTION_PUBLIC_BYTES_ONLY = 1u << 1,
    VCS_ZCODE_REPRODUCTION_NO_CREDENTIALS = 1u << 2,
    VCS_ZCODE_REPRODUCTION_NO_LIVE_DATADIR = 1u << 3,
};

#define VCS_ZCODE_REPRODUCTION_REQUIRED_FLAGS \
    (VCS_ZCODE_REPRODUCTION_SIMULATION_ONLY | \
     VCS_ZCODE_REPRODUCTION_PUBLIC_BYTES_ONLY | \
     VCS_ZCODE_REPRODUCTION_NO_CREDENTIALS | \
     VCS_ZCODE_REPRODUCTION_NO_LIVE_DATADIR)

enum vcs_zcode_reproduction_error {
    VCS_ZCODE_REPRODUCTION_OK = 0,
    VCS_ZCODE_REPRODUCTION_NULL,
    VCS_ZCODE_REPRODUCTION_WIRE_SIZE,
    VCS_ZCODE_REPRODUCTION_MAGIC,
    VCS_ZCODE_REPRODUCTION_VERSION,
    VCS_ZCODE_REPRODUCTION_FLAGS,
    VCS_ZCODE_REPRODUCTION_RESERVED,
    VCS_ZCODE_REPRODUCTION_ROOT,
    VCS_ZCODE_REPRODUCTION_ACTION,
    VCS_ZCODE_REPRODUCTION_CONFINEMENT,
    VCS_ZCODE_REPRODUCTION_TIME,
    VCS_ZCODE_REPRODUCTION_BUDGET,
};

struct vcs_zcode_reproduction_request_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint8_t confinement;
    uint8_t network_genesis_root[32];
    uint8_t zc23_policy_root[32];
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t package_root[32];
    uint8_t release_root[32];
    uint8_t recipe_root[32];
    uint8_t dependency_lock_root[32];
    uint8_t toolchain_capsule_root[32];
    uint8_t reference_build_root[32];
    uint8_t output_manifest_root[32];
    uint8_t action_root[32];
    uint8_t challenge_nonce[32];
    uint8_t requester_contributor_binding_root[32];
    int64_t created_unix;
    int64_t expires_unix;
    uint32_t max_cpu_seconds;
    uint32_t max_processes;
    uint64_t max_memory_bytes;
    uint64_t max_output_bytes;
};

const char *vcs_zcode_reproduction_error_string(
    enum vcs_zcode_reproduction_error error);
void vcs_zcode_reproduction_request_init(
    struct vcs_zcode_reproduction_request_v1 *request);
enum vcs_zcode_reproduction_error vcs_zcode_reproduction_request_validate(
    const struct vcs_zcode_reproduction_request_v1 *request);
enum vcs_zcode_reproduction_error vcs_zcode_reproduction_request_serialize(
    const struct vcs_zcode_reproduction_request_v1 *request,
    uint8_t out[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES]);
enum vcs_zcode_reproduction_error vcs_zcode_reproduction_request_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_reproduction_request_v1 *out);
enum vcs_zcode_reproduction_error vcs_zcode_reproduction_request_root(
    const struct vcs_zcode_reproduction_request_v1 *request,
    uint8_t out[32]);

#endif /* ZCL_VCS_ZCODE_REPRODUCTION_REQUEST_H */
