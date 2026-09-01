/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pointer-free declarative service policy for the shadow service fabric.
 * Validation and hashing grant no runtime authority; an init implementation
 * must still bind every descriptor, IPC grant, generation, and peer. */

#ifndef ZCL_KERNEL_SERVICE_MANIFEST_H
#define ZCL_KERNEL_SERVICE_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_SERVICE_MANIFEST_V1 1u
#define ZCL_SERVICE_MANIFEST_SCHEMA_NAME "zcl.service_manifest.v1"
#define ZCL_SERVICE_MANIFEST_NAME_MAX 31u
#define ZCL_SERVICE_STATE_SCHEMA_MAX 63u
#define ZCL_SERVICE_DEPENDENCY_MAX 8u
#define ZCL_SERVICE_IPC_GRANT_MAX 16u
#define ZCL_SERVICE_DESCRIPTOR_MAX 8u
#define ZCL_SERVICE_CATALOG_MAX 64u

enum zcl_service_role_v1 {
    ZCL_SERVICE_ROLE_INVALID = 0,
    ZCL_SERVICE_ROLE_INIT = 1,
    ZCL_SERVICE_ROLE_CORE = 2,
    ZCL_SERVICE_ROLE_EDGE = 3,
    ZCL_SERVICE_ROLE_WALLET = 4,
    ZCL_SERVICE_ROLE_APPD = 5,
    ZCL_SERVICE_ROLE_BUILDD = 6,
};

enum zcl_service_trust_class_v1 {
    ZCL_SERVICE_TRUST_INVALID = 0,
    ZCL_SERVICE_TRUST_SUPERVISOR = 1,
    ZCL_SERVICE_TRUST_CONSENSUS = 2,
    ZCL_SERVICE_TRUST_PUBLIC_EDGE = 3,
    ZCL_SERVICE_TRUST_KEY_CUSTODY = 4,
    ZCL_SERVICE_TRUST_APP_BROKER = 5,
    ZCL_SERVICE_TRUST_UNTRUSTED_BUILD = 6,
};

/* This lifecycle is the target process-service projection. It deliberately
 * does not reinterpret enum zcl_service_state in the existing callback
 * service kernel while the catalog is shadow-only. */
enum zcl_service_lifecycle_v1 {
    ZCL_SERVICE_LIFECYCLE_DECLARED = 1,
    ZCL_SERVICE_LIFECYCLE_STARTING = 2,
    ZCL_SERVICE_LIFECYCLE_READY = 3,
    ZCL_SERVICE_LIFECYCLE_DEGRADED = 4,
    ZCL_SERVICE_LIFECYCLE_BLOCKED = 5,
    ZCL_SERVICE_LIFECYCLE_STOPPING = 6,
    ZCL_SERVICE_LIFECYCLE_EXITED = 7,
};

enum zcl_service_enforcement_v1 {
    ZCL_SERVICE_ENFORCEMENT_INVALID = 0,
    ZCL_SERVICE_ENFORCEMENT_SHADOW = 1,
    ZCL_SERVICE_ENFORCEMENT_ACTIVE = 2,
};

/* Erlang/OTP names and meanings match the existing supervisor contract.
 * Failure classification is separate: a parity, provenance, corruption, or
 * policy blocker is never restartable under any value below. */
enum zcl_service_restart_policy_v1 {
    ZCL_SERVICE_RESTART_TEMPORARY = 0,
    ZCL_SERVICE_RESTART_TRANSIENT = 1,
    ZCL_SERVICE_RESTART_PERMANENT = 2,
};

enum zcl_service_readiness_kind_v1 {
    ZCL_SERVICE_READINESS_INVALID = 0,
    ZCL_SERVICE_READINESS_SELF_TEST = 1,
    ZCL_SERVICE_READINESS_SERVICE_READY = 2,
    ZCL_SERVICE_READINESS_DURABLE_PROGRESS = 3,
};

/* Classes are semantic inherited capabilities, not operating-system fd
 * numbers and never filesystem paths. */
enum zcl_service_descriptor_class_v1 {
    ZCL_SERVICE_DESCRIPTOR_INVALID = 0,
    ZCL_SERVICE_DESCRIPTOR_CONTROL = 1,
    ZCL_SERVICE_DESCRIPTOR_LOG = 2,
    ZCL_SERVICE_DESCRIPTOR_CONSENSUS_STATE = 3,
    ZCL_SERVICE_DESCRIPTOR_CHAIN_LISTENER = 4,
    ZCL_SERVICE_DESCRIPTOR_PUBLIC_LISTENER = 5,
    ZCL_SERVICE_DESCRIPTOR_WALLET_SECRETS = 6,
    ZCL_SERVICE_DESCRIPTOR_APP_STATE = 7,
    ZCL_SERVICE_DESCRIPTOR_PRIVATE_CAS = 8,
    ZCL_SERVICE_DESCRIPTOR_BUILD_INPUT = 9,
    ZCL_SERVICE_DESCRIPTOR_BUILD_OUTPUT = 10,
};

enum zcl_service_descriptor_right_v1 {
    ZCL_SERVICE_DESCRIPTOR_READ = 1u << 0,
    ZCL_SERVICE_DESCRIPTOR_WRITE = 1u << 1,
    ZCL_SERVICE_DESCRIPTOR_ACCEPT = 1u << 2,
};

struct zcl_service_readiness_witness_v1 {
    uint32_t kind;
    uint32_t source_service_id;
    uint32_t witness_schema_id;
    uint64_t max_age_ms;
};

/* Direction is explicit: the declared service may call operation_id on peer.
 * A numeric operation without its exact peer would be ambiguous authority. */
struct zcl_service_ipc_grant_v1 {
    uint32_t peer_service_id;
    uint32_t operation_id;
};

struct zcl_service_descriptor_grant_v1 {
    uint32_t capability_id;
    uint32_t descriptor_class;
    uint32_t rights;
};

struct zcl_service_resource_budget_v1 {
    uint64_t cpu_quota_us;
    uint64_t cpu_period_us;
    uint64_t memory_bytes;
    uint64_t storage_bytes;
    uint32_t process_limit;
    uint32_t open_file_limit;
};

struct zcl_service_restart_budget_v1 {
    uint32_t policy;
    uint32_t max_restarts;
    uint64_t window_ms;
};

/* Canonical encoders hash fields individually in fixed-width little-endian
 * order. The in-memory struct, its padding, and enum representation are never
 * a wire format or an authority identity. */
struct zcl_service_manifest_v1 {
    uint32_t struct_size;
    uint32_t schema_version;
    uint32_t service_id;
    char name[ZCL_SERVICE_MANIFEST_NAME_MAX + 1u];
    uint32_t role;
    uint32_t trust_class;
    uint32_t enforcement;

    uint32_t dependency_count;
    uint32_t dependencies[ZCL_SERVICE_DEPENDENCY_MAX];
    struct zcl_service_readiness_witness_v1 readiness;

    uint32_t ipc_grant_count;
    struct zcl_service_ipc_grant_v1 ipc_grants[ZCL_SERVICE_IPC_GRANT_MAX];
    uint32_t descriptor_count;
    struct zcl_service_descriptor_grant_v1
        descriptors[ZCL_SERVICE_DESCRIPTOR_MAX];

    struct zcl_service_resource_budget_v1 resources;
    struct zcl_service_restart_budget_v1 restart;
    char state_schema[ZCL_SERVICE_STATE_SCHEMA_MAX + 1u];
    uint8_t active_generation_root[32];
    uint64_t health_deadline_ms;
    uint32_t durable_progress_schema_id;
};

enum zcl_service_manifest_result {
    ZCL_SERVICE_MANIFEST_OK = 0,
    ZCL_SERVICE_MANIFEST_NULL,
    ZCL_SERVICE_MANIFEST_SCHEMA,
    ZCL_SERVICE_MANIFEST_IDENTITY,
    ZCL_SERVICE_MANIFEST_ROLE_TRUST,
    ZCL_SERVICE_MANIFEST_ENFORCEMENT,
    ZCL_SERVICE_MANIFEST_DEPENDENCY,
    ZCL_SERVICE_MANIFEST_READINESS,
    ZCL_SERVICE_MANIFEST_IPC_GRANT,
    ZCL_SERVICE_MANIFEST_DESCRIPTOR,
    ZCL_SERVICE_MANIFEST_RESOURCE_BUDGET,
    ZCL_SERVICE_MANIFEST_RESTART_BUDGET,
    ZCL_SERVICE_MANIFEST_STATE_SCHEMA,
    ZCL_SERVICE_MANIFEST_GENERATION,
    ZCL_SERVICE_MANIFEST_HEALTH,
    ZCL_SERVICE_MANIFEST_CATALOG_ORDER,
    ZCL_SERVICE_MANIFEST_CATALOG_REFERENCE,
    ZCL_SERVICE_MANIFEST_CATALOG_CYCLE,
};

enum zcl_service_manifest_result zcl_service_manifest_validate_v1(
    const struct zcl_service_manifest_v1 *manifest);

enum zcl_service_manifest_result zcl_service_manifest_catalog_validate_v1(
    const struct zcl_service_manifest_v1 *manifests,
    size_t count,
    size_t *bad_index);

/* Invalid input fails closed and zeros out. */
bool zcl_service_manifest_digest_v1(
    const struct zcl_service_manifest_v1 *manifest,
    uint8_t out[32]);

bool zcl_service_manifest_catalog_digest_v1(
    const struct zcl_service_manifest_v1 *manifests,
    size_t count,
    uint8_t out[32]);

#endif /* ZCL_KERNEL_SERVICE_MANIFEST_H */
