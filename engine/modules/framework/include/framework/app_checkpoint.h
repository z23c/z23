/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Portable, pointer-free App checkpoint and acceptance contracts. Checkpoint
 * bytes are private App state, never package-swarm content or execution
 * authority. Save/restore remains disabled until appd owns isolated App DBs. */

#ifndef ZCL_FRAMEWORK_APP_CHECKPOINT_H
#define ZCL_FRAMEWORK_APP_CHECKPOINT_H

#include "zclassic23/app.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_APP_CHECKPOINT_V1 1u
#define ZCL_APP_CHECKPOINT_SCHEMA_NAME "zcl.app.checkpoint.v1"
#define ZCL_APP_CHECKPOINT_ACCEPTANCE_V1 1u
#define ZCL_APP_STATE_CHUNK_BYTES_V1 65536u
#define ZCL_APP_STATE_CHUNK_MAX_V1 1048576u
#define ZCL_APP_STATE_BYTES_MAX_V1 UINT64_C(68719476736)
#define ZCL_APP_LOGICAL_ROOT_CODEC_V1 1u
#define ZCL_APP_WARM_CACHE_FORMAT_V1 1u

enum zcl_app_checkpoint_storage_format_v1 {
    ZCL_APP_CHECKPOINT_STORAGE_INVALID = 0,
    ZCL_APP_CHECKPOINT_STORAGE_SQLITE3 = 1,
};

/* V1 state chunks are private-local only. Replication uses separately signed
 * AppEvents, not whole-database checkpoint bytes. A future encrypted-export
 * format requires a new explicit storage class/version. */
enum zcl_app_checkpoint_storage_class_v1 {
    ZCL_APP_CHECKPOINT_CLASS_INVALID = 0,
    ZCL_APP_CHECKPOINT_CLASS_PRIVATE_LOCAL = 1,
};

enum zcl_app_checkpoint_origin_v1 {
    ZCL_APP_CHECKPOINT_ORIGIN_INVALID = 0,
    ZCL_APP_CHECKPOINT_ORIGIN_LIVE = 1,
    ZCL_APP_CHECKPOINT_ORIGIN_ISOLATED_FORK = 2,
    ZCL_APP_CHECKPOINT_ORIGIN_SYNTHETIC_FIXTURE = 3,
};

/* CONTROLLED means platform policy may later deliver a committed outbox; it
 * does not itself authorize delivery. Forks and fixtures must be quarantined. */
enum zcl_app_checkpoint_outbox_mode_v1 {
    ZCL_APP_CHECKPOINT_OUTBOX_INVALID = 0,
    ZCL_APP_CHECKPOINT_OUTBOX_CONTROLLED = 1,
    ZCL_APP_CHECKPOINT_OUTBOX_QUARANTINED = 2,
};

enum zcl_app_checkpoint_cause_v1 {
    ZCL_APP_CHECKPOINT_CAUSE_INVALID = 0,
    ZCL_APP_CHECKPOINT_CAUSE_INITIAL = 1,
    ZCL_APP_CHECKPOINT_CAUSE_MANUAL = 2,
    ZCL_APP_CHECKPOINT_CAUSE_SCHEDULED = 3,
    ZCL_APP_CHECKPOINT_CAUSE_PRE_UPGRADE = 4,
    ZCL_APP_CHECKPOINT_CAUSE_ROLLBACK = 5,
    ZCL_APP_CHECKPOINT_CAUSE_LLM_FORK = 6,
    ZCL_APP_CHECKPOINT_CAUSE_SCENARIO_FIXTURE = 7,
    ZCL_APP_CHECKPOINT_CAUSE_MIGRATION = 8,
    ZCL_APP_CHECKPOINT_CAUSE_RESTORE = 9,
};

enum zcl_app_checkpoint_component_v1 {
    ZCL_APP_CHECKPOINT_COMPONENT_EVENTS = 1,
    ZCL_APP_CHECKPOINT_COMPONENT_OUTBOX = 2,
    ZCL_APP_CHECKPOINT_COMPONENT_SUBSCRIPTIONS = 3,
    ZCL_APP_CHECKPOINT_COMPONENT_ROUTES = 4,
    ZCL_APP_CHECKPOINT_COMPONENT_JOBS = 5,
    ZCL_APP_CHECKPOINT_COMPONENT_COUNT = 5,
};

enum zcl_app_checkpoint_admission_v1 {
    ZCL_APP_CHECKPOINT_ADMISSION_INVALID = 0,
    ZCL_APP_CHECKPOINT_ADMISSION_RESTORE_SOURCE = 1,
    ZCL_APP_CHECKPOINT_ADMISSION_ISOLATED_SCENARIO = 2,
    ZCL_APP_CHECKPOINT_ADMISSION_PRODUCTION_SWITCH = 3,
};

enum zcl_app_warm_cache_architecture_v1 {
    ZCL_APP_WARM_ARCH_INVALID = 0,
    ZCL_APP_WARM_ARCH_X86_64 = 1,
    ZCL_APP_WARM_ARCH_AARCH64 = 2,
};

enum zcl_app_warm_cache_endianness_v1 {
    ZCL_APP_WARM_ENDIAN_INVALID = 0,
    ZCL_APP_WARM_ENDIAN_LITTLE = 1,
    ZCL_APP_WARM_ENDIAN_BIG = 2,
};

enum zcl_app_warm_cache_encoding_v1 {
    ZCL_APP_WARM_POINTER_FREE = 1u << 0,
    ZCL_APP_WARM_CANONICAL_OFFSETS = 1u << 1,
    ZCL_APP_WARM_ZERO_PADDING = 1u << 2,
    ZCL_APP_WARM_NON_EXECUTABLE = 1u << 3,
};

#define ZCL_APP_WARM_REQUIRED_ENCODING_V1 \
    (ZCL_APP_WARM_POINTER_FREE | ZCL_APP_WARM_CANONICAL_OFFSETS | \
     ZCL_APP_WARM_ZERO_PADDING | ZCL_APP_WARM_NON_EXECUTABLE)

struct zcl_app_checkpoint_cursor_v1 {
    uint64_t sequence;
    uint8_t root[32];
};

struct zcl_app_state_chunk_v1 {
    uint32_t index;
    uint32_t length;
    uint64_t offset;
    uint8_t digest[32];
};

/* A warm cache is a detachable, discardable attachment. The portable
 * checkpoint digest excludes it; zcl_app_warm_cache_attachment_digest_v1()
 * binds it separately to the exact checkpoint and therefore to the artifact,
 * SDK, schema, activation generation, state generation, and grant revision. */
struct zcl_app_warm_cache_v1 {
    uint32_t present;
    uint32_t format_version;
    uint32_t architecture;
    uint32_t endianness;
    uint32_t data_model_bits;
    uint32_t page_size;
    uint32_t alignment;
    uint32_t encoding_flags;
    uint32_t region_count;
    uint64_t cpu_feature_floor[2];
    uint64_t byte_length;
    uint8_t root[32];
};

struct zcl_app_checkpoint_manifest_v1 {
    uint32_t struct_size;
    uint32_t schema_version;
    char app_id[ZCL_APP_ID_MAX + 1u];
    uint8_t instance_id[32];
    uint8_t publisher_root[32];
    uint8_t package_root[32];
    uint8_t artifact_root[32];

    /* Worker activation/deployment and database state generations are
     * distinct identities. A cheap state fork does not mint worker authority. */
    uint64_t activation_generation;
    uint8_t activation_generation_root[32];
    uint64_t state_generation;
    /* Stable opaque lineage identity minted by platform control. It is not a
     * content hash and therefore does not change on each checkpoint. */
    uint8_t state_generation_root[32];
    uint64_t grant_revision;
    uint8_t grant_root[32];

    uint32_t storage_format;
    uint32_t storage_class;
    uint32_t app_schema_version;
    uint32_t sdk_abi;
    uint32_t logical_root_codec;
    uint8_t migration_lineage_root[32];
    uint8_t sqlite_image_root[32];
    uint8_t logical_state_root[32];

    struct zcl_app_checkpoint_cursor_v1 events;
    struct zcl_app_checkpoint_cursor_v1 outbox;
    struct zcl_app_checkpoint_cursor_v1 subscriptions;
    /* These roots are App-local cursor/projection witnesses. Package and
     * platform control remain the authority for routes and schedules. */
    struct zcl_app_checkpoint_cursor_v1 routes;
    struct zcl_app_checkpoint_cursor_v1 jobs;

    uint32_t chunk_size;
    uint32_t chunk_count;
    uint64_t total_bytes;
    uint32_t creation_cause;
    uint32_t state_origin;
    uint32_t outbox_mode;
    uint32_t has_parent;
    uint8_t parent_checkpoint_root[32];
};

struct zcl_app_checkpoint_cursor_floors_v1 {
    uint64_t events;
    uint64_t outbox;
    uint64_t subscriptions;
    uint64_t routes;
    uint64_t jobs;
};

struct zcl_app_checkpoint_expected_v1 {
    uint32_t struct_size;
    uint32_t admission;
    uint8_t checkpoint_root[32];
    uint32_t accepting_service_id;
    uint64_t control_sequence;
    uint8_t control_event_id[32];
    uint8_t control_segment_root[32];
    uint8_t parent_acceptance_receipt_root[32];
    /* Required only for an INITIAL checkpoint. The trusted caller resolves
     * this from the platform-control INSTANCE_CREATED receipt proving that the
     * exact App instance has no previously accepted checkpoint. */
    uint8_t instance_creation_receipt_root[32];
    /* Required only for ISOLATED_SCENARIO. These values come from the
     * platform grant validator, not from checkpoint bytes. */
    uint8_t scenario_principal_root[32];
    uint64_t scenario_grant_revision;
    uint8_t scenario_grant_root[32];
    uint8_t attenuation_receipt_root[32];
    char app_id[ZCL_APP_ID_MAX + 1u];
    uint8_t instance_id[32];
    uint8_t publisher_root[32];
    uint8_t package_root[32];
    uint8_t artifact_root[32];
    uint64_t activation_generation;
    uint8_t activation_generation_root[32];
    uint64_t state_generation;
    uint8_t state_generation_root[32];
    uint64_t grant_revision;
    uint8_t grant_root[32];
    uint32_t app_schema_version;
    uint32_t sdk_abi;
    uint32_t logical_root_codec;
    uint8_t migration_lineage_root[32];
    struct zcl_app_checkpoint_cursor_floors_v1 cursor_floors;
};

struct zcl_app_warm_cache_host_v1 {
    uint32_t struct_size;
    uint32_t format_version;
    uint32_t architecture;
    uint32_t endianness;
    uint32_t data_model_bits;
    uint32_t page_size;
    uint64_t cpu_features[2];
};

/* Separate from checkpoint content to avoid a checkpoint-root/control-event
 * hash cycle. The control event names checkpoint_root; this receipt names the
 * resulting event and segment root. */
struct zcl_app_checkpoint_acceptance_v1 {
    uint32_t struct_size;
    uint32_t schema_version;
    uint8_t checkpoint_root[32];
    uint64_t control_sequence;
    uint8_t control_event_id[32];
    uint8_t control_segment_root[32];
    uint32_t accepting_service_id;
};

enum zcl_app_checkpoint_result {
    ZCL_APP_CHECKPOINT_OK = 0,
    ZCL_APP_CHECKPOINT_NULL,
    ZCL_APP_CHECKPOINT_SCHEMA,
    ZCL_APP_CHECKPOINT_APP_ID,
    ZCL_APP_CHECKPOINT_IDENTITY,
    ZCL_APP_CHECKPOINT_GENERATION,
    ZCL_APP_CHECKPOINT_GRANT,
    ZCL_APP_CHECKPOINT_STATE_SCHEMA,
    ZCL_APP_CHECKPOINT_STORAGE_CLASS,
    ZCL_APP_CHECKPOINT_ROOT,
    ZCL_APP_CHECKPOINT_CURSOR,
    ZCL_APP_CHECKPOINT_CHUNK_LAYOUT,
    ZCL_APP_CHECKPOINT_IMAGE_ROOT,
    ZCL_APP_CHECKPOINT_CAUSALITY,
    ZCL_APP_CHECKPOINT_SIDE_EFFECT,
    ZCL_APP_CHECKPOINT_EXPECTED_BINDING,
    ZCL_APP_CHECKPOINT_ADMISSION,
    ZCL_APP_CHECKPOINT_ACCEPTANCE,
};

bool zcl_app_state_chunk_digest_v1(const uint8_t *bytes, uint32_t length,
                                   uint8_t out[32]);

bool zcl_app_checkpoint_empty_component_root_v1(uint32_t component,
                                                uint8_t out[32]);

bool zcl_app_checkpoint_image_root_v1(
    uint32_t chunk_size,
    uint64_t total_bytes,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count,
    uint8_t out[32]);

/* Structural validation checks canonical metadata and chunk digests, not the
 * underlying CAS bytes or any platform-control authorization. */
enum zcl_app_checkpoint_result zcl_app_checkpoint_validate_structure_v1(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count);

/* Every non-initial checkpoint must be admitted with its accepted parent.
 * Origin taint is monotonic: LIVE may fork to isolated/synthetic, but an
 * isolated or synthetic lineage can never be relabeled LIVE. */
enum zcl_app_checkpoint_result zcl_app_checkpoint_validate_lineage_v1(
    const struct zcl_app_checkpoint_manifest_v1 *child,
    const struct zcl_app_state_chunk_v1 *child_chunks,
    size_t child_chunk_count,
    const struct zcl_app_checkpoint_manifest_v1 *parent,
    const struct zcl_app_state_chunk_v1 *parent_chunks,
    size_t parent_chunk_count);

/* Admission always requires a non-NULL exact expected binding and exact
 * receipts already resolved from the verified platform control journal.
 * Nonzero instance-creation and attenuation roots are not self-authenticating;
 * the trusted caller must verify those receipts before constructing expected.
 * CAS must rehash every chunk's bytes against its descriptor before this
 * metadata gate. appd must still recheck the live grant under a generation
 * lease immediately before an atomic switch. */
enum zcl_app_checkpoint_result zcl_app_checkpoint_validate_admission_v1(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count,
    const struct zcl_app_checkpoint_expected_v1 *expected,
    const struct zcl_app_checkpoint_acceptance_v1 *acceptance,
    const struct zcl_app_checkpoint_manifest_v1 *parent,
    const struct zcl_app_state_chunk_v1 *parent_chunks,
    size_t parent_chunk_count,
    const struct zcl_app_checkpoint_acceptance_v1 *parent_acceptance);

bool zcl_app_checkpoint_cursors_meet_floors_v1(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_checkpoint_cursor_floors_v1 *floors);

/* Portable checkpoint identity excludes the optional warm cache and any
 * control-journal acceptance metadata. */
bool zcl_app_checkpoint_digest_v1(
    const struct zcl_app_checkpoint_manifest_v1 *manifest,
    const struct zcl_app_state_chunk_v1 *chunks,
    size_t chunk_count,
    uint8_t out[32]);

bool zcl_app_warm_cache_attachment_digest_v1(
    const uint8_t checkpoint_root[32],
    const struct zcl_app_warm_cache_v1 *cache,
    uint8_t out[32]);

bool zcl_app_warm_cache_compatible_v1(
    const struct zcl_app_warm_cache_v1 *cache,
    const struct zcl_app_warm_cache_host_v1 *host);

/* A cache may be mapped only when its separately trusted attachment root
 * matches as well as the host tuple. Compatibility by itself is insufficient. */
bool zcl_app_warm_cache_admitted_v1(
    const struct zcl_app_warm_cache_v1 *cache,
    const uint8_t checkpoint_root[32],
    const uint8_t expected_attachment_root[32],
    const struct zcl_app_warm_cache_host_v1 *host);

enum zcl_app_checkpoint_result zcl_app_checkpoint_acceptance_validate_v1(
    const struct zcl_app_checkpoint_acceptance_v1 *receipt,
    const uint8_t expected_checkpoint_root[32]);

bool zcl_app_checkpoint_acceptance_digest_v1(
    const struct zcl_app_checkpoint_acceptance_v1 *receipt,
    uint8_t out[32]);

#endif /* ZCL_FRAMEWORK_APP_CHECKPOINT_H */
